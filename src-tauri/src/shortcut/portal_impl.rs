//! Linux XDG GlobalShortcuts portal owner.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex, Weak,
    },
    time::Duration,
};

use super::portal_dbus::{BoundShortcut, NewShortcut, PortalClient, PortalSession, PortalSignal};
use ashpd::{
    zbus::{fdo::DBusProxy, names::BusName, Connection},
    AppID, WindowIdentifier,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use specta::Type;
use tokio::{
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
};
use xkbcommon::xkb;

use crate::settings::{KeyboardImplementation, ShortcutBinding};

const APP_ID: &str = "com.pais.handy";
const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
const PRIMARY_ID: &str = "transcribe";
const POST_PROCESS_ID: &str = "transcribe_with_post_process";
pub const PRIMARY_BINDING_MISSING: &str =
    "The desktop did not bind the primary transcription shortcut";
pub const IDENTITY_UNAVAILABLE: &str = "Desktop portal application registration is unavailable";
pub const PORTAL_UNAVAILABLE: &str = "Desktop GlobalShortcuts portal is unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutBackendKind {
    Tauri,
    XdgPortal,
    HandyKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutBackendState {
    Initializing,
    Ready,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ShortcutBackendStatus {
    pub backend: ShortcutBackendKind,
    pub state: ShortcutBackendState,
    pub message: Option<String>,
    pub bindings: HashMap<String, String>,
    pub can_configure: bool,
}

impl ShortcutBackendStatus {
    pub fn static_ready(backend: ShortcutBackendKind) -> Self {
        Self {
            backend,
            state: ShortcutBackendState::Ready,
            message: None,
            bindings: HashMap::new(),
            can_configure: false,
        }
    }
    fn initializing() -> Self {
        Self {
            backend: ShortcutBackendKind::XdgPortal,
            state: ShortcutBackendState::Initializing,
            message: None,
            bindings: HashMap::new(),
            can_configure: false,
        }
    }
}

pub fn resolve_shortcut_backend(
    is_linux: bool,
    is_wayland: bool,
    implementation: KeyboardImplementation,
) -> ShortcutBackendKind {
    match implementation {
        KeyboardImplementation::HandyKeys => ShortcutBackendKind::HandyKeys,
        KeyboardImplementation::Tauri if is_linux && is_wayland => ShortcutBackendKind::XdgPortal,
        KeyboardImplementation::Tauri => ShortcutBackendKind::Tauri,
    }
}
/// Pure half of the Linux callback gate. The dispatcher supplies the committed backend and
/// generation; staged, retired, stale, and unknown callbacks are rejected.
pub fn portal_callback_is_active(
    active_backend: ShortcutBackendKind,
    active_generation: Option<u64>,
    callback_generation: u64,
    known_id: bool,
) -> bool {
    active_backend == ShortcutBackendKind::XdgPortal
        && active_generation == Some(callback_generation)
        && known_id
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalShortcutSpec {
    pub id: String,
    pub description: String,
    pub preferred_trigger: String,
}

pub fn shortcut_specs_from_settings(
    bindings: &HashMap<String, ShortcutBinding>,
    post_process_enabled: bool,
) -> Result<Vec<PortalShortcutSpec>, String> {
    let mut ids = vec![PRIMARY_ID];
    if post_process_enabled {
        ids.push(POST_PROCESS_ID);
    }
    ids.into_iter()
        .map(|id| {
            let binding = bindings
                .get(id)
                .ok_or_else(|| format!("Missing shortcut setting: {id}"))?;
            Ok(PortalShortcutSpec {
                id: binding.id.clone(),
                description: binding.description.clone(),
                preferred_trigger: portal_trigger_from_binding(&binding.current_binding)?,
            })
        })
        .collect()
}

/// Consumes only recognized modifier prefixes; the complete suffix is the main-key token.
pub fn portal_trigger_from_binding(binding: &str) -> Result<String, String> {
    let mut rest = binding.trim();
    let mut modifiers = [false; 4];
    while let Some(plus) = rest.find('+') {
        let prefix = rest[..plus].trim().to_ascii_lowercase();
        let index = match prefix.as_str() {
            "ctrl" | "control" => 0,
            "alt" | "option" => 1,
            "shift" => 2,
            "super" | "meta" | "command" | "cmd" | "win" | "logo" => 3,
            _ => break,
        };
        if modifiers[index] {
            return Err(format!("Duplicate shortcut modifier: {prefix}"));
        }
        modifiers[index] = true;
        rest = &rest[plus + 1..];
    }
    let mut parts = modifiers
        .into_iter()
        .zip(["CTRL", "ALT", "SHIFT", "LOGO"])
        .filter(|(set, _)| *set)
        .map(|(_, name)| name.to_string())
        .collect::<Vec<_>>();
    parts.push(canonical_main_key(rest.trim())?);
    Ok(parts.join("+"))
}

fn canonical_main_key(token: &str) -> Result<String, String> {
    if token.is_empty() || token == "+" {
        return Err("Shortcut must contain a supported main key".into());
    }
    let lower = token.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "ctrl"
            | "control"
            | "alt"
            | "option"
            | "shift"
            | "super"
            | "meta"
            | "command"
            | "cmd"
            | "win"
            | "logo"
            | "fn"
    ) {
        return Err("Shortcut must contain a supported main key".into());
    }
    let name = match lower.as_str() {
        "space" => "space".into(),
        "enter" | "return" => "Return".into(),
        "backspace" => "BackSpace".into(),
        "esc" | "escape" => "Escape".into(),
        "delete" => "Delete".into(),
        "tab" => "Tab".into(),
        "up" | "arrow up" => "Up".into(),
        "down" | "arrow down" => "Down".into(),
        "left" | "arrow left" => "Left".into(),
        "right" | "arrow right" => "Right".into(),
        "home" => "Home".into(),
        "end" => "End".into(),
        "page up" | "pageup" => "Page_Up".into(),
        "page down" | "pagedown" => "Page_Down".into(),
        "insert" => "Insert".into(),
        "print screen" | "printscreen" => "Print".into(),
        "scroll lock" | "scrolllock" => "Scroll_Lock".into(),
        "pause" => "Pause".into(),
        "menu" | "context menu" => "Menu".into(),
        "num lock" | "numlock" => "Num_Lock".into(),
        "caps lock" | "capslock" => "Caps_Lock".into(),
        "numpad *" => "KP_Multiply".into(),
        "numpad +" => "KP_Add".into(),
        "numpad -" => "KP_Subtract".into(),
        "numpad ." => "KP_Decimal".into(),
        "numpad /" => "KP_Divide".into(),
        ";" => "semicolon".into(),
        "=" => "equal".into(),
        "," => "comma".into(),
        "-" => "minus".into(),
        "." => "period".into(),
        "/" => "slash".into(),
        "`" => "grave".into(),
        "[" => "bracketleft".into(),
        "\\" => "backslash".into(),
        "]" => "bracketright".into(),
        "'" => "apostrophe".into(),
        _ if lower.starts_with("numpad ")
            && lower.len() == 8
            && lower.as_bytes()[7].is_ascii_digit() =>
        {
            format!("KP_{}", &lower[7..])
        }
        _ if lower.len() == 1 && lower.as_bytes()[0].is_ascii_alphanumeric() => lower,
        _ if lower
            .strip_prefix('f')
            .and_then(|n| n.parse::<u8>().ok())
            .is_some_and(|n| (1..=24).contains(&n)) =>
        {
            lower.to_ascii_uppercase()
        }
        _ => token.to_string(),
    };
    let mut symbol = xkb::keysym_from_name(&name, xkb::KEYSYM_NO_FLAGS);
    if symbol.raw() == xkb::keysyms::KEY_NoSymbol {
        symbol = xkb::keysym_from_name(&name, xkb::KEYSYM_CASE_INSENSITIVE);
    }
    if symbol.raw() == xkb::keysyms::KEY_NoSymbol {
        return Err(format!("Unsupported shortcut key: {token}"));
    }
    let canonical = xkb::keysym_get_name(symbol);
    if canonical.is_empty() {
        Err(format!("Unsupported shortcut key: {token}"))
    } else if matches!(name.as_str(), "Page_Up" | "Page_Down") {
        // XKB validates these names but reports their older synonymous names Prior/Next.
        // The portal trigger grammar accepts the clearer exact XKB aliases Handy requests.
        Ok(name)
    } else {
        Ok(canonical)
    }
}

pub fn classify_portal_bindings(
    requested: &HashSet<String>,
    bindings: &HashMap<String, String>,
) -> ShortcutBackendStatus {
    let primary = bindings.contains_key(PRIMARY_ID);
    let state = if !primary {
        ShortcutBackendState::Unavailable
    } else if requested.iter().all(|id| bindings.contains_key(id)) {
        ShortcutBackendState::Ready
    } else {
        ShortcutBackendState::Partial
    };
    ShortcutBackendStatus {
        backend: ShortcutBackendKind::XdgPortal,
        state,
        message: (!primary).then(|| PRIMARY_BINDING_MISSING.to_string()),
        bindings: bindings.clone(),
        can_configure: true,
    }
}

fn apply_configure_capability(
    mut status: ShortcutBackendStatus,
    portal_version: u32,
) -> ShortcutBackendStatus {
    // GlobalShortcuts v1 has no standard way to reopen configuration for a
    // complete persistent binding. Keep retry available for incomplete states,
    // where a fresh BindShortcuts may still prompt for missing shortcuts.
    if portal_version < 2 && status.state == ShortcutBackendState::Ready {
        status.can_configure = false;
    }
    status
}

fn shortcut_map(shortcuts: &[BoundShortcut]) -> HashMap<String, String> {
    shortcuts
        .iter()
        .map(|shortcut| (shortcut.id.clone(), shortcut.trigger_description.clone()))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalShortcutEvent {
    pub generation_id: u64,
    pub shortcut_id: String,
    /// Latest portal-provided trigger description for handler diagnostics.
    pub shortcut: String,
    pub is_pressed: bool,
    pub synthetic: bool,
}
pub type PortalEventHandler = Arc<dyn Fn(PortalShortcutEvent) + Send + Sync + 'static>;
pub type PortalStatusHandler = Arc<dyn Fn(ShortcutBackendStatus) + Send + Sync + 'static>;

#[derive(Clone)]
struct Runtime {
    requested: HashSet<String>,
    bindings: HashMap<String, String>,
    pressed: HashSet<String>,
}
impl Runtime {
    fn press(&mut self, id: &str) -> Option<String> {
        let shortcut = self.bindings.get(id)?.clone();
        self.pressed.insert(id.to_string()).then_some(shortcut)
    }
    fn release(&mut self, id: &str) -> Option<String> {
        if self.pressed.remove(id) {
            self.bindings.get(id).cloned()
        } else {
            None
        }
    }
    fn update(&mut self, bindings: HashMap<String, String>) -> Vec<(String, String)> {
        let releases = self
            .pressed
            .iter()
            .filter(|id| !bindings.contains_key(*id))
            .filter_map(|id| {
                self.bindings
                    .get(id)
                    .cloned()
                    .map(|shortcut| (id.clone(), shortcut))
            })
            .collect::<Vec<_>>();
        for (id, _) in &releases {
            self.pressed.remove(id);
        }
        self.bindings = bindings;
        releases
    }
    fn drain(&mut self) -> Vec<(String, String)> {
        let pressed = self.pressed.drain().collect::<Vec<_>>();
        pressed
            .into_iter()
            .filter_map(|id| {
                self.bindings
                    .get(&id)
                    .cloned()
                    .map(|shortcut| (id, shortcut))
            })
            .collect()
    }
}

fn classify_active_runtime(
    runtime: &Runtime,
    portal_version: u32,
    can_configure_suppressed: bool,
) -> ShortcutBackendStatus {
    let mut status = apply_configure_capability(
        classify_portal_bindings(&runtime.requested, &runtime.bindings),
        portal_version,
    );
    if can_configure_suppressed {
        status.can_configure = false;
    }
    status
}

fn generation_accepts_signals(
    active_generation: u64,
    deliberate: bool,
    failed_epoch: Option<u64>,
    callback_generation: u64,
) -> bool {
    active_generation == callback_generation && !deliberate && failed_epoch.is_none()
}

fn initializing_can_publish(active: Option<(bool, Option<u64>)>) -> bool {
    active.is_none_or(|(deliberate, failed_epoch)| !deliberate && failed_epoch.is_none())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateHealth {
    owner: String,
    failed: bool,
    bindings: Option<HashMap<String, String>>,
}

fn apply_candidate_bindings(
    runtime: &mut Runtime,
    health: &CandidateHealth,
    portal_version: u32,
) -> ShortcutBackendStatus {
    if let Some(bindings) = health.bindings.clone() {
        runtime.update(bindings);
    }
    apply_configure_capability(
        classify_portal_bindings(&runtime.requested, &runtime.bindings),
        portal_version,
    )
}

fn candidate_can_commit(
    health: Option<&CandidateHealth>,
    candidate_owner: &str,
    current_owner: &str,
    tracked_owner: Option<&str>,
    current_base: Option<u64>,
    candidate_base: Option<u64>,
) -> bool {
    health.is_some_and(|health| !health.failed && health.owner == candidate_owner)
        && candidate_owner == current_owner
        && tracked_owner == Some(current_owner)
        && current_base == candidate_base
}

fn configuration_is_available(
    owner: Option<&str>,
    registration: Option<&Result<(), String>>,
    cached_owner: Option<&str>,
) -> bool {
    owner.is_some_and(|owner| matches!(registration, Some(Ok(()))) && cached_owner == Some(owner))
}

fn refreshed_no_active_status(
    status: &ShortcutBackendStatus,
    has_active: bool,
    operation_in_flight: bool,
    can_configure: bool,
) -> Option<ShortcutBackendStatus> {
    if has_active
        || operation_in_flight
        || !can_configure
        || status.backend != ShortcutBackendKind::XdgPortal
        || status.state != ShortcutBackendState::Unavailable
        || status.can_configure
    {
        return None;
    }
    let mut status = status.clone();
    status.can_configure = true;
    Some(status)
}

struct Generation {
    id: u64,
    session: Arc<PortalSession>,
    portal: Arc<PortalClient>,
    version: u32,
    specs: Vec<PortalShortcutSpec>,
    owner: String,
    runtime: Runtime,
    tasks: Vec<JoinHandle<()>>,
    deliberate: bool,
    failed_epoch: Option<u64>,
}
#[derive(Clone)]
struct CachedPortal {
    owner: String,
    portal: Arc<PortalClient>,
    version: u32,
}
struct Inner {
    status: ShortcutBackendStatus,
    next_generation: u64,
    active: Option<Generation>,
    candidates: HashMap<u64, CandidateHealth>,
    registrations: HashMap<String, Result<(), String>>,
    registration_flights: HashMap<String, Arc<Notify>>,
    cached_portal: Option<CachedPortal>,
    owner: Option<String>,
    loss_epoch: u64,
    recovered_epoch: u64,
    last_specs: Option<Vec<PortalShortcutSpec>>,
    can_configure_suppressed: bool,
}

struct LossTransition {
    epoch: u64,
    releases: Vec<(String, String)>,
    specs: Vec<PortalShortcutSpec>,
    status: ShortcutBackendStatus,
}

fn fail_generation(inner: &mut Inner, generation: u64) -> Option<LossTransition> {
    if let Some(candidate) = inner.candidates.get_mut(&generation) {
        candidate.failed = true;
        return None;
    }
    if !inner.active.as_ref().is_some_and(|active| {
        generation_accepts_signals(
            active.id,
            active.deliberate,
            active.failed_epoch,
            generation,
        )
    }) {
        return None;
    }
    inner.loss_epoch += 1;
    let epoch = inner.loss_epoch;
    let active = inner.active.as_mut().unwrap();
    active.failed_epoch = Some(epoch);
    let releases = active.runtime.drain();
    let specs = active.specs.clone();
    let status = ShortcutBackendStatus {
        backend: ShortcutBackendKind::XdgPortal,
        state: ShortcutBackendState::Unavailable,
        message: Some("The desktop shortcut session ended unexpectedly".into()),
        bindings: HashMap::new(),
        can_configure: false,
    };
    inner.can_configure_suppressed = true;
    inner.status = status.clone();
    Some(LossTransition {
        epoch,
        releases,
        specs,
        status,
    })
}
#[derive(Default)]
struct InitFlight {
    running: bool,
    attempt: u64,
    result: Option<(u64, Result<ShortcutBackendStatus, String>)>,
}

fn finish_init_flight(
    init: &mut InitFlight,
    attempt: u64,
    result: Result<ShortcutBackendStatus, String>,
) -> bool {
    if !init.running || init.attempt != attempt {
        return false;
    }
    init.running = false;
    init.result = Some((attempt, result));
    true
}
enum InitRole {
    Leader(u64),
    Follower(u64),
}

struct InitLeaderGuard {
    state: Weak<PortalShortcutState>,
    attempt: u64,
    completed: bool,
}

impl InitLeaderGuard {
    fn new(state: &Arc<PortalShortcutState>, attempt: u64) -> Self {
        Self {
            state: Arc::downgrade(state),
            attempt,
            completed: false,
        }
    }

    fn complete(mut self, result: Result<ShortcutBackendStatus, String>) {
        if let Some(state) = self.state.upgrade() {
            state.complete_initialize(self.attempt, result);
        }
        self.completed = true;
    }
}

impl Drop for InitLeaderGuard {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(state) = self.state.upgrade() {
                state.cancel_initialize(self.attempt);
            }
        }
    }
}
pub struct PortalCandidate {
    generation: Option<Generation>,
    status: ShortcutBackendStatus,
    owner: String,
    base: Option<u64>,
    state: Weak<PortalShortcutState>,
    generation_id: u64,
}

impl Drop for PortalCandidate {
    fn drop(&mut self) {
        if self.generation.is_some() {
            if let Some(state) = self.state.upgrade() {
                state.discard_candidate(self.generation_id);

                state.cancel_operation();
            }
        }
        if let Some(generation) = self.generation.take() {
            tokio::spawn(close_generation(generation));
        }
    }
}
struct ConfigureGuard {
    state: Weak<PortalShortcutState>,
    generation: u64,
    armed: bool,
}

impl ConfigureGuard {
    fn new(state: &Arc<PortalShortcutState>, generation: u64) -> Self {
        Self {
            state: Arc::downgrade(state),
            generation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ConfigureGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(state) = self.state.upgrade() {
                state.cancel_configuration(self.generation);
            }
        }
    }
}

struct ArmedCommit {
    state: Weak<PortalShortcutState>,
    generation: Option<Generation>,
}

impl Drop for ArmedCommit {
    fn drop(&mut self) {
        if let Some(generation) = self.generation.as_ref() {
            if let Some(state) = self.state.upgrade() {
                state.discard_candidate(generation.id);
                state.cancel_operation();
            }
        }
        if let Some(generation) = self.generation.take() {
            tokio::spawn(close_generation(generation));
        }
    }
}

struct ArmedOperation {
    state: Weak<PortalShortcutState>,
    armed: bool,
}

impl ArmedOperation {
    fn new(state: &Arc<PortalShortcutState>) -> Self {
        Self {
            state: Arc::downgrade(state),
            armed: true,
        }
    }

    fn transfer(&mut self) {
        self.armed = false;
    }
}

impl Drop for ArmedOperation {
    fn drop(&mut self) {
        if self.armed {
            if let Some(state) = self.state.upgrade() {
                state.cancel_operation();
            }
        }
    }
}

struct ArmedCandidate {
    state: Weak<PortalShortcutState>,
    generation: Option<u64>,
    session: Option<Arc<PortalSession>>,
    tasks: Vec<JoinHandle<()>>,
}

impl ArmedCandidate {
    fn new(state: &Arc<PortalShortcutState>, session: Arc<PortalSession>) -> Self {
        Self {
            state: Arc::downgrade(state),
            generation: None,
            session: Some(session),
            tasks: Vec::new(),
        }
    }

    fn arm_generation(&mut self, generation: u64) {
        self.generation = Some(generation);
    }

    fn set_tasks(&mut self, tasks: Vec<JoinHandle<()>>) {
        self.tasks = tasks;
    }

    fn transfer(mut self) -> (Arc<PortalSession>, Vec<JoinHandle<()>>) {
        self.generation = None;
        self.state = Weak::new();
        let session = self.session.take().unwrap();
        let tasks = std::mem::take(&mut self.tasks);
        (session, tasks)
    }
}

impl Drop for ArmedCandidate {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            if let Some(generation) = self.generation.take() {
                state.discard_candidate(generation);
            }
            state.cancel_operation();
        }
        for task in &self.tasks {
            task.abort();
        }
        let tasks = std::mem::take(&mut self.tasks);
        let Some(session) = self.session.take() else {
            return;
        };
        tokio::spawn(async move {
            for task in tasks {
                let _ = task.await;
            }
            best_effort_close(&session).await;
        });
    }
}

pub struct PortalShortcutState {
    connection: Connection,
    lifecycle: AsyncMutex<()>,
    dispatch: StdMutex<()>,
    inner: StdMutex<Inner>,
    init: StdMutex<InitFlight>,
    init_notify: Notify,
    shutdown: AtomicBool,
    shutdown_notify: Notify,
    owner_notify: Notify,
    owner_task: StdMutex<Option<JoinHandle<()>>>,
    on_event: PortalEventHandler,
    on_status: PortalStatusHandler,
}

impl PortalShortcutState {
    pub async fn new(
        on_event: PortalEventHandler,
        on_status: PortalStatusHandler,
    ) -> Result<Arc<Self>, String> {
        let connection = Connection::session()
            .await
            .map_err(|error| format!("Failed to connect to the session bus: {error}"))?;
        let state = Arc::new(Self {
            connection,
            lifecycle: AsyncMutex::new(()),
            dispatch: StdMutex::new(()),
            inner: StdMutex::new(Inner {
                status: ShortcutBackendStatus::initializing(),
                next_generation: 1,
                active: None,
                candidates: HashMap::new(),
                registrations: HashMap::new(),
                registration_flights: HashMap::new(),
                cached_portal: None,
                owner: None,
                loss_epoch: 0,
                recovered_epoch: 0,
                last_specs: None,
                can_configure_suppressed: false,
            }),
            init: StdMutex::new(InitFlight::default()),
            init_notify: Notify::new(),
            shutdown: AtomicBool::new(false),
            shutdown_notify: Notify::new(),
            owner_notify: Notify::new(),
            owner_task: StdMutex::new(None),
            on_event,
            on_status,
        });
        state.start_owner_monitor().await?;
        Ok(state)
    }

    pub fn status(&self) -> ShortcutBackendStatus {
        self.inner.lock().unwrap().status.clone()
    }
    pub fn active_generation_id(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .active
            .as_ref()
            .filter(|generation| !generation.deliberate && generation.failed_epoch.is_none())
            .map(|generation| generation.id)
    }

    /// Serialize a pressed-ID snapshot and the caller's synchronous source
    /// commit against portal edge dispatch.
    pub fn with_active_pressed_binding_ids<T>(
        &self,
        commit: impl FnOnce(Option<(u64, HashSet<String>)>) -> T,
    ) -> T {
        let _dispatch = self.dispatch.lock().unwrap();
        let snapshot = self
            .inner
            .lock()
            .unwrap()
            .active
            .as_ref()
            .filter(|generation| !generation.deliberate && generation.failed_epoch.is_none())
            .map(|generation| (generation.id, generation.runtime.pressed.clone()));
        commit(snapshot)
    }

    pub async fn initialize(
        self: &Arc<Self>,
        specs: Vec<PortalShortcutSpec>,
        parent: Option<WindowIdentifier>,
    ) -> Result<ShortcutBackendStatus, String> {
        if let Some(status) = self.active_status() {
            return Ok(status);
        }
        let role = {
            let mut init = self.init.lock().unwrap();
            if init.running {
                InitRole::Follower(init.attempt)
            } else {
                init.running = true;
                init.attempt += 1;
                InitRole::Leader(init.attempt)
            }
        };
        if let InitRole::Follower(attempt) = role {
            loop {
                let notified = self.init_notify.notified();
                if let Some(result) = self
                    .init
                    .lock()
                    .unwrap()
                    .result
                    .as_ref()
                    .filter(|(done, _)| *done == attempt)
                    .map(|(_, result)| result.clone())
                {
                    return result;
                }
                notified.await;
            }
        }
        let InitRole::Leader(attempt) = role else {
            unreachable!()
        };
        let leader = InitLeaderGuard::new(self, attempt);
        let result = {
            let _operation = self.lifecycle.lock().await;
            if let Some(status) = self.active_status() {
                Ok(status)
            } else {
                let previous = self.active_status();
                match self.bind_locked(specs, parent).await {
                    Ok(candidate) => match self.commit_locked(candidate).await {
                        Ok(status) => Ok(status),
                        Err(error) => {
                            self.restore(previous, &error);
                            Err(error)
                        }
                    },
                    Err(error) => {
                        self.restore(previous, &error);
                        Err(error)
                    }
                }
            }
        };
        leader.complete(result.clone());
        result
    }

    /// Bind first, then run a synchronous persistence commit and swap generations while the
    /// lifecycle remains serialized. If persistence fails, only the candidate is closed.
    pub async fn replace_transactionally<F>(
        self: &Arc<Self>,
        specs: Vec<PortalShortcutSpec>,
        parent: Option<WindowIdentifier>,
        commit_settings: F,
    ) -> Result<ShortcutBackendStatus, String>
    where
        F: FnOnce() -> Result<(), String> + Send,
    {
        let _operation = self.lifecycle.lock().await;
        let previous = self.active_status();
        let candidate = match self.bind_locked(specs, parent).await {
            Ok(candidate) => candidate,
            Err(error) => {
                self.restore(previous, &error);
                return Err(error);
            }
        };
        match self.commit_locked_with(candidate, commit_settings).await {
            Ok(status) => Ok(status),
            Err(error) => {
                self.restore(previous, &error);
                Err(error)
            }
        }
    }

    pub async fn configure(
        self: &Arc<Self>,
        parent: Option<WindowIdentifier>,
    ) -> Result<ShortcutBackendStatus, String> {
        let _operation = self.lifecycle.lock().await;
        let active = {
            let inner = self.inner.lock().unwrap();
            inner.active.as_ref().and_then(|generation| {
                (!generation.deliberate && generation.failed_epoch.is_none()).then(|| {
                    (
                        generation.id,
                        generation.owner.clone(),
                        generation.portal.clone(),
                        generation.session.clone(),
                        generation.version,
                        generation.specs.clone(),
                    )
                })
            })
        };
        let Some((generation, owner, portal, session, version, specs)) = active else {
            let specs = self
                .inner
                .lock()
                .unwrap()
                .last_specs
                .clone()
                .ok_or_else(|| "No portal shortcut snapshot is available for retry".to_string())?;
            return self.bind_and_commit_or_restore(specs, parent).await;
        };
        if version < 2 {
            return self.bind_and_commit_or_restore(specs, parent).await;
        }
        let observed_owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => return Err(error.into()),
        };
        if observed_owner != owner {
            self.owner_changed(Some(observed_owner));
            return Err("Desktop portal restarted before shortcut configuration".into());
        }

        let previous = self.status();
        let mut busy = previous.clone();
        busy.can_configure = false;
        if !self.publish_for_generation(generation, busy.clone(), true) {
            return Err("Shortcut portal session is no longer active".into());
        }
        let mut configure_guard = ConfigureGuard::new(self, generation);
        let result = self
            .until_shutdown(portal.configure_shortcuts(&session, parent.as_ref()))
            .await
            .map_err(str::to_string)?;
        let observed_owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => return Err(error.into()),
        };
        if observed_owner != owner {
            self.owner_changed(Some(observed_owner));
            return Err("Desktop portal restarted during shortcut configuration".into());
        }
        if let Err(error) = result {
            self.publish_for_generation(generation, previous, false);
            configure_guard.disarm();
            return Err(format!(
                "Failed to open desktop shortcut configuration: {error}"
            ));
        }
        let current = self.status();
        let result = if current == busy {
            if self.publish_for_generation(generation, previous.clone(), false) {
                Ok(previous)
            } else {
                Ok(self.status())
            }
        } else {
            let mut current = current;
            current.can_configure = true;
            if self.publish_for_generation(generation, current.clone(), false) {
                Ok(current)
            } else {
                Ok(self.status())
            }
        };
        configure_guard.disarm();
        result
    }

    async fn bind_and_commit_or_restore(
        self: &Arc<Self>,
        specs: Vec<PortalShortcutSpec>,
        parent: Option<WindowIdentifier>,
    ) -> Result<ShortcutBackendStatus, String> {
        let previous = self.active_status();
        match self.bind_locked(specs, parent).await {
            Ok(candidate) => match self.commit_locked(candidate).await {
                Ok(status) => Ok(status),
                Err(error) => {
                    self.restore(previous, &error);
                    Err(error)
                }
            },
            Err(error) => {
                self.restore(previous, &error);
                Err(error)
            }
        }
    }

    /// Retire the current portal generation without permanently shutting down the portal owner.
    /// Used when another shortcut backend has already been prepared for an atomic source switch.
    pub async fn retire_active(self: &Arc<Self>) {
        let _operation = self.lifecycle.lock().await;
        let active = {
            let _dispatch = self.dispatch.lock().unwrap();
            let (active, releases) = {
                let mut inner = self.inner.lock().unwrap();
                let releases = inner
                    .active
                    .as_mut()
                    .map(|generation| {
                        generation.deliberate = true;
                        let id = generation.id;
                        generation
                            .runtime
                            .drain()
                            .into_iter()
                            .map(|(shortcut_id, shortcut)| (id, shortcut_id, shortcut))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                (inner.active.take(), releases)
            };
            for (generation_id, shortcut_id, shortcut) in releases {
                (self.on_event)(PortalShortcutEvent {
                    generation_id,
                    shortcut_id,
                    shortcut,
                    is_pressed: false,
                    synthetic: true,
                });
            }
            active
        };
        if let Some(generation) = active {
            tokio::spawn(close_generation(generation));
        }
    }

    pub async fn shutdown(self: &Arc<Self>) {
        {
            let _dispatch = self.dispatch.lock().unwrap();
            let releases = {
                let mut inner = self.inner.lock().unwrap();
                if self.shutdown.swap(true, Ordering::AcqRel) {
                    return;
                }
                for health in inner.candidates.values_mut() {
                    health.failed = true;
                }
                inner
                    .active
                    .as_mut()
                    .map(|generation| {
                        generation.deliberate = true;
                        let id = generation.id;
                        generation
                            .runtime
                            .drain()
                            .into_iter()
                            .map(|(shortcut_id, shortcut)| (id, shortcut_id, shortcut))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            for (generation_id, shortcut_id, shortcut) in releases {
                (self.on_event)(PortalShortcutEvent {
                    generation_id,
                    shortcut_id,
                    shortcut,
                    is_pressed: false,
                    synthetic: true,
                });
            }
        }
        self.shutdown_notify.notify_waiters();
        self.owner_notify.notify_waiters();
        let _operation = self.lifecycle.lock().await;
        let active = {
            let _dispatch = self.dispatch.lock().unwrap();
            self.inner.lock().unwrap().active.take()
        };
        if let Some(generation) = active {
            close_generation(generation).await;
        }
        let owner_task = self.owner_task.lock().unwrap().take();
        if let Some(task) = owner_task {
            task.abort();
            let _ = task.await;
        }
    }

    async fn bind_locked(
        self: &Arc<Self>,
        specs: Vec<PortalShortcutSpec>,
        parent: Option<WindowIdentifier>,
    ) -> Result<PortalCandidate, String> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err("Shortcut portal is shutting down".into());
        }
        if !specs.iter().any(|spec| spec.id == PRIMARY_ID) {
            return Err("Portal shortcut request is missing transcribe".into());
        }
        if specs
            .iter()
            .map(|spec| &spec.id)
            .collect::<HashSet<_>>()
            .len()
            != specs.len()
        {
            return Err("Portal shortcut IDs must be unique".into());
        }
        self.inner.lock().unwrap().last_specs = Some(specs.clone());
        let mut operation = ArmedOperation::new(self);
        self.publish_initializing();
        let cached = self.ensure_portal().await?;
        let session = Arc::new(
            self.until_shutdown(cached.portal.create_session())
                .await
                .map_err(str::to_string)?
                .map_err(|error| format!("Failed to create shortcut portal session: {error}"))?,
        );
        let mut armed = ArmedCandidate::new(self, session.clone());
        operation.transfer();
        let observed_owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => return Err(error.into()),
        };
        if observed_owner != cached.owner {
            self.owner_changed(Some(observed_owner));
            return Err("Desktop portal restarted while creating the shortcut session".into());
        }
        let path = session.path().to_string();
        let allocation = {
            let _dispatch = self.dispatch.lock().unwrap();
            let mut inner = self.inner.lock().unwrap();
            if self.shutdown.load(Ordering::Acquire)
                || inner.owner.as_deref() != Some(cached.owner.as_str())
            {
                None
            } else {
                let id = inner.next_generation;
                inner.next_generation += 1;
                let base = inner.active.as_ref().map(|active| active.id);
                inner.candidates.insert(
                    id,
                    CandidateHealth {
                        owner: cached.owner.clone(),
                        failed: false,
                        bindings: None,
                    },
                );
                Some((id, base))
            }
        };
        let Some((generation_id, base)) = allocation else {
            return Err("Desktop portal owner changed before shortcut listeners were ready".into());
        };
        armed.arm_generation(generation_id);
        let tasks = self
            .listeners(cached.portal.clone(), session.clone(), path, generation_id)
            .await?;
        armed.set_tasks(tasks);
        let requested = specs
            .iter()
            .map(|spec| spec.id.clone())
            .collect::<HashSet<_>>();
        let shortcuts = specs
            .iter()
            .map(|spec| NewShortcut::new(&spec.id, &spec.description, &spec.preferred_trigger))
            .collect::<Vec<_>>();
        let response = match self
            .until_shutdown(
                cached
                    .portal
                    .bind_shortcuts(&session, &shortcuts, parent.as_ref()),
            )
            .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                return Err(format!("Failed to request desktop shortcuts: {error}"));
            }
            Err(error) => return Err(error.into()),
        };
        let observed_owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => return Err(error.into()),
        };
        if observed_owner != cached.owner {
            self.owner_changed(Some(observed_owner));
            return Err("Desktop portal restarted during shortcut binding".into());
        }
        let bindings = shortcut_map(&response);
        let status = apply_configure_capability(
            classify_portal_bindings(&requested, &bindings),
            cached.version,
        );
        if status.state == ShortcutBackendState::Unavailable {
            return Err(PRIMARY_BINDING_MISSING.into());
        }
        let (session, tasks) = armed.transfer();
        Ok(PortalCandidate {
            generation: Some(Generation {
                id: generation_id,
                session,
                portal: cached.portal,
                version: cached.version,
                specs,
                owner: cached.owner.clone(),
                runtime: Runtime {
                    requested,
                    bindings,
                    pressed: HashSet::new(),
                },
                tasks,
                deliberate: false,
                failed_epoch: None,
            }),
            status,
            owner: cached.owner,
            base,
            state: Arc::downgrade(self),
            generation_id,
        })
    }

    async fn commit_locked(
        self: &Arc<Self>,
        candidate: PortalCandidate,
    ) -> Result<ShortcutBackendStatus, String> {
        self.commit_locked_with(candidate, || Ok(())).await
    }

    async fn commit_locked_with<F>(
        self: &Arc<Self>,
        mut candidate: PortalCandidate,
        commit_settings: F,
    ) -> Result<ShortcutBackendStatus, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        let generation = candidate
            .generation
            .take()
            .ok_or_else(|| "Portal candidate was already consumed".to_string())?;
        let mut armed = ArmedCommit {
            generation: Some(generation),
            state: Arc::downgrade(self),
        };
        let generation_id = armed.generation.as_ref().unwrap().id;
        let observed_owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                self.discard_candidate(generation_id);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => {
                self.discard_candidate(generation_id);
                return Err(error.into());
            }
        };
        if observed_owner != candidate.owner {
            self.owner_changed(Some(observed_owner));
            self.discard_candidate(generation_id);
            return Err("Desktop portal restarted before shortcut commit".into());
        }

        let mut commit_settings = Some(commit_settings);
        let transition = {
            let _dispatch = self.dispatch.lock().unwrap();
            let valid = {
                let mut inner = self.inner.lock().unwrap();
                let health = inner.candidates.remove(&generation_id);
                if let Some(health) = &health {
                    let generation = armed.generation.as_mut().unwrap();
                    candidate.status = apply_candidate_bindings(
                        &mut generation.runtime,
                        health,
                        generation.version,
                    );
                }
                let current_base = inner.active.as_ref().map(|active| active.id);
                candidate.status.state != ShortcutBackendState::Unavailable
                    && candidate_can_commit(
                        health.as_ref(),
                        &candidate.owner,
                        &observed_owner,
                        inner.owner.as_deref(),
                        current_base,
                        candidate.base,
                    )
                    && armed.generation.as_ref().is_some_and(|generation| {
                        generation.owner == candidate.owner
                            && !generation.deliberate
                            && generation.failed_epoch.is_none()
                    })
            };
            if !valid {
                Err("Portal candidate became unavailable before commit".to_string())
            } else if let Err(error) = commit_settings.take().unwrap()() {
                Err(error)
            } else {
                let (retired, releases) = {
                    let mut inner = self.inner.lock().unwrap();
                    let releases = inner
                        .active
                        .as_mut()
                        .map(|active| {
                            active.deliberate = true;
                            let id = active.id;
                            active
                                .runtime
                                .drain()
                                .into_iter()
                                .map(|(shortcut_id, shortcut)| (id, shortcut_id, shortcut))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let retired = inner.active.replace(armed.generation.take().unwrap());
                    inner.can_configure_suppressed = false;
                    inner.status = candidate.status.clone();
                    (retired, releases)
                };
                for (generation_id, shortcut_id, shortcut) in releases {
                    (self.on_event)(PortalShortcutEvent {
                        generation_id,
                        shortcut_id,
                        shortcut,
                        is_pressed: false,
                        synthetic: true,
                    });
                }
                (self.on_status)(candidate.status.clone());
                Ok(retired)
            }
        };
        let retired = match transition {
            Ok(retired) => retired,
            Err(error) => return Err(error),
        };
        if let Some(old) = retired {
            let cleanup = tokio::spawn(close_generation(old));
            let _ = cleanup.await;
        }
        Ok(candidate.status.clone())
    }

    async fn listeners(
        self: &Arc<Self>,
        portal: Arc<PortalClient>,
        session: Arc<PortalSession>,
        path: String,
        generation: u64,
    ) -> Result<Vec<JoinHandle<()>>, String> {
        let signals = self
            .until_shutdown(portal.receive_signals())
            .await
            .map_err(str::to_string)?
            .map_err(|error| format!("Failed to subscribe to portal shortcut signals: {error}"))?;
        let closed = self
            .until_shutdown(session.receive_closed())
            .await
            .map_err(str::to_string)?
            .map_err(|error| format!("Failed to subscribe to Closed: {error}"))?;

        let weak = Arc::downgrade(self);
        let signal_path = path.clone();
        let signals_task = tokio::spawn(async move {
            let mut stream = Box::pin(signals);
            while let Some(signal) = stream.next().await {
                let Ok(signal) = signal else { break };
                let Some(state) = weak.upgrade() else { return };
                match signal {
                    PortalSignal::Activated(signal)
                        if signal.session_path.as_str() == signal_path =>
                    {
                        state.activated(generation, &signal.shortcut_id);
                    }
                    PortalSignal::Deactivated(signal)
                        if signal.session_path.as_str() == signal_path =>
                    {
                        state.deactivated(generation, &signal.shortcut_id);
                    }
                    PortalSignal::ShortcutsChanged(signal)
                        if signal.session_path.as_str() == signal_path =>
                    {
                        state.changed(generation, shortcut_map(&signal.shortcuts));
                    }
                    _ => {}
                }
            }
            if let Some(state) = weak.upgrade() {
                state.lost(generation);
            }
        });
        let weak = Arc::downgrade(self);
        let closed_task = tokio::spawn(async move {
            let mut stream = Box::pin(closed);
            let _ = stream.next().await;
            if let Some(state) = weak.upgrade() {
                state.lost(generation);
            }
        });
        Ok(vec![signals_task, closed_task])
    }

    fn activated(&self, generation: u64, id: &str) {
        let _dispatch = self.dispatch.lock().unwrap();
        let shortcut = {
            let mut inner = self.inner.lock().unwrap();
            inner
                .active
                .as_mut()
                .filter(|active| {
                    generation_accepts_signals(
                        active.id,
                        active.deliberate,
                        active.failed_epoch,
                        generation,
                    ) && active.runtime.requested.contains(id)
                        && active.runtime.bindings.contains_key(id)
                })
                .and_then(|active| active.runtime.press(id))
        };
        if let Some(shortcut) = shortcut {
            (self.on_event)(PortalShortcutEvent {
                generation_id: generation,
                shortcut_id: id.into(),
                shortcut,
                is_pressed: true,
                synthetic: false,
            });
        }
    }
    fn deactivated(&self, generation: u64, id: &str) {
        let _dispatch = self.dispatch.lock().unwrap();
        let shortcut = {
            let mut inner = self.inner.lock().unwrap();
            inner
                .active
                .as_mut()
                .filter(|active| {
                    generation_accepts_signals(
                        active.id,
                        active.deliberate,
                        active.failed_epoch,
                        generation,
                    ) && active.runtime.requested.contains(id)
                })
                .and_then(|active| active.runtime.release(id))
        };
        if let Some(shortcut) = shortcut {
            (self.on_event)(PortalShortcutEvent {
                generation_id: generation,
                shortcut_id: id.into(),
                shortcut,
                is_pressed: false,
                synthetic: false,
            });
        }
    }
    fn changed(&self, generation: u64, bindings: HashMap<String, String>) {
        let _dispatch = self.dispatch.lock().unwrap();
        let update = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(candidate) = inner.candidates.get_mut(&generation) {
                if !candidate.failed {
                    candidate.bindings = Some(bindings);
                }
                return;
            }
            let can_configure_suppressed = inner.can_configure_suppressed;
            let Some(active) = inner.active.as_mut().filter(|active| {
                generation_accepts_signals(
                    active.id,
                    active.deliberate,
                    active.failed_epoch,
                    generation,
                )
            }) else {
                return;
            };
            let releases = active.runtime.update(bindings);
            let status =
                classify_active_runtime(&active.runtime, active.version, can_configure_suppressed);
            inner.status = status.clone();
            (releases, status)
        };
        for (id, shortcut) in update.0 {
            (self.on_event)(PortalShortcutEvent {
                generation_id: generation,
                shortcut_id: id,
                shortcut,
                is_pressed: false,
                synthetic: true,
            });
        }
        (self.on_status)(update.1);
    }

    fn lost(self: &Arc<Self>, generation: u64) {
        if self.shutdown.load(Ordering::Acquire) {
            return;
        }
        let loss = {
            let _dispatch = self.dispatch.lock().unwrap();
            if self.shutdown.load(Ordering::Acquire) {
                return;
            }
            let loss = {
                let mut inner = self.inner.lock().unwrap();
                fail_generation(&mut inner, generation)
            };
            let Some(loss) = loss else {
                return;
            };
            for (id, shortcut) in &loss.releases {
                (self.on_event)(PortalShortcutEvent {
                    generation_id: generation,
                    shortcut_id: id.clone(),
                    shortcut: shortcut.clone(),
                    is_pressed: false,
                    synthetic: true,
                });
            }
            (self.on_status)(loss.status.clone());
            loss
        };
        let state = self.clone();
        tokio::spawn(async move {
            state.recover(generation, loss.epoch, loss.specs).await;
        });
    }

    async fn recover(self: Arc<Self>, generation: u64, epoch: u64, specs: Vec<PortalShortcutSpec>) {
        loop {
            let owner_changed = self.owner_notify.notified();
            let shutdown = self.shutdown_notify.notified();
            tokio::pin!(owner_changed);
            tokio::pin!(shutdown);
            if self.shutdown.load(Ordering::Acquire) {
                return;
            }
            let ready = {
                let inner = self.inner.lock().unwrap();
                if !inner.active.as_ref().is_some_and(|active| {
                    active.id == generation
                        && active.failed_epoch == Some(epoch)
                        && !active.deliberate
                }) || inner.recovered_epoch >= epoch
                {
                    return;
                }
                inner.owner.is_some()
            };
            if ready {
                break;
            }
            tokio::select! { _ = &mut owner_changed => {}, _ = &mut shutdown => return }
        }
        let _operation = self.lifecycle.lock().await;
        {
            let mut inner = self.inner.lock().unwrap();
            if !inner.active.as_ref().is_some_and(|active| {
                active.id == generation && active.failed_epoch == Some(epoch) && !active.deliberate
            }) || inner.recovered_epoch >= epoch
                || self.shutdown.load(Ordering::Acquire)
            {
                return;
            }
            inner.recovered_epoch = epoch;
        }
        match self.bind_locked(specs, None).await {
            Ok(candidate) => {
                if let Err(error) = self.commit_locked(candidate).await {
                    self.restore(None, &error);
                }
            }
            Err(error) => self.restore(None, &error),
        }
    }

    async fn ensure_registered(self: &Arc<Self>, owner: &str) -> Result<(), String> {
        let app_id = AppID::from_str(APP_ID).map_err(|_| IDENTITY_UNAVAILABLE.to_string())?;
        let (notify, start) = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(result) = inner.registrations.get(owner) {
                return result.clone();
            }
            if let Some(notify) = inner.registration_flights.get(owner) {
                (notify.clone(), false)
            } else {
                let notify = Arc::new(Notify::new());
                inner
                    .registration_flights
                    .insert(owner.to_string(), notify.clone());
                (notify, true)
            }
        };
        if start {
            let state = self.clone();
            let connection = self.connection.clone();
            let owner = owner.to_string();
            let completion = notify.clone();
            tokio::spawn(async move {
                let registration = PortalClient::register(&connection, &owner, &app_id)
                    .await
                    .map_err(|_| IDENTITY_UNAVAILABLE.to_string());
                let cached = if registration.is_ok()
                    && !state.shutdown.load(Ordering::Acquire)
                    && current_owner(&connection).await.as_deref() == Ok(owner.as_str())
                {
                    match PortalClient::new(connection.clone(), owner.clone()).await {
                        Ok(portal)
                            if current_owner(&connection).await.as_deref()
                                == Ok(owner.as_str()) =>
                        {
                            let portal = Arc::new(portal);
                            Some(CachedPortal {
                                owner: portal.owner().to_string(),
                                version: portal.version(),
                                portal,
                            })
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let _dispatch = state.dispatch.lock().unwrap();
                let status = {
                    let mut inner = state.inner.lock().unwrap();
                    inner.registrations.insert(owner.clone(), registration);
                    inner.registration_flights.remove(&owner);
                    if !state.shutdown.load(Ordering::Acquire)
                        && inner.owner.as_deref() == Some(owner.as_str())
                    {
                        if let Some(cached) = cached {
                            inner.cached_portal = Some(cached);
                        }
                    }
                    let can_configure = configuration_is_available(
                        inner.owner.as_deref(),
                        inner
                            .owner
                            .as_deref()
                            .and_then(|owner| inner.registrations.get(owner)),
                        inner
                            .cached_portal
                            .as_ref()
                            .map(|cached| cached.owner.as_str()),
                    );
                    let status = refreshed_no_active_status(
                        &inner.status,
                        inner.active.is_some(),
                        inner.can_configure_suppressed,
                        can_configure && !state.shutdown.load(Ordering::Acquire),
                    );
                    if let Some(status) = &status {
                        inner.status = status.clone();
                    }
                    status
                };
                completion.notify_waiters();
                if let Some(status) = status {
                    (state.on_status)(status);
                }
            });
        }
        loop {
            let registered = notify.notified();
            let shutdown = self.shutdown_notify.notified();
            tokio::pin!(registered);
            tokio::pin!(shutdown);
            if let Some(result) = self.inner.lock().unwrap().registrations.get(owner).cloned() {
                return result;
            }
            if self.shutdown.load(Ordering::Acquire) {
                return Err("Shortcut portal is shutting down".into());
            }
            tokio::select! {
                _ = &mut registered => {}
                _ = &mut shutdown => return Err("Shortcut portal is shutting down".into()),
            }
        }
    }

    async fn ensure_portal(self: &Arc<Self>) -> Result<CachedPortal, String> {
        let owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => return Err(error.into()),
        };
        self.owner_changed(Some(owner.clone()));
        if let Some(cached) = self
            .inner
            .lock()
            .unwrap()
            .cached_portal
            .as_ref()
            .filter(|cached| cached.owner == owner)
            .cloned()
        {
            return Ok(cached);
        }
        self.ensure_registered(&owner).await?;
        if let Some(cached) = self
            .inner
            .lock()
            .unwrap()
            .cached_portal
            .as_ref()
            .filter(|cached| cached.owner == owner)
            .cloned()
        {
            return Ok(cached);
        }
        let observed_owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => return Err(error.into()),
        };
        if observed_owner != owner {
            self.owner_changed(Some(observed_owner));
            return Err("Desktop portal restarted during application registration".into());
        }
        let portal = Arc::new(
            self.until_shutdown(PortalClient::new(self.connection.clone(), owner.clone()))
                .await
                .map_err(str::to_string)?
                .map_err(|_| PORTAL_UNAVAILABLE.to_string())?,
        );
        let observed_owner = match self.until_shutdown(current_owner(&self.connection)).await {
            Ok(Ok(owner)) => owner,
            Ok(Err(_)) => {
                self.owner_changed(None);
                return Err(PORTAL_UNAVAILABLE.into());
            }
            Err(error) => return Err(error.into()),
        };
        if observed_owner != owner {
            self.owner_changed(Some(observed_owner));
            return Err("Desktop portal restarted while creating the shortcuts proxy".into());
        }
        let cached = CachedPortal {
            owner: portal.owner().to_string(),
            version: portal.version(),
            portal,
        };
        let _dispatch = self.dispatch.lock().unwrap();
        let mut inner = self.inner.lock().unwrap();
        if inner.owner.as_deref() != Some(owner.as_str()) {
            return Err("Desktop portal owner changed before proxy cache commit".into());
        }
        inner.cached_portal = Some(cached.clone());
        Ok(cached)
    }

    async fn start_owner_monitor(self: &Arc<Self>) -> Result<(), String> {
        let weak = Arc::downgrade(self);
        let connection = self.connection.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            monitor_owner(weak, connection, ready_tx).await;
        });
        *self.owner_task.lock().unwrap() = Some(task);
        let ready = ready_rx.await.unwrap_or_else(|_| {
            Err("Desktop portal owner monitor ended before initialization".into())
        });
        if ready.is_err() {
            let task = self.owner_task.lock().unwrap().take();
            if let Some(task) = task {
                let _ = task.await;
            }
        }
        ready
    }
    fn owner_changed(self: &Arc<Self>, owner: Option<String>) {
        let loss = {
            let _dispatch = self.dispatch.lock().unwrap();
            let loss = {
                let mut inner = self.inner.lock().unwrap();
                if inner.owner == owner {
                    return;
                }
                inner.owner = owner;
                inner.cached_portal = None;
                for health in inner.candidates.values_mut() {
                    health.failed = true;
                }
                inner
                    .active
                    .as_ref()
                    .map(|active| active.id)
                    .and_then(|generation| {
                        fail_generation(&mut inner, generation).map(|loss| (generation, loss))
                    })
            };
            if let Some((generation, loss)) = &loss {
                for (id, shortcut) in &loss.releases {
                    (self.on_event)(PortalShortcutEvent {
                        generation_id: *generation,
                        shortcut_id: id.clone(),
                        shortcut: shortcut.clone(),
                        is_pressed: false,
                        synthetic: true,
                    });
                }
                (self.on_status)(loss.status.clone());
            }
            loss
        };
        self.owner_notify.notify_waiters();
        if let Some((generation, loss)) = loss {
            let state = self.clone();
            tokio::spawn(async move {
                state.recover(generation, loss.epoch, loss.specs).await;
            });
        }
    }
    async fn until_shutdown<F: Future>(&self, future: F) -> Result<F::Output, &'static str> {
        let shutdown = self.shutdown_notify.notified();
        tokio::pin!(shutdown);
        if self.shutdown.load(Ordering::Acquire) {
            return Err("Shortcut portal is shutting down");
        }
        tokio::select! { biased; _ = &mut shutdown => Err("Shortcut portal is shutting down"), value = future => Ok(value) }
    }
    fn publish_initializing(&self) {
        let status = ShortcutBackendStatus::initializing();
        let _dispatch = self.dispatch.lock().unwrap();
        let published = {
            let mut inner = self.inner.lock().unwrap();
            inner.can_configure_suppressed = true;
            let active = inner
                .active
                .as_ref()
                .map(|active| (active.deliberate, active.failed_epoch));
            let published = initializing_can_publish(active);
            if published {
                inner.status = status.clone();
            }
            published
        };
        if published {
            (self.on_status)(status);
        }
    }
    fn publish_for_generation(
        &self,
        generation: u64,
        status: ShortcutBackendStatus,
        suppress_configure: bool,
    ) -> bool {
        let _dispatch = self.dispatch.lock().unwrap();
        let published = {
            let mut inner = self.inner.lock().unwrap();
            let published = inner.active.as_ref().is_some_and(|active| {
                generation_accepts_signals(
                    active.id,
                    active.deliberate,
                    active.failed_epoch,
                    generation,
                )
            });
            if published {
                inner.can_configure_suppressed = suppress_configure;
                inner.status = status.clone();
            }
            published
        };
        if published {
            (self.on_status)(status);
        }
        published
    }
    fn active_status(&self) -> Option<ShortcutBackendStatus> {
        let inner = self.inner.lock().unwrap();
        inner.active.as_ref().and_then(|active| {
            (!active.deliberate && active.failed_epoch.is_none()).then(|| {
                classify_active_runtime(
                    &active.runtime,
                    active.version,
                    inner.can_configure_suppressed,
                )
            })
        })
    }
    fn restore(&self, previous: Option<ShortcutBackendStatus>, error: &str) {
        let _dispatch = self.dispatch.lock().unwrap();
        let status = {
            let mut inner = self.inner.lock().unwrap();
            let owner = inner.owner.as_deref();
            let can_configure = configuration_is_available(
                owner,
                owner.and_then(|owner| inner.registrations.get(owner)),
                inner
                    .cached_portal
                    .as_ref()
                    .map(|cached| cached.owner.as_str()),
            );
            let status = match inner.active.as_ref() {
                Some(active) if !active.deliberate && active.failed_epoch.is_none() => Some(
                    classify_active_runtime(&active.runtime, active.version, false),
                ),
                Some(_) if previous.is_some() => None,

                _ => Some(ShortcutBackendStatus {
                    backend: ShortcutBackendKind::XdgPortal,
                    state: ShortcutBackendState::Unavailable,
                    message: Some(error.into()),
                    bindings: HashMap::new(),
                    can_configure,
                }),
            };
            if let Some(status) = &status {
                inner.can_configure_suppressed = false;
                inner.status = status.clone();
            }
            status
        };
        if let Some(status) = status {
            (self.on_status)(status);
        }
    }
    fn complete_initialize(&self, attempt: u64, result: Result<ShortcutBackendStatus, String>) {
        {
            let mut init = self.init.lock().unwrap();
            if !finish_init_flight(&mut init, attempt, result) {
                return;
            }
        }
        self.init_notify.notify_waiters();
    }

    fn cancel_initialize(&self, attempt: u64) {
        {
            let mut init = self.init.lock().unwrap();
            if !finish_init_flight(
                &mut init,
                attempt,
                Err("Shortcut portal initialization was cancelled".into()),
            ) {
                return;
            }
        }
        self.init_notify.notify_waiters();
    }

    fn cancel_configuration(&self, generation: u64) {
        let _dispatch = self.dispatch.lock().unwrap();
        let status = {
            let mut inner = self.inner.lock().unwrap();
            let status = inner.active.as_ref().and_then(|active| {
                generation_accepts_signals(
                    active.id,
                    active.deliberate,
                    active.failed_epoch,
                    generation,
                )
                .then(|| classify_active_runtime(&active.runtime, active.version, false))
            });
            if let Some(status) = &status {
                inner.can_configure_suppressed = false;
                inner.status = status.clone();
            }
            status
        };
        if let Some(status) = status {
            (self.on_status)(status);
        }
    }

    fn cancel_operation(&self) {
        let _dispatch = self.dispatch.lock().unwrap();
        let status = {
            let mut inner = self.inner.lock().unwrap();
            let owner = inner.owner.as_deref();
            let can_configure = configuration_is_available(
                owner,
                owner.and_then(|owner| inner.registrations.get(owner)),
                inner
                    .cached_portal
                    .as_ref()
                    .map(|cached| cached.owner.as_str()),
            );
            let status = match inner.active.as_ref() {
                Some(active) if !active.deliberate && active.failed_epoch.is_none() => Some(
                    classify_active_runtime(&active.runtime, active.version, false),
                ),
                Some(_) => None,
                None => Some(ShortcutBackendStatus {
                    backend: ShortcutBackendKind::XdgPortal,
                    state: ShortcutBackendState::Unavailable,
                    message: Some("Shortcut portal operation was cancelled".into()),
                    bindings: HashMap::new(),
                    can_configure,
                }),
            };
            if let Some(status) = &status {
                inner.can_configure_suppressed = false;
                inner.status = status.clone();
            }
            status
        };
        if let Some(status) = status {
            (self.on_status)(status);
        }
    }
    fn discard_candidate(&self, generation: u64) {
        let _dispatch = self.dispatch.lock().unwrap();
        self.inner.lock().unwrap().candidates.remove(&generation);
    }
}

async fn current_owner(connection: &Connection) -> Result<String, String> {
    let proxy = DBusProxy::new(connection)
        .await
        .map_err(|error| error.to_string())?;
    proxy
        .get_name_owner(BusName::try_from(PORTAL_NAME).map_err(|error| error.to_string())?)
        .await
        .map(|owner| owner.to_string())
        .map_err(|error| error.to_string())
}

async fn monitor_owner(
    state: Weak<PortalShortcutState>,
    connection: Connection,
    ready: tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    let proxy = match DBusProxy::new(&connection).await {
        Ok(proxy) => proxy,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "Failed to create desktop portal owner monitor: {error}"
            )));
            return;
        }
    };
    let mut stream = match proxy
        .receive_name_owner_changed_with_args(&[(0, PORTAL_NAME)])
        .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "Failed to subscribe to desktop portal owner changes: {error}"
            )));
            return;
        }
    };
    let bus_name = match BusName::try_from(PORTAL_NAME) {
        Ok(name) => name,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "Failed to parse desktop portal bus name: {error}"
            )));
            return;
        }
    };
    let owner = match proxy.get_name_owner(bus_name).await {
        Ok(owner) => Some(owner.to_string()),
        Err(ashpd::zbus::fdo::Error::NameHasNoOwner(_)) => None,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "Failed to reconcile desktop portal owner: {error}"
            )));
            return;
        }
    };
    let Some(current_state) = state.upgrade() else {
        let _ = ready.send(Err(
            "Desktop portal state ended before owner reconciliation".into(),
        ));
        return;
    };
    current_state.owner_changed(owner);
    drop(current_state);
    if ready.send(Ok(())).is_err() {
        return;
    }
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else { continue };
        let Some(state) = state.upgrade() else { return };
        state.owner_changed(args.new_owner().as_ref().map(ToString::to_string));
    }
    if let Some(state) = state.upgrade() {
        state.owner_changed(None);
    }
}
async fn best_effort_close(session: &PortalSession) {
    let _ = tokio::time::timeout(Duration::from_secs(2), session.close()).await;
}
async fn close_generation(mut generation: Generation) {
    generation.deliberate = true;
    for task in &generation.tasks {
        task.abort();
    }
    for task in generation.tasks.drain(..) {
        let _ = task.await;
    }
    best_effort_close(&generation.session).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    fn bindings(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(id, description)| ((*id).into(), (*description).into()))
            .collect()
    }

    fn setting(id: &str, description: &str, current_binding: &str) -> ShortcutBinding {
        ShortcutBinding {
            id: id.into(),
            name: id.into(),
            description: description.into(),
            default_binding: current_binding.into(),
            current_binding: current_binding.into(),
        }
    }

    #[test]
    fn route_selects_portal_only_for_linux_wayland_system_shortcuts() {
        for (is_linux, is_wayland, implementation, expected) in [
            (
                true,
                true,
                KeyboardImplementation::Tauri,
                ShortcutBackendKind::XdgPortal,
            ),
            (
                true,
                false,
                KeyboardImplementation::Tauri,
                ShortcutBackendKind::Tauri,
            ),
            (
                false,
                true,
                KeyboardImplementation::Tauri,
                ShortcutBackendKind::Tauri,
            ),
            (
                false,
                false,
                KeyboardImplementation::Tauri,
                ShortcutBackendKind::Tauri,
            ),
            (
                true,
                true,
                KeyboardImplementation::HandyKeys,
                ShortcutBackendKind::HandyKeys,
            ),
            (
                true,
                false,
                KeyboardImplementation::HandyKeys,
                ShortcutBackendKind::HandyKeys,
            ),
            (
                false,
                true,
                KeyboardImplementation::HandyKeys,
                ShortcutBackendKind::HandyKeys,
            ),
        ] {
            assert_eq!(
                resolve_shortcut_backend(is_linux, is_wayland, implementation),
                expected
            );
        }
    }

    #[test]
    fn modifier_parser_preserves_the_complete_main_key_suffix() {
        for (input, expected) in [
            ("ctrl+space", "CTRL+space"),
            ("ctrl+shift+space", "CTRL+SHIFT+space"),
            ("super+f8", "LOGO+F8"),
            ("alt+enter", "ALT+Return"),
            ("ctrl+;", "CTRL+semicolon"),
            ("ctrl+numpad +", "CTRL+KP_Add"),
            ("numpad +", "KP_Add"),
            ("numpad 7", "KP_7"),
            ("numpad *", "KP_Multiply"),
            ("numpad -", "KP_Subtract"),
            ("numpad .", "KP_Decimal"),
            ("numpad /", "KP_Divide"),
            ("shift+command+option+control+a", "CTRL+ALT+SHIFT+LOGO+a"),
            ("meta+escape", "LOGO+Escape"),
            ("win+page down", "LOGO+Page_Down"),
            ("win+page up", "LOGO+Page_Up"),
            ("caps lock", "Caps_Lock"),
            ("ctrl+capslock", "CTRL+Caps_Lock"),
        ] {
            assert_eq!(
                portal_trigger_from_binding(input).as_deref(),
                Ok(expected),
                "{input}"
            );
        }

        for input in [
            "+",
            "ctrl+",
            "ctrl+shift",
            "fn",
            "unknown key",
            "ctrl+alt+ctrl+a",
            "ctrl+numpad ++",
        ] {
            assert!(portal_trigger_from_binding(input).is_err(), "{input}");
        }
    }

    #[test]
    fn requested_specs_keep_stable_ids_descriptions_and_preferred_triggers() {
        let settings = HashMap::from([
            (
                PRIMARY_ID.into(),
                setting(PRIMARY_ID, "Start or stop transcription", "ctrl+space"),
            ),
            (
                POST_PROCESS_ID.into(),
                setting(
                    POST_PROCESS_ID,
                    "Transcribe and post-process",
                    "ctrl+numpad +",
                ),
            ),
            (
                "cancel".into(),
                setting("cancel", "Cancel transcription", "escape"),
            ),
        ]);

        let primary_only = shortcut_specs_from_settings(&settings, false).unwrap();
        assert_eq!(
            primary_only,
            vec![PortalShortcutSpec {
                id: PRIMARY_ID.into(),
                description: "Start or stop transcription".into(),
                preferred_trigger: "CTRL+space".into(),
            }]
        );

        let with_post_process = shortcut_specs_from_settings(&settings, true).unwrap();
        assert_eq!(
            with_post_process,
            vec![
                PortalShortcutSpec {
                    id: PRIMARY_ID.into(),
                    description: "Start or stop transcription".into(),
                    preferred_trigger: "CTRL+space".into(),
                },
                PortalShortcutSpec {
                    id: POST_PROCESS_ID.into(),
                    description: "Transcribe and post-process".into(),
                    preferred_trigger: "CTRL+KP_Add".into(),
                },
            ]
        );
        assert!(with_post_process.iter().all(|spec| spec.id != "cancel"));
    }

    #[test]
    fn classifier_uses_the_authoritative_subset_and_trigger_descriptions() {
        let requested = ids(&[PRIMARY_ID, POST_PROCESS_ID]);
        let complete_bindings = bindings(&[
            (PRIMARY_ID, "Ctrl+Space"),
            (POST_PROCESS_ID, "Ctrl+Shift+Space"),
        ]);
        let complete = classify_portal_bindings(&requested, &complete_bindings);
        assert_eq!(complete.state, ShortcutBackendState::Ready);
        assert_eq!(complete.message, None);
        assert_eq!(complete.bindings, complete_bindings);
        assert!(complete.can_configure);

        let primary_bindings = bindings(&[(PRIMARY_ID, "F8")]);
        let subset = classify_portal_bindings(&requested, &primary_bindings);
        assert_eq!(subset.state, ShortcutBackendState::Partial);
        assert_eq!(subset.message, None);
        assert_eq!(subset.bindings, primary_bindings);

        let secondary_bindings = bindings(&[(POST_PROCESS_ID, "F9")]);
        let missing_primary = classify_portal_bindings(&requested, &secondary_bindings);
        assert_eq!(missing_primary.state, ShortcutBackendState::Unavailable);
        assert_eq!(
            missing_primary.message.as_deref(),
            Some(PRIMARY_BINDING_MISSING)
        );
        assert_eq!(missing_primary.bindings, secondary_bindings);
        assert!(missing_primary.can_configure);

        let empty = classify_portal_bindings(&requested, &HashMap::new());
        assert_eq!(empty.state, ShortcutBackendState::Unavailable);
        assert_eq!(empty.message.as_deref(), Some(PRIMARY_BINDING_MISSING));
        assert!(empty.bindings.is_empty());

        let primary_requested = ids(&[PRIMARY_ID]);
        assert_eq!(
            classify_portal_bindings(&primary_requested, &bindings(&[(PRIMARY_ID, "Ctrl+Space")]))
                .state,
            ShortcutBackendState::Ready
        );
    }

    #[test]
    fn portal_version_controls_configuration_for_complete_bindings_only() {
        let requested = ids(&[PRIMARY_ID, POST_PROCESS_ID]);
        let ready = classify_portal_bindings(
            &requested,
            &bindings(&[(PRIMARY_ID, "F8"), (POST_PROCESS_ID, "Ctrl+F8")]),
        );
        let partial = classify_portal_bindings(&requested, &bindings(&[(PRIMARY_ID, "F8")]));
        let unavailable = classify_portal_bindings(&requested, &HashMap::new());

        assert!(!apply_configure_capability(ready.clone(), 1).can_configure);
        assert!(apply_configure_capability(partial, 1).can_configure);
        assert!(apply_configure_capability(unavailable, 1).can_configure);
        assert!(apply_configure_capability(ready, 2).can_configure);
    }

    #[test]
    fn duplicate_edges_are_idempotent_and_keep_trigger_descriptions() {
        let mut runtime = Runtime {
            requested: ids(&[PRIMARY_ID, POST_PROCESS_ID]),
            bindings: bindings(&[
                (PRIMARY_ID, "Ctrl+Space"),
                (POST_PROCESS_ID, "Ctrl+Shift+Space"),
            ]),
            pressed: HashSet::new(),
        };

        assert_eq!(runtime.press(PRIMARY_ID).as_deref(), Some("Ctrl+Space"));
        assert!(runtime.press(PRIMARY_ID).is_none());
        assert!(runtime.press("unknown").is_none());
        assert_eq!(runtime.release(PRIMARY_ID).as_deref(), Some("Ctrl+Space"));
        assert!(runtime.release(PRIMARY_ID).is_none());
        assert!(runtime.release("unknown").is_none());
    }

    #[test]
    fn binding_removal_releases_once_with_the_previous_trigger_description() {
        let requested = ids(&[PRIMARY_ID, POST_PROCESS_ID]);
        let mut runtime = Runtime {
            requested: requested.clone(),
            bindings: bindings(&[
                (PRIMARY_ID, "Ctrl+Space"),
                (POST_PROCESS_ID, "Ctrl+Shift+Space"),
            ]),
            pressed: HashSet::new(),
        };
        assert!(runtime.press(PRIMARY_ID).is_some());
        assert!(runtime.press(POST_PROCESS_ID).is_some());

        assert_eq!(
            runtime.update(bindings(&[(PRIMARY_ID, "F8")])),
            vec![(POST_PROCESS_ID.to_string(), "Ctrl+Shift+Space".to_string(),)]
        );
        assert_eq!(runtime.requested, requested);
        assert!(runtime.release(POST_PROCESS_ID).is_none());
        assert_eq!(runtime.release(PRIMARY_ID).as_deref(), Some("F8"));
        assert!(runtime.update(bindings(&[(PRIMARY_ID, "F8")])).is_empty());
    }

    #[test]
    fn draining_releases_every_pressed_binding_exactly_once() {
        let mut runtime = Runtime {
            requested: ids(&[PRIMARY_ID, POST_PROCESS_ID]),
            bindings: bindings(&[(PRIMARY_ID, "F8"), (POST_PROCESS_ID, "F9")]),
            pressed: HashSet::new(),
        };
        assert!(runtime.press(PRIMARY_ID).is_some());
        assert!(runtime.press(POST_PROCESS_ID).is_some());

        let mut releases = runtime.drain();
        releases.sort();
        assert_eq!(
            releases,
            vec![
                (PRIMARY_ID.to_string(), "F8".to_string()),
                (POST_PROCESS_ID.to_string(), "F9".to_string()),
            ]
        );
        assert!(runtime.drain().is_empty());
        assert!(runtime.release(PRIMARY_ID).is_none());
        assert!(runtime.release(POST_PROCESS_ID).is_none());
    }

    #[test]
    fn callback_gate_rejects_staged_retired_stale_and_unknown_events() {
        assert!(portal_callback_is_active(
            ShortcutBackendKind::XdgPortal,
            Some(7),
            7,
            true,
        ));
        for (backend, active, callback, known) in [
            (ShortcutBackendKind::Tauri, Some(7), 7, true),
            (ShortcutBackendKind::HandyKeys, Some(7), 7, true),
            (ShortcutBackendKind::XdgPortal, None, 7, true),
            (ShortcutBackendKind::XdgPortal, Some(7), 8, true),
            (ShortcutBackendKind::XdgPortal, Some(8), 7, true),
            (ShortcutBackendKind::XdgPortal, Some(7), 7, false),
        ] {
            assert!(
                !portal_callback_is_active(backend, active, callback, known),
                "{backend:?} {active:?} {callback} {known}"
            );
        }
    }

    #[test]
    fn failed_or_retired_generations_reject_late_signals() {
        assert!(generation_accepts_signals(7, false, None, 7));
        assert!(!generation_accepts_signals(7, false, Some(3), 7));
        assert!(!generation_accepts_signals(7, true, None, 7));
        assert!(!generation_accepts_signals(7, false, None, 8));
    }

    #[test]
    fn failed_active_loss_cannot_be_masked_by_candidate_initializing() {
        let unavailable = ShortcutBackendStatus {
            backend: ShortcutBackendKind::XdgPortal,
            state: ShortcutBackendState::Unavailable,
            message: Some("The desktop shortcut session ended unexpectedly".into()),
            bindings: HashMap::new(),
            can_configure: false,
        };
        let mut status = unavailable.clone();

        assert!(initializing_can_publish(None));
        assert!(initializing_can_publish(Some((false, None))));
        if initializing_can_publish(Some((false, Some(7)))) {
            status = ShortcutBackendStatus::initializing();
        }
        assert_eq!(status, unavailable);
        assert!(!initializing_can_publish(Some((true, None))));
    }
    #[test]
    fn candidate_commit_requires_live_health_and_the_same_unique_owner() {
        let healthy = CandidateHealth {
            owner: ":1.42".into(),
            failed: false,
            bindings: None,
        };
        assert!(candidate_can_commit(
            Some(&healthy),
            ":1.42",
            ":1.42",
            Some(":1.42"),
            Some(4),
            Some(4),
        ));

        let failed = CandidateHealth {
            owner: ":1.42".into(),
            failed: true,
            bindings: None,
        };
        assert!(!candidate_can_commit(
            Some(&failed),
            ":1.42",
            ":1.42",
            Some(":1.42"),
            Some(4),
            Some(4),
        ));
        assert!(!candidate_can_commit(
            None,
            ":1.42",
            ":1.42",
            Some(":1.42"),
            Some(4),
            Some(4),
        ));
        assert!(!candidate_can_commit(
            Some(&healthy),
            ":1.42",
            ":1.43",
            Some(":1.43"),
            Some(4),
            Some(4),
        ));
        assert!(!candidate_can_commit(
            Some(&healthy),
            ":1.42",
            ":1.42",
            Some(":1.43"),
            Some(4),
            Some(4),
        ));
        assert!(!candidate_can_commit(
            Some(&healthy),
            ":1.42",
            ":1.42",
            Some(":1.42"),
            Some(5),
            Some(4),
        ));
    }

    #[test]
    fn candidate_loss_marks_shared_health_before_commit() {
        let mut inner = Inner {
            status: ShortcutBackendStatus::initializing(),
            next_generation: 10,
            active: None,
            candidates: HashMap::from([(
                9,
                CandidateHealth {
                    owner: ":1.42".into(),
                    failed: false,
                    bindings: None,
                },
            )]),
            registrations: HashMap::new(),
            registration_flights: HashMap::new(),
            cached_portal: None,
            owner: Some(":1.42".into()),
            loss_epoch: 0,
            recovered_epoch: 0,
            last_specs: None,
            can_configure_suppressed: false,
        };

        assert!(fail_generation(&mut inner, 9).is_none());
        let health = inner.candidates.get(&9).unwrap();
        assert!(health.failed);
        assert!(!candidate_can_commit(
            Some(health),
            ":1.42",
            ":1.42",
            inner.owner.as_deref(),
            None,
            None,
        ));
        assert_eq!(inner.loss_epoch, 0);
    }

    #[test]
    fn candidate_commit_uses_latest_ordered_binding_snapshot() {
        let mut runtime = Runtime {
            requested: ids(&[PRIMARY_ID, POST_PROCESS_ID]),
            bindings: bindings(&[(PRIMARY_ID, "F8"), (POST_PROCESS_ID, "Ctrl+F8")]),
            pressed: HashSet::new(),
        };
        let health = CandidateHealth {
            owner: ":1.42".into(),
            failed: false,
            bindings: Some(bindings(&[(PRIMARY_ID, "F9")])),
        };

        let status = apply_candidate_bindings(&mut runtime, &health, 1);
        assert_eq!(status.state, ShortcutBackendState::Partial);
        assert_eq!(status.bindings, bindings(&[(PRIMARY_ID, "F9")]));
        assert_eq!(runtime.bindings, status.bindings);

        let removed_primary = CandidateHealth {
            bindings: Some(HashMap::new()),
            ..health
        };
        assert_eq!(
            apply_candidate_bindings(&mut runtime, &removed_primary, 1).state,
            ShortcutBackendState::Unavailable
        );
    }
    #[test]
    fn configuration_requires_current_registered_owner_and_cached_interface() {
        let registered: Result<(), String> = Ok(());
        let rejected = Err("registration rejected".to_string());

        assert!(configuration_is_available(
            Some(":1.42"),
            Some(&registered),
            Some(":1.42"),
        ));
        assert!(!configuration_is_available(
            None,
            Some(&registered),
            Some(":1.42"),
        ));
        assert!(!configuration_is_available(
            Some(":1.42"),
            None,
            Some(":1.42"),
        ));
        assert!(!configuration_is_available(
            Some(":1.42"),
            Some(&rejected),
            Some(":1.42"),
        ));
        assert!(!configuration_is_available(
            Some(":1.42"),
            Some(&registered),
            None,
        ));
        assert!(!configuration_is_available(
            Some(":1.42"),
            Some(&registered),
            Some(":1.43"),
        ));
    }

    #[test]
    fn completed_portal_cache_only_reenables_a_cancelled_idle_status() {
        let cancelled = ShortcutBackendStatus {
            backend: ShortcutBackendKind::XdgPortal,
            state: ShortcutBackendState::Unavailable,
            message: Some("Shortcut portal operation was cancelled".into()),
            bindings: HashMap::new(),
            can_configure: false,
        };
        let refreshed =
            refreshed_no_active_status(&cancelled, false, false, true).expect("idle retry");
        assert!(refreshed.can_configure);
        assert_eq!(refreshed.message, cancelled.message);

        assert!(refreshed_no_active_status(&cancelled, true, false, true).is_none());
        assert!(refreshed_no_active_status(&cancelled, false, true, true).is_none());
        assert!(refreshed_no_active_status(&cancelled, false, false, false).is_none());
        assert!(refreshed_no_active_status(
            &ShortcutBackendStatus::initializing(),
            false,
            false,
            true,
        )
        .is_none());
    }
    #[test]
    fn active_binding_changes_stay_non_configurable_while_operation_is_suppressed() {
        let runtime = Runtime {
            requested: ids(&[PRIMARY_ID]),
            bindings: bindings(&[(PRIMARY_ID, "F8")]),
            pressed: HashSet::new(),
        };

        assert!(classify_active_runtime(&runtime, 2, false).can_configure);
        assert!(!classify_active_runtime(&runtime, 2, true).can_configure);
    }

    #[test]
    fn cancelled_initialize_flight_finishes_followers_and_allows_retry() {
        let mut init = InitFlight {
            running: true,
            attempt: 7,
            result: None,
        };
        assert!(!finish_init_flight(
            &mut init,
            6,
            Err("stale cancellation".into()),
        ));
        assert!(init.running);

        assert!(finish_init_flight(
            &mut init,
            7,
            Err("Shortcut portal initialization was cancelled".into()),
        ));
        assert!(!init.running);
        assert!(init.result.as_ref().unwrap().1.is_err());

        init.running = true;
        init.attempt = 8;
        let ready = ShortcutBackendStatus::static_ready(ShortcutBackendKind::XdgPortal);
        assert!(finish_init_flight(&mut init, 8, Ok(ready.clone())));
        assert_eq!(init.result, Some((8, Ok(ready))));
    }
}
