//! Keyboard shortcut management and runtime backend routing.

mod handler;
pub mod handy_keys;
#[cfg(target_os = "linux")]
mod portal_dbus;
#[cfg(target_os = "linux")]
pub mod portal_impl;
pub mod tauri_impl;

#[cfg(target_os = "linux")]
pub use portal_impl::{ShortcutBackendKind, ShortcutBackendState, ShortcutBackendStatus};

use log::{debug, error, info, warn};
use parking_lot::{Mutex, RwLock};
#[cfg(not(target_os = "linux"))]
use serde::Deserialize;
use serde::Serialize;
use specta::Type;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{Mutex as AsyncMutex, Notify};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::settings::APPLE_INTELLIGENCE_DEFAULT_MODEL_ID;
use crate::settings::{
    self, get_settings, AutoSubmitKey, ClipboardHandling, KeyboardImplementation, LLMPrompt,
    OverlayPosition, OverlayStyle, PasteMethod, ProgressiveOutputDestination, ShortcutBinding,
    SoundTheme, Theme, TypingTool, VadBackend, APPLE_INTELLIGENCE_PROVIDER_ID,
};
use crate::tray;
#[cfg(target_os = "linux")]
use ashpd::WindowIdentifier;
#[cfg(target_os = "linux")]
use raw_window_handle::{HasDisplayHandle, HasWindowHandle};

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutBackendKind {
    Tauri,
    XdgPortal,
    HandyKeys,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutBackendState {
    Initializing,
    Ready,
    Partial,
    Unavailable,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ShortcutBackendStatus {
    pub backend: ShortcutBackendKind,
    pub state: ShortcutBackendState,
    pub message: Option<String>,
    pub bindings: HashMap<String, String>,
    pub can_configure: bool,
}

#[cfg(not(target_os = "linux"))]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortcutDispatchSource {
    Tauri,
    HandyKeys,
    Portal(u64),
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct RetiringPortalReleases {
    generation: u64,
    binding_ids: HashSet<String>,
}

#[derive(Clone)]
struct ShortcutBackendRuntimeSnapshot {
    active: Option<ShortcutDispatchSource>,
    #[cfg(target_os = "linux")]
    retiring_portal: Option<RetiringPortalReleases>,
    status: ShortcutBackendStatus,
}

/// Managed runtime gate. On Linux its single lock is the atomic commit point
/// for dispatch ownership and frontend-visible backend status.
pub struct ShortcutBackendRuntimeState {
    snapshot: RwLock<ShortcutBackendRuntimeSnapshot>,
    pub operation: AsyncMutex<()>,
}

impl Default for ShortcutBackendRuntimeState {
    fn default() -> Self {
        Self {
            snapshot: RwLock::new(ShortcutBackendRuntimeSnapshot {
                active: None,
                #[cfg(target_os = "linux")]
                retiring_portal: None,
                status: initializing_status(ShortcutBackendKind::Tauri),
            }),
            operation: AsyncMutex::new(()),
        }
    }
}

impl ShortcutBackendRuntimeState {
    fn commit(&self, source: ShortcutDispatchSource, status: ShortcutBackendStatus) {
        *self.snapshot.write() = ShortcutBackendRuntimeSnapshot {
            active: Some(source),
            #[cfg(target_os = "linux")]
            retiring_portal: None,
            status,
        };
    }

    #[cfg(target_os = "linux")]
    fn commit_with_retiring_portal(
        &self,
        source: ShortcutDispatchSource,
        status: ShortcutBackendStatus,
        retiring_portal: Option<(u64, HashSet<String>)>,
    ) {
        *self.snapshot.write() = ShortcutBackendRuntimeSnapshot {
            active: Some(source),
            retiring_portal: retiring_portal.map(|(generation, binding_ids)| {
                RetiringPortalReleases {
                    generation,
                    binding_ids,
                }
            }),
            status,
        };
    }

    #[cfg(target_os = "linux")]
    fn finish_portal_retirement(&self, generation: Option<u64>) {
        let mut snapshot = self.snapshot.write();
        if snapshot
            .retiring_portal
            .as_ref()
            .map(|retiring| retiring.generation)
            == generation
        {
            snapshot.retiring_portal = None;
        }
    }

    fn set_status(&self, status: ShortcutBackendStatus) {
        self.snapshot.write().status = status;
    }

    fn status(&self) -> ShortcutBackendStatus {
        self.snapshot.read().status.clone()
    }
}

#[cfg(target_os = "linux")]
fn callback_matches_runtime(
    active: Option<ShortcutDispatchSource>,
    retiring_portal: &mut Option<RetiringPortalReleases>,
    source: ShortcutDispatchSource,
    binding_id: &str,
    is_pressed: bool,
) -> bool {
    let known_binding = matches!(binding_id, "transcribe" | "transcribe_with_post_process");
    match (active, source) {
        (Some(ShortcutDispatchSource::Tauri), ShortcutDispatchSource::Tauri) => true,
        (Some(ShortcutDispatchSource::HandyKeys), ShortcutDispatchSource::HandyKeys) => {
            if is_pressed {
                if let Some(retiring) = retiring_portal {
                    retiring.binding_ids.remove(binding_id);
                }
            }
            true
        }
        (
            Some(ShortcutDispatchSource::Portal(active_generation)),
            ShortcutDispatchSource::Portal(callback_generation),
        ) => portal_impl::portal_callback_is_active(
            ShortcutBackendKind::XdgPortal,
            Some(active_generation),
            callback_generation,
            known_binding,
        ),
        (
            Some(ShortcutDispatchSource::HandyKeys),
            ShortcutDispatchSource::Portal(callback_generation),
        ) => {
            !is_pressed
                && known_binding
                && retiring_portal.as_mut().is_some_and(|retiring| {
                    retiring.generation == callback_generation
                        && retiring.binding_ids.remove(binding_id)
                })
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
pub fn shortcut_callback_is_active(
    app: &AppHandle,
    source: ShortcutDispatchSource,
    binding_id: &str,
    is_pressed: bool,
) -> bool {
    let Some(runtime) = app.try_state::<ShortcutBackendRuntimeState>() else {
        return false;
    };
    let mut snapshot = runtime.snapshot.write();
    let active = snapshot.active;
    callback_matches_runtime(
        active,
        &mut snapshot.retiring_portal,
        source,
        binding_id,
        is_pressed,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn shortcut_callback_is_active(
    _app: &AppHandle,
    _source: ShortcutDispatchSource,
    _binding_id: &str,
    _is_pressed: bool,
) -> bool {
    true
}

#[derive(Default)]
struct InitializationFlight {
    running: bool,
    attempt: u64,
    result: Option<(u64, Result<ShortcutBackendStatus, String>)>,
    successful: bool,
}

/// Managed single-flight state for the public initialization command.
pub struct ShortcutInitializationState {
    flight: Mutex<InitializationFlight>,
    notify: Notify,
}

impl Default for ShortcutInitializationState {
    fn default() -> Self {
        Self {
            flight: Mutex::new(InitializationFlight::default()),
            notify: Notify::new(),
        }
    }
}

struct InitializationLeaderGuard<'a> {
    initialization: &'a ShortcutInitializationState,
    attempt: u64,
    armed: bool,
}

impl Drop for InitializationLeaderGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut flight = self.initialization.flight.lock();
        if flight.running && flight.attempt == self.attempt {
            flight.running = false;
            flight.result = Some((
                self.attempt,
                Err("Shortcut initialization attempt was cancelled".into()),
            ));
        }
        drop(flight);
        self.initialization.notify.notify_waiters();
    }
}

#[cfg(target_os = "linux")]
pub struct PortalShortcutStateHolder {
    construction: AsyncMutex<()>,
    state: RwLock<Option<Arc<portal_impl::PortalShortcutState>>>,
    status: Mutex<ShortcutBackendStatus>,
}

#[cfg(target_os = "linux")]
impl Default for PortalShortcutStateHolder {
    fn default() -> Self {
        Self {
            construction: AsyncMutex::new(()),
            state: RwLock::new(None),
            status: Mutex::new(initializing_status(ShortcutBackendKind::XdgPortal)),
        }
    }
}

#[cfg(target_os = "linux")]
impl PortalShortcutStateHolder {
    pub fn current(&self) -> Option<Arc<portal_impl::PortalShortcutState>> {
        self.state.read().clone()
    }

    fn status(&self) -> ShortcutBackendStatus {
        self.status.lock().clone()
    }

    fn publish(&self, app: &AppHandle, status: ShortcutBackendStatus) {
        *self.status.lock() = status.clone();
        if resolved_backend(settings::get_settings(app).keyboard_implementation)
            != ShortcutBackendKind::XdgPortal
        {
            return;
        }
        if let Some(generation) = self
            .current()
            .and_then(|state| state.active_generation_id())
        {
            if let Some(runtime) = app.try_state::<ShortcutBackendRuntimeState>() {
                runtime.commit(ShortcutDispatchSource::Portal(generation), status.clone());
            }
            let _ = app.emit("shortcut-backend-status-changed", status);
        } else {
            if let Some(runtime) = app.try_state::<ShortcutBackendRuntimeState>() {
                runtime.set_status(status.clone());
            }
            let _ = app.emit("shortcut-backend-status-changed", status);
        }
    }

    async fn get_or_create(
        &self,
        app: &AppHandle,
    ) -> Result<Arc<portal_impl::PortalShortcutState>, String> {
        if let Some(state) = self.current() {
            return Ok(state);
        }
        let _construction = self.construction.lock().await;
        if let Some(state) = self.current() {
            return Ok(state);
        }

        let event_app = app.clone();
        let on_event: portal_impl::PortalEventHandler = Arc::new(move |event| {
            handler::handle_shortcut_event(
                &event_app,
                ShortcutDispatchSource::Portal(event.generation_id),
                &event.shortcut_id,
                &event.shortcut,
                event.is_pressed,
            );
        });
        let status_app = app.clone();
        let on_status: portal_impl::PortalStatusHandler = Arc::new(move |status| {
            if let Some(holder) = status_app.try_state::<PortalShortcutStateHolder>() {
                holder.publish(&status_app, status);
            }
        });

        match portal_impl::PortalShortcutState::new(on_event, on_status).await {
            Ok(state) => {
                *self.state.write() = Some(state.clone());
                Ok(state)
            }
            Err(error) => {
                let status =
                    unavailable_status(ShortcutBackendKind::XdgPortal, error.clone(), false);
                self.publish(app, status);
                Err(error)
            }
        }
    }
}

fn initializing_status(backend: ShortcutBackendKind) -> ShortcutBackendStatus {
    ShortcutBackendStatus {
        backend,
        state: ShortcutBackendState::Initializing,
        message: None,
        bindings: HashMap::new(),
        can_configure: false,
    }
}

fn unavailable_status(
    backend: ShortcutBackendKind,
    message: String,
    can_configure: bool,
) -> ShortcutBackendStatus {
    ShortcutBackendStatus {
        backend,
        state: ShortcutBackendState::Unavailable,
        message: Some(message),
        bindings: HashMap::new(),
        can_configure,
    }
}
fn resolved_backend(implementation: KeyboardImplementation) -> ShortcutBackendKind {
    #[cfg(target_os = "linux")]
    {
        portal_impl::resolve_shortcut_backend(true, crate::utils::is_wayland(), implementation)
    }
    #[cfg(not(target_os = "linux"))]
    {
        match implementation {
            KeyboardImplementation::Tauri => ShortcutBackendKind::Tauri,
            KeyboardImplementation::HandyKeys => ShortcutBackendKind::HandyKeys,
        }
    }
}

fn publish_runtime_status(
    app: &AppHandle,
    source: Option<ShortcutDispatchSource>,
    status: ShortcutBackendStatus,
) {
    if let Some(runtime) = app.try_state::<ShortcutBackendRuntimeState>() {
        if let Some(source) = source {
            runtime.commit(source, status.clone());
        } else {
            runtime.set_status(status.clone());
        }
    }
    let _ = app.emit("shortcut-backend-status-changed", status);
}

#[cfg(target_os = "linux")]
async fn portal_parent(app: &AppHandle) -> Option<WindowIdentifier> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let parent_app = app.clone();
    if let Err(error) = app.run_on_main_thread(move || {
        let handles = (|| {
            let window = parent_app
                .get_webview_window("main")
                .ok_or_else(|| "The main window is unavailable".to_string())?;
            let window_handle = window
                .window_handle()
                .map_err(|error| format!("Could not obtain the main window handle: {error}"))?
                .as_raw();
            let display_handle = window.display_handle().ok().map(|handle| handle.as_raw());
            Ok::<_, String>((window_handle, display_handle))
        })();

        match handles {
            Ok((window_handle, display_handle)) => {
                gtk::glib::MainContext::default().spawn_local(async move {
                    let parent =
                        WindowIdentifier::from_raw_handle(&window_handle, display_handle.as_ref())
                            .await;
                    let _ = sender.send(parent);
                });
            }
            Err(error) => {
                warn!("{error}");
                let _ = sender.send(None);
            }
        }
    }) {
        warn!("Could not schedule portal parent export on the main thread: {error}");
        return None;
    }

    let parent = match receiver.await {
        Ok(parent) => parent,
        Err(error) => {
            warn!("Portal parent export did not complete: {error}");
            None
        }
    };
    if parent.is_none() {
        warn!("Opening the desktop shortcut dialog without a parent window");
    }
    parent
}

#[cfg(target_os = "linux")]
fn portal_specs(
    settings: &crate::settings::AppSettings,
) -> Result<Vec<portal_impl::PortalShortcutSpec>, String> {
    portal_impl::shortcut_specs_from_settings(&settings.bindings, settings.post_process_enabled)
}

async fn initialize_backend(app: &AppHandle) -> Result<ShortcutBackendStatus, String> {
    let runtime = app
        .try_state::<ShortcutBackendRuntimeState>()
        .ok_or("ShortcutBackendRuntimeState is not managed")?;
    let _operation = runtime.operation.lock().await;
    let user_settings = settings::load_or_create_app_settings(app);
    let backend = resolved_backend(user_settings.keyboard_implementation);
    publish_runtime_status(app, None, initializing_status(backend));

    match backend {
        ShortcutBackendKind::Tauri => {
            tauri_impl::init_shortcuts(app);
            let status = ShortcutBackendStatus::static_ready(ShortcutBackendKind::Tauri);
            publish_runtime_status(app, Some(ShortcutDispatchSource::Tauri), status.clone());
            Ok(status)
        }
        ShortcutBackendKind::HandyKeys => {
            if let Err(error) = handy_keys::init_shortcuts(app) {
                let status =
                    unavailable_status(ShortcutBackendKind::HandyKeys, error.clone(), false);
                publish_runtime_status(app, None, status);
                return Err(error);
            }
            let status = ShortcutBackendStatus::static_ready(ShortcutBackendKind::HandyKeys);
            publish_runtime_status(app, Some(ShortcutDispatchSource::HandyKeys), status.clone());
            Ok(status)
        }
        ShortcutBackendKind::XdgPortal => {
            #[cfg(target_os = "linux")]
            {
                let holder = app
                    .try_state::<PortalShortcutStateHolder>()
                    .ok_or("PortalShortcutStateHolder is not managed")?;
                let state = holder.get_or_create(app).await?;
                let specs = match portal_specs(&user_settings) {
                    Ok(specs) => specs,
                    Err(error) => {
                        holder.publish(
                            app,
                            unavailable_status(
                                ShortcutBackendKind::XdgPortal,
                                error.clone(),
                                false,
                            ),
                        );
                        return Err(error);
                    }
                };
                state.initialize(specs, portal_parent(app).await).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("portal routing is Linux-only")
            }
        }
    }
}

/// Initialize the resolved shortcut backend. Concurrent callers share the
/// same attempt and result; only a later call retries a failed attempt.
pub async fn init_shortcuts(app: &AppHandle) -> Result<ShortcutBackendStatus, String> {
    enum Role {
        Leader(u64),
        Follower(u64),
    }

    let initialization = app
        .try_state::<ShortcutInitializationState>()
        .ok_or("ShortcutInitializationState is not managed")?;
    let role = {
        let mut flight = initialization.flight.lock();
        if flight.successful {
            return Ok(get_shortcut_backend_status(app.clone()));
        }
        if flight.running {
            Role::Follower(flight.attempt)
        } else {
            flight.running = true;
            flight.attempt += 1;
            Role::Leader(flight.attempt)
        }
    };

    if let Role::Follower(attempt) = role {
        loop {
            let notified = initialization.notify.notified();
            if let Some(result) = initialization
                .flight
                .lock()
                .result
                .as_ref()
                .filter(|(completed, _)| *completed == attempt)
                .map(|(_, result)| result.clone())
            {
                return result;
            }
            notified.await;
        }
    }

    let Role::Leader(attempt) = role else {
        unreachable!()
    };
    let mut leader = InitializationLeaderGuard {
        initialization: &initialization,
        attempt,
        armed: true,
    };
    let result = initialize_backend(app).await;
    {
        let mut flight = initialization.flight.lock();
        flight.running = false;
        flight.successful = result.as_ref().is_ok_and(|status| {
            matches!(
                status.state,
                ShortcutBackendState::Ready | ShortcutBackendState::Partial
            )
        });
        flight.result = Some((attempt, result.clone()));
        leader.armed = false;
    }
    initialization.notify.notify_waiters();
    result
}

#[tauri::command]
#[specta::specta]
pub fn get_shortcut_backend_status(app: AppHandle) -> ShortcutBackendStatus {
    let settings = settings::get_settings(&app);
    let backend = resolved_backend(settings.keyboard_implementation);
    #[cfg(target_os = "linux")]
    if backend == ShortcutBackendKind::XdgPortal {
        return app
            .try_state::<PortalShortcutStateHolder>()
            .map(|holder| holder.status())
            .unwrap_or_else(|| {
                unavailable_status(
                    ShortcutBackendKind::XdgPortal,
                    "PortalShortcutStateHolder is not managed".into(),
                    false,
                )
            });
    }

    app.try_state::<ShortcutBackendRuntimeState>()
        .map(|runtime| runtime.status())
        .filter(|status| status.backend == backend)
        .unwrap_or_else(|| initializing_status(backend))
}

#[tauri::command]
#[specta::specta]
pub async fn configure_system_shortcuts(app: AppHandle) -> Result<ShortcutBackendStatus, String> {
    #[cfg(target_os = "linux")]
    {
        let runtime = app
            .try_state::<ShortcutBackendRuntimeState>()
            .ok_or("ShortcutBackendRuntimeState is not managed")?;
        let _operation = runtime.operation.lock().await;
        let settings = settings::get_settings(&app);
        if resolved_backend(settings.keyboard_implementation) != ShortcutBackendKind::XdgPortal {
            return Err("System shortcuts are not managed by the desktop".into());
        }
        let holder = app
            .try_state::<PortalShortcutStateHolder>()
            .ok_or("PortalShortcutStateHolder is not managed")?;
        let state = holder.get_or_create(&app).await?;
        let parent = portal_parent(&app).await;
        if state.active_generation_id().is_some() {
            state.configure(parent).await
        } else {
            state.initialize(portal_specs(&settings)?, parent).await
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        Err("System shortcuts are not managed by the desktop".into())
    }
}

/// Register the cancel shortcut (called when recording starts)
pub fn register_cancel_shortcut(app: &AppHandle) {
    // Track recording lifecycle independently of the current implementation so
    // switching implementations mid-recording cannot leave stale fallback state.
    crate::secure_input::register_cancel_fallback(app);

    let settings = get_settings(app);
    match resolved_backend(settings.keyboard_implementation) {
        ShortcutBackendKind::Tauri => tauri_impl::register_cancel_shortcut(app),
        ShortcutBackendKind::HandyKeys => handy_keys::register_cancel_shortcut(app),
        ShortcutBackendKind::XdgPortal => {}
    }
}

/// Unregister the cancel shortcut (called when recording stops)
pub fn unregister_cancel_shortcut(app: &AppHandle) {
    crate::secure_input::unregister_cancel_fallback(app);

    let settings = get_settings(app);
    match resolved_backend(settings.keyboard_implementation) {
        ShortcutBackendKind::Tauri => tauri_impl::unregister_cancel_shortcut(app),
        ShortcutBackendKind::HandyKeys => handy_keys::unregister_cancel_shortcut(app),
        ShortcutBackendKind::XdgPortal => {}
    }
}

/// Register a shortcut using the appropriate implementation
pub fn register_shortcut(app: &AppHandle, binding: ShortcutBinding) -> Result<(), String> {
    let settings = get_settings(app);
    match resolved_backend(settings.keyboard_implementation) {
        ShortcutBackendKind::Tauri => tauri_impl::register_shortcut(app, binding),
        ShortcutBackendKind::HandyKeys => handy_keys::register_shortcut(app, binding),
        ShortcutBackendKind::XdgPortal => {
            Err("Portal shortcuts are configured by the desktop".into())
        }
    }
}

/// Unregister a shortcut using the appropriate implementation
pub fn unregister_shortcut(app: &AppHandle, binding: ShortcutBinding) -> Result<(), String> {
    let settings = get_settings(app);
    match resolved_backend(settings.keyboard_implementation) {
        ShortcutBackendKind::Tauri => tauri_impl::unregister_shortcut(app, binding),
        ShortcutBackendKind::HandyKeys => handy_keys::unregister_shortcut(app, binding),
        ShortcutBackendKind::XdgPortal => {
            Err("Portal shortcuts are configured by the desktop".into())
        }
    }
}

// ============================================================================
// Binding Management Commands
// ============================================================================

#[derive(Serialize, Type)]
pub struct BindingResponse {
    success: bool,
    binding: Option<ShortcutBinding>,
    error: Option<String>,
}

#[tauri::command]
#[specta::specta]
pub fn change_binding(
    app: AppHandle,
    id: String,
    binding: String,
) -> Result<BindingResponse, String> {
    if resolved_backend(settings::get_settings(&app).keyboard_implementation)
        == ShortcutBackendKind::XdgPortal
    {
        return Err("Portal shortcuts are configured by the desktop".into());
    }
    // Reject empty bindings — every shortcut should have a value
    if binding.trim().is_empty() {
        return Err("Binding cannot be empty".to_string());
    }

    let mut settings = settings::get_settings(&app);

    // Get the binding to modify, or create it from defaults if it doesn't exist
    let binding_to_modify = match settings.bindings.get(&id) {
        Some(binding) => binding.clone(),
        None => {
            // Try to get the default binding for this id
            let default_settings = settings::get_default_settings();
            match default_settings.bindings.get(&id) {
                Some(default_binding) => {
                    warn!(
                        "Binding '{}' not found in settings, creating from defaults",
                        id
                    );
                    default_binding.clone()
                }
                None => {
                    let error_msg = format!("Binding with id '{}' not found in defaults", id);
                    warn!("change_binding error: {}", error_msg);
                    return Ok(BindingResponse {
                        success: false,
                        binding: None,
                        error: Some(error_msg),
                    });
                }
            }
        }
    };

    // If this is the cancel binding, just update the settings and return
    // It's managed dynamically, so we don't register/unregister here
    if id == "cancel" {
        if let Some(mut b) = settings.bindings.get(&id).cloned() {
            b.current_binding = binding;
            settings.bindings.insert(id.clone(), b.clone());
            settings::write_settings(&app, settings);
            crate::secure_input::reconcile_fallback(&app);
            return Ok(BindingResponse {
                success: true,
                binding: Some(b.clone()),
                error: None,
            });
        }
    }

    // Unregister the existing binding
    if let Err(e) = unregister_shortcut(&app, binding_to_modify.clone()) {
        let error_msg = format!("Failed to unregister shortcut: {}", e);
        error!("change_binding error: {}", error_msg);
    }

    // Validate the new shortcut for the current keyboard implementation
    if let Err(e) = validate_shortcut_for_implementation(&binding, settings.keyboard_implementation)
    {
        warn!("change_binding validation error: {}", e);
        restore_registration(&app, &binding_to_modify);
        return Err(e);
    }

    // Create an updated binding
    let mut updated_binding = binding_to_modify.clone();
    updated_binding.current_binding = binding;

    // Register the new binding
    if let Err(e) = register_shortcut(&app, updated_binding.clone()) {
        let error_msg = format!("Failed to register shortcut: {}", e);
        error!("change_binding error: {}", error_msg);
        restore_registration(&app, &binding_to_modify);
        return Ok(BindingResponse {
            success: false,
            binding: None,
            error: Some(error_msg),
        });
    }

    // Update the binding in the settings
    settings.bindings.insert(id, updated_binding.clone());

    // Save the settings and synchronize any active Secure Input shadows.
    settings::write_settings(&app, settings);
    crate::secure_input::reconcile_fallback(&app);

    // Return the updated binding
    Ok(BindingResponse {
        success: true,
        binding: Some(updated_binding),
        error: None,
    })
}

/// Best-effort re-register of the previous binding after a failed change,
/// so a failure leaves the user's shortcut working exactly as before.
fn restore_registration(app: &AppHandle, binding: &ShortcutBinding) {
    if let Err(e) = register_shortcut(app, binding.clone()) {
        error!(
            "Failed to restore previous binding '{}' ({}): {}",
            binding.id, binding.current_binding, e
        );
    }
}

#[tauri::command]
#[specta::specta]
pub fn reset_binding(app: AppHandle, id: String) -> Result<BindingResponse, String> {
    let binding = settings::get_stored_binding(&app, &id);
    change_binding(app, id, binding.default_binding)
}

/// Unregister every binding while the user is recording a new shortcut in
/// the UI, so no existing shortcut can fire — or swallow the keystrokes —
/// mid-capture. The "cancel" binding is untouched: it is managed dynamically
/// by the recording lifecycle.
pub fn suspend_all_shortcuts(app: &AppHandle) {
    for (id, binding) in settings::get_bindings(app) {
        if id == "cancel" {
            continue;
        }
        if let Err(e) = unregister_shortcut(app, binding) {
            debug!(
                "suspend_all_shortcuts: could not unregister '{}': {}",
                id, e
            );
        }
    }
}

/// Re-register every binding from settings after shortcut recording ends.
/// Registering an already-registered shortcut fails cleanly in both
/// implementations, so this is idempotent and safe on every exit path.
pub fn resume_all_shortcuts(app: &AppHandle) {
    let settings = get_settings(app);
    for (id, binding) in &settings.bindings {
        if id == "cancel" {
            continue;
        }
        if id == "transcribe_with_post_process" && !settings.post_process_enabled {
            continue;
        }
        if let Err(e) = register_shortcut(app, binding.clone()) {
            debug!("resume_all_shortcuts: could not register '{}': {}", id, e);
        }
    }
}

/// Temporarily unregister all bindings while the user is recording a
/// shortcut in the UI. This avoids firing actions while keys are recorded.
#[tauri::command]
#[specta::specta]
pub fn suspend_all_bindings(app: AppHandle) -> Result<(), String> {
    if resolved_backend(settings::get_settings(&app).keyboard_implementation)
        == ShortcutBackendKind::XdgPortal
    {
        return Err("Portal shortcuts are configured by the desktop".into());
    }
    suspend_all_shortcuts(&app);
    Ok(())
}

/// Re-register all bindings after the user has finished recording.
#[tauri::command]
#[specta::specta]
pub fn resume_all_bindings(app: AppHandle) -> Result<(), String> {
    if resolved_backend(settings::get_settings(&app).keyboard_implementation)
        == ShortcutBackendKind::XdgPortal
    {
        return Err("Portal shortcuts are configured by the desktop".into());
    }
    resume_all_shortcuts(&app);
    Ok(())
}

// ============================================================================
// Keyboard Implementation Switching
// ============================================================================

/// Result of changing keyboard implementation
#[derive(Serialize, Type)]
pub struct ImplementationChangeResult {
    pub success: bool,
    /// List of binding IDs that were reset to defaults due to incompatibility
    pub reset_bindings: Vec<String>,
}

/// Change shortcut implementation without committing settings or dispatch
/// ownership until the complete candidate backend is ready.
#[tauri::command]
#[specta::specta]
pub async fn change_keyboard_implementation_setting(
    app: AppHandle,
    implementation: String,
) -> Result<ImplementationChangeResult, String> {
    let new_impl = parse_keyboard_implementation(&implementation);
    let runtime = app
        .try_state::<ShortcutBackendRuntimeState>()
        .ok_or("ShortcutBackendRuntimeState is not managed")?;
    let _operation = runtime.operation.lock().await;
    let current_settings = settings::get_settings(&app);
    let current_impl = current_settings.keyboard_implementation;
    if current_impl == new_impl {
        return Ok(ImplementationChangeResult {
            success: true,
            reset_bindings: vec![],
        });
    }
    let old_backend = resolved_backend(current_impl);
    let new_backend = resolved_backend(new_impl);
    let mut proposed = current_settings.clone();
    proposed.keyboard_implementation = new_impl;
    let (candidate_bindings, reset_bindings) =
        prepare_candidate_bindings(&mut proposed, new_backend)?;

    info!(
        "Switching keyboard implementation from {:?} to {:?}",
        current_impl, new_impl
    );

    match new_backend {
        ShortcutBackendKind::XdgPortal => {
            #[cfg(target_os = "linux")]
            {
                let holder = app
                    .try_state::<PortalShortcutStateHolder>()
                    .ok_or("PortalShortcutStateHolder is not managed")?;
                let state = holder.get_or_create(&app).await?;
                let specs = portal_specs(&proposed)?;
                let persist_app = app.clone();
                let persist_settings = proposed.clone();
                state
                    .replace_transactionally(specs, portal_parent(&app).await, move || {
                        settings::write_settings(&persist_app, persist_settings);
                        Ok(())
                    })
                    .await?;
            }
            #[cfg(not(target_os = "linux"))]
            unreachable!("portal routing is Linux-only");
        }
        ShortcutBackendKind::HandyKeys => {
            handy_keys::register_candidate(&app, &candidate_bindings)?;
            #[cfg(target_os = "linux")]
            let portal_to_retire = if old_backend == ShortcutBackendKind::XdgPortal {
                app.try_state::<PortalShortcutStateHolder>()
                    .and_then(|holder| holder.current())
            } else {
                None
            };

            settings::write_settings(&app, proposed.clone());
            let status = ShortcutBackendStatus::static_ready(ShortcutBackendKind::HandyKeys);
            #[cfg(target_os = "linux")]
            if let Some(state) = portal_to_retire {
                let retiring_generation =
                    state.with_active_pressed_binding_ids(|retiring_portal| {
                        let generation =
                            retiring_portal.as_ref().map(|(generation, _)| *generation);
                        runtime.commit_with_retiring_portal(
                            ShortcutDispatchSource::HandyKeys,
                            status.clone(),
                            retiring_portal,
                        );
                        generation
                    });
                let _ = app.emit("shortcut-backend-status-changed", status);
                state.retire_active().await;
                runtime.finish_portal_retirement(retiring_generation);
            } else {
                publish_runtime_status(&app, Some(ShortcutDispatchSource::HandyKeys), status);
            }
            #[cfg(not(target_os = "linux"))]
            publish_runtime_status(&app, Some(ShortcutDispatchSource::HandyKeys), status);
        }
        ShortcutBackendKind::Tauri => {
            // Carbon Secure Input shadows use this same native backend and
            // would conflict with the Tauri candidate. Suspend them around the
            // complete transition so a failed candidate restores Handy Keys
            // first, then its prior shadows, without exposing a mixed backend.
            let previous_bindings = active_bindings(&current_settings);
            crate::secure_input::with_fallback_suspended(&app, || {
                if old_backend == ShortcutBackendKind::HandyKeys {
                    unregister_bindings_for_backend(&app, old_backend, &previous_bindings);
                }
                if let Err(error) = register_tauri_candidate(&app, &candidate_bindings) {
                    if old_backend == ShortcutBackendKind::HandyKeys {
                        if let Err(restore_error) =
                            handy_keys::register_candidate(&app, &previous_bindings)
                        {
                            error!(
                                "Failed to restore Handy Keys after Tauri candidate failure: {}",
                                restore_error
                            );
                            return Err(format!(
                                "{}; additionally failed to restore Handy Keys: {}",
                                error, restore_error
                            ));
                        }
                    }
                    return Err(error);
                }
                settings::write_settings(&app, proposed.clone());
                let status = ShortcutBackendStatus::static_ready(ShortcutBackendKind::Tauri);
                publish_runtime_status(&app, Some(ShortcutDispatchSource::Tauri), status);
                Ok(())
            })?;
        }
    }

    // Candidate callbacks were gated until the commit above. Retiring the old
    // non-portal registrations afterwards cannot create a duplicate dispatch window.
    if old_backend != ShortcutBackendKind::XdgPortal
        && !(old_backend == ShortcutBackendKind::HandyKeys
            && new_backend == ShortcutBackendKind::Tauri)
    {
        unregister_bindings_for_backend(&app, old_backend, &active_bindings(&current_settings));
    }
    crate::secure_input::reconcile_fallback(&app);
    let _ = app.emit(
        "settings-changed",
        serde_json::json!({
            "setting": "keyboard_implementation",
            "value": implementation,
            "reset_bindings": reset_bindings,
        }),
    );

    Ok(ImplementationChangeResult {
        success: true,
        reset_bindings,
    })
}

/// Get the current persisted keyboard implementation.
#[tauri::command]
#[specta::specta]
pub fn get_keyboard_implementation(app: AppHandle) -> String {
    let settings = settings::get_settings(&app);
    match settings.keyboard_implementation {
        KeyboardImplementation::Tauri => "tauri".to_string(),
        KeyboardImplementation::HandyKeys => "handy_keys".to_string(),
    }
}

fn validate_shortcut_for_backend(raw: &str, backend: ShortcutBackendKind) -> Result<(), String> {
    match backend {
        ShortcutBackendKind::Tauri => tauri_impl::validate_shortcut(raw),
        ShortcutBackendKind::HandyKeys => handy_keys::validate_shortcut(raw),
        ShortcutBackendKind::XdgPortal => {
            #[cfg(target_os = "linux")]
            {
                portal_impl::portal_trigger_from_binding(raw).map(|_| ())
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("Portal shortcuts are unavailable on this platform".into())
            }
        }
    }
}

fn validate_shortcut_for_implementation(
    raw: &str,
    implementation: KeyboardImplementation,
) -> Result<(), String> {
    validate_shortcut_for_backend(raw, resolved_backend(implementation))
}

fn parse_keyboard_implementation(s: &str) -> KeyboardImplementation {
    match s {
        "tauri" => KeyboardImplementation::Tauri,
        "handy_keys" => KeyboardImplementation::HandyKeys,
        other => {
            warn!(
                "Invalid keyboard implementation '{}', defaulting to tauri",
                other
            );
            KeyboardImplementation::Tauri
        }
    }
}

fn active_bindings(settings: &crate::settings::AppSettings) -> Vec<ShortcutBinding> {
    settings
        .bindings
        .iter()
        .filter(|(id, _)| {
            id.as_str() != "cancel"
                && (id.as_str() != "transcribe_with_post_process" || settings.post_process_enabled)
        })
        .map(|(_, binding)| binding.clone())
        .collect()
}

fn prepare_candidate_bindings(
    proposed: &mut crate::settings::AppSettings,
    backend: ShortcutBackendKind,
) -> Result<(Vec<ShortcutBinding>, Vec<String>), String> {
    let defaults = settings::get_default_settings().bindings;
    let mut reset_bindings = Vec::new();
    let mut bindings = Vec::new();
    for (id, default_binding) in defaults {
        if id == "cancel"
            || (id == "transcribe_with_post_process" && !proposed.post_process_enabled)
        {
            continue;
        }
        let mut binding = proposed
            .bindings
            .get(&id)
            .cloned()
            .unwrap_or_else(|| default_binding.clone());
        if let Err(error) = validate_shortcut_for_backend(&binding.current_binding, backend) {
            info!(
                "Shortcut '{}' ({}) is invalid for {:?}: {}. Resetting to default.",
                id, binding.current_binding, backend, error
            );
            binding.current_binding = default_binding.current_binding.clone();
            validate_shortcut_for_backend(&binding.current_binding, backend)?;
            proposed.bindings.insert(id.clone(), binding.clone());
            reset_bindings.push(id);
        }
        bindings.push(binding);
    }
    Ok((bindings, reset_bindings))
}

fn register_tauri_candidate(app: &AppHandle, bindings: &[ShortcutBinding]) -> Result<(), String> {
    let mut registered = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if let Err(error) = tauri_impl::register_shortcut(app, binding.clone()) {
            for registered_binding in registered.into_iter().rev() {
                let _ = tauri_impl::unregister_shortcut(app, registered_binding);
            }
            return Err(format!(
                "Failed to register system shortcut '{}': {}",
                binding.id, error
            ));
        }
        registered.push(binding.clone());
    }
    Ok(())
}

fn unregister_bindings_for_backend(
    app: &AppHandle,
    backend: ShortcutBackendKind,
    bindings: &[ShortcutBinding],
) {
    for binding in bindings {
        let result = match backend {
            ShortcutBackendKind::Tauri => tauri_impl::unregister_shortcut(app, binding.clone()),
            ShortcutBackendKind::HandyKeys => handy_keys::unregister_shortcut(app, binding.clone()),
            ShortcutBackendKind::XdgPortal => continue,
        };
        if let Err(error) = result {
            warn!(
                "Failed to retire shortcut '{}' from {:?}: {}",
                binding.id, backend, error
            );
        }
    }
}

// ============================================================================
// General Settings Commands
// ============================================================================

#[tauri::command]
#[specta::specta]
pub fn change_ptt_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.push_to_talk = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_audio_feedback_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.audio_feedback = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_audio_feedback_volume_setting(app: AppHandle, volume: f32) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.audio_feedback_volume = volume;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_sound_theme_setting(app: AppHandle, theme: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match theme.as_str() {
        "marimba" => SoundTheme::Marimba,
        "pop" => SoundTheme::Pop,
        "custom" => SoundTheme::Custom,
        other => {
            warn!("Invalid sound theme '{}', defaulting to marimba", other);
            SoundTheme::Marimba
        }
    };
    settings.sound_theme = parsed;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_theme_setting(app: AppHandle, theme: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match theme.as_str() {
        "system" => Theme::System,
        "light" => Theme::Light,
        "dark" => Theme::Dark,
        other => {
            warn!("Invalid theme '{}', defaulting to system", other);
            Theme::System
        }
    };
    settings.theme = parsed;
    settings::write_settings(&app, settings);
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    apply_window_theme(&app, parsed);
    // Notify other webviews (the recording overlay) so they re-apply the palette
    // live — they set `data-theme` on their own document and can't see this one.
    let _ = app.emit("theme-changed", parsed);
    Ok(())
}

/// Applies the appearance setting to the native window chrome (title bar), which
/// CSS `data-theme` cannot reach. `System` clears the override so the window
/// follows the OS. Call this on startup and whenever the setting changes to keep
/// the title bar in sync with the in-app palette.
///
/// On Windows this themes the title bar only. On macOS `set_theme` sets
/// `NSApp.appearance` app-wide, which is what we want here: it darkens the title
/// bar and keeps the overlay in step. Linux is left to `data-theme` alone, since
/// its window theming is backend-dependent and unreliable.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn apply_window_theme(app: &AppHandle, theme: Theme) {
    let window_theme = match theme {
        Theme::System => None,
        Theme::Light => Some(tauri::Theme::Light),
        Theme::Dark => Some(tauri::Theme::Dark),
    };
    if let Some(window) = app.get_webview_window("main") {
        if let Err(e) = window.set_theme(window_theme) {
            warn!("Failed to apply window theme: {}", e);
        }
    }
}

#[tauri::command]
#[specta::specta]
pub fn change_translate_to_english_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.translate_to_english = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_selected_language_setting(app: AppHandle, language: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.selected_language = language;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_overlay_position_setting(app: AppHandle, position: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match position.as_str() {
        // "none" is retired (visibility is overlay_style now); fold legacy callers
        // onto Bottom rather than warn.
        "none" | "bottom" => OverlayPosition::Bottom,
        "top" => OverlayPosition::Top,
        other => {
            warn!("Invalid overlay position '{}', defaulting to bottom", other);
            OverlayPosition::Bottom
        }
    };
    settings.overlay_position = parsed;
    settings::write_settings(&app, settings);

    // Whether the overlay shows at all is owned by overlay_style now; position
    // only ever toggles Top/Bottom, so the enabled cache is untouched here.
    // Update overlay position without recreating window
    crate::utils::update_overlay_position(&app);

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_overlay_style_setting(app: AppHandle, style: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match style.as_str() {
        "none" => OverlayStyle::None,
        "minimal" => OverlayStyle::Minimal,
        "live" => OverlayStyle::Live,
        other => {
            warn!("Invalid overlay style '{}', defaulting to minimal", other);
            OverlayStyle::Minimal
        }
    };
    settings.overlay_style = parsed;
    settings::write_settings(&app, settings);

    // Keep the cached overlay-enabled flag in sync so emit_levels stops (or
    // resumes) emitting on the next audio callback.
    crate::overlay::update_overlay_enabled_cache(parsed != OverlayStyle::None);

    // Reposition in case the window needs to re-center for the new style.
    crate::utils::update_overlay_position(&app);

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_debug_mode_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.debug_mode = enabled;
    settings::write_settings(&app, settings);

    // Keep webview log streaming in sync: the live log viewer only exists in
    // debug mode, so logs are forwarded to the frontend only while it is on.
    crate::WEBVIEW_LOG_STREAMING.store(enabled, std::sync::atomic::Ordering::Relaxed);

    // Emit event to notify frontend of debug mode change
    let _ = app.emit(
        "settings-changed",
        serde_json::json!({
            "setting": "debug_mode",
            "value": enabled
        }),
    );

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_start_hidden_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.start_hidden = enabled;
    settings::write_settings(&app, settings);

    // Notify frontend
    let _ = app.emit(
        "settings-changed",
        serde_json::json!({
            "setting": "start_hidden",
            "value": enabled
        }),
    );

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_autostart_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.autostart_enabled = enabled;
    settings::write_settings(&app, settings);

    // Apply the autostart setting immediately
    crate::autostart::apply_autostart(&app, enabled);

    // Notify frontend
    let _ = app.emit(
        "settings-changed",
        serde_json::json!({
            "setting": "autostart_enabled",
            "value": enabled
        }),
    );

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_update_checks_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.update_checks_enabled = enabled;
    settings::write_settings(&app, settings);

    let _ = app.emit(
        "settings-changed",
        serde_json::json!({
            "setting": "update_checks_enabled",
            "value": enabled
        }),
    );

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_show_whats_new_on_update_setting(
    app: AppHandle,
    enabled: bool,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.show_whats_new_on_update = enabled;
    settings::write_settings(&app, settings);

    let _ = app.emit(
        "settings-changed",
        serde_json::json!({
            "setting": "show_whats_new_on_update",
            "value": enabled
        }),
    );

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_whats_new_last_seen_version_setting(
    app: AppHandle,
    version: String,
) -> Result<(), String> {
    let version = version.trim().to_string();
    let mut settings = settings::get_settings(&app);
    settings.whats_new_last_seen_version = version.clone();
    settings::write_settings(&app, settings);

    let _ = app.emit(
        "settings-changed",
        serde_json::json!({
            "setting": "whats_new_last_seen_version",
            "value": version
        }),
    );

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn update_custom_words(app: AppHandle, words: Vec<String>) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.custom_words = words;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_word_correction_threshold_setting(
    app: AppHandle,
    threshold: f64,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.word_correction_threshold = threshold;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_extra_recording_buffer_setting(app: AppHandle, ms: u64) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.extra_recording_buffer_ms = ms;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_paste_delay_ms_setting(app: AppHandle, ms: u64) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.paste_delay_ms = ms;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_paste_delay_after_ms_setting(app: AppHandle, ms: u64) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.paste_delay_after_ms = ms;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_reliable_paste_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.reliable_paste = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_paste_method_setting(app: AppHandle, method: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match method.as_str() {
        "ctrl_v" => PasteMethod::CtrlV,
        "direct" => PasteMethod::Direct,
        "none" => PasteMethod::None,
        "shift_insert" => PasteMethod::ShiftInsert,
        "ctrl_shift_v" => PasteMethod::CtrlShiftV,
        "external_script" => PasteMethod::ExternalScript,
        other => {
            warn!("Invalid paste method '{}', defaulting to ctrl_v", other);
            PasteMethod::CtrlV
        }
    };
    settings.paste_method = parsed;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn get_available_typing_tools() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        crate::clipboard::get_available_typing_tools()
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec!["auto".to_string()]
    }
}

#[tauri::command]
#[specta::specta]
pub fn change_typing_tool_setting(app: AppHandle, tool: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match tool.as_str() {
        "auto" => TypingTool::Auto,
        "wtype" => TypingTool::Wtype,
        "kwtype" => TypingTool::Kwtype,
        "dotool" => TypingTool::Dotool,
        "ydotool" => TypingTool::Ydotool,
        "xdotool" => TypingTool::Xdotool,
        other => {
            warn!("Invalid typing tool '{}', defaulting to auto", other);
            TypingTool::Auto
        }
    };
    settings.typing_tool = parsed;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_external_script_path_setting(
    app: AppHandle,
    path: Option<String>,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.external_script_path = path;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_clipboard_handling_setting(app: AppHandle, handling: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match handling.as_str() {
        "dont_modify" => ClipboardHandling::DontModify,
        "copy_to_clipboard" => ClipboardHandling::CopyToClipboard,
        other => {
            warn!(
                "Invalid clipboard handling '{}', defaulting to dont_modify",
                other
            );
            ClipboardHandling::DontModify
        }
    };
    settings.clipboard_handling = parsed;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_auto_submit_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.auto_submit = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_auto_submit_key_setting(app: AppHandle, key: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let parsed = match key.as_str() {
        "enter" => AutoSubmitKey::Enter,
        "ctrl_enter" => AutoSubmitKey::CtrlEnter,
        "cmd_enter" => AutoSubmitKey::CmdEnter,
        other => {
            warn!("Invalid auto submit key '{}', defaulting to enter", other);
            AutoSubmitKey::Enter
        }
    };
    settings.auto_submit_key = parsed;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub async fn change_post_process_enabled_setting(
    app: AppHandle,
    enabled: bool,
) -> Result<(), String> {
    let runtime = app
        .try_state::<ShortcutBackendRuntimeState>()
        .ok_or("ShortcutBackendRuntimeState is not managed")?;
    let _operation = runtime.operation.lock().await;
    let current = settings::get_settings(&app);
    if current.post_process_enabled == enabled {
        return Ok(());
    }
    let backend = resolved_backend(current.keyboard_implementation);
    let mut proposed = current.clone();
    proposed.post_process_enabled = enabled;

    if backend == ShortcutBackendKind::XdgPortal {
        #[cfg(target_os = "linux")]
        {
            let holder = app
                .try_state::<PortalShortcutStateHolder>()
                .ok_or("PortalShortcutStateHolder is not managed")?;
            let state = holder.get_or_create(&app).await?;
            let persist_app = app.clone();
            state
                .replace_transactionally(
                    portal_specs(&proposed)?,
                    portal_parent(&app).await,
                    move || {
                        settings::write_settings(&persist_app, proposed);
                        Ok(())
                    },
                )
                .await?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!("portal routing is Linux-only");
    }

    if let Some(binding) = proposed
        .bindings
        .get("transcribe_with_post_process")
        .cloned()
    {
        if enabled {
            register_shortcut(&app, binding)?;
        } else {
            unregister_shortcut(&app, binding)?;
        }
    }
    settings::write_settings(&app, proposed);
    crate::secure_input::reconcile_fallback(&app);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_progressive_output_destination_setting(
    app: AppHandle,
    value: ProgressiveOutputDestination,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.progressive_output_destination = value;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_experimental_enabled_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.experimental_enabled = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_post_process_base_url_setting(
    app: AppHandle,
    provider_id: String,
    base_url: String,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    let label = settings
        .post_process_provider(&provider_id)
        .map(|provider| provider.label.clone())
        .ok_or_else(|| format!("Provider '{}' not found", provider_id))?;

    let provider = settings
        .post_process_provider_mut(&provider_id)
        .expect("Provider looked up above must exist");

    if provider.id != "custom" {
        return Err(format!(
            "Provider '{}' does not allow editing the base URL",
            label
        ));
    }

    provider.base_url = base_url;
    settings::write_settings(&app, settings);
    Ok(())
}

/// Generic helper to validate provider exists
fn validate_provider_exists(
    settings: &settings::AppSettings,
    provider_id: &str,
) -> Result<(), String> {
    if !settings
        .post_process_providers
        .iter()
        .any(|provider| provider.id == provider_id)
    {
        return Err(format!("Provider '{}' not found", provider_id));
    }
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_post_process_api_key_setting(
    app: AppHandle,
    provider_id: String,
    api_key: String,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    validate_provider_exists(&settings, &provider_id)?;
    settings.post_process_api_keys.insert(provider_id, api_key);
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_post_process_model_setting(
    app: AppHandle,
    provider_id: String,
    model: String,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    validate_provider_exists(&settings, &provider_id)?;
    settings.post_process_models.insert(provider_id, model);
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn set_post_process_provider(app: AppHandle, provider_id: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    validate_provider_exists(&settings, &provider_id)?;
    settings.post_process_provider_id = provider_id;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn add_post_process_prompt(
    app: AppHandle,
    name: String,
    prompt: String,
) -> Result<LLMPrompt, String> {
    let mut settings = settings::get_settings(&app);

    // Generate unique ID using timestamp and random component
    let id = format!("prompt_{}", chrono::Utc::now().timestamp_millis());

    let new_prompt = LLMPrompt {
        id: id.clone(),
        name,
        prompt,
    };

    settings.post_process_prompts.push(new_prompt.clone());
    settings::write_settings(&app, settings);

    Ok(new_prompt)
}

#[tauri::command]
#[specta::specta]
pub fn update_post_process_prompt(
    app: AppHandle,
    id: String,
    name: String,
    prompt: String,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);

    if let Some(existing_prompt) = settings
        .post_process_prompts
        .iter_mut()
        .find(|p| p.id == id)
    {
        existing_prompt.name = name;
        existing_prompt.prompt = prompt;
        settings::write_settings(&app, settings);
        Ok(())
    } else {
        Err(format!("Prompt with id '{}' not found", id))
    }
}

#[tauri::command]
#[specta::specta]
pub fn delete_post_process_prompt(app: AppHandle, id: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);

    // Don't allow deleting the last prompt
    if settings.post_process_prompts.len() <= 1 {
        return Err("Cannot delete the last prompt".to_string());
    }

    // Find and remove the prompt
    let original_len = settings.post_process_prompts.len();
    settings.post_process_prompts.retain(|p| p.id != id);

    if settings.post_process_prompts.len() == original_len {
        return Err(format!("Prompt with id '{}' not found", id));
    }

    // If the deleted prompt was selected, select the first one or None
    if settings.post_process_selected_prompt_id.as_ref() == Some(&id) {
        settings.post_process_selected_prompt_id =
            settings.post_process_prompts.first().map(|p| p.id.clone());
    }

    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub async fn fetch_post_process_models(
    app: AppHandle,
    provider_id: String,
) -> Result<Vec<String>, String> {
    let settings = settings::get_settings(&app);

    // Find the provider
    let provider = settings
        .post_process_providers
        .iter()
        .find(|p| p.id == provider_id)
        .ok_or_else(|| format!("Provider '{}' not found", provider_id))?;

    if provider.id == APPLE_INTELLIGENCE_PROVIDER_ID {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            return Ok(vec![APPLE_INTELLIGENCE_DEFAULT_MODEL_ID.to_string()]);
        }

        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            return Err("Apple Intelligence is only available on Apple silicon Macs running macOS 15 or later.".to_string());
        }
    }

    // Get API key
    let api_key = settings
        .post_process_api_keys
        .get(&provider_id)
        .cloned()
        .unwrap_or_default();

    // Skip fetching if no API key for providers that typically need one
    if api_key.trim().is_empty() && provider.id != "custom" {
        return Err(format!(
            "API key is required for {}. Please add an API key to list available models.",
            provider.label
        ));
    }

    crate::llm_client::fetch_models(provider, api_key).await
}

#[tauri::command]
#[specta::specta]
pub fn set_post_process_selected_prompt(app: AppHandle, id: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);

    // Verify the prompt exists
    if !settings.post_process_prompts.iter().any(|p| p.id == id) {
        return Err(format!("Prompt with id '{}' not found", id));
    }

    settings.post_process_selected_prompt_id = Some(id);
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_mute_while_recording_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.mute_while_recording = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_append_trailing_space_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.append_trailing_space = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_lazy_stream_close_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.lazy_stream_close = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_vad_enabled_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.vad_enabled = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub async fn change_vad_backend_setting(app: AppHandle, backend: VadBackend) -> Result<(), String> {
    if settings::get_settings(&app).vad_backend == backend {
        return Ok(());
    }

    // Construct/swap the detector and, when necessary, reopen cpal away from
    // the webview thread. Persist only after the runtime change succeeds so a
    // rejected in-progress switch or failed microphone reopen rolls back cleanly.
    let manager = app
        .state::<std::sync::Arc<crate::managers::audio::AudioRecordingManager>>()
        .inner()
        .clone();
    tokio::task::spawn_blocking(move || manager.update_vad_backend(backend))
        .await
        .map_err(|e| format!("audio task join failed: {e}"))?
        .map_err(|e| format!("Failed to update VAD backend: {e}"))?;

    let mut current_settings = settings::get_settings(&app);
    current_settings.vad_backend = backend;
    settings::write_settings(&app, current_settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_filler_word_removal_enabled_setting(
    app: AppHandle,
    enabled: bool,
) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.filler_word_removal_enabled = enabled;
    settings::write_settings(&app, settings);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_app_language_setting(app: AppHandle, language: String) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.app_language = language.clone();
    settings::write_settings(&app, settings);

    // Refresh the tray menu with the new language
    tray::update_tray_menu(&app);

    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_show_tray_icon_setting(app: AppHandle, enabled: bool) -> Result<(), String> {
    let mut settings = settings::get_settings(&app);
    settings.show_tray_icon = enabled;
    settings::write_settings(&app, settings);

    // Apply change immediately
    tray::set_tray_visibility(&app, enabled);

    Ok(())
}

/// Save accelerator settings and make the next model use reload with them.
/// The currently running transcription, if any, keeps its existing engine.
fn save_accelerator_and_reload_next_use(app: &AppHandle, s: settings::AppSettings) {
    settings::write_settings(app, s);

    let tm = app.state::<std::sync::Arc<crate::managers::transcription::TranscriptionManager>>();
    tm.reload_model_on_next_use();
}

#[tauri::command]
#[specta::specta]
pub fn change_transcribe_accelerator_setting(
    app: AppHandle,
    accelerator: settings::TranscribeAcceleratorSetting,
) -> Result<(), String> {
    let mut s = settings::get_settings(&app);
    s.transcribe_accelerator = accelerator;
    save_accelerator_and_reload_next_use(&app, s);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_ort_accelerator_setting(
    app: AppHandle,
    accelerator: settings::OrtAcceleratorSetting,
) -> Result<(), String> {
    let mut s = settings::get_settings(&app);
    s.ort_accelerator = accelerator;
    save_accelerator_and_reload_next_use(&app, s);
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn change_transcribe_gpu_device(app: AppHandle, device: Option<String>) -> Result<(), String> {
    let mut s = settings::get_settings(&app);
    s.transcribe_gpu_device = device;
    save_accelerator_and_reload_next_use(&app, s);
    Ok(())
}

/// Return which accelerators and GPU devices are available for this build.
///
/// First-call cost is dominated by enumerating GPU devices through the
/// transcribe.cpp Metal/Vulkan backend, which loads dynamic libraries and
/// probes hardware. Run it on the blocking pool so the webview thread
/// stays responsive — see also the startup pre-warm in `lib.rs`.
#[tauri::command]
#[specta::specta]
pub async fn get_available_accelerators() -> crate::managers::transcription::AvailableAccelerators {
    tauri::async_runtime::spawn_blocking(crate::managers::transcription::get_available_accelerators)
        .await
        .expect("get_available_accelerators panicked")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_commit_switches_dispatch_source_and_status_together() {
        let runtime = ShortcutBackendRuntimeState::default();
        {
            let initial = runtime.snapshot.read();
            assert_eq!(initial.active, None);
            assert_eq!(initial.status.backend, ShortcutBackendKind::Tauri);
            assert_eq!(initial.status.state, ShortcutBackendState::Initializing);
        }

        let ready = ShortcutBackendStatus {
            backend: ShortcutBackendKind::XdgPortal,
            state: ShortcutBackendState::Ready,
            message: None,
            bindings: HashMap::from([("transcribe".into(), "F8".into())]),
            can_configure: true,
        };
        runtime.commit(ShortcutDispatchSource::Portal(7), ready.clone());
        {
            let committed = runtime.snapshot.read();
            assert_eq!(committed.active, Some(ShortcutDispatchSource::Portal(7)));
            assert_eq!(committed.status, ready);
        }

        let unavailable = ShortcutBackendStatus {
            backend: ShortcutBackendKind::XdgPortal,
            state: ShortcutBackendState::Unavailable,
            message: Some("The desktop shortcut session ended unexpectedly".into()),
            bindings: HashMap::new(),
            can_configure: true,
        };
        runtime.set_status(unavailable.clone());
        let changed = runtime.snapshot.read();
        assert_eq!(changed.active, Some(ShortcutDispatchSource::Portal(7)));
        assert_eq!(changed.status, unavailable);
    }

    #[cfg(target_os = "linux")]
    fn retiring_releases(generation: u64, binding_ids: &[&str]) -> Option<RetiringPortalReleases> {
        Some(RetiringPortalReleases {
            generation,
            binding_ids: binding_ids.iter().map(|id| (*id).to_string()).collect(),
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pre_cutover_held_portal_release_is_accepted_once() {
        let mut retiring = retiring_releases(7, &["transcribe"]);
        assert!(callback_matches_runtime(
            Some(ShortcutDispatchSource::HandyKeys),
            &mut retiring,
            ShortcutDispatchSource::Portal(7),
            "transcribe",
            false,
        ));
        assert!(!callback_matches_runtime(
            Some(ShortcutDispatchSource::HandyKeys),
            &mut retiring,
            ShortcutDispatchSource::Portal(7),
            "transcribe",
            false,
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_cutover_portal_press_and_release_are_rejected() {
        let mut retiring = retiring_releases(7, &[]);
        assert!(!callback_matches_runtime(
            Some(ShortcutDispatchSource::HandyKeys),
            &mut retiring,
            ShortcutDispatchSource::Portal(7),
            "transcribe",
            true,
        ));
        assert!(!callback_matches_runtime(
            Some(ShortcutDispatchSource::HandyKeys),
            &mut retiring,
            ShortcutDispatchSource::Portal(7),
            "transcribe",
            false,
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn active_handy_press_cancels_matching_portal_release_authorization() {
        let mut retiring = retiring_releases(7, &["transcribe"]);
        assert!(callback_matches_runtime(
            Some(ShortcutDispatchSource::HandyKeys),
            &mut retiring,
            ShortcutDispatchSource::HandyKeys,
            "transcribe",
            true,
        ));
        assert!(!callback_matches_runtime(
            Some(ShortcutDispatchSource::HandyKeys),
            &mut retiring,
            ShortcutDispatchSource::Portal(7),
            "transcribe",
            false,
        ));
        assert!(callback_matches_runtime(
            Some(ShortcutDispatchSource::HandyKeys),
            &mut retiring,
            ShortcutDispatchSource::HandyKeys,
            "transcribe",
            false,
        ));
    }

    #[test]
    fn dropped_initialization_leader_unblocks_attempt_for_retry() {
        let initialization = ShortcutInitializationState::default();
        {
            let mut flight = initialization.flight.lock();
            flight.running = true;
            flight.attempt = 1;
        }
        {
            let _leader = InitializationLeaderGuard {
                initialization: &initialization,
                attempt: 1,
                armed: true,
            };
        }

        let flight = initialization.flight.lock();
        assert!(!flight.running);
        assert!(!flight.successful);
        let (attempt, result) = flight.result.as_ref().expect("cancellation result");
        assert_eq!(*attempt, 1);
        assert_eq!(
            result.as_ref().unwrap_err(),
            "Shortcut initialization attempt was cancelled"
        );
    }
}
