use super::{BeginSession, FocusedFieldBackend, FocusedTargetSession, SessionEventSink};
use crate::clipboard::TrustedExecutable;
use crate::focused_output::types::{
    BeginContext, BeginReceipt, DictationSessionId, FocusedOutputBackend, FocusedOutputCapability,
    FocusedOutputPermission, FocusedOutputReasonCode, InsertOutcome, InsertionRequest,
    InsertionTransport, MixedInputSupport, ObservationId, ReceiptConfidence,
    ResolvedInsertionCapability, SessionCancellation, SubmitOutcome, TargetInteractionEvent,
    UnsafeEditKind, BACKEND_SHUTDOWN_DEADLINE, CHILD_PROCESS_DEADLINE, HANDY_RECEIPT_DEADLINE,
    TARGET_CALL_DEADLINE, THREAD_CLOSE_DEADLINE, THREAD_READY_DEADLINE,
};
use crate::settings::{AutoSubmitKey, TypingTool};
use atspi::events::focus::FocusEvent;
use atspi::events::object::{
    StateChangedEvent, TextCaretMovedEvent, TextChangedEvent, TextSelectionChangedEvent,
};
use atspi::events::{DBusInterface, DBusMember, Event, FocusEvents, MouseEvents, ObjectEvents};
use atspi::proxy::accessible::AccessibleProxy;
use atspi::proxy::cache::CacheProxy;
use atspi::proxy::device_event_controller::{
    DeviceEvent, EventListenerMode, EventType, KeyDefinition,
};
use atspi::proxy::editable_text::EditableTextProxy;
use atspi::proxy::text::TextProxy;
use atspi::zbus;
use atspi::{
    connection::{read_session_accessibility, set_session_accessibility},
    AccessibilityConnection, CacheItem, Interface, InterfaceSet, ObjectRefOwned, Operation, Role,
    State, StateSet,
};
use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};
use futures_util::{FutureExt, Stream, StreamExt};
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::process::{Child, ChildStdin, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

const COMMAND_CAPACITY: usize = 16;
const MONITOR_CAPACITY: usize = 64;
const LISTENER_ROOT: &str = "/com/pais/handy/focused_output/linux";
const REGISTRY: &str = "org.a11y.atspi.Registry";
const DEVICE_EVENT_CONTROLLER_PATH: &str = "/org/a11y/atspi/registry/deviceeventcontroller";
const DEVICE_EVENT_CONTROLLER_INTERFACE: &str = "org.a11y.atspi.DeviceEventController";
const DEVICE_EVENT_LISTENER_INTERFACE: &str = "org.a11y.atspi.DeviceEventListener";
// AT-SPI 2.46+ defines this argument as a u32 bitmask. atspi-proxies
// 0.14.0 still emits the obsolete `au` signature, so keystroke registration
// and deregistration use a raw zbus proxy.
const KEY_EVENT_TYPES: u32 =
    (1 << EventType::KeyPressed as u32) | (1 << EventType::KeyReleased as u32);
const CACHE_PATH: &str = "/org/a11y/atspi/cache";
const ROOT_PATH: &str = "/org/a11y/atspi/accessible/root";
const MAX_SCALARS: usize = 16;
const MAX_ANCESTORS: usize = 128;
const POLL: Duration = Duration::from_millis(5);
const FOCUS_LOSS_GRACE: Duration = Duration::from_millis(100);
const T_SECURE: u8 = 11;

const T_NONE: u8 = 0;
const T_TARGET: u8 = 1;
const T_POINTER: u8 = 2;
const T_EDIT: u8 = 3;
const T_CARET: u8 = 4;
const T_SELECTION: u8 = 5;
const T_COMMAND: u8 = 6;
const T_IME: u8 = 7;
const T_MONITOR: u8 = 8;
const T_CLOSED: u8 = 9;
const T_CANCELLED: u8 = 10;
const T_MIXED: u8 = 12;

/// Strict Linux AT-SPI focused-field backend.
///
/// Construction does not connect to D-Bus or inspect/spawn typing tools. The
/// first capability query or Begin lazily starts one current-thread Tokio owner.
pub struct LinuxFocusedFieldBackend {
    owner: Mutex<BackendOwner>,
}

struct BackendOwner {
    controller: Option<Arc<Controller>>,
    thread: Option<JoinHandle<()>>,
    shut_down: bool,
}

struct Controller {
    tx: Sender<LoopCommand>,
    closed: AtomicBool,
}

impl LinuxFocusedFieldBackend {
    pub fn new() -> Self {
        Self {
            owner: Mutex::new(BackendOwner {
                controller: None,
                thread: None,
                shut_down: false,
            }),
        }
    }

    fn controller(&self) -> Result<Arc<Controller>, FocusedOutputReasonCode> {
        let mut owner = self
            .owner
            .lock()
            .map_err(|_| FocusedOutputReasonCode::BackendDisconnected)?;
        if owner.shut_down {
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }
        if let Some(controller) = owner.controller.as_ref() {
            if !controller.closed.load(Ordering::Acquire) {
                return Ok(controller.clone());
            }
        }
        let (tx, rx) = bounded(COMMAND_CAPACITY);
        let (ready_tx, ready_rx) = bounded(1);
        let controller = Arc::new(Controller {
            tx,
            closed: AtomicBool::new(false),
        });
        let thread_controller = controller.clone();
        let handle = thread::Builder::new()
            .name("focused-output-atspi".to_owned())
            .spawn(move || platform_thread(rx, ready_tx, thread_controller))
            .map_err(|_| FocusedOutputReasonCode::BackendDisconnected)?;
        if ready_rx.recv_timeout(THREAD_READY_DEADLINE) != Ok(true) {
            controller.closed.store(true, Ordering::Release);
            drop(handle);
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }
        owner.controller = Some(controller.clone());
        owner.thread = Some(handle);
        Ok(controller)
    }
}

impl Default for LinuxFocusedFieldBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FocusedFieldBackend for LinuxFocusedFieldBackend {
    fn global_capability(&self) -> FocusedOutputCapability {
        let Ok(controller) = self.controller() else {
            return unavailable(FocusedOutputReasonCode::BackendDisconnected);
        };
        let (tx, rx) = bounded(1);
        if controller
            .tx
            .send_timeout(LoopCommand::Probe(tx), TARGET_CALL_DEADLINE)
            .is_err()
        {
            return unavailable(FocusedOutputReasonCode::BackendDisconnected);
        }
        rx.recv_timeout(TARGET_CALL_DEADLINE + POLL)
            .unwrap_or_else(|_| unavailable(FocusedOutputReasonCode::AtSpiUnavailable))
    }

    fn request_permission(
        &self,
        _permission: FocusedOutputPermission,
    ) -> Result<FocusedOutputCapability, FocusedOutputReasonCode> {
        Err(FocusedOutputReasonCode::PlatformUnsupported)
    }

    fn begin(
        &self,
        context: BeginContext,
        sink: Arc<dyn SessionEventSink>,
        cancellation: SessionCancellation,
    ) -> Result<BeginSession, FocusedOutputReasonCode> {
        if cancellation.is_cancelled() {
            return Err(FocusedOutputReasonCode::Cancelled);
        }
        let controller = self.controller()?;
        let session_id = context.session_id;
        let (tx, rx) = bounded(1);
        controller
            .tx
            .send_timeout(
                LoopCommand::Begin {
                    context,
                    sink,
                    cancellation: cancellation.clone(),
                    reply: tx,
                },
                TARGET_CALL_DEADLINE,
            )
            .map_err(|_| FocusedOutputReasonCode::BackendDisconnected)?;
        // Initial connection, target capture, listener registration, and final
        // revalidation each contain independently bounded calls. Allow their
        // combined setup budget before declaring the backend disconnected.
        let begun = rx
            .recv_timeout(THREAD_READY_DEADLINE + TARGET_CALL_DEADLINE * 8)
            .map_err(|_| FocusedOutputReasonCode::BackendDisconnected)??;
        let receipt = BeginReceipt::new(session_id, begun.capability.clone(), begun.application)
            .ok_or(FocusedOutputReasonCode::BackendDisconnected)?;
        Ok(BeginSession {
            receipt,
            session: Box::new(LinuxSession {
                controller,
                generation: begun.generation,
                session_id,
                capability: begun.capability,
                cancellation,
                closed: false,
            }),
        })
    }

    fn shutdown(&self) {
        let (controller, thread) = {
            let Ok(mut owner) = self.owner.lock() else {
                return;
            };
            if owner.shut_down {
                return;
            }
            owner.shut_down = true;
            (owner.controller.take(), owner.thread.take())
        };
        let Some(controller) = controller else {
            return;
        };
        if controller.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let (tx, rx) = bounded(1);
        let sent = controller
            .tx
            .send_timeout(LoopCommand::Shutdown(tx), THREAD_CLOSE_DEADLINE)
            .is_ok();
        let quiesced = sent && rx.recv_timeout(BACKEND_SHUTDOWN_DEADLINE).is_ok();
        if let Some(thread) = thread {
            if quiesced {
                let _ = thread.join();
            } else {
                // Retain all thread-owned callback state until process exit when
                // bounded shutdown cannot prove quiescence.
                std::mem::forget(thread);
            }
        }
    }
}

impl Drop for LinuxFocusedFieldBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct LinuxSession {
    controller: Arc<Controller>,
    generation: u64,
    session_id: DictationSessionId,
    capability: FocusedOutputCapability,
    cancellation: SessionCancellation,
    closed: bool,
}

impl FocusedTargetSession for LinuxSession {
    fn capability(&self) -> &FocusedOutputCapability {
        &self.capability
    }

    fn insert_if_valid(&mut self, request: InsertionRequest) -> InsertOutcome {
        if self.closed || self.cancellation.is_cancelled() || request.session_id != self.session_id
        {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        let (tx, rx) = bounded(1);
        if self
            .controller
            .tx
            .send_timeout(
                LoopCommand::Insert {
                    generation: self.generation,
                    request,
                    reply: tx,
                },
                TARGET_CALL_DEADLINE,
            )
            .is_err()
        {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::BackendDisconnected,
            };
        }
        rx.recv_timeout(CHILD_PROCESS_DEADLINE + TARGET_CALL_DEADLINE)
            .unwrap_or(InsertOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            })
    }

    fn submit_if_valid(&mut self, key: AutoSubmitKey) -> SubmitOutcome {
        if self.closed || self.cancellation.is_cancelled() {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        let (tx, rx) = bounded(1);
        if self
            .controller
            .tx
            .send_timeout(
                LoopCommand::Submit {
                    generation: self.generation,
                    key,
                    reply: tx,
                },
                TARGET_CALL_DEADLINE,
            )
            .is_err()
        {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::BackendDisconnected,
            };
        }
        rx.recv_timeout(CHILD_PROCESS_DEADLINE + TARGET_CALL_DEADLINE)
            .unwrap_or(SubmitOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            })
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let (tx, rx) = bounded(1);
        if self
            .controller
            .tx
            .send_timeout(
                LoopCommand::Close(self.generation, tx),
                THREAD_CLOSE_DEADLINE,
            )
            .is_ok()
        {
            let _ = rx.recv_timeout(THREAD_CLOSE_DEADLINE);
        }
    }
}

impl Drop for LinuxSession {
    fn drop(&mut self) {
        self.close();
    }
}

enum LoopCommand {
    Probe(Sender<FocusedOutputCapability>),
    Begin {
        context: BeginContext,
        sink: Arc<dyn SessionEventSink>,
        cancellation: SessionCancellation,
        reply: Sender<Result<BeginData, FocusedOutputReasonCode>>,
    },
    Insert {
        generation: u64,
        request: InsertionRequest,
        reply: Sender<InsertOutcome>,
    },
    Submit {
        generation: u64,
        key: AutoSubmitKey,
        reply: Sender<SubmitOutcome>,
    },
    Close(u64, Sender<()>),
    Shutdown(Sender<()>),
}

struct BeginData {
    generation: u64,
    capability: FocusedOutputCapability,
    application: Option<String>,
}

fn unavailable(reason: FocusedOutputReasonCode) -> FocusedOutputCapability {
    FocusedOutputCapability::unavailable(FocusedOutputBackend::LinuxAtSpi, reason)
}

fn platform_thread(rx: Receiver<LoopCommand>, ready: Sender<bool>, controller: Arc<Controller>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = ready.try_send(false);
            controller.closed.store(true, Ordering::Release);
            return;
        }
    };
    let _ = ready.try_send(true);
    runtime.block_on(disconnected_loop(rx));
    controller.closed.store(true, Ordering::Release);
}

async fn disconnected_loop(commands: Receiver<LoopCommand>) {
    let mut generation = 1_u64;
    loop {
        let command = match commands.recv_timeout(POLL) {
            Ok(command) => command,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
        };
        match command {
            LoopCommand::Shutdown(reply) => {
                let _ = reply.try_send(());
                return;
            }
            LoopCommand::Probe(reply) => match connect_for_probe().await {
                Ok(Some(connection)) => {
                    let _ = reply.try_send(FocusedOutputCapability::global_ready(
                        FocusedOutputBackend::LinuxAtSpi,
                    ));
                    if !connected_loop(&commands, connection, None, &mut generation).await {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = reply.try_send(FocusedOutputCapability::global_ready(
                        FocusedOutputBackend::LinuxAtSpi,
                    ));
                }
                Err(()) => {
                    let _ = reply.try_send(unavailable(FocusedOutputReasonCode::AtSpiUnavailable));
                }
            },
            begin @ LoopCommand::Begin { .. } => match connect_for_begin().await {
                Ok(connection) => {
                    if !connected_loop(&commands, connection, Some(begin), &mut generation).await {
                        return;
                    }
                }
                Err(()) => reject(begin, FocusedOutputReasonCode::AtSpiUnavailable),
            },
            other => reject(other, FocusedOutputReasonCode::BackendDisconnected),
        }
    }
}

async fn connect_for_probe() -> Result<Option<AccessibilityConnection>, ()> {
    match timeout(TARGET_CALL_DEADLINE, read_session_accessibility()).await {
        Ok(Ok(true)) => connect().await.map(Some),
        Ok(Ok(false)) => Ok(None),
        _ => Err(()),
    }
}

async fn connect_for_begin() -> Result<AccessibilityConnection, ()> {
    match timeout(TARGET_CALL_DEADLINE, set_session_accessibility(true)).await {
        Ok(Ok(())) => connect().await,
        _ => Err(()),
    }
}

async fn connect() -> Result<AccessibilityConnection, ()> {
    match timeout(TARGET_CALL_DEADLINE, AccessibilityConnection::new()).await {
        Ok(Ok(connection)) => Ok(connection),
        _ => Err(()),
    }
}

fn reject(command: LoopCommand, reason: FocusedOutputReasonCode) {
    match command {
        LoopCommand::Probe(reply) => {
            let _ = reply.try_send(unavailable(reason));
        }
        LoopCommand::Begin { reply, .. } => {
            let _ = reply.try_send(Err(reason));
        }
        LoopCommand::Insert { reply, .. } => {
            let _ = reply.try_send(InsertOutcome::Rejected { reason });
        }
        LoopCommand::Submit { reply, .. } => {
            let _ = reply.try_send(SubmitOutcome::Rejected { reason });
        }
        LoopCommand::Close(_, reply) | LoopCommand::Shutdown(reply) => {
            let _ = reply.try_send(());
        }
    }
}

#[derive(Default)]
struct EventRegistrations {
    text_changed: bool,
    caret_moved: bool,
    selection_changed: bool,
    state_changed: bool,
    focus: bool,
    mouse: bool,
}

struct ConnectedState {
    session: Option<SessionRecord>,
    registrations: EventRegistrations,
    connection_failed: bool,
    registry_owner: Arc<RegistryOwnerMonitor>,
}

fn is_focused_event_header(interface: &str, member: &str) -> bool {
    (interface == ObjectEvents::DBUS_INTERFACE
        && matches!(
            member,
            TextChangedEvent::DBUS_MEMBER
                | TextCaretMovedEvent::DBUS_MEMBER
                | TextSelectionChangedEvent::DBUS_MEMBER
                | StateChangedEvent::DBUS_MEMBER
        ))
        || (interface == FocusEvents::DBUS_INTERFACE && member == FocusEvent::DBUS_MEMBER)
        || interface == MouseEvents::DBUS_INTERFACE
}

fn focused_event_stream(
    connection: &AccessibilityConnection,
) -> impl Stream<Item = Result<Event, atspi::AtspiError>> {
    zbus::MessageStream::from(connection.connection()).filter_map(|result| async move {
        let message = match result {
            Ok(message) => message,
            Err(error) => return Some(Err(error.into())),
        };
        if message.message_type() != zbus::message::Type::Signal {
            return None;
        }
        let header = message.header();
        let (Some(interface), Some(member)) = (header.interface(), header.member()) else {
            return None;
        };
        if is_focused_event_header(interface.as_str(), member.as_str()) {
            Some(Event::try_from(&message))
        } else {
            None
        }
    })
}

struct RegistryOwnerMonitor {
    lost: AtomicBool,
    active: Mutex<Option<std::sync::Weak<MonitorShared>>>,
    notify: tokio::sync::Notify,
}

impl RegistryOwnerMonitor {
    fn new() -> Self {
        Self {
            lost: AtomicBool::new(false),
            active: Mutex::new(None),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn arm(&self, monitor: &Arc<MonitorShared>) {
        match self.active.lock() {
            Ok(mut active) => *active = Some(Arc::downgrade(monitor)),
            Err(poisoned) => *poisoned.into_inner() = Some(Arc::downgrade(monitor)),
        }
        if self.lost.load(Ordering::Acquire) {
            monitor.terminal(T_MONITOR);
        }
    }

    fn lose(&self) {
        if !self.lost.swap(true, Ordering::AcqRel) {
            let monitor = match self.active.lock() {
                Ok(active) => active.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            if let Some(monitor) = monitor.and_then(|monitor| monitor.upgrade()) {
                monitor.terminal(T_MONITOR);
            }
            self.notify.notify_one();
        }
    }

    fn is_lost(&self) -> bool {
        self.lost.load(Ordering::Acquire)
    }
}

struct AbortTask(tokio::task::JoinHandle<()>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn monitor_registry_owner(
    connection: zbus::Connection,
    monitor: Arc<RegistryOwnerMonitor>,
    ready: tokio::sync::oneshot::Sender<Result<(), ()>>,
) {
    let proxy = match zbus::fdo::DBusProxy::new(&connection).await {
        Ok(proxy) => proxy,
        Err(_) => {
            let _ = ready.send(Err(()));
            return;
        }
    };
    let mut stream = match proxy
        .receive_name_owner_changed_with_args(&[(0, REGISTRY)])
        .await
    {
        Ok(stream) => stream,
        Err(_) => {
            let _ = ready.send(Err(()));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        return;
    }
    match stream.next().await {
        Some(signal) if signal.args().is_ok() => {
            log::debug!("Linux focused AT-SPI registry owner changed");
        }
        Some(_) => {
            log::debug!("Linux focused AT-SPI registry owner signal was invalid");
        }
        None => {
            log::debug!("Linux focused AT-SPI registry owner stream closed");
        }
    }
    monitor.lose();
}

async fn connected_loop(
    commands: &Receiver<LoopCommand>,
    connection: AccessibilityConnection,
    first: Option<LoopCommand>,
    next_generation: &mut u64,
) -> bool {
    let event_connection = connection.clone();
    let mut events = Box::pin(focused_event_stream(&event_connection));
    let registry_owner = Arc::new(RegistryOwnerMonitor::new());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let _owner_task = AbortTask(tokio::spawn(monitor_registry_owner(
        connection.connection().clone(),
        registry_owner.clone(),
        ready_tx,
    )));
    if !matches!(ready_rx.await, Ok(Ok(()))) {
        if let Some(command) = first {
            reject(command, FocusedOutputReasonCode::MonitorUnavailable);
        }
        return true;
    }
    let mut state = ConnectedState {
        session: None,
        registrations: EventRegistrations::default(),
        connection_failed: false,
        registry_owner: registry_owner.clone(),
    };
    let mut command = first;
    loop {
        if registry_owner.is_lost() {
            invalidate_bus(&mut state);
            close_all(&connection, &mut state).await;
            return true;
        }
        if let Some(current) = command.take() {
            if !handle_command(
                &connection,
                &mut events,
                &mut state,
                current,
                next_generation,
            )
            .await
            {
                close_all(&connection, &mut state).await;
                return false;
            }
        }
        if state.connection_failed {
            close_all(&connection, &mut state).await;
            return true;
        }
        drain_monitor(&connection, &mut state).await;
        if state.connection_failed {
            close_all(&connection, &mut state).await;
            return true;
        }
        tokio::select! {
            event = events.next() => match event {
                Some(Ok(event)) => process_idle_event(&mut state, event),
                Some(Err(_)) => {
                    log::debug!("Linux focused AT-SPI event stream failed");
                    invalidate_bus(&mut state);
                    close_all(&connection, &mut state).await;
                    return true;
                }
                None => {
                    log::debug!("Linux focused AT-SPI event stream closed");
                    invalidate_bus(&mut state);
                    close_all(&connection, &mut state).await;
                    return true;
                }
            },
            _ = registry_owner.notify.notified() => {
                invalidate_bus(&mut state);
                close_all(&connection, &mut state).await;
                return true;
            },
            _ = sleep(POLL) => match commands.try_recv() {
                Ok(next) => command = Some(next),
                Err(TryRecvError::Empty) => {},
                Err(TryRecvError::Disconnected) => {
                    close_all(&connection, &mut state).await;
                    return false;
                }
            }
        }
    }
}

async fn handle_command<S>(
    connection: &AccessibilityConnection,
    events: &mut Pin<Box<S>>,
    state: &mut ConnectedState,
    command: LoopCommand,
    next_generation: &mut u64,
) -> bool
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    match command {
        LoopCommand::Probe(reply) => {
            let _ = reply.try_send(FocusedOutputCapability::global_ready(
                FocusedOutputBackend::LinuxAtSpi,
            ));
        }
        LoopCommand::Begin {
            context,
            sink,
            cancellation,
            reply,
        } => {
            if state.session.is_some() {
                let _ = reply.try_send(Err(FocusedOutputReasonCode::AlreadyActive));
            } else {
                let generation = *next_generation;
                *next_generation = next_generation.wrapping_add(1).max(1);
                let result = begin_session(
                    connection,
                    events,
                    state,
                    context,
                    sink,
                    cancellation,
                    generation,
                )
                .await;
                let _ = reply.try_send(result);
            }
        }
        LoopCommand::Insert {
            generation,
            request,
            reply,
        } => {
            let outcome = if state.session.as_ref().map(|s| s.generation) == Some(generation) {
                let mut session = state.session.take().expect("checked session");
                let outcome = insert(connection, events, &mut session, request).await;
                state.session = Some(session);
                outcome
            } else {
                InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::TargetChanged,
                }
            };
            let _ = reply.try_send(outcome);
        }
        LoopCommand::Submit {
            generation,
            key,
            reply,
        } => {
            let outcome = if state.session.as_ref().map(|s| s.generation) == Some(generation) {
                let session = state.session.as_mut().expect("checked session");
                submit(connection, session, key).await
            } else {
                SubmitOutcome::Rejected {
                    reason: FocusedOutputReasonCode::TargetChanged,
                }
            };
            let _ = reply.try_send(outcome);
        }
        LoopCommand::Close(generation, reply) => {
            if state.session.as_ref().map(|s| s.generation) == Some(generation) {
                let mut session = state.session.take().expect("checked session");
                if session.monitor_tier == MonitorTier::AtSpiSemanticOnly {
                    let _ = drain_buffered_semantic_events(events, &mut session);
                }
                if !cleanup(connection, &mut session).await {
                    state.connection_failed = true;
                }
            }
            if deregister_all_events(connection, &mut state.registrations)
                .await
                .is_err()
            {
                state.connection_failed = true;
            }
            let _ = reply.try_send(());
        }
        LoopCommand::Shutdown(reply) => {
            close_all(connection, state).await;
            let _ = reply.try_send(());
            return false;
        }
    }
    true
}

struct SessionRecord {
    generation: u64,
    session_id: DictationSessionId,
    target: Target,
    route: Route,
    monitor_tier: MonitorTier,
    sink: Arc<dyn SessionEventSink>,
    cancellation: SessionCancellation,
    monitor: Arc<MonitorShared>,
    monitor_rx: Receiver<MonitorSignal>,
    listener_path: Option<String>,
    next_observation: u64,
    caret: i32,
    semantic_character_count: Option<i32>,
    user_intent: bool,
    external_caret: Option<i32>,
    focus_loss_at: Option<Instant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    bus: String,
    path: String,
    app_bus: String,
    app_path: String,
    pid: u32,
    start_ticks: u64,
    owner_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MonitorTier {
    Physical,
    AtSpiSemanticOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoutePolicy {
    Direct(MixedInputSupport),
    Guarded,
    Unavailable,
}

fn route_policy(direct: bool, monitor_tier: MonitorTier) -> RoutePolicy {
    match (direct, monitor_tier) {
        (true, MonitorTier::Physical) => {
            RoutePolicy::Direct(MixedInputSupport::ObservedInsertionsOnly)
        }
        (true, MonitorTier::AtSpiSemanticOnly) => {
            RoutePolicy::Direct(MixedInputSupport::Unavailable)
        }
        (false, MonitorTier::Physical) => RoutePolicy::Guarded,
        (false, MonitorTier::AtSpiSemanticOnly) => RoutePolicy::Unavailable,
    }
}

enum Route {
    Direct,
    Guarded(PinnedTool),
}

#[derive(Clone)]
struct PinnedTool {
    executable: TrustedExecutable,
    kind: ToolKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolKind {
    Wtype,
    Ydotool,
}

struct Capture {
    target: Target,
    application: Option<String>,
    caret: i32,
    direct: bool,
}

async fn begin_session<S>(
    connection: &AccessibilityConnection,
    events: &mut Pin<Box<S>>,
    state: &mut ConnectedState,
    context: BeginContext,
    sink: Arc<dyn SessionEventSink>,
    cancellation: SessionCancellation,
    generation: u64,
) -> Result<BeginData, FocusedOutputReasonCode>
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    if cancellation.is_cancelled() {
        return Err(FocusedOutputReasonCode::Cancelled);
    }
    let captured = capture_target(connection, generation).await?;
    if context.auto_submit_requested {
        return Err(FocusedOutputReasonCode::AutoSubmitUnsupported);
    }
    let stop_chord = StopChord::parse(context.control_shortcut.as_deref());
    if context.control_shortcut.is_some() && stop_chord.is_none() {
        return Err(FocusedOutputReasonCode::ControlShortcutUnsupported);
    }
    if let Err(reason) = register_target_events(connection, &mut state.registrations).await {
        state.connection_failed = true;
        return Err(reason);
    }
    let (monitor_tx, monitor_rx) = bounded(MONITOR_CAPACITY);
    let monitor = Arc::new(MonitorShared {
        terminal: AtomicU8::new(T_NONE),
        published: AtomicBool::new(false),
        dispatch: AtomicBool::new(false),
        dispatch_direct: AtomicBool::new(false),
        dispatch_text: AtomicBool::new(false),
        intent_epoch: AtomicU64::new(0),
        tool_key_presses: AtomicU64::new(0),
        expected_tool_key_presses: AtomicU64::new(0),
        physical_callbacks: AtomicU64::new(0),
        tx: monitor_tx,
        stop_chord,
        cancellation: cancellation.clone(),
    });
    let listener_path = format!("{LISTENER_ROOT}/{generation}");
    let monitor_tier = match register_pointer_events(connection, &mut state.registrations).await {
        Ok(()) => match register_device_listener(connection, &listener_path, monitor.clone()).await
        {
            Ok(PhysicalMonitorProbe::Installed) => MonitorTier::Physical,
            Ok(PhysicalMonitorProbe::Unsupported) => {
                if deregister_pointer_events(connection, &mut state.registrations)
                    .await
                    .is_err()
                {
                    state.connection_failed = true;
                    let _ = deregister_all_events(connection, &mut state.registrations).await;
                    return Err(FocusedOutputReasonCode::MonitorUnavailable);
                }
                MonitorTier::AtSpiSemanticOnly
            }
            Err(reason) => {
                state.connection_failed = true;
                let _ = deregister_all_events(connection, &mut state.registrations).await;
                return Err(reason);
            }
        },
        Err(reason) => {
            state.connection_failed = true;
            let _ = deregister_all_events(connection, &mut state.registrations).await;
            return Err(reason);
        }
    };
    let installed_listener =
        (monitor_tier == MonitorTier::Physical).then_some(listener_path.clone());
    if state.registry_owner.is_lost() {
        cleanup_unarmed(connection, state, installed_listener).await;
        state.connection_failed = true;
        return Err(FocusedOutputReasonCode::MonitorUnavailable);
    }
    let semantic_character_count = if monitor_tier == MonitorTier::AtSpiSemanticOnly {
        match capture_character_count(connection, &captured.target).await {
            Ok(count) if semantic_snapshot_valid(captured.caret, count) => Some(count),
            Ok(_) => {
                cleanup_unarmed(connection, state, installed_listener).await;
                return Err(FocusedOutputReasonCode::TargetUnsupported);
            }
            Err(reason) => {
                cleanup_unarmed(connection, state, installed_listener).await;
                return Err(reason);
            }
        }
    } else {
        None
    };
    if let Err(reason) = drain_prearm_events(events, &captured.target) {
        cleanup_unarmed(connection, state, installed_listener).await;
        if reason == FocusedOutputReasonCode::MonitorUnavailable {
            state.connection_failed = true;
        }
        return Err(reason);
    }
    let recaptured = capture_target(connection, generation).await;
    let recaptured = match recaptured {
        Ok(value) if value.target == captured.target && value.caret == captured.caret => value,
        Ok(_) => {
            cleanup_unarmed(connection, state, installed_listener).await;
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        Err(reason) => {
            cleanup_unarmed(connection, state, installed_listener).await;
            return Err(reason);
        }
    };
    let semantic_character_count = if let Some(expected) = semantic_character_count {
        match capture_character_count(connection, &recaptured.target).await {
            Ok(observed)
                if observed == expected && semantic_snapshot_valid(recaptured.caret, observed) =>
            {
                Some(observed)
            }
            Ok(_) => {
                cleanup_unarmed(connection, state, installed_listener).await;
                return Err(FocusedOutputReasonCode::TargetChanged);
            }
            Err(reason) => {
                cleanup_unarmed(connection, state, installed_listener).await;
                return Err(reason);
            }
        }
    } else {
        None
    };
    let (route, capability) = match route_policy(recaptured.direct, monitor_tier) {
        RoutePolicy::Direct(mixed_input_support) => (
            Route::Direct,
            FocusedOutputCapability::verified_control(
                FocusedOutputBackend::LinuxAtSpi,
                ResolvedInsertionCapability {
                    insertion_transport: InsertionTransport::AtSpiEditableText,
                    receipt_confidence: ReceiptConfidence::Verified,
                },
                mixed_input_support,
                false,
            ),
        ),
        RoutePolicy::Guarded => {
            let request = match tool_request(context.typing_tool) {
                Ok(request) => request,
                Err(reason) => {
                    cleanup_unarmed(connection, state, installed_listener).await;
                    return Err(reason);
                }
            };
            let Some(tool) = probe_tool(request).await else {
                cleanup_unarmed(connection, state, installed_listener).await;
                return Err(FocusedOutputReasonCode::TypingToolUnavailable);
            };
            (
                Route::Guarded(tool),
                FocusedOutputCapability::guarded_focused_control(
                    FocusedOutputBackend::LinuxAtSpi,
                    ResolvedInsertionCapability {
                        insertion_transport: InsertionTransport::LinuxFocusedKeyboard,
                        receipt_confidence: ReceiptConfidence::Posted,
                    },
                    MixedInputSupport::ObservedInsertionsOnly,
                    false,
                ),
            )
        }
        RoutePolicy::Unavailable => {
            cleanup_unarmed(connection, state, installed_listener).await;
            return Err(FocusedOutputReasonCode::MonitorUnavailable);
        }
    };
    state.registry_owner.arm(&monitor);
    state.session = Some(SessionRecord {
        generation,
        session_id: context.session_id,
        target: recaptured.target,
        route,
        monitor_tier,
        sink,
        cancellation,
        monitor,
        monitor_rx,
        listener_path: installed_listener,
        next_observation: 1,
        caret: recaptured.caret,
        semantic_character_count,
        user_intent: false,
        external_caret: None,
        focus_loss_at: None,
    });
    Ok(BeginData {
        generation,
        capability,
        application: recaptured.application,
    })
}

async fn cleanup_unarmed(
    connection: &AccessibilityConnection,
    state: &mut ConnectedState,
    listener_path: Option<String>,
) {
    if let Some(listener_path) = listener_path {
        if deregister_device_listener(connection, &listener_path)
            .await
            .is_err()
        {
            state.connection_failed = true;
        }
    }
    if deregister_all_events(connection, &mut state.registrations)
        .await
        .is_err()
    {
        state.connection_failed = true;
    }
}
fn semantic_snapshot_valid(caret: i32, character_count: i32) -> bool {
    caret >= 0 && character_count >= caret
}

fn drain_prearm_events<S>(
    events: &mut Pin<Box<S>>,
    target: &Target,
) -> Result<(), FocusedOutputReasonCode>
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    loop {
        match events.next().now_or_never() {
            None => return Ok(()),
            Some(Some(Ok(event))) if !prearm_event_invalidates(target, &event) => {}
            Some(Some(Ok(_))) => return Err(FocusedOutputReasonCode::TargetChanged),
            Some(Some(Err(_))) | Some(None) => {
                return Err(FocusedOutputReasonCode::MonitorUnavailable)
            }
        }
    }
}

fn prearm_event_invalidates(target: &Target, event: &Event) -> bool {
    match event {
        Event::Object(ObjectEvents::TextChanged(event)) => same_object(&event.item, target),
        Event::Object(ObjectEvents::TextCaretMoved(event)) => same_object(&event.item, target),
        Event::Object(ObjectEvents::TextSelectionChanged(event)) => {
            same_object(&event.item, target)
        }
        Event::Object(ObjectEvents::StateChanged(event)) => {
            same_object(&event.item, target)
                && match event.state {
                    State::Focused | State::Sensitive | State::Editable => !event.enabled,
                    State::Defunct => event.enabled,
                    _ => false,
                }
        }
        Event::Focus(FocusEvents::Focus(event)) => !same_object(&event.item, target),
        Event::Mouse(_) => true,
        _ => false,
    }
}

async fn application_cache_items(
    connection: &AccessibilityConnection,
) -> Result<Vec<CacheItem>, FocusedOutputReasonCode> {
    let root = AccessibleProxy::builder(connection.connection())
        .destination(REGISTRY)
        .map_err(|_| FocusedOutputReasonCode::AtSpiUnavailable)?
        .path(ROOT_PATH)
        .map_err(|_| FocusedOutputReasonCode::AtSpiUnavailable)?
        .build()
        .await
        .map_err(|_| FocusedOutputReasonCode::AtSpiUnavailable)?;
    let applications = root
        .get_children()
        .await
        .map_err(|_| FocusedOutputReasonCode::AtSpiUnavailable)?;
    let mut items = Vec::new();
    let mut successful_caches = 0usize;
    for application in applications {
        let Some(bus) = application.name_as_str() else {
            continue;
        };
        let Ok(cache) = CacheProxy::builder(connection.connection())
            .destination(bus)
            .and_then(|builder| builder.path(CACHE_PATH))
        else {
            continue;
        };
        let Ok(cache) = cache.build().await else {
            continue;
        };
        let Ok(mut application_items) = cache.get_items().await else {
            continue;
        };
        successful_caches = successful_caches.saturating_add(1);
        items.append(&mut application_items);
    }
    if successful_caches == 0 {
        Err(FocusedOutputReasonCode::AtSpiUnavailable)
    } else {
        Ok(items)
    }
}

fn live_target_metadata_eligible(states: StateSet, interfaces: InterfaceSet) -> bool {
    states.contains(State::Focused)
        && states.contains(State::Sensitive)
        && states.contains(State::Editable)
        && !states.contains(State::Defunct)
        && interfaces.contains(Interface::Accessible)
        && interfaces.contains(Interface::Text)
}

async fn live_focused_candidates(
    connection: &AccessibilityConnection,
    items: Vec<CacheItem>,
) -> Result<Vec<CacheItem>, FocusedOutputReasonCode> {
    let mut candidates = Vec::new();
    for item in items.into_iter().filter(|item| {
        item.states.contains(State::Editable)
            && !item.states.contains(State::Defunct)
            && item.ifaces.contains(Interface::Accessible)
            && item.ifaces.contains(Interface::Text)
    }) {
        let Some(bus) = item.object.name_as_str() else {
            continue;
        };
        let path = item.object.path_as_str();
        let Ok(target) = accessible(connection, bus, path).await else {
            continue;
        };
        let Ok(states) = target.get_state().await else {
            continue;
        };
        let Ok(role) = target.get_role().await else {
            continue;
        };
        let Ok(interfaces) = target.get_interfaces().await else {
            continue;
        };
        let Ok(attributes) = target.get_attributes().await else {
            continue;
        };
        if !live_target_metadata_eligible(states, interfaces) {
            continue;
        }
        if role == Role::PasswordText || secure_metadata(role, &attributes) {
            return Err(FocusedOutputReasonCode::SecureField);
        }
        candidates.push(item);
    }
    Ok(candidates)
}

async fn capture_target(
    connection: &AccessibilityConnection,
    owner_generation: u64,
) -> Result<Capture, FocusedOutputReasonCode> {
    let items = timeout(TARGET_CALL_DEADLINE, application_cache_items(connection))
        .await
        .map_err(|_| FocusedOutputReasonCode::AtSpiUnavailable)??;
    let candidates = timeout(
        TARGET_CALL_DEADLINE,
        live_focused_candidates(connection, items),
    )
    .await
    .map_err(|_| FocusedOutputReasonCode::AtSpiUnavailable)??;
    let mut candidates = candidates.into_iter();
    let item = candidates
        .next()
        .ok_or(FocusedOutputReasonCode::NoFocusedTarget)?;
    if candidates.next().is_some() {
        return Err(FocusedOutputReasonCode::TargetUnsupported);
    }
    let bus = item
        .object
        .name_as_str()
        .ok_or(FocusedOutputReasonCode::TargetUnsupported)?
        .to_owned();
    let path = item.object.path_as_str().to_owned();
    let app_bus = item
        .app
        .name_as_str()
        .ok_or(FocusedOutputReasonCode::TargetUnsupported)?
        .to_owned();
    let app_path = item.app.path_as_str().to_owned();
    if bus != app_bus {
        return Err(FocusedOutputReasonCode::TargetUnsupported);
    }
    let dbus = zbus::fdo::DBusProxy::new(connection.connection())
        .await
        .map_err(|_| FocusedOutputReasonCode::AtSpiUnavailable)?;
    let bus_name: zbus::names::BusName<'_> = bus
        .as_str()
        .try_into()
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let pid = bounded_call(dbus.get_connection_unix_process_id(bus_name))
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let process = process_identity(pid).map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    reject_own_process_tree(pid)?;
    let target_accessible = accessible(connection, &bus, &path).await?;
    let live_states = bounded_call(target_accessible.get_state())
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let live_role = bounded_call(target_accessible.get_role())
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let live_interfaces = bounded_call(target_accessible.get_interfaces())
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let attributes = bounded_call(target_accessible.get_attributes())
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    if secure_metadata(live_role, &attributes) {
        return Err(FocusedOutputReasonCode::SecureField);
    }
    if !live_target_metadata_eligible(live_states, live_interfaces) {
        return Err(FocusedOutputReasonCode::TargetUnsupported);
    }
    let direct = live_interfaces.contains(Interface::EditableText);
    let text = text(connection, &bus, &path).await?;
    let caret = collapsed_caret(&text).await?;
    // AT-SPI Accessible.name is target-controlled and may contain a document
    // title or URL. Do not carry it across the focused-output trust boundary.
    let application = None;
    drop(text);
    drop(target_accessible);
    Ok(Capture {
        target: Target {
            bus,
            path,
            app_bus,
            app_path,
            pid,
            start_ticks: process.start_ticks,
            owner_generation,
        },
        application,
        caret,
        direct,
    })
}

async fn capture_character_count(
    connection: &AccessibilityConnection,
    target: &Target,
) -> Result<i32, FocusedOutputReasonCode> {
    let text = text(connection, &target.bus, &target.path).await?;
    bounded_call(text.character_count())
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)
}

async fn bounded_call<F, T, E>(future: F) -> Result<T, ()>
where
    F: Future<Output = Result<T, E>>,
{
    match timeout(TARGET_CALL_DEADLINE, future).await {
        Ok(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}

async fn target_metadata_call<F, T, E>(
    session: &SessionRecord,
    future: F,
) -> Result<T, FocusedOutputReasonCode>
where
    F: Future<Output = Result<T, E>>,
{
    match bounded_call(future).await {
        Ok(value) => Ok(value),
        Err(()) => {
            session.monitor.terminal(T_TARGET);
            Err(FocusedOutputReasonCode::TargetChanged)
        }
    }
}

async fn accessible<'a>(
    connection: &'a AccessibilityConnection,
    bus: &'a str,
    path: &'a str,
) -> Result<AccessibleProxy<'a>, FocusedOutputReasonCode> {
    AccessibleProxy::builder(connection.connection())
        .destination(bus)
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .path(path)
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .build()
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)
}

async fn text<'a>(
    connection: &'a AccessibilityConnection,
    bus: &'a str,
    path: &'a str,
) -> Result<TextProxy<'a>, FocusedOutputReasonCode> {
    TextProxy::builder(connection.connection())
        .destination(bus)
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .path(path)
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .build()
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)
}

async fn editable<'a>(
    connection: &'a AccessibilityConnection,
    target: &'a Target,
) -> Result<EditableTextProxy<'a>, FocusedOutputReasonCode> {
    EditableTextProxy::builder(connection.connection())
        .destination(target.bus.as_str())
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .path(target.path.as_str())
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .build()
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)
}

async fn collapsed_caret(proxy: &TextProxy<'_>) -> Result<i32, FocusedOutputReasonCode> {
    let count = bounded_call(proxy.get_n_selections())
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let caret = bounded_call(proxy.caret_offset())
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    if count == 0 {
        return Ok(caret);
    }
    if count != 1 {
        return Err(FocusedOutputReasonCode::InitialSelectionNotCollapsed);
    }
    let (start, end) = bounded_call(proxy.get_selection(0))
        .await
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    if start != end || start != caret {
        return Err(FocusedOutputReasonCode::InitialSelectionNotCollapsed);
    }
    Ok(caret)
}

fn secure_metadata(role: Role, attributes: &HashMap<String, String>) -> bool {
    role == Role::PasswordText || protected_attributes(attributes)
}

fn protected_attributes(attributes: &HashMap<String, String>) -> bool {
    attributes.iter().any(|(key, value)| {
        contains_ascii(key.as_bytes(), b"password")
            || contains_ascii(key.as_bytes(), b"protected")
            || value.eq_ignore_ascii_case("password")
            || value.eq_ignore_ascii_case("protected")
            || value.eq_ignore_ascii_case("true")
                && (contains_ascii(key.as_bytes(), b"secret")
                    || contains_ascii(key.as_bytes(), b"masked"))
    })
}

fn contains_ascii(value: &[u8], needle: &[u8]) -> bool {
    value
        .windows(needle.len())
        .any(|part| part.eq_ignore_ascii_case(needle))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    parent: u32,
    start_ticks: u64,
}

fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_proc_stat(&stat).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proc stat"))
}

fn parse_proc_stat(stat: &str) -> Option<ProcessIdentity> {
    let close = stat.rfind(')')?;
    let mut fields = stat.get(close + 1..)?.split_whitespace();
    fields.next()?; // state (field 3)
    let parent = fields.next()?.parse().ok()?; // ppid (field 4)
    let start_ticks = fields.nth(17)?.parse().ok()?; // starttime (field 22)
    Some(ProcessIdentity {
        parent,
        start_ticks,
    })
}

fn reject_own_process_tree(pid: u32) -> Result<(), FocusedOutputReasonCode> {
    let own = std::process::id();
    if pid == own {
        return Err(FocusedOutputReasonCode::HandyOwnedTarget);
    }
    let mut current = pid;
    for _ in 0..MAX_ANCESTORS {
        let identity =
            process_identity(current).map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if identity.parent == own {
            return Err(FocusedOutputReasonCode::HandyOwnedTarget);
        }
        if identity.parent == 0 || identity.parent == current {
            return Ok(());
        }
        current = identity.parent;
    }
    Err(FocusedOutputReasonCode::TargetUnsupported)
}

async fn validate_target(
    connection: &AccessibilityConnection,
    session: &SessionRecord,
) -> Result<i32, FocusedOutputReasonCode> {
    if session.cancellation.is_cancelled() {
        session.monitor.terminal(T_CANCELLED);
        return Err(FocusedOutputReasonCode::Cancelled);
    }
    let terminal = session.monitor.terminal.load(Ordering::Acquire);
    if terminal != T_NONE {
        return Err(reason_for_terminal(terminal));
    }
    if session.target.owner_generation != session.generation
        || session.target.bus != session.target.app_bus
    {
        session.monitor.terminal(T_TARGET);
        return Err(FocusedOutputReasonCode::TargetChanged);
    }
    if !matches!(
        process_identity(session.target.pid),
        Ok(identity) if identity.start_ticks == session.target.start_ticks
    ) {
        session.monitor.terminal(T_TARGET);
        return Err(FocusedOutputReasonCode::TargetChanged);
    }
    let dbus = zbus::fdo::DBusProxy::new(connection.connection())
        .await
        .map_err(|_| FocusedOutputReasonCode::BackendDisconnected)?;
    let bus: zbus::names::BusName<'_> = session
        .target
        .bus
        .as_str()
        .try_into()
        .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
    if bounded_call(dbus.get_connection_unix_process_id(bus)).await != Ok(session.target.pid) {
        session.monitor.terminal(T_TARGET);
        return Err(FocusedOutputReasonCode::TargetChanged);
    }
    let application = accessible(
        connection,
        &session.target.app_bus,
        &session.target.app_path,
    )
    .await
    .map_err(|_| {
        session.monitor.terminal(T_TARGET);
        FocusedOutputReasonCode::TargetChanged
    })?;
    if target_metadata_call(session, application.get_role()).await? != Role::Application {
        session.monitor.terminal(T_TARGET);
        return Err(FocusedOutputReasonCode::TargetChanged);
    }
    let accessible = accessible(connection, &session.target.bus, &session.target.path)
        .await
        .map_err(|_| {
            session.monitor.terminal(T_TARGET);
            FocusedOutputReasonCode::TargetChanged
        })?;
    let states = target_metadata_call(session, accessible.get_state()).await?;
    let role = target_metadata_call(session, accessible.get_role()).await?;
    let interfaces = target_metadata_call(session, accessible.get_interfaces()).await?;
    let attributes = target_metadata_call(session, accessible.get_attributes()).await?;
    if secure_metadata(role, &attributes) {
        session.monitor.terminal(T_SECURE);
        return Err(FocusedOutputReasonCode::SecureField);
    }
    if !live_target_metadata_eligible(states, interfaces)
        || (matches!(&session.route, Route::Direct)
            && !interfaces.contains(Interface::EditableText))
    {
        session.monitor.terminal(T_TARGET);
        return Err(FocusedOutputReasonCode::TargetChanged);
    }
    let proxy = text(connection, &session.target.bus, &session.target.path)
        .await
        .map_err(|_| {
            session.monitor.terminal(T_TARGET);
            FocusedOutputReasonCode::TargetChanged
        })?;
    collapsed_caret(&proxy).await.map_err(|_| {
        session.monitor.terminal(T_TARGET);
        FocusedOutputReasonCode::TargetChanged
    })
}

async fn semantic_character_count(
    connection: &AccessibilityConnection,
    session: &SessionRecord,
) -> Result<i32, FocusedOutputReasonCode> {
    let proxy = text(connection, &session.target.bus, &session.target.path)
        .await
        .map_err(|_| {
            session.monitor.terminal(T_TARGET);
            FocusedOutputReasonCode::TargetChanged
        })?;
    target_metadata_call(session, proxy.character_count()).await
}

fn drain_buffered_semantic_events<S>(events: &mut Pin<Box<S>>, session: &mut SessionRecord) -> bool
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    if session.monitor_tier == MonitorTier::Physical {
        return true;
    }
    loop {
        match events.next().now_or_never() {
            None => return session.monitor.terminal.load(Ordering::Acquire) == T_NONE,
            Some(Some(Ok(event))) => process_session_event(session, event),
            Some(Some(Err(_))) | Some(None) => {
                session.monitor.terminal(T_MONITOR);
                publish_terminal(session);
                return false;
            }
        }
        if session.monitor.terminal.load(Ordering::Acquire) != T_NONE {
            return false;
        }
    }
}

async fn insert<S>(
    connection: &AccessibilityConnection,
    events: &mut Pin<Box<S>>,
    session: &mut SessionRecord,
    request: InsertionRequest,
) -> InsertOutcome
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    if request.session_id != session.session_id {
        return InsertOutcome::Rejected {
            reason: FocusedOutputReasonCode::TargetChanged,
        };
    }
    if request.text.is_empty() {
        return InsertOutcome::Complete {
            receipt: if matches!(&session.route, Route::Direct) {
                ReceiptConfidence::Verified
            } else {
                ReceiptConfidence::Posted
            },
        };
    }

    loop {
        let intent_epoch = session.monitor.intent_epoch.load(Ordering::Acquire);
        if !finish_external_caret(events, session).await {
            session.monitor.terminal(T_MONITOR);
            publish_terminal(session);
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::MonitorUnavailable,
            };
        }
        let direct = matches!(&session.route, Route::Direct);
        session
            .monitor
            .dispatch_direct
            .store(direct, Ordering::Release);
        session
            .monitor
            .dispatch_text
            .store(!direct, Ordering::Release);
        session.monitor.dispatch.store(true, Ordering::Release);
        let terminal = session.monitor.terminal.load(Ordering::Acquire);
        if session.monitor.intent_epoch.load(Ordering::Acquire) == intent_epoch
            && session.monitor.physical_callbacks.load(Ordering::Acquire) == 0
            && terminal == T_NONE
            && !session.cancellation.is_cancelled()
        {
            break;
        }
        session.monitor.dispatch.store(false, Ordering::Release);
        session
            .monitor
            .dispatch_direct
            .store(false, Ordering::Release);
        session
            .monitor
            .dispatch_text
            .store(false, Ordering::Release);
        if terminal != T_NONE || session.cancellation.is_cancelled() {
            log::debug!(
                "Linux focused insertion disarmed before dispatch: terminal={terminal}, cancelled={}",
                session.cancellation.is_cancelled()
            );
            publish_terminal(session);
            return InsertOutcome::Rejected {
                reason: if terminal == T_NONE {
                    FocusedOutputReasonCode::Cancelled
                } else {
                    reason_for_terminal(terminal)
                },
            };
        }
    }
    let outcome = if matches!(&session.route, Route::Direct) {
        insert_direct(connection, events, session, request).await
    } else {
        let tool = match &session.route {
            Route::Guarded(tool) => tool.clone(),
            Route::Direct => unreachable!(),
        };
        insert_guarded(connection, events, session, request, tool).await
    };
    session.monitor.dispatch.store(false, Ordering::Release);
    session
        .monitor
        .dispatch_direct
        .store(false, Ordering::Release);
    session
        .monitor
        .dispatch_text
        .store(false, Ordering::Release);
    session
        .monitor
        .expected_tool_key_presses
        .store(0, Ordering::Release);
    publish_terminal(session);
    outcome
}

async fn insert_direct<S>(
    connection: &AccessibilityConnection,
    events: &mut Pin<Box<S>>,
    session: &mut SessionRecord,
    request: InsertionRequest,
) -> InsertOutcome
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    let mut accepted = 0;
    for range in scalar_chunks(&request.text, MAX_SCALARS) {
        let chunk = &request.text[range];
        if !drain_buffered_semantic_events(events, session) {
            let terminal = session.monitor.terminal.load(Ordering::Acquire);
            return verified_prefix(accepted, reason_for_terminal(terminal));
        }
        let semantic_count_before = if session.monitor_tier == MonitorTier::AtSpiSemanticOnly {
            let expected = session
                .semantic_character_count
                .expect("semantic-only sessions capture a character count");
            match semantic_character_count(connection, session).await {
                Ok(observed) if observed == expected => Some(expected),
                Ok(observed) => {
                    log::debug!(
                        "Linux semantic-only target length changed: expected={expected}, observed={observed}"
                    );
                    session.monitor.terminal(T_MIXED);
                    return verified_prefix(
                        accepted,
                        FocusedOutputReasonCode::MixedInputUnavailable,
                    );
                }
                Err(reason) => return verified_prefix(accepted, reason),
            }
        } else {
            None
        };
        let caret = match validate_target(connection, session).await {
            Ok(caret) if caret == session.caret => caret,
            Ok(observed) => {
                log::debug!(
                    "Linux focused insertion caret changed: expected={}, observed={observed}",
                    session.caret
                );
                session.monitor.terminal(T_CARET);
                return verified_prefix(accepted, FocusedOutputReasonCode::CaretMoved);
            }
            Err(reason) => {
                log::debug!("Linux focused insertion target validation failed: {reason:?}");
                return verified_prefix(accepted, reason);
            }
        };
        let bytes = match i32::try_from(chunk.len()) {
            Ok(value) => value,
            Err(_) => return verified_prefix(accepted, FocusedOutputReasonCode::InjectionDenied),
        };
        let chars = match i32::try_from(chunk.chars().count()) {
            Ok(value) => value,
            Err(_) => return verified_prefix(accepted, FocusedOutputReasonCode::InjectionDenied),
        };
        let proxy = match editable(connection, &session.target).await {
            Ok(proxy) => proxy,
            Err(reason) => return verified_prefix(accepted, reason),
        };
        let terminal = session.monitor.terminal.load(Ordering::Acquire);
        if terminal != T_NONE || session.cancellation.is_cancelled() {
            return verified_prefix(
                accepted,
                if terminal == T_NONE {
                    FocusedOutputReasonCode::Cancelled
                } else {
                    reason_for_terminal(terminal)
                },
            );
        }
        match timeout(TARGET_CALL_DEADLINE, proxy.insert_text(caret, chunk, bytes)).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                return verified_prefix(accepted, FocusedOutputReasonCode::InjectionDenied)
            }
            _ => {
                return InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                }
            }
        }
        let observed = match read_range(connection, &session.target, caret, chars).await {
            Ok(value) => value,
            Err(()) => {
                return InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                }
            }
        };
        match classify_readback(chunk, &observed) {
            Readback::Complete => {
                accepted += chunk.len();
                session.caret = caret + chars;
            }
            Readback::Partial(bytes) => {
                return InsertOutcome::Partial {
                    accepted_bytes: accepted + bytes,
                    receipt: ReceiptConfidence::Verified,
                    reason: FocusedOutputReasonCode::InjectionPartial,
                }
            }
            Readback::Mismatch => {
                return InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                }
            }
        }
        drop(observed);
        if let Some(count_before) = semantic_count_before {
            let expected_count = match count_before.checked_add(chars) {
                Some(value) => value,
                None => {
                    return verified_prefix_with_deferred_terminal(
                        session,
                        accepted,
                        FocusedOutputReasonCode::MixedInputUnavailable,
                    );
                }
            };
            let observed_caret = match validate_target(connection, session).await {
                Ok(value) => value,
                Err(reason) => {
                    return verified_prefix_with_deferred_terminal(session, accepted, reason)
                }
            };
            let observed_count = match semantic_character_count(connection, session).await {
                Ok(value) => value,
                Err(reason) => {
                    return verified_prefix_with_deferred_terminal(session, accepted, reason)
                }
            };
            if observed_caret != session.caret || observed_count != expected_count {
                log::debug!(
                    "Linux semantic-only post-insert state changed: caret expected={}, observed={observed_caret}; length expected={expected_count}, observed={observed_count}",
                    session.caret
                );
                return verified_prefix_with_deferred_terminal(
                    session,
                    accepted,
                    FocusedOutputReasonCode::MixedInputUnavailable,
                );
            }
            session.semantic_character_count = Some(observed_count);
        }
        let marker = request.injection_id.get();
        let expected = ExpectedEffect {
            start: caret,
            chars,
            marker,
            hash: text_hash(session.generation ^ marker, chunk),
            caret_after: caret + chars,
            tool_key_presses: 0,
        };
        match wait_effect(events, session, expected).await {
            EffectResult::Matched => {}
            EffectResult::Missing | EffectResult::Disconnected => {
                // Exact direct readback is authoritative for this unit. Defer
                // termination until the manager commits its verified prefix.
                return verified_prefix_with_deferred_terminal(
                    session,
                    accepted,
                    FocusedOutputReasonCode::MonitorUnavailable,
                );
            }
            EffectResult::Unsafe => {
                let terminal = session.monitor.terminal.load(Ordering::Acquire);
                let reason = if terminal == T_NONE && session.cancellation.is_cancelled() {
                    FocusedOutputReasonCode::Cancelled
                } else {
                    reason_for_terminal(terminal)
                };
                return verified_prefix_with_deferred_terminal(session, accepted, reason);
            }
        }
    }
    if accepted == request.text.len() {
        session.sink.publish(
            session.session_id,
            TargetInteractionEvent::HandyInsertionObserved {
                injection_id: request.injection_id,
                caret_after: Some(i64::from(session.caret)),
            },
        );
        InsertOutcome::Complete {
            receipt: ReceiptConfidence::Verified,
        }
    } else {
        InsertOutcome::Partial {
            accepted_bytes: accepted,
            receipt: ReceiptConfidence::Verified,
            reason: FocusedOutputReasonCode::InjectionPartial,
        }
    }
}

fn verified_prefix(accepted: usize, reason: FocusedOutputReasonCode) -> InsertOutcome {
    if accepted == 0 {
        InsertOutcome::Rejected { reason }
    } else {
        InsertOutcome::Partial {
            accepted_bytes: accepted,
            receipt: ReceiptConfidence::Verified,
            reason: FocusedOutputReasonCode::InjectionPartial,
        }
    }
}
fn verified_prefix_with_deferred_terminal(
    session: &SessionRecord,
    accepted: usize,
    reason: FocusedOutputReasonCode,
) -> InsertOutcome {
    debug_assert!(accepted > 0);
    session.monitor.terminal.store(T_NONE, Ordering::Release);
    session.monitor.published.store(false, Ordering::Release);
    InsertOutcome::Partial {
        accepted_bytes: accepted,
        receipt: ReceiptConfidence::Verified,
        reason,
    }
}

async fn insert_guarded<S>(
    connection: &AccessibilityConnection,
    events: &mut Pin<Box<S>>,
    session: &mut SessionRecord,
    request: InsertionRequest,

    tool: PinnedTool,
) -> InsertOutcome
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    for range in scalar_chunks(&request.text, MAX_SCALARS) {
        let chunk = &request.text[range];
        let caret = match validate_target(connection, session).await {
            Ok(caret) if caret == session.caret => caret,
            Ok(_) => {
                session.monitor.terminal(T_CARET);
                return InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::CaretMoved,
                };
            }
            Err(reason) => return InsertOutcome::Rejected { reason },
        };
        if !tool.still_pinned() {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::TypingToolUnavailable,
            };
        }
        let char_count = chunk.chars().count();
        let chars = match i32::try_from(char_count) {
            Ok(value) => value,
            Err(_) => {
                return InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::InjectionDenied,
                }
            }
        };
        let expected_presses = match u64::try_from(char_count) {
            Ok(value) => value,
            Err(_) => {
                return InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::InjectionDenied,
                }
            }
        };
        let terminal = session.monitor.terminal.load(Ordering::Acquire);
        if terminal != T_NONE || session.cancellation.is_cancelled() {
            return InsertOutcome::Rejected {
                reason: if terminal == T_NONE {
                    FocusedOutputReasonCode::Cancelled
                } else {
                    reason_for_terminal(terminal)
                },
            };
        }
        session.monitor.tool_key_presses.store(0, Ordering::Release);
        session
            .monitor
            .expected_tool_key_presses
            .store(expected_presses, Ordering::Release);
        let child = typing_child(&tool, chunk, &session.cancellation).await;
        let terminal = session.monitor.terminal.load(Ordering::Acquire);
        if terminal != T_NONE {
            return match child {
                ChildResult::NotStarted => InsertOutcome::Rejected {
                    reason: reason_for_terminal(terminal),
                },
                ChildResult::Complete | ChildResult::PossiblyPosted => InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                },
            };
        }
        match child {
            ChildResult::Complete => {}
            ChildResult::NotStarted => {
                return InsertOutcome::Rejected {
                    reason: if session.cancellation.is_cancelled() {
                        FocusedOutputReasonCode::Cancelled
                    } else {
                        FocusedOutputReasonCode::InjectionDenied
                    },
                };
            }
            ChildResult::PossiblyPosted => {
                return InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                };
            }
        }
        if validate_target(connection, session).await.is_err() {
            return InsertOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            };
        }
        let observed = match read_range(connection, &session.target, caret, chars).await {
            Ok(value) => value,
            Err(()) => {
                return InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                }
            }
        };
        if classify_readback(chunk, &observed) != Readback::Complete {
            return InsertOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            };
        }
        drop(observed);
        let marker = request.injection_id.get();
        let expected = ExpectedEffect {
            start: caret,
            chars,
            marker,
            hash: text_hash(session.generation ^ marker, chunk),
            caret_after: caret + chars,
            tool_key_presses: usize::try_from(chars).unwrap_or(usize::MAX),
        };
        if wait_effect(events, session, expected).await != EffectResult::Matched {
            return InsertOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            };
        }
        session
            .monitor
            .expected_tool_key_presses
            .store(0, Ordering::Release);
        session.caret = caret + chars;
    }
    session.sink.publish(
        session.session_id,
        TargetInteractionEvent::HandyInsertionObserved {
            injection_id: request.injection_id,
            caret_after: Some(i64::from(session.caret)),
        },
    );
    InsertOutcome::Complete {
        receipt: ReceiptConfidence::Posted,
    }
}

async fn read_range(
    connection: &AccessibilityConnection,
    target: &Target,
    start: i32,
    chars: i32,
) -> Result<String, ()> {
    let end = start.checked_add(chars).ok_or(())?;
    let proxy = text(connection, &target.bus, &target.path)
        .await
        .map_err(|_| ())?;
    bounded_call(proxy.get_text(start, end)).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Readback {
    Complete,
    Partial(usize),
    Mismatch,
}

fn classify_readback(requested: &str, observed: &str) -> Readback {
    if requested == observed {
        Readback::Complete
    } else if !observed.is_empty()
        && observed.len() < requested.len()
        && requested.starts_with(observed)
        && requested.is_char_boundary(observed.len())
    {
        Readback::Partial(observed.len())
    } else {
        Readback::Mismatch
    }
}

fn scalar_chunks(text: &str, max: usize) -> ScalarChunks<'_> {
    assert!(max > 0);
    ScalarChunks {
        text,
        max,
        start: 0,
    }
}

struct ScalarChunks<'a> {
    text: &'a str,
    max: usize,
    start: usize,
}

impl Iterator for ScalarChunks<'_> {
    type Item = std::ops::Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start == self.text.len() {
            return None;
        }
        let end = self.text[self.start..]
            .char_indices()
            .nth(self.max)
            .map(|(offset, _)| self.start + offset)
            .unwrap_or(self.text.len());
        let range = self.start..end;
        self.start = end;
        Some(range)
    }
}

#[derive(Clone, Copy)]
struct ExpectedEffect {
    start: i32,
    chars: i32,
    marker: u64,
    hash: u64,
    caret_after: i32,
    tool_key_presses: usize,
}

async fn finish_external_caret<S>(events: &mut Pin<Box<S>>, session: &mut SessionRecord) -> bool
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    drain_one_monitor(session);
    if !session.user_intent && session.external_caret.is_none() {
        return true;
    }
    let deadline = tokio::time::Instant::now() + HANDY_RECEIPT_DEADLINE;
    while (session.user_intent || session.external_caret.is_some())
        && tokio::time::Instant::now() < deadline
    {
        drain_one_monitor(session);
        if session.monitor.terminal.load(Ordering::Acquire) != T_NONE {
            return false;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event = match timeout(remaining.min(POLL), events.next()).await {
            Err(_) => continue,
            Ok(Some(Ok(event))) => event,
            Ok(Some(Err(_))) | Ok(None) => return false,
        };
        let foreign_focus = matches!(&event, Event::Focus(_));
        match classify_event(session, event, None) {
            EventClass::Neutral => {}
            EventClass::External(chars, caret) => {
                let id = next_observation(session);
                session.sink.publish(
                    session.session_id,
                    TargetInteractionEvent::CompatibleExternalInsertion {
                        observation_id: id,
                        chars,
                        caret_after: caret,
                    },
                );
            }
            EventClass::Foreign if !foreign_focus => {}
            EventClass::Foreign => session.monitor.terminal(T_TARGET),
            EventClass::Unsafe(code) => session.monitor.terminal(code),
            EventClass::ExpectedText | EventClass::ExpectedCaret => {
                session.monitor.terminal(T_EDIT);
            }
        }
    }
    if session.user_intent && session.external_caret.is_none() {
        session.user_intent = false;
        true
    } else {
        !session.user_intent && session.external_caret.is_none()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EffectResult {
    Matched,
    Missing,
    Unsafe,
    Disconnected,
}

async fn wait_effect<S>(
    events: &mut Pin<Box<S>>,
    session: &mut SessionRecord,
    expected: ExpectedEffect,
) -> EffectResult
where
    S: Stream<Item = Result<Event, atspi::AtspiError>>,
{
    let deadline = tokio::time::Instant::now() + HANDY_RECEIPT_DEADLINE;
    let mut text_seen = false;
    let mut caret_seen = false;
    loop {
        drain_one_monitor(session);
        if session.cancellation.is_cancelled()
            || session.monitor.terminal.load(Ordering::Acquire) != T_NONE
        {
            return EffectResult::Unsafe;
        }
        let tool_keys = usize::try_from(session.monitor.tool_key_presses.load(Ordering::Acquire))
            .unwrap_or(usize::MAX);
        if expected.tool_key_presses > 0 && tool_keys > expected.tool_key_presses {
            session.monitor.terminal(T_EDIT);
            return EffectResult::Unsafe;
        }
        if text_seen
            && caret_seen
            && (expected.tool_key_presses == 0 || tool_keys == expected.tool_key_presses)
        {
            return EffectResult::Matched;
        }
        if tokio::time::Instant::now() >= deadline {
            return EffectResult::Missing;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event = match timeout(remaining.min(POLL), events.next()).await {
            Err(_) => continue,
            Ok(Some(Ok(event))) => event,
            Ok(Some(Err(_))) | Ok(None) => return EffectResult::Disconnected,
        };
        match classify_event(session, event, Some(expected)) {
            EventClass::ExpectedText => text_seen = true,
            EventClass::ExpectedCaret => caret_seen = true,
            EventClass::Neutral => {}
            EventClass::Unsafe(code) => {
                session.monitor.terminal(code);
                return EffectResult::Unsafe;
            }
            EventClass::External(_, _) | EventClass::Foreign => {
                session.monitor.terminal(T_EDIT);
                return EffectResult::Unsafe;
            }
        }
        if text_seen
            && caret_seen
            && (expected.tool_key_presses == 0
                || usize::try_from(session.monitor.tool_key_presses.load(Ordering::Acquire)).ok()
                    == Some(expected.tool_key_presses))
        {
            return EffectResult::Matched;
        }
    }
}

fn text_hash(generation: u64, text: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ generation.rotate_left(17);
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

enum EventClass {
    ExpectedText,
    ExpectedCaret,
    External(usize, Option<i64>),
    Unsafe(u8),
    Foreign,
    Neutral,
}

fn classify_event(
    session: &mut SessionRecord,
    event: Event,
    expected: Option<ExpectedEffect>,
) -> EventClass {
    match event {
        Event::Object(ObjectEvents::TextChanged(event)) => {
            if !same_object(&event.item, &session.target) {
                return EventClass::Foreign;
            }
            if event.operation == Operation::Delete {
                return EventClass::Unsafe(T_EDIT);
            }
            if let Some(expected) = expected {
                if event.start_pos == expected.start
                    && event.length == expected.chars
                    && text_hash(session.generation ^ expected.marker, &event.text) == expected.hash
                {
                    EventClass::ExpectedText
                } else {
                    EventClass::Unsafe(T_EDIT)
                }
            } else if session.monitor_tier == MonitorTier::AtSpiSemanticOnly {
                EventClass::Unsafe(T_MIXED)
            } else if session.user_intent && event.start_pos == session.caret && event.length > 0 {
                let caret = event.start_pos.saturating_add(event.length);
                match session.external_caret {
                    Some(observed) if observed != caret => {
                        return EventClass::Unsafe(T_CARET);
                    }
                    Some(_) => session.external_caret = None,
                    None => session.external_caret = Some(caret),
                }
                session.user_intent = false;
                session.caret = caret;
                EventClass::External(
                    usize::try_from(event.length).unwrap_or(0),
                    Some(i64::from(session.caret)),
                )
            } else {
                EventClass::Unsafe(T_EDIT)
            }
        }
        Event::Object(ObjectEvents::TextCaretMoved(event)) => {
            if !same_object(&event.item, &session.target) {
                EventClass::Foreign
            } else if expected
                .map(|expected| event.position == expected.caret_after)
                .unwrap_or(false)
            {
                EventClass::ExpectedCaret
            } else if session.user_intent && event.position >= session.caret {
                session.external_caret = Some(event.position);
                EventClass::Neutral
            } else if let Some(expected_caret) = session.external_caret.take() {
                if event.position == expected_caret {
                    EventClass::Neutral
                } else {
                    EventClass::Unsafe(T_CARET)
                }
            } else {
                EventClass::Unsafe(T_CARET)
            }
        }
        Event::Object(ObjectEvents::TextSelectionChanged(event)) => {
            if same_object(&event.item, &session.target) {
                EventClass::Unsafe(T_SELECTION)
            } else {
                EventClass::Foreign
            }
        }
        Event::Object(ObjectEvents::StateChanged(event)) => {
            if !same_object(&event.item, &session.target) {
                EventClass::Foreign
            } else if event.state == State::Focused && !event.enabled {
                if session.monitor_tier == MonitorTier::AtSpiSemanticOnly {
                    EventClass::Unsafe(T_TARGET)
                } else {
                    session.focus_loss_at = Some(Instant::now());
                    EventClass::Neutral
                }
            } else if event.state == State::Focused && event.enabled {
                session.focus_loss_at = None;
                EventClass::Neutral
            } else if (event.state == State::Sensitive || event.state == State::Editable)
                && !event.enabled
            {
                EventClass::Unsafe(T_TARGET)
            } else if event.state == State::Defunct && event.enabled {
                EventClass::Unsafe(T_CLOSED)
            } else {
                EventClass::Neutral
            }
        }
        Event::Focus(FocusEvents::Focus(event)) => {
            if same_object(&event.item, &session.target) {
                EventClass::Neutral
            } else {
                EventClass::Foreign
            }
        }
        Event::Mouse(_) => EventClass::Unsafe(T_POINTER),
        _ => EventClass::Neutral,
    }
}

fn same_object(item: &ObjectRefOwned, target: &Target) -> bool {
    item.name_as_str() == Some(target.bus.as_str()) && item.path_as_str() == target.path
}

fn process_idle_event(state: &mut ConnectedState, event: Event) {
    let Some(session) = state.session.as_mut() else {
        return;
    };
    process_session_event(session, event);
}

fn process_session_event(session: &mut SessionRecord, event: Event) {
    let foreign_focus = matches!(&event, Event::Focus(_));
    match classify_event(session, event, None) {
        EventClass::External(chars, caret) => {
            let id = next_observation(session);
            session.sink.publish(
                session.session_id,
                TargetInteractionEvent::CompatibleExternalInsertion {
                    observation_id: id,
                    chars,
                    caret_after: caret,
                },
            );
        }
        EventClass::Unsafe(code) => session.monitor.terminal(code),
        EventClass::Foreign if foreign_focus => session.monitor.terminal(T_TARGET),
        EventClass::Foreign => {}
        EventClass::ExpectedText | EventClass::ExpectedCaret | EventClass::Neutral => {}
    }
    publish_terminal(session);
}

struct MonitorShared {
    terminal: AtomicU8,
    published: AtomicBool,
    dispatch: AtomicBool,
    dispatch_text: AtomicBool,
    dispatch_direct: AtomicBool,
    tool_key_presses: AtomicU64,
    expected_tool_key_presses: AtomicU64,
    intent_epoch: AtomicU64,
    tx: Sender<MonitorSignal>,
    stop_chord: Option<StopChord>,
    physical_callbacks: AtomicU64,
    cancellation: SessionCancellation,
}

impl MonitorShared {
    fn terminal(&self, code: u8) {
        if self
            .terminal
            .compare_exchange(T_NONE, code, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            log::debug!("Linux focused input monitor entered terminal state: code={code}");
            self.cancellation.cancel();
        }
    }
    fn observe_tool_key(&self) {
        let observed = self
            .tool_key_presses
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if observed > self.expected_tool_key_presses.load(Ordering::Acquire) {
            self.terminal(T_EDIT);
        }
    }

    fn callback(&self, signal: MonitorSignal) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(signal) {
            self.terminal(T_MONITOR);
        }
    }

    fn publish_signal(&self, signal: MonitorSignal) {
        self.callback(signal);
        if matches!(signal, MonitorSignal::SafeIntent) && self.dispatch.load(Ordering::Acquire) {
            self.terminal(T_EDIT);
        }
    }
}

#[derive(Clone, Copy)]
enum MonitorSignal {
    SafeIntent,
    Command,
    Ime,
    Pointer,
    ToolKey,
}

struct CallbackActivity<'a> {
    shared: &'a MonitorShared,
    active: bool,
}

impl<'a> CallbackActivity<'a> {
    fn begin(shared: &'a MonitorShared) -> Self {
        let active = shared
            .physical_callbacks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .is_ok();
        if !active {
            shared.terminal(T_MONITOR);
        }
        Self { shared, active }
    }
}

impl Drop for CallbackActivity<'_> {
    fn drop(&mut self) {
        if self.active {
            self.shared
                .physical_callbacks
                .fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControllerIdentity {
    sender: String,
    pid: u32,
    uid: u32,
}

struct DeviceListener {
    shared: Arc<MonitorShared>,
    controller: ControllerIdentity,
}

#[zbus::interface(name = "org.a11y.atspi.DeviceEventListener", crate = "atspi::zbus")]
impl DeviceListener {
    fn notify_event(
        &self,
        event: DeviceEvent<'_>,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> bool {
        match catch_unwind(AssertUnwindSafe(|| {
            let _activity = CallbackActivity::begin(&self.shared);
            if !sender_is_controller(&self.controller, header.sender().map(|name| name.as_str())) {
                log::debug!(
                    "Linux focused device callback sender mismatch: expected={} actual={:?}",
                    self.controller.sender,
                    header.sender().map(|name| name.as_str())
                );
                self.shared.terminal(T_MONITOR);
                return false;
            }
            if let Some(signal) = device_signal(&self.shared, &event) {
                match signal {
                    MonitorSignal::Command => self.shared.terminal(T_COMMAND),
                    MonitorSignal::Ime => self.shared.terminal(T_IME),
                    MonitorSignal::Pointer => self.shared.terminal(T_POINTER),
                    MonitorSignal::ToolKey => self.shared.observe_tool_key(),
                    MonitorSignal::SafeIntent => {}
                }
                self.shared.publish_signal(signal);
            }
            false
        })) {
            Ok(value) => value,
            Err(_) => {
                log::debug!("Linux focused device callback panicked");
                self.shared.terminal(T_MONITOR);
                false
            }
        }
    }
}

fn sender_is_controller(controller: &ControllerIdentity, sender: Option<&str>) -> bool {
    sender == Some(controller.sender.as_str())
}

async fn controller_identity(
    connection: &AccessibilityConnection,
) -> Result<ControllerIdentity, ()> {
    let dbus = zbus::fdo::DBusProxy::new(connection.connection())
        .await
        .map_err(|_| ())?;
    let registry: zbus::names::BusName<'_> = REGISTRY.try_into().map_err(|_| ())?;
    let owner = bounded_call(dbus.get_name_owner(registry)).await?;
    let owner_name = owner.as_str().to_owned();
    let pid_name: zbus::names::BusName<'_> = owner_name.as_str().try_into().map_err(|_| ())?;
    let pid = bounded_call(dbus.get_connection_unix_process_id(pid_name)).await?;
    let uid_name: zbus::names::BusName<'_> = owner_name.as_str().try_into().map_err(|_| ())?;
    let uid = bounded_call(dbus.get_connection_unix_user(uid_name)).await?;
    Ok(ControllerIdentity {
        sender: owner_name,
        pid,
        uid,
    })
}

fn is_modifier_key(value: &str) -> bool {
    matches_key(
        value,
        &[
            "Shift_L",
            "Shift_R",
            "Control_L",
            "Control_R",
            "Alt_L",
            "Alt_R",
            "Meta_L",
            "Meta_R",
            "Super_L",
            "Super_R",
            "Hyper_L",
            "Hyper_R",
            "ISO_Level3_Shift",
        ],
    )
}

fn device_signal(shared: &MonitorShared, event: &DeviceEvent<'_>) -> Option<MonitorSignal> {
    match event.event_type {
        EventType::ButtonPressed | EventType::ButtonReleased => {
            if !shared.dispatch.load(Ordering::Acquire) {
                shared.intent_epoch.fetch_add(1, Ordering::AcqRel);
                if shared.dispatch.load(Ordering::Acquire) {
                    shared.terminal(T_EDIT);
                    return None;
                }
            }
            Some(MonitorSignal::Pointer)
        }
        EventType::KeyReleased => None,
        EventType::KeyPressed => {
            // Modifier presses have no text-field effect by themselves. The
            // following non-modifier key determines whether this is the
            // configured stop chord or an unsafe command.
            if is_modifier_key(event.event_string) {
                return None;
            }
            if shared
                .stop_chord
                .map(|chord| chord.matches(event.modifiers, event.event_string))
                .unwrap_or(false)
            {
                return None;
            }
            let dispatch = shared.dispatch.load(Ordering::Acquire);
            if !dispatch {
                shared.intent_epoch.fetch_add(1, Ordering::AcqRel);
                if shared.dispatch.load(Ordering::Acquire) {
                    shared.terminal(T_EDIT);
                    return None;
                }
            }
            if dispatch || shared.dispatch.load(Ordering::Acquire) {
                if shared.dispatch_direct.load(Ordering::Acquire) {
                    shared.terminal(T_EDIT);
                    return None;
                }
                if shared.dispatch_text.load(Ordering::Acquire) && !event.is_text {
                    if is_modifier_key(event.event_string) {
                        return None;
                    }
                    return Some(
                        if matches_key(event.event_string, &["Multi_key", "Compose"]) {
                            MonitorSignal::Ime
                        } else {
                            MonitorSignal::Command
                        },
                    );
                }
                return Some(MonitorSignal::ToolKey);
            }
            if matches_key(
                event.event_string,
                &["Multi_key", "Compose", "ISO_Level3_Shift"],
            ) {
                Some(MonitorSignal::Ime)
            } else if unsafe_key(event.modifiers, event.event_string, event.is_text) {
                Some(MonitorSignal::Command)
            } else {
                event.is_text.then_some(MonitorSignal::SafeIntent)
            }
        }
    }
}

fn unsafe_key(modifiers: i32, key: &str, is_text: bool) -> bool {
    const COMMAND_MASK: i32 = (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6);
    if modifiers & COMMAND_MASK != 0 {
        return true;
    }
    !is_text
        && matches_key(
            key,
            &[
                "BackSpace",
                "Delete",
                "Return",
                "Enter",
                "Tab",
                "Escape",
                "Left",
                "Right",
                "Up",
                "Down",
                "Home",
                "End",
                "Page_Up",
                "Page_Down",
                "Insert",
            ],
        )
}

fn matches_key(value: &str, keys: &[&str]) -> bool {
    keys.iter().any(|key| value.eq_ignore_ascii_case(key))
}

#[derive(Clone, Copy)]
struct StopChord {
    modifiers: i32,
    key: ChordKey,
}

#[derive(Clone, Copy)]
enum ChordKey {
    Ascii(u8),
    Space,
    Return,
    Tab,
}

impl StopChord {
    fn parse(value: Option<&str>) -> Option<Self> {
        let mut modifiers = 0;
        let mut key = None;
        for part in value?.split('+').map(str::trim) {
            if part.eq_ignore_ascii_case("ctrl")
                || part.eq_ignore_ascii_case("control")
                || part.eq_ignore_ascii_case("commandorcontrol")
            {
                modifiers |= 1 << 2;
            } else if part.eq_ignore_ascii_case("shift") {
                modifiers |= 1;
            } else if part.eq_ignore_ascii_case("alt") || part.eq_ignore_ascii_case("option") {
                modifiers |= 1 << 3;
            } else if part.eq_ignore_ascii_case("super")
                || part.eq_ignore_ascii_case("meta")
                || part.eq_ignore_ascii_case("command")
            {
                modifiers |= 1 << 4;
            } else if part.eq_ignore_ascii_case("space") {
                key = Some(ChordKey::Space);
            } else if part.eq_ignore_ascii_case("return") || part.eq_ignore_ascii_case("enter") {
                key = Some(ChordKey::Return);
            } else if part.eq_ignore_ascii_case("tab") {
                key = Some(ChordKey::Tab);
            } else if part.len() == 1 && part.as_bytes()[0].is_ascii_alphanumeric() {
                key = Some(ChordKey::Ascii(part.as_bytes()[0].to_ascii_lowercase()));
            } else {
                return None;
            }
        }
        key.map(|key| Self { modifiers, key })
    }

    fn matches(self, modifiers: i32, key: &str) -> bool {
        const RELEVANT: i32 = 1 | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6);
        if modifiers & RELEVANT != self.modifiers {
            return false;
        }
        match self.key {
            ChordKey::Ascii(expected) => {
                key.len() == 1 && key.as_bytes()[0].to_ascii_lowercase() == expected
            }
            ChordKey::Space => key == " " || key.eq_ignore_ascii_case("space"),
            ChordKey::Return => {
                key.eq_ignore_ascii_case("return") || key.eq_ignore_ascii_case("enter")
            }
            ChordKey::Tab => key.eq_ignore_ascii_case("tab"),
        }
    }
}

async fn register_target_events(
    connection: &AccessibilityConnection,
    registrations: &mut EventRegistrations,
) -> Result<(), FocusedOutputReasonCode> {
    let result = async {
        register_event::<TextChangedEvent>(connection).await?;
        registrations.text_changed = true;
        register_event::<TextCaretMovedEvent>(connection).await?;
        registrations.caret_moved = true;
        register_event::<TextSelectionChangedEvent>(connection).await?;
        registrations.selection_changed = true;
        register_event::<StateChangedEvent>(connection).await?;
        registrations.state_changed = true;
        register_event::<FocusEvent>(connection).await?;
        registrations.focus = true;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = deregister_target_events(connection, registrations).await;
    }
    result
}

async fn register_pointer_events(
    connection: &AccessibilityConnection,
    registrations: &mut EventRegistrations,
) -> Result<(), FocusedOutputReasonCode> {
    register_event::<MouseEvents>(connection).await?;
    registrations.mouse = true;
    Ok(())
}

async fn register_event<T>(
    connection: &AccessibilityConnection,
) -> Result<(), FocusedOutputReasonCode>
where
    T: atspi::events::RegistryEventString + atspi::events::DBusMatchRule,
{
    timeout(TARGET_CALL_DEADLINE, connection.register_event::<T>())
        .await
        .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?
        .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)
}

async fn deregister_target_events(
    connection: &AccessibilityConnection,
    registrations: &mut EventRegistrations,
) -> Result<(), ()> {
    let mut removed = true;
    removed &= deregister_if::<TextChangedEvent>(connection, &mut registrations.text_changed)
        .await
        .is_ok();
    removed &= deregister_if::<TextCaretMovedEvent>(connection, &mut registrations.caret_moved)
        .await
        .is_ok();
    removed &= deregister_if::<TextSelectionChangedEvent>(
        connection,
        &mut registrations.selection_changed,
    )
    .await
    .is_ok();
    removed &= deregister_if::<StateChangedEvent>(connection, &mut registrations.state_changed)
        .await
        .is_ok();
    removed &= deregister_if::<FocusEvent>(connection, &mut registrations.focus)
        .await
        .is_ok();
    removed.then_some(()).ok_or(())
}

async fn deregister_pointer_events(
    connection: &AccessibilityConnection,
    registrations: &mut EventRegistrations,
) -> Result<(), ()> {
    deregister_if::<MouseEvents>(connection, &mut registrations.mouse).await
}

async fn deregister_all_events(
    connection: &AccessibilityConnection,
    registrations: &mut EventRegistrations,
) -> Result<(), ()> {
    let pointer = deregister_pointer_events(connection, registrations)
        .await
        .is_ok();
    let target = deregister_target_events(connection, registrations)
        .await
        .is_ok();
    (pointer && target).then_some(()).ok_or(())
}

async fn deregister_if<T>(
    connection: &AccessibilityConnection,
    installed: &mut bool,
) -> Result<(), ()>
where
    T: atspi::events::RegistryEventString + atspi::events::DBusMatchRule,
{
    if !*installed {
        return Ok(());
    }
    deregister_event::<T>(connection).await?;
    *installed = false;
    Ok(())
}

async fn deregister_event<T>(connection: &AccessibilityConnection) -> Result<(), ()>
where
    T: atspi::events::RegistryEventString + atspi::events::DBusMatchRule,
{
    let registry_removed = matches!(
        timeout(
            TARGET_CALL_DEADLINE,
            connection.remove_registry_event::<T>(),
        )
        .await,
        Ok(Ok(()))
    );
    // Removing the registry event does not remove the local D-Bus match rule.
    let rule = zbus::MatchRule::try_from(T::MATCH_RULE_STRING).map_err(|_| ())?;
    let proxy = timeout(
        TARGET_CALL_DEADLINE,
        zbus::fdo::DBusProxy::new(connection.connection()),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let match_removed = matches!(
        timeout(TARGET_CALL_DEADLINE, proxy.remove_match_rule(rule)).await,
        Ok(Ok(()))
    );
    (registry_removed && match_removed).then_some(()).ok_or(())
}

type RegisteredKeystrokeListener = (
    String,
    zbus::zvariant::OwnedObjectPath,
    u32,
    u32,
    Vec<(i32, i32, String, i32)>,
    u32,
    (bool, bool, bool),
);

fn registered_keystroke_listener_identity_matches(
    registration: &RegisteredKeystrokeListener,
    bus: &str,
    path: &str,
) -> bool {
    registration.0 == bus && registration.1.as_str() == path
}

fn registered_keystroke_listener_matches(
    registration: &RegisteredKeystrokeListener,
    bus: &str,
    path: &str,
) -> bool {
    registered_keystroke_listener_identity_matches(registration, bus, path)
        && registration.2 == 0
        && registration.3 == KEY_EVENT_TYPES
        && registration.4.is_empty()
        && registration.5 == 0
        && registration.6 == (false, false, true)
}

fn listener_registration_absent(
    registrations: &[RegisteredKeystrokeListener],
    bus: &str,
    path: &str,
) -> bool {
    !registrations
        .iter()
        .any(|registration| registered_keystroke_listener_identity_matches(registration, bus, path))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhysicalMonitorProbe {
    Installed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistrationReceipt {
    Exact,
    NoExact,
    TimedOut,
    Malformed,
}

fn physical_probe_decision(
    receipt: RegistrationReceipt,
    listener_absent: bool,
    owner_stable: bool,
) -> Result<PhysicalMonitorProbe, FocusedOutputReasonCode> {
    match receipt {
        RegistrationReceipt::Exact => Ok(PhysicalMonitorProbe::Installed),
        RegistrationReceipt::NoExact | RegistrationReceipt::TimedOut
            if listener_absent && owner_stable =>
        {
            Ok(PhysicalMonitorProbe::Unsupported)
        }
        RegistrationReceipt::NoExact
        | RegistrationReceipt::TimedOut
        | RegistrationReceipt::Malformed => Err(FocusedOutputReasonCode::MonitorUnavailable),
    }
}

async fn register_device_listener(
    connection: &AccessibilityConnection,
    listener_path: &str,
    shared: Arc<MonitorShared>,
) -> Result<PhysicalMonitorProbe, FocusedOutputReasonCode> {
    let controller = controller_identity(connection)
        .await
        .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
    let listener_bus = connection
        .connection()
        .unique_name()
        .map(|name| name.as_str().to_owned())
        .ok_or(FocusedOutputReasonCode::MonitorUnavailable)?;
    let path: zbus::zvariant::ObjectPath<'_> = listener_path
        .try_into()
        .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
    let mode = EventListenerMode {
        synchronous: false,
        preemptive: false,
        global: true,
    };
    let signal_rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(controller.sender.as_str())
        .and_then(|builder| builder.path(DEVICE_EVENT_CONTROLLER_PATH))
        .and_then(|builder| builder.interface(DEVICE_EVENT_LISTENER_INTERFACE))
        .and_then(|builder| builder.member("KeystrokeListenerRegistered"))
        .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?
        .build();
    let mut registrations = timeout(
        TARGET_CALL_DEADLINE,
        zbus::MessageStream::for_match_rule(signal_rule, connection.connection(), Some(1)),
    )
    .await
    .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?
    .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
    let raw_proxy = zbus::Proxy::new(
        connection.connection(),
        REGISTRY,
        DEVICE_EVENT_CONTROLLER_PATH,
        DEVICE_EVENT_CONTROLLER_INTERFACE,
    )
    .await
    .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
    connection
        .connection()
        .object_server()
        .at(
            listener_path,
            DeviceListener {
                shared,
                controller: controller.clone(),
            },
        )
        .await
        .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
    let keys: [KeyDefinition<'_>; 0] = [];
    let registration_args = (&path, keys.as_slice(), 0u32, KEY_EVENT_TYPES, &mode);
    let registration_signal = async {
        while let Some(message) = registrations.next().await {
            let message = message.map_err(|_| ())?;
            let registration = message
                .body()
                .deserialize::<RegisteredKeystrokeListener>()
                .map_err(|_| ())?;
            let exact =
                registered_keystroke_listener_matches(&registration, &listener_bus, listener_path);
            log::debug!("AT-SPI key registration signal matched request: {exact}");
            if exact {
                return Ok::<bool, ()>(true);
            }
        }
        Ok::<bool, ()>(false)
    };
    let (_registration_call, keystrokes) = tokio::join!(
        timeout(
            TARGET_CALL_DEADLINE,
            raw_proxy.call::<_, _, bool>("RegisterKeystrokeListener", &registration_args,),
        ),
        timeout(TARGET_CALL_DEADLINE, registration_signal),
    );
    let receipt = match keystrokes {
        Ok(Ok(true)) => RegistrationReceipt::Exact,
        Ok(Ok(false)) => RegistrationReceipt::NoExact,
        Err(_) => RegistrationReceipt::TimedOut,
        Ok(Err(())) => RegistrationReceipt::Malformed,
    };
    if receipt == RegistrationReceipt::Exact {
        return physical_probe_decision(receipt, true, true);
    }
    let listener_absent = rollback_device_listener(connection, listener_path, &listener_bus)
        .await
        .is_ok();
    let owner_stable = controller_identity(connection).await == Ok(controller);
    physical_probe_decision(receipt, listener_absent, owner_stable)
}

async fn rollback_device_listener(
    connection: &AccessibilityConnection,
    listener_path: &str,
    listener_bus: &str,
) -> Result<(), ()> {
    let path = zbus::zvariant::ObjectPath::try_from(listener_path).map_err(|_| ())?;
    let raw_proxy = zbus::Proxy::new(
        connection.connection(),
        REGISTRY,
        DEVICE_EVENT_CONTROLLER_PATH,
        DEVICE_EVENT_CONTROLLER_INTERFACE,
    )
    .await
    .map_err(|_| ())?;
    let keys: [KeyDefinition<'_>; 0] = [];
    let _ = timeout(
        TARGET_CALL_DEADLINE,
        raw_proxy.call::<_, _, ()>(
            "DeregisterKeystrokeListener",
            &(&path, keys.as_slice(), 0u32, KEY_EVENT_TYPES),
        ),
    )
    .await;
    let listeners = timeout(
        TARGET_CALL_DEADLINE,
        raw_proxy.call::<_, _, Vec<RegisteredKeystrokeListener>>("GetKeystrokeListeners", &()),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    if !listener_registration_absent(&listeners, listener_bus, listener_path) {
        return Err(());
    }
    remove_listener(connection, listener_path).await
}

async fn deregister_device_listener(
    connection: &AccessibilityConnection,
    listener_path: &str,
) -> Result<(), ()> {
    let listener_bus = connection
        .connection()
        .unique_name()
        .map(|name| name.as_str().to_owned());
    let result = match listener_bus {
        Some(listener_bus) => {
            rollback_device_listener(connection, listener_path, &listener_bus).await
        }
        None => Err(()),
    };
    if result.is_err() {
        let _ = remove_listener(connection, listener_path).await;
    }
    result
}

async fn remove_listener(
    connection: &AccessibilityConnection,
    listener_path: &str,
) -> Result<(), ()> {
    timeout(
        TARGET_CALL_DEADLINE,
        connection
            .connection()
            .object_server()
            .remove::<DeviceListener, _>(listener_path),
    )
    .await
    .map_err(|_| ())?
    .map(|_| ())
    .map_err(|_| ())
}

fn focus_loss_expired(lost_at: Option<Instant>) -> bool {
    lost_at.is_some_and(|lost_at| lost_at.elapsed() >= FOCUS_LOSS_GRACE)
}

async fn drain_monitor(connection: &AccessibilityConnection, state: &mut ConnectedState) {
    let Some(session) = state.session.as_mut() else {
        return;
    };
    drain_one_monitor(session);
    if session.monitor.terminal.load(Ordering::Acquire) != T_NONE {
        if let Some(listener_path) = session.listener_path.take() {
            if deregister_device_listener(connection, &listener_path)
                .await
                .is_err()
            {
                state.connection_failed = true;
            }
        }
    }
}

fn drain_one_monitor(session: &mut SessionRecord) {
    if focus_loss_expired(session.focus_loss_at) {
        session.monitor.terminal(T_CLOSED);
    }
    while let Ok(signal) = session.monitor_rx.try_recv() {
        match signal {
            MonitorSignal::SafeIntent => {
                if session.user_intent || session.external_caret.is_some() {
                    session.monitor.terminal(T_EDIT);
                } else {
                    session.user_intent = true;
                }
            }
            MonitorSignal::Command => session.monitor.terminal(T_COMMAND),
            MonitorSignal::Ime => session.monitor.terminal(T_IME),
            MonitorSignal::Pointer => session.monitor.terminal(T_POINTER),
            MonitorSignal::ToolKey => {}
        }
    }
    publish_terminal(session);
}

fn next_observation(session: &mut SessionRecord) -> ObservationId {
    let id = session.next_observation;
    session.next_observation = session.next_observation.wrapping_add(1).max(1);
    ObservationId(id)
}

fn publish_terminal(session: &mut SessionRecord) {
    let code = session.monitor.terminal.load(Ordering::Acquire);
    if code == T_NONE || session.monitor.published.swap(true, Ordering::AcqRel) {
        return;
    }
    let id = next_observation(session);
    let event = match code {
        T_POINTER => TargetInteractionEvent::TargetInvalidated {
            observation_id: id,
            reason: FocusedOutputReasonCode::PhysicalPointerActivity,
        },
        T_EDIT => TargetInteractionEvent::UnsafeEdit {
            observation_id: id,
            kind: UnsafeEditKind::Unknown,
        },
        T_MIXED => TargetInteractionEvent::UnsafeEdit {
            observation_id: id,
            kind: UnsafeEditKind::UnattributedInsertion,
        },
        T_CARET => TargetInteractionEvent::UnsafeEdit {
            observation_id: id,
            kind: UnsafeEditKind::CaretRepositioned,
        },
        T_SELECTION => TargetInteractionEvent::UnsafeEdit {
            observation_id: id,
            kind: UnsafeEditKind::SelectionChanged,
        },
        T_COMMAND => TargetInteractionEvent::UnsafeEdit {
            observation_id: id,
            kind: UnsafeEditKind::CommandShortcut,
        },
        T_IME => TargetInteractionEvent::UnsafeEdit {
            observation_id: id,
            kind: UnsafeEditKind::ImeComposition,
        },
        T_MONITOR => TargetInteractionEvent::MonitorUnavailable { observation_id: id },
        T_CLOSED => TargetInteractionEvent::TargetInvalidated {
            observation_id: id,
            reason: FocusedOutputReasonCode::TargetClosed,
        },
        T_CANCELLED => TargetInteractionEvent::TargetInvalidated {
            observation_id: id,
            reason: FocusedOutputReasonCode::Cancelled,
        },
        T_SECURE => TargetInteractionEvent::TargetInvalidated {
            observation_id: id,
            reason: FocusedOutputReasonCode::SecureField,
        },
        _ => TargetInteractionEvent::TargetInvalidated {
            observation_id: id,
            reason: FocusedOutputReasonCode::TargetChanged,
        },
    };
    session.sink.publish(session.session_id, event);
}

fn reason_for_terminal(code: u8) -> FocusedOutputReasonCode {
    match code {
        T_POINTER => FocusedOutputReasonCode::PhysicalPointerActivity,
        T_EDIT => FocusedOutputReasonCode::DestructiveUserEdit,
        T_CARET => FocusedOutputReasonCode::CaretMoved,
        T_SELECTION => FocusedOutputReasonCode::SelectionChanged,
        T_COMMAND => FocusedOutputReasonCode::UnsafeKeyboardCommand,
        T_IME => FocusedOutputReasonCode::ImeCompositionUnsupported,
        T_MIXED => FocusedOutputReasonCode::MixedInputUnavailable,
        T_MONITOR => FocusedOutputReasonCode::MonitorUnavailable,
        T_CLOSED => FocusedOutputReasonCode::TargetClosed,
        T_CANCELLED => FocusedOutputReasonCode::Cancelled,
        T_SECURE => FocusedOutputReasonCode::SecureField,
        _ => FocusedOutputReasonCode::TargetChanged,
    }
}

fn invalidate_bus(state: &mut ConnectedState) {
    if let Some(session) = state.session.as_mut() {
        session.monitor.terminal(T_MONITOR);
        publish_terminal(session);
    }
}

async fn cleanup(connection: &AccessibilityConnection, session: &mut SessionRecord) -> bool {
    session.monitor.terminal(T_CANCELLED);
    session.monitor.dispatch.store(false, Ordering::Release);
    session
        .monitor
        .dispatch_direct
        .store(false, Ordering::Release);
    session
        .monitor
        .dispatch_text
        .store(false, Ordering::Release);
    match session.listener_path.take() {
        Some(listener_path) => deregister_device_listener(connection, &listener_path)
            .await
            .is_ok(),
        None => true,
    }
}

async fn close_all(connection: &AccessibilityConnection, state: &mut ConnectedState) {
    if let Some(mut session) = state.session.take() {
        cleanup(connection, &mut session).await;
    }
    let _ = deregister_all_events(connection, &mut state.registrations).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolRequest {
    Auto,
    Wtype,
    Ydotool,
}

fn tool_request(tool: TypingTool) -> Result<ToolRequest, FocusedOutputReasonCode> {
    match tool {
        TypingTool::Auto => Ok(ToolRequest::Auto),
        TypingTool::Wtype => Ok(ToolRequest::Wtype),
        TypingTool::Ydotool => Ok(ToolRequest::Ydotool),
        TypingTool::Kwtype | TypingTool::Dotool | TypingTool::Xdotool => {
            Err(FocusedOutputReasonCode::TypingToolUnavailable)
        }
    }
}

async fn probe_tool(request: ToolRequest) -> Option<PinnedTool> {
    let kinds: &[ToolKind] = match request {
        ToolRequest::Auto => &[ToolKind::Wtype, ToolKind::Ydotool],
        ToolRequest::Wtype => &[ToolKind::Wtype],
        ToolRequest::Ydotool => &[ToolKind::Ydotool],
    };
    for kind in kinds {
        let Some(tool) = PinnedTool::resolve(*kind) else {
            continue;
        };
        // Empty stdin probes the exact reviewed transport without typing into
        // the focused target. ydotool must positively accept --file=-.
        if typing_child(&tool, "", &SessionCancellation::default()).await == ChildResult::Complete {
            return Some(tool);
        }
    }
    None
}

impl PinnedTool {
    fn resolve(kind: ToolKind) -> Option<Self> {
        let executable = TrustedExecutable::resolve(match kind {
            ToolKind::Wtype => "wtype",
            ToolKind::Ydotool => "ydotool",
        })?;
        Some(Self { executable, kind })
    }

    fn still_pinned(&self) -> bool {
        self.executable.is_unchanged()
    }
}

fn typing_args(kind: ToolKind) -> &'static [&'static str] {
    match kind {
        ToolKind::Wtype => &["-"],
        ToolKind::Ydotool => &["type", "--file=-"],
    }
}

async fn typing_child(
    tool: &PinnedTool,
    text: &str,
    cancellation: &SessionCancellation,
) -> ChildResult {
    if cancellation.is_cancelled() {
        return ChildResult::NotStarted;
    }
    match ChildGuard::spawn(&tool.executable, typing_args(tool.kind)) {
        Ok(child) => child.run(text.as_bytes(), cancellation).await,
        Err(_) => ChildResult::NotStarted,
    }
}

async fn submit(
    _connection: &AccessibilityConnection,
    _session: &mut SessionRecord,
    _key: AutoSubmitKey,
) -> SubmitOutcome {
    SubmitOutcome::Rejected {
        reason: FocusedOutputReasonCode::AutoSubmitUnsupported,
    }
}

struct ChildGuard {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    process_group: i32,
    limits: ChildLimits,
}

#[derive(Clone, Copy)]
struct ChildLimits {
    ipc: Duration,
    process: Duration,
}

impl Default for ChildLimits {
    fn default() -> Self {
        Self {
            ipc: TARGET_CALL_DEADLINE,
            process: CHILD_PROCESS_DEADLINE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildResult {
    Complete,
    NotStarted,
    PossiblyPosted,
}

impl ChildGuard {
    fn spawn(executable: &TrustedExecutable, args: &[&str]) -> io::Result<Self> {
        Self::spawn_with_limits(executable, args, ChildLimits::default())
    }

    fn spawn_with_limits(
        executable: &TrustedExecutable,
        args: &[&str],
        limits: ChildLimits,
    ) -> io::Result<Self> {
        let mut command = executable.command()?;
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        let process_group = match i32::try_from(child.id()) {
            Ok(pid) => pid,
            Err(_) => {
                terminate_spawned(child, 0);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "child pid"));
            }
        };
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                terminate_spawned(child, process_group);
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "missing stdin"));
            }
        };
        if let Err(error) = set_nonblocking(stdin.as_raw_fd()) {
            drop(stdin);
            terminate_spawned(child, process_group);
            return Err(error);
        }
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            process_group,
            limits,
        })
    }

    async fn run(mut self, input: &[u8], cancellation: &SessionCancellation) -> ChildResult {
        let started = Instant::now();
        let ipc_deadline = started + self.limits.ipc;
        let process_deadline = started + self.limits.process;
        let mut written = 0;
        while written < input.len() {
            if cancellation.is_cancelled() {
                self.kill_reap().await;
                return if written == 0 {
                    ChildResult::NotStarted
                } else {
                    ChildResult::PossiblyPosted
                };
            }
            if Instant::now() >= ipc_deadline || Instant::now() >= process_deadline {
                self.kill_reap().await;
                return ChildResult::PossiblyPosted;
            }
            match self
                .stdin
                .as_mut()
                .expect("stdin exists while writing")
                .write(&input[written..])
            {
                Ok(0) => {
                    self.kill_reap().await;
                    return ChildResult::PossiblyPosted;
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => sleep(POLL).await,
                Err(_) => {
                    self.kill_reap().await;
                    return if written == 0 {
                        ChildResult::NotStarted
                    } else {
                        ChildResult::PossiblyPosted
                    };
                }
            }
        }
        self.stdin.take();
        loop {
            if cancellation.is_cancelled() {
                self.kill_reap().await;
                return ChildResult::PossiblyPosted;
            }
            let wait_result = match self.child.as_mut() {
                Some(child) => child.try_wait(),
                None => return ChildResult::PossiblyPosted,
            };
            match wait_result {
                Ok(Some(status)) => {
                    unsafe {
                        libc::kill(-self.process_group, libc::SIGKILL);
                    }
                    self.child.take();
                    return classify_exit(status, written);
                }
                Ok(None) if Instant::now() < process_deadline => sleep(POLL).await,
                Ok(None) | Err(_) => {
                    self.kill_reap().await;
                    return ChildResult::PossiblyPosted;
                }
            }
        }
    }

    async fn kill_reap(&mut self) {
        self.stdin.take();
        if self.child.is_none() {
            return;
        }
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            let reaped = match self.child.as_mut() {
                Some(child) => matches!(child.try_wait(), Ok(Some(_))),
                None => true,
            };
            if reaped {
                self.child.take();
                return;
            }
            if Instant::now() >= deadline {
                if let Some(child) = self.child.take() {
                    crate::clipboard::reap_child_later(child);
                }
                return;
            }
            sleep(POLL).await;
        }
    }
}
fn terminate_spawned(mut child: Child, process_group: i32) {
    if process_group > 0 {
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    crate::clipboard::reap_child_later(child);
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stdin.take();
        let Some(mut child) = self.child.take() else {
            return;
        };
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        let _ = child.kill();
        crate::clipboard::reap_child_later(child);
    }
}

fn classify_exit(status: ExitStatus, written: usize) -> ChildResult {
    if status.success() {
        ChildResult::Complete
    } else if written == 0 {
        ChildResult::NotStarted
    } else {
        ChildResult::PossiblyPosted
    }
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn runtime_route_policy_downgrades_only_direct_semantic_targets() {
        assert_eq!(
            route_policy(true, MonitorTier::Physical),
            RoutePolicy::Direct(MixedInputSupport::ObservedInsertionsOnly)
        );
        assert_eq!(
            route_policy(true, MonitorTier::AtSpiSemanticOnly),
            RoutePolicy::Direct(MixedInputSupport::Unavailable)
        );
        assert_eq!(
            route_policy(false, MonitorTier::Physical),
            RoutePolicy::Guarded
        );
        assert_eq!(
            route_policy(false, MonitorTier::AtSpiSemanticOnly),
            RoutePolicy::Unavailable
        );
    }

    #[test]
    fn semantic_snapshot_requires_nonnegative_bounded_caret() {
        assert!(semantic_snapshot_valid(0, 0));
        assert!(semantic_snapshot_valid(4, 4));
        assert!(semantic_snapshot_valid(4, 5));
        assert!(!semantic_snapshot_valid(-1, 0));
        assert!(!semantic_snapshot_valid(-2, -1));
        assert!(!semantic_snapshot_valid(5, 4));
    }

    #[test]
    fn physical_probe_downgrades_only_after_proven_cleanup() {
        assert_eq!(
            physical_probe_decision(RegistrationReceipt::Exact, false, false),
            Ok(PhysicalMonitorProbe::Installed)
        );
        for receipt in [RegistrationReceipt::NoExact, RegistrationReceipt::TimedOut] {
            assert_eq!(
                physical_probe_decision(receipt, true, true),
                Ok(PhysicalMonitorProbe::Unsupported)
            );
            assert_eq!(
                physical_probe_decision(receipt, false, true),
                Err(FocusedOutputReasonCode::MonitorUnavailable)
            );
            assert_eq!(
                physical_probe_decision(receipt, true, false),
                Err(FocusedOutputReasonCode::MonitorUnavailable)
            );
        }
        assert_eq!(
            physical_probe_decision(RegistrationReceipt::Malformed, true, true),
            Err(FocusedOutputReasonCode::MonitorUnavailable)
        );
    }

    #[derive(Default)]
    struct TestSessionSink {
        events: Mutex<Vec<TargetInteractionEvent>>,
    }

    impl SessionEventSink for TestSessionSink {
        fn publish(&self, _: DictationSessionId, event: TargetInteractionEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn test_session_with_sink(monitor_tier: MonitorTier) -> (SessionRecord, Arc<TestSessionSink>) {
        let cancellation = SessionCancellation::default();
        let (tx, monitor_rx) = bounded(4);
        let monitor = Arc::new(MonitorShared {
            terminal: AtomicU8::new(T_NONE),
            published: AtomicBool::new(false),
            dispatch: AtomicBool::new(false),
            dispatch_text: AtomicBool::new(false),
            dispatch_direct: AtomicBool::new(false),
            tool_key_presses: AtomicU64::new(0),
            expected_tool_key_presses: AtomicU64::new(0),
            intent_epoch: AtomicU64::new(0),
            tx,
            stop_chord: None,
            physical_callbacks: AtomicU64::new(0),
            cancellation: cancellation.clone(),
        });
        let sink = Arc::new(TestSessionSink::default());
        let session = SessionRecord {
            generation: 1,
            session_id: DictationSessionId(1),
            target: Target {
                bus: ":0.0".to_owned(),
                path: "/org/a11y/atspi/test/default".to_owned(),
                app_bus: ":0.0".to_owned(),
                app_path: "/org/a11y/atspi/test/default".to_owned(),
                pid: 1,
                start_ticks: 1,
                owner_generation: 1,
            },
            route: Route::Direct,
            monitor_tier,
            sink: sink.clone(),
            cancellation,
            monitor,
            monitor_rx,
            listener_path: None,
            next_observation: 1,
            caret: 4,
            semantic_character_count: (monitor_tier == MonitorTier::AtSpiSemanticOnly).then_some(4),
            user_intent: false,
            external_caret: None,
            focus_loss_at: None,
        };
        (session, sink)
    }

    fn test_session(monitor_tier: MonitorTier) -> SessionRecord {
        test_session_with_sink(monitor_tier).0
    }

    fn test_item() -> ObjectRefOwned {
        atspi::ObjectRef::new_owned(
            zbus::names::UniqueName::from_static_str_unchecked(":0.0"),
            zbus::zvariant::ObjectPath::from_static_str_unchecked("/org/a11y/atspi/test/default"),
        )
    }

    fn text_insert_event(text: &str) -> Event {
        Event::Object(ObjectEvents::TextChanged(TextChangedEvent {
            item: test_item(),
            operation: Operation::Insert,
            start_pos: 4,
            length: i32::try_from(text.chars().count()).unwrap(),
            text: text.to_owned(),
        }))
    }

    #[test]
    fn semantic_only_insertions_are_unattributed_unless_expected() {
        let mut session = test_session(MonitorTier::AtSpiSemanticOnly);
        assert!(matches!(
            classify_event(&mut session, text_insert_event("x"), None),
            EventClass::Unsafe(T_MIXED)
        ));
        assert_eq!(
            reason_for_terminal(T_MIXED),
            FocusedOutputReasonCode::MixedInputUnavailable
        );

        let expected = ExpectedEffect {
            start: 4,
            chars: 1,
            marker: 7,
            hash: text_hash(session.generation ^ 7, "x"),
            caret_after: 5,
            tool_key_presses: 0,
        };
        assert!(matches!(
            classify_event(&mut session, text_insert_event("x"), Some(expected)),
            EventClass::ExpectedText
        ));
    }

    #[test]
    fn semantic_only_conflict_reports_unattributed_insertion() {
        let (mut session, sink) = test_session_with_sink(MonitorTier::AtSpiSemanticOnly);
        process_session_event(&mut session, text_insert_event("private"));
        let event = sink.events.lock().unwrap().pop().unwrap();
        assert!(matches!(
            event,
            TargetInteractionEvent::UnsafeEdit {
                kind: UnsafeEditKind::UnattributedInsertion,
                ..
            }
        ));
    }

    #[test]
    fn semantic_only_prewrite_drain_rejects_buffered_target_edits() {
        let mut session = test_session(MonitorTier::AtSpiSemanticOnly);
        let events =
            futures_util::stream::iter([Ok::<_, atspi::AtspiError>(text_insert_event("x"))]);
        let mut events = Box::pin(events);
        assert!(!drain_buffered_semantic_events(&mut events, &mut session));
        assert_eq!(session.monitor.terminal.load(Ordering::Acquire), T_MIXED);
    }

    #[test]
    fn semantic_only_prewrite_drain_treats_stream_closure_as_monitor_loss() {
        let mut session = test_session(MonitorTier::AtSpiSemanticOnly);
        let events = futures_util::stream::iter(Vec::<Result<Event, atspi::AtspiError>>::new());
        let mut events = Box::pin(events);
        assert!(!drain_buffered_semantic_events(&mut events, &mut session));
        assert_eq!(session.monitor.terminal.load(Ordering::Acquire), T_MONITOR);
    }

    #[test]
    fn physical_prewrite_path_does_not_consume_semantic_events() {
        let mut session = test_session(MonitorTier::Physical);
        let events =
            futures_util::stream::iter([Ok::<_, atspi::AtspiError>(text_insert_event("x"))]);
        let mut events = Box::pin(events);
        assert!(drain_buffered_semantic_events(&mut events, &mut session));
        assert!(matches!(events.next().now_or_never(), Some(Some(Ok(_)))));
    }

    #[test]
    fn physical_monitor_retains_compatible_external_insertion_classification() {
        let mut session = test_session(MonitorTier::Physical);
        session.user_intent = true;
        assert!(matches!(
            classify_event(&mut session, text_insert_event("x"), None),
            EventClass::External(1, Some(5))
        ));
    }

    #[test]
    fn semantic_only_target_state_loss_is_immediately_terminal() {
        let mut session = test_session(MonitorTier::AtSpiSemanticOnly);
        for state in [State::Focused, State::Sensitive, State::Editable] {
            let event = Event::Object(ObjectEvents::StateChanged(StateChangedEvent {
                item: test_item(),
                state,
                enabled: false,
            }));
            assert!(matches!(
                classify_event(&mut session, event, None),
                EventClass::Unsafe(T_TARGET)
            ));
        }
        let event = Event::Object(ObjectEvents::StateChanged(StateChangedEvent {
            item: test_item(),
            state: State::Defunct,
            enabled: true,
        }));
        assert!(matches!(
            classify_event(&mut session, event, None),
            EventClass::Unsafe(T_CLOSED)
        ));
    }
    #[test]
    fn allowlist_rejects_unreviewed_and_argv_transports() {
        assert_eq!(tool_request(TypingTool::Auto), Ok(ToolRequest::Auto));
        assert_eq!(tool_request(TypingTool::Wtype), Ok(ToolRequest::Wtype));
        assert_eq!(tool_request(TypingTool::Ydotool), Ok(ToolRequest::Ydotool));
        for tool in [TypingTool::Dotool, TypingTool::Kwtype, TypingTool::Xdotool] {
            assert_eq!(
                tool_request(tool).err(),
                Some(FocusedOutputReasonCode::TypingToolUnavailable)
            );
        }
        assert_eq!(typing_args(ToolKind::Wtype), ["-"]);
        assert_eq!(typing_args(ToolKind::Ydotool), ["type", "--file=-"]);
    }

    #[test]
    fn scalar_chunks_are_utf8_safe_and_at_most_sixteen() {
        let value = "aé日🦀bcdefghijklmnopq🦀rst";
        let ranges = scalar_chunks(value, MAX_SCALARS);
        let mut rebuilt = String::new();
        for range in ranges {
            let chunk = &value[range];
            assert!(chunk.chars().count() <= MAX_SCALARS);
            rebuilt.push_str(chunk);
        }
        assert_eq!(rebuilt, value);
    }

    #[test]
    fn readback_classification_never_guesses() {
        assert_eq!(classify_readback("hello🦀", "hello🦀"), Readback::Complete);
        assert_eq!(classify_readback("hello🦀", "hello"), Readback::Partial(5));
        assert_eq!(classify_readback("hello", "hallo"), Readback::Mismatch);
        assert_eq!(classify_readback("hello", ""), Readback::Mismatch);
        assert_eq!(classify_readback("é", "\u{fffd}"), Readback::Mismatch);
    }

    #[test]
    fn proc_identity_and_tree_rejection_are_strict() {
        let mut fields = vec!["S".to_owned(), "42".to_owned()];
        fields.extend((5..22).map(|number| number.to_string()));
        fields.push("987654".to_owned());
        let parsed = parse_proc_stat(&format!("123 (app (renderer)) {}", fields.join(" ")))
            .expect("valid stat");
        assert_eq!(parsed.parent, 42);
        assert_eq!(parsed.start_ticks, 987654);

        fn rejects(target: u32, own: u32, parents: &BTreeMap<u32, u32>) -> bool {
            if target == own {
                return true;
            }
            let mut current = target;
            for _ in 0..MAX_ANCESTORS {
                let Some(parent) = parents.get(&current).copied() else {
                    return true;
                };
                if parent == own {
                    return true;
                }
                if parent == 0 || parent == current {
                    return false;
                }
                current = parent;
            }
            true
        }
        let parents = BTreeMap::from([(500, 400), (400, 100), (900, 1), (1, 0)]);
        assert!(rejects(100, 100, &parents));
        assert!(rejects(500, 100, &parents));
        assert!(!rejects(900, 100, &parents));
        assert!(rejects(777, 100, &parents));
    }

    #[test]
    fn live_target_metadata_accepts_required_metadata_without_enabled() {
        let states = StateSet::new(State::Focused | State::Sensitive | State::Editable);
        let interfaces = InterfaceSet::new(Interface::Accessible | Interface::Text);

        assert!(!states.contains(State::Enabled));
        assert!(live_target_metadata_eligible(states, interfaces));
    }

    #[test]
    fn live_target_metadata_rejects_missing_requirements_and_defunct_targets() {
        let states = StateSet::new(State::Focused | State::Sensitive | State::Editable);
        let interfaces = InterfaceSet::new(Interface::Accessible | Interface::Text);

        for missing in [State::Focused, State::Sensitive, State::Editable] {
            let mut incomplete = states;
            incomplete.remove(missing);
            assert!(!live_target_metadata_eligible(incomplete, interfaces));
        }

        let mut defunct = states;
        defunct.insert(State::Defunct);
        assert!(!live_target_metadata_eligible(defunct, interfaces));

        for incomplete in [
            InterfaceSet::new(Interface::Accessible),
            InterfaceSet::new(Interface::Text),
        ] {
            assert!(!live_target_metadata_eligible(states, incomplete));
        }
    }

    #[test]
    fn secure_role_transition_fails_closed() {
        let attributes = HashMap::new();
        assert!(!secure_metadata(Role::Text, &attributes));
        assert!(secure_metadata(Role::PasswordText, &attributes));
        assert!(secure_metadata(
            Role::Text,
            &HashMap::from([("protected".to_owned(), "true".to_owned())])
        ));
    }

    #[test]
    fn device_listener_requires_exact_controller_sender() {
        let controller = ControllerIdentity {
            sender: ":1.42".to_owned(),
            pid: 123,
            uid: 456,
        };
        assert!(sender_is_controller(&controller, Some(":1.42")));
        assert!(!sender_is_controller(&controller, None));
        assert!(!sender_is_controller(&controller, Some(":1.43")));
        assert!(!sender_is_controller(
            &controller,
            Some("org.a11y.atspi.Registry")
        ));
    }
    #[test]
    fn focused_event_stream_excludes_control_and_unregistered_signals() {
        assert!(is_focused_event_header(
            ObjectEvents::DBUS_INTERFACE,
            TextChangedEvent::DBUS_MEMBER
        ));
        assert!(is_focused_event_header(
            FocusEvents::DBUS_INTERFACE,
            FocusEvent::DBUS_MEMBER
        ));
        assert!(is_focused_event_header(
            MouseEvents::DBUS_INTERFACE,
            "Button"
        ));
        assert!(!is_focused_event_header(
            DEVICE_EVENT_LISTENER_INTERFACE,
            "KeystrokeListenerRegistered"
        ));
        assert!(!is_focused_event_header(
            ObjectEvents::DBUS_INTERFACE,
            "PropertyChange"
        ));
    }

    #[test]
    fn keystroke_listener_uses_current_at_spi_bitmask_signature() {
        use zbus::zvariant::DynamicType;

        let path = zbus::zvariant::ObjectPath::try_from("/com/pais/handy/test").unwrap();
        let keys: [KeyDefinition<'_>; 0] = [];
        let mode = EventListenerMode {
            synchronous: false,
            preemptive: false,
            global: true,
        };
        let register = (&path, keys.as_slice(), 0u32, KEY_EVENT_TYPES, &mode);
        let deregister = (&path, keys.as_slice(), 0u32, KEY_EVENT_TYPES);

        assert_eq!(register.signature().to_string(), "(oa(iisi)uu(bbb))");
        assert_eq!(deregister.signature().to_string(), "(oa(iisi)uu)");
        let registration = (
            ":1.42".to_owned(),
            zbus::zvariant::OwnedObjectPath::try_from("/com/pais/handy/test").unwrap(),
            0,
            KEY_EVENT_TYPES,
            Vec::new(),
            0,
            (false, false, true),
        );
        assert_eq!(registration.signature().to_string(), "(souua(iisi)u(bbb))");
        assert!(registered_keystroke_listener_matches(
            &registration,
            ":1.42",
            "/com/pais/handy/test"
        ));
        assert!(!registered_keystroke_listener_matches(
            &registration,
            ":1.43",
            "/com/pais/handy/test"
        ));
        assert!(!listener_registration_absent(
            std::slice::from_ref(&registration),
            ":1.42",
            "/com/pais/handy/test"
        ));
        assert!(listener_registration_absent(
            std::slice::from_ref(&registration),
            ":1.43",
            "/com/pais/handy/test"
        ));
        assert!(listener_registration_absent(
            &[],
            ":1.42",
            "/com/pais/handy/test"
        ));
        let mut non_global = registration;
        non_global.6 = (false, false, false);
        assert!(!registered_keystroke_listener_matches(
            &non_global,
            ":1.42",
            "/com/pais/handy/test"
        ));
        assert!(!listener_registration_absent(
            std::slice::from_ref(&non_global),
            ":1.42",
            "/com/pais/handy/test"
        ));
    }

    #[test]
    fn event_correlation_is_generation_shape_and_content_exact() {
        let expected = ExpectedEffect {
            start: 7,
            chars: 3,
            marker: 9,
            hash: text_hash(4 ^ 9, "ab🦀"),
            caret_after: 10,
            tool_key_presses: 3,
        };
        assert_eq!(expected.start, 7);
        assert_eq!(expected.chars, 3);
        assert_eq!(expected.caret_after, 10);
        assert_eq!(expected.hash, text_hash(4 ^ 9, "ab🦀"));
        assert_ne!(expected.hash, text_hash(4 ^ 9, "abx"));
        assert_ne!(expected.hash, text_hash(5 ^ 9, "ab🦀"));
        assert_ne!(expected.hash, text_hash(4 ^ 8, "ab🦀"));
    }

    fn key_event(event_string: &str, is_text: bool) -> DeviceEvent<'_> {
        DeviceEvent {
            event_type: EventType::KeyPressed,
            id: 0,
            hw_code: 0,
            modifiers: 0,
            timestamp: 0,
            event_string,
            is_text,
        }
    }

    #[test]
    fn guarded_dispatch_allows_modifiers_but_cancels_unknown_and_excess_keys() {
        let (tx, _rx) = bounded(4);
        let shared = MonitorShared {
            terminal: AtomicU8::new(T_NONE),
            published: AtomicBool::new(false),
            dispatch: AtomicBool::new(true),
            dispatch_direct: AtomicBool::new(false),
            dispatch_text: AtomicBool::new(true),
            intent_epoch: AtomicU64::new(0),
            physical_callbacks: AtomicU64::new(0),
            tool_key_presses: AtomicU64::new(0),
            expected_tool_key_presses: AtomicU64::new(1),
            tx,
            stop_chord: None,
            cancellation: SessionCancellation::default(),
        };

        assert!(device_signal(&shared, &key_event("Shift_L", false)).is_none());
        assert!(matches!(
            device_signal(&shared, &key_event("BackSpace", false)),
            Some(MonitorSignal::Command)
        ));
        assert!(matches!(
            device_signal(&shared, &key_event("a", true)),
            Some(MonitorSignal::ToolKey)
        ));
        shared.observe_tool_key();
        assert_eq!(shared.terminal.load(Ordering::Acquire), T_NONE);
        shared.observe_tool_key();
        assert_eq!(shared.terminal.load(Ordering::Acquire), T_EDIT);
        assert!(shared.cancellation.is_cancelled());
    }

    #[test]
    fn intent_publication_racing_dispatch_cancels_before_injection() {
        let (tx, _rx) = bounded(2);
        let shared = MonitorShared {
            terminal: AtomicU8::new(T_NONE),
            published: AtomicBool::new(false),
            dispatch: AtomicBool::new(false),
            dispatch_direct: AtomicBool::new(false),
            dispatch_text: AtomicBool::new(false),
            intent_epoch: AtomicU64::new(0),
            physical_callbacks: AtomicU64::new(0),
            tool_key_presses: AtomicU64::new(0),
            expected_tool_key_presses: AtomicU64::new(0),
            tx,
            stop_chord: None,
            cancellation: SessionCancellation::default(),
        };

        let signal = device_signal(&shared, &key_event("a", true)).unwrap();
        assert!(matches!(signal, MonitorSignal::SafeIntent));
        assert_eq!(shared.intent_epoch.load(Ordering::Acquire), 1);
        shared.dispatch.store(true, Ordering::Release);
        shared.publish_signal(signal);
        assert_eq!(shared.terminal.load(Ordering::Acquire), T_EDIT);
        assert!(shared.cancellation.is_cancelled());
    }

    #[test]
    fn stop_chord_is_neutral_only_on_exact_match() {
        let chord = StopChord::parse(Some("Ctrl+Shift+Space")).unwrap();
        assert!(chord.matches((1 << 2) | 1, "space"));
        assert!(!chord.matches(1 << 2, "space"));
        assert!(!chord.matches((1 << 2) | 1, "Return"));

        let (tx, _rx) = bounded(2);
        let shared = MonitorShared {
            terminal: AtomicU8::new(T_NONE),
            published: AtomicBool::new(false),
            dispatch: AtomicBool::new(false),
            dispatch_direct: AtomicBool::new(false),
            dispatch_text: AtomicBool::new(false),
            intent_epoch: AtomicU64::new(0),
            physical_callbacks: AtomicU64::new(0),
            tool_key_presses: AtomicU64::new(0),
            expected_tool_key_presses: AtomicU64::new(0),
            tx,
            stop_chord: Some(chord),
            cancellation: SessionCancellation::default(),
        };
        let mut modifier = key_event("Control_L", false);
        modifier.modifiers = 1 << 2;
        assert!(device_signal(&shared, &modifier).is_none());
        assert_eq!(shared.terminal.load(Ordering::Acquire), T_NONE);

        let mut stop_key = key_event("space", false);
        stop_key.modifiers = (1 << 2) | 1;
        assert!(device_signal(&shared, &stop_key).is_none());

        let mut other_command = key_event("x", true);
        other_command.modifiers = 1 << 2;
        assert!(matches!(
            device_signal(&shared, &other_command),
            Some(MonitorSignal::Command)
        ));
    }

    #[test]
    fn transient_focus_loss_expires_only_after_grace() {
        assert!(!focus_loss_expired(None));
        assert!(!focus_loss_expired(Some(Instant::now())));
        assert!(focus_loss_expired(Some(Instant::now() - FOCUS_LOSS_GRACE)));
    }

    #[test]
    fn callback_overflow_self_disarms_and_first_terminal_wins() {
        let (tx, _rx) = bounded(1);
        let shared = MonitorShared {
            terminal: AtomicU8::new(T_NONE),
            published: AtomicBool::new(false),
            dispatch: AtomicBool::new(false),
            dispatch_direct: AtomicBool::new(false),
            dispatch_text: AtomicBool::new(false),
            physical_callbacks: AtomicU64::new(0),
            intent_epoch: AtomicU64::new(0),
            tool_key_presses: AtomicU64::new(0),
            expected_tool_key_presses: AtomicU64::new(0),
            tx,
            stop_chord: None,
            cancellation: SessionCancellation::default(),
        };
        shared.callback(MonitorSignal::SafeIntent);
        shared.callback(MonitorSignal::SafeIntent);
        assert_eq!(shared.terminal.load(Ordering::Acquire), T_MONITOR);
        assert!(shared.cancellation.is_cancelled());
        shared.terminal(T_POINTER);
        assert_eq!(shared.terminal.load(Ordering::Acquire), T_MONITOR);
    }

    #[test]
    fn registry_owner_loss_cancels_an_in_flight_session() {
        let cancellation = SessionCancellation::default();
        let (tx, _rx) = bounded(1);
        let shared = Arc::new(MonitorShared {
            terminal: AtomicU8::new(T_NONE),
            published: AtomicBool::new(false),
            dispatch: AtomicBool::new(true),
            dispatch_direct: AtomicBool::new(true),
            dispatch_text: AtomicBool::new(false),
            physical_callbacks: AtomicU64::new(0),
            intent_epoch: AtomicU64::new(0),
            tool_key_presses: AtomicU64::new(0),
            expected_tool_key_presses: AtomicU64::new(0),
            tx,
            stop_chord: None,
            cancellation: cancellation.clone(),
        });
        let owner = RegistryOwnerMonitor::new();
        owner.arm(&shared);

        owner.lose();

        assert!(owner.is_lost());
        assert_eq!(shared.terminal.load(Ordering::Acquire), T_MONITOR);
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn cancellation_and_absent_submit_capability_are_explicit() {
        let cancellation = SessionCancellation::default();
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        let direct = FocusedOutputCapability::verified_control(
            FocusedOutputBackend::LinuxAtSpi,
            ResolvedInsertionCapability {
                insertion_transport: InsertionTransport::AtSpiEditableText,
                receipt_confidence: ReceiptConfidence::Verified,
            },
            MixedInputSupport::ObservedInsertionsOnly,
            false,
        );
        let guarded = FocusedOutputCapability::guarded_focused_control(
            FocusedOutputBackend::LinuxAtSpi,
            ResolvedInsertionCapability {
                insertion_transport: InsertionTransport::LinuxFocusedKeyboard,
                receipt_confidence: ReceiptConfidence::Posted,
            },
            MixedInputSupport::ObservedInsertionsOnly,
            false,
        );
        assert!(!direct.supports_auto_submit());
        assert!(!guarded.supports_auto_submit());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn child_timeout_kills_and_reaps_without_transcript_channels() {
        let cancellation = SessionCancellation::default();
        let shell = TrustedExecutable::open(Path::new("/usr/bin/bash")).unwrap();
        let guard = ChildGuard::spawn_with_limits(
            &shell,
            &["-c", "trap '' TERM; sleep 30"],
            ChildLimits {
                ipc: Duration::from_millis(50),
                process: Duration::from_millis(100),
            },
        )
        .unwrap();
        let pid = guard.child.as_ref().unwrap().id();
        assert_eq!(
            guard.run(b"private", &cancellation).await,
            ChildResult::PossiblyPosted
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        while Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_before_write_is_not_posted() {
        let cancellation = SessionCancellation::default();
        cancellation.cancel();
        let shell = TrustedExecutable::open(Path::new("/usr/bin/bash")).unwrap();
        let guard = ChildGuard::spawn_with_limits(
            &shell,
            &["-c", "sleep 30"],
            ChildLimits {
                ipc: Duration::from_millis(50),
                process: Duration::from_millis(100),
            },
        )
        .unwrap();
        assert_eq!(
            guard.run(b"private", &cancellation).await,
            ChildResult::NotStarted
        );
    }
}
