use super::{BeginSession, FocusedFieldBackend, FocusedTargetSession, SessionEventSink};
use crate::{
    focused_output::types::{
        BeginContext, BeginReceipt, DictationSessionId, FocusedOutputBackend,
        FocusedOutputCapability, FocusedOutputPermission, FocusedOutputReasonCode, InjectionId,
        InsertOutcome, InsertionRequest, InsertionTransport, MixedInputSupport, ObservationId,
        PlatformDeadlines, ReceiptConfidence, ResolvedInsertionCapability, SessionCancellation,
        SubmitOutcome, TargetInteractionEvent, UnsafeEditKind,
    },
    settings::AutoSubmitKey,
};
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows::{
    core::{implement, Interface, Ref, Result as WindowsResult},
    Win32::{
        Foundation::{CloseHandle, HANDLE, HWND, LPARAM, LRESULT, WPARAM},
        System::{
            Com::{
                CoCancelCall, CoCreateInstance, CoDisableCallCancellation,
                CoEnableCallCancellation, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
                COINIT_MULTITHREADED, SAFEARRAY,
            },
            Ole::SafeArrayDestroy,
            Threading::{GetCurrentProcessId, GetCurrentThreadId},
            Variant::VARIANT,
        },
        UI::{
            Accessibility::{
                CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationEventHandler,
                IUIAutomationEventHandler_Impl, IUIAutomationFocusChangedEventHandler,
                IUIAutomationFocusChangedEventHandler_Impl,
                IUIAutomationPropertyChangedEventHandler,
                IUIAutomationPropertyChangedEventHandler_Impl, IUIAutomationTextPattern,
                IUIAutomationTextRange, IUIAutomationValuePattern, TextPatternRangeEndpoint_End,
                TextPatternRangeEndpoint_Start, TreeScope_Element, UIA_IsReadOnlyAttributeId,
                UIA_TextPatternId, UIA_Text_TextChangedEventId,
                UIA_Text_TextSelectionChangedEventId, UIA_ValuePatternId, UIA_ValueValuePropertyId,
                UIA_CONTROLTYPE_ID, UIA_EVENT_ID, UIA_PROPERTY_ID,
            },
            Input::KeyboardAndMouse::{
                SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KBDLLHOOKSTRUCT, KEYBDINPUT,
                KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, LLKHF_INJECTED, LLMHF_INJECTED, MSLLHOOKSTRUCT,
                VIRTUAL_KEY, VK_CONTROL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_INSERT,
                VK_LCONTROL, VK_LEFT, VK_LMENU, VK_LSHIFT, VK_LWIN, VK_MENU, VK_NEXT, VK_PRIOR,
                VK_RCONTROL, VK_RETURN, VK_RIGHT, VK_RMENU, VK_RSHIFT, VK_RWIN, VK_SHIFT, VK_SPACE,
                VK_TAB, VK_UP,
            },
            WindowsAndMessaging::{
                CallNextHookEx, GetAncestor, GetForegroundWindow, GetMessageW,
                GetWindowThreadProcessId, PeekMessageW, PostThreadMessageW, SetWindowsHookExW,
                UnhookWindowsHookEx, GA_ROOT, HC_ACTION, MSG, PM_NOREMOVE, WH_KEYBOARD_LL,
                WH_MOUSE_LL, WM_KEYDOWN, WM_KEYUP, WM_QUIT, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_USER,
            },
        },
    },
};

const CALLBACK_QUEUE_CAPACITY: usize = 256;
const COMMAND_QUEUE_CAPACITY: usize = 8;
const TERMINAL_NONE: u8 = 0;
const TERMINAL_TARGET_CHANGED: u8 = 1;
const TERMINAL_POINTER: u8 = 2;
const TERMINAL_UNSAFE_KEY: u8 = 3;
const TERMINAL_MONITOR_LOST: u8 = 4;
const TERMINAL_CANCELLED: u8 = 5;
const TERMINAL_RECEIPT_TIMEOUT: u8 = 6;
const MOD_CTRL: u8 = 1;
const MOD_SHIFT: u8 = 2;
const MOD_ALT: u8 = 4;
const MOD_WIN: u8 = 8;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
const TH32CS_SNAPPROCESS: u32 = 2;

static HOOK_CONTEXT: AtomicPtr<HookContext> = AtomicPtr::new(ptr::null_mut());
static NEXT_HOOK_GENERATION: AtomicU64 = AtomicU64::new(1);
static ACTIVE_HOOK_GENERATION: AtomicU64 = AtomicU64::new(0);
static MARKER_FALLBACK: AtomicUsize = AtomicUsize::new(0x4841_4e45usize);

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, buffer_len: u32, flags: u32)
        -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> HANDLE;
    fn Process32FirstW(snapshot: HANDLE, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: HANDLE, entry: *mut ProcessEntry32W) -> i32;
}

#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    priority_base: i32,
    flags: u32,
    executable_file: [u16; 260],
}

impl Default for ProcessEntry32W {
    fn default() -> Self {
        // This is the ABI-prescribed initialization for PROCESSENTRY32W.
        let mut entry: Self = unsafe { zeroed() };
        entry.size = size_of::<Self>() as u32;
        entry
    }
}

/// Strict Windows focused-field output. A successful session is always pinned
/// to one UI Automation element and the Unicode SendInput route.
pub struct WindowsFocusedFieldBackend {
    state: Arc<BackendState>,
}

struct BackendState {
    shutdown: AtomicBool,
    sessions: Mutex<Vec<Weak<SessionSignal>>>,
    deadlines: PlatformDeadlines,
}

impl WindowsFocusedFieldBackend {
    pub fn new() -> Self {
        Self {
            state: Arc::new(BackendState {
                shutdown: AtomicBool::new(false),
                sessions: Mutex::new(Vec::new()),
                deadlines: PlatformDeadlines::default(),
            }),
        }
    }
}

impl Default for WindowsFocusedFieldBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FocusedFieldBackend for WindowsFocusedFieldBackend {
    fn global_capability(&self) -> FocusedOutputCapability {
        if self.state.shutdown.load(Ordering::Acquire) {
            FocusedOutputCapability::unavailable(
                FocusedOutputBackend::Windows,
                FocusedOutputReasonCode::BackendDisconnected,
            )
        } else {
            FocusedOutputCapability::global_ready(FocusedOutputBackend::Windows)
        }
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
        event_sink: Arc<dyn SessionEventSink>,
        cancellation: SessionCancellation,
    ) -> Result<BeginSession, FocusedOutputReasonCode> {
        if self.state.shutdown.load(Ordering::Acquire) {
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }

        let stop_chord = StopChord::parse(context.control_shortcut.as_deref())?;
        let marker = random_marker();
        let (native_tx, native_rx) = bounded(CALLBACK_QUEUE_CAPACITY);
        let signal = Arc::new(SessionSignal::new());
        let callback_state = Arc::new(CallbackState {
            terminal: AtomicU8::new(TERMINAL_NONE),
            active_marker: AtomicUsize::new(0),
            modifiers: AtomicU8::new(0),
            hook_thread_id: AtomicU32::new(0),
            stop_chord,
            events: native_tx,
        });

        let (hook_ready_tx, hook_ready_rx) = bounded(1);
        let hook_state = Arc::clone(&callback_state);
        let hook_signal = Arc::clone(&signal);
        let hook_handle = thread::Builder::new()
            .name("focused-output-win-hooks".into())
            .spawn(move || hook_thread(hook_state, hook_signal, hook_ready_tx))
            .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;

        match hook_ready_rx.recv_timeout(self.state.deadlines.thread_ready) {
            Ok(Ok(thread_id)) => {
                signal.hook_thread_id.store(thread_id, Ordering::Release);
                callback_state
                    .hook_thread_id
                    .store(thread_id, Ordering::Release);
            }
            Ok(Err(reason)) => {
                let _ = hook_handle.join();
                return Err(reason);
            }
            Err(_) => {
                signal.request_close();
                drop(hook_handle);
                return Err(FocusedOutputReasonCode::MonitorUnavailable);
            }
        }

        let (command_tx, command_rx) = bounded(COMMAND_QUEUE_CAPACITY);
        signal.set_command_sender(command_tx.clone());
        let (thread_started_tx, thread_started_rx) = bounded(1);
        let (begin_tx, begin_rx) = bounded(1);
        let worker_signal = Arc::clone(&signal);
        let worker_callback = Arc::clone(&callback_state);
        let worker_cancellation = cancellation.clone();
        let session_id = context.session_id;
        let worker_handle = thread::Builder::new()
            .name("focused-output-win-uia".into())
            .spawn(move || {
                uia_thread(
                    session_id,
                    event_sink,
                    worker_cancellation,
                    marker,
                    worker_callback,
                    native_rx,
                    command_rx,
                    worker_signal,
                    thread_started_tx,
                    begin_tx,
                )
            })
            .map_err(|_| {
                signal.request_close();
                FocusedOutputReasonCode::BackendDisconnected
            })?;

        let uia_thread_id = match thread_started_rx.recv_timeout(self.state.deadlines.thread_ready)
        {
            Ok(id) => {
                signal.uia_thread_id.store(id, Ordering::Release);
                id
            }
            Err(_) => {
                signal.request_close();
                drop(worker_handle);
                drop(hook_handle);
                return Err(FocusedOutputReasonCode::BackendDisconnected);
            }
        };

        let begin_info = match begin_rx.recv_timeout(self.state.deadlines.target_call) {
            Ok(Ok(info)) => info,
            Ok(Err(reason)) => {
                signal.request_close();
                wait_and_join_failed(
                    &signal,
                    worker_handle,
                    hook_handle,
                    self.state.deadlines.thread_close,
                );
                return Err(reason);
            }
            Err(_) => {
                // The provider call may still be in flight. Cancellation is issued
                // from a different thread as required by COM call cancellation.
                let _ = unsafe { CoCancelCall(uia_thread_id, 0) };
                signal.request_close();
                drop(worker_handle);
                drop(hook_handle);
                return Err(FocusedOutputReasonCode::TargetUnsupported);
            }
        };

        if cancellation.is_cancelled() {
            signal.request_close();
            wait_and_join_failed(
                &signal,
                worker_handle,
                hook_handle,
                self.state.deadlines.thread_close,
            );
            return Err(FocusedOutputReasonCode::Cancelled);
        }

        let receipt = BeginReceipt::new(session_id, begin_info.capability.clone(), None)
            .ok_or(FocusedOutputReasonCode::TargetUnsupported)?;
        self.state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(&signal));

        Ok(BeginSession {
            receipt,
            session: Box::new(WindowsTargetSession {
                session_id,
                capability: begin_info.capability,
                command_tx,
                cancellation,
                callback_state,
                signal,
                worker_handle: Some(worker_handle),
                hook_handle: Some(hook_handle),
                deadlines: self.state.deadlines,
                closed: false,
            }),
        })
    }

    fn shutdown(&self) {
        if self.state.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }

        let sessions: Vec<_> = self
            .state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for session in &sessions {
            session.request_close();
        }
        let deadline = Instant::now() + self.state.deadlines.backend_shutdown;
        while Instant::now() < deadline
            && sessions
                .iter()
                .any(|session| !session.both_threads_stopped())
        {
            thread::sleep(Duration::from_millis(2));
        }
        for session in &sessions {
            if !session.worker_stopped.load(Ordering::Acquire) {
                let thread_id = session.uia_thread_id.load(Ordering::Acquire);
                if thread_id != 0 {
                    let _ = unsafe { CoCancelCall(thread_id, 0) };
                }
            }
        }
    }
}

struct BeginInfo {
    capability: FocusedOutputCapability,
}

struct WindowsTargetSession {
    session_id: DictationSessionId,
    capability: FocusedOutputCapability,
    command_tx: Sender<Command>,
    cancellation: SessionCancellation,
    callback_state: Arc<CallbackState>,
    signal: Arc<SessionSignal>,
    worker_handle: Option<JoinHandle<()>>,
    hook_handle: Option<JoinHandle<()>>,
    deadlines: PlatformDeadlines,
    closed: bool,
}

impl WindowsTargetSession {
    fn call_insert(&self, request: InsertionRequest) -> InsertOutcome {
        let (reply_tx, reply_rx) = bounded(1);
        if self
            .command_tx
            .send_timeout(
                Command::Insert(request, reply_tx),
                self.deadlines.target_call,
            )
            .is_err()
        {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::BackendDisconnected,
            };
        }
        match reply_rx.recv_timeout(self.deadlines.target_call) {
            Ok(outcome) => outcome,
            Err(_) => {
                let thread_id = self.signal.uia_thread_id.load(Ordering::Acquire);
                if thread_id != 0 {
                    let _ = unsafe { CoCancelCall(thread_id, 0) };
                }
                InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                }
            }
        }
    }

    fn call_submit(&self, key: AutoSubmitKey) -> SubmitOutcome {
        let (reply_tx, reply_rx) = bounded(1);
        if self
            .command_tx
            .send_timeout(Command::Submit(key, reply_tx), self.deadlines.target_call)
            .is_err()
        {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::BackendDisconnected,
            };
        }
        match reply_rx.recv_timeout(self.deadlines.target_call) {
            Ok(outcome) => outcome,
            Err(_) => {
                let thread_id = self.signal.uia_thread_id.load(Ordering::Acquire);
                if thread_id != 0 {
                    let _ = unsafe { CoCancelCall(thread_id, 0) };
                }
                SubmitOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                }
            }
        }
    }
}

impl FocusedTargetSession for WindowsTargetSession {
    fn capability(&self) -> &FocusedOutputCapability {
        &self.capability
    }

    fn insert_if_valid(&mut self, request: InsertionRequest) -> InsertOutcome {
        if self.closed || request.session_id != self.session_id {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetChanged,
            };
        }
        if self.cancellation.is_cancelled() {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        self.call_insert(request)
    }

    fn submit_if_valid(&mut self, key: AutoSubmitKey) -> SubmitOutcome {
        if self.closed {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetClosed,
            };
        }
        if self.cancellation.is_cancelled() {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        self.call_submit(key)
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.callback_state
            .active_marker
            .store(0, Ordering::Release);
        self.signal.request_close();

        let deadline = Instant::now() + self.deadlines.thread_close;
        while Instant::now() < deadline && !self.signal.both_threads_stopped() {
            thread::sleep(Duration::from_millis(2));
        }
        if self.signal.worker_stopped.load(Ordering::Acquire) {
            if let Some(handle) = self.worker_handle.take() {
                let _ = handle.join();
            }
        } else {
            let thread_id = self.signal.uia_thread_id.load(Ordering::Acquire);
            if thread_id != 0 {
                let _ = unsafe { CoCancelCall(thread_id, 0) };
            }
            // The UIA handler owns its Arc until COM removal and callback
            // quiescence. Detaching here deliberately retains that context.
            drop(self.worker_handle.take());
        }
        if self.signal.hook_stopped.load(Ordering::Acquire) {
            if let Some(handle) = self.hook_handle.take() {
                let _ = handle.join();
            }
        } else {
            // Windows exposes no liveness query for silently removed low-level
            // hooks. The hook thread and raw Arc stay alive on timeout, avoiding
            // a callback UAF at the cost of a bounded residual process-lifetime
            // retention. This is the documented Guarded/Posted residual race.
            drop(self.hook_handle.take());
        }
    }
}

impl Drop for WindowsTargetSession {
    fn drop(&mut self) {
        self.close();
    }
}

struct SessionSignal {
    close_requested: AtomicBool,
    worker_stopped: AtomicBool,
    hook_stopped: AtomicBool,
    uia_thread_id: AtomicU32,
    hook_thread_id: AtomicU32,
    command_sender: Mutex<Option<Sender<Command>>>,
}

impl SessionSignal {
    fn new() -> Self {
        Self {
            close_requested: AtomicBool::new(false),
            worker_stopped: AtomicBool::new(false),
            hook_stopped: AtomicBool::new(false),
            uia_thread_id: AtomicU32::new(0),
            hook_thread_id: AtomicU32::new(0),
            command_sender: Mutex::new(None),
        }
    }

    fn set_command_sender(&self, sender: Sender<Command>) {
        *self
            .command_sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sender);
    }

    fn request_close(&self) {
        self.close_requested.store(true, Ordering::Release);
        let hook_thread = self.hook_thread_id.load(Ordering::Acquire);
        if hook_thread != 0 {
            let _ = unsafe { PostThreadMessageW(hook_thread, WM_QUIT, WPARAM(0), LPARAM(0)) };
        }
        // Wake a worker blocked on its bounded command receiver without ever
        // waiting for queue space.
        if let Some(sender) = self
            .command_sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            let _ = sender.try_send(Command::Wake);
        }
    }

    fn both_threads_stopped(&self) -> bool {
        self.worker_stopped.load(Ordering::Acquire) && self.hook_stopped.load(Ordering::Acquire)
    }
}

enum Command {
    Insert(InsertionRequest, Sender<InsertOutcome>),
    Submit(AutoSubmitKey, Sender<SubmitOutcome>),
    Wake,
}

#[derive(Clone, Copy)]
struct StopChord {
    modifiers: u8,
    virtual_key: u32,
    configured: bool,
}

impl StopChord {
    fn parse(value: Option<&str>) -> Result<Self, FocusedOutputReasonCode> {
        let Some(value) = value else {
            return Ok(Self {
                modifiers: 0,
                virtual_key: 0,
                configured: false,
            });
        };
        let mut modifiers = 0;
        let mut virtual_key = None;
        for component in value.split('+').map(str::trim) {
            if component.eq_ignore_ascii_case("ctrl")
                || component.eq_ignore_ascii_case("control")
                || component.eq_ignore_ascii_case("commandorcontrol")
                || component.eq_ignore_ascii_case("cmdorctrl")
            {
                modifiers |= MOD_CTRL;
            } else if component.eq_ignore_ascii_case("shift") {
                modifiers |= MOD_SHIFT;
            } else if component.eq_ignore_ascii_case("alt") {
                modifiers |= MOD_ALT;
            } else if component.eq_ignore_ascii_case("win")
                || component.eq_ignore_ascii_case("super")
                || component.eq_ignore_ascii_case("meta")
            {
                modifiers |= MOD_WIN;
            } else if component.eq_ignore_ascii_case("space") {
                virtual_key = Some(VK_SPACE.0 as u32);
            } else if component.eq_ignore_ascii_case("enter")
                || component.eq_ignore_ascii_case("return")
            {
                virtual_key = Some(VK_RETURN.0 as u32);
            } else if component.len() == 1 {
                let byte = component.as_bytes()[0];
                if byte.is_ascii_alphanumeric() {
                    virtual_key = Some(byte.to_ascii_uppercase() as u32);
                } else {
                    return Err(FocusedOutputReasonCode::ControlShortcutUnsupported);
                }
            } else {
                return Err(FocusedOutputReasonCode::ControlShortcutUnsupported);
            }
        }
        let virtual_key = virtual_key.ok_or(FocusedOutputReasonCode::ControlShortcutUnsupported)?;
        Ok(Self {
            modifiers,
            virtual_key,
            configured: true,
        })
    }

    fn matches(self, modifiers: u8, virtual_key: u32) -> bool {
        self.configured && self.modifiers == modifiers && self.virtual_key == virtual_key
    }
}

#[derive(Clone, Copy)]
enum NativeEvent {
    TextChanged,
    SelectionChanged,
    CompatibleKey { chars: usize },
    Terminal { code: u8 },
}

struct CallbackState {
    terminal: AtomicU8,
    active_marker: AtomicUsize,
    modifiers: AtomicU8,
    hook_thread_id: AtomicU32,
    stop_chord: StopChord,
    events: Sender<NativeEvent>,
}
struct HookContext {
    generation: u64,
    state: Weak<CallbackState>,
}

impl CallbackState {
    fn publish(&self, event: NativeEvent) {
        if let Err(error) = self.events.try_send(event) {
            if matches!(error, TrySendError::Full(_) | TrySendError::Disconnected(_)) {
                self.terminate(TERMINAL_MONITOR_LOST);
            }
        }
    }

    fn terminate(&self, code: u8) -> bool {
        if self
            .terminal
            .compare_exchange(TERMINAL_NONE, code, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.active_marker.store(0, Ordering::Release);
            let _ = self.events.try_send(NativeEvent::Terminal { code });
            let hook_thread = self.hook_thread_id.load(Ordering::Acquire);
            if hook_thread != 0 {
                let _ = unsafe { PostThreadMessageW(hook_thread, WM_QUIT, WPARAM(0), LPARAM(0)) };
            }
            true
        } else {
            false
        }
    }
}

#[implement(
    IUIAutomationEventHandler,
    IUIAutomationFocusChangedEventHandler,
    IUIAutomationPropertyChangedEventHandler
)]
struct UiaCallback {
    state: Arc<CallbackState>,
}

impl IUIAutomationEventHandler_Impl for UiaCallback {
    fn HandleAutomationEvent(
        &self,
        _sender: Ref<'_, IUIAutomationElement>,
        event_id: UIA_EVENT_ID,
    ) -> WindowsResult<()> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            if self.state.terminal.load(Ordering::Acquire) != TERMINAL_NONE {
                return;
            }
            if event_id == UIA_Text_TextChangedEventId {
                self.state.publish(NativeEvent::TextChanged);
            } else if event_id == UIA_Text_TextSelectionChangedEventId {
                self.state.publish(NativeEvent::SelectionChanged);
            }
        }));
        if result.is_err() {
            self.state.terminate(TERMINAL_MONITOR_LOST);
        }
        Ok(())
    }
}

impl IUIAutomationFocusChangedEventHandler_Impl for UiaCallback {
    fn HandleFocusChangedEvent(&self, _sender: Ref<'_, IUIAutomationElement>) -> WindowsResult<()> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.state.terminate(TERMINAL_TARGET_CHANGED);
        }));
        if result.is_err() {
            self.state.terminate(TERMINAL_MONITOR_LOST);
        }
        Ok(())
    }
}

impl IUIAutomationPropertyChangedEventHandler_Impl for UiaCallback {
    fn HandlePropertyChangedEvent(
        &self,
        _sender: Ref<'_, IUIAutomationElement>,
        property_id: UIA_PROPERTY_ID,
        _new_value: &[VARIANT],
    ) -> WindowsResult<()> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            if property_id == UIA_ValueValuePropertyId
                && self.state.terminal.load(Ordering::Acquire) == TERMINAL_NONE
            {
                self.state.publish(NativeEvent::TextChanged);
            }
        }));
        if result.is_err() {
            self.state.terminate(TERMINAL_MONITOR_LOST);
        }
        Ok(())
    }
}

unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if code != HC_ACTION as i32 {
            return;
        }
        let Some(state) = current_hook_state() else {
            return;
        };
        if state.terminal.load(Ordering::Acquire) != TERMINAL_NONE {
            return;
        }
        let input = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
        let is_down = wparam.0 as u32 == WM_KEYDOWN || wparam.0 as u32 == WM_SYSKEYDOWN;
        let is_up = wparam.0 as u32 == WM_KEYUP || wparam.0 as u32 == WM_SYSKEYUP;
        if !is_down && !is_up {
            return;
        }

        if input.flags.contains(LLKHF_INJECTED) {
            let active = state.active_marker.load(Ordering::Acquire);
            if active == 0 || input.dwExtraInfo != active {
                state.terminate(TERMINAL_UNSAFE_KEY);
            }
            return;
        }

        if let Some(bit) = modifier_bit(input.vkCode) {
            if is_down {
                state.modifiers.fetch_or(bit, Ordering::AcqRel);
            } else {
                state.modifiers.fetch_and(!bit, Ordering::AcqRel);
            }
            return;
        }
        if is_up {
            return;
        }

        let modifiers = state.modifiers.load(Ordering::Acquire);
        if state.stop_chord.matches(modifiers, input.vkCode) {
            return;
        }
        if is_compatible_printable(input.vkCode, modifiers) {
            state.publish(NativeEvent::CompatibleKey { chars: 1 });
        } else {
            state.terminate(TERMINAL_UNSAFE_KEY);
        }
    }));

    if result.is_err() {
        if let Some(state) = current_hook_state() {
            state.terminate(TERMINAL_MONITOR_LOST);
        }
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

unsafe extern "system" fn mouse_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if code != HC_ACTION as i32 {
            return;
        }
        let Some(state) = current_hook_state() else {
            return;
        };
        let input = unsafe { &*(lparam.0 as *const MSLLHOOKSTRUCT) };
        let _injected = input.flags & LLMHF_INJECTED != 0;
        // This backend never injects pointer input, so both physical and
        // foreign-injected pointer activity invalidate the guarded route.
        state.terminate(TERMINAL_POINTER);
    }));
    if result.is_err() {
        if let Some(state) = current_hook_state() {
            state.terminate(TERMINAL_MONITOR_LOST);
        }
    }
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

fn hook_thread(
    state: Arc<CallbackState>,
    signal: Arc<SessionSignal>,
    ready: Sender<Result<u32, FocusedOutputReasonCode>>,
) {
    struct StopGuard(Arc<SessionSignal>);
    impl Drop for StopGuard {
        fn drop(&mut self) {
            self.0.hook_stopped.store(true, Ordering::Release);
        }
    }
    let _guard = StopGuard(Arc::clone(&signal));
    let thread_id = unsafe { GetCurrentThreadId() };
    signal.hook_thread_id.store(thread_id, Ordering::Release);
    state.hook_thread_id.store(thread_id, Ordering::Release);

    let mut message = MSG::default();
    unsafe {
        PeekMessageW(&mut message, None, WM_USER, WM_USER, PM_NOREMOVE);
    }

    let generation = NEXT_HOOK_GENERATION.fetch_add(1, Ordering::Relaxed);
    let raw = Box::into_raw(Box::new(HookContext {
        generation,
        state: Arc::downgrade(&state),
    }));
    if HOOK_CONTEXT
        .compare_exchange(ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        unsafe { drop(Box::from_raw(raw)) };
        let _ = ready.send(Err(FocusedOutputReasonCode::AlreadyActive));
        return;
    }
    ACTIVE_HOOK_GENERATION.store(generation, Ordering::Release);

    let keyboard = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), None, 0) };
    let keyboard = match keyboard {
        Ok(hook) => hook,
        Err(_) => {
            clear_hook_context(raw);
            let _ = ready.send(Err(FocusedOutputReasonCode::MonitorUnavailable));
            return;
        }
    };
    let mouse = unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), None, 0) };
    let mouse = match mouse {
        Ok(hook) => hook,
        Err(_) => {
            let _ = unsafe { UnhookWindowsHookEx(keyboard) };
            clear_hook_context(raw);
            let _ = ready.send(Err(FocusedOutputReasonCode::MonitorUnavailable));
            return;
        }
    };

    if ready.send(Ok(thread_id)).is_err() {
        let _ = unsafe { UnhookWindowsHookEx(mouse) };
        let _ = unsafe { UnhookWindowsHookEx(keyboard) };
        clear_hook_context(raw);
        return;
    }

    loop {
        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if result.0 <= 0 || signal.close_requested.load(Ordering::Acquire) {
            break;
        }
    }
    let _ = unsafe { UnhookWindowsHookEx(mouse) };
    let _ = unsafe { UnhookWindowsHookEx(keyboard) };
    clear_hook_context(raw);
}

fn current_hook_state() -> Option<Arc<CallbackState>> {
    let raw = HOOK_CONTEXT.load(Ordering::Acquire);
    if raw.is_null() {
        return None;
    }
    let context = unsafe { &*raw };
    if context.generation != ACTIVE_HOOK_GENERATION.load(Ordering::Acquire) {
        return None;
    }
    context.state.upgrade()
}

fn clear_hook_context(raw: *mut HookContext) {
    ACTIVE_HOOK_GENERATION.store(0, Ordering::Release);
    if HOOK_CONTEXT
        .compare_exchange(raw, ptr::null_mut(), Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        unsafe { drop(Box::from_raw(raw)) };
    }
}

fn modifier_bit(virtual_key: u32) -> Option<u8> {
    match VIRTUAL_KEY(virtual_key as u16) {
        VK_CONTROL | VK_LCONTROL | VK_RCONTROL => Some(MOD_CTRL),
        VK_SHIFT | VK_LSHIFT | VK_RSHIFT => Some(MOD_SHIFT),
        VK_MENU | VK_LMENU | VK_RMENU => Some(MOD_ALT),
        VK_LWIN | VK_RWIN => Some(MOD_WIN),
        _ => None,
    }
}

fn is_compatible_printable(virtual_key: u32, modifiers: u8) -> bool {
    if modifiers & (MOD_CTRL | MOD_ALT | MOD_WIN) != 0 {
        return false;
    }
    virtual_key == VK_SPACE.0 as u32
        || (b'A' as u32..=b'Z' as u32).contains(&virtual_key)
        || (b'0' as u32..=b'9' as u32).contains(&virtual_key)
}

fn uia_thread(
    session_id: DictationSessionId,
    event_sink: Arc<dyn SessionEventSink>,
    cancellation: SessionCancellation,
    marker: usize,
    callback_state: Arc<CallbackState>,
    native_events: Receiver<NativeEvent>,
    commands: Receiver<Command>,
    signal: Arc<SessionSignal>,
    thread_started: Sender<u32>,
    begin_result: Sender<Result<BeginInfo, FocusedOutputReasonCode>>,
) {
    struct WorkerGuard(Arc<SessionSignal>);
    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            self.0.worker_stopped.store(true, Ordering::Release);
        }
    }
    let _guard = WorkerGuard(Arc::clone(&signal));
    let thread_id = unsafe { GetCurrentThreadId() };
    signal.uia_thread_id.store(thread_id, Ordering::Release);
    if thread_started.send(thread_id).is_err() {
        return;
    }

    if unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_err() {
        let _ = begin_result.send(Err(FocusedOutputReasonCode::BackendDisconnected));
        return;
    }
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            let _ = unsafe { CoDisableCallCancellation(None) };
            unsafe { CoUninitialize() };
        }
    }
    let _com_guard = ComGuard;
    if unsafe { CoEnableCallCancellation(None) }.is_err() {
        let _ = begin_result.send(Err(FocusedOutputReasonCode::BackendDisconnected));
        return;
    }

    let automation: IUIAutomation =
        match unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) } {
            Ok(value) => value,
            Err(_) => {
                let _ = begin_result.send(Err(FocusedOutputReasonCode::BackendDisconnected));
                return;
            }
        };
    let target = match UiaTarget::capture(&automation) {
        Ok(target) => target,
        Err(reason) => {
            let _ = begin_result.send(Err(reason));
            return;
        }
    };
    let mut subscriptions = match UiaSubscriptions::install(
        &automation,
        &target.element,
        Arc::clone(&callback_state),
    ) {
        Ok(value) => value,
        Err(reason) => {
            let _ = begin_result.send(Err(reason));
            return;
        }
    };
    if let Err(reason) = target.revalidate(&automation) {
        subscriptions.remove(&automation, &target.element);
        let _ = begin_result.send(Err(reason));
        return;
    }
    if callback_state.terminal.load(Ordering::Acquire) != TERMINAL_NONE {
        subscriptions.remove(&automation, &target.element);
        let _ = begin_result.send(Err(FocusedOutputReasonCode::MonitorUnavailable));
        return;
    }

    let capability = windows_route_capability(true);
    if begin_result
        .send(Ok(BeginInfo {
            capability: capability.clone(),
        }))
        .is_err()
    {
        subscriptions.remove(&automation, &target.element);
        return;
    }

    let initial_selection = match target.current_selection(&automation) {
        Ok(range) => range,
        Err(_) => {
            callback_state.terminate(TERMINAL_MONITOR_LOST);
            subscriptions.remove(&automation, &target.element);
            return;
        }
    };
    let mut worker = UiaWorker {
        session_id,
        event_sink,
        cancellation,
        marker,
        callback_state,
        automation,
        target,
        last_selection: initial_selection,
        pending: None,
        next_observation: 1,
        submitted: false,
        published_terminal: TERMINAL_NONE,
        duplicate_effect_deadline: None,
    };

    while !signal.close_requested.load(Ordering::Acquire) {
        crossbeam_channel::select! {
            recv(native_events) -> event => {
                match event {
                    Ok(event) => worker.handle_native_event(event),
                    Err(_) => {
                        worker.invalidate(TERMINAL_MONITOR_LOST);
                        break;
                    }
                }
            }
            recv(commands) -> command => {
                match command {
                    Ok(Command::Insert(request, reply)) => {
                        let outcome = worker.insert(request, &native_events);
                        let _ = reply.send(outcome);
                    }
                    Ok(Command::Submit(key, reply)) => {
                        let outcome = worker.submit(key, &native_events);
                        let _ = reply.send(outcome);
                    }
                    Ok(Command::Wake) => {}
                    Err(_) => break,
                }
            }
            default(Duration::from_millis(10)) => {
                worker.expire_pending();
            }
        }
        worker.observe_terminal();
        if worker.callback_state.terminal.load(Ordering::Acquire) != TERMINAL_NONE {
            subscriptions.remove(&worker.automation, &worker.target.element);
        }
    }
    subscriptions.remove(&worker.automation, &worker.target.element);
    worker
        .callback_state
        .active_marker
        .store(0, Ordering::Release);
}

struct RuntimeId(*mut SAFEARRAY);

impl Drop for RuntimeId {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { SafeArrayDestroy(self.0) };
        }
    }
}

struct UiaTarget {
    element: IUIAutomationElement,
    runtime_id: RuntimeId,
    process_id: u32,
    foreground: HWND,
    native_window: Option<HWND>,
    control_type: UIA_CONTROLTYPE_ID,
}

impl UiaTarget {
    fn capture(automation: &IUIAutomation) -> Result<Self, FocusedOutputReasonCode> {
        let foreground = unsafe { GetForegroundWindow() };
        if foreground.0.is_null() {
            return Err(FocusedOutputReasonCode::NoFocusedTarget);
        }
        let mut foreground_pid = 0;
        unsafe { GetWindowThreadProcessId(foreground, Some(&mut foreground_pid as *mut u32)) };
        if foreground_pid == 0 {
            return Err(FocusedOutputReasonCode::NoFocusedTarget);
        }
        if belongs_to_handy_process_tree(foreground_pid)? {
            return Err(FocusedOutputReasonCode::HandyOwnedTarget);
        }

        let element = unsafe { automation.GetFocusedElement() }
            .map_err(|_| FocusedOutputReasonCode::NoFocusedTarget)?;
        let process_id = unsafe { element.CurrentProcessId() }
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if process_id <= 0 || process_id as u32 != foreground_pid {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let process_id = process_id as u32;
        if belongs_to_handy_process_tree(process_id)? {
            return Err(FocusedOutputReasonCode::HandyOwnedTarget);
        }
        validate_element_metadata(&element, true)?;
        let native = unsafe { element.CurrentNativeWindowHandle() }
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        let native_window = if native.0.is_null() {
            None
        } else {
            let root = unsafe { GetAncestor(native, GA_ROOT) };
            if root != foreground {
                return Err(FocusedOutputReasonCode::TargetChanged);
            }
            Some(native)
        };
        let control_type = unsafe { element.CurrentControlType() }
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        let runtime_id = unsafe { element.GetRuntimeId() }
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if runtime_id.is_null() {
            return Err(FocusedOutputReasonCode::TargetUnsupported);
        }
        let target = Self {
            element,
            runtime_id: RuntimeId(runtime_id),
            process_id,
            foreground,
            native_window,
            control_type,
        };
        target.current_selection(automation)?;
        Ok(target)
    }

    fn revalidate(
        &self,
        automation: &IUIAutomation,
    ) -> Result<IUIAutomationTextRange, FocusedOutputReasonCode> {
        if unsafe { GetForegroundWindow() } != self.foreground {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let current = unsafe { automation.GetFocusedElement() }
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        let same_element = unsafe { automation.CompareElements(&self.element, &current) }
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?
            .as_bool();
        if !same_element {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let current_runtime = unsafe { current.GetRuntimeId() }
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        if current_runtime.is_null() {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let current_runtime = RuntimeId(current_runtime);
        let same_runtime =
            unsafe { automation.CompareRuntimeIds(self.runtime_id.0, current_runtime.0) }
                .map_err(|_| FocusedOutputReasonCode::TargetChanged)?
                .as_bool();
        if !same_runtime {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let process_id = unsafe { current.CurrentProcessId() }
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        if process_id <= 0 || process_id as u32 != self.process_id {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let control_type = unsafe { current.CurrentControlType() }
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        if control_type != self.control_type {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let native = unsafe { current.CurrentNativeWindowHandle() }
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        let current_native = (!native.0.is_null()).then_some(native);
        if current_native != self.native_window {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        validate_element_metadata(&current, false)?;
        self.current_selection_for(&current)
    }

    fn current_selection(
        &self,
        _automation: &IUIAutomation,
    ) -> Result<IUIAutomationTextRange, FocusedOutputReasonCode> {
        self.current_selection_for(&self.element)
    }

    fn current_selection_for(
        &self,
        element: &IUIAutomationElement,
    ) -> Result<IUIAutomationTextRange, FocusedOutputReasonCode> {
        let pattern: IUIAutomationTextPattern =
            unsafe { element.GetCurrentPatternAs(UIA_TextPatternId) }
                .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        let selections = unsafe { pattern.GetSelection() }
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if unsafe { selections.Length() }.map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
            != 1
        {
            return Err(FocusedOutputReasonCode::SelectionChanged);
        }
        let range = unsafe { selections.GetElement(0) }
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if !selection_is_collapsed(&range)? {
            return Err(FocusedOutputReasonCode::SelectionChanged);
        }
        Ok(range)
    }
}

fn validate_element_metadata(
    element: &IUIAutomationElement,
    initial: bool,
) -> Result<(), FocusedOutputReasonCode> {
    let enabled = unsafe { element.CurrentIsEnabled() }
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .as_bool();
    let focusable = unsafe { element.CurrentIsKeyboardFocusable() }
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .as_bool();
    let focused = unsafe { element.CurrentHasKeyboardFocus() }
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .as_bool();
    if !enabled || !focusable || !focused {
        return Err(FocusedOutputReasonCode::TargetNotEditable);
    }
    let password = unsafe { element.CurrentIsPassword() }
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        .as_bool();
    if password {
        return Err(FocusedOutputReasonCode::SecureField);
    }
    let text: IUIAutomationTextPattern = unsafe { element.GetCurrentPatternAs(UIA_TextPatternId) }
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let selections =
        unsafe { text.GetSelection() }.map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    if unsafe { selections.Length() }.map_err(|_| FocusedOutputReasonCode::TargetUnsupported)? != 1
    {
        return Err(if initial {
            FocusedOutputReasonCode::InitialSelectionNotCollapsed
        } else {
            FocusedOutputReasonCode::SelectionChanged
        });
    }
    let range = unsafe { selections.GetElement(0) }
        .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
    let read_only = match unsafe {
        element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
    } {
        Ok(value) => unsafe { value.CurrentIsReadOnly() }
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
            .as_bool(),
        Err(_) => {
            let attribute = unsafe { range.GetAttributeValue(UIA_IsReadOnlyAttributeId) }
                .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
            bool::try_from(&attribute).map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        }
    };
    if read_only {
        return Err(FocusedOutputReasonCode::TargetNotEditable);
    }
    if !selection_is_collapsed(&range)? {
        return Err(if initial {
            FocusedOutputReasonCode::InitialSelectionNotCollapsed
        } else {
            FocusedOutputReasonCode::SelectionChanged
        });
    }
    Ok(())
}

fn selection_is_collapsed(range: &IUIAutomationTextRange) -> Result<bool, FocusedOutputReasonCode> {
    Ok(unsafe {
        range.CompareEndpoints(
            TextPatternRangeEndpoint_Start,
            range,
            TextPatternRangeEndpoint_End,
        )
    }
    .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?
        == 0)
}

struct UiaSubscriptions {
    event_handler: IUIAutomationEventHandler,
    focus_handler: IUIAutomationFocusChangedEventHandler,
    property_handler: IUIAutomationPropertyChangedEventHandler,
    installed: bool,
}

impl UiaSubscriptions {
    fn install(
        automation: &IUIAutomation,
        element: &IUIAutomationElement,
        state: Arc<CallbackState>,
    ) -> Result<Self, FocusedOutputReasonCode> {
        let event_handler: IUIAutomationEventHandler = UiaCallback { state }.into();
        let focus_handler: IUIAutomationFocusChangedEventHandler = event_handler
            .cast()
            .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
        let property_handler: IUIAutomationPropertyChangedEventHandler = event_handler
            .cast()
            .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
        let mut result = Self {
            event_handler,
            focus_handler,
            property_handler,
            installed: false,
        };
        unsafe {
            automation.AddAutomationEventHandler(
                UIA_Text_TextChangedEventId,
                element,
                TreeScope_Element,
                None,
                &result.event_handler,
            )
        }
        .map_err(|_| FocusedOutputReasonCode::MonitorUnavailable)?;
        if unsafe {
            automation.AddAutomationEventHandler(
                UIA_Text_TextSelectionChangedEventId,
                element,
                TreeScope_Element,
                None,
                &result.event_handler,
            )
        }
        .is_err()
        {
            let _ = unsafe {
                automation.RemoveAutomationEventHandler(
                    UIA_Text_TextChangedEventId,
                    element,
                    &result.event_handler,
                )
            };
            return Err(FocusedOutputReasonCode::MonitorUnavailable);
        }
        if unsafe {
            automation.AddPropertyChangedEventHandlerNativeArray(
                element,
                TreeScope_Element,
                None,
                &result.property_handler,
                &[UIA_ValueValuePropertyId],
            )
        }
        .is_err()
        {
            result.remove_partial(automation, element);
            return Err(FocusedOutputReasonCode::MonitorUnavailable);
        }
        if unsafe { automation.AddFocusChangedEventHandler(None, &result.focus_handler) }.is_err() {
            result.remove_partial(automation, element);
            return Err(FocusedOutputReasonCode::MonitorUnavailable);
        }
        result.installed = true;
        Ok(result)
    }

    fn remove_partial(&self, automation: &IUIAutomation, element: &IUIAutomationElement) {
        let _ = unsafe {
            automation.RemoveAutomationEventHandler(
                UIA_Text_TextChangedEventId,
                element,
                &self.event_handler,
            )
        };
        let _ = unsafe {
            automation.RemoveAutomationEventHandler(
                UIA_Text_TextSelectionChangedEventId,
                element,
                &self.event_handler,
            )
        };
        let _ = unsafe {
            automation.RemovePropertyChangedEventHandler(element, &self.property_handler)
        };
    }

    fn remove(&mut self, automation: &IUIAutomation, element: &IUIAutomationElement) {
        if !self.installed {
            return;
        }
        self.installed = false;
        let _ = unsafe { automation.RemoveFocusChangedEventHandler(&self.focus_handler) };
        self.remove_partial(automation, element);
    }
}

struct PendingEvidence {
    kind: PendingKind,
    selection_before: IUIAutomationTextRange,
    value_changed: bool,
    selection_changed: bool,
    deadline: Instant,
}

enum PendingKind {
    Handy(InjectionId),
    External { chars: usize },
}

struct UiaWorker {
    session_id: DictationSessionId,
    event_sink: Arc<dyn SessionEventSink>,
    cancellation: SessionCancellation,
    marker: usize,
    callback_state: Arc<CallbackState>,
    automation: IUIAutomation,
    target: UiaTarget,
    last_selection: IUIAutomationTextRange,
    pending: Option<PendingEvidence>,
    next_observation: u64,
    submitted: bool,
    published_terminal: u8,
    duplicate_effect_deadline: Option<Instant>,
}

impl UiaWorker {
    fn insert(
        &mut self,
        request: InsertionRequest,
        events: &Receiver<NativeEvent>,
    ) -> InsertOutcome {
        if request.session_id != self.session_id {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetChanged,
            };
        }
        if self.submitted {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetClosed,
            };
        }
        if let Err(reason) = self.await_pending(events) {
            return InsertOutcome::Rejected { reason };
        }
        if self.cancellation.is_cancelled() {
            self.invalidate(TERMINAL_CANCELLED);
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        if let Some(reason) = terminal_reason(self.callback_state.terminal.load(Ordering::Acquire))
        {
            return InsertOutcome::Rejected { reason };
        }

        let selection_before = match self.target.revalidate(&self.automation) {
            Ok(selection) => selection,
            Err(reason) => {
                self.invalidate(reason_to_terminal(reason));
                return InsertOutcome::Rejected { reason };
            }
        };
        let injection_marker = marker_for_injection(self.marker, request.injection_id);
        self.duplicate_effect_deadline = None;
        self.pending = Some(PendingEvidence {
            kind: PendingKind::Handy(request.injection_id),
            selection_before,
            value_changed: false,
            selection_changed: false,
            deadline: Instant::now() + PlatformDeadlines::default().handy_receipt,
        });
        self.callback_state
            .active_marker
            .store(injection_marker, Ordering::Release);

        let mut posted_scalars = 0usize;
        for scalar in request.text.chars() {
            if self.cancellation.is_cancelled() {
                self.invalidate(TERMINAL_CANCELLED);
                return if posted_scalars == 0 {
                    InsertOutcome::Rejected {
                        reason: FocusedOutputReasonCode::Cancelled,
                    }
                } else {
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    }
                };
            }
            if terminal_reason(self.callback_state.terminal.load(Ordering::Acquire)).is_some() {
                return if posted_scalars == 0 {
                    InsertOutcome::Rejected {
                        reason: terminal_reason(
                            self.callback_state.terminal.load(Ordering::Acquire),
                        )
                        .unwrap_or(FocusedOutputReasonCode::MonitorUnavailable),
                    }
                } else {
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    }
                };
            }
            if let Err(reason) = self.target.revalidate(&self.automation) {
                self.invalidate(reason_to_terminal(reason));
                return if posted_scalars == 0 {
                    InsertOutcome::Rejected { reason }
                } else {
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    }
                };
            }
            // Cancellation and terminal state are deliberately checked again
            // after the final target call and immediately before this one-scalar
            // dispatch unit.
            if self.cancellation.is_cancelled()
                || self.callback_state.terminal.load(Ordering::Acquire) != TERMINAL_NONE
            {
                return if posted_scalars == 0 {
                    InsertOutcome::Rejected {
                        reason: FocusedOutputReasonCode::Cancelled,
                    }
                } else {
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    }
                };
            }
            let (inputs, count) = unicode_scalar_inputs(scalar, injection_marker);
            let returned =
                unsafe { SendInput(&inputs[..count], size_of::<INPUT>() as i32) } as usize;
            match classify_send_input(count, returned, posted_scalars != 0) {
                SendClassification::Posted => posted_scalars += 1,
                SendClassification::Rejected => {
                    self.pending = None;
                    self.callback_state
                        .active_marker
                        .store(0, Ordering::Release);
                    return InsertOutcome::Rejected {
                        reason: FocusedOutputReasonCode::InjectionDenied,
                    };
                }
                SendClassification::Ambiguous => {
                    self.invalidate(TERMINAL_MONITOR_LOST);
                    return InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    };
                }
            }
        }

        if posted_scalars == 0 {
            self.pending = None;
            self.callback_state
                .active_marker
                .store(0, Ordering::Release);
        }
        InsertOutcome::Complete {
            receipt: ReceiptConfidence::Posted,
        }
    }

    fn submit(&mut self, key: AutoSubmitKey, events: &Receiver<NativeEvent>) -> SubmitOutcome {
        if self.submitted {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetClosed,
            };
        }
        if !submit_key_supported(key) {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::AutoSubmitUnsupported,
            };
        }
        if let Err(reason) = self.await_pending(events) {
            return SubmitOutcome::Rejected { reason };
        }
        if self.cancellation.is_cancelled() {
            self.invalidate(TERMINAL_CANCELLED);
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        if let Some(reason) = terminal_reason(self.callback_state.terminal.load(Ordering::Acquire))
        {
            return SubmitOutcome::Rejected { reason };
        }
        if let Err(reason) = self.target.revalidate(&self.automation) {
            self.invalidate(reason_to_terminal(reason));
            return SubmitOutcome::Rejected { reason };
        }
        if self.cancellation.is_cancelled()
            || self.callback_state.terminal.load(Ordering::Acquire) != TERMINAL_NONE
        {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }

        let submit_marker = (self.marker.rotate_left(17) ^ 0x5355_424dusize) | 1;
        self.callback_state
            .active_marker
            .store(submit_marker, Ordering::Release);
        let (inputs, count) = submit_inputs(key, submit_marker);
        let returned = unsafe { SendInput(&inputs[..count], size_of::<INPUT>() as i32) } as usize;
        match classify_send_input(count, returned, false) {
            SendClassification::Posted => {
                // Submit is the final guarded unit. Monitoring stays armed until
                // close, but no later insertion can overtake the chord.
                self.submitted = true;
                SubmitOutcome::Complete {
                    receipt: ReceiptConfidence::Posted,
                }
            }
            SendClassification::Rejected => {
                self.callback_state
                    .active_marker
                    .store(0, Ordering::Release);
                SubmitOutcome::Rejected {
                    reason: FocusedOutputReasonCode::InjectionDenied,
                }
            }
            SendClassification::Ambiguous => {
                self.invalidate(TERMINAL_MONITOR_LOST);
                SubmitOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                }
            }
        }
    }

    fn await_pending(
        &mut self,
        events: &Receiver<NativeEvent>,
    ) -> Result<(), FocusedOutputReasonCode> {
        while let Some(pending) = &self.pending {
            let now = Instant::now();
            if now >= pending.deadline {
                self.invalidate(TERMINAL_RECEIPT_TIMEOUT);
                return Err(FocusedOutputReasonCode::ReceiptTimeout);
            }
            let wait = pending.deadline.saturating_duration_since(now);
            match events.recv_timeout(wait) {
                Ok(event) => self.handle_native_event(event),
                Err(_) => {
                    self.invalidate(TERMINAL_RECEIPT_TIMEOUT);
                    return Err(FocusedOutputReasonCode::ReceiptTimeout);
                }
            }
            if let Some(reason) =
                terminal_reason(self.callback_state.terminal.load(Ordering::Acquire))
            {
                return Err(reason);
            }
        }
        Ok(())
    }

    fn handle_native_event(&mut self, event: NativeEvent) {
        match event {
            NativeEvent::CompatibleKey { chars } => {
                if self.pending.is_some() || self.submitted {
                    self.invalidate(TERMINAL_UNSAFE_KEY);
                    return;
                }
                self.duplicate_effect_deadline = None;
                let before = match unsafe { self.last_selection.Clone() } {
                    Ok(range) => range,
                    Err(_) => {
                        self.invalidate(TERMINAL_MONITOR_LOST);
                        return;
                    }
                };
                self.pending = Some(PendingEvidence {
                    kind: PendingKind::External { chars },
                    selection_before: before,
                    value_changed: false,
                    selection_changed: false,
                    deadline: Instant::now() + PlatformDeadlines::default().input_effect,
                });
            }
            NativeEvent::TextChanged => {
                if self.submitted {
                    return;
                }
                if let Some(pending) = &mut self.pending {
                    pending.value_changed = true;
                    self.try_complete_evidence();
                } else if !self.duplicate_effect_is_current() {
                    self.invalidate(TERMINAL_UNSAFE_KEY);
                }
            }
            NativeEvent::SelectionChanged => {
                if self.submitted {
                    return;
                }
                if let Some(pending) = &mut self.pending {
                    pending.selection_changed = true;
                    if pending.value_changed {
                        self.try_complete_evidence();
                    }
                } else if !self.duplicate_effect_is_current() {
                    self.invalidate(TERMINAL_UNSAFE_KEY);
                }
            }
            NativeEvent::Terminal { code: _ } => self.observe_terminal(),
        }
    }

    fn try_complete_evidence(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if !pending.value_changed {
            self.pending = Some(pending);
            return;
        }
        let after = match self.target.revalidate(&self.automation) {
            Ok(range) => range,
            Err(reason) => {
                self.invalidate(reason_to_terminal(reason));
                return;
            }
        };
        let forward = unsafe {
            after.CompareEndpoints(
                TextPatternRangeEndpoint_Start,
                &pending.selection_before,
                TextPatternRangeEndpoint_Start,
            )
        }
        .map(|ordering| ordering > 0)
        .unwrap_or(false);
        if !forward {
            self.invalidate(TERMINAL_UNSAFE_KEY);
            return;
        }
        self.last_selection = after;
        match pending.kind {
            PendingKind::Handy(injection_id) => {
                self.callback_state
                    .active_marker
                    .store(0, Ordering::Release);
                self.event_sink.publish(
                    self.session_id,
                    TargetInteractionEvent::HandyInsertionObserved {
                        injection_id,
                        caret_after: None,
                    },
                );
            }
            PendingKind::External { chars } => {
                let observation_id = self.allocate_observation();
                self.event_sink.publish(
                    self.session_id,
                    TargetInteractionEvent::CompatibleExternalInsertion {
                        observation_id,
                        chars,
                        caret_after: None,
                    },
                );
            }
        }
        self.duplicate_effect_deadline = Some(Instant::now() + Duration::from_millis(25));
    }

    fn expire_pending(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| Instant::now() >= pending.deadline)
        {
            self.invalidate(TERMINAL_RECEIPT_TIMEOUT);
        }
    }

    fn duplicate_effect_is_current(&self) -> bool {
        self.duplicate_effect_deadline
            .is_some_and(|deadline| Instant::now() <= deadline)
    }

    fn invalidate(&mut self, code: u8) {
        self.callback_state.terminate(code);
        self.pending = None;
        self.callback_state
            .active_marker
            .store(0, Ordering::Release);
    }
    fn observe_terminal(&mut self) {
        let code = self.callback_state.terminal.load(Ordering::Acquire);
        if code != TERMINAL_NONE && code != self.published_terminal {
            self.published_terminal = code;
            self.publish_terminal(code);
        }
    }

    fn publish_terminal(&mut self, code: u8) {
        let observation_id = self.allocate_observation();
        match code {
            TERMINAL_POINTER => self.event_sink.publish(
                self.session_id,
                TargetInteractionEvent::TargetInvalidated {
                    observation_id,
                    reason: FocusedOutputReasonCode::PhysicalPointerActivity,
                },
            ),
            TERMINAL_UNSAFE_KEY => self.event_sink.publish(
                self.session_id,
                TargetInteractionEvent::UnsafeEdit {
                    observation_id,
                    kind: UnsafeEditKind::CommandShortcut,
                },
            ),
            TERMINAL_MONITOR_LOST => self.event_sink.publish(
                self.session_id,
                TargetInteractionEvent::MonitorUnavailable { observation_id },
            ),
            TERMINAL_RECEIPT_TIMEOUT => self.event_sink.publish(
                self.session_id,
                TargetInteractionEvent::TargetInvalidated {
                    observation_id,
                    reason: FocusedOutputReasonCode::ReceiptTimeout,
                },
            ),
            TERMINAL_CANCELLED => self.event_sink.publish(
                self.session_id,
                TargetInteractionEvent::TargetInvalidated {
                    observation_id,
                    reason: FocusedOutputReasonCode::Cancelled,
                },
            ),
            _ => self.event_sink.publish(
                self.session_id,
                TargetInteractionEvent::TargetInvalidated {
                    observation_id,
                    reason: FocusedOutputReasonCode::TargetChanged,
                },
            ),
        }
    }

    fn allocate_observation(&mut self) -> ObservationId {
        let id = self.next_observation;
        self.next_observation = self.next_observation.saturating_add(1);
        ObservationId(id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendClassification {
    Posted,
    Rejected,
    Ambiguous,
}

fn classify_send_input(
    expected: usize,
    returned: usize,
    posted_before: bool,
) -> SendClassification {
    if returned == expected {
        SendClassification::Posted
    } else if returned == 0 && !posted_before {
        SendClassification::Rejected
    } else {
        SendClassification::Ambiguous
    }
}
fn marker_for_injection(base: usize, injection_id: InjectionId) -> usize {
    let id = injection_id.0 as usize;
    (base ^ id.wrapping_mul(0x9e37_79b9usize).rotate_left(13)) | 1
}

fn unicode_scalar_inputs(scalar: char, marker: usize) -> ([INPUT; 4], usize) {
    let mut utf16 = [0u16; 2];
    let units = scalar.encode_utf16(&mut utf16);
    let mut inputs = [INPUT::default(); 4];
    let mut count = 0;
    for unit in units.iter().copied() {
        inputs[count] = keyboard_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE, marker);
        count += 1;
        inputs[count] = keyboard_input(
            VIRTUAL_KEY(0),
            unit,
            KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
            marker,
        );
        count += 1;
    }
    (inputs, count)
}

fn submit_inputs(key: AutoSubmitKey, marker: usize) -> ([INPUT; 4], usize) {
    let mut inputs = [INPUT::default(); 4];
    match key {
        AutoSubmitKey::Enter => {
            inputs[0] = keyboard_input(VK_RETURN, 0, Default::default(), marker);
            inputs[1] = keyboard_input(VK_RETURN, 0, KEYEVENTF_KEYUP, marker);
            (inputs, 2)
        }
        AutoSubmitKey::CtrlEnter => {
            inputs[0] = keyboard_input(VK_CONTROL, 0, Default::default(), marker);
            inputs[1] = keyboard_input(VK_RETURN, 0, Default::default(), marker);
            inputs[2] = keyboard_input(VK_RETURN, 0, KEYEVENTF_KEYUP, marker);
            inputs[3] = keyboard_input(VK_CONTROL, 0, KEYEVENTF_KEYUP, marker);
            (inputs, 4)
        }
        AutoSubmitKey::CmdEnter => (inputs, 0),
    }
}

fn keyboard_input(
    virtual_key: VIRTUAL_KEY,
    scan_code: u16,
    flags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS,
    marker: usize,
) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: virtual_key,
                wScan: scan_code,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: marker,
            },
        },
    }
}

fn submit_key_supported(key: AutoSubmitKey) -> bool {
    matches!(key, AutoSubmitKey::Enter | AutoSubmitKey::CtrlEnter)
}

fn windows_route_capability(supports_auto_submit: bool) -> FocusedOutputCapability {
    FocusedOutputCapability::guarded_focused_control(
        FocusedOutputBackend::Windows,
        ResolvedInsertionCapability {
            insertion_transport: InsertionTransport::WindowsUnicodeSendInput,
            receipt_confidence: ReceiptConfidence::Posted,
        },
        MixedInputSupport::GuardedKeyboardInsertionsOnly,
        supports_auto_submit,
    )
}

fn terminal_reason(code: u8) -> Option<FocusedOutputReasonCode> {
    match code {
        TERMINAL_NONE => None,
        TERMINAL_TARGET_CHANGED => Some(FocusedOutputReasonCode::TargetChanged),
        TERMINAL_POINTER => Some(FocusedOutputReasonCode::PhysicalPointerActivity),
        TERMINAL_UNSAFE_KEY => Some(FocusedOutputReasonCode::UnsafeKeyboardCommand),
        TERMINAL_MONITOR_LOST => Some(FocusedOutputReasonCode::MonitorUnavailable),
        TERMINAL_CANCELLED => Some(FocusedOutputReasonCode::Cancelled),
        TERMINAL_RECEIPT_TIMEOUT => Some(FocusedOutputReasonCode::ReceiptTimeout),
        _ => Some(FocusedOutputReasonCode::MonitorUnavailable),
    }
}

fn reason_to_terminal(reason: FocusedOutputReasonCode) -> u8 {
    match reason {
        FocusedOutputReasonCode::Cancelled => TERMINAL_CANCELLED,
        FocusedOutputReasonCode::MonitorUnavailable
        | FocusedOutputReasonCode::BackendDisconnected => TERMINAL_MONITOR_LOST,
        FocusedOutputReasonCode::ReceiptTimeout => TERMINAL_RECEIPT_TIMEOUT,
        _ => TERMINAL_TARGET_CHANGED,
    }
}

fn random_marker() -> usize {
    let mut marker = 0usize;
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            (&mut marker as *mut usize).cast(),
            size_of::<usize>() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 || marker == 0 {
        marker = MARKER_FALLBACK.fetch_add(0x9e37_79b9usize, Ordering::Relaxed);
    }
    marker | 1
}

fn belongs_to_handy_process_tree(process_id: u32) -> Result<bool, FocusedOutputReasonCode> {
    let own = unsafe { GetCurrentProcessId() };
    if process_id == own {
        return Ok(true);
    }
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.0 as isize == -1 {
        return Err(FocusedOutputReasonCode::TargetUnsupported);
    }
    struct Snapshot(HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
    let _snapshot = Snapshot(snapshot);

    let mut current = process_id;
    for _ in 0..64 {
        if current == own {
            return Ok(true);
        }
        let Some(parent) = process_parent(snapshot, current) else {
            return Ok(false);
        };
        if parent == 0 || parent == current {
            return Ok(false);
        }
        current = parent;
    }
    Err(FocusedOutputReasonCode::TargetUnsupported)
}

fn process_parent(snapshot: HANDLE, process_id: u32) -> Option<u32> {
    let mut entry = ProcessEntry32W::default();
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while ok {
        if entry.process_id == process_id {
            return Some(entry.parent_process_id);
        }
        entry = ProcessEntry32W::default();
        ok = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    None
}

fn wait_and_join_failed(
    signal: &SessionSignal,
    worker: JoinHandle<()>,
    hook: JoinHandle<()>,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && !signal.both_threads_stopped() {
        thread::sleep(Duration::from_millis(2));
    }
    if signal.worker_stopped.load(Ordering::Acquire) {
        let _ = worker.join();
    } else {
        drop(worker);
    }
    if signal.hook_stopped.load(Ordering::Acquire) {
        let _ = hook.join();
    } else {
        drop(hook);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_input_count_classification_is_strict() {
        assert_eq!(classify_send_input(2, 2, false), SendClassification::Posted);
        assert_eq!(
            classify_send_input(2, 0, false),
            SendClassification::Rejected
        );
        assert_eq!(
            classify_send_input(2, 1, false),
            SendClassification::Ambiguous
        );
        assert_eq!(
            classify_send_input(2, 0, true),
            SendClassification::Ambiguous
        );
    }

    #[test]
    fn unicode_construction_is_one_scalar_and_preserves_surrogates() {
        let (ascii, ascii_count) = unicode_scalar_inputs('A', 77);
        assert_eq!(ascii_count, 2);
        let ascii_down = unsafe { ascii[0].Anonymous.ki };
        let ascii_up = unsafe { ascii[1].Anonymous.ki };
        assert_eq!(ascii_down.wScan, b'A' as u16);
        assert!(ascii_down.dwFlags.contains(KEYEVENTF_UNICODE));
        assert!(ascii_up.dwFlags.contains(KEYEVENTF_KEYUP));
        assert_eq!(ascii_down.dwExtraInfo, 77);

        let (astral, astral_count) = unicode_scalar_inputs('\u{1f642}', 91);
        assert_eq!(astral_count, 4);
        let first = unsafe { astral[0].Anonymous.ki };
        let second = unsafe { astral[2].Anonymous.ki };
        assert_eq!([first.wScan, second.wScan], [0xd83d, 0xde42]);
    }

    #[derive(Clone, Copy)]
    struct TargetFacts {
        process: u32,
        runtime: u64,
        control: u32,
        password: bool,
        read_only: bool,
        collapsed: bool,
    }

    fn validate_facts(
        expected: TargetFacts,
        actual: TargetFacts,
    ) -> Result<(), FocusedOutputReasonCode> {
        if expected.process != actual.process
            || expected.runtime != actual.runtime
            || expected.control != actual.control
        {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        if actual.password {
            return Err(FocusedOutputReasonCode::SecureField);
        }
        if actual.read_only {
            return Err(FocusedOutputReasonCode::TargetNotEditable);
        }
        if !actual.collapsed {
            return Err(FocusedOutputReasonCode::SelectionChanged);
        }
        Ok(())
    }

    fn safe_facts() -> TargetFacts {
        TargetFacts {
            process: 3,
            runtime: 5,
            control: 7,
            password: false,
            read_only: false,
            collapsed: true,
        }
    }

    #[test]
    fn exact_target_identity_changes_are_rejected() {
        let expected = safe_facts();
        for changed in [
            TargetFacts {
                process: 4,
                ..expected
            },
            TargetFacts {
                runtime: 6,
                ..expected
            },
            TargetFacts {
                control: 8,
                ..expected
            },
        ] {
            assert_eq!(
                validate_facts(expected, changed),
                Err(FocusedOutputReasonCode::TargetChanged)
            );
        }
    }

    #[test]
    fn password_and_selection_are_rejected() {
        let expected = safe_facts();
        assert_eq!(
            validate_facts(
                expected,
                TargetFacts {
                    password: true,
                    ..expected
                }
            ),
            Err(FocusedOutputReasonCode::SecureField)
        );
        assert_eq!(
            validate_facts(
                expected,
                TargetFacts {
                    collapsed: false,
                    ..expected
                }
            ),
            Err(FocusedOutputReasonCode::SelectionChanged)
        );
        assert_eq!(
            validate_facts(
                expected,
                TargetFacts {
                    read_only: true,
                    ..expected
                }
            ),
            Err(FocusedOutputReasonCode::TargetNotEditable)
        );
    }

    #[test]
    fn cancellation_gate_runs_before_dispatch() {
        let cancellation = SessionCancellation::default();
        cancellation.cancel();
        let calls = AtomicUsize::new(0);
        let dispatched = if cancellation.is_cancelled() {
            false
        } else {
            calls.fetch_add(1, Ordering::Relaxed);
            true
        };
        assert!(!dispatched);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn terminal_compare_exchange_is_first_wins_and_self_disarms() {
        let (sender, receiver) = bounded(4);
        let state = CallbackState {
            terminal: AtomicU8::new(TERMINAL_NONE),
            active_marker: AtomicUsize::new(0),
            modifiers: AtomicU8::new(0),
            hook_thread_id: AtomicU32::new(0),
            stop_chord: StopChord {
                modifiers: 0,
                virtual_key: 0,
                configured: false,
            },
            events: sender,
        };
        assert!(state.terminate(TERMINAL_POINTER));
        assert!(!state.terminate(TERMINAL_TARGET_CHANGED));
        assert_eq!(state.terminal.load(Ordering::Acquire), TERMINAL_POINTER);
        assert!(matches!(
            receiver.try_recv(),
            Ok(NativeEvent::Terminal {
                code: TERMINAL_POINTER
            })
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn route_is_pinned_to_posted_unicode_and_supported_submit_chords() {
        let capability = windows_route_capability(true);
        assert_eq!(
            capability.route(),
            Some(ResolvedInsertionCapability {
                insertion_transport: InsertionTransport::WindowsUnicodeSendInput,
                receipt_confidence: ReceiptConfidence::Posted,
            })
        );
        assert!(capability.supports_auto_submit());
        assert!(submit_key_supported(AutoSubmitKey::Enter));
        assert!(submit_key_supported(AutoSubmitKey::CtrlEnter));
        assert!(!submit_key_supported(AutoSubmitKey::CmdEnter));
        assert_ne!(
            marker_for_injection(11, InjectionId(1)),
            marker_for_injection(11, InjectionId(2))
        );
    }

    #[test]
    fn close_signal_and_callback_terminal_are_idempotent() {
        let signal = SessionSignal::new();
        signal.request_close();
        signal.request_close();
        assert!(signal.close_requested.load(Ordering::Acquire));

        let (sender, _receiver) = bounded(1);
        let state = CallbackState {
            terminal: AtomicU8::new(TERMINAL_NONE),
            active_marker: AtomicUsize::new(42),
            modifiers: AtomicU8::new(0),
            hook_thread_id: AtomicU32::new(0),
            stop_chord: StopChord {
                modifiers: 0,
                virtual_key: 0,
                configured: false,
            },
            events: sender,
        };
        assert!(state.terminate(TERMINAL_MONITOR_LOST));
        assert!(!state.terminate(TERMINAL_MONITOR_LOST));
        assert_eq!(state.active_marker.load(Ordering::Acquire), 0);
    }

    #[test]
    fn configured_stop_chord_is_neutral_but_other_commands_are_not_compatible() {
        let chord = StopChord::parse(Some("Ctrl+Shift+Space")).unwrap();
        assert!(chord.matches(MOD_CTRL | MOD_SHIFT, VK_SPACE.0 as u32));
        assert!(!is_compatible_printable(VK_SPACE.0 as u32, MOD_CTRL));
        assert!(is_compatible_printable(b'A' as u32, MOD_SHIFT));
        assert!(!is_compatible_printable(VK_DELETE.0 as u32, 0));
        assert!(!is_compatible_printable(VK_TAB.0 as u32, 0));
        assert!(!is_compatible_printable(VK_ESCAPE.0 as u32, 0));
        assert!(!is_compatible_printable(VK_LEFT.0 as u32, 0));
        assert!(!is_compatible_printable(VK_RIGHT.0 as u32, 0));
        assert!(!is_compatible_printable(VK_UP.0 as u32, 0));
        assert!(!is_compatible_printable(VK_DOWN.0 as u32, 0));
        assert!(!is_compatible_printable(VK_HOME.0 as u32, 0));
        assert!(!is_compatible_printable(VK_END.0 as u32, 0));
        assert!(!is_compatible_printable(VK_PRIOR.0 as u32, 0));
        assert!(!is_compatible_printable(VK_NEXT.0 as u32, 0));
        assert!(!is_compatible_printable(VK_INSERT.0 as u32, 0));
    }
}
