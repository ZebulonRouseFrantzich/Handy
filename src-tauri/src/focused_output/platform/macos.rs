use super::{BeginSession, FocusedFieldBackend, FocusedTargetSession, SessionEventSink};
use crate::focused_output::types::{
    BeginContext, BeginReceipt, DictationSessionId, FocusedOutputBackend, FocusedOutputCapability,
    FocusedOutputPermission, FocusedOutputReasonCode, InjectionId, InsertOutcome, InsertionRequest,
    InsertionTransport, MixedInputSupport, ObservationId, PlatformDeadlines, ReceiptConfidence,
    ResolvedInsertionCapability, SessionCancellation, SubmitOutcome, TargetInteractionEvent,
    UnsafeEditKind,
};
use crate::settings::AutoSubmitKey;
use std::ffi::{c_char, c_double, c_float, c_long, c_void, CString};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const QUEUE_LEN: usize = 64;
const COMMAND_LEN: usize = 4;
const LOOP_SLICE: Duration = Duration::from_millis(4);
const DUPLICATE_GUARD: Duration = Duration::from_millis(25);
const AX_OK: i32 = 0;
const AX_CANNOT_COMPLETE: i32 = -25204;
const UTF8: u32 = 0x0800_0100;
const AX_CF_RANGE: i32 = 4;
const CF_RUN_LOOP_HANDLED_SOURCE: i32 = 4;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const EVENT_VALUE: u8 = 1;
const EVENT_SELECTION: u8 = 2;
const EVENT_TARGET_LOST: u8 = 3;
const EVENT_KEY: u8 = 4;
const EVENT_POINTER: u8 = 5;
const EVENT_TAP_LOST: u8 = 6;
const TERMINAL_NONE: u8 = 0;
const TERMINAL_TARGET: u8 = 1;
const TERMINAL_POINTER: u8 = 2;
const TERMINAL_MONITOR: u8 = 3;
const KEY_DOWN: u32 = 10;
const FLAGS_CHANGED: u32 = 12;
const LEFT_DOWN: u32 = 1;
const LEFT_UP: u32 = 2;
const RIGHT_DOWN: u32 = 3;
const RIGHT_UP: u32 = 4;
const MOUSE_MOVED: u32 = 5;
const LEFT_DRAGGED: u32 = 6;
const RIGHT_DRAGGED: u32 = 7;
const SCROLL_WHEEL: u32 = 22;
const TABLET_POINTER: u32 = 23;
const TABLET_PROXIMITY: u32 = 24;
const OTHER_DOWN: u32 = 25;
const OTHER_UP: u32 = 26;
const OTHER_DRAGGED: u32 = 27;
const TAP_TIMEOUT: u32 = u32::MAX - 1;
const TAP_DISABLED: u32 = u32::MAX;
const EVENT_KEYCODE: u32 = 9;
const EVENT_USER_DATA: u32 = 42;
const FLAG_SHIFT: u64 = 1 << 17;
const FLAG_CONTROL: u64 = 1 << 18;
const FLAG_OPTION: u64 = 1 << 19;
const FLAG_COMMAND: u64 = 1 << 20;
const RETURN_KEY: u16 = 36;
const KEYPAD_ENTER_KEY: u16 = 76;
const KEY_INTENT_PRINTABLE: u64 = 0;
const KEY_INTENT_DELETE: u64 = 1;
const KEY_INTENT_SELECTION: u64 = 2;
const KEY_INTENT_CARET: u64 = 3;
const KEY_INTENT_FOCUS: u64 = 4;
const KEY_INTENT_SUBMIT: u64 = 5;
const KEY_INTENT_COMMAND: u64 = 6;
const KEY_INTENT_IME: u64 = 7;
const KEY_INTENT_UNKNOWN: u64 = 8;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CFRange {
    location: c_long,
    length: c_long,
}
type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFRunLoopRef = *mut c_void;
type CFRunLoopSourceRef = *mut c_void;
type AXUIElementRef = *mut c_void;
type AXObserverRef = *mut c_void;
type CGEventRef = *mut c_void;
type CFMachPortRef = *mut c_void;

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
    fn AXUIElementCreateSystemWide() -> AXUIElementRef;
    fn AXUIElementGetPid(element: AXUIElementRef, pid: *mut i32) -> i32;
    fn AXUIElementCopyAttributeValue(
        element: AXUIElementRef,
        name: CFStringRef,
        value: *mut CFTypeRef,
    ) -> i32;
    fn AXUIElementCopyParameterizedAttributeValue(
        element: AXUIElementRef,
        name: CFStringRef,
        parameter: CFTypeRef,
        value: *mut CFTypeRef,
    ) -> i32;
    fn AXUIElementSetAttributeValue(
        element: AXUIElementRef,
        name: CFStringRef,
        value: CFTypeRef,
    ) -> i32;
    fn AXUIElementIsAttributeSettable(
        element: AXUIElementRef,
        name: CFStringRef,
        settable: *mut bool,
    ) -> i32;
    fn AXUIElementSetMessagingTimeout(element: AXUIElementRef, timeout: c_float) -> i32;
    fn AXValueCreate(kind: i32, value: *const c_void) -> CFTypeRef;
    fn AXValueGetValue(value: CFTypeRef, kind: i32, output: *mut c_void) -> bool;
    fn AXObserverCreate(
        pid: i32,
        callback: unsafe extern "C" fn(AXObserverRef, AXUIElementRef, CFStringRef, *mut c_void),
        observer: *mut AXObserverRef,
    ) -> i32;
    fn AXObserverAddNotification(
        observer: AXObserverRef,
        element: AXUIElementRef,
        name: CFStringRef,
        refcon: *mut c_void,
    ) -> i32;
    fn AXObserverRemoveNotification(
        observer: AXObserverRef,
        element: AXUIElementRef,
        name: CFStringRef,
    ) -> i32;
    fn AXObserverGetRunLoopSource(observer: AXObserverRef) -> CFRunLoopSourceRef;
    fn CGPreflightListenEventAccess() -> bool;
    fn CGRequestListenEventAccess() -> bool;
    fn CGEventTapCreate(
        tap: u32,
        place: u32,
        options: u32,
        mask: u64,
        callback: unsafe extern "C" fn(*mut c_void, u32, CGEventRef, *mut c_void) -> CGEventRef,
        user: *mut c_void,
    ) -> CFMachPortRef;
    fn CGEventTapEnable(tap: CFMachPortRef, enable: bool);
    fn CGEventTapIsEnabled(tap: CFMachPortRef) -> bool;
    fn CGEventGetIntegerValueField(event: CGEventRef, field: u32) -> i64;
    fn CGEventGetFlags(event: CGEventRef) -> u64;
    fn CGEventSourceCreate(state: i32) -> CFTypeRef;
    fn CGEventCreateKeyboardEvent(source: CFTypeRef, key: u16, down: bool) -> CGEventRef;
    fn CGEventKeyboardGetUnicodeString(
        event: CGEventRef,
        max_len: usize,
        actual_len: *mut usize,
        text: *mut u16,
    );
    fn CGEventKeyboardSetUnicodeString(event: CGEventRef, len: usize, text: *const u16);
    fn CGEventSetFlags(event: CGEventRef, flags: u64);
    fn CGEventSetIntegerValueField(event: CGEventRef, field: u32, value: i64);
    fn CGEventPost(tap: u32, event: CGEventRef);
}
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecRandomDefault: *const c_void;
    fn SecRandomCopyBytes(random: *const c_void, count: usize, bytes: *mut u8) -> i32;
}
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut c_void, buffer_size: u32) -> i32;
}
#[link(name = "Carbon", kind = "framework")]
unsafe extern "C" {
    static kTISPropertyInputSourceType: CFStringRef;
    static kTISTypeKeyboardLayout: CFStringRef;
    fn TISCopyCurrentKeyboardInputSource() -> CFTypeRef;
    fn TISGetInputSourceProperty(input_source: CFTypeRef, property_key: CFStringRef) -> CFTypeRef;
    fn IsSecureEventInputEnabled() -> u8;
}
fn secure_input_enabled() -> bool {
    unsafe { IsSecureEventInputEnabled() != 0 }
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFRunLoopDefaultMode: CFStringRef;
    static kCFBooleanTrue: CFTypeRef;
    fn CFRetain(value: CFTypeRef) -> CFTypeRef;
    fn CFRelease(value: CFTypeRef);
    fn CFEqual(a: CFTypeRef, b: CFTypeRef) -> bool;
    fn CFGetTypeID(value: CFTypeRef) -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFBooleanGetValue(value: CFTypeRef) -> bool;
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetLength(value: CFStringRef) -> c_long;
    fn CFStringGetMaximumSizeForEncoding(len: c_long, encoding: u32) -> c_long;
    fn CFStringGetCString(
        value: CFStringRef,
        buffer: *mut c_char,
        size: c_long,
        encoding: u32,
    ) -> bool;
    fn CFStringCreateWithCString(
        allocator: CFTypeRef,
        value: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        len: c_long,
        encoding: u32,
        external: bool,
    ) -> CFStringRef;
    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: c_long,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopAddSource(run_loop: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRemoveSource(run_loop: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRunInMode(mode: CFStringRef, seconds: c_double, after_source: bool) -> i32;
    fn CFMachPortCreateRunLoopSource(
        allocator: CFTypeRef,
        port: CFMachPortRef,
        order: c_long,
    ) -> CFRunLoopSourceRef;
    fn CFMachPortInvalidate(port: CFMachPortRef);
}

struct Owned(CFTypeRef);
impl Owned {
    fn new(value: CFTypeRef) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }
    fn ax(&self) -> AXUIElementRef {
        self.0.cast_mut()
    }
}
impl Clone for Owned {
    fn clone(&self) -> Self {
        unsafe { CFRetain(self.0) };
        Self(self.0)
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) }
    }
}
unsafe impl Send for Owned {}

struct Ring {
    head: AtomicU64,
    tail: AtomicU64,
    kinds: [AtomicU8; QUEUE_LEN],
    data: [AtomicU64; QUEUE_LEN],
}
impl Ring {
    fn new() -> Self {
        Self {
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            kinds: [const { AtomicU8::new(0) }; QUEUE_LEN],
            data: [const { AtomicU64::new(0) }; QUEUE_LEN],
        }
    }
    fn push(&self, kind: u8, data: u64) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        if head.wrapping_sub(self.tail.load(Ordering::Acquire)) >= QUEUE_LEN as u64 {
            return false;
        }
        let index = head as usize % QUEUE_LEN;
        self.data[index].store(data, Ordering::Relaxed);
        self.kinds[index].store(kind, Ordering::Relaxed);
        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }
    fn pop(&self) -> Option<(u8, u64)> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        let index = tail as usize % QUEUE_LEN;
        let value = (
            self.kinds[index].load(Ordering::Relaxed),
            self.data[index].load(Ordering::Relaxed),
        );
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(value)
    }
}
struct CallbackState {
    ring: Ring,
    terminal: AtomicU8,
    injection: AtomicU64,
    session_marker: u64,
    active_marker: AtomicU64,
    active_seen: AtomicU64,
    guard: Option<KeyGuard>,
}
impl CallbackState {
    fn publish(&self, kind: u8, data: u64) {
        if !self.ring.push(kind, data) {
            self.terminal(TERMINAL_MONITOR);
        }
    }
    fn terminal(&self, reason: u8) {
        let _ = self.terminal.compare_exchange(
            TERMINAL_NONE,
            reason,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}
struct Registration {
    state: *const CallbackState,
    kind: u8,
}
impl Registration {
    fn new(state: &Arc<CallbackState>, kind: u8) -> Self {
        Self {
            state: Arc::into_raw(state.clone()),
            kind,
        }
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        unsafe { drop(Arc::from_raw(self.state)) }
    }
}

unsafe extern "C" fn ax_callback(
    _: AXObserverRef,
    _: AXUIElementRef,
    _: CFStringRef,
    refcon: *mut c_void,
) {
    if refcon.is_null() {
        return;
    }
    let registration = unsafe { &*refcon.cast::<Registration>() };
    let state = unsafe { &*registration.state };
    if registration.kind == EVENT_TARGET_LOST {
        state.terminal(TERMINAL_TARGET);
    }
    state.publish(registration.kind, state.injection.load(Ordering::Acquire));
}
unsafe extern "C" fn tap_callback(
    _: *mut c_void,
    kind: u32,
    event: CGEventRef,
    user: *mut c_void,
) -> CGEventRef {
    if user.is_null() {
        return event;
    }
    let state = unsafe { &*user.cast::<CallbackState>() };
    if kind == TAP_TIMEOUT || kind == TAP_DISABLED {
        state.terminal(TERMINAL_MONITOR);
        state.publish(EVENT_TAP_LOST, 0);
        return event;
    }
    if pointer_event(kind) {
        state.terminal(TERMINAL_POINTER);
        state.publish(EVENT_POINTER, 0);
        return event;
    }
    if kind != KEY_DOWN {
        return event;
    }
    let marker = unsafe { CGEventGetIntegerValueField(event, EVENT_USER_DATA) } as u64;
    match marker_disposition(marker, state.active_marker.load(Ordering::Acquire)) {
        MarkerDisposition::Active => {
            state.active_seen.store(marker, Ordering::Release);
            return event;
        }
        MarkerDisposition::Foreign => {
            state.terminal(TERMINAL_TARGET);
            state.publish(EVENT_KEY, KEY_INTENT_UNKNOWN);
            return event;
        }
        MarkerDisposition::Physical => {}
    }
    let key = unsafe { CGEventGetIntegerValueField(event, EVENT_KEYCODE) } as u16;
    let flags = unsafe { CGEventGetFlags(event) } & modifier_mask();
    if state.guard == Some(KeyGuard { key, flags }) {
        return event;
    }
    let mut unicode = [0u16; 8];
    let mut unicode_len = 0;
    unsafe {
        CGEventKeyboardGetUnicodeString(
            event,
            unicode.len(),
            &mut unicode_len,
            unicode.as_mut_ptr(),
        )
    };
    let intent = if unicode_len <= unicode.len() {
        classify_key_intent(
            key,
            flags,
            &unicode[..unicode_len],
            keyboard_layout_active(),
        )
    } else {
        KEY_INTENT_IME
    };
    state.publish(EVENT_KEY, intent);
    event
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyGuard {
    key: u16,
    flags: u64,
}
fn modifier_mask() -> u64 {
    FLAG_SHIFT | FLAG_CONTROL | FLAG_OPTION | FLAG_COMMAND
}
fn pointer_event(kind: u32) -> bool {
    matches!(
        kind,
        LEFT_DOWN
            | LEFT_UP
            | RIGHT_DOWN
            | RIGHT_UP
            | MOUSE_MOVED
            | LEFT_DRAGGED
            | RIGHT_DRAGGED
            | SCROLL_WHEEL
            | TABLET_POINTER
            | TABLET_PROXIMITY
            | OTHER_DOWN
            | OTHER_UP
            | OTHER_DRAGGED
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkerDisposition {
    Physical,
    Active,
    Foreign,
}
fn marker_disposition(observed: u64, active: u64) -> MarkerDisposition {
    if observed == 0 {
        MarkerDisposition::Physical
    } else if active != 0 && observed == active {
        MarkerDisposition::Active
    } else {
        MarkerDisposition::Foreign
    }
}
fn printable_keycode(key: u16) -> bool {
    matches!(
        key,
        0..=9
            | 11..=35
            | 37..=47
            | 49..=50
            | 65
            | 67
            | 69
            | 75
            | 78
            | 81..=92
    )
}
fn classify_key_intent(key: u16, flags: u64, unicode: &[u16], layout_active: bool) -> u64 {
    if matches!(key, RETURN_KEY | KEYPAD_ENTER_KEY) {
        return KEY_INTENT_SUBMIT;
    }
    if flags & (FLAG_COMMAND | FLAG_CONTROL) != 0 {
        return KEY_INTENT_COMMAND;
    }
    if flags & FLAG_OPTION != 0 {
        return KEY_INTENT_IME;
    }
    if matches!(key, 51 | 117) {
        return KEY_INTENT_DELETE;
    }
    if matches!(key, 115 | 116 | 119 | 121 | 123..=126) {
        return if flags & FLAG_SHIFT != 0 {
            KEY_INTENT_SELECTION
        } else {
            KEY_INTENT_CARET
        };
    }
    if key == 48 {
        return KEY_INTENT_FOCUS;
    }
    if !layout_active {
        return KEY_INTENT_IME;
    }
    if !printable_keycode(key) {
        return KEY_INTENT_UNKNOWN;
    }
    let mut chars = char::decode_utf16(unicode.iter().copied());
    match (chars.next(), chars.next()) {
        (Some(Ok(value)), None) if !value.is_control() => KEY_INTENT_PRINTABLE,
        _ => KEY_INTENT_IME,
    }
}
fn keyboard_layout_active() -> bool {
    let Some(source) = Owned::new(unsafe { TISCopyCurrentKeyboardInputSource() }) else {
        return false;
    };
    let kind = unsafe { TISGetInputSourceProperty(source.0, kTISPropertyInputSourceType) };
    !kind.is_null() && unsafe { CFEqual(kind, kTISTypeKeyboardLayout.cast()) }
}
fn key_intent_kind(intent: u64) -> UnsafeEditKind {
    match intent {
        KEY_INTENT_DELETE => UnsafeEditKind::Delete,
        KEY_INTENT_SELECTION => UnsafeEditKind::SelectionChanged,
        KEY_INTENT_CARET => UnsafeEditKind::CaretRepositioned,
        KEY_INTENT_FOCUS => UnsafeEditKind::FocusTraversal,
        KEY_INTENT_SUBMIT => UnsafeEditKind::SubmitOrNewlineAmbiguous,
        KEY_INTENT_COMMAND => UnsafeEditKind::CommandShortcut,
        KEY_INTENT_IME => UnsafeEditKind::ImeComposition,
        _ => UnsafeEditKind::Unknown,
    }
}
fn parse_guard(value: Option<&str>) -> Result<Option<KeyGuard>, FocusedOutputReasonCode> {
    let Some(value) = value else { return Ok(None) };
    let mut flags = 0;
    let mut key = None;
    for part in value.split('+') {
        match part.trim().to_ascii_lowercase().as_str() {
            "cmd" | "command" | "meta" | "super" => flags |= FLAG_COMMAND,
            "ctrl" | "control" => flags |= FLAG_CONTROL,
            "shift" => flags |= FLAG_SHIFT,
            "alt" | "option" => flags |= FLAG_OPTION,
            "space" => set_key(&mut key, 49)?,
            "enter" | "return" => set_key(&mut key, RETURN_KEY)?,
            _ => return Err(FocusedOutputReasonCode::ControlShortcutUnsupported),
        }
    }
    Ok(Some(KeyGuard {
        key: key.ok_or(FocusedOutputReasonCode::ControlShortcutUnsupported)?,
        flags,
    }))
}
fn set_key(slot: &mut Option<u16>, key: u16) -> Result<(), FocusedOutputReasonCode> {
    if slot.replace(key).is_some() {
        Err(FocusedOutputReasonCode::ControlShortcutUnsupported)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Ax,
    Cg,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    AppKit,
    WebKit,
    Chromium,
    Unknown,
}
fn negotiate(settable: bool, readable: bool) -> Route {
    if settable && readable {
        Route::Ax
    } else {
        Route::Cg
    }
}
fn provider(executable: &str) -> Provider {
    let executable = executable.to_ascii_lowercase();
    if executable == "safari"
        || executable == "webkit"
        || executable.starts_with("com.apple.webkit.")
    {
        Provider::WebKit
    } else if matches!(
        executable.as_str(),
        "google chrome" | "chromium" | "microsoft edge" | "brave browser" | "electron"
    ) || executable.starts_with("google chrome helper")
        || executable.starts_with("chromium helper")
        || executable.starts_with("microsoft edge helper")
        || executable.starts_with("brave browser helper")
        || executable.starts_with("electron helper")
    {
        Provider::Chromium
    } else if matches!(
        executable.as_str(),
        "notes" | "textedit" | "mail" | "messages"
    ) {
        Provider::AppKit
    } else {
        Provider::Unknown
    }
}
fn checked_security_metadata(
    subrole: Result<String, i32>,
    protected: Result<bool, i32>,
) -> Result<String, FocusedOutputReasonCode> {
    let subrole = subrole.map_err(|_| FocusedOutputReasonCode::SecureField)?;
    let protected = protected.map_err(|_| FocusedOutputReasonCode::SecureField)?;
    if subrole == "AXSecureTextField" || protected {
        Err(FocusedOutputReasonCode::SecureField)
    } else {
        Ok(subrole)
    }
}
fn submit_supported(provider: Provider, role: &str, _: AutoSubmitKey) -> bool {
    provider != Provider::Unknown && role == "AXTextField"
}
fn capability(route: Route, submit: bool) -> FocusedOutputCapability {
    let resolved = ResolvedInsertionCapability {
        insertion_transport: if route == Route::Ax {
            InsertionTransport::MacAxSelectedText
        } else {
            InsertionTransport::MacCgEventUnicode
        },
        receipt_confidence: if route == Route::Ax {
            ReceiptConfidence::Verified
        } else {
            ReceiptConfidence::Posted
        },
    };
    if route == Route::Ax {
        FocusedOutputCapability::verified_control(
            FocusedOutputBackend::MacOs,
            resolved,
            MixedInputSupport::GuardedKeyboardInsertionsOnly,
            submit,
        )
    } else {
        FocusedOutputCapability::guarded_focused_control(
            FocusedOutputBackend::MacOs,
            resolved,
            MixedInputSupport::GuardedKeyboardInsertionsOnly,
            submit,
        )
    }
}
fn classify_ax(request: &str, set_error: Option<i32>, readback: Option<&str>) -> InsertOutcome {
    if let Some(error) = set_error {
        return if error == AX_CANNOT_COMPLETE {
            InsertOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            }
        } else {
            InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::InjectionFailed,
            }
        };
    }
    let Some(readback) = readback else {
        return InsertOutcome::Ambiguous {
            reason: FocusedOutputReasonCode::InjectionAmbiguous,
        };
    };
    if readback == request {
        InsertOutcome::Complete {
            receipt: ReceiptConfidence::Verified,
        }
    } else {
        InsertOutcome::Ambiguous {
            reason: FocusedOutputReasonCode::InjectionAmbiguous,
        }
    }
}
fn scalars(text: &str) -> impl Iterator<Item = ([u16; 2], usize, usize)> + '_ {
    text.chars().map(|c| {
        let mut b = [0; 2];
        let n = c.encode_utf16(&mut b).len();
        (b, n, c.len_utf8())
    })
}
fn verified_cg_prefix(total_bytes: usize, accepted_bytes: usize) -> InsertOutcome {
    if accepted_bytes == total_bytes {
        InsertOutcome::Complete {
            receipt: ReceiptConfidence::Verified,
        }
    } else {
        InsertOutcome::Partial {
            accepted_bytes,
            receipt: ReceiptConfidence::Verified,
            reason: FocusedOutputReasonCode::InjectionPartial,
        }
    }
}

pub struct MacFocusedFieldBackend {
    shutdown: AtomicBool,
    sessions: Mutex<Vec<Weak<Control>>>,
    deadlines: PlatformDeadlines,
}
impl MacFocusedFieldBackend {
    pub fn new() -> Self {
        Self {
            shutdown: AtomicBool::new(false),
            sessions: Mutex::new(Vec::new()),
            deadlines: PlatformDeadlines::default(),
        }
    }
    fn preflight() -> Result<(), FocusedOutputReasonCode> {
        if !unsafe { AXIsProcessTrusted() } {
            Err(FocusedOutputReasonCode::AccessibilityPermissionMissing)
        } else if !unsafe { CGPreflightListenEventAccess() } {
            Err(FocusedOutputReasonCode::InputMonitoringPermissionMissing)
        } else if secure_input_enabled() {
            Err(FocusedOutputReasonCode::SecureInputActive)
        } else {
            Ok(())
        }
    }
}
impl Default for MacFocusedFieldBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl FocusedFieldBackend for MacFocusedFieldBackend {
    fn global_capability(&self) -> FocusedOutputCapability {
        if self.shutdown.load(Ordering::Acquire) {
            return FocusedOutputCapability::unavailable(
                FocusedOutputBackend::MacOs,
                FocusedOutputReasonCode::BackendDisconnected,
            );
        }
        match Self::preflight() {
            Ok(()) => FocusedOutputCapability::global_ready(FocusedOutputBackend::MacOs),
            Err(e) => FocusedOutputCapability::unavailable(FocusedOutputBackend::MacOs, e),
        }
    }
    fn request_permission(
        &self,
        permission: FocusedOutputPermission,
    ) -> Result<FocusedOutputCapability, FocusedOutputReasonCode> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }
        match permission {
            FocusedOutputPermission::MacAccessibility => request_ax(),
            FocusedOutputPermission::MacInputMonitoring => {
                unsafe { CGRequestListenEventAccess() };
            }
        }
        Ok(self.global_capability())
    }
    fn begin(
        &self,
        context: BeginContext,
        sink: Arc<dyn SessionEventSink>,
        cancellation: SessionCancellation,
    ) -> Result<BeginSession, FocusedOutputReasonCode> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }
        Self::preflight()?;
        if cancellation.is_cancelled() {
            return Err(FocusedOutputReasonCode::Cancelled);
        }
        let guard = parse_guard(context.control_shortcut.as_deref())?;
        let (tx, rx) = mpsc::sync_channel(COMMAND_LEN);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let control = Arc::new(Control {
            tx,
            cancellation: cancellation.clone(),
            closed: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            done: Mutex::new(done_rx),
        });
        let thread_control = control.clone();
        let deadlines = self.deadlines;
        let cancel2 = cancellation.clone();
        let id = context.session_id;
        let join = thread::Builder::new()
            .name("focused-output-macos".into())
            .spawn(move || {
                match Native::capture(
                    id,
                    guard,
                    sink,
                    cancel2,
                    deadlines,
                    context.auto_submit_requested,
                ) {
                    Ok(mut native) => {
                        let info = (native.capability.clone(), native.app_name.clone());
                        if ready_tx.send(Ok(info)).is_ok() {
                            native.run(rx);
                        }
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
                thread_control.finished.store(true, Ordering::Release);
                thread_control.closed.store(true, Ordering::Release);
                let _ = done_tx.try_send(());
            })
            .map_err(|_| FocusedOutputReasonCode::BackendDisconnected)?;
        let (cap, app) = match ready_rx.recv_timeout(self.deadlines.thread_ready) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = join.join();
                return Err(e);
            }
            Err(_) => {
                cancellation.cancel();
                control.close();
                drop(join);
                return Err(FocusedOutputReasonCode::BackendDisconnected);
            }
        };
        let receipt = BeginReceipt::new(id, cap.clone(), app)
            .ok_or(FocusedOutputReasonCode::BackendDisconnected)?;
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::downgrade(&control));
        Ok(BeginSession {
            receipt,
            session: Box::new(MacSession {
                id,
                capability: cap,
                cancellation,
                control,
                join: Some(join),
                deadlines: self.deadlines,
                closed: false,
            }),
        })
    }
    fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        let sessions: Vec<_> = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .filter_map(|v| v.upgrade())
            .collect();
        let end = Instant::now() + self.deadlines.backend_shutdown;
        for v in &sessions {
            v.close()
        }
        for v in sessions {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let _ = v
                .done
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv_timeout(left);
        }
    }
}

struct Control {
    tx: SyncSender<Command>,
    cancellation: SessionCancellation,
    closed: AtomicBool,
    finished: AtomicBool,
    done: Mutex<Receiver<()>>,
}
impl Control {
    fn close(&self) {
        self.cancellation.cancel();
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = self.tx.try_send(Command::Close);
        }
    }
}
struct MacSession {
    id: DictationSessionId,
    capability: FocusedOutputCapability,
    cancellation: SessionCancellation,
    control: Arc<Control>,
    join: Option<JoinHandle<()>>,
    deadlines: PlatformDeadlines,
    closed: bool,
}
impl FocusedTargetSession for MacSession {
    fn capability(&self) -> &FocusedOutputCapability {
        &self.capability
    }
    fn insert_if_valid(&mut self, request: InsertionRequest) -> InsertOutcome {
        if request.session_id != self.id || self.cancellation.is_cancelled() {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        let (tx, rx) = mpsc::sync_channel(1);
        if self
            .control
            .tx
            .try_send(Command::Insert(request, tx))
            .is_err()
        {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::BackendDisconnected,
            };
        }
        rx.recv_timeout(self.deadlines.target_call + self.deadlines.input_effect)
            .unwrap_or(InsertOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::ReceiptTimeout,
            })
    }
    fn submit_if_valid(&mut self, key: AutoSubmitKey) -> SubmitOutcome {
        if !self.capability.supports_auto_submit() {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::AutoSubmitUnsupported,
            };
        }
        let (tx, rx) = mpsc::sync_channel(1);
        if self.control.tx.try_send(Command::Submit(key, tx)).is_err() {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::BackendDisconnected,
            };
        }
        rx.recv_timeout(self.deadlines.target_call)
            .unwrap_or(SubmitOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::ReceiptTimeout,
            })
    }
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.cancellation.cancel();
        self.control.close();
        let complete = self.control.finished.load(Ordering::Acquire)
            || self
                .control
                .done
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv_timeout(self.deadlines.thread_close)
                .is_ok();
        if complete {
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        } else {
            drop(self.join.take());
        }
    }
}
impl Drop for MacSession {
    fn drop(&mut self) {
        self.close()
    }
}
enum Command {
    Insert(InsertionRequest, SyncSender<InsertOutcome>),
    Submit(AutoSubmitKey, SyncSender<SubmitOutcome>),
    Close,
}
struct Identity {
    app: Owned,
    element: Owned,
    window: Owned,
    pid: i32,
    role: String,
    subrole: String,
    identifier: String,
}
struct Subscription {
    observer: Owned,
    source: CFRunLoopSourceRef,
    registrations: Vec<(Box<Registration>, Owned, String)>,
}
struct Tap {
    tap: Owned,
    source: Owned,
    context: *const CallbackState,
}
impl Drop for Subscription {
    fn drop(&mut self) {
        let run_loop = unsafe { CFRunLoopGetCurrent() };
        for (_, element, name) in &self.registrations {
            let name = cfstr(name);
            unsafe {
                AXObserverRemoveNotification(
                    self.observer.0.cast_mut(),
                    element.ax(),
                    name.0.cast(),
                );
            }
        }
        unsafe {
            CFRunLoopRemoveSource(run_loop, self.source, kCFRunLoopDefaultMode);
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, true);
        }
    }
}
impl Drop for Tap {
    fn drop(&mut self) {
        unsafe {
            CGEventTapEnable(self.tap.0.cast_mut(), false);
            CFRunLoopRemoveSource(
                CFRunLoopGetCurrent(),
                self.source.0.cast_mut(),
                kCFRunLoopDefaultMode,
            );
            CFMachPortInvalidate(self.tap.0.cast_mut());
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, true);
            drop(Arc::from_raw(self.context));
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    caret: c_long,
    utf16: usize,
}
enum CgScalarOutcome {
    Observed(Snapshot),
    VerifiedNoReceipt(Snapshot),
    Rejected,
    Ambiguous,
}
fn verified_ax_partial_bytes(
    request: &str,
    before: Snapshot,
    after: Snapshot,
    observed: &str,
) -> Option<usize> {
    let caret_units = after.caret.checked_sub(before.caret)?;
    let value_units = after.utf16.checked_sub(before.utf16)?;
    (caret_units > 0
        && caret_units as usize == value_units
        && !observed.is_empty()
        && observed.len() < request.len()
        && observed.encode_utf16().count() == value_units
        && request.starts_with(observed))
    .then_some(observed.len())
}
struct Native {
    id: DictationSessionId,
    cancellation: SessionCancellation,
    deadlines: PlatformDeadlines,
    identity: Identity,
    route: Route,
    provider: Provider,
    capability: FocusedOutputCapability,
    app_name: Option<String>,
    callback: Arc<CallbackState>,
    subscription: Option<Subscription>,
    tap: Option<Tap>,
    sink: Arc<dyn SessionEventSink>,
    observation: u64,
    invalid: bool,
    last: Snapshot,
    last_injection: u64,
    last_marker: u64,
    pending_external_key: Option<Instant>,
    allowed_external_selection: Option<(Snapshot, Instant)>,
}
impl Native {
    fn capture(
        id: DictationSessionId,
        guard: Option<KeyGuard>,
        sink: Arc<dyn SessionEventSink>,
        cancellation: SessionCancellation,
        deadlines: PlatformDeadlines,
        auto_submit: bool,
    ) -> Result<Self, FocusedOutputReasonCode> {
        if secure_input_enabled() {
            return Err(FocusedOutputReasonCode::SecureInputActive);
        }
        let system = Owned::new(unsafe { AXUIElementCreateSystemWide() }.cast())
            .ok_or(FocusedOutputReasonCode::NoFocusedTarget)?;
        let app = attr(system.ax(), "AXFocusedApplication")
            .map_err(|_| FocusedOutputReasonCode::NoFocusedTarget)?;
        let mut pid = 0;
        if unsafe { AXUIElementGetPid(app.ax(), &mut pid) } != AX_OK || pid <= 0 {
            return Err(FocusedOutputReasonCode::NoFocusedTarget);
        }
        if pid == std::process::id() as i32 {
            return Err(FocusedOutputReasonCode::HandyOwnedTarget);
        }
        let executable =
            process_executable(pid).ok_or(FocusedOutputReasonCode::TargetUnsupported)?;
        if matches!(
            executable.to_ascii_lowercase().as_str(),
            "handy" | "handy.app"
        ) {
            return Err(FocusedOutputReasonCode::HandyOwnedTarget);
        }
        if unsafe { AXUIElementSetMessagingTimeout(app.ax(), deadlines.target_call.as_secs_f32()) }
            != AX_OK
        {
            return Err(FocusedOutputReasonCode::TargetUnsupported);
        }
        let element = attr(system.ax(), "AXFocusedUIElement")
            .map_err(|_| FocusedOutputReasonCode::NoFocusedTarget)?;
        let window = attr(app.ax(), "AXFocusedWindow")
            .map_err(|_| FocusedOutputReasonCode::NoFocusedTarget)?;
        let app_name = Some(executable.clone());
        let role = string_attr(element.ax(), "AXRole")
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if !matches!(role.as_str(), "AXTextField" | "AXTextArea" | "AXComboBox") {
            return Err(FocusedOutputReasonCode::TargetNotEditable);
        }
        let subrole = checked_security_metadata(
            string_attr(element.ax(), "AXSubrole"),
            bool_attr(element.ax(), "AXProtectedContent"),
        )?;
        let identifier = string_attr(element.ax(), "AXIdentifier")
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if identifier.is_empty() {
            return Err(FocusedOutputReasonCode::TargetUnsupported);
        }
        if !bool_attr(element.ax(), "AXEnabled").unwrap_or(false)
            || !bool_attr(element.ax(), "AXEditable").unwrap_or(false)
        {
            return Err(FocusedOutputReasonCode::TargetNotEditable);
        }

        let range = range_attr(element.ax(), "AXSelectedTextRange")
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        if range.location < 0 || range.length != 0 {
            return Err(FocusedOutputReasonCode::InitialSelectionNotCollapsed);
        }
        let value = string_attr(element.ax(), "AXValue")
            .map_err(|_| FocusedOutputReasonCode::TargetUnsupported)?;
        let last = Snapshot {
            caret: range.location,
            utf16: value.encode_utf16().count(),
        };
        let provider = provider(&executable);
        let submit = [
            AutoSubmitKey::Enter,
            AutoSubmitKey::CtrlEnter,
            AutoSubmitKey::CmdEnter,
        ]
        .into_iter()
        .all(|k| submit_supported(provider, &role, k));
        if auto_submit && !submit {
            return Err(FocusedOutputReasonCode::AutoSubmitUnsupported);
        }
        let route = negotiate(
            settable(element.ax(), "AXSelectedText"),
            read_range(element.ax(), range).is_ok(),
        );
        let capability = capability(route, submit);
        let session_marker =
            secure_marker(&[]).ok_or(FocusedOutputReasonCode::MonitorUnavailable)?;
        let callback = Arc::new(CallbackState {
            ring: Ring::new(),
            terminal: AtomicU8::new(0),
            injection: AtomicU64::new(0),
            session_marker,
            active_marker: AtomicU64::new(0),
            active_seen: AtomicU64::new(0),
            guard,
        });
        let identity = Identity {
            app,
            element,
            window,
            pid,
            role,
            subrole,
            identifier,
        };
        let subscription = subscribe(&identity, &callback)?;
        let tap = install_tap(&callback)?;
        Ok(Self {
            id,
            cancellation,
            deadlines,
            identity,
            route,
            provider,
            capability,
            app_name,
            callback,
            subscription: Some(subscription),
            tap: Some(tap),
            sink,
            observation: 0,
            invalid: false,
            last,
            last_injection: 0,
            last_marker: session_marker,
            pending_external_key: None,
            allowed_external_selection: None,
        })
    }
    fn run(&mut self, rx: Receiver<Command>) {
        loop {
            unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, LOOP_SLICE.as_secs_f64(), true) };
            if secure_input_enabled() {
                self.callback.terminal(TERMINAL_TARGET);
            }
            self.drain();
            if self.cancellation.is_cancelled() || self.invalid {
                break;
            }
            match rx.recv_timeout(LOOP_SLICE) {
                Ok(Command::Insert(request, reply)) => {
                    let result = self.insert(request);
                    let terminal = matches!(
                        result,
                        InsertOutcome::Partial { .. } | InsertOutcome::Ambiguous { .. }
                    );
                    let _ = reply.try_send(result);
                    self.invalid |= terminal;
                }
                Ok(Command::Submit(key, reply)) => {
                    let result = self.submit(key);
                    self.invalid |= matches!(
                        result,
                        SubmitOutcome::Complete { .. } | SubmitOutcome::Ambiguous { .. }
                    );
                    let _ = reply.try_send(result);
                }
                Ok(Command::Close) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
        self.teardown();
    }
    fn validate(&self) -> Result<Snapshot, FocusedOutputReasonCode> {
        if self.cancellation.is_cancelled() {
            return Err(FocusedOutputReasonCode::Cancelled);
        }
        if secure_input_enabled() {
            return Err(FocusedOutputReasonCode::SecureInputActive);
        }
        if self.callback.terminal.load(Ordering::Acquire) != 0 {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        if self
            .tap
            .as_ref()
            .is_none_or(|v| !unsafe { CGEventTapIsEnabled(v.tap.0.cast_mut()) })
        {
            return Err(FocusedOutputReasonCode::MonitorUnavailable);
        }
        let system = Owned::new(unsafe { AXUIElementCreateSystemWide() }.cast())
            .ok_or(FocusedOutputReasonCode::TargetChanged)?;
        let app = attr(system.ax(), "AXFocusedApplication")
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        let element = attr(system.ax(), "AXFocusedUIElement")
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        let window = attr(app.ax(), "AXFocusedWindow")
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        let mut pid = 0;
        if unsafe { AXUIElementGetPid(app.ax(), &mut pid) } != AX_OK
            || pid != self.identity.pid
            || !unsafe { CFEqual(app.0, self.identity.app.0) }
            || !unsafe { CFEqual(element.0, self.identity.element.0) }
            || !unsafe { CFEqual(window.0, self.identity.window.0) }
        {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let role = string_attr(element.ax(), "AXRole")
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        let subrole = checked_security_metadata(
            string_attr(element.ax(), "AXSubrole"),
            bool_attr(element.ax(), "AXProtectedContent"),
        )?;
        if role != self.identity.role
            || subrole != self.identity.subrole
            || string_attr(element.ax(), "AXIdentifier")
                .map_err(|_| FocusedOutputReasonCode::TargetChanged)?
                != self.identity.identifier
        {
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        if !bool_attr(element.ax(), "AXEditable").unwrap_or(false) {
            return Err(FocusedOutputReasonCode::TargetNotEditable);
        }
        let range = range_attr(element.ax(), "AXSelectedTextRange")
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        if range.length != 0 {
            return Err(FocusedOutputReasonCode::SelectionChanged);
        }
        let value = string_attr(element.ax(), "AXValue")
            .map_err(|_| FocusedOutputReasonCode::TargetChanged)?;
        Ok(Snapshot {
            caret: range.location,
            utf16: value.encode_utf16().count(),
        })
    }
    fn insert(&mut self, request: InsertionRequest) -> InsertOutcome {
        if request.session_id != self.id {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        if self.pending_external_key.is_some() {
            return InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetChanged,
            };
        }
        self.allowed_external_selection = None;
        let before = match self.validate() {
            Ok(v) => v,
            Err(e) => return InsertOutcome::Rejected { reason: e },
        };
        let injection = request.injection_id;
        let (mut result, verified_after) = if self.route == Route::Ax {
            self.ax_insert(&request, before)
        } else {
            self.cg_insert(&request, before)
        };
        if matches!(result, InsertOutcome::Complete { .. }) {
            match verified_after {
                Some(after) => {
                    self.last = after;
                    if self.callback.terminal.load(Ordering::Acquire) == TERMINAL_NONE {
                        self.publish_handy(injection, after.caret as i64);
                    }
                }
                None => {
                    result = InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    };
                }
            }
        }
        self.callback.active_marker.store(0, Ordering::Release);
        self.callback.injection.store(0, Ordering::Release);
        result
    }
    fn fresh_secret(&mut self, extra_exclusion: u64) -> Option<u64> {
        let secret = secure_marker(&[
            self.callback.session_marker,
            self.last_marker,
            extra_exclusion,
        ])?;
        self.last_marker = secret;
        Some(secret)
    }
    fn ax_insert(
        &mut self,
        request: &InsertionRequest,
        before: Snapshot,
    ) -> (InsertOutcome, Option<Snapshot>) {
        if self.cancellation.is_cancelled() {
            return (
                InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::Cancelled,
                },
                None,
            );
        }
        let Some(text) = string_bytes(request.text.as_bytes()) else {
            return (
                InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::InjectionFailed,
                },
                None,
            );
        };
        let Some(correlation) = self.fresh_secret(0) else {
            return (
                InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::InjectionFailed,
                },
                None,
            );
        };
        self.callback
            .injection
            .store(correlation, Ordering::Release);
        let outcome = self.ax_insert_tagged(request, before, &text, correlation);
        self.callback.injection.store(0, Ordering::Release);
        outcome
    }
    fn ax_insert_tagged(
        &mut self,
        request: &InsertionRequest,
        before: Snapshot,
        text: &Owned,
        correlation: u64,
    ) -> (InsertOutcome, Option<Snapshot>) {
        let name = cfstr("AXSelectedText");
        let error = unsafe {
            AXUIElementSetAttributeValue(self.identity.element.ax(), name.0.cast(), text.0)
        };
        if error != AX_OK {
            return (classify_ax(&request.text, Some(error), None), None);
        }
        let expected: Vec<_> = request.text.encode_utf16().collect();
        let range = CFRange {
            location: before.caret,
            length: expected.len() as c_long,
        };
        let result = match read_range(self.identity.element.ax(), range) {
            Ok(value) => classify_ax(&request.text, None, Some(&value)),
            Err(_) => classify_ax(&request.text, None, None),
        };
        if !matches!(result, InsertOutcome::Complete { .. }) {
            return self
                .verified_ax_partial(before, &request.text)
                .unwrap_or((result, None));
        }
        let Some(after) = self.matches_change(before, &expected) else {
            return (
                InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                },
                None,
            );
        };
        let end = Instant::now() + self.deadlines.handy_receipt;
        let mut value_count = 0u8;
        let mut selection_count = 0u8;
        let mut matched_at = None;
        loop {
            let run_status = unsafe {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, LOOP_SLICE.as_secs_f64(), true)
            };
            let (valid, values, selections) = self.drain_injection_callbacks(
                correlation,
                before,
                &expected,
                matched_at.is_some(),
            );
            value_count = value_count.saturating_add(values);
            selection_count = selection_count.saturating_add(selections);
            if !valid || value_count > 1 || selection_count > 1 {
                self.callback.terminal(TERMINAL_TARGET);
                return (
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    },
                    None,
                );
            }
            let now = Instant::now();
            if value_count == 1 {
                if matched_at.is_none() {
                    matched_at = Some(now);
                    self.callback.injection.store(0, Ordering::Release);
                }
                let matched = matched_at.expect("set above");
                if now >= matched + DUPLICATE_GUARD && run_status != CF_RUN_LOOP_HANDLED_SOURCE {
                    return (result, Some(after));
                }
                if now >= matched + self.deadlines.handy_receipt {
                    self.callback.terminal(TERMINAL_MONITOR);
                    return (
                        InsertOutcome::Ambiguous {
                            reason: FocusedOutputReasonCode::MonitorUnavailable,
                        },
                        None,
                    );
                }
            } else if now >= end {
                self.callback.terminal(TERMINAL_MONITOR);
                return (
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::MonitorUnavailable,
                    },
                    None,
                );
            }
            if self.cancellation.is_cancelled() {
                self.callback.terminal(TERMINAL_TARGET);
                return (
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    },
                    None,
                );
            }
        }
    }
    fn verified_ax_partial(
        &self,
        before: Snapshot,
        request: &str,
    ) -> Option<(InsertOutcome, Option<Snapshot>)> {
        let after = self.validate().ok()?;
        let caret_units = after.caret.checked_sub(before.caret)?;
        if caret_units <= 0 {
            return None;
        }
        let range = CFRange {
            location: before.caret,
            length: caret_units,
        };
        let observed = read_range(self.identity.element.ax(), range).ok()?;
        let accepted_bytes = verified_ax_partial_bytes(request, before, after, &observed)?;
        Some((
            InsertOutcome::Partial {
                accepted_bytes,
                receipt: ReceiptConfidence::Verified,
                reason: FocusedOutputReasonCode::InjectionPartial,
            },
            Some(after),
        ))
    }
    fn cg_insert(
        &mut self,
        request: &InsertionRequest,
        mut before: Snapshot,
    ) -> (InsertOutcome, Option<Snapshot>) {
        let mut accepted_bytes = 0;
        for (unit, len, utf8_len) in scalars(&request.text) {
            if self.cancellation.is_cancelled() {
                return if accepted_bytes > 0 {
                    (
                        verified_cg_prefix(request.text.len(), accepted_bytes),
                        Some(before),
                    )
                } else {
                    (
                        InsertOutcome::Rejected {
                            reason: FocusedOutputReasonCode::Cancelled,
                        },
                        None,
                    )
                };
            }
            match self.validate() {
                Ok(v) if v == before => {}
                Ok(_) | Err(_) if accepted_bytes > 0 => {
                    self.callback.terminal(TERMINAL_TARGET);
                    return (
                        verified_cg_prefix(request.text.len(), accepted_bytes),
                        Some(before),
                    );
                }
                Ok(_) => {
                    return (
                        InsertOutcome::Rejected {
                            reason: FocusedOutputReasonCode::TargetChanged,
                        },
                        None,
                    );
                }
                Err(e) => return (InsertOutcome::Rejected { reason: e }, None),
            }
            match self.cg_scalar(before, &unit[..len]) {
                CgScalarOutcome::Observed(after) => {
                    accepted_bytes += utf8_len;
                    before = after;
                }
                CgScalarOutcome::VerifiedNoReceipt(after) => {
                    accepted_bytes += utf8_len;
                    return (
                        verified_cg_prefix(request.text.len(), accepted_bytes),
                        Some(after),
                    );
                }
                CgScalarOutcome::Rejected if accepted_bytes > 0 => {
                    return (
                        verified_cg_prefix(request.text.len(), accepted_bytes),
                        Some(before),
                    );
                }
                CgScalarOutcome::Rejected => {
                    return (
                        InsertOutcome::Rejected {
                            reason: FocusedOutputReasonCode::InjectionFailed,
                        },
                        None,
                    );
                }
                CgScalarOutcome::Ambiguous => {
                    return (
                        InsertOutcome::Ambiguous {
                            reason: FocusedOutputReasonCode::InjectionAmbiguous,
                        },
                        None,
                    );
                }
            }
        }
        (
            InsertOutcome::Complete {
                receipt: ReceiptConfidence::Posted,
            },
            Some(before),
        )
    }
    fn cg_scalar(&mut self, before: Snapshot, expected: &[u16]) -> CgScalarOutcome {
        if self.callback.ring.pop().is_some() {
            self.callback.terminal(TERMINAL_TARGET);
            return CgScalarOutcome::Ambiguous;
        }
        let Some(correlation) = self.fresh_secret(0) else {
            return CgScalarOutcome::Rejected;
        };
        let Some(marker) = self.fresh_secret(correlation) else {
            return CgScalarOutcome::Rejected;
        };
        self.callback
            .injection
            .store(correlation, Ordering::Release);
        self.callback.active_seen.store(0, Ordering::Release);
        self.callback.active_marker.store(marker, Ordering::Release);
        let mut outcome = CgScalarOutcome::Rejected;
        if post_scalar(
            &[expected[0], expected.get(1).copied().unwrap_or(0)],
            expected.len(),
            marker,
        ) {
            let effect_deadline = Instant::now() + self.deadlines.input_effect;
            let receipt_deadline = Instant::now() + self.deadlines.handy_receipt;
            let mut exact_after = None;
            let mut value_count = 0u8;
            let mut selection_count = 0u8;
            let mut matched_at = None;
            loop {
                let run_status = unsafe {
                    CFRunLoopRunInMode(kCFRunLoopDefaultMode, LOOP_SLICE.as_secs_f64(), true)
                };
                let (valid, values, selections) = self.drain_injection_callbacks(
                    correlation,
                    before,
                    expected,
                    matched_at.is_some(),
                );
                value_count = value_count.saturating_add(values);
                selection_count = selection_count.saturating_add(selections);
                if !valid || value_count > 1 || selection_count > 1 {
                    self.callback.terminal(TERMINAL_TARGET);
                    outcome = CgScalarOutcome::Ambiguous;
                    break;
                }
                if exact_after.is_none() {
                    exact_after = self.matches_change(before, expected);
                }
                let marker_seen = self.callback.active_seen.load(Ordering::Acquire) == marker;
                if let Some(after) = exact_after {
                    let now = Instant::now();
                    if value_count == 1 && marker_seen {
                        if matched_at.is_none() {
                            matched_at = Some(now);
                            self.callback.injection.store(0, Ordering::Release);
                        }
                        let matched = matched_at.expect("set above");
                        if now >= matched + DUPLICATE_GUARD
                            && run_status != CF_RUN_LOOP_HANDLED_SOURCE
                        {
                            outcome = CgScalarOutcome::Observed(after);
                            break;
                        }
                        if now >= matched + self.deadlines.handy_receipt {
                            self.callback.terminal(TERMINAL_MONITOR);
                            outcome = CgScalarOutcome::VerifiedNoReceipt(after);
                            break;
                        }
                    } else if self.cancellation.is_cancelled() || now >= receipt_deadline {
                        if marker_seen {
                            self.callback.terminal(if self.cancellation.is_cancelled() {
                                TERMINAL_TARGET
                            } else {
                                TERMINAL_MONITOR
                            });
                            outcome = CgScalarOutcome::VerifiedNoReceipt(after);
                        } else {
                            self.callback.terminal(TERMINAL_MONITOR);
                            outcome = CgScalarOutcome::Ambiguous;
                        }
                        break;
                    }
                } else if self.cancellation.is_cancelled() || Instant::now() >= effect_deadline {
                    outcome = CgScalarOutcome::Ambiguous;
                    break;
                }
            }
        }
        self.callback.active_marker.store(0, Ordering::Release);
        self.callback.injection.store(0, Ordering::Release);
        outcome
    }
    fn submit(&mut self, key: AutoSubmitKey) -> SubmitOutcome {
        if !submit_supported(self.provider, &self.identity.role, key) {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::AutoSubmitUnsupported,
            };
        }
        if self.pending_external_key.is_some() {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetChanged,
            };
        }
        if let Err(e) = self.validate() {
            return SubmitOutcome::Rejected { reason: e };
        }
        let Some(marker) = secure_marker(&[self.callback.session_marker, self.last_marker]) else {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::InjectionFailed,
            };
        };
        self.last_marker = marker;
        self.callback.active_seen.store(0, Ordering::Release);
        self.callback.active_marker.store(marker, Ordering::Release);
        let posted = post_key(key, marker);
        let observed = posted
            && self.wait_for_marker(
                marker,
                self.deadlines.target_call.saturating_sub(LOOP_SLICE),
            );
        self.callback.active_marker.store(0, Ordering::Release);
        if observed {
            SubmitOutcome::Complete {
                receipt: ReceiptConfidence::Posted,
            }
        } else if posted {
            SubmitOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::MonitorUnavailable,
            }
        } else {
            SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::InjectionFailed,
            }
        }
    }
    fn drain(&mut self) {
        let terminal = self.callback.terminal.load(Ordering::Acquire);
        if terminal != 0 && !self.invalid {
            self.invalid = true;
            self.observation += 1;
            let event = if terminal == TERMINAL_MONITOR {
                TargetInteractionEvent::MonitorUnavailable {
                    observation_id: ObservationId(self.observation),
                }
            } else {
                TargetInteractionEvent::TargetInvalidated {
                    observation_id: ObservationId(self.observation),
                    reason: if secure_input_enabled() {
                        FocusedOutputReasonCode::SecureInputActive
                    } else if terminal == TERMINAL_POINTER {
                        FocusedOutputReasonCode::PhysicalPointerActivity
                    } else {
                        FocusedOutputReasonCode::TargetChanged
                    },
                }
            };
            self.sink.publish(self.id, event);
        }
        while let Some((kind, data)) = self.callback.ring.pop() {
            match kind {
                EVENT_KEY if data == KEY_INTENT_PRINTABLE => {
                    if self.pending_external_key.is_some() {
                        self.publish_unsafe(UnsafeEditKind::ImeComposition);
                    } else {
                        self.pending_external_key =
                            Some(Instant::now() + self.deadlines.input_effect);
                    }
                }
                EVENT_KEY => self.publish_unsafe(key_intent_kind(data)),
                EVENT_VALUE if data == 0 && self.pending_external_key.take().is_some() => {
                    self.classify_external();
                }
                EVENT_VALUE => self.publish_unsafe(UnsafeEditKind::Unknown),
                EVENT_SELECTION if data == 0 && self.pending_external_key.is_some() => {}
                EVENT_SELECTION if data == 0 => {
                    let allowed =
                        self.allowed_external_selection
                            .take()
                            .is_some_and(|(expected, until)| {
                                Instant::now() <= until && self.validate().ok() == Some(expected)
                            });
                    if !allowed {
                        self.publish_unsafe(UnsafeEditKind::SelectionChanged);
                    }
                }
                EVENT_TARGET_LOST | EVENT_POINTER | EVENT_TAP_LOST => {}
                _ => self.publish_unsafe(UnsafeEditKind::Unknown),
            }
        }
        if self
            .pending_external_key
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.pending_external_key = None;
            self.publish_unsafe(UnsafeEditKind::Unknown);
        }
        if self
            .allowed_external_selection
            .is_some_and(|(_, deadline)| Instant::now() >= deadline)
        {
            self.allowed_external_selection = None;
        }
    }
    fn publish_unsafe(&mut self, kind: UnsafeEditKind) {
        if self.invalid {
            return;
        }
        self.observation += 1;
        self.sink.publish(
            self.id,
            TargetInteractionEvent::UnsafeEdit {
                observation_id: ObservationId(self.observation),
                kind,
            },
        );
        self.invalid = true;
    }
    fn publish_handy(&mut self, injection: InjectionId, caret: i64) {
        if injection.0 == 0 || self.last_injection == injection.0 {
            return;
        }
        self.last_injection = injection.0;
        self.sink.publish(
            self.id,
            TargetInteractionEvent::HandyInsertionObserved {
                injection_id: injection,
                caret_after: Some(caret),
            },
        );
    }
    fn matches_change(&self, before: Snapshot, expected: &[u16]) -> Option<Snapshot> {
        let after = self.validate().ok()?;
        if after.caret != before.caret + expected.len() as c_long
            || after.utf16 != before.utf16 + expected.len()
        {
            return None;
        }
        let range = CFRange {
            location: before.caret,
            length: expected.len() as c_long,
        };
        let observed = read_range(self.identity.element.ax(), range).ok()?;
        observed
            .encode_utf16()
            .eq(expected.iter().copied())
            .then_some(after)
    }
    fn drain_injection_callbacks(
        &self,
        correlation: u64,
        before: Snapshot,
        expected: &[u16],
        allow_zero_selection: bool,
    ) -> (bool, u8, u8) {
        let mut valid = true;
        let mut values = 0u8;
        let mut selections = 0u8;
        while let Some((kind, data)) = self.callback.ring.pop() {
            let tag_matches = data == correlation
                || (allow_zero_selection && kind == EVENT_SELECTION && data == 0);
            if !matches!(kind, EVENT_VALUE | EVENT_SELECTION)
                || !tag_matches
                || self.matches_change(before, expected).is_none()
            {
                valid = false;
            } else if kind == EVENT_VALUE {
                values = values.saturating_add(1);
            } else {
                selections = selections.saturating_add(1);
            }
        }
        if !valid {
            self.callback.terminal(TERMINAL_TARGET);
        }
        (valid, values, selections)
    }
    // A printable key is only provisionally compatible. The following target-bound
    // value growth must be a single collapsed-caret insertion; a residual selection
    // notification is accepted only while it reads back that same exact snapshot.
    fn classify_external(&mut self) {
        let Ok(after) = self.validate() else {
            self.publish_unsafe(UnsafeEditKind::Unknown);
            return;
        };
        self.observation += 1;
        if after.caret > self.last.caret
            && after.utf16 > self.last.utf16
            && (after.caret - self.last.caret) as usize == after.utf16 - self.last.utf16
        {
            self.sink.publish(
                self.id,
                TargetInteractionEvent::CompatibleExternalInsertion {
                    observation_id: ObservationId(self.observation),
                    chars: after.utf16 - self.last.utf16,
                    caret_after: Some(after.caret as i64),
                },
            );
            self.last = after;
            self.allowed_external_selection =
                Some((after, Instant::now() + self.deadlines.input_effect));
        } else {
            self.sink.publish(
                self.id,
                TargetInteractionEvent::UnsafeEdit {
                    observation_id: ObservationId(self.observation),
                    kind: UnsafeEditKind::Unknown,
                },
            );
            self.invalid = true;
        }
    }
    fn wait_for_marker(&self, marker: u64, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        loop {
            if self.callback.active_seen.load(Ordering::Acquire) == marker {
                return self.callback.terminal.load(Ordering::Acquire) == TERMINAL_NONE;
            }
            if self.cancellation.is_cancelled() || Instant::now() >= end {
                return false;
            }
            unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, LOOP_SLICE.as_secs_f64(), true) };
        }
    }
    fn teardown(&mut self) {
        self.cancellation.cancel();
        drop(self.subscription.take());
        self.callback.active_marker.store(0, Ordering::Release);
        self.callback.injection.store(0, Ordering::Release);
        drop(self.tap.take());
    }
}

fn request_ax() {
    let key = cfstr("AXTrustedCheckOptionPrompt");
    let keys = [key.0];
    let values = [unsafe { kCFBooleanTrue }];
    let dictionary = unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            ptr::null(),
            ptr::null(),
        )
    };
    if !dictionary.is_null() {
        unsafe {
            AXIsProcessTrustedWithOptions(dictionary);
            CFRelease(dictionary)
        };
    }
}
fn cfstr(value: &str) -> Owned {
    let value = CString::new(value).expect("static AX name");
    Owned::new(unsafe { CFStringCreateWithCString(ptr::null(), value.as_ptr(), UTF8) })
        .expect("CFString")
}
fn string_bytes(value: &[u8]) -> Option<Owned> {
    Owned::new(unsafe {
        CFStringCreateWithBytes(
            ptr::null(),
            value.as_ptr(),
            value.len() as c_long,
            UTF8,
            false,
        )
    })
}
fn attr(element: AXUIElementRef, name: &str) -> Result<Owned, i32> {
    let name = cfstr(name);
    let mut value = ptr::null();
    let error = unsafe { AXUIElementCopyAttributeValue(element, name.0.cast(), &mut value) };
    if error == AX_OK {
        Owned::new(value).ok_or(AX_CANNOT_COMPLETE)
    } else {
        Err(error)
    }
}
fn string_attr(element: AXUIElementRef, name: &str) -> Result<String, i32> {
    to_string(attr(element, name)?.0).ok_or(AX_CANNOT_COMPLETE)
}
fn to_string(value: CFTypeRef) -> Option<String> {
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return None;
    }
    let len = unsafe { CFStringGetLength(value.cast()) };
    let size = unsafe { CFStringGetMaximumSizeForEncoding(len, UTF8) } + 1;
    if size <= 0 {
        return None;
    }
    let mut bytes = vec![0; size as usize];
    if !unsafe { CFStringGetCString(value.cast(), bytes.as_mut_ptr().cast(), size, UTF8) } {
        return None;
    }
    bytes.truncate(bytes.iter().position(|v| *v == 0)?);
    String::from_utf8(bytes).ok()
}
fn bool_attr(element: AXUIElementRef, name: &str) -> Result<bool, i32> {
    let value = attr(element, name)?;
    if unsafe { CFGetTypeID(value.0) } != unsafe { CFBooleanGetTypeID() } {
        Err(AX_CANNOT_COMPLETE)
    } else {
        Ok(unsafe { CFBooleanGetValue(value.0) })
    }
}
fn range_attr(element: AXUIElementRef, name: &str) -> Result<CFRange, i32> {
    let value = attr(element, name)?;
    let mut range = CFRange {
        location: -1,
        length: -1,
    };
    if unsafe { AXValueGetValue(value.0, AX_CF_RANGE, (&mut range as *mut CFRange).cast()) } {
        Ok(range)
    } else {
        Err(AX_CANNOT_COMPLETE)
    }
}
fn settable(element: AXUIElementRef, name: &str) -> bool {
    let name = cfstr(name);
    let mut value = false;
    unsafe { AXUIElementIsAttributeSettable(element, name.0.cast(), &mut value) == AX_OK && value }
}
fn read_range(element: AXUIElementRef, range: CFRange) -> Result<String, i32> {
    let parameter =
        Owned::new(unsafe { AXValueCreate(AX_CF_RANGE, (&range as *const CFRange).cast()) })
            .ok_or(AX_CANNOT_COMPLETE)?;
    let name = cfstr("AXStringForRange");
    let mut value = ptr::null();
    let error = unsafe {
        AXUIElementCopyParameterizedAttributeValue(element, name.0.cast(), parameter.0, &mut value)
    };
    if error != AX_OK {
        return Err(error);
    }
    let value = Owned::new(value).ok_or(AX_CANNOT_COMPLETE)?;
    to_string(value.0).ok_or(AX_CANNOT_COMPLETE)
}
fn sanitize(value: &str) -> Option<String> {
    let value: String = value
        .chars()
        .filter(|v| !v.is_control())
        .take(128)
        .collect();
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}
fn process_executable(pid: i32) -> Option<String> {
    let mut buffer = [0u8; PROC_PIDPATHINFO_MAXSIZE];
    let len = unsafe {
        proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };
    if len <= 0 || len as usize > buffer.len() {
        return None;
    }
    let bytes = &buffer[..len as usize];
    let end = bytes
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(bytes.len());
    let path = std::str::from_utf8(&bytes[..end]).ok()?;
    let executable = Path::new(path).file_name()?.to_str()?;
    sanitize(executable)
}
fn secure_marker(excluded: &[u64]) -> Option<u64> {
    for _ in 0..4 {
        let mut marker = 0u64;
        if unsafe {
            SecRandomCopyBytes(
                kSecRandomDefault,
                std::mem::size_of::<u64>(),
                (&mut marker as *mut u64).cast(),
            )
        } == AX_OK
            && marker != 0
            && !excluded.contains(&marker)
        {
            return Some(marker);
        }
    }
    None
}
fn subscribe(
    identity: &Identity,
    state: &Arc<CallbackState>,
) -> Result<Subscription, FocusedOutputReasonCode> {
    let mut observer = ptr::null_mut();
    if unsafe { AXObserverCreate(identity.pid, ax_callback, &mut observer) } != AX_OK {
        return Err(FocusedOutputReasonCode::MonitorUnavailable);
    }
    let observer =
        Owned::new(observer.cast()).ok_or(FocusedOutputReasonCode::MonitorUnavailable)?;
    let source = unsafe { AXObserverGetRunLoopSource(observer.0.cast_mut()) };
    if source.is_null() {
        return Err(FocusedOutputReasonCode::MonitorUnavailable);
    }
    unsafe { CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode) };
    let mut result = Subscription {
        observer,
        source,
        registrations: Vec::with_capacity(4),
    };
    for (element, name, kind) in [
        (&identity.element, "AXValueChanged", EVENT_VALUE),
        (&identity.element, "AXSelectedTextChanged", EVENT_SELECTION),
        (
            &identity.app,
            "AXFocusedUIElementChanged",
            EVENT_TARGET_LOST,
        ),
        (&identity.element, "AXUIElementDestroyed", EVENT_TARGET_LOST),
    ] {
        let mut registration = Box::new(Registration::new(state, kind));
        let notification = cfstr(name);
        if unsafe {
            AXObserverAddNotification(
                result.observer.0.cast_mut(),
                element.ax(),
                notification.0.cast(),
                (&mut *registration as *mut Registration).cast(),
            )
        } != AX_OK
        {
            unsafe { CFRunLoopRemoveSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode) };
            return Err(FocusedOutputReasonCode::MonitorUnavailable);
        }
        result
            .registrations
            .push((registration, element.clone(), name.to_owned()));
    }
    Ok(result)
}
fn install_tap(state: &Arc<CallbackState>) -> Result<Tap, FocusedOutputReasonCode> {
    let mask = [
        LEFT_DOWN,
        RIGHT_DOWN,
        LEFT_UP,
        MOUSE_MOVED,
        RIGHT_UP,
        LEFT_DRAGGED,
        RIGHT_DRAGGED,
        SCROLL_WHEEL,
        TABLET_POINTER,
        TABLET_PROXIMITY,
        OTHER_DOWN,
        OTHER_DRAGGED,
        OTHER_UP,
        KEY_DOWN,
        FLAGS_CHANGED,
    ]
    .into_iter()
    .fold(0, |a, v| a | 1u64 << v);
    let context = Arc::into_raw(state.clone());
    let tap = unsafe { CGEventTapCreate(1, 0, 1, mask, tap_callback, context.cast_mut().cast()) };
    let Some(tap) = Owned::new(tap.cast()) else {
        unsafe { drop(Arc::from_raw(context)) };
        return Err(FocusedOutputReasonCode::MonitorUnavailable);
    };
    let source = unsafe { CFMachPortCreateRunLoopSource(ptr::null(), tap.0.cast_mut(), 0) };
    let Some(source) = Owned::new(source.cast()) else {
        unsafe { drop(Arc::from_raw(context)) };
        return Err(FocusedOutputReasonCode::MonitorUnavailable);
    };
    unsafe {
        CFRunLoopAddSource(
            CFRunLoopGetCurrent(),
            source.0.cast_mut(),
            kCFRunLoopDefaultMode,
        );
        CGEventTapEnable(tap.0.cast_mut(), true)
    };
    if !unsafe { CGEventTapIsEnabled(tap.0.cast_mut()) } {
        unsafe {
            CFRunLoopRemoveSource(
                CFRunLoopGetCurrent(),
                source.0.cast_mut(),
                kCFRunLoopDefaultMode,
            );
            drop(Arc::from_raw(context))
        };
        return Err(FocusedOutputReasonCode::MonitorUnavailable);
    }
    Ok(Tap {
        tap,
        source,
        context,
    })
}
fn events(key: u16, flags: u64, marker: u64) -> Option<(Owned, Owned)> {
    let source = Owned::new(unsafe { CGEventSourceCreate(0) })?;
    let down = Owned::new(unsafe { CGEventCreateKeyboardEvent(source.0, key, true) }.cast())?;
    let up = Owned::new(unsafe { CGEventCreateKeyboardEvent(source.0, key, false) }.cast())?;
    unsafe {
        CGEventSetFlags(down.0.cast_mut(), flags);
        CGEventSetFlags(up.0.cast_mut(), flags);
        CGEventSetIntegerValueField(down.0.cast_mut(), EVENT_USER_DATA, marker as i64);
        CGEventSetIntegerValueField(up.0.cast_mut(), EVENT_USER_DATA, marker as i64);
    }
    Some((down, up))
}
fn post_scalar(unit: &[u16; 2], len: usize, marker: u64) -> bool {
    let Some((down, up)) = events(0, 0, marker) else {
        return false;
    };
    unsafe {
        CGEventKeyboardSetUnicodeString(down.0.cast_mut(), len, unit.as_ptr());
        CGEventKeyboardSetUnicodeString(up.0.cast_mut(), len, unit.as_ptr());
        CGEventPost(0, down.0.cast_mut());
        CGEventPost(0, up.0.cast_mut());
    }
    true
}
fn post_key(key: AutoSubmitKey, marker: u64) -> bool {
    let flags = match key {
        AutoSubmitKey::Enter => 0,
        AutoSubmitKey::CtrlEnter => FLAG_CONTROL,
        AutoSubmitKey::CmdEnter => FLAG_COMMAND,
    };
    let Some((down, up)) = events(RETURN_KEY, flags, marker) else {
        return false;
    };
    unsafe {
        CGEventPost(0, down.0.cast_mut());
        CGEventPost(0, up.0.cast_mut());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_negotiation_is_pinned() {
        assert_eq!(negotiate(true, true), Route::Ax);
        assert_eq!(negotiate(true, false), Route::Cg);
        assert_eq!(negotiate(false, true), Route::Cg);
        assert_eq!(
            capability(Route::Ax, true)
                .route()
                .unwrap()
                .receipt_confidence,
            ReceiptConfidence::Verified
        );
    }
    #[test]
    fn ax_classification_is_strict() {
        assert_eq!(
            classify_ax("hé", None, Some("hé")),
            InsertOutcome::Complete {
                receipt: ReceiptConfidence::Verified
            }
        );
        assert!(matches!(
            classify_ax("héllo", None, Some("hé")),
            InsertOutcome::Ambiguous { .. }
        ));
        assert!(matches!(
            classify_ax("abc", None, Some("axc")),
            InsertOutcome::Ambiguous { .. }
        ));
        assert!(matches!(
            classify_ax("abc", None, None),
            InsertOutcome::Ambiguous { .. }
        ));
        assert!(matches!(
            classify_ax("abc", Some(AX_CANNOT_COMPLETE), None),
            InsertOutcome::Ambiguous { .. }
        ));
        let before = Snapshot {
            caret: 4,
            utf16: 10,
        };
        let after = Snapshot {
            caret: 5,
            utf16: 11,
        };
        assert_eq!(
            verified_ax_partial_bytes("abcd", before, after, "a"),
            Some(1)
        );
        assert_eq!(
            verified_ax_partial_bytes("abcd", before, after, "abc"),
            None
        );
        assert!(pointer_event(OTHER_DOWN));
        assert!(pointer_event(SCROLL_WHEEL));
    }
    #[test]
    fn unicode_dispatch_is_scalar_guarded() {
        let units: Vec<_> = scalars("a😀é").collect();
        assert_eq!(units.len(), 3);
        assert_eq!([units[0].1, units[1].1, units[2].1], [1, 2, 1]);
        assert_eq!([units[0].2, units[1].2, units[2].2], [1, 4, 2]);
        assert!(matches!(
            verified_cg_prefix("éx".len(), "é".len()),
            InsertOutcome::Partial {
                accepted_bytes: 2,
                receipt: ReceiptConfidence::Verified,
                ..
            }
        ));
        assert_eq!(
            verified_cg_prefix("éx".len(), "éx".len()),
            InsertOutcome::Complete {
                receipt: ReceiptConfidence::Verified
            }
        );
    }
    #[test]
    fn secure_and_selection_checks_reject() {
        fn check(
            secure: bool,
            protected: bool,
            same: bool,
            range: CFRange,
        ) -> Result<(), FocusedOutputReasonCode> {
            if secure {
                Err(FocusedOutputReasonCode::SecureInputActive)
            } else if protected {
                Err(FocusedOutputReasonCode::SecureField)
            } else if !same {
                Err(FocusedOutputReasonCode::TargetChanged)
            } else if range.length != 0 {
                Err(FocusedOutputReasonCode::SelectionChanged)
            } else {
                Ok(())
            }
        }
        let r = CFRange {
            location: 2,
            length: 0,
        };
        assert_eq!(check(false, false, true, r), Ok(()));
        assert_eq!(
            check(true, false, true, r),
            Err(FocusedOutputReasonCode::SecureInputActive)
        );
        assert_eq!(
            check(false, true, true, r),
            Err(FocusedOutputReasonCode::SecureField)
        );
        assert_eq!(
            check(false, false, false, r),
            Err(FocusedOutputReasonCode::TargetChanged)
        );
    }
    #[test]
    fn security_metadata_fails_closed() {
        assert_eq!(
            checked_security_metadata(Err(AX_CANNOT_COMPLETE), Ok(false)),
            Err(FocusedOutputReasonCode::SecureField)
        );
        assert_eq!(
            checked_security_metadata(Ok("AXStandard".into()), Err(AX_CANNOT_COMPLETE)),
            Err(FocusedOutputReasonCode::SecureField)
        );
        assert_eq!(
            checked_security_metadata(Ok("AXSecureTextField".into()), Ok(false)),
            Err(FocusedOutputReasonCode::SecureField)
        );
        assert_eq!(
            checked_security_metadata(Ok("AXStandard".into()), Ok(false)),
            Ok("AXStandard".into())
        );
    }
    #[test]
    fn callback_context_lives_until_teardown() {
        let state = Arc::new(CallbackState {
            ring: Ring::new(),
            terminal: AtomicU8::new(0),
            injection: AtomicU64::new(0),
            session_marker: 11,
            active_marker: AtomicU64::new(0),
            active_seen: AtomicU64::new(0),
            guard: None,
        });
        let weak = Arc::downgrade(&state);
        let registration = Registration::new(&state, EVENT_VALUE);
        drop(state);
        assert!(weak.upgrade().is_some());
        drop(registration);
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn callback_queue_is_bounded() {
        let ring = Ring::new();
        for i in 0..QUEUE_LEN as u64 {
            assert!(ring.push(EVENT_VALUE, u64::MAX - i));
        }
        assert!(!ring.push(EVENT_VALUE, 99));
        for i in 0..QUEUE_LEN as u64 {
            assert_eq!(ring.pop(), Some((EVENT_VALUE, u64::MAX - i)));
        }
    }
    #[test]
    fn submit_support_is_single_line_and_provider_bound() {
        for (app, expected) in [
            ("Notes", Provider::AppKit),
            ("Safari", Provider::WebKit),
            ("Google Chrome", Provider::Chromium),
        ] {
            let found = provider(app);
            assert_eq!(found, expected);
            for key in [
                AutoSubmitKey::Enter,
                AutoSubmitKey::CtrlEnter,
                AutoSubmitKey::CmdEnter,
            ] {
                assert!(submit_supported(found, "AXTextField", key));
            }
            assert!(!submit_supported(found, "AXTextArea", AutoSubmitKey::Enter));
            assert!(!submit_supported(found, "AXComboBox", AutoSubmitKey::Enter));
        }
        assert!(!submit_supported(
            Provider::Unknown,
            "AXWebArea",
            AutoSubmitKey::Enter
        ));
        assert!(!submit_supported(
            Provider::AppKit,
            "AXTextArea",
            AutoSubmitKey::Enter
        ));
        assert_eq!(
            provider("Safari — attacker-controlled document"),
            Provider::Unknown
        );
        assert_eq!(provider("attacker-app"), Provider::Unknown);
    }
    #[test]
    fn marker_acceptance_is_active_and_exact() {
        assert_eq!(marker_disposition(0, 7), MarkerDisposition::Physical);
        assert_eq!(marker_disposition(7, 7), MarkerDisposition::Active);
        assert_eq!(marker_disposition(7, 0), MarkerDisposition::Foreign);
        assert_eq!(marker_disposition(6, 7), MarkerDisposition::Foreign);
    }
    #[test]
    fn key_intent_is_fail_closed() {
        assert_eq!(
            key_intent_kind(classify_key_intent(RETURN_KEY, 0, &[b'\r' as u16], true)),
            UnsafeEditKind::SubmitOrNewlineAmbiguous
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(51, 0, &[], true)),
            UnsafeEditKind::Delete
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(123, 0, &[], true)),
            UnsafeEditKind::CaretRepositioned
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(123, FLAG_SHIFT, &[], true)),
            UnsafeEditKind::SelectionChanged
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(48, 0, &[b'\t' as u16], true)),
            UnsafeEditKind::FocusTraversal
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(0, FLAG_COMMAND, &[b'a' as u16], true)),
            UnsafeEditKind::CommandShortcut
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(0, FLAG_OPTION, &[], true)),
            UnsafeEditKind::ImeComposition
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(0, 0, &[], true)),
            UnsafeEditKind::ImeComposition
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(0, 0, &[b'a' as u16], false)),
            UnsafeEditKind::ImeComposition
        );
        assert_eq!(
            key_intent_kind(classify_key_intent(122, 0, &[], true)),
            UnsafeEditKind::Unknown
        );
        assert_eq!(
            classify_key_intent(0, 0, &[b'a' as u16], true),
            KEY_INTENT_PRINTABLE
        );
    }
    #[test]
    fn cancellation_and_guard_are_exact() {
        let c = SessionCancellation::default();
        c.cancel();
        assert!(c.is_cancelled());
        assert_eq!(
            parse_guard(Some("Command+Shift+Space")),
            Ok(Some(KeyGuard {
                key: 49,
                flags: FLAG_COMMAND | FLAG_SHIFT
            }))
        );
        assert!(parse_guard(Some("Command+X")).is_err());
    }
}
