#[cfg(target_os = "linux")]
use crate::settings::TypingTool;
use crate::settings::{AutoSubmitKey, ClipboardHandling};
use serde::{Deserialize, Serialize};
use specta::Type;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Type)]
pub struct DictationSessionId(pub u64);

impl DictationSessionId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InjectionId(pub u64);

impl InjectionId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObservationId(pub u64);

/// An exact, bytewise snapshot from the native streaming recognizer.
///
/// Deliberately does not implement `Debug`: both strings may contain a
/// transcript. Consumers must not normalize either field before reconciliation.
#[derive(Clone)]
pub struct TranscriptSnapshot {
    pub session_id: DictationSessionId,
    pub revision: u64,
    pub committed: String,
    pub tentative: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum FocusedOutputSafetyLevel {
    VerifiedControl,
    GuardedFocusedControl,
    Unavailable,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum InsertionTransport {
    WindowsUnicodeSendInput,
    MacAxSelectedText,
    MacCgEventUnicode,
    AtSpiEditableText,
    LinuxFocusedKeyboard,
    Test,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptConfidence {
    Verified,
    Posted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
pub struct ResolvedInsertionCapability {
    pub insertion_transport: InsertionTransport,
    pub receipt_confidence: ReceiptConfidence,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum MixedInputSupport {
    ObservedInsertionsOnly,
    GuardedKeyboardInsertionsOnly,
    Unavailable,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum FocusedOutputBackend {
    Windows,
    MacOs,
    LinuxAtSpi,
    Test,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum FocusedOutputPermission {
    MacAccessibility,
    MacInputMonitoring,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum FocusedOutputReasonCode {
    Disabled,
    ExperimentalFeaturesDisabled,
    ModelDoesNotSupportStreaming,
    PostProcessingIncompatible,
    PasteMethodDisabled,
    ExternalScriptIncompatible,
    AccessibilityPermissionMissing,
    InputMonitoringPermissionMissing,
    AtSpiUnavailable,
    TypingToolUnavailable,
    ControlShortcutUnsupported,
    AutoSubmitUnsupported,
    SecureInputActive,
    SecureField,
    HandyOwnedTarget,
    NoFocusedTarget,
    TargetNotEditable,
    InitialSelectionNotCollapsed,
    TargetUnsupported,
    TargetChanged,
    PhysicalPointerActivity,
    DestructiveUserEdit,
    CaretMoved,
    SelectionChanged,
    UnsafeKeyboardCommand,
    ImeCompositionUnsupported,
    MixedInputUnavailable,
    TargetClosed,
    MonitorUnavailable,
    BackendDisconnected,
    InjectionDenied,
    InjectionPartial,
    InjectionAmbiguous,
    InjectionFailed,
    ReceiptTimeout,
    FinalConflict,
    HistoryUnavailable,
    StreamFailed,
    Cancelled,
    PlatformUnsupported,
    AlreadyActive,
}

/// A capability is constructed through one of the three state constructors so
/// route and reason fields cannot contradict the lifecycle state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct FocusedOutputCapability {
    available: bool,
    safety_level: FocusedOutputSafetyLevel,
    backend: FocusedOutputBackend,
    route: Option<ResolvedInsertionCapability>,
    mixed_input_support: MixedInputSupport,
    supports_auto_submit: bool,
    reason_code: Option<FocusedOutputReasonCode>,
}

impl FocusedOutputCapability {
    pub fn unavailable(backend: FocusedOutputBackend, reason: FocusedOutputReasonCode) -> Self {
        Self {
            available: false,
            safety_level: FocusedOutputSafetyLevel::Unavailable,
            backend,
            route: None,
            mixed_input_support: MixedInputSupport::Unavailable,
            supports_auto_submit: false,
            reason_code: Some(reason),
        }
    }

    /// The platform is globally ready, but no target or insertion route has yet
    /// been captured. Target-specific claims are intentionally unset.
    pub fn global_ready(backend: FocusedOutputBackend) -> Self {
        Self {
            available: true,
            safety_level: FocusedOutputSafetyLevel::Unavailable,
            backend,
            route: None,
            mixed_input_support: MixedInputSupport::Unavailable,
            supports_auto_submit: false,
            reason_code: None,
        }
    }

    pub fn verified_control(
        backend: FocusedOutputBackend,
        route: ResolvedInsertionCapability,
        mixed_input_support: MixedInputSupport,
        supports_auto_submit: bool,
    ) -> Self {
        assert_eq!(
            route.receipt_confidence,
            ReceiptConfidence::Verified,
            "verified-control routes require verified receipts"
        );
        Self::resolved(
            FocusedOutputSafetyLevel::VerifiedControl,
            backend,
            route,
            mixed_input_support,
            supports_auto_submit,
        )
    }

    pub fn guarded_focused_control(
        backend: FocusedOutputBackend,
        route: ResolvedInsertionCapability,
        mixed_input_support: MixedInputSupport,
        supports_auto_submit: bool,
    ) -> Self {
        assert_eq!(
            route.receipt_confidence,
            ReceiptConfidence::Posted,
            "focus-routed insertion cannot claim a verified receipt"
        );
        Self::resolved(
            FocusedOutputSafetyLevel::GuardedFocusedControl,
            backend,
            route,
            mixed_input_support,
            supports_auto_submit,
        )
    }

    fn resolved(
        safety_level: FocusedOutputSafetyLevel,
        backend: FocusedOutputBackend,
        route: ResolvedInsertionCapability,
        mixed_input_support: MixedInputSupport,
        supports_auto_submit: bool,
    ) -> Self {
        assert_ne!(
            mixed_input_support,
            MixedInputSupport::Unavailable,
            "a resolved Begin route requires mixed-input monitoring"
        );
        Self {
            available: true,
            safety_level,
            backend,
            route: Some(route),
            mixed_input_support,
            supports_auto_submit,
            reason_code: None,
        }
    }

    pub fn available(&self) -> bool {
        self.available
    }

    pub fn safety_level(&self) -> FocusedOutputSafetyLevel {
        self.safety_level
    }

    pub fn route(&self) -> Option<ResolvedInsertionCapability> {
        self.route
    }

    pub fn mixed_input_support(&self) -> MixedInputSupport {
        self.mixed_input_support
    }

    pub fn supports_auto_submit(&self) -> bool {
        self.supports_auto_submit
    }

    pub fn reason_code(&self) -> Option<FocusedOutputReasonCode> {
        self.reason_code
    }

    pub fn is_resolved(&self) -> bool {
        self.available && self.route.is_some()
    }
}

#[derive(Clone)]
pub struct BeginContext {
    pub session_id: DictationSessionId,
    pub control_shortcut: Option<String>,
    pub auto_submit_requested: bool,
    #[cfg(target_os = "linux")]
    pub typing_tool: TypingTool,
}

/// Successful target capture. `target_application` is restricted to a verified
/// product/running-application name; it must never contain field or document
/// metadata.
#[derive(Clone)]
pub struct BeginReceipt {
    session_id: DictationSessionId,
    capability: FocusedOutputCapability,
    target_application: Option<String>,
}

impl BeginReceipt {
    pub fn new(
        session_id: DictationSessionId,
        capability: FocusedOutputCapability,
        target_application: Option<String>,
    ) -> Option<Self> {
        capability.is_resolved().then_some(Self {
            session_id,
            capability,
            target_application,
        })
    }

    pub fn session_id(&self) -> DictationSessionId {
        self.session_id
    }

    pub fn capability(&self) -> &FocusedOutputCapability {
        &self.capability
    }

    pub fn into_parts(self) -> (DictationSessionId, FocusedOutputCapability, Option<String>) {
        (self.session_id, self.capability, self.target_application)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertionKind {
    Speech,
    TrailingSpace,
}

/// Owned insertion input. Deliberately does not implement `Clone` or `Debug` so
/// transcript text cannot be copied or accidentally formatted by platform code.
pub struct InsertionRequest {
    pub session_id: DictationSessionId,
    pub injection_id: InjectionId,
    pub text: String,
    #[allow(dead_code)]
    pub kind: InsertionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    Complete {
        receipt: ReceiptConfidence,
    },
    Partial {
        accepted_bytes: usize,
        receipt: ReceiptConfidence,
        reason: FocusedOutputReasonCode,
    },
    Ambiguous {
        reason: FocusedOutputReasonCode,
    },
    Rejected {
        reason: FocusedOutputReasonCode,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Complete {
        receipt: ReceiptConfidence,
    },
    Ambiguous {
        reason: FocusedOutputReasonCode,
    },
    Rejected {
        reason: FocusedOutputReasonCode,
    },
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsafeEditKind {
    Delete,
    Replace,
    Cut,
    Paste,
    UndoRedo,
    SelectionChanged,
    CaretRepositioned,
    FocusTraversal,
    SubmitOrNewlineAmbiguous,
    CommandShortcut,
    ImeComposition,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetInteractionEvent {
    HandyInsertionObserved {
        injection_id: InjectionId,
        caret_after: Option<i64>,
    },
    CompatibleExternalInsertion {
        observation_id: ObservationId,
        chars: usize,
        caret_after: Option<i64>,
    },
    UnsafeEdit {
        observation_id: ObservationId,
        kind: UnsafeEditKind,
    },
    TargetInvalidated {
        observation_id: ObservationId,
        reason: FocusedOutputReasonCode,
    },
    MonitorUnavailable {
        observation_id: ObservationId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalReason {
    PartialInsertion,
    AmbiguousInsertion,
    TargetInvalidated,
    UnsafeUserEdit,
    MonitorUnavailable,
    ReceiptTimeout,
    FinalConflict,
    StreamFailed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputPlanKind {
    Fallback,
    Focused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivePlan {
    pub session_id: DictationSessionId,
    pub kind: OutputPlanKind,
}

pub enum FinalDeliveryDisposition {
    Focused(FocusedDeliveryDisposition),
    LegacyPaste(LegacyPasteAuthority),
    NoText,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusedDeliveryDisposition {
    Delivered {
        safety_level: FocusedOutputSafetyLevel,
        receipt_confidence: ReceiptConfidence,
        external_edit_epoch: u64,
        trailing_space_delivered: bool,
        submit: SubmitDisposition,
    },
    PreservePartial {
        reason: TerminalReason,
        speech_delivered_chars: usize,
        external_edit_epoch: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitDisposition {
    NotRequested,
    Submitted { receipt: ReceiptConfidence },
    Failed { reason: FocusedOutputReasonCode },
}

/// A non-cloneable authority consumed by the sole legacy paste call site.
/// Construction is intentionally mediated by `FallbackAuthority`.
pub struct LegacyPasteAuthority {
    _private: (),
}

/// Owned only by an unarmed fallback plan. Consuming that plan is the only path
/// to a `LegacyPasteAuthority`; an armed plan has no corresponding field.
pub(super) struct FallbackAuthority {
    legacy_paste: LegacyPasteAuthority,
}

impl FallbackAuthority {
    pub(super) fn new() -> Self {
        Self {
            legacy_paste: LegacyPasteAuthority { _private: () },
        }
    }

    pub(super) fn into_legacy_paste(self) -> LegacyPasteAuthority {
        self.legacy_paste
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizeOptions {
    pub append_trailing_space: bool,
    pub clipboard_handling: ClipboardHandling,
    pub auto_submit: bool,
    pub auto_submit_key: AutoSubmitKey,
    pub history_available: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditEffectEvidence {
    DetailedInsert {
        start: i64,
        removed_len: usize,
        inserted_chars: usize,
    },
    GuardedCaretAdvance {
        value_changed: bool,
        caret_before: i64,
        caret_after: i64,
    },
}

/// Transcript-bearing platform attribution state. It intentionally has no
/// `Debug` implementation and must be cleared on match, timeout, cancellation,
/// terminal invalidation, or close.
pub(super) struct PendingInjection {
    pub(super) injection_id: InjectionId,
    pub(super) random_marker: u64,
    pub(super) expected_text: String,
    pub(super) caret_before: Option<i64>,
    pub(super) deadline: Instant,
    pub(super) immediate_receipt: Option<ReceiptConfidence>,
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const INPUT_EFFECT_DEADLINE: Duration = Duration::from_millis(500);
pub const HANDY_RECEIPT_DEADLINE: Duration = Duration::from_millis(500);
pub const TARGET_CALL_DEADLINE: Duration = Duration::from_secs(1);
pub const CHILD_PROCESS_DEADLINE: Duration = Duration::from_secs(2);
pub const THREAD_READY_DEADLINE: Duration = Duration::from_secs(2);
pub const THREAD_CLOSE_DEADLINE: Duration = Duration::from_secs(2);
pub const BACKEND_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformDeadlines {
    pub input_effect: Duration,
    pub handy_receipt: Duration,
    pub target_call: Duration,
    pub child_process: Duration,
    pub thread_ready: Duration,
    pub thread_close: Duration,
    pub backend_shutdown: Duration,
}

impl Default for PlatformDeadlines {
    fn default() -> Self {
        Self {
            input_effect: INPUT_EFFECT_DEADLINE,
            handy_receipt: HANDY_RECEIPT_DEADLINE,
            target_call: TARGET_CALL_DEADLINE,
            child_process: CHILD_PROCESS_DEADLINE,
            thread_ready: THREAD_READY_DEADLINE,
            thread_close: THREAD_CLOSE_DEADLINE,
            backend_shutdown: BACKEND_SHUTDOWN_DEADLINE,
        }
    }
}

/// Cloneable, out-of-band cancellation checked immediately before every
/// platform dispatch unit.
#[derive(Clone, Default)]
pub struct SessionCancellation {
    cancelled: Arc<AtomicBool>,
}

impl SessionCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum FocusedOutputStatus {
    Armed,
    Streaming,
    Fallback,
    Invalidated,
    Conflict,
    Completed,
    Cancelled,
    Faulted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type, tauri_specta::Event)]
pub struct FocusedOutputStatusEvent {
    pub session_id: DictationSessionId,
    pub status: FocusedOutputStatus,
    pub reason: Option<FocusedOutputReasonCode>,
    pub capability: Option<FocusedOutputCapability>,
    pub target_application: Option<String>,
    pub speech_delivered_chars: usize,
    pub external_edit_epoch: u64,
    pub history_available: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROUTE: ResolvedInsertionCapability = ResolvedInsertionCapability {
        insertion_transport: InsertionTransport::Test,
        receipt_confidence: ReceiptConfidence::Verified,
    };

    #[test]
    fn unavailable_capability_has_reason_and_no_route() {
        let capability = FocusedOutputCapability::unavailable(
            FocusedOutputBackend::Test,
            FocusedOutputReasonCode::PlatformUnsupported,
        );

        assert!(!capability.available());
        assert_eq!(
            capability.safety_level(),
            FocusedOutputSafetyLevel::Unavailable
        );
        assert_eq!(capability.route(), None);
        assert_eq!(
            capability.reason_code(),
            Some(FocusedOutputReasonCode::PlatformUnsupported)
        );
    }

    #[test]
    fn global_capability_has_neither_route_nor_reason() {
        let capability = FocusedOutputCapability::global_ready(FocusedOutputBackend::Test);

        assert!(capability.available());
        assert_eq!(capability.route(), None);
        assert_eq!(capability.reason_code(), None);
        assert!(!capability.supports_auto_submit());
    }

    #[test]
    fn begin_accepts_only_a_resolved_capability() {
        let global = FocusedOutputCapability::global_ready(FocusedOutputBackend::Test);
        assert!(BeginReceipt::new(DictationSessionId(1), global, None).is_none());

        let resolved = FocusedOutputCapability::verified_control(
            FocusedOutputBackend::Test,
            TEST_ROUTE,
            MixedInputSupport::ObservedInsertionsOnly,
            true,
        );
        let receipt = BeginReceipt::new(DictationSessionId(1), resolved, None)
            .expect("resolved capability must be accepted");
        assert!(receipt.capability.is_resolved());
        assert_eq!(receipt.capability.reason_code(), None);
    }

    #[test]
    fn fallback_authority_is_consumed_into_legacy_paste() {
        let authority = FallbackAuthority::new();
        let _legacy = authority.into_legacy_paste();
    }

    #[test]
    fn platform_deadlines_match_the_fixed_contract() {
        let deadlines = PlatformDeadlines::default();
        assert_eq!(deadlines.input_effect, Duration::from_millis(500));
        assert_eq!(deadlines.handy_receipt, Duration::from_millis(500));
        assert_eq!(deadlines.target_call, Duration::from_secs(1));
        assert_eq!(deadlines.child_process, Duration::from_secs(2));
        assert_eq!(deadlines.thread_ready, Duration::from_secs(2));
        assert_eq!(deadlines.thread_close, Duration::from_secs(2));
        assert_eq!(deadlines.backend_shutdown, Duration::from_secs(2));
    }
}
