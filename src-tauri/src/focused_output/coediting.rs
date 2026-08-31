use super::types::{
    DictationSessionId, EditEffectEvidence, InjectionId, MixedInputSupport, ObservationId,
    PendingInjection, ReceiptConfidence, TargetInteractionEvent, TerminalReason, UnsafeEditKind,
};
use std::time::Instant;

/// Stable, content-free identity for the monitor which produced an observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AttributionScope {
    pub(crate) session_id: DictationSessionId,
    pub(crate) generation: u64,
    pub(crate) source_marker: u64,
}

/// An already-normalized interaction and its structural attribution proof.
/// Random injection markers intentionally cannot be printed through `Debug`.
pub(crate) struct InteractionEvidence {
    scope: AttributionScope,
    observation_id: ObservationId,
    random_marker: Option<u64>,
    received_at: Instant,
    effect: Option<EditEffectEvidence>,
    event: TargetInteractionEvent,
}

impl InteractionEvidence {
    pub(crate) fn normalized(
        scope: AttributionScope,
        observation_id: ObservationId,
        received_at: Instant,
        event: TargetInteractionEvent,
        effect: Option<EditEffectEvidence>,
    ) -> Self {
        Self {
            scope,
            observation_id,
            random_marker: None,
            received_at,
            effect,
            event,
        }
    }

    #[cfg(test)]
    pub(crate) fn handy(
        scope: AttributionScope,
        observation_id: ObservationId,
        random_marker: u64,
        received_at: Instant,
        injection_id: InjectionId,
        caret_after: Option<i64>,
        effect: EditEffectEvidence,
    ) -> Self {
        Self {
            scope,
            observation_id,
            random_marker: Some(random_marker),
            received_at,
            effect: Some(effect),
            event: TargetInteractionEvent::HandyInsertionObserved {
                injection_id,
                caret_after,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoeditDecision {
    Continue,
    Ignored,
    HandyAcknowledged {
        injection_id: InjectionId,
    },
    ExternalInsertionAccepted {
        observation_id: ObservationId,
        external_edit_epoch: u64,
    },
    Terminal(TerminalReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArmPendingResult {
    Armed,
    AlreadyPending { injection_id: InjectionId },
    Terminal(TerminalReason),
}

/// Pure co-editing and Handy-attribution state.
///
/// Target contents and external user text never enter this state. The expected
/// Handy insertion held by `PendingInjection` cannot be debug-printed and is
/// cleared on acknowledgement, timeout, cancellation, invalidation, or close.
pub(crate) struct CoeditingState {
    scope: AttributionScope,
    mixed_input_support: MixedInputSupport,
    external_edit_epoch: u64,
    terminal: Option<TerminalReason>,
    last_observation: Option<ObservationId>,
    pending_injection: Option<PendingInjection>,
}

impl CoeditingState {
    pub(crate) fn new(scope: AttributionScope, mixed_input_support: MixedInputSupport) -> Self {
        let terminal = match mixed_input_support {
            MixedInputSupport::ObservedInsertionsOnly
            | MixedInputSupport::GuardedKeyboardInsertionsOnly => None,
            MixedInputSupport::Unavailable => Some(TerminalReason::MonitorUnavailable),
        };
        Self {
            scope,
            mixed_input_support,
            external_edit_epoch: 0,
            terminal,
            last_observation: None,
            pending_injection: None,
        }
    }

    pub(crate) fn external_edit_epoch(&self) -> u64 {
        self.external_edit_epoch
    }

    pub(crate) fn terminal(&self) -> Option<TerminalReason> {
        self.terminal
    }

    pub(crate) fn pending_injection_id(&self) -> Option<InjectionId> {
        self.pending_injection
            .as_ref()
            .map(|pending| pending.injection_id)
    }

    pub(crate) fn pending_deadline(&self) -> Option<Instant> {
        self.pending_injection
            .as_ref()
            .map(|pending| pending.deadline)
    }

    /// A second insertion cannot overtake an unacknowledged target effect.
    pub(super) fn arm_pending(&mut self, pending: PendingInjection) -> ArmPendingResult {
        if let Some(reason) = self.terminal {
            return ArmPendingResult::Terminal(reason);
        }
        if let Some(active) = self.pending_injection.as_ref() {
            return ArmPendingResult::AlreadyPending {
                injection_id: active.injection_id,
            };
        }
        self.pending_injection = Some(pending);
        ArmPendingResult::Armed
    }

    /// Starts the observation window only after the bounded transport call
    /// returns, so helper/IPC time cannot consume receipt-attribution time.
    pub(crate) fn start_receipt_deadline(
        &mut self,
        injection_id: InjectionId,
        deadline: Instant,
    ) -> CoeditDecision {
        if let Some(reason) = self.terminal {
            return CoeditDecision::Terminal(reason);
        }
        let Some(pending) = self.pending_injection.as_mut() else {
            return CoeditDecision::Ignored;
        };
        if pending.injection_id != injection_id {
            return self.set_terminal(TerminalReason::AmbiguousInsertion);
        }
        pending.deadline = deadline;
        CoeditDecision::Continue
    }

    /// A synchronous transport receipt does not replace its asynchronous,
    /// exactly-attributed target acknowledgement unless the route proved an
    /// exact target-bound readback synchronously.
    pub(crate) fn record_immediate_receipt(
        &mut self,
        injection_id: InjectionId,
        receipt: ReceiptConfidence,
    ) -> CoeditDecision {
        if let Some(reason) = self.terminal {
            return CoeditDecision::Terminal(reason);
        }
        let Some(pending) = self.pending_injection.as_mut() else {
            return CoeditDecision::Ignored;
        };
        if pending.injection_id != injection_id {
            return self.set_terminal(TerminalReason::AmbiguousInsertion);
        }
        pending.immediate_receipt = Some(receipt);
        CoeditDecision::Continue
    }

    /// Completes a pending insertion from a transport whose `Verified`
    /// receipt is itself exact target-bound range readback.
    pub(crate) fn acknowledge_verified_receipt(
        &mut self,
        injection_id: InjectionId,
    ) -> CoeditDecision {
        if let Some(reason) = self.terminal {
            return CoeditDecision::Terminal(reason);
        }
        let Some(pending) = self.pending_injection.as_ref() else {
            return CoeditDecision::Ignored;
        };
        if pending.injection_id != injection_id
            || pending.immediate_receipt != Some(ReceiptConfidence::Verified)
        {
            return self.set_terminal(TerminalReason::AmbiguousInsertion);
        }
        self.pending_injection = None;
        CoeditDecision::HandyAcknowledged { injection_id }
    }

    /// Platform event sinks publish this only after exact target-bound
    /// attribution. Core still validates that the acknowledgement is for the
    /// one currently pending insertion.
    pub(crate) fn acknowledge_platform_observation(
        &mut self,
        injection_id: InjectionId,
    ) -> CoeditDecision {
        if let Some(reason) = self.terminal {
            return CoeditDecision::Terminal(reason);
        }
        let Some(pending) = self.pending_injection.as_ref() else {
            return CoeditDecision::Ignored;
        };
        if injection_id < pending.injection_id {
            return CoeditDecision::Ignored;
        }
        if pending.injection_id != injection_id {
            return self.set_terminal(TerminalReason::AmbiguousInsertion);
        }
        self.pending_injection = None;
        CoeditDecision::HandyAcknowledged { injection_id }
    }

    pub(crate) fn check_deadline(&mut self, now: Instant) -> CoeditDecision {
        if let Some(reason) = self.terminal {
            return CoeditDecision::Terminal(reason);
        }
        let Some(pending) = self.pending_injection.as_ref() else {
            return CoeditDecision::Continue;
        };
        if now < pending.deadline {
            return CoeditDecision::Continue;
        }
        let reason = match pending.immediate_receipt {
            Some(ReceiptConfidence::Verified) => TerminalReason::MonitorUnavailable,
            Some(ReceiptConfidence::Posted) | None => TerminalReason::ReceiptTimeout,
        };
        self.set_terminal(reason)
    }

    pub(crate) fn on_evidence(&mut self, evidence: InteractionEvidence) -> CoeditDecision {
        if let Some(reason) = self.terminal {
            return CoeditDecision::Terminal(reason);
        }
        let deadline = self.check_deadline(evidence.received_at);
        if matches!(deadline, CoeditDecision::Terminal(_)) {
            return deadline;
        }
        if evidence.scope.session_id != self.scope.session_id
            || evidence.scope.generation != self.scope.generation
        {
            return CoeditDecision::Ignored;
        }
        if evidence.scope.source_marker != self.scope.source_marker {
            return self.set_terminal(TerminalReason::TargetInvalidated);
        }
        if self
            .last_observation
            .is_some_and(|last| evidence.observation_id <= last)
        {
            return CoeditDecision::Ignored;
        }

        match evidence.event {
            TargetInteractionEvent::HandyInsertionObserved {
                injection_id,
                caret_after,
            } => self.on_handy_observation(
                evidence.observation_id,
                evidence.random_marker,
                injection_id,
                caret_after,
                evidence.effect,
            ),
            TargetInteractionEvent::CompatibleExternalInsertion {
                observation_id,
                chars,
                caret_after,
            } => self.on_external_insertion(
                evidence.observation_id,
                observation_id,
                chars,
                caret_after,
                evidence.random_marker,
                evidence.effect,
            ),
            TargetInteractionEvent::UnsafeEdit {
                observation_id,
                kind,
            } => {
                if evidence.observation_id != observation_id || evidence.random_marker.is_some() {
                    return self.set_terminal(TerminalReason::AmbiguousInsertion);
                }
                self.last_observation = Some(observation_id);
                self.set_terminal(classify_unsafe_edit(kind))
            }
            TargetInteractionEvent::TargetInvalidated {
                observation_id,
                reason: _,
            } => {
                if evidence.observation_id != observation_id || evidence.random_marker.is_some() {
                    return self.set_terminal(TerminalReason::AmbiguousInsertion);
                }
                self.last_observation = Some(observation_id);
                self.set_terminal(TerminalReason::TargetInvalidated)
            }
            TargetInteractionEvent::MonitorUnavailable { observation_id } => {
                if evidence.observation_id != observation_id || evidence.random_marker.is_some() {
                    return self.set_terminal(TerminalReason::AmbiguousInsertion);
                }
                self.last_observation = Some(observation_id);
                self.set_terminal(TerminalReason::MonitorUnavailable)
            }
        }
    }

    pub(crate) fn terminate(&mut self, reason: TerminalReason) -> CoeditDecision {
        self.set_terminal(reason)
    }

    fn on_handy_observation(
        &mut self,
        observation_id: ObservationId,
        random_marker: Option<u64>,
        injection_id: InjectionId,
        caret_after: Option<i64>,
        effect: Option<EditEffectEvidence>,
    ) -> CoeditDecision {
        let Some(pending) = self.pending_injection.as_ref() else {
            self.last_observation = Some(observation_id);
            return CoeditDecision::Ignored;
        };
        let matches = random_marker == Some(pending.random_marker)
            && injection_id == pending.injection_id
            && effect.is_some_and(|effect| {
                handy_effect_matches(self.mixed_input_support, pending, caret_after, effect)
            });
        if !matches {
            return self.set_terminal(TerminalReason::AmbiguousInsertion);
        }
        self.last_observation = Some(observation_id);
        self.pending_injection = None;
        CoeditDecision::HandyAcknowledged { injection_id }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_external_insertion(
        &mut self,
        envelope_id: ObservationId,
        event_id: ObservationId,
        chars: usize,
        caret_after: Option<i64>,
        random_marker: Option<u64>,
        effect: Option<EditEffectEvidence>,
    ) -> CoeditDecision {
        if envelope_id != event_id || random_marker.is_some() {
            return self.set_terminal(TerminalReason::AmbiguousInsertion);
        }
        if chars == 0 {
            self.last_observation = Some(event_id);
            return CoeditDecision::Continue;
        }
        if !effect.is_some_and(|effect| {
            external_effect_matches(self.mixed_input_support, chars, caret_after, effect)
        }) {
            return self.set_terminal(TerminalReason::UnsafeUserEdit);
        }
        let Some(next_epoch) = self.external_edit_epoch.checked_add(1) else {
            return self.set_terminal(TerminalReason::MonitorUnavailable);
        };
        self.external_edit_epoch = next_epoch;
        self.last_observation = Some(event_id);
        CoeditDecision::ExternalInsertionAccepted {
            observation_id: event_id,
            external_edit_epoch: next_epoch,
        }
    }

    fn set_terminal(&mut self, reason: TerminalReason) -> CoeditDecision {
        let first = *self.terminal.get_or_insert(reason);
        self.pending_injection = None;
        CoeditDecision::Terminal(first)
    }
}

fn classify_unsafe_edit(kind: UnsafeEditKind) -> TerminalReason {
    match kind {
        UnsafeEditKind::Delete
        | UnsafeEditKind::Replace
        | UnsafeEditKind::Cut
        | UnsafeEditKind::Paste
        | UnsafeEditKind::UndoRedo
        | UnsafeEditKind::SelectionChanged
        | UnsafeEditKind::CaretRepositioned
        | UnsafeEditKind::FocusTraversal
        | UnsafeEditKind::SubmitOrNewlineAmbiguous
        | UnsafeEditKind::CommandShortcut
        | UnsafeEditKind::ImeComposition
        | UnsafeEditKind::Unknown => TerminalReason::UnsafeUserEdit,
    }
}

fn handy_effect_matches(
    support: MixedInputSupport,
    pending: &PendingInjection,
    event_caret_after: Option<i64>,
    effect: EditEffectEvidence,
) -> bool {
    let expected_chars = pending.expected_text.chars().count();
    match (support, effect) {
        (
            MixedInputSupport::ObservedInsertionsOnly,
            EditEffectEvidence::DetailedInsert {
                start,
                removed_len,
                inserted_chars,
            },
        ) => {
            removed_len == 0
                && inserted_chars == expected_chars
                && pending.caret_before.is_none_or(|before| before == start)
                && event_caret_after.is_none_or(|after| {
                    usize_to_i64(inserted_chars).and_then(|inserted| start.checked_add(inserted))
                        == Some(after)
                })
        }
        (
            MixedInputSupport::GuardedKeyboardInsertionsOnly,
            EditEffectEvidence::GuardedCaretAdvance {
                value_changed,
                caret_before,
                caret_after,
            },
        ) => {
            value_changed
                && caret_after > caret_before
                && pending
                    .caret_before
                    .is_none_or(|expected| expected == caret_before)
                && event_caret_after.is_none_or(|expected| expected == caret_after)
        }
        _ => false,
    }
}

fn external_effect_matches(
    support: MixedInputSupport,
    chars: usize,
    event_caret_after: Option<i64>,
    effect: EditEffectEvidence,
) -> bool {
    match (support, effect) {
        (
            MixedInputSupport::ObservedInsertionsOnly,
            EditEffectEvidence::DetailedInsert {
                start,
                removed_len,
                inserted_chars,
            },
        ) => {
            removed_len == 0
                && inserted_chars == chars
                && event_caret_after.is_none_or(|after| {
                    usize_to_i64(inserted_chars).and_then(|inserted| start.checked_add(inserted))
                        == Some(after)
                })
        }
        (
            MixedInputSupport::GuardedKeyboardInsertionsOnly,
            EditEffectEvidence::GuardedCaretAdvance {
                value_changed,
                caret_before,
                caret_after,
            },
        ) => {
            value_changed
                && caret_after > caret_before
                && event_caret_after.is_none_or(|expected| expected == caret_after)
        }
        _ => false,
    }
}

fn usize_to_i64(value: usize) -> Option<i64> {
    i64::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focused_output::types::{FocusedOutputReasonCode, HANDY_RECEIPT_DEADLINE};
    use std::time::Duration;

    const SCOPE: AttributionScope = AttributionScope {
        session_id: DictationSessionId(7),
        generation: 11,
        source_marker: 13,
    };

    fn state(support: MixedInputSupport) -> CoeditingState {
        CoeditingState::new(SCOPE, support)
    }

    fn pending(
        injection: u64,
        marker: u64,
        now: Instant,
        receipt: Option<ReceiptConfidence>,
    ) -> PendingInjection {
        PendingInjection {
            injection_id: InjectionId(injection),
            random_marker: marker,
            expected_text: String::from("abc"),
            caret_before: Some(20),
            deadline: now + HANDY_RECEIPT_DEADLINE,
            immediate_receipt: receipt,
        }
    }

    fn external(
        scope: AttributionScope,
        observation: u64,
        chars: usize,
        now: Instant,
        support: MixedInputSupport,
    ) -> InteractionEvidence {
        let id = ObservationId(observation);
        let (caret_after, effect) = match support {
            MixedInputSupport::ObservedInsertionsOnly => (
                Some(10 + chars as i64),
                EditEffectEvidence::DetailedInsert {
                    start: 10,
                    removed_len: 0,
                    inserted_chars: chars,
                },
            ),
            MixedInputSupport::GuardedKeyboardInsertionsOnly => (
                Some(11),
                EditEffectEvidence::GuardedCaretAdvance {
                    value_changed: true,
                    caret_before: 10,
                    caret_after: 11,
                },
            ),
            MixedInputSupport::Unavailable => unreachable!(),
        };
        InteractionEvidence::normalized(
            scope,
            id,
            now,
            TargetInteractionEvent::CompatibleExternalInsertion {
                observation_id: id,
                chars,
                caret_after,
            },
            Some(effect),
        )
    }

    fn handy(now: Instant, observation: u64, injection: u64, marker: u64) -> InteractionEvidence {
        InteractionEvidence::handy(
            SCOPE,
            ObservationId(observation),
            marker,
            now,
            InjectionId(injection),
            Some(23),
            EditEffectEvidence::DetailedInsert {
                start: 20,
                removed_len: 0,
                inserted_chars: 3,
            },
        )
    }

    #[test]
    fn exact_handy_ack_is_neutral_and_does_not_coalesce() {
        let now = Instant::now();
        let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
        assert_eq!(
            state.arm_pending(pending(1, 41, now, Some(ReceiptConfidence::Verified))),
            ArmPendingResult::Armed
        );
        assert_eq!(
            state.on_evidence(handy(now, 1, 1, 41)),
            CoeditDecision::HandyAcknowledged {
                injection_id: InjectionId(1)
            }
        );
        assert_eq!(state.external_edit_epoch(), 0);
        assert_eq!(state.pending_injection_id(), None);
        assert_eq!(
            state.on_evidence(handy(now, 1, 1, 41)),
            CoeditDecision::Ignored
        );
    }

    #[test]
    fn safe_external_insertions_coexist_with_pending_handy_attribution() {
        let now = Instant::now();
        let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
        state.arm_pending(pending(1, 51, now, Some(ReceiptConfidence::Posted)));
        assert!(matches!(
            state.on_evidence(external(
                SCOPE,
                1,
                2,
                now,
                MixedInputSupport::ObservedInsertionsOnly
            )),
            CoeditDecision::ExternalInsertionAccepted {
                external_edit_epoch: 1,
                ..
            }
        ));
        assert_eq!(state.pending_injection_id(), Some(InjectionId(1)));
        assert!(matches!(
            state.on_evidence(handy(now, 2, 1, 51)),
            CoeditDecision::HandyAcknowledged { .. }
        ));
        assert_eq!(state.external_edit_epoch(), 1);
    }

    #[test]
    fn guarded_and_observed_evidence_are_distinct() {
        let now = Instant::now();
        for (configured, supplied) in [
            (
                MixedInputSupport::ObservedInsertionsOnly,
                MixedInputSupport::GuardedKeyboardInsertionsOnly,
            ),
            (
                MixedInputSupport::GuardedKeyboardInsertionsOnly,
                MixedInputSupport::ObservedInsertionsOnly,
            ),
        ] {
            let mut state = state(configured);
            assert_eq!(
                state.on_evidence(external(SCOPE, 1, 1, now, supplied)),
                CoeditDecision::Terminal(TerminalReason::UnsafeUserEdit)
            );
        }
    }

    #[test]
    fn unique_insertions_increment_once_while_zero_stale_and_duplicate_are_neutral() {
        let now = Instant::now();
        let support = MixedInputSupport::ObservedInsertionsOnly;
        let mut state = state(support);
        assert!(matches!(
            state.on_evidence(external(SCOPE, 2, 1, now, support)),
            CoeditDecision::ExternalInsertionAccepted { .. }
        ));
        assert_eq!(
            state.on_evidence(external(SCOPE, 2, 1, now, support)),
            CoeditDecision::Ignored
        );
        assert_eq!(
            state.on_evidence(external(SCOPE, 1, 1, now, support)),
            CoeditDecision::Ignored
        );
        assert_eq!(
            state.on_evidence(external(SCOPE, 3, 0, now, support)),
            CoeditDecision::Continue
        );
        assert_eq!(state.external_edit_epoch(), 1);
    }

    #[test]
    fn at_most_one_pending_insertion_exists() {
        let now = Instant::now();
        let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
        assert_eq!(
            state.arm_pending(pending(1, 1, now, None)),
            ArmPendingResult::Armed
        );
        assert_eq!(
            state.arm_pending(pending(2, 2, now, None)),
            ArmPendingResult::AlreadyPending {
                injection_id: InjectionId(1)
            }
        );
    }

    #[test]
    fn wrong_session_and_generation_are_ignored_but_same_generation_forgery_is_terminal() {
        let now = Instant::now();
        let support = MixedInputSupport::ObservedInsertionsOnly;
        let mut state = state(support);
        for stale in [
            AttributionScope {
                session_id: DictationSessionId(8),
                ..SCOPE
            },
            AttributionScope {
                generation: 10,
                ..SCOPE
            },
        ] {
            assert_eq!(
                state.on_evidence(external(stale, 1, 1, now, support)),
                CoeditDecision::Ignored
            );
        }
        let forged = AttributionScope {
            source_marker: 14,
            ..SCOPE
        };
        assert_eq!(
            state.on_evidence(external(forged, 1, 1, now, support)),
            CoeditDecision::Terminal(TerminalReason::TargetInvalidated)
        );
    }

    #[test]
    fn fresh_mismatched_handy_markers_ids_and_shapes_are_terminal() {
        let now = Instant::now();
        for case in 0..3 {
            let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
            state.arm_pending(pending(1, 9, now, Some(ReceiptConfidence::Verified)));
            let mut evidence = handy(now, 1, 1, 9);
            match case {
                0 => evidence.random_marker = Some(10),
                1 => {
                    evidence.event = TargetInteractionEvent::HandyInsertionObserved {
                        injection_id: InjectionId(2),
                        caret_after: Some(23),
                    }
                }
                _ => {
                    evidence.effect = Some(EditEffectEvidence::DetailedInsert {
                        start: 20,
                        removed_len: 1,
                        inserted_chars: 3,
                    })
                }
            }
            assert_eq!(
                state.on_evidence(evidence),
                CoeditDecision::Terminal(TerminalReason::AmbiguousInsertion)
            );
            assert_eq!(state.pending_injection_id(), None);
        }
    }

    #[test]
    fn posted_and_verified_timeouts_have_distinct_reasons_and_late_ack_cannot_win() {
        let now = Instant::now();
        for (receipt, reason) in [
            (ReceiptConfidence::Posted, TerminalReason::ReceiptTimeout),
            (
                ReceiptConfidence::Verified,
                TerminalReason::MonitorUnavailable,
            ),
        ] {
            let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
            state.arm_pending(pending(1, 1, now, Some(receipt)));
            assert_eq!(
                state.on_evidence(handy(now + HANDY_RECEIPT_DEADLINE, 1, 1, 1)),
                CoeditDecision::Terminal(reason)
            );
            assert_eq!(state.pending_injection_id(), None);
        }
    }

    #[test]
    fn every_unsafe_edit_class_is_terminal() {
        let kinds = [
            UnsafeEditKind::Delete,
            UnsafeEditKind::Replace,
            UnsafeEditKind::Cut,
            UnsafeEditKind::Paste,
            UnsafeEditKind::UndoRedo,
            UnsafeEditKind::SelectionChanged,
            UnsafeEditKind::CaretRepositioned,
            UnsafeEditKind::FocusTraversal,
            UnsafeEditKind::SubmitOrNewlineAmbiguous,
            UnsafeEditKind::CommandShortcut,
            UnsafeEditKind::ImeComposition,
            UnsafeEditKind::Unknown,
        ];
        for kind in kinds {
            let now = Instant::now();
            let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
            let id = ObservationId(1);
            assert_eq!(
                state.on_evidence(InteractionEvidence::normalized(
                    SCOPE,
                    id,
                    now,
                    TargetInteractionEvent::UnsafeEdit {
                        observation_id: id,
                        kind,
                    },
                    None,
                )),
                CoeditDecision::Terminal(TerminalReason::UnsafeUserEdit)
            );
        }
    }

    #[test]
    fn focus_identity_and_monitor_loss_are_terminal() {
        let now = Instant::now();
        let id = ObservationId(1);
        let mut focus = state(MixedInputSupport::ObservedInsertionsOnly);
        assert_eq!(
            focus.on_evidence(InteractionEvidence::normalized(
                SCOPE,
                id,
                now,
                TargetInteractionEvent::TargetInvalidated {
                    observation_id: id,
                    reason: FocusedOutputReasonCode::TargetChanged,
                },
                None,
            )),
            CoeditDecision::Terminal(TerminalReason::TargetInvalidated)
        );
        let mut monitor = state(MixedInputSupport::ObservedInsertionsOnly);
        assert_eq!(
            monitor.on_evidence(InteractionEvidence::normalized(
                SCOPE,
                id,
                now,
                TargetInteractionEvent::MonitorUnavailable { observation_id: id },
                None,
            )),
            CoeditDecision::Terminal(TerminalReason::MonitorUnavailable)
        );
    }

    #[test]
    fn receipt_is_not_an_ack_and_terminal_is_first_wins() {
        let now = Instant::now();
        let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
        state.arm_pending(pending(1, 1, now, None));
        assert_eq!(
            state.record_immediate_receipt(InjectionId(1), ReceiptConfidence::Verified),
            CoeditDecision::Continue
        );
        assert_eq!(state.pending_injection_id(), Some(InjectionId(1)));
        assert_eq!(
            state.terminate(TerminalReason::Cancelled),
            CoeditDecision::Terminal(TerminalReason::Cancelled)
        );
        assert_eq!(state.pending_injection_id(), None);
        assert_eq!(
            state.terminate(TerminalReason::StreamFailed),
            CoeditDecision::Terminal(TerminalReason::Cancelled)
        );
    }

    #[test]
    fn exact_verified_receipt_can_acknowledge_synchronously() {
        let now = Instant::now();
        let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
        state.arm_pending(pending(1, 1, now, None));
        assert_eq!(
            state.record_immediate_receipt(InjectionId(1), ReceiptConfidence::Verified),
            CoeditDecision::Continue
        );
        assert_eq!(
            state.acknowledge_verified_receipt(InjectionId(1)),
            CoeditDecision::HandyAcknowledged {
                injection_id: InjectionId(1),
            }
        );
        assert_eq!(state.pending_injection_id(), None);
    }

    #[test]
    fn platform_acknowledgement_must_match_the_one_pending_id() {
        let now = Instant::now();
        let mut state = state(MixedInputSupport::GuardedKeyboardInsertionsOnly);
        state.arm_pending(pending(2, 1, now, Some(ReceiptConfidence::Posted)));
        assert_eq!(
            state.acknowledge_platform_observation(InjectionId(1)),
            CoeditDecision::Ignored
        );
        assert_eq!(
            state.acknowledge_platform_observation(InjectionId(3)),
            CoeditDecision::Terminal(TerminalReason::AmbiguousInsertion)
        );
        assert_eq!(state.pending_injection_id(), None);
    }

    #[test]
    fn deterministic_mixed_event_loops_preserve_epoch_and_terminal_monotonicity() {
        let now = Instant::now();
        for seed in 0_u64..256 {
            let support = if seed & 1 == 0 {
                MixedInputSupport::ObservedInsertionsOnly
            } else {
                MixedInputSupport::GuardedKeyboardInsertionsOnly
            };
            let mut state = state(support);
            let mut random = seed ^ 0x9e37_79b9_7f4a_7c15;
            let mut observation = 0_u64;
            let mut accepted = 0_u64;
            let mut first_terminal = None;
            for _ in 0..128 {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let action = (random >> 61) as u8;
                let before_epoch = state.external_edit_epoch();
                let before_terminal = state.terminal();
                let decision = match action {
                    0..=4 => {
                        observation += 1;
                        state.on_evidence(external(SCOPE, observation, 1, now, support))
                    }
                    5 => state.on_evidence(external(SCOPE, observation.max(1), 1, now, support)),
                    6 => {
                        observation += 1;
                        let id = ObservationId(observation);
                        state.on_evidence(InteractionEvidence::normalized(
                            SCOPE,
                            id,
                            now,
                            TargetInteractionEvent::UnsafeEdit {
                                observation_id: id,
                                kind: UnsafeEditKind::CommandShortcut,
                            },
                            None,
                        ))
                    }
                    _ => state.terminate(TerminalReason::Cancelled),
                };
                if let Some(reason) = before_terminal {
                    assert_eq!(decision, CoeditDecision::Terminal(reason));
                    assert_eq!(state.external_edit_epoch(), before_epoch);
                    assert_eq!(state.terminal(), Some(reason));
                    continue;
                }
                if matches!(decision, CoeditDecision::ExternalInsertionAccepted { .. }) {
                    accepted += 1;
                }
                if let CoeditDecision::Terminal(reason) = decision {
                    first_terminal.get_or_insert(reason);
                }
                assert_eq!(state.external_edit_epoch(), accepted);
                assert_eq!(state.terminal(), first_terminal);
                assert!(state.pending_injection_id().is_none());
            }
        }
    }

    #[test]
    fn unavailable_monitor_starts_terminal() {
        let state = state(MixedInputSupport::Unavailable);
        assert_eq!(state.terminal(), Some(TerminalReason::MonitorUnavailable));
    }

    #[test]
    fn deadline_before_expiry_is_neutral() {
        let now = Instant::now();
        let mut state = state(MixedInputSupport::ObservedInsertionsOnly);
        state.arm_pending(pending(1, 1, now, Some(ReceiptConfidence::Posted)));
        assert_eq!(
            state.check_deadline(now + HANDY_RECEIPT_DEADLINE - Duration::from_nanos(1)),
            CoeditDecision::Continue
        );
    }
}
