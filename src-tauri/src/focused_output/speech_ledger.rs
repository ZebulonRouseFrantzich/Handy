use super::types::{DictationSessionId, InsertOutcome, TerminalReason, TranscriptSnapshot};

/// Speech-only append ledger for one focused-output session.
///
/// This type deliberately does not implement `Debug`: `speech_delivered` is a
/// transcript. The ledger never receives or retains target contents or user
/// input, and all comparisons are exact UTF-8 byte comparisons.
pub struct SpeechLedger {
    session_id: DictationSessionId,
    speech_delivered: String,
    speech_delivered_chars: usize,
    last_revision: Option<u64>,
    conflict_revision: Option<u64>,
    terminal_reason: Option<TerminalReason>,
    pending_append: Option<PendingAppend>,
    finalized: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingAppendKind {
    Live,
    Final,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PendingAppend {
    kind: PendingAppendKind,
    requested_bytes: usize,
}

/// Reconciliation result for one streaming snapshot.
///
/// This type deliberately does not implement `Debug` because `Append` owns a
/// transcript suffix.
#[must_use]
pub enum SnapshotDecision {
    /// The snapshot belongs to another dictation session.
    IgnoredSession,
    /// The revision was stale, duplicated, or contained no new speech.
    Noop,
    /// An insertion receipt must be applied before another snapshot is handled.
    InsertionPending,
    /// Insert exactly this compatible speech suffix.
    Append(String),
    /// The volatile candidate did not extend delivered speech. No text is sent.
    HoldConflict { revision: u64 },
    /// Successful finalization already made the ledger immutable.
    RejectedFinalized,
    /// A permanent terminal condition rejects this and all later snapshots.
    Terminal(TerminalReason),
}

/// Result of applying an insertion receipt or explicitly terminating a ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ApplyDecision {
    /// A live insertion completed and streaming may continue.
    Continue,
    /// A final compatible tail completed exactly once.
    Finalized,
    /// The first permanent terminal reason was retained.
    Terminal(TerminalReason),
    /// No append decision is awaiting an outcome.
    NoPendingInsertion,
    /// Successful finalization already made the ledger immutable.
    AlreadyFinalized,
}

/// Reconciliation result for the final speech transcript.
///
/// This type deliberately does not implement `Debug` because `AppendTail` owns
/// transcript text. Conflict decisions expose no delivered or final contents.
#[must_use]
pub enum FinalDecision {
    /// Insert this one exact suffix, then apply its outcome to the ledger.
    AppendTail(String),
    /// Final speech exactly equals delivered speech.
    Complete,
    /// Final speech conflicts bytewise with delivered speech; preserve output.
    PreserveConflict,
    /// Preserve delivered output because the ledger was already terminal.
    PreserveTerminal(TerminalReason),
    /// A live insertion must complete before final speech can be reconciled.
    InsertionPending,
    /// A final tail has already been issued and awaits its one outcome.
    FinalizationPending,
    /// Finalization has already produced a terminal result.
    AlreadyFinalized,
}

impl SpeechLedger {
    pub fn new(session_id: DictationSessionId) -> Self {
        Self {
            session_id,
            speech_delivered: String::new(),
            speech_delivered_chars: 0,
            last_revision: None,
            conflict_revision: None,
            terminal_reason: None,
            pending_append: None,
            finalized: false,
        }
    }

    pub fn session_id(&self) -> DictationSessionId {
        self.session_id
    }

    pub fn speech_delivered(&self) -> &str {
        &self.speech_delivered
    }

    pub fn speech_delivered_chars(&self) -> usize {
        self.speech_delivered_chars
    }

    pub fn last_revision(&self) -> Option<u64> {
        self.last_revision
    }

    pub fn conflict_revision(&self) -> Option<u64> {
        self.conflict_revision
    }

    pub fn terminal_reason(&self) -> Option<TerminalReason> {
        self.terminal_reason
    }

    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Reconciles one native-streaming snapshot against speech already accepted
    /// by the target backend.
    ///
    /// Only the append suffix is allocated. In particular, committed and
    /// tentative text are compared as two adjacent byte slices rather than
    /// concatenated into a second full candidate.
    pub fn reconcile_snapshot(&mut self, snapshot: &TranscriptSnapshot) -> SnapshotDecision {
        if snapshot.session_id != self.session_id {
            return SnapshotDecision::IgnoredSession;
        }
        if self.finalized {
            return SnapshotDecision::RejectedFinalized;
        }
        if let Some(reason) = self.terminal_reason {
            return SnapshotDecision::Terminal(reason);
        }
        if self.pending_append.is_some() {
            return SnapshotDecision::InsertionPending;
        }
        if self
            .last_revision
            .is_some_and(|revision| snapshot.revision <= revision)
        {
            return SnapshotDecision::Noop;
        }

        self.last_revision = Some(snapshot.revision);
        let Some(suffix) = compatible_snapshot_suffix(
            &self.speech_delivered,
            &snapshot.committed,
            &snapshot.tentative,
        ) else {
            self.conflict_revision = Some(snapshot.revision);
            return SnapshotDecision::HoldConflict {
                revision: snapshot.revision,
            };
        };

        self.conflict_revision = None;
        if suffix.is_empty() {
            SnapshotDecision::Noop
        } else {
            self.pending_append = Some(PendingAppend {
                kind: PendingAppendKind::Live,
                requested_bytes: suffix.len(),
            });
            SnapshotDecision::Append(suffix)
        }
    }

    /// Applies the backend outcome for the single outstanding append decision.
    ///
    /// `Partial.accepted_bytes` is accepted only when it identifies an exact
    /// UTF-8 prefix of `requested`. A malformed backend result is treated as an
    /// ambiguous terminal failure instead of slicing or guessing.
    pub fn apply_insert_outcome(
        &mut self,
        requested: &str,
        outcome: InsertOutcome,
    ) -> ApplyDecision {
        if self.finalized {
            return ApplyDecision::AlreadyFinalized;
        }
        if let Some(reason) = self.terminal_reason {
            return ApplyDecision::Terminal(reason);
        }

        let Some(pending) = self.pending_append.take() else {
            return ApplyDecision::NoPendingInsertion;
        };
        if requested.len() != pending.requested_bytes {
            return self.set_terminal(TerminalReason::AmbiguousInsertion);
        }

        match outcome {
            InsertOutcome::Complete { .. } => {
                self.append_accepted(requested);
                match pending.kind {
                    PendingAppendKind::Live => ApplyDecision::Continue,
                    PendingAppendKind::Final => {
                        self.finalized = true;
                        ApplyDecision::Finalized
                    }
                }
            }
            InsertOutcome::Partial { accepted_bytes, .. } => {
                let Some(accepted) = requested.get(..accepted_bytes) else {
                    return self.set_terminal(TerminalReason::AmbiguousInsertion);
                };
                self.append_accepted(accepted);
                self.set_terminal(TerminalReason::PartialInsertion)
            }
            InsertOutcome::Ambiguous { .. } => {
                self.set_terminal(TerminalReason::AmbiguousInsertion)
            }
            InsertOutcome::Rejected { .. } => self.set_terminal(TerminalReason::TargetInvalidated),
        }
    }

    /// Reconciles processed final speech without modifying delivered output.
    /// A compatible tail is issued at most once and must be completed through
    /// `apply_insert_outcome`.
    pub fn reconcile_final(&mut self, final_text: &str) -> FinalDecision {
        if self.finalized {
            return FinalDecision::AlreadyFinalized;
        }
        if let Some(reason) = self.terminal_reason {
            self.finalized = true;
            return FinalDecision::PreserveTerminal(reason);
        }
        if let Some(pending) = self.pending_append {
            return match pending.kind {
                PendingAppendKind::Live => FinalDecision::InsertionPending,
                PendingAppendKind::Final => FinalDecision::FinalizationPending,
            };
        }

        if final_text == self.speech_delivered {
            self.finalized = true;
            return FinalDecision::Complete;
        }

        if let Some(tail) = final_text.strip_prefix(&self.speech_delivered) {
            self.pending_append = Some(PendingAppend {
                kind: PendingAppendKind::Final,
                requested_bytes: tail.len(),
            });
            return FinalDecision::AppendTail(tail.to_owned());
        }

        self.terminal_reason = Some(TerminalReason::FinalConflict);
        self.finalized = true;
        FinalDecision::PreserveConflict
    }

    /// Sets the first permanent terminal reason and cancels any unacknowledged
    /// append. Later calls cannot replace that reason.
    pub fn terminate(&mut self, reason: TerminalReason) -> ApplyDecision {
        if self.finalized {
            return ApplyDecision::AlreadyFinalized;
        }
        if let Some(existing) = self.terminal_reason {
            return ApplyDecision::Terminal(existing);
        }
        self.pending_append = None;
        self.set_terminal(reason)
    }

    fn append_accepted(&mut self, accepted: &str) {
        self.speech_delivered.push_str(accepted);
        self.speech_delivered_chars += accepted.chars().count();
    }

    fn set_terminal(&mut self, reason: TerminalReason) -> ApplyDecision {
        let retained = *self.terminal_reason.get_or_insert(reason);
        ApplyDecision::Terminal(retained)
    }
}

/// Returns the one suffix following `delivered` in `committed + tentative`, or
/// `None` when that two-slice candidate does not begin with `delivered`.
fn compatible_snapshot_suffix(delivered: &str, committed: &str, tentative: &str) -> Option<String> {
    let delivered_bytes = delivered.as_bytes();
    let committed_bytes = committed.as_bytes();
    let tentative_bytes = tentative.as_bytes();
    let candidate_len = committed_bytes.len().checked_add(tentative_bytes.len())?;

    if delivered_bytes.len() > candidate_len {
        return None;
    }

    let delivered_in_committed = delivered_bytes.len().min(committed_bytes.len());
    if delivered_bytes[..delivered_in_committed] != committed_bytes[..delivered_in_committed] {
        return None;
    }

    if delivered_bytes.len() > committed_bytes.len() {
        let delivered_in_tentative = delivered_bytes.len() - committed_bytes.len();
        if delivered_bytes[committed_bytes.len()..] != tentative_bytes[..delivered_in_tentative] {
            return None;
        }
    }

    let suffix_len = candidate_len - delivered_bytes.len();
    let mut suffix = String::with_capacity(suffix_len);
    if delivered_bytes.len() < committed_bytes.len() {
        suffix.push_str(&committed[delivered_bytes.len()..]);
        suffix.push_str(tentative);
    } else {
        suffix.push_str(&tentative[delivered_bytes.len() - committed_bytes.len()..]);
    }
    Some(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focused_output::types::{FocusedOutputReasonCode, ReceiptConfidence};

    const SESSION: DictationSessionId = DictationSessionId(7);
    const OTHER_SESSION: DictationSessionId = DictationSessionId(8);

    fn snapshot(
        session_id: DictationSessionId,
        revision: u64,
        committed: &str,
        tentative: &str,
    ) -> TranscriptSnapshot {
        TranscriptSnapshot {
            session_id,
            revision,
            committed: committed.to_owned(),
            tentative: tentative.to_owned(),
        }
    }

    fn complete() -> InsertOutcome {
        InsertOutcome::Complete {
            receipt: ReceiptConfidence::Verified,
        }
    }

    fn partial(accepted_bytes: usize) -> InsertOutcome {
        InsertOutcome::Partial {
            accepted_bytes,
            receipt: ReceiptConfidence::Verified,
            reason: FocusedOutputReasonCode::InjectionPartial,
        }
    }

    fn take_append(decision: SnapshotDecision) -> String {
        match decision {
            SnapshotDecision::Append(suffix) => suffix,
            _ => panic!("expected append decision"),
        }
    }

    fn deliver_snapshot(ledger: &mut SpeechLedger, snapshot: &TranscriptSnapshot) -> String {
        let suffix = take_append(ledger.reconcile_snapshot(snapshot));
        assert_eq!(
            ledger.apply_insert_outcome(&suffix, complete()),
            ApplyDecision::Continue
        );
        suffix
    }

    #[test]
    fn revision_zero_empty_and_first_growth_are_accepted() {
        let mut ledger = SpeechLedger::new(SESSION);
        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(SESSION, 0, "", "")),
            SnapshotDecision::Noop
        ));
        assert_eq!(ledger.last_revision(), Some(0));

        let suffix = deliver_snapshot(&mut ledger, &snapshot(SESSION, 1, "hel", "lo"));
        assert_eq!(suffix, "hello");
        assert_eq!(ledger.speech_delivered(), "hello");
        assert_eq!(ledger.speech_delivered_chars(), 5);
    }

    #[test]
    fn duplicate_and_out_of_order_revisions_are_noops() {
        let mut ledger = SpeechLedger::new(SESSION);
        deliver_snapshot(&mut ledger, &snapshot(SESSION, 4, "four", ""));
        let before = ledger.speech_delivered().to_owned();

        for stale in [4, 3, 0] {
            assert!(matches!(
                ledger.reconcile_snapshot(&snapshot(SESSION, stale, "four changed", "")),
                SnapshotDecision::Noop
            ));
            assert_eq!(ledger.speech_delivered(), before);
            assert_eq!(ledger.last_revision(), Some(4));
        }

        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(SESSION, 5, "four", "")),
            SnapshotDecision::Noop
        ));
        assert_eq!(ledger.last_revision(), Some(5));
    }

    #[test]
    fn wrong_session_does_not_mutate_revision_or_text() {
        let mut ledger = SpeechLedger::new(SESSION);
        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(OTHER_SESSION, u64::MAX, "foreign", "")),
            SnapshotDecision::IgnoredSession
        ));
        assert_eq!(ledger.last_revision(), None);
        assert_eq!(ledger.speech_delivered(), "");

        let mut replacement = SpeechLedger::new(OTHER_SESSION);
        deliver_snapshot(
            &mut replacement,
            &snapshot(OTHER_SESSION, 0, "replacement", ""),
        );
        assert_eq!(replacement.speech_delivered(), "replacement");
        assert_eq!(ledger.speech_delivered(), "");
    }

    #[test]
    fn volatile_conflict_holds_then_recovers() {
        let mut ledger = SpeechLedger::new(SESSION);
        deliver_snapshot(
            &mut ledger,
            &snapshot(SESSION, 0, "I think we should change the", ""),
        );

        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(
                SESSION,
                1,
                "I think we should change this API",
                ""
            )),
            SnapshotDecision::HoldConflict { revision: 1 }
        ));
        assert_eq!(ledger.conflict_revision(), Some(1));
        assert_eq!(ledger.speech_delivered(), "I think we should change the");

        let suffix = deliver_snapshot(
            &mut ledger,
            &snapshot(SESSION, 2, "I think we should change the API", " endpoint"),
        );
        assert_eq!(suffix, " API endpoint");
        assert_eq!(ledger.conflict_revision(), None);
    }

    #[test]
    fn committed_prefix_can_catch_up_without_duplicate_output() {
        let mut ledger = SpeechLedger::new(SESSION);
        deliver_snapshot(&mut ledger, &snapshot(SESSION, 0, "", "hello"));
        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(SESSION, 1, "hello", "")),
            SnapshotDecision::Noop
        ));
        let suffix = deliver_snapshot(&mut ledger, &snapshot(SESSION, 2, "hello", " world"));
        assert_eq!(suffix, " world");
        assert_eq!(ledger.speech_delivered(), "hello world");
    }

    #[test]
    fn pending_live_append_blocks_overlapping_snapshot() {
        let mut ledger = SpeechLedger::new(SESSION);
        let suffix = take_append(ledger.reconcile_snapshot(&snapshot(SESSION, 0, "one", "")));
        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(SESSION, 1, "one two", "")),
            SnapshotDecision::InsertionPending
        ));
        assert_eq!(ledger.last_revision(), Some(0));
        assert_eq!(
            ledger.apply_insert_outcome(&suffix, complete()),
            ApplyDecision::Continue
        );
        assert_eq!(
            deliver_snapshot(&mut ledger, &snapshot(SESSION, 1, "one two", "")),
            " two"
        );
    }

    #[test]
    fn partial_appends_only_exact_utf8_prefix_and_terminates() {
        let mut ledger = SpeechLedger::new(SESSION);
        let requested = take_append(ledger.reconcile_snapshot(&snapshot(SESSION, 0, "é🙂字", "")));
        assert_eq!(
            ledger.apply_insert_outcome(&requested, partial("é🙂".len())),
            ApplyDecision::Terminal(TerminalReason::PartialInsertion)
        );
        assert_eq!(ledger.speech_delivered(), "é🙂");
        assert_eq!(ledger.speech_delivered_chars(), 2);
        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(SESSION, 1, "é🙂字 more", "")),
            SnapshotDecision::Terminal(TerminalReason::PartialInsertion)
        ));
    }

    #[test]
    fn invalid_partial_byte_boundary_is_ambiguous_without_append() {
        let mut ledger = SpeechLedger::new(SESSION);
        let requested = take_append(ledger.reconcile_snapshot(&snapshot(SESSION, 0, "é", "")));
        assert_eq!(
            ledger.apply_insert_outcome(&requested, partial(1)),
            ApplyDecision::Terminal(TerminalReason::AmbiguousInsertion)
        );
        assert_eq!(ledger.speech_delivered(), "");
    }

    #[test]
    fn oversized_partial_and_mismatched_request_are_ambiguous() {
        let mut oversized = SpeechLedger::new(SESSION);
        let requested = take_append(oversized.reconcile_snapshot(&snapshot(SESSION, 0, "abc", "")));
        assert_eq!(
            oversized.apply_insert_outcome(&requested, partial(4)),
            ApplyDecision::Terminal(TerminalReason::AmbiguousInsertion)
        );
        assert_eq!(oversized.speech_delivered(), "");

        let mut mismatched = SpeechLedger::new(SESSION);
        let _ = mismatched.reconcile_snapshot(&snapshot(SESSION, 0, "abc", ""));
        assert_eq!(
            mismatched.apply_insert_outcome("wrong length", complete()),
            ApplyDecision::Terminal(TerminalReason::AmbiguousInsertion)
        );
        assert_eq!(mismatched.speech_delivered(), "");
    }

    #[test]
    fn ambiguous_and_rejected_outcomes_never_guess_or_retry() {
        let mut ambiguous = SpeechLedger::new(SESSION);
        let requested = take_append(ambiguous.reconcile_snapshot(&snapshot(SESSION, 0, "abc", "")));
        assert_eq!(
            ambiguous.apply_insert_outcome(
                &requested,
                InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                },
            ),
            ApplyDecision::Terminal(TerminalReason::AmbiguousInsertion)
        );
        assert_eq!(ambiguous.speech_delivered(), "");

        let mut rejected = SpeechLedger::new(SESSION);
        let requested = take_append(rejected.reconcile_snapshot(&snapshot(SESSION, 0, "abc", "")));
        assert_eq!(
            rejected.apply_insert_outcome(
                &requested,
                InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::TargetChanged,
                },
            ),
            ApplyDecision::Terminal(TerminalReason::TargetInvalidated)
        );
        assert_eq!(rejected.speech_delivered(), "");
    }

    #[test]
    fn explicit_terminal_reason_is_first_and_permanent() {
        let mut ledger = SpeechLedger::new(SESSION);
        assert_eq!(
            ledger.terminate(TerminalReason::Cancelled),
            ApplyDecision::Terminal(TerminalReason::Cancelled)
        );
        assert_eq!(
            ledger.terminate(TerminalReason::StreamFailed),
            ApplyDecision::Terminal(TerminalReason::Cancelled)
        );
        assert!(matches!(
            ledger.reconcile_snapshot(&snapshot(SESSION, 0, "later", "")),
            SnapshotDecision::Terminal(TerminalReason::Cancelled)
        ));
    }

    #[test]
    fn exact_final_and_compatible_tail_finalize_once() {
        let mut exact = SpeechLedger::new(SESSION);
        deliver_snapshot(&mut exact, &snapshot(SESSION, 0, "hello", ""));
        assert!(matches!(
            exact.reconcile_final("hello"),
            FinalDecision::Complete
        ));
        assert!(exact.is_finalized());
        assert!(matches!(
            exact.reconcile_snapshot(&snapshot(SESSION, 1, "hello again", "")),
            SnapshotDecision::RejectedFinalized
        ));

        let mut tail = SpeechLedger::new(SESSION);
        deliver_snapshot(&mut tail, &snapshot(SESSION, 0, "hel", ""));
        let requested = match tail.reconcile_final("hello") {
            FinalDecision::AppendTail(tail) => tail,
            _ => panic!("expected final tail"),
        };
        assert_eq!(requested, "lo");
        assert!(matches!(
            tail.reconcile_final("hello"),
            FinalDecision::FinalizationPending
        ));
        assert_eq!(
            tail.apply_insert_outcome(&requested, complete()),
            ApplyDecision::Finalized
        );
        assert_eq!(tail.speech_delivered(), "hello");
        assert!(matches!(
            tail.reconcile_final("hello"),
            FinalDecision::AlreadyFinalized
        ));
    }

    #[test]
    fn final_conflicts_preserve_delivered_text() {
        for final_text in ["hell", "help", ""] {
            let mut ledger = SpeechLedger::new(SESSION);
            deliver_snapshot(&mut ledger, &snapshot(SESSION, 0, "hello", ""));
            assert!(matches!(
                ledger.reconcile_final(final_text),
                FinalDecision::PreserveConflict
            ));
            assert_eq!(ledger.speech_delivered(), "hello");
            assert_eq!(
                ledger.terminal_reason(),
                Some(TerminalReason::FinalConflict)
            );
            assert!(ledger.is_finalized());
        }
    }

    #[test]
    fn empty_ledger_accepts_one_nonempty_final_tail() {
        let mut ledger = SpeechLedger::new(SESSION);
        let requested = match ledger.reconcile_final("final only") {
            FinalDecision::AppendTail(tail) => tail,
            _ => panic!("expected final tail"),
        };
        assert_eq!(requested, "final only");
        assert_eq!(
            ledger.apply_insert_outcome(&requested, complete()),
            ApplyDecision::Finalized
        );
        assert_eq!(ledger.speech_delivered(), "final only");
    }

    #[test]
    fn partial_final_tail_preserves_exact_prefix() {
        let mut ledger = SpeechLedger::new(SESSION);
        deliver_snapshot(&mut ledger, &snapshot(SESSION, 0, "hello", ""));
        let requested = match ledger.reconcile_final("hello 世界") {
            FinalDecision::AppendTail(tail) => tail,
            _ => panic!("expected final tail"),
        };
        assert_eq!(
            ledger.apply_insert_outcome(&requested, partial(" 世".len())),
            ApplyDecision::Terminal(TerminalReason::PartialInsertion)
        );
        assert_eq!(ledger.speech_delivered(), "hello 世");
        assert!(matches!(
            ledger.reconcile_final("hello 世界"),
            FinalDecision::PreserveTerminal(TerminalReason::PartialInsertion)
        ));
    }

    #[test]
    fn final_barrier_waits_for_live_receipt_then_reconciles_latest_text() {
        let mut ledger = SpeechLedger::new(SESSION);
        let live = take_append(ledger.reconcile_snapshot(&snapshot(SESSION, 12, "barrier", "")));
        assert!(matches!(
            ledger.reconcile_final("barrier tail"),
            FinalDecision::InsertionPending
        ));
        assert_eq!(
            ledger.apply_insert_outcome(&live, complete()),
            ApplyDecision::Continue
        );
        let tail = match ledger.reconcile_final("barrier tail") {
            FinalDecision::AppendTail(tail) => tail,
            _ => panic!("expected post-barrier final tail"),
        };
        assert_eq!(tail, " tail");
        assert_eq!(
            ledger.apply_insert_outcome(&tail, complete()),
            ApplyDecision::Finalized
        );
        assert_eq!(ledger.speech_delivered(), "barrier tail");
    }

    #[test]
    fn final_ambiguous_and_rejected_outcomes_preserve_live_speech() {
        let cases = [
            (
                InsertOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                },
                TerminalReason::AmbiguousInsertion,
            ),
            (
                InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::TargetChanged,
                },
                TerminalReason::TargetInvalidated,
            ),
        ];

        for (outcome, expected_reason) in cases {
            let mut ledger = SpeechLedger::new(SESSION);
            deliver_snapshot(&mut ledger, &snapshot(SESSION, 0, "live", ""));
            let tail = match ledger.reconcile_final("live final") {
                FinalDecision::AppendTail(tail) => tail,
                _ => panic!("expected final tail"),
            };
            assert_eq!(
                ledger.apply_insert_outcome(&tail, outcome),
                ApplyDecision::Terminal(expected_reason)
            );
            assert_eq!(ledger.speech_delivered(), "live");
            assert!(matches!(
                ledger.reconcile_final("live final"),
                FinalDecision::PreserveTerminal(reason) if reason == expected_reason
            ));
        }
    }

    #[test]
    fn user_text_and_voice_keyboard_alternations_never_enter_speech_ledger() {
        let mut ledger = SpeechLedger::new(SESSION);
        let mut user_target_text = String::from("pre-existing:");

        assert_eq!(
            deliver_snapshot(&mut ledger, &snapshot(SESSION, 0, "voice one", "")),
            "voice one"
        );
        user_target_text.push_str("[typed α]");
        assert_eq!(
            deliver_snapshot(
                &mut ledger,
                &snapshot(SESSION, 1, "voice one voice two", "")
            ),
            " voice two"
        );
        user_target_text.push_str("[typed β]");
        assert_eq!(
            deliver_snapshot(
                &mut ledger,
                &snapshot(SESSION, 2, "voice one voice two voice three", "")
            ),
            " voice three"
        );

        assert_eq!(ledger.speech_delivered(), "voice one voice two voice three");
        assert!(!ledger.speech_delivered().contains("typed"));
        assert_eq!(user_target_text, "pre-existing:[typed α][typed β]");
    }

    #[test]
    fn empty_final_on_empty_ledger_completes_without_insertion() {
        let mut ledger = SpeechLedger::new(SESSION);
        assert!(matches!(
            ledger.reconcile_final(""),
            FinalDecision::Complete
        ));
        assert_eq!(ledger.speech_delivered(), "");
        assert!(ledger.is_finalized());
        assert_eq!(
            ledger.apply_insert_outcome("", complete()),
            ApplyDecision::AlreadyFinalized
        );
    }

    #[test]
    fn bytewise_semantics_preserve_whitespace_and_unicode_forms() {
        let cases = [
            " leading  and trailing ",
            "line one\n\tline two",
            "emoji 😀 and supplementary 𐐷",
            "e\u{301}",
            "漢字かな交じり文",
            "العربية עברית",
        ];

        for (index, text) in cases.iter().enumerate() {
            let mut ledger = SpeechLedger::new(DictationSessionId(index as u64));
            deliver_snapshot(
                &mut ledger,
                &snapshot(DictationSessionId(index as u64), 0, "", text),
            );
            assert_eq!(ledger.speech_delivered(), *text);
            assert_eq!(ledger.speech_delivered_chars(), text.chars().count());
        }

        let mut normalization = SpeechLedger::new(SESSION);
        deliver_snapshot(&mut normalization, &snapshot(SESSION, 0, "é", ""));
        assert!(matches!(
            normalization.reconcile_snapshot(&snapshot(SESSION, 1, "e\u{301}", "")),
            SnapshotDecision::HoldConflict { revision: 1 }
        ));
    }

    #[test]
    fn very_long_and_coalesced_snapshots_emit_only_suffixes() {
        let mut ledger = SpeechLedger::new(SESSION);
        let long = "界".repeat(32_768);
        let first = &long[..long.len() / 2];
        deliver_snapshot(&mut ledger, &snapshot(SESSION, 0, first, ""));
        let suffix = deliver_snapshot(&mut ledger, &snapshot(SESSION, 50, &long, " done"));
        assert_eq!(suffix, format!("{} done", &long[first.len()..]));
        assert_eq!(ledger.speech_delivered(), format!("{long} done"));
    }

    #[test]
    fn deterministic_unicode_sequences_preserve_ledger_invariants() {
        const ALPHABET: [char; 14] = [
            'a', ' ', '\n', '\t', 'é', '\u{301}', '🙂', '𐐷', '漢', '字', 'ع', 'ב', 'क', '界',
        ];

        for seed in 0..96_u64 {
            let mut state = seed.wrapping_add(1);
            let mut candidate = String::new();
            for _ in 0..48 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                candidate.push(ALPHABET[(state as usize) % ALPHABET.len()]);
            }

            let session = DictationSessionId(seed);
            let mut ledger = SpeechLedger::new(session);
            let boundaries: Vec<usize> = candidate
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(candidate.len()))
                .collect();
            let mut revision = 0_u64;

            for &end in boundaries.iter().skip(1).step_by(3) {
                let previous = ledger.speech_delivered().to_owned();
                let current = &candidate[..end];
                let split = current
                    .char_indices()
                    .nth(current.chars().count() / 2)
                    .map_or(current.len(), |(index, _)| index);
                let suffix = deliver_snapshot(
                    &mut ledger,
                    &snapshot(session, revision, &current[..split], &current[split..]),
                );
                assert!(current.starts_with(&previous));
                assert_eq!(suffix, &current[previous.len()..]);
                assert!(ledger.speech_delivered().starts_with(&previous));
                assert!(std::str::from_utf8(ledger.speech_delivered().as_bytes()).is_ok());

                let before_stale = ledger.speech_delivered().to_owned();
                assert!(matches!(
                    ledger.reconcile_snapshot(&snapshot(session, revision, "conflict", "")),
                    SnapshotDecision::Noop
                ));
                assert_eq!(ledger.speech_delivered(), before_stale);
                revision += 1;
            }

            if ledger.speech_delivered() != candidate {
                let previous = ledger.speech_delivered().to_owned();
                let suffix =
                    deliver_snapshot(&mut ledger, &snapshot(session, revision, &candidate, ""));
                assert_eq!(suffix, &candidate[previous.len()..]);
            }
            assert_eq!(ledger.speech_delivered(), candidate);
            assert_eq!(ledger.speech_delivered_chars(), candidate.chars().count());

            let final_text = format!("{candidate}終");
            let final_tail = match ledger.reconcile_final(&final_text) {
                FinalDecision::AppendTail(tail) => tail,
                _ => panic!("expected one final tail"),
            };
            assert_eq!(final_tail, "終");
            assert!(matches!(
                ledger.reconcile_final(&final_text),
                FinalDecision::FinalizationPending
            ));
            assert_eq!(
                ledger.apply_insert_outcome(&final_tail, complete()),
                ApplyDecision::Finalized
            );
            assert_eq!(ledger.speech_delivered(), final_text);
            assert!(matches!(
                ledger.reconcile_snapshot(&snapshot(session, revision + 1, &final_text, "more")),
                SnapshotDecision::RejectedFinalized
            ));
        }
    }
}
