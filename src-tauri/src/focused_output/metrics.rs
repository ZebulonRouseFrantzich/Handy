use super::types::{FocusedOutputReasonCode, InsertionKind, ReceiptConfidence, TerminalReason};
use std::time::{Duration, Instant};

/// Per-session operational counters. This deliberately contains no transcript,
/// target, key, clipboard, or raw backend data.
#[derive(Clone, Copy, Default)]
pub(crate) struct SessionMetrics {
    started_at: Option<Instant>,
    snapshot_revisions_seen: u64,
    stale_snapshots: u64,
    insertion_units: u64,
    speech_units: u64,
    trailing_space_units: u64,
    verified_accepted_chars: u64,
    posted_units: u64,
    timeouts: u64,
    terminal_reason: Option<TerminalReason>,
    terminal_code: Option<FocusedOutputReasonCode>,
    completed_in: Option<Duration>,
}

impl SessionMetrics {
    pub(crate) fn started() -> Self {
        Self {
            started_at: Some(Instant::now()),
            ..Self::default()
        }
    }

    pub(crate) fn record_snapshot(&mut self, stale: bool) {
        self.snapshot_revisions_seen = self.snapshot_revisions_seen.saturating_add(1);
        if stale {
            self.stale_snapshots = self.stale_snapshots.saturating_add(1);
        }
    }

    pub(crate) fn record_insertion(
        &mut self,
        kind: InsertionKind,
        accepted_chars: usize,
        receipt: ReceiptConfidence,
    ) {
        self.insertion_units = self.insertion_units.saturating_add(1);
        match kind {
            InsertionKind::Speech => {
                self.speech_units = self.speech_units.saturating_add(1);
            }
            InsertionKind::TrailingSpace => {
                self.trailing_space_units = self.trailing_space_units.saturating_add(1);
            }
        }
        match receipt {
            ReceiptConfidence::Verified => {
                self.verified_accepted_chars = self
                    .verified_accepted_chars
                    .saturating_add(u64::try_from(accepted_chars).unwrap_or(u64::MAX));
            }
            ReceiptConfidence::Posted => {
                self.posted_units = self.posted_units.saturating_add(1);
            }
        }
    }

    pub(crate) fn record_timeout(&mut self) {
        self.timeouts = self.timeouts.saturating_add(1);
    }

    pub(crate) fn record_terminal(
        &mut self,
        reason: TerminalReason,
        code: FocusedOutputReasonCode,
    ) {
        if self.terminal_reason.is_none() {
            self.terminal_reason = Some(reason);
            self.terminal_code = Some(code);
        }
    }

    pub(crate) fn complete(&mut self) {
        if self.completed_in.is_none() {
            self.completed_in = self.started_at.map(|started| started.elapsed());
        }
        // Materialize the content-free record so every maintained metric is
        // intentionally observed even when no logger/telemetry sink is wired.
        let _record = (
            self.snapshot_revisions_seen,
            self.stale_snapshots,
            self.insertion_units,
            self.speech_units,
            self.trailing_space_units,
            self.verified_accepted_chars,
            self.posted_units,
            self.timeouts,
            self.terminal_reason,
            self.terminal_code,
            self.completed_in,
        );
    }
}
