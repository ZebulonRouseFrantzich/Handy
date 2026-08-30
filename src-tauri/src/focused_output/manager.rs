use super::coediting::{AttributionScope, CoeditDecision, CoeditingState, InteractionEvidence};
use super::metrics::SessionMetrics;
use super::observer::{StreamLifecycleEvent, StreamObserverError};
use super::platform::{BeginSession, FocusedFieldBackend, FocusedTargetSession, SessionEventSink};
use super::speech_ledger::{ApplyDecision, FinalDecision, SnapshotDecision, SpeechLedger};
use super::types::*;
use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const EVENT_QUEUE_CAPACITY: usize = 128;
const LIFECYCLE_QUEUE_CAPACITY: usize = 16;
const TERMINAL_QUEUE_CAPACITY: usize = 16;
const CONTROL_QUEUE_CAPACITY: usize = 4;
const MAX_INSERTION_SCALARS: usize = 16;
const MANAGER_WAIT: Duration = Duration::from_secs(2);

/// Tauri-free destination for content-free lifecycle transitions.
pub trait FocusedOutputStatusSink: Send + Sync {
    fn publish(&self, event: &FocusedOutputStatusEvent);
}

#[derive(Default)]
pub struct NoopFocusedOutputStatusSink;

impl FocusedOutputStatusSink for NoopFocusedOutputStatusSink {
    fn publish(&self, _event: &FocusedOutputStatusEvent) {}
}

struct SessionEventEnvelope {
    session_id: DictationSessionId,
    event: TargetInteractionEvent,
}

#[derive(Clone, Copy)]
struct TerminalEnvelope {
    session_id: DictationSessionId,
    reason: TerminalReason,
}

enum ControlMessage {
    Finalize {
        session_id: DictationSessionId,
        final_text: String,
        barrier_revision: Option<u64>,
        options: FinalizeOptions,
        response: Sender<FinalDeliveryDisposition>,
    },
    FinishNoText {
        session_id: DictationSessionId,
        response: Sender<()>,
    },
    Shutdown {
        response: Sender<()>,
    },
}

struct ManagerEventSink {
    events: Sender<SessionEventEnvelope>,
    wake: Sender<()>,
    overflow_session: Arc<AtomicU64>,
    active_session: Arc<AtomicU64>,
    cancellation: SessionCancellation,
}

impl SessionEventSink for ManagerEventSink {
    fn publish(&self, session_id: DictationSessionId, event: TargetInteractionEvent) {
        if self.active_session.load(Ordering::Acquire) != session_id.get() {
            return;
        }
        if matches!(
            event,
            TargetInteractionEvent::UnsafeEdit { .. }
                | TargetInteractionEvent::TargetInvalidated { .. }
                | TargetInteractionEvent::MonitorUnavailable { .. }
        ) {
            self.cancellation.cancel();
        }
        match self
            .events
            .try_send(SessionEventEnvelope { session_id, event })
        {
            Ok(()) => {}
            Err(TrySendError::Full(envelope)) => {
                let _ = self.overflow_session.compare_exchange(
                    0,
                    envelope.session_id.get(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            Err(TrySendError::Disconnected(_)) => return,
        }
        let _ = self.wake.try_send(());
    }
}

enum OutputPlan {
    Fallback {
        session_id: DictationSessionId,
        authority: FallbackAuthority,
    },
    Armed(ArmedSession),
}

impl OutputPlan {
    fn session_id(&self) -> DictationSessionId {
        match self {
            Self::Fallback { session_id, .. } => *session_id,
            Self::Armed(session) => session.session_id,
        }
    }
}

struct ArmedSession {
    session_id: DictationSessionId,
    target: Box<dyn FocusedTargetSession>,
    capability: FocusedOutputCapability,
    target_application: Option<String>,
    receipt_confidence: ReceiptConfidence,
    cancellation: SessionCancellation,
    ledger: SpeechLedger,
    coediting: CoeditingState,
    next_injection_id: u64,
    terminal_reason: Option<TerminalReason>,
    terminal_code: Option<FocusedOutputReasonCode>,
    closed: bool,
    metrics: SessionMetrics,
}

impl ArmedSession {
    fn new(
        session_id: DictationSessionId,
        target: Box<dyn FocusedTargetSession>,
        capability: FocusedOutputCapability,
        target_application: Option<String>,
        cancellation: SessionCancellation,
    ) -> Self {
        let scope = AttributionScope {
            session_id,
            generation: session_id.get(),
            source_marker: session_id.get() ^ 0xa5a5_5a5a_d3c3_b4b4,
        };
        let receipt_confidence = capability
            .route()
            .map(|route| route.receipt_confidence)
            .unwrap_or(ReceiptConfidence::Posted);
        Self {
            session_id,
            target,
            coediting: CoeditingState::new(scope, capability.mixed_input_support()),
            capability,
            receipt_confidence,
            target_application,
            cancellation,
            ledger: SpeechLedger::new(session_id),
            next_injection_id: 1,
            terminal_reason: None,
            terminal_code: None,
            closed: false,
            metrics: SessionMetrics::started(),
        }
    }

    fn next_injection_id(&mut self) -> InjectionId {
        let id = InjectionId(self.next_injection_id);
        self.next_injection_id = self.next_injection_id.saturating_add(1);
        id
    }

    fn set_terminal(&mut self, reason: TerminalReason, code: FocusedOutputReasonCode) {
        if self.terminal_reason.is_some() {
            return;
        }
        self.terminal_reason = Some(reason);
        self.terminal_code = Some(code);
        let _ = self.ledger.terminate(reason);
        let _ = self.coediting.terminate(reason);
        self.metrics.record_terminal(reason, code);
        if code == FocusedOutputReasonCode::ReceiptTimeout {
            self.metrics.record_timeout();
        }
        self.cancellation.cancel();
        self.close();
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.cancellation.cancel();
        self.target.close();
    }

    fn external_edit_epoch(&self) -> u64 {
        self.coediting.external_edit_epoch()
    }

    fn status(
        &self,
        status: FocusedOutputStatus,
        history_available: bool,
    ) -> FocusedOutputStatusEvent {
        FocusedOutputStatusEvent {
            session_id: self.session_id,
            status,
            reason: self.terminal_code,
            capability: (!self.closed).then(|| self.capability.clone()),
            target_application: (!self.closed)
                .then(|| self.target_application.clone())
                .flatten(),
            speech_delivered_chars: self.ledger.speech_delivered_chars(),
            external_edit_epoch: self.external_edit_epoch(),
            history_available,
        }
    }
}

struct ManagerState {
    plan: Option<OutputPlan>,
    beginning: Option<DictationSessionId>,
    latest_status: Option<FocusedOutputStatusEvent>,
    status_sink: Arc<dyn FocusedOutputStatusSink>,
}

impl ManagerState {
    fn new(status_sink: Arc<dyn FocusedOutputStatusSink>) -> Self {
        Self {
            plan: None,
            beginning: None,
            latest_status: None,
            status_sink,
        }
    }

    fn set_status(&mut self, event: FocusedOutputStatusEvent) {
        if self.latest_status.as_ref() == Some(&event) {
            return;
        }
        self.status_sink.publish(&event);
        self.latest_status = Some(event);
    }
}

/// Owns the one fallback or armed focused-output plan for the process.
pub struct FocusedOutputManager {
    backend: Arc<dyn FocusedFieldBackend>,
    state: Arc<Mutex<ManagerState>>,
    latest_snapshot: Arc<Mutex<Option<TranscriptSnapshot>>>,
    event_tx: Sender<SessionEventEnvelope>,
    lifecycle_tx: Sender<StreamLifecycleEvent>,
    terminal_tx: Sender<TerminalEnvelope>,
    wake_tx: Sender<()>,
    control_tx: Sender<ControlMessage>,
    active_session: Arc<AtomicU64>,
    active_cancellation: Arc<Mutex<Option<(DictationSessionId, SessionCancellation)>>>,
    next_session_id: AtomicU64,
    closed: Arc<AtomicBool>,
    overflow_session: Arc<AtomicU64>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl FocusedOutputManager {
    pub fn new(backend: Arc<dyn FocusedFieldBackend>) -> Arc<Self> {
        Self::new_with_status_sink(backend, Arc::new(NoopFocusedOutputStatusSink))
    }

    pub fn new_with_status_sink(
        backend: Arc<dyn FocusedFieldBackend>,
        status_sink: Arc<dyn FocusedOutputStatusSink>,
    ) -> Arc<Self> {
        let (event_tx, event_rx) = bounded(EVENT_QUEUE_CAPACITY);
        let (lifecycle_tx, lifecycle_rx) = bounded(LIFECYCLE_QUEUE_CAPACITY);
        let (terminal_tx, terminal_rx) = bounded(TERMINAL_QUEUE_CAPACITY);
        let (wake_tx, wake_rx) = bounded(1);
        let (control_tx, control_rx) = bounded(CONTROL_QUEUE_CAPACITY);
        let state = Arc::new(Mutex::new(ManagerState::new(status_sink)));
        let latest_snapshot = Arc::new(Mutex::new(None));
        let active_session = Arc::new(AtomicU64::new(0));
        let active_cancellation = Arc::new(Mutex::new(None));
        let closed = Arc::new(AtomicBool::new(false));
        let overflow_session = Arc::new(AtomicU64::new(0));

        let worker_state = Arc::clone(&state);
        let worker_latest = Arc::clone(&latest_snapshot);
        let worker_active = Arc::clone(&active_session);
        let worker_cancellation = Arc::clone(&active_cancellation);
        let worker_overflow = Arc::clone(&overflow_session);
        let worker_backend = Arc::clone(&backend);
        let worker = thread::Builder::new()
            .name("focused-output".to_owned())
            .spawn(move || {
                worker_loop(
                    worker_backend,
                    worker_state,
                    worker_latest,
                    event_rx,
                    lifecycle_rx,
                    terminal_rx,
                    wake_rx,
                    control_rx,
                    worker_active,
                    worker_cancellation,
                    worker_overflow,
                );
            })
            .ok();
        if worker.is_none() {
            closed.store(true, Ordering::Release);
            backend.shutdown();
        }

        Arc::new(Self {
            backend,
            state,
            latest_snapshot,
            event_tx,
            lifecycle_tx,
            terminal_tx,
            wake_tx,
            control_tx,
            active_session,
            active_cancellation,
            next_session_id: AtomicU64::new(1),
            closed,
            overflow_session,
            worker: Mutex::new(worker),
        })
    }

    pub fn allocate_session_id(&self) -> DictationSessionId {
        DictationSessionId(self.next_session_id.fetch_add(1, Ordering::Relaxed))
    }

    pub fn register_fallback(
        &self,
        session_id: DictationSessionId,
    ) -> Result<(), FocusedOutputReasonCode> {
        if self.closed.load(Ordering::Acquire) {
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }
        let mut state = lock_recover(&self.state);
        if state.plan.is_some() || state.beginning.is_some() {
            return Err(FocusedOutputReasonCode::AlreadyActive);
        }
        state.plan = Some(OutputPlan::Fallback {
            session_id,
            authority: FallbackAuthority::new(),
        });
        state.set_status(FocusedOutputStatusEvent {
            session_id,
            status: FocusedOutputStatus::Fallback,
            reason: None,
            capability: None,
            target_application: None,
            speech_delivered_chars: 0,
            external_edit_epoch: 0,
            history_available: false,
        });
        self.active_session
            .store(session_id.get(), Ordering::Release);
        Ok(())
    }

    pub fn begin(&self, context: BeginContext) -> Result<BeginReceipt, FocusedOutputReasonCode> {
        if self.closed.load(Ordering::Acquire) {
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }
        let session_id = context.session_id;
        let auto_submit_requested = context.auto_submit_requested;
        let upgrading_fallback = {
            let mut state = lock_recover(&self.state);
            if state.beginning.is_some() {
                return Err(FocusedOutputReasonCode::AlreadyActive);
            }
            let upgrading = match state.plan.as_ref() {
                None => false,
                Some(OutputPlan::Fallback {
                    session_id: fallback_id,
                    ..
                }) if *fallback_id == session_id => true,
                Some(_) => return Err(FocusedOutputReasonCode::AlreadyActive),
            };
            state.beginning = Some(session_id);
            upgrading
        };
        self.active_session
            .store(session_id.get(), Ordering::Release);
        let cancellation = SessionCancellation::default();
        *lock_recover(&self.active_cancellation) = Some((session_id, cancellation.clone()));
        let sink: Arc<dyn SessionEventSink> = Arc::new(ManagerEventSink {
            events: self.event_tx.clone(),
            wake: self.wake_tx.clone(),
            overflow_session: Arc::clone(&self.overflow_session),
            active_session: Arc::clone(&self.active_session),
            cancellation: cancellation.clone(),
        });

        let result = self.backend.begin(context, sink, cancellation.clone());
        let BeginSession {
            receipt,
            mut session,
        } = match result {
            Ok(session) => session,
            Err(reason) => {
                if cancellation.is_cancelled()
                    || self.active_session.load(Ordering::Acquire) != session_id.get()
                {
                    self.clear_cancelled_begin(session_id);
                    return Err(FocusedOutputReasonCode::Cancelled);
                }
                self.clear_failed_begin(session_id, reason);
                return Err(reason);
            }
        };
        if cancellation.is_cancelled()
            || self.active_session.load(Ordering::Acquire) != session_id.get()
        {
            session.close();
            self.clear_cancelled_begin(session_id);
            return Err(FocusedOutputReasonCode::Cancelled);
        }
        if receipt.session_id() != session_id || !receipt.capability().is_resolved() {
            session.close();
            self.clear_failed_begin(session_id, FocusedOutputReasonCode::TargetChanged);
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        if receipt.capability() != session.capability() {
            session.close();
            self.clear_failed_begin(session_id, FocusedOutputReasonCode::TargetChanged);
            return Err(FocusedOutputReasonCode::TargetChanged);
        }
        let (_, capability, target_application) = receipt.clone().into_parts();
        if auto_submit_requested && !capability.supports_auto_submit() {
            session.close();
            self.clear_failed_begin(session_id, FocusedOutputReasonCode::AutoSubmitUnsupported);
            return Err(FocusedOutputReasonCode::AutoSubmitUnsupported);
        }

        let mut state = lock_recover(&self.state);
        let plan_is_expected = if upgrading_fallback {
            matches!(
                state.plan.as_ref(),
                Some(OutputPlan::Fallback {
                    session_id: fallback_id,
                    ..
                }) if *fallback_id == session_id
            )
        } else {
            state.plan.is_none()
        };
        if state.beginning != Some(session_id) || !plan_is_expected {
            session.close();
            if state.beginning == Some(session_id) {
                state.beginning = None;
            }
            drop(state);
            self.clear_active_identity(session_id);
            return Err(FocusedOutputReasonCode::AlreadyActive);
        }
        state.beginning = None;
        let armed = ArmedSession::new(
            session_id,
            session,
            capability.clone(),
            target_application,
            cancellation,
        );
        state.set_status(armed.status(FocusedOutputStatus::Armed, false));
        state.plan = Some(OutputPlan::Armed(armed));
        Ok(receipt)
    }

    fn clear_cancelled_begin(&self, session_id: DictationSessionId) {
        let mut state = lock_recover(&self.state);
        if state.beginning == Some(session_id) {
            state.beginning = None;
        }
        if matches!(
            state.plan.as_ref(),
            Some(OutputPlan::Fallback {
                session_id: fallback_id,
                ..
            }) if *fallback_id == session_id
        ) {
            state.plan = None;
        }
        state.set_status(FocusedOutputStatusEvent {
            session_id,
            status: FocusedOutputStatus::Cancelled,
            reason: Some(FocusedOutputReasonCode::Cancelled),
            capability: None,
            target_application: None,
            speech_delivered_chars: 0,
            external_edit_epoch: 0,
            history_available: false,
        });
        drop(state);
        self.clear_active_identity(session_id);
    }

    fn clear_failed_begin(&self, session_id: DictationSessionId, reason: FocusedOutputReasonCode) {
        let retained_fallback = {
            let mut state = lock_recover(&self.state);
            if state.beginning != Some(session_id) {
                false
            } else {
                state.beginning = None;
                let retained = matches!(
                    state.plan.as_ref(),
                    Some(OutputPlan::Fallback {
                        session_id: fallback_id,
                        ..
                    }) if *fallback_id == session_id
                );
                state.set_status(FocusedOutputStatusEvent {
                    session_id,
                    status: FocusedOutputStatus::Fallback,
                    reason: Some(reason),
                    capability: None,
                    target_application: None,
                    speech_delivered_chars: 0,
                    external_edit_epoch: 0,
                    history_available: false,
                });
                retained
            }
        };

        if retained_fallback {
            let mut active = lock_recover(&self.active_cancellation);
            if active.as_ref().is_some_and(|(id, _)| *id == session_id) {
                *active = None;
            }
            self.active_session
                .store(session_id.get(), Ordering::Release);
        } else {
            self.clear_active_identity(session_id);
        }
    }

    fn clear_active_identity(&self, session_id: DictationSessionId) {
        let _ = self.active_session.compare_exchange(
            session_id.get(),
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let mut active = lock_recover(&self.active_cancellation);
        if active.as_ref().is_some_and(|(id, _)| *id == session_id) {
            *active = None;
        }
    }

    pub fn active_session_id(&self) -> Option<DictationSessionId> {
        let id = self.active_session.load(Ordering::Acquire);
        (id != 0).then_some(DictationSessionId(id))
    }

    pub fn active_plan(&self) -> Option<ActivePlan> {
        let state = lock_recover(&self.state);
        state.plan.as_ref().map(|plan| ActivePlan {
            session_id: plan.session_id(),
            kind: match plan {
                OutputPlan::Fallback { .. } => OutputPlanKind::Fallback,
                OutputPlan::Armed(_) => OutputPlanKind::Focused,
            },
        })
    }

    /// Completes an exact active session without granting legacy paste authority.
    ///
    /// Processing runs on the manager worker so any already-published terminal
    /// transition wins before the plan is consumed.
    pub fn finish_no_text(&self, session_id: DictationSessionId) {
        if self.active_session.load(Ordering::Acquire) != session_id.get() {
            return;
        }
        self.cancel_token_if_active(session_id);
        let (response_tx, response_rx) = bounded(1);
        if self
            .control_tx
            .send_timeout(
                ControlMessage::FinishNoText {
                    session_id,
                    response: response_tx,
                },
                MANAGER_WAIT,
            )
            .is_ok()
        {
            let _ = response_rx.recv_timeout(MANAGER_WAIT);
        }
    }

    /// Lossy, nonblocking publication. A different session replaces the slot;
    /// the same session replaces it only at a strictly newer revision.
    pub fn publish_snapshot(&self, snapshot: TranscriptSnapshot) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut latest) = self.latest_snapshot.try_lock() else {
            return;
        };
        let replace = should_replace_snapshot(latest.as_ref(), &snapshot);
        if replace {
            *latest = Some(snapshot);
            let _ = self.wake_tx.try_send(());
        }
    }

    pub fn publish_lifecycle(
        &self,
        event: StreamLifecycleEvent,
    ) -> Result<(), StreamObserverError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(StreamObserverError::Disconnected);
        }
        self.lifecycle_tx
            .try_send(event)
            .map_err(|error| match error {
                TrySendError::Full(_) => StreamObserverError::QueueFull,
                TrySendError::Disconnected(_) => StreamObserverError::Disconnected,
            })?;
        let _ = self.wake_tx.try_send(());
        Ok(())
    }

    /// First-wins tagged terminal publication. Cancellation is flipped before
    /// the bounded cleanup notification is attempted.
    pub fn terminate(&self, session_id: DictationSessionId, reason: TerminalReason) {
        if self.active_session.load(Ordering::Acquire) != session_id.get() {
            return;
        }
        self.cancel_token_if_active(session_id);
        let _ = self
            .terminal_tx
            .try_send(TerminalEnvelope { session_id, reason });
        let _ = self.wake_tx.try_send(());
    }

    pub fn cancel(&self, session_id: DictationSessionId) {
        if self.active_session.load(Ordering::Acquire) != session_id.get() {
            return;
        }
        self.cancel_token_if_active(session_id);
        if self
            .active_session
            .compare_exchange(session_id.get(), 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if let Ok(mut active) = self.active_cancellation.try_lock() {
            if active.as_ref().is_some_and(|(id, _)| *id == session_id) {
                *active = None;
            }
        }
        let _ = self.terminal_tx.try_send(TerminalEnvelope {
            session_id,
            reason: TerminalReason::Cancelled,
        });
        let _ = self.wake_tx.try_send(());
    }

    fn cancel_token_if_active(&self, session_id: DictationSessionId) {
        if self.active_session.load(Ordering::Acquire) != session_id.get() {
            return;
        }
        if let Ok(active) = self.active_cancellation.try_lock() {
            if let Some((active_id, cancellation)) = active.as_ref() {
                if *active_id == session_id {
                    cancellation.cancel();
                }
            }
        }
    }

    pub fn finalize(
        &self,
        session_id: DictationSessionId,
        final_text: String,
        barrier_revision: Option<u64>,
        options: FinalizeOptions,
    ) -> FinalDeliveryDisposition {
        let (response_tx, response_rx) = bounded(1);
        let message = ControlMessage::Finalize {
            session_id,
            final_text,
            barrier_revision,
            options,
            response: response_tx,
        };
        if self.control_tx.send_timeout(message, MANAGER_WAIT).is_err() {
            self.cancel_token_if_active(session_id);
            return FinalDeliveryDisposition::NoText;
        }
        match response_rx.recv_timeout(MANAGER_WAIT) {
            Ok(disposition) => disposition,
            Err(_) => {
                self.cancel_token_if_active(session_id);
                FinalDeliveryDisposition::NoText
            }
        }
    }

    pub fn global_capability(&self) -> FocusedOutputCapability {
        self.backend.global_capability()
    }

    pub fn request_permission(
        &self,
        permission: FocusedOutputPermission,
    ) -> Result<FocusedOutputCapability, FocusedOutputReasonCode> {
        let state = lock_recover(&self.state);
        if state.plan.is_some() || state.beginning.is_some() {
            return Err(FocusedOutputReasonCode::AlreadyActive);
        }
        let result = self.backend.request_permission(permission);
        drop(state);
        result
    }

    pub fn latest_status(&self) -> Option<FocusedOutputStatusEvent> {
        lock_recover(&self.state).latest_status.clone()
    }

    pub fn shutdown(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(session_id) = self.active_session_id() {
            self.cancel_token_if_active(session_id);
        }
        let (response_tx, response_rx) = bounded(1);
        let shutdown_started = Instant::now();
        let sent = self
            .control_tx
            .send_timeout(
                ControlMessage::Shutdown {
                    response: response_tx,
                },
                MANAGER_WAIT,
            )
            .is_ok();
        let remaining = MANAGER_WAIT.saturating_sub(shutdown_started.elapsed());
        let acknowledged = sent && response_rx.recv_timeout(remaining).is_ok();
        self.active_session.store(0, Ordering::Release);
        *lock_recover(&self.active_cancellation) = None;

        let mut worker = lock_recover(&self.worker);
        if acknowledged {
            if let Some(handle) = worker.take() {
                let _ = handle.join();
            }
        } else {
            // A backend which violates its bounded shutdown contract must not
            // keep application shutdown waiting. Dropping the handle detaches
            // the retained context; cancellation already prevents dispatch.
            let _ = worker.take();
        }
    }
}

impl Drop for FocusedOutputManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[allow(clippy::too_many_arguments)]
fn worker_loop(
    backend: Arc<dyn FocusedFieldBackend>,
    state: Arc<Mutex<ManagerState>>,
    latest_snapshot: Arc<Mutex<Option<TranscriptSnapshot>>>,
    event_rx: Receiver<SessionEventEnvelope>,
    lifecycle_rx: Receiver<StreamLifecycleEvent>,
    terminal_rx: Receiver<TerminalEnvelope>,
    wake_rx: Receiver<()>,
    control_rx: Receiver<ControlMessage>,
    active_session: Arc<AtomicU64>,
    active_cancellation: Arc<Mutex<Option<(DictationSessionId, SessionCancellation)>>>,
    overflow_session: Arc<AtomicU64>,
) {
    loop {
        crossbeam_channel::select! {
            recv(control_rx) -> message => match message {
                Ok(ControlMessage::Finalize { session_id, final_text, barrier_revision, options, response }) => {
                    drain_terminals(&state, &terminal_rx);
                    drain_lifecycle(&state, &lifecycle_rx);
                    drain_events(&state, &event_rx, &overflow_session);
                    process_latest_snapshot(&state, &latest_snapshot, barrier_revision);
                    drain_events(&state, &event_rx, &overflow_session);
                    let disposition = finalize_plan(&state, session_id, &final_text, options, &event_rx, &overflow_session);
                    clear_worker_identity(session_id, &active_session, &active_cancellation);
                    let _ = response.try_send(disposition);
                }
                Ok(ControlMessage::FinishNoText { session_id, response }) => {
                    drain_terminals(&state, &terminal_rx);
                    drain_lifecycle(&state, &lifecycle_rx);
                    drain_events(&state, &event_rx, &overflow_session);
                    finish_no_text_plan(&state, session_id);
                    clear_worker_identity(session_id, &active_session, &active_cancellation);
                    let _ = response.try_send(());
                }
                Ok(ControlMessage::Shutdown { response }) => {
                    close_active_plan(&state);
                    if let Ok(mut latest) = latest_snapshot.lock() {
                        *latest = None;
                    }
                    backend.shutdown();
                    let _ = response.try_send(());
                    break;
                }
                Err(_) => break,
            },
            recv(wake_rx) -> _ => {
                drain_terminals(&state, &terminal_rx);
                drain_lifecycle(&state, &lifecycle_rx);
                drain_events(&state, &event_rx, &overflow_session);
                process_latest_snapshot(&state, &latest_snapshot, None);
                drain_events(&state, &event_rx, &overflow_session);
            }
        }
    }
}

fn drain_terminals(state: &Mutex<ManagerState>, receiver: &Receiver<TerminalEnvelope>) {
    while let Ok(envelope) = receiver.try_recv() {
        apply_terminal(state, envelope.session_id, envelope.reason);
    }
}

fn drain_lifecycle(state: &Mutex<ManagerState>, receiver: &Receiver<StreamLifecycleEvent>) {
    while let Ok(event) = receiver.try_recv() {
        let (session_id, action) = match event {
            StreamLifecycleEvent::Started { session_id, .. } => (session_id, 0),
            StreamLifecycleEvent::Unavailable { session_id, .. } => (session_id, 1),
            StreamLifecycleEvent::Failed { session_id, .. } => (session_id, 2),
            StreamLifecycleEvent::Ended { session_id, .. } => (session_id, 3),
        };
        let mut state = lock_recover(state);
        let Some(OutputPlan::Armed(armed)) = state.plan.as_mut() else {
            continue;
        };
        if armed.session_id != session_id {
            continue;
        }
        let latest = match action {
            0 if armed.terminal_reason.is_none() => {
                Some(armed.status(FocusedOutputStatus::Streaming, false))
            }
            2 => {
                armed.set_terminal(
                    TerminalReason::StreamFailed,
                    FocusedOutputReasonCode::StreamFailed,
                );
                armed
                    .terminal_reason
                    .map(|retained| armed.status(status_for_terminal(retained), false))
            }
            0..=3 => None,
            _ => unreachable!(),
        };
        if let Some(event) = latest {
            state.set_status(event);
        }
    }
}

fn drain_events(
    state: &Mutex<ManagerState>,
    receiver: &Receiver<SessionEventEnvelope>,
    overflow_session: &AtomicU64,
) {
    let overflow = overflow_session.swap(0, Ordering::AcqRel);
    if overflow != 0 {
        apply_terminal(
            state,
            DictationSessionId(overflow),
            TerminalReason::MonitorUnavailable,
        );
    }
    loop {
        match receiver.try_recv() {
            Ok(envelope) => {
                let mut state = lock_recover(state);
                let Some(OutputPlan::Armed(armed)) = state.plan.as_mut() else {
                    continue;
                };
                if armed.session_id != envelope.session_id {
                    continue;
                }
                apply_interaction(armed, envelope.event);
                let latest = armed.terminal_reason.map(|reason| {
                    let status = status_for_terminal(reason);
                    armed.status(status, false)
                });
                if let Some(event) = latest {
                    state.set_status(event);
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
}

fn apply_interaction(armed: &mut ArmedSession, event: TargetInteractionEvent) {
    if armed.terminal_reason.is_some() {
        return;
    }
    if matches!(event, TargetInteractionEvent::HandyInsertionObserved { .. }) {
        return;
    }
    let event_code = interaction_reason_code(event);
    let (observation_id, effect) = match event {
        TargetInteractionEvent::CompatibleExternalInsertion {
            observation_id,
            chars,
            caret_after,
        } => {
            let after = caret_after.unwrap_or_else(|| i64::try_from(chars).unwrap_or(i64::MAX));
            let before = after.saturating_sub(i64::try_from(chars).unwrap_or(i64::MAX));
            let effect = match armed.capability.mixed_input_support() {
                MixedInputSupport::ObservedInsertionsOnly => EditEffectEvidence::DetailedInsert {
                    start: before,
                    removed_len: 0,
                    inserted_chars: chars,
                },
                MixedInputSupport::GuardedKeyboardInsertionsOnly
                | MixedInputSupport::Unavailable => EditEffectEvidence::GuardedCaretAdvance {
                    value_changed: chars != 0,
                    caret_before: before,
                    caret_after: after,
                },
            };
            (observation_id, Some(effect))
        }
        TargetInteractionEvent::UnsafeEdit { observation_id, .. }
        | TargetInteractionEvent::TargetInvalidated { observation_id, .. }
        | TargetInteractionEvent::MonitorUnavailable { observation_id } => (observation_id, None),
        TargetInteractionEvent::HandyInsertionObserved { .. } => return,
    };
    let scope = AttributionScope {
        session_id: armed.session_id,
        generation: armed.session_id.get(),
        source_marker: armed.session_id.get() ^ 0xa5a5_5a5a_d3c3_b4b4,
    };
    let evidence =
        InteractionEvidence::normalized(scope, observation_id, Instant::now(), event, effect);
    if let CoeditDecision::Terminal(reason) = armed.coediting.on_evidence(evidence) {
        armed.set_terminal(reason, event_code.unwrap_or_else(|| reason_code(reason)));
    }
}

fn process_latest_snapshot(
    state: &Mutex<ManagerState>,
    latest_snapshot: &Mutex<Option<TranscriptSnapshot>>,
    barrier_revision: Option<u64>,
) {
    let snapshot = {
        let mut latest = lock_recover(latest_snapshot);
        let should_take = latest.as_ref().is_some_and(|snapshot| {
            barrier_revision.is_none_or(|barrier| snapshot.revision <= barrier)
        });
        should_take.then(|| latest.take()).flatten()
    };
    let Some(snapshot) = snapshot else {
        return;
    };
    let mut state = lock_recover(state);
    let Some(OutputPlan::Armed(armed)) = state.plan.as_mut() else {
        return;
    };
    if snapshot.session_id != armed.session_id {
        return;
    }
    process_snapshot(armed, &snapshot);
    let status = armed
        .terminal_reason
        .map(status_for_terminal)
        .unwrap_or(FocusedOutputStatus::Streaming);
    let event = armed.status(status, false);
    state.set_status(event);
}

fn process_snapshot(armed: &mut ArmedSession, snapshot: &TranscriptSnapshot) {
    match armed.ledger.reconcile_snapshot(snapshot) {
        SnapshotDecision::Append(suffix) => {
            armed.metrics.record_snapshot(false);
            let outcome = insert_in_units(armed, &suffix, InsertionKind::Speech);
            let code = outcome_reason(outcome);
            if let ApplyDecision::Terminal(reason) =
                armed.ledger.apply_insert_outcome(&suffix, outcome)
            {
                armed.set_terminal(reason, code.unwrap_or_else(|| reason_code(reason)));
            }
        }
        SnapshotDecision::Noop | SnapshotDecision::HoldConflict { .. } => {
            armed.metrics.record_snapshot(false);
        }
        SnapshotDecision::IgnoredSession
        | SnapshotDecision::InsertionPending
        | SnapshotDecision::RejectedFinalized => {
            armed.metrics.record_snapshot(true);
        }
        SnapshotDecision::Terminal(reason) => {
            armed.set_terminal(reason, reason_code(reason));
        }
    }
}

fn insert_in_units(armed: &mut ArmedSession, text: &str, kind: InsertionKind) -> InsertOutcome {
    let mut accepted_bytes = 0usize;
    let mut aggregate_receipt = ReceiptConfidence::Verified;
    for unit in scalar_units(text, MAX_INSERTION_SCALARS) {
        if armed.cancellation.is_cancelled() || armed.terminal_reason.is_some() {
            return prefix_or_rejected(
                accepted_bytes,
                aggregate_receipt,
                FocusedOutputReasonCode::Cancelled,
            );
        }
        let injection_id = armed.next_injection_id();
        let outcome = armed.target.insert_if_valid(InsertionRequest {
            session_id: armed.session_id,
            injection_id,
            text: unit.to_owned(),
            kind,
        });
        match outcome {
            InsertOutcome::Complete { receipt } => {
                aggregate_receipt = weakest_receipt(aggregate_receipt, receipt);
                armed.receipt_confidence = weakest_receipt(armed.receipt_confidence, receipt);
                accepted_bytes = accepted_bytes.saturating_add(unit.len());
                armed
                    .metrics
                    .record_insertion(kind, unit.chars().count(), receipt);
            }
            InsertOutcome::Partial {
                accepted_bytes: unit_bytes,
                receipt,
                reason,
            } => {
                let valid = unit.get(..unit_bytes).is_some();
                if !valid {
                    return InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    };
                }
                aggregate_receipt = weakest_receipt(aggregate_receipt, receipt);
                let total = accepted_bytes.saturating_add(unit_bytes);
                armed
                    .metrics
                    .record_insertion(kind, unit[..unit_bytes].chars().count(), receipt);
                armed.receipt_confidence = weakest_receipt(armed.receipt_confidence, receipt);
                return InsertOutcome::Partial {
                    accepted_bytes: total,
                    receipt: aggregate_receipt,
                    reason,
                };
            }
            InsertOutcome::Ambiguous { reason } => {
                return if accepted_bytes == 0 {
                    InsertOutcome::Ambiguous { reason }
                } else {
                    InsertOutcome::Partial {
                        accepted_bytes,
                        receipt: aggregate_receipt,
                        reason,
                    }
                };
            }
            InsertOutcome::Rejected { reason } => {
                return if accepted_bytes == 0 {
                    InsertOutcome::Rejected { reason }
                } else {
                    InsertOutcome::Partial {
                        accepted_bytes,
                        receipt: aggregate_receipt,
                        reason,
                    }
                };
            }
        }
    }
    InsertOutcome::Complete {
        receipt: aggregate_receipt,
    }
}

fn prefix_or_rejected(
    accepted_bytes: usize,
    receipt: ReceiptConfidence,
    reason: FocusedOutputReasonCode,
) -> InsertOutcome {
    if accepted_bytes == 0 {
        InsertOutcome::Rejected { reason }
    } else {
        InsertOutcome::Partial {
            accepted_bytes,
            receipt,
            reason,
        }
    }
}

fn scalar_units(text: &str, max_scalars: usize) -> impl Iterator<Item = &str> {
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start == text.len() {
            return None;
        }
        let end = text[start..]
            .char_indices()
            .nth(max_scalars)
            .map_or(text.len(), |(offset, _)| start + offset);
        let unit = &text[start..end];
        start = end;
        Some(unit)
    })
}

fn weakest_receipt(left: ReceiptConfidence, right: ReceiptConfidence) -> ReceiptConfidence {
    if left == ReceiptConfidence::Posted || right == ReceiptConfidence::Posted {
        ReceiptConfidence::Posted
    } else {
        ReceiptConfidence::Verified
    }
}
fn finish_no_text_plan(state: &Mutex<ManagerState>, session_id: DictationSessionId) {
    let mut state = lock_recover(state);
    let matching_begin = state.beginning == Some(session_id);
    if matching_begin {
        state.beginning = None;
    }
    if !matching_begin
        && state
            .plan
            .as_ref()
            .is_none_or(|plan| plan.session_id() != session_id)
    {
        return;
    }

    let event = match state.plan.take() {
        Some(OutputPlan::Armed(mut armed)) if armed.session_id == session_id => {
            let status = armed
                .terminal_reason
                .map(status_for_terminal)
                .unwrap_or(FocusedOutputStatus::Completed);
            armed.close();
            armed.status(status, false)
        }
        Some(OutputPlan::Fallback {
            session_id: fallback_id,
            ..
        }) if fallback_id == session_id => FocusedOutputStatusEvent {
            session_id,
            status: FocusedOutputStatus::Completed,
            reason: None,
            capability: None,
            target_application: None,
            speech_delivered_chars: 0,
            external_edit_epoch: 0,
            history_available: false,
        },
        Some(other) => {
            state.plan = Some(other);
            return;
        }
        None => FocusedOutputStatusEvent {
            session_id,
            status: FocusedOutputStatus::Completed,
            reason: None,
            capability: None,
            target_application: None,
            speech_delivered_chars: 0,
            external_edit_epoch: 0,
            history_available: false,
        },
    };
    state.set_status(event);
}

fn outcome_reason(outcome: InsertOutcome) -> Option<FocusedOutputReasonCode> {
    match outcome {
        InsertOutcome::Complete { .. } => None,
        InsertOutcome::Partial { reason, .. }
        | InsertOutcome::Ambiguous { reason }
        | InsertOutcome::Rejected { reason } => Some(reason),
    }
}

fn finalize_plan(
    state: &Mutex<ManagerState>,
    session_id: DictationSessionId,
    final_text: &str,
    options: FinalizeOptions,
    event_rx: &Receiver<SessionEventEnvelope>,
    overflow_session: &AtomicU64,
) -> FinalDeliveryDisposition {
    let plan = {
        let mut state = lock_recover(state);
        if state.plan.as_ref().map(OutputPlan::session_id) != Some(session_id) {
            return FinalDeliveryDisposition::NoText;
        }
        state.plan.take()
    };
    let Some(plan) = plan else {
        return FinalDeliveryDisposition::NoText;
    };
    match plan {
        OutputPlan::Fallback { authority, .. } => {
            let mut state = lock_recover(state);
            state.set_status(FocusedOutputStatusEvent {
                session_id,
                status: FocusedOutputStatus::Completed,
                reason: None,
                capability: None,
                target_application: None,
                speech_delivered_chars: 0,
                external_edit_epoch: 0,
                history_available: options.history_available,
            });
            if final_text.is_empty() {
                FinalDeliveryDisposition::NoText
            } else {
                FinalDeliveryDisposition::LegacyPaste(authority.into_legacy_paste())
            }
        }
        OutputPlan::Armed(mut armed) => {
            drain_events_for_armed(&mut armed, event_rx, overflow_session);
            let disposition =
                finalize_armed(&mut armed, final_text, options, event_rx, overflow_session);
            armed.metrics.complete();
            armed.close();
            let status = match disposition {
                FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered {
                    ..
                })
                | FinalDeliveryDisposition::NoText => FocusedOutputStatus::Completed,
                FinalDeliveryDisposition::Focused(
                    FocusedDeliveryDisposition::PreservePartial { reason, .. },
                ) => status_for_terminal(reason),
                FinalDeliveryDisposition::LegacyPaste(_) => unreachable!(),
            };
            let event = armed.status(status, options.history_available);
            let mut state = lock_recover(state);
            state.set_status(event);
            disposition
        }
    }
}

fn drain_events_for_armed(
    armed: &mut ArmedSession,
    receiver: &Receiver<SessionEventEnvelope>,
    overflow_session: &AtomicU64,
) {
    if overflow_session.swap(0, Ordering::AcqRel) == armed.session_id.get() {
        armed.set_terminal(
            TerminalReason::MonitorUnavailable,
            FocusedOutputReasonCode::MonitorUnavailable,
        );
    }
    while let Ok(envelope) = receiver.try_recv() {
        if envelope.session_id == armed.session_id {
            apply_interaction(armed, envelope.event);
        }
    }
}

fn finalize_armed(
    armed: &mut ArmedSession,
    final_text: &str,
    options: FinalizeOptions,
    event_rx: &Receiver<SessionEventEnvelope>,
    overflow_session: &AtomicU64,
) -> FinalDeliveryDisposition {
    if let Some(reason) = armed.terminal_reason {
        return preserve(armed, reason);
    }
    match armed.ledger.reconcile_final(final_text) {
        FinalDecision::AppendTail(tail) => {
            let outcome = insert_in_units(armed, &tail, InsertionKind::Speech);
            let code = outcome_reason(outcome);
            if let ApplyDecision::Terminal(reason) =
                armed.ledger.apply_insert_outcome(&tail, outcome)
            {
                armed.set_terminal(reason, code.unwrap_or_else(|| reason_code(reason)));
                return preserve(armed, reason);
            }
        }
        FinalDecision::Complete => {}
        FinalDecision::PreserveConflict => {
            armed.set_terminal(
                TerminalReason::FinalConflict,
                FocusedOutputReasonCode::FinalConflict,
            );
            return preserve(armed, TerminalReason::FinalConflict);
        }
        FinalDecision::PreserveTerminal(reason) => return preserve(armed, reason),
        FinalDecision::InsertionPending | FinalDecision::FinalizationPending => {
            armed.set_terminal(
                TerminalReason::AmbiguousInsertion,
                FocusedOutputReasonCode::InjectionAmbiguous,
            );
            return preserve(armed, TerminalReason::AmbiguousInsertion);
        }
        FinalDecision::AlreadyFinalized => {}
    }

    drain_events_for_armed(armed, event_rx, overflow_session);
    if let Some(reason) = armed.terminal_reason {
        return preserve(armed, reason);
    }
    if final_text.is_empty() && armed.ledger.speech_delivered_chars() == 0 {
        return FinalDeliveryDisposition::NoText;
    }

    let mut trailing_space_delivered = false;
    if options.append_trailing_space {
        let outcome = insert_in_units(armed, " ", InsertionKind::TrailingSpace);
        match outcome {
            InsertOutcome::Complete { .. } => trailing_space_delivered = true,
            InsertOutcome::Partial { reason, .. } => {
                armed.set_terminal(TerminalReason::PartialInsertion, reason);
                return preserve(armed, TerminalReason::PartialInsertion);
            }
            InsertOutcome::Ambiguous { reason } => {
                armed.set_terminal(TerminalReason::AmbiguousInsertion, reason);
                return preserve(armed, TerminalReason::AmbiguousInsertion);
            }
            InsertOutcome::Rejected { reason } => {
                armed.set_terminal(TerminalReason::TargetInvalidated, reason);
                return preserve(armed, TerminalReason::TargetInvalidated);
            }
        }
    }

    drain_events_for_armed(armed, event_rx, overflow_session);
    if let Some(reason) = armed.terminal_reason {
        return preserve(armed, reason);
    }
    let submit = if !options.auto_submit {
        SubmitDisposition::NotRequested
    } else if !armed.capability.supports_auto_submit() {
        SubmitDisposition::Failed {
            reason: FocusedOutputReasonCode::AutoSubmitUnsupported,
        }
    } else {
        match armed.target.submit_if_valid(options.auto_submit_key) {
            SubmitOutcome::Complete { receipt } => SubmitDisposition::Submitted { receipt },
            SubmitOutcome::Ambiguous { reason } | SubmitOutcome::Rejected { reason } => {
                SubmitDisposition::Failed { reason }
            }
        }
    };

    FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered {
        safety_level: armed.capability.safety_level(),
        receipt_confidence: armed.receipt_confidence,
        external_edit_epoch: armed.external_edit_epoch(),
        trailing_space_delivered,
        submit,
    })
}

fn preserve(armed: &ArmedSession, reason: TerminalReason) -> FinalDeliveryDisposition {
    FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::PreservePartial {
        reason,
        speech_delivered_chars: armed.ledger.speech_delivered_chars(),
        external_edit_epoch: armed.external_edit_epoch(),
    })
}

fn apply_terminal(
    state: &Mutex<ManagerState>,
    session_id: DictationSessionId,
    reason: TerminalReason,
) {
    let mut state = lock_recover(state);
    let fallback_cancel = reason == TerminalReason::Cancelled
        && matches!(
            state.plan.as_ref(),
            Some(OutputPlan::Fallback {
                session_id: active,
                ..
            }) if *active == session_id
        );
    if fallback_cancel {
        if state.beginning == Some(session_id) {
            state.beginning = None;
        }
        state.plan = None;
        state.set_status(FocusedOutputStatusEvent {
            session_id,
            status: FocusedOutputStatus::Cancelled,
            reason: Some(FocusedOutputReasonCode::Cancelled),
            capability: None,
            target_application: None,
            speech_delivered_chars: 0,
            external_edit_epoch: 0,
            history_available: false,
        });
        return;
    }
    let Some(OutputPlan::Armed(armed)) = state.plan.as_mut() else {
        return;
    };
    if armed.session_id != session_id {
        return;
    }
    armed.set_terminal(reason, reason_code(reason));
    let retained = armed.terminal_reason.unwrap_or(reason);
    let event = armed.status(status_for_terminal(retained), false);
    state.set_status(event);
}

fn interaction_reason_code(event: TargetInteractionEvent) -> Option<FocusedOutputReasonCode> {
    match event {
        TargetInteractionEvent::UnsafeEdit { kind, .. } => Some(match kind {
            UnsafeEditKind::Delete
            | UnsafeEditKind::Replace
            | UnsafeEditKind::Cut
            | UnsafeEditKind::Paste
            | UnsafeEditKind::UndoRedo
            | UnsafeEditKind::Unknown => FocusedOutputReasonCode::DestructiveUserEdit,
            UnsafeEditKind::SelectionChanged => FocusedOutputReasonCode::SelectionChanged,
            UnsafeEditKind::CaretRepositioned | UnsafeEditKind::FocusTraversal => {
                FocusedOutputReasonCode::CaretMoved
            }
            UnsafeEditKind::SubmitOrNewlineAmbiguous | UnsafeEditKind::CommandShortcut => {
                FocusedOutputReasonCode::UnsafeKeyboardCommand
            }
            UnsafeEditKind::ImeComposition => FocusedOutputReasonCode::ImeCompositionUnsupported,
        }),
        TargetInteractionEvent::TargetInvalidated { reason, .. } => Some(reason),
        TargetInteractionEvent::MonitorUnavailable { .. } => {
            Some(FocusedOutputReasonCode::MonitorUnavailable)
        }
        TargetInteractionEvent::HandyInsertionObserved { .. }
        | TargetInteractionEvent::CompatibleExternalInsertion { .. } => None,
    }
}

fn reason_code(reason: TerminalReason) -> FocusedOutputReasonCode {
    match reason {
        TerminalReason::PartialInsertion => FocusedOutputReasonCode::InjectionPartial,
        TerminalReason::AmbiguousInsertion => FocusedOutputReasonCode::InjectionAmbiguous,
        TerminalReason::TargetInvalidated => FocusedOutputReasonCode::TargetChanged,
        TerminalReason::UnsafeUserEdit => FocusedOutputReasonCode::DestructiveUserEdit,
        TerminalReason::MonitorUnavailable => FocusedOutputReasonCode::MonitorUnavailable,
        TerminalReason::ReceiptTimeout => FocusedOutputReasonCode::ReceiptTimeout,
        TerminalReason::FinalConflict => FocusedOutputReasonCode::FinalConflict,
        TerminalReason::StreamFailed => FocusedOutputReasonCode::StreamFailed,
        TerminalReason::Cancelled => FocusedOutputReasonCode::Cancelled,
    }
}

fn status_for_terminal(reason: TerminalReason) -> FocusedOutputStatus {
    match reason {
        TerminalReason::TargetInvalidated
        | TerminalReason::UnsafeUserEdit
        | TerminalReason::MonitorUnavailable => FocusedOutputStatus::Invalidated,
        TerminalReason::FinalConflict => FocusedOutputStatus::Conflict,
        TerminalReason::Cancelled => FocusedOutputStatus::Cancelled,
        TerminalReason::PartialInsertion
        | TerminalReason::AmbiguousInsertion
        | TerminalReason::ReceiptTimeout
        | TerminalReason::StreamFailed => FocusedOutputStatus::Faulted,
    }
}

fn close_active_plan(state: &Mutex<ManagerState>) {
    let mut state = lock_recover(state);
    if let Some(OutputPlan::Armed(armed)) = state.plan.as_mut() {
        armed.cancellation.cancel();
        armed.close();
    }
    state.plan = None;
    state.beginning = None;
}

fn clear_worker_identity(
    session_id: DictationSessionId,
    active_session: &AtomicU64,
    active_cancellation: &Mutex<Option<(DictationSessionId, SessionCancellation)>>,
) {
    let _ =
        active_session.compare_exchange(session_id.get(), 0, Ordering::AcqRel, Ordering::Acquire);
    let mut active = lock_recover(active_cancellation);
    if active.as_ref().is_some_and(|(id, _)| *id == session_id) {
        *active = None;
    }
}

fn should_replace_snapshot(
    current: Option<&TranscriptSnapshot>,
    incoming: &TranscriptSnapshot,
) -> bool {
    match current {
        None => true,
        Some(current) if current.session_id != incoming.session_id => true,
        Some(current) => incoming.revision > current.revision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focused_output::platform::conformance::{posted_capability, FakeBackend};
    use crate::settings::{AutoSubmitKey, ClipboardHandling};
    use std::sync::Mutex;

    struct UnavailableBackend;

    impl FocusedFieldBackend for UnavailableBackend {
        fn global_capability(&self) -> FocusedOutputCapability {
            FocusedOutputCapability::global_ready(FocusedOutputBackend::Test)
        }

        fn request_permission(
            &self,
            _permission: FocusedOutputPermission,
        ) -> Result<FocusedOutputCapability, FocusedOutputReasonCode> {
            Ok(self.global_capability())
        }

        fn begin(
            &self,
            _context: BeginContext,
            _event_sink: Arc<dyn SessionEventSink>,
            _cancellation: SessionCancellation,
        ) -> Result<BeginSession, FocusedOutputReasonCode> {
            Err(FocusedOutputReasonCode::TargetUnsupported)
        }

        fn shutdown(&self) {}
    }

    struct CancellingBackend;

    impl FocusedFieldBackend for CancellingBackend {
        fn global_capability(&self) -> FocusedOutputCapability {
            FocusedOutputCapability::global_ready(FocusedOutputBackend::Test)
        }

        fn request_permission(
            &self,
            _permission: FocusedOutputPermission,
        ) -> Result<FocusedOutputCapability, FocusedOutputReasonCode> {
            Ok(self.global_capability())
        }

        fn begin(
            &self,
            _context: BeginContext,
            _event_sink: Arc<dyn SessionEventSink>,
            cancellation: SessionCancellation,
        ) -> Result<BeginSession, FocusedOutputReasonCode> {
            cancellation.cancel();
            Err(FocusedOutputReasonCode::Cancelled)
        }

        fn shutdown(&self) {}
    }

    #[derive(Default)]
    struct RecordingStatusSink {
        events: Mutex<Vec<FocusedOutputStatusEvent>>,
    }

    impl FocusedOutputStatusSink for RecordingStatusSink {
        fn publish(&self, event: &FocusedOutputStatusEvent) {
            lock_recover(&self.events).push(event.clone());
        }
    }

    fn options() -> FinalizeOptions {
        FinalizeOptions {
            append_trailing_space: false,
            clipboard_handling: ClipboardHandling::DontModify,
            auto_submit: false,
            auto_submit_key: AutoSubmitKey::Enter,
            history_available: true,
        }
    }

    fn context(session_id: DictationSessionId) -> BeginContext {
        BeginContext {
            session_id,
            control_shortcut: None,
            auto_submit_requested: false,
            #[cfg(target_os = "linux")]
            typing_tool: crate::settings::TypingTool::Auto,
        }
    }

    #[test]
    fn latest_snapshot_replacement_is_session_and_revision_exact() {
        let current = TranscriptSnapshot {
            session_id: DictationSessionId(1),
            revision: 7,
            committed: String::new(),
            tentative: String::new(),
        };
        let stale_same_session = TranscriptSnapshot {
            session_id: current.session_id,
            revision: 6,
            committed: String::new(),
            tentative: String::new(),
        };
        let duplicate = TranscriptSnapshot {
            session_id: current.session_id,
            revision: 7,
            committed: String::new(),
            tentative: String::new(),
        };
        let newer = TranscriptSnapshot {
            session_id: current.session_id,
            revision: 8,
            committed: String::new(),
            tentative: String::new(),
        };
        let new_session = TranscriptSnapshot {
            session_id: DictationSessionId(2),
            revision: 0,
            committed: String::new(),
            tentative: String::new(),
        };

        assert!(!should_replace_snapshot(
            Some(&current),
            &stale_same_session
        ));
        assert!(!should_replace_snapshot(Some(&current), &duplicate));
        assert!(should_replace_snapshot(Some(&current), &newer));
        assert!(should_replace_snapshot(Some(&current), &new_session));
    }

    #[test]
    fn fallback_authority_is_consumed_exactly_once_and_never_armed() {
        let manager = FocusedOutputManager::new(Arc::new(UnavailableBackend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();

        assert!(matches!(
            manager.finalize(session_id, "private final text".to_owned(), None, options()),
            FinalDeliveryDisposition::LegacyPaste(_)
        ));
        assert!(matches!(
            manager.finalize(session_id, "private final text".to_owned(), None, options()),
            FinalDeliveryDisposition::NoText
        ));
        manager.shutdown();
    }

    #[test]
    fn cancelling_fallback_destroys_paste_authority() {
        let manager = FocusedOutputManager::new(Arc::new(UnavailableBackend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();
        manager.cancel(session_id);

        assert!(matches!(
            manager.finalize(session_id, "private final text".to_owned(), None, options()),
            FinalDeliveryDisposition::NoText
        ));
        manager.shutdown();
    }

    #[test]
    fn matching_fallback_is_atomically_upgraded_to_focused() {
        let backend = FakeBackend::new(posted_capability(false));
        let manager = FocusedOutputManager::new(Arc::new(backend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();

        manager.begin(context(session_id)).unwrap();
        assert_eq!(
            manager.active_plan(),
            Some(ActivePlan {
                session_id,
                kind: OutputPlanKind::Focused,
            })
        );
        assert!(!matches!(
            manager.finalize(session_id, "final text".to_owned(), None, options()),
            FinalDeliveryDisposition::LegacyPaste(_)
        ));
        manager.shutdown();
    }

    #[test]
    fn fallback_upgrade_rejects_a_mismatched_session() {
        let manager = FocusedOutputManager::new(Arc::new(UnavailableBackend));
        let fallback_id = manager.allocate_session_id();
        let other_id = manager.allocate_session_id();
        manager.register_fallback(fallback_id).unwrap();

        assert!(matches!(
            manager.begin(context(other_id)),
            Err(FocusedOutputReasonCode::AlreadyActive)
        ));
        assert!(matches!(
            manager.finalize(fallback_id, "final text".to_owned(), None, options()),
            FinalDeliveryDisposition::LegacyPaste(_)
        ));
        manager.shutdown();
    }

    #[test]
    fn pre_arm_failure_retains_fallback_authority() {
        let manager = FocusedOutputManager::new(Arc::new(UnavailableBackend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();

        assert!(matches!(
            manager.begin(context(session_id)),
            Err(FocusedOutputReasonCode::TargetUnsupported)
        ));
        assert_eq!(
            manager.active_plan(),
            Some(ActivePlan {
                session_id,
                kind: OutputPlanKind::Fallback,
            })
        );
        assert!(matches!(
            manager.finalize(session_id, "final text".to_owned(), None, options()),
            FinalDeliveryDisposition::LegacyPaste(_)
        ));
        manager.shutdown();
    }

    #[test]
    fn cancellation_during_begin_consumes_fallback_and_never_rearms() {
        let manager = FocusedOutputManager::new(Arc::new(CancellingBackend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();

        assert!(matches!(
            manager.begin(context(session_id)),
            Err(FocusedOutputReasonCode::Cancelled)
        ));
        assert_eq!(manager.active_plan(), None);
        assert_eq!(manager.active_session_id(), None);
        assert!(matches!(
            manager.finalize(session_id, "final text".to_owned(), None, options()),
            FinalDeliveryDisposition::NoText
        ));
        manager.shutdown();
    }

    #[test]
    fn post_arm_failure_cannot_recover_legacy_paste_authority() {
        let backend = FakeBackend::new(posted_capability(false));
        let manager = FocusedOutputManager::new(Arc::new(backend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();
        manager.begin(context(session_id)).unwrap();

        manager.terminate(session_id, TerminalReason::StreamFailed);
        assert!(matches!(
            manager.finalize(session_id, "final text".to_owned(), None, options()),
            FinalDeliveryDisposition::Focused(_) | FinalDeliveryDisposition::NoText
        ));
        manager.shutdown();
    }

    #[test]
    fn armed_cancel_keeps_an_earlier_unsafe_terminal_and_preserves_partial() {
        let backend = FakeBackend::new(posted_capability(false));
        let manager = FocusedOutputManager::new(Arc::new(backend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();
        manager.begin(context(session_id)).unwrap();

        manager.terminate(session_id, TerminalReason::UnsafeUserEdit);
        manager.cancel(session_id);
        assert!(matches!(
            manager.finalize(session_id, "final text".to_owned(), None, options()),
            FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::PreservePartial {
                reason: TerminalReason::UnsafeUserEdit,
                ..
            })
        ));
        manager.shutdown();
    }

    #[test]
    fn status_sink_receives_fallback_armed_streaming_and_final_transitions() {
        let backend = FakeBackend::new(posted_capability(false));
        let sink = Arc::new(RecordingStatusSink::default());
        let manager = FocusedOutputManager::new_with_status_sink(Arc::new(backend), sink.clone());
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();
        manager.begin(context(session_id)).unwrap();
        manager
            .publish_lifecycle(StreamLifecycleEvent::Started {
                session_id,
                worker_token: 1,
            })
            .unwrap();
        let _ = manager.finalize(session_id, String::new(), None, options());

        let statuses = lock_recover(&sink.events)
            .iter()
            .map(|event| event.status)
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            vec![
                FocusedOutputStatus::Fallback,
                FocusedOutputStatus::Armed,
                FocusedOutputStatus::Streaming,
                FocusedOutputStatus::Completed,
            ]
        );
        manager.shutdown();
    }

    #[test]
    fn status_sink_delivers_content_free_terminal_transition_before_cleanup() {
        let backend = FakeBackend::new(posted_capability(false));
        let sink = Arc::new(RecordingStatusSink::default());
        let manager = FocusedOutputManager::new_with_status_sink(Arc::new(backend), sink.clone());
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();
        manager.begin(context(session_id)).unwrap();

        manager.terminate(session_id, TerminalReason::StreamFailed);
        manager.finish_no_text(session_id);

        let event = lock_recover(&sink.events).last().cloned().unwrap();
        assert_eq!(event.status, FocusedOutputStatus::Faulted);
        assert_eq!(event.reason, Some(FocusedOutputReasonCode::StreamFailed));
        assert_eq!(event.capability, None);
        assert_eq!(event.target_application, None);
        assert_eq!(manager.active_plan(), None);
        manager.shutdown();
    }

    #[test]
    fn permission_request_is_rejected_while_any_plan_is_active() {
        let manager = FocusedOutputManager::new(Arc::new(UnavailableBackend));
        let session_id = manager.allocate_session_id();
        manager.register_fallback(session_id).unwrap();

        assert_eq!(
            manager.request_permission(FocusedOutputPermission::MacAccessibility),
            Err(FocusedOutputReasonCode::AlreadyActive)
        );
        manager.finish_no_text(session_id);
        manager.shutdown();
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
