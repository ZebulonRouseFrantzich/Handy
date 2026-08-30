use super::{BeginSession, FocusedFieldBackend, FocusedTargetSession, SessionEventSink};
use crate::focused_output::types::{
    BeginContext, BeginReceipt, DictationSessionId, FocusedOutputBackend, FocusedOutputCapability,
    FocusedOutputPermission, FocusedOutputReasonCode, FocusedOutputSafetyLevel, InjectionId,
    InsertOutcome, InsertionKind, InsertionRequest, InsertionTransport, MixedInputSupport,
    ReceiptConfidence, ResolvedInsertionCapability, SessionCancellation, SubmitOutcome,
    TargetInteractionEvent,
};
use crate::settings::AutoSubmitKey;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const VERIFIED_ROUTE: ResolvedInsertionCapability = ResolvedInsertionCapability {
    insertion_transport: InsertionTransport::Test,
    receipt_confidence: ReceiptConfidence::Verified,
};

const POSTED_ROUTE: ResolvedInsertionCapability = ResolvedInsertionCapability {
    insertion_transport: InsertionTransport::Test,
    receipt_confidence: ReceiptConfidence::Posted,
};

pub(crate) fn verified_capability(supports_auto_submit: bool) -> FocusedOutputCapability {
    FocusedOutputCapability::verified_control(
        FocusedOutputBackend::Test,
        VERIFIED_ROUTE,
        MixedInputSupport::ObservedInsertionsOnly,
        supports_auto_submit,
    )
}

pub(crate) fn posted_capability(supports_auto_submit: bool) -> FocusedOutputCapability {
    FocusedOutputCapability::guarded_focused_control(
        FocusedOutputBackend::Test,
        POSTED_ROUTE,
        MixedInputSupport::GuardedKeyboardInsertionsOnly,
        supports_auto_submit,
    )
}

pub(crate) struct FakeSessionScript {
    insert_outcomes: VecDeque<InsertOutcome>,
    submit_outcomes: VecDeque<SubmitOutcome>,
}

impl FakeSessionScript {
    pub(crate) fn new(
        insert_outcomes: impl IntoIterator<Item = InsertOutcome>,
        submit_outcomes: impl IntoIterator<Item = SubmitOutcome>,
    ) -> Self {
        Self {
            insert_outcomes: insert_outcomes.into_iter().collect(),
            submit_outcomes: submit_outcomes.into_iter().collect(),
        }
    }

    fn complete() -> Self {
        Self::new([], [])
    }
}

struct FakeInsertionCall {
    session_id: DictationSessionId,
    injection_id: InjectionId,
    text: String,
    kind: InsertionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FakeCallKind {
    InsertSpeech,
    InsertTrailingSpace,
    Submit,
    Close,
}

struct FakeSessionState {
    session_id: DictationSessionId,
    route_number: usize,
    event_sink: Arc<dyn SessionEventSink>,
    insertion_calls: Mutex<Vec<FakeInsertionCall>>,
    submit_calls: Mutex<Vec<AutoSubmitKey>>,
    call_order: Mutex<Vec<FakeCallKind>>,
    close_calls: AtomicUsize,
    closed: AtomicBool,
}

impl FakeSessionState {
    fn new(
        session_id: DictationSessionId,
        route_number: usize,
        event_sink: Arc<dyn SessionEventSink>,
    ) -> Self {
        Self {
            session_id,
            route_number,
            event_sink,
            insertion_calls: Mutex::new(Vec::new()),
            submit_calls: Mutex::new(Vec::new()),
            call_order: Mutex::new(Vec::new()),
            close_calls: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }
    }
}

#[derive(Clone)]
pub(crate) struct FakeSessionHandle {
    state: Arc<FakeSessionState>,
}

impl FakeSessionHandle {
    pub(crate) fn session_id(&self) -> DictationSessionId {
        self.state.session_id
    }

    pub(crate) fn route_number(&self) -> usize {
        self.state.route_number
    }

    pub(crate) fn insertion_count(&self) -> usize {
        self.state
            .insertion_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub(crate) fn insertion_session_ids(&self) -> Vec<DictationSessionId> {
        self.state
            .insertion_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|call| call.session_id)
            .collect()
    }

    pub(crate) fn insertion_ids(&self) -> Vec<InjectionId> {
        self.state
            .insertion_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|call| call.injection_id)
            .collect()
    }

    pub(crate) fn insertion_kinds(&self) -> Vec<InsertionKind> {
        self.state
            .insertion_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|call| call.kind)
            .collect()
    }

    pub(crate) fn submit_count(&self) -> usize {
        self.state
            .submit_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub(crate) fn close_calls(&self) -> usize {
        self.state.close_calls.load(Ordering::Acquire)
    }

    pub(crate) fn call_order(&self) -> Vec<FakeCallKind> {
        self.state
            .call_order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn publish_tagged(
        &self,
        session_id: DictationSessionId,
        event: TargetInteractionEvent,
    ) {
        self.state.event_sink.publish(session_id, event);
    }

    fn inserted_texts(&self) -> Vec<String> {
        self.state
            .insertion_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|call| call.text.clone())
            .collect()
    }
}

struct FakeBackendState {
    global_capability: Mutex<FocusedOutputCapability>,
    route_capability: Mutex<FocusedOutputCapability>,
    scripts: Mutex<VecDeque<Result<FakeSessionScript, FocusedOutputReasonCode>>>,
    sessions: Mutex<Vec<Arc<FakeSessionState>>>,
    next_route_number: AtomicUsize,
    shutdown_calls: AtomicUsize,
    shut_down: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct FakeBackend {
    state: Arc<FakeBackendState>,
}

impl FakeBackend {
    pub(crate) fn new(route_capability: FocusedOutputCapability) -> Self {
        Self {
            state: Arc::new(FakeBackendState {
                global_capability: Mutex::new(FocusedOutputCapability::global_ready(
                    FocusedOutputBackend::Test,
                )),
                route_capability: Mutex::new(route_capability),
                scripts: Mutex::new(VecDeque::new()),
                sessions: Mutex::new(Vec::new()),
                next_route_number: AtomicUsize::new(1),
                shutdown_calls: AtomicUsize::new(0),
                shut_down: AtomicBool::new(false),
            }),
        }
    }

    pub(crate) fn queue_script(&self, script: FakeSessionScript) {
        self.state
            .scripts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push_back(Ok(script));
    }

    pub(crate) fn set_route_capability(&self, capability: FocusedOutputCapability) {
        *self
            .state
            .route_capability
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = capability;
    }

    pub(crate) fn sessions(&self) -> Vec<FakeSessionHandle> {
        self.state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|state| FakeSessionHandle {
                state: Arc::clone(state),
            })
            .collect()
    }

    pub(crate) fn session(&self, session_id: DictationSessionId) -> FakeSessionHandle {
        let state = self
            .state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .find(|session| session.session_id == session_id)
            .cloned()
            .expect("fake session must exist");
        FakeSessionHandle { state }
    }

    pub(crate) fn shutdown_calls(&self) -> usize {
        self.state.shutdown_calls.load(Ordering::Acquire)
    }
}

impl FocusedFieldBackend for FakeBackend {
    fn global_capability(&self) -> FocusedOutputCapability {
        self.state
            .global_capability
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn request_permission(
        &self,
        _permission: FocusedOutputPermission,
    ) -> Result<FocusedOutputCapability, FocusedOutputReasonCode> {
        Ok(self.global_capability())
    }

    fn begin(
        &self,
        context: BeginContext,
        event_sink: Arc<dyn SessionEventSink>,
        cancellation: SessionCancellation,
    ) -> Result<BeginSession, FocusedOutputReasonCode> {
        if self.state.shut_down.load(Ordering::Acquire) {
            return Err(FocusedOutputReasonCode::BackendDisconnected);
        }

        let capability = self
            .state
            .route_capability
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if context.auto_submit_requested && !capability.supports_auto_submit() {
            return Err(FocusedOutputReasonCode::AutoSubmitUnsupported);
        }
        let script = self
            .state
            .scripts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .unwrap_or_else(|| Ok(FakeSessionScript::complete()))?;
        let receipt = BeginReceipt::new(context.session_id, capability.clone(), None)
            .expect("fake route capability must be resolved");
        let route_number = self.state.next_route_number.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(FakeSessionState::new(
            context.session_id,
            route_number,
            Arc::clone(&event_sink),
        ));
        self.state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::clone(&state));

        Ok(BeginSession {
            receipt,
            session: Box::new(FakeTargetSession {
                session_id: context.session_id,
                capability,
                event_sink,
                cancellation,
                script,
                state,
            }),
        })
    }

    fn shutdown(&self) {
        if !self.state.shut_down.swap(true, Ordering::AcqRel) {
            self.state.shutdown_calls.fetch_add(1, Ordering::AcqRel);
        }
    }
}

struct FakeTargetSession {
    session_id: DictationSessionId,
    capability: FocusedOutputCapability,
    event_sink: Arc<dyn SessionEventSink>,
    cancellation: SessionCancellation,
    script: FakeSessionScript,
    state: Arc<FakeSessionState>,
}

impl FakeTargetSession {
    fn rejected(reason: FocusedOutputReasonCode) -> InsertOutcome {
        InsertOutcome::Rejected { reason }
    }
}

impl FocusedTargetSession for FakeTargetSession {
    fn capability(&self) -> &FocusedOutputCapability {
        &self.capability
    }

    fn insert_if_valid(&mut self, request: InsertionRequest) -> InsertOutcome {
        if self.state.closed.load(Ordering::Acquire) {
            return Self::rejected(FocusedOutputReasonCode::TargetClosed);
        }
        if self.cancellation.is_cancelled() {
            return Self::rejected(FocusedOutputReasonCode::Cancelled);
        }
        if request.session_id != self.session_id {
            return Self::rejected(FocusedOutputReasonCode::TargetChanged);
        }

        let injection_id = request.injection_id;
        self.state
            .insertion_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(FakeInsertionCall {
                session_id: request.session_id,
                injection_id,
                text: request.text,
                kind: request.kind,
            });
        self.state
            .call_order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(match request.kind {
                InsertionKind::Speech => FakeCallKind::InsertSpeech,
                InsertionKind::TrailingSpace => FakeCallKind::InsertTrailingSpace,
            });
        let outcome = self
            .script
            .insert_outcomes
            .pop_front()
            .unwrap_or(InsertOutcome::Complete {
                receipt: self
                    .capability
                    .route()
                    .expect("fake target route is resolved")
                    .receipt_confidence,
            });
        if matches!(
            outcome,
            InsertOutcome::Complete { .. } | InsertOutcome::Partial { .. }
        ) {
            self.event_sink.publish(
                self.session_id,
                TargetInteractionEvent::HandyInsertionObserved {
                    injection_id,
                    caret_after: None,
                },
            );
        }
        outcome
    }

    fn submit_if_valid(&mut self, key: AutoSubmitKey) -> SubmitOutcome {
        if self.state.closed.load(Ordering::Acquire) {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetClosed,
            };
        }
        if self.cancellation.is_cancelled() {
            return SubmitOutcome::Rejected {
                reason: FocusedOutputReasonCode::Cancelled,
            };
        }
        self.state
            .submit_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(key);
        self.state
            .call_order
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(FakeCallKind::Submit);
        self.script
            .submit_outcomes
            .pop_front()
            .unwrap_or(SubmitOutcome::Complete {
                receipt: self
                    .capability
                    .route()
                    .expect("fake target route is resolved")
                    .receipt_confidence,
            })
    }

    fn close(&mut self) {
        if !self.state.closed.swap(true, Ordering::AcqRel) {
            self.state.close_calls.fetch_add(1, Ordering::AcqRel);
            self.state
                .call_order
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(FakeCallKind::Close);
        }
    }
}

impl Drop for FakeTargetSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focused_output::manager::FocusedOutputManager;
    use crate::focused_output::types::{
        FinalDeliveryDisposition, FinalizeOptions, FocusedDeliveryDisposition, ObservationId,
        SubmitDisposition, TerminalReason, TranscriptSnapshot, UnsafeEditKind,
    };
    use crate::settings::ClipboardHandling;
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<(DictationSessionId, TargetInteractionEvent)>>,
    }

    impl SessionEventSink for RecordingSink {
        fn publish(&self, session_id: DictationSessionId, event: TargetInteractionEvent) {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((session_id, event));
        }
    }

    fn context(session_id: DictationSessionId, auto_submit_requested: bool) -> BeginContext {
        BeginContext {
            session_id,
            control_shortcut: None,
            auto_submit_requested,
            #[cfg(target_os = "linux")]
            typing_tool: crate::settings::TypingTool::Auto,
        }
    }

    fn request(
        session_id: DictationSessionId,
        injection_id: u64,
        text: &str,
        kind: InsertionKind,
    ) -> InsertionRequest {
        InsertionRequest {
            session_id,
            injection_id: InjectionId(injection_id),
            text: text.to_owned(),
            kind,
        }
    }

    fn finalize_options(append_trailing_space: bool, auto_submit: bool) -> FinalizeOptions {
        FinalizeOptions {
            append_trailing_space,
            clipboard_handling: ClipboardHandling::DontModify,
            auto_submit,
            auto_submit_key: AutoSubmitKey::Enter,
            history_available: true,
        }
    }

    fn publish_until_inserted(
        manager: &FocusedOutputManager,
        session: &FakeSessionHandle,
        expected: usize,
        session_id: DictationSessionId,
        revision: u64,
        committed: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while session.insertion_count() < expected {
            assert!(
                Instant::now() < deadline,
                "focused manager did not reach the expected insertion count"
            );
            manager.publish_snapshot(TranscriptSnapshot {
                session_id,
                revision,
                committed: committed.to_owned(),
                tentative: String::new(),
            });
            thread::yield_now();
        }
    }

    #[test]
    fn capability_states_preserve_route_invariants() {
        let unavailable = FocusedOutputCapability::unavailable(
            FocusedOutputBackend::Test,
            FocusedOutputReasonCode::PlatformUnsupported,
        );
        assert!(!unavailable.available());
        assert_eq!(
            unavailable.safety_level(),
            FocusedOutputSafetyLevel::Unavailable
        );
        assert_eq!(unavailable.route(), None);
        assert!(unavailable.reason_code().is_some());

        let global = FocusedOutputCapability::global_ready(FocusedOutputBackend::Test);
        assert!(global.available());
        assert_eq!(global.safety_level(), FocusedOutputSafetyLevel::Unavailable);
        assert_eq!(global.route(), None);
        assert_eq!(global.reason_code(), None);

        let verified = verified_capability(true);
        assert!(verified.is_resolved());
        assert_eq!(
            verified.safety_level(),
            FocusedOutputSafetyLevel::VerifiedControl
        );
        assert_eq!(verified.route(), Some(VERIFIED_ROUTE));
        assert_eq!(verified.reason_code(), None);
        assert!(verified.supports_auto_submit());

        let posted = posted_capability(false);
        assert!(posted.is_resolved());
        assert_eq!(
            posted.safety_level(),
            FocusedOutputSafetyLevel::GuardedFocusedControl
        );
        assert_eq!(posted.route(), Some(POSTED_ROUTE));
        assert_eq!(posted.reason_code(), None);
        assert!(!posted.supports_auto_submit());
    }

    #[test]
    fn fake_rejects_requested_submit_before_target_capture_when_route_cannot_submit() {
        let backend = FakeBackend::new(posted_capability(false));
        let result = backend.begin(
            context(DictationSessionId(6), true),
            Arc::new(RecordingSink::default()),
            SessionCancellation::default(),
        );
        assert!(matches!(
            result,
            Err(FocusedOutputReasonCode::AutoSubmitUnsupported)
        ));
        assert!(backend.sessions().is_empty());
    }

    #[test]
    fn fake_route_is_pinned_and_session_tags_are_exact() {
        let backend = FakeBackend::new(verified_capability(true));
        let sink = Arc::new(RecordingSink::default());
        let cancellation = SessionCancellation::default();
        let session_id = DictationSessionId(7);
        let mut captured = backend
            .begin(context(session_id, true), sink, cancellation)
            .unwrap();

        backend.set_route_capability(posted_capability(false));
        assert_eq!(captured.receipt.session_id(), session_id);
        assert_eq!(captured.session.capability().route(), Some(VERIFIED_ROUTE));
        assert_eq!(
            captured.session.insert_if_valid(request(
                DictationSessionId(8),
                1,
                "private wrong-session text",
                InsertionKind::Speech,
            )),
            InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::TargetChanged,
            }
        );
        assert_eq!(backend.session(session_id).insertion_count(), 0);

        assert!(matches!(
            captured.session.insert_if_valid(request(
                session_id,
                2,
                "private exact-session text",
                InsertionKind::Speech,
            )),
            InsertOutcome::Complete {
                receipt: ReceiptConfidence::Verified
            }
        ));
        assert_eq!(
            backend.session(session_id).insertion_session_ids(),
            [session_id]
        );
        captured.session.close();
        captured.session.close();
        drop(captured);
        assert_eq!(backend.session(session_id).close_calls(), 1);
    }

    #[test]
    fn scripts_preserve_each_outcome_and_acknowledgement() {
        let outcomes = [
            InsertOutcome::Complete {
                receipt: ReceiptConfidence::Verified,
            },
            InsertOutcome::Partial {
                accepted_bytes: 1,
                receipt: ReceiptConfidence::Verified,
                reason: FocusedOutputReasonCode::InjectionPartial,
            },
            InsertOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            },
            InsertOutcome::Rejected {
                reason: FocusedOutputReasonCode::InjectionDenied,
            },
        ];
        let backend = FakeBackend::new(verified_capability(true));
        backend.queue_script(FakeSessionScript::new(
            outcomes,
            [
                SubmitOutcome::Complete {
                    receipt: ReceiptConfidence::Verified,
                },
                SubmitOutcome::Ambiguous {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous,
                },
                SubmitOutcome::Rejected {
                    reason: FocusedOutputReasonCode::InjectionDenied,
                },
            ],
        ));
        let sink = Arc::new(RecordingSink::default());
        let session_id = DictationSessionId(9);
        let mut captured = backend
            .begin(
                context(session_id, true),
                sink.clone(),
                SessionCancellation::default(),
            )
            .unwrap();

        for (index, expected) in outcomes.into_iter().enumerate() {
            assert_eq!(
                captured.session.insert_if_valid(request(
                    session_id,
                    index as u64 + 1,
                    "private scripted insertion",
                    InsertionKind::Speech,
                )),
                expected
            );
        }
        assert_eq!(
            sink.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            2
        );
        let acknowledged_ids: Vec<_> = sink
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(_, event)| match event {
                TargetInteractionEvent::HandyInsertionObserved { injection_id, .. } => injection_id,
                _ => panic!("fake only emits Handy insertion acknowledgements"),
            })
            .copied()
            .collect();
        assert_eq!(acknowledged_ids, [InjectionId(1), InjectionId(2)]);

        assert!(matches!(
            captured.session.submit_if_valid(AutoSubmitKey::Enter),
            SubmitOutcome::Complete { .. }
        ));
        assert!(matches!(
            captured.session.submit_if_valid(AutoSubmitKey::CtrlEnter),
            SubmitOutcome::Ambiguous { .. }
        ));
        assert!(matches!(
            captured.session.submit_if_valid(AutoSubmitKey::CmdEnter),
            SubmitOutcome::Rejected { .. }
        ));
        assert_eq!(backend.session(session_id).submit_count(), 3);
    }

    #[test]
    fn backend_shutdown_is_immediate_and_idempotent_at_the_boundary() {
        let backend = FakeBackend::new(verified_capability(false));
        backend.shutdown();
        backend.shutdown();
        assert_eq!(backend.shutdown_calls(), 1);
        let result = backend.begin(
            context(DictationSessionId(1), false),
            Arc::new(RecordingSink::default()),
            SessionCancellation::default(),
        );
        assert!(matches!(
            result,
            Err(FocusedOutputReasonCode::BackendDisconnected)
        ));
    }

    #[test]
    fn manager_runs_250_deterministic_lifecycles_with_exact_routes_and_tags() {
        let backend = FakeBackend::new(verified_capability(false));
        let manager = FocusedOutputManager::new(Arc::new(backend.clone()));

        for sequence in 0..250 {
            let mode = sequence % 5;
            let (capability, outcome) = match mode {
                0 => (
                    verified_capability(false),
                    InsertOutcome::Complete {
                        receipt: ReceiptConfidence::Verified,
                    },
                ),
                1 => (
                    posted_capability(false),
                    InsertOutcome::Complete {
                        receipt: ReceiptConfidence::Posted,
                    },
                ),
                2 => (
                    verified_capability(false),
                    InsertOutcome::Partial {
                        accepted_bytes: 1,
                        receipt: ReceiptConfidence::Verified,
                        reason: FocusedOutputReasonCode::InjectionPartial,
                    },
                ),
                3 => (
                    verified_capability(false),
                    InsertOutcome::Ambiguous {
                        reason: FocusedOutputReasonCode::InjectionAmbiguous,
                    },
                ),
                _ => (
                    verified_capability(false),
                    InsertOutcome::Rejected {
                        reason: FocusedOutputReasonCode::InjectionDenied,
                    },
                ),
            };
            backend.set_route_capability(capability.clone());
            backend.queue_script(FakeSessionScript::new([outcome], []));

            let session_id = manager.allocate_session_id();
            let receipt = manager.begin(context(session_id, false)).unwrap();
            assert_eq!(receipt.session_id(), session_id);
            assert_eq!(receipt.capability(), &capability);
            assert_eq!(manager.active_session_id(), Some(session_id));

            let competing_id = manager.allocate_session_id();
            assert!(matches!(
                manager.begin(context(competing_id, false)),
                Err(FocusedOutputReasonCode::AlreadyActive)
            ));
            assert_eq!(manager.active_session_id(), Some(session_id));

            let final_text = format!("s{sequence}");
            manager.publish_snapshot(TranscriptSnapshot {
                session_id,
                revision: 0,
                committed: final_text.clone(),
                tentative: String::new(),
            });
            let disposition = manager.finalize(
                session_id,
                final_text,
                Some(0),
                finalize_options(false, false),
            );

            match (mode, disposition) {
                (
                    0,
                    FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered {
                        receipt_confidence: ReceiptConfidence::Verified,
                        ..
                    }),
                )
                | (
                    1,
                    FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered {
                        receipt_confidence: ReceiptConfidence::Posted,
                        ..
                    }),
                ) => {}
                (
                    2,
                    FinalDeliveryDisposition::Focused(
                        FocusedDeliveryDisposition::PreservePartial {
                            reason: TerminalReason::PartialInsertion,
                            speech_delivered_chars: 1,
                            ..
                        },
                    ),
                ) => {}
                (
                    3,
                    FinalDeliveryDisposition::Focused(
                        FocusedDeliveryDisposition::PreservePartial {
                            reason: TerminalReason::AmbiguousInsertion,
                            speech_delivered_chars: 0,
                            ..
                        },
                    ),
                ) => {}
                (
                    4,
                    FinalDeliveryDisposition::Focused(
                        FocusedDeliveryDisposition::PreservePartial {
                            reason: TerminalReason::TargetInvalidated,
                            speech_delivered_chars: 0,
                            ..
                        },
                    ),
                ) => {}
                _ => panic!("unexpected deterministic lifecycle disposition"),
            }

            let session = backend.session(session_id);
            assert_eq!(session.insertion_count(), 1);
            assert_eq!(session.insertion_session_ids(), [session_id]);
            assert_eq!(session.insertion_kinds(), [InsertionKind::Speech]);
            assert_eq!(session.close_calls(), 1);
            assert_eq!(manager.active_session_id(), None);
        }

        let sessions = backend.sessions();
        assert_eq!(sessions.len(), 250);
        for (index, session) in sessions.iter().enumerate() {
            assert_eq!(session.session_id().get(), (index as u64) * 2 + 1);
            assert_eq!(session.route_number(), index + 1);
            assert_eq!(session.close_calls(), 1);
        }
        manager.shutdown();
    }

    #[test]
    fn manager_runs_100_mixed_input_sequences_without_coalescing_acknowledgements() {
        let backend = FakeBackend::new(verified_capability(false));
        let manager = FocusedOutputManager::new(Arc::new(backend.clone()));
        let mut previous: Option<(DictationSessionId, FakeSessionHandle)> = None;

        for sequence in 0..100 {
            let session_id = manager.allocate_session_id();
            manager.begin(context(session_id, false)).unwrap();
            let session = backend.session(session_id);

            if let Some((stale_id, stale_session)) = previous.take() {
                stale_session.publish_tagged(
                    stale_id,
                    TargetInteractionEvent::UnsafeEdit {
                        observation_id: ObservationId(500),
                        kind: UnsafeEditKind::Delete,
                    },
                );
                manager.terminate(stale_id, TerminalReason::Cancelled);
                manager.publish_snapshot(TranscriptSnapshot {
                    session_id: stale_id,
                    revision: 999,
                    committed: "private stale snapshot".to_owned(),
                    tentative: String::new(),
                });
            }

            let initial = format!("m{sequence}");
            publish_until_inserted(&manager, &session, 1, session_id, 0, &initial);

            session.publish_tagged(
                session_id,
                TargetInteractionEvent::CompatibleExternalInsertion {
                    observation_id: ObservationId(1),
                    chars: 1,
                    caret_after: None,
                },
            );
            let final_text = format!("{initial}z");
            publish_until_inserted(&manager, &session, 2, session_id, 1, &final_text);

            let disposition = manager.finalize(
                session_id,
                final_text,
                Some(1),
                finalize_options(false, false),
            );
            assert!(matches!(
                disposition,
                FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered {
                    external_edit_epoch: 1,
                    ..
                })
            ));
            assert_eq!(
                session.call_order(),
                [
                    FakeCallKind::InsertSpeech,
                    FakeCallKind::InsertSpeech,
                    FakeCallKind::Close,
                ]
            );
            assert_eq!(session.insertion_session_ids(), [session_id, session_id]);
            let insertion_ids = session.insertion_ids();
            assert_eq!(insertion_ids.len(), 2);
            assert_ne!(insertion_ids[0], insertion_ids[1]);
            assert_eq!(session.inserted_texts(), [initial, "z".to_owned()]);
            assert_eq!(session.close_calls(), 1);
            assert_eq!(manager.active_session_id(), None);
            previous = Some((session_id, session));
        }

        assert_eq!(backend.sessions().len(), 100);
        manager.shutdown();
    }

    #[test]
    fn manager_terminal_is_first_wins_and_stale_activity_is_a_no_op() {
        let backend = FakeBackend::new(verified_capability(false));
        let manager = FocusedOutputManager::new(Arc::new(backend.clone()));
        let first_id = manager.allocate_session_id();
        manager.begin(context(first_id, false)).unwrap();
        let first_session = backend.session(first_id);

        manager.terminate(first_id, TerminalReason::UnsafeUserEdit);
        manager.terminate(first_id, TerminalReason::Cancelled);
        let first_disposition = manager.finalize(
            first_id,
            "private terminal final".to_owned(),
            None,
            finalize_options(false, false),
        );
        assert!(matches!(
            first_disposition,
            FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::PreservePartial {
                reason: TerminalReason::UnsafeUserEdit,
                ..
            })
        ));

        let second_id = manager.allocate_session_id();
        manager.begin(context(second_id, false)).unwrap();
        manager.terminate(first_id, TerminalReason::Cancelled);
        first_session.publish_tagged(
            first_id,
            TargetInteractionEvent::MonitorUnavailable {
                observation_id: ObservationId(2),
            },
        );
        manager.publish_snapshot(TranscriptSnapshot {
            session_id: first_id,
            revision: 100,
            committed: "private stale terminal snapshot".to_owned(),
            tentative: String::new(),
        });

        let second_disposition = manager.finalize(
            second_id,
            "current".to_owned(),
            None,
            finalize_options(false, false),
        );
        assert!(matches!(
            second_disposition,
            FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered { .. })
        ));
        assert_eq!(
            backend.session(second_id).insertion_session_ids(),
            [second_id]
        );
        assert_eq!(first_session.close_calls(), 1);
        assert_eq!(backend.session(second_id).close_calls(), 1);
        manager.shutdown();
    }

    #[test]
    fn manager_submits_only_after_complete_speech_and_trailing_space() {
        let backend = FakeBackend::new(verified_capability(true));
        let manager = FocusedOutputManager::new(Arc::new(backend.clone()));

        let complete_id = manager.allocate_session_id();
        backend.queue_script(FakeSessionScript::new(
            [],
            [SubmitOutcome::Complete {
                receipt: ReceiptConfidence::Verified,
            }],
        ));
        manager.begin(context(complete_id, true)).unwrap();
        let complete = manager.finalize(
            complete_id,
            "complete".to_owned(),
            None,
            finalize_options(true, true),
        );
        assert!(matches!(
            complete,
            FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered {
                trailing_space_delivered: true,
                submit: SubmitDisposition::Submitted {
                    receipt: ReceiptConfidence::Verified
                },
                ..
            })
        ));
        assert_eq!(
            backend.session(complete_id).call_order(),
            [
                FakeCallKind::InsertSpeech,
                FakeCallKind::InsertTrailingSpace,
                FakeCallKind::Submit,
                FakeCallKind::Close,
            ]
        );

        let partial_id = manager.allocate_session_id();
        backend.queue_script(FakeSessionScript::new(
            [InsertOutcome::Partial {
                accepted_bytes: 1,
                receipt: ReceiptConfidence::Verified,
                reason: FocusedOutputReasonCode::InjectionPartial,
            }],
            [SubmitOutcome::Complete {
                receipt: ReceiptConfidence::Verified,
            }],
        ));
        manager.begin(context(partial_id, true)).unwrap();
        let partial = manager.finalize(
            partial_id,
            "partial".to_owned(),
            None,
            finalize_options(true, true),
        );
        assert!(matches!(
            partial,
            FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::PreservePartial {
                reason: TerminalReason::PartialInsertion,
                ..
            })
        ));
        assert_eq!(
            backend.session(partial_id).call_order(),
            [FakeCallKind::InsertSpeech, FakeCallKind::Close]
        );
        assert_eq!(backend.session(partial_id).submit_count(), 0);

        let trailing_rejected_id = manager.allocate_session_id();
        backend.queue_script(FakeSessionScript::new(
            [
                InsertOutcome::Complete {
                    receipt: ReceiptConfidence::Verified,
                },
                InsertOutcome::Rejected {
                    reason: FocusedOutputReasonCode::TargetChanged,
                },
            ],
            [SubmitOutcome::Complete {
                receipt: ReceiptConfidence::Verified,
            }],
        ));
        manager.begin(context(trailing_rejected_id, true)).unwrap();
        let trailing_rejected = manager.finalize(
            trailing_rejected_id,
            "speech".to_owned(),
            None,
            finalize_options(true, true),
        );
        assert!(matches!(
            trailing_rejected,
            FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::PreservePartial {
                reason: TerminalReason::TargetInvalidated,
                ..
            })
        ));
        assert_eq!(
            backend.session(trailing_rejected_id).call_order(),
            [
                FakeCallKind::InsertSpeech,
                FakeCallKind::InsertTrailingSpace,
                FakeCallKind::Close,
            ]
        );
        assert_eq!(backend.session(trailing_rejected_id).submit_count(), 0);

        let submit_ambiguous_id = manager.allocate_session_id();
        backend.queue_script(FakeSessionScript::new(
            [],
            [SubmitOutcome::Ambiguous {
                reason: FocusedOutputReasonCode::InjectionAmbiguous,
            }],
        ));
        manager.begin(context(submit_ambiguous_id, true)).unwrap();
        let submit_ambiguous = manager.finalize(
            submit_ambiguous_id,
            "speech".to_owned(),
            None,
            finalize_options(false, true),
        );
        assert!(matches!(
            submit_ambiguous,
            FinalDeliveryDisposition::Focused(FocusedDeliveryDisposition::Delivered {
                submit: SubmitDisposition::Failed {
                    reason: FocusedOutputReasonCode::InjectionAmbiguous
                },
                ..
            })
        ));
        assert_eq!(
            backend.session(submit_ambiguous_id).call_order(),
            [
                FakeCallKind::InsertSpeech,
                FakeCallKind::Submit,
                FakeCallKind::Close,
            ]
        );
        manager.shutdown();
    }

    #[test]
    fn manager_shutdown_is_bounded_and_close_is_idempotent() {
        let backend = FakeBackend::new(verified_capability(false));
        let manager = FocusedOutputManager::new(Arc::new(backend.clone()));
        let session_id = manager.allocate_session_id();
        manager.begin(context(session_id, false)).unwrap();
        let session = backend.session(session_id);

        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let shutdown_manager = Arc::clone(&manager);
        let shutdown_thread = thread::spawn(move || {
            shutdown_manager.shutdown();
            let _ = finished_tx.send(());
        });
        assert!(
            finished_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "focused manager shutdown exceeded its bounded deadline"
        );
        shutdown_thread.join().unwrap();

        manager.shutdown();
        assert_eq!(backend.shutdown_calls(), 1);
        assert_eq!(session.close_calls(), 1);
        assert_eq!(manager.active_session_id(), None);
    }
}
