use super::manager::FocusedOutputManager;
use super::{DictationSessionId, FocusedOutputReasonCode, TerminalReason, TranscriptSnapshot};
use std::sync::Arc;

/// Content-free lifecycle notifications emitted by a native streaming worker.
///
/// Worker tokens distinguish successive workers associated with a dictation
/// session. Failure and unavailability reasons are stable codes; they must
/// never contain engine errors or transcript text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamLifecycleEvent {
    Started {
        session_id: DictationSessionId,
        worker_token: u64,
    },
    Unavailable {
        session_id: DictationSessionId,
        reason: FocusedOutputReasonCode,
    },
    Failed {
        session_id: DictationSessionId,
        reason: FocusedOutputReasonCode,
    },
    Ended {
        session_id: DictationSessionId,
        worker_token: u64,
    },
}

/// A content-free reason why a lifecycle notification was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamObserverError {
    QueueFull,
    Disconnected,
}

impl std::fmt::Display for StreamObserverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::QueueFull => "stream observer queue is full",
            Self::Disconnected => "stream observer is disconnected",
        })
    }
}

impl std::error::Error for StreamObserverError {}

/// Nonblocking boundary between native transcription and focused output.
///
/// Snapshot publication is deliberately lossy: the manager retains only the
/// newest relevant snapshot. Lifecycle publication reports bounded-channel
/// backpressure without waiting for capacity.
pub trait StreamTranscriptObserver: Send + Sync {
    fn publish_snapshot(&self, snapshot: TranscriptSnapshot);

    fn publish_lifecycle(&self, event: StreamLifecycleEvent) -> Result<(), StreamObserverError>;
}

/// Observer used when focused output is disabled or unavailable, including
/// headless and legacy-only operation.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopStreamTranscriptObserver;

impl StreamTranscriptObserver for NoopStreamTranscriptObserver {
    fn publish_snapshot(&self, _snapshot: TranscriptSnapshot) {}

    fn publish_lifecycle(&self, _event: StreamLifecycleEvent) -> Result<(), StreamObserverError> {
        Ok(())
    }
}

/// Production observer that forwards into the manager's bounded,
/// nonblocking publication paths.
#[derive(Clone)]
pub struct FocusedOutputPublisher {
    manager: Arc<FocusedOutputManager>,
}

impl FocusedOutputPublisher {
    pub fn new(manager: Arc<FocusedOutputManager>) -> Self {
        Self { manager }
    }
}

impl StreamTranscriptObserver for FocusedOutputPublisher {
    fn publish_snapshot(&self, snapshot: TranscriptSnapshot) {
        forward_snapshot(snapshot, |snapshot| {
            self.manager.publish_snapshot(snapshot);
        });
    }

    fn publish_lifecycle(&self, event: StreamLifecycleEvent) -> Result<(), StreamObserverError> {
        forward_lifecycle(
            event,
            |session_id, reason| self.manager.terminate(session_id, reason),
            |event| self.manager.publish_lifecycle(event),
        )
    }
}

fn forward_snapshot(snapshot: TranscriptSnapshot, sink: impl FnOnce(TranscriptSnapshot)) {
    sink(snapshot);
}

fn forward_lifecycle(
    event: StreamLifecycleEvent,
    terminate: impl FnOnce(DictationSessionId, TerminalReason),
    publish: impl FnOnce(StreamLifecycleEvent) -> Result<(), StreamObserverError>,
) -> Result<(), StreamObserverError> {
    if let StreamLifecycleEvent::Failed { session_id, .. } = event {
        // This tagged terminal transition is intentionally performed before
        // the best-effort queue wake. It remains effective if the queue is
        // full or disconnected, and stale session IDs are manager no-ops.
        terminate(session_id, TerminalReason::StreamFailed);
    }

    publish(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingObserver {
        snapshots: Mutex<Vec<TranscriptSnapshot>>,
        lifecycle: Mutex<Vec<StreamLifecycleEvent>>,
    }

    impl StreamTranscriptObserver for RecordingObserver {
        fn publish_snapshot(&self, snapshot: TranscriptSnapshot) {
            self.snapshots.lock().unwrap().push(snapshot);
        }

        fn publish_lifecycle(
            &self,
            event: StreamLifecycleEvent,
        ) -> Result<(), StreamObserverError> {
            self.lifecycle.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[test]
    fn observer_preserves_snapshot_and_lifecycle_tags() {
        let observer = RecordingObserver::default();
        observer.publish_snapshot(TranscriptSnapshot {
            session_id: DictationSessionId(17),
            revision: 4,
            committed: "committed".to_owned(),
            tentative: " tentative".to_owned(),
        });
        observer
            .publish_lifecycle(StreamLifecycleEvent::Started {
                session_id: DictationSessionId(17),
                worker_token: 29,
            })
            .unwrap();

        let snapshots = observer.snapshots.lock().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].session_id, DictationSessionId(17));
        assert_eq!(snapshots[0].revision, 4);
        assert_eq!(snapshots[0].committed, "committed");
        assert_eq!(snapshots[0].tentative, " tentative");
        drop(snapshots);

        assert_eq!(
            observer.lifecycle.lock().unwrap().as_slice(),
            &[StreamLifecycleEvent::Started {
                session_id: DictationSessionId(17),
                worker_token: 29,
            }]
        );
    }

    #[test]
    fn noop_observer_accepts_all_publications() {
        let observer = NoopStreamTranscriptObserver;
        observer.publish_snapshot(TranscriptSnapshot {
            session_id: DictationSessionId(3),
            revision: 0,
            committed: "not retained".to_owned(),
            tentative: String::new(),
        });

        assert_eq!(
            observer.publish_lifecycle(StreamLifecycleEvent::Ended {
                session_id: DictationSessionId(3),
                worker_token: 5,
            }),
            Ok(())
        );
    }

    #[test]
    fn publisher_seam_forwards_snapshot_without_retagging() {
        let mut recorded = None;
        forward_snapshot(
            TranscriptSnapshot {
                session_id: DictationSessionId(41),
                revision: 7,
                committed: "one".to_owned(),
                tentative: " two".to_owned(),
            },
            |snapshot| recorded = Some(snapshot),
        );

        let snapshot = recorded.unwrap();
        assert_eq!(snapshot.session_id, DictationSessionId(41));
        assert_eq!(snapshot.revision, 7);
        assert_eq!(snapshot.committed, "one");
        assert_eq!(snapshot.tentative, " two");
    }

    #[test]
    fn failed_lifecycle_marks_tagged_session_terminal_before_publication() {
        #[derive(Debug, PartialEq, Eq)]
        enum Call {
            Terminate(DictationSessionId, TerminalReason),
            Publish(StreamLifecycleEvent),
        }

        let calls = Mutex::new(Vec::new());
        let event = StreamLifecycleEvent::Failed {
            session_id: DictationSessionId(73),
            reason: FocusedOutputReasonCode::StreamFailed,
        };

        let result = forward_lifecycle(
            event,
            |session_id, reason| {
                calls
                    .lock()
                    .unwrap()
                    .push(Call::Terminate(session_id, reason))
            },
            |event| {
                calls.lock().unwrap().push(Call::Publish(event));
                Err(StreamObserverError::QueueFull)
            },
        );

        assert_eq!(result, Err(StreamObserverError::QueueFull));
        assert_eq!(
            calls.into_inner().unwrap(),
            vec![
                Call::Terminate(DictationSessionId(73), TerminalReason::StreamFailed),
                Call::Publish(event),
            ]
        );
    }

    #[test]
    fn nonfailed_lifecycle_does_not_terminate() {
        let mut terminated = false;
        let mut published = None;
        let event = StreamLifecycleEvent::Unavailable {
            session_id: DictationSessionId(91),
            reason: FocusedOutputReasonCode::ModelDoesNotSupportStreaming,
        };

        assert_eq!(
            forward_lifecycle(
                event,
                |_, _| terminated = true,
                |event| {
                    published = Some(event);
                    Ok(())
                },
            ),
            Ok(())
        );
        assert!(!terminated);
        assert_eq!(published, Some(event));
    }
}
