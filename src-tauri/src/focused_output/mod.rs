pub mod coediting;
pub mod commands;
pub mod manager;
pub mod metrics;
pub mod observer;
pub mod platform;
pub mod speech_ledger;
pub mod types;

pub use commands::TauriFocusedOutputStatusSink;
pub use manager::{FocusedOutputManager, FocusedOutputStatusSink};
pub use observer::{
    FocusedOutputPublisher, NoopStreamTranscriptObserver, StreamLifecycleEvent,
    StreamObserverError, StreamTranscriptObserver,
};
pub use platform::{BeginSession, FocusedFieldBackend, FocusedTargetSession, SessionEventSink};
pub use types::*;
