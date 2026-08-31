use super::types::{
    BeginContext, BeginReceipt, DictationSessionId, FocusedOutputCapability,
    FocusedOutputPermission, FocusedOutputReasonCode, InsertOutcome, InsertionRequest,
    SessionCancellation, SubmitOutcome, TargetInteractionEvent,
};
use crate::settings::AutoSubmitKey;
use std::sync::Arc;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::LinuxFocusedFieldBackend;
#[cfg(target_os = "macos")]
pub use macos::MacFocusedFieldBackend;
#[cfg(target_os = "windows")]
pub use windows::WindowsFocusedFieldBackend;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn native_backend() -> Arc<dyn FocusedFieldBackend> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(LinuxFocusedFieldBackend::new())
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacFocusedFieldBackend::new())
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(WindowsFocusedFieldBackend::new())
    }
}

/// Content-free event destination used by platform monitors. Implementations
/// must return promptly; native callback paths publish through bounded,
/// nonblocking adapters rather than calling manager or target APIs directly.
pub trait SessionEventSink: Send + Sync {
    fn publish(&self, session_id: DictationSessionId, event: TargetInteractionEvent);
}

/// Successful target capture and its route-pinned session.
pub struct BeginSession {
    pub receipt: BeginReceipt,
    pub session: Box<dyn FocusedTargetSession>,
}

/// Platform-global entry point. Capability probing must not prompt for
/// permissions or start target/input monitoring.
pub trait FocusedFieldBackend: Send + Sync {
    fn global_capability(&self) -> FocusedOutputCapability;

    fn request_permission(
        &self,
        permission: FocusedOutputPermission,
    ) -> Result<FocusedOutputCapability, FocusedOutputReasonCode>;

    fn begin(
        &self,
        context: BeginContext,
        event_sink: Arc<dyn SessionEventSink>,
        cancellation: SessionCancellation,
    ) -> Result<BeginSession, FocusedOutputReasonCode>;

    fn shutdown(&self);
}

/// A single captured target and insertion route. The absence of validate or
/// route parameters is intentional: each insert/submit operation revalidates
/// the captured target and performs at most one guarded dispatch unit under the
/// same platform gate. A caller cannot switch routes after Begin.
pub trait FocusedTargetSession: Send {
    fn capability(&self) -> &FocusedOutputCapability;

    fn insert_if_valid(&mut self, request: InsertionRequest) -> InsertOutcome;

    fn submit_if_valid(&mut self, key: AutoSubmitKey) -> SubmitOutcome;

    /// Idempotently disarms monitoring and releases the captured target.
    fn close(&mut self);
}

#[cfg(test)]
pub(crate) mod conformance;

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_backend_object_safe(_: Option<Arc<dyn FocusedFieldBackend>>) {}
    fn assert_session_object_safe(_: Option<Box<dyn FocusedTargetSession>>) {}
    fn assert_sink_object_safe(_: Option<Arc<dyn SessionEventSink>>) {}

    #[test]
    fn contracts_are_object_safe() {
        assert_backend_object_safe(None);
        assert_session_object_safe(None);
        assert_sink_object_safe(None);
    }
}

#[cfg(all(test, target_os = "windows"))]
#[allow(unused_imports)]
mod windows_dependency_contract {
    use windows::Win32::System::Com as _;
    use windows::Win32::UI::Accessibility as _;
    use windows::Win32::UI::Input::KeyboardAndMouse as _;
}

#[cfg(all(test, target_os = "macos"))]
#[allow(unused_imports)]
mod macos_dependency_contract {
    use objc2_application_services as _;
    use objc2_core_foundation as _;
    use objc2_core_graphics as _;
}

#[cfg(all(test, target_os = "linux"))]
mod linux_dependency_contract {
    use atspi::zbus as _;

    #[allow(dead_code)]
    fn required_tokio_features_compile() {
        let _runtime = tokio::runtime::Builder::new_current_thread();
        let (_sender, _receiver) = tokio::sync::mpsc::channel::<()>(1);
        let _instant = tokio::time::Instant::now();
    }
}
