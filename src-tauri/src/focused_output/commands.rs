use super::{
    FocusedOutputCapability, FocusedOutputManager, FocusedOutputPermission,
    FocusedOutputReasonCode, FocusedOutputStatusEvent, FocusedOutputStatusSink,
};
use std::sync::Arc;
use tauri::{AppHandle, Manager};
use tauri_specta::Event;

pub struct TauriFocusedOutputStatusSink {
    app: AppHandle,
}

impl TauriFocusedOutputStatusSink {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl FocusedOutputStatusSink for TauriFocusedOutputStatusSink {
    fn publish(&self, event: &FocusedOutputStatusEvent) {
        let _ = event.clone().emit(&self.app);
    }
}

#[tauri::command]
#[specta::specta]
pub fn get_focused_output_capability(app: AppHandle) -> FocusedOutputCapability {
    app.state::<Arc<FocusedOutputManager>>().global_capability()
}

#[tauri::command]
#[specta::specta]
pub fn get_focused_output_status(app: AppHandle) -> Option<FocusedOutputStatusEvent> {
    app.state::<Arc<FocusedOutputManager>>().latest_status()
}

#[tauri::command]
#[specta::specta]
pub fn request_focused_output_permission(
    app: AppHandle,
    permission: FocusedOutputPermission,
) -> Result<FocusedOutputCapability, FocusedOutputReasonCode> {
    app.state::<Arc<FocusedOutputManager>>()
        .request_permission(permission)
}
