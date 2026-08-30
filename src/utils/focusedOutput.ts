import type {
  FocusedOutputBackend,
  FocusedOutputReasonCode,
  FocusedOutputSafetyLevel,
  FocusedOutputStatus,
  InsertionTransport,
  MixedInputSupport,
  ReceiptConfidence,
} from "@/bindings";

export const focusedOutputReasonKey: Record<FocusedOutputReasonCode, string> = {
  disabled: "focusedOutput.reasons.disabled",
  experimental_features_disabled:
    "focusedOutput.reasons.experimentalFeaturesDisabled",
  model_does_not_support_streaming:
    "focusedOutput.reasons.modelDoesNotSupportStreaming",
  post_processing_incompatible:
    "focusedOutput.reasons.postProcessingIncompatible",
  paste_method_disabled: "focusedOutput.reasons.pasteMethodDisabled",
  external_script_incompatible:
    "focusedOutput.reasons.externalScriptIncompatible",
  accessibility_permission_missing:
    "focusedOutput.reasons.accessibilityPermissionMissing",
  input_monitoring_permission_missing:
    "focusedOutput.reasons.inputMonitoringPermissionMissing",
  at_spi_unavailable: "focusedOutput.reasons.atSpiUnavailable",
  typing_tool_unavailable: "focusedOutput.reasons.typingToolUnavailable",
  control_shortcut_unsupported:
    "focusedOutput.reasons.controlShortcutUnsupported",
  auto_submit_unsupported: "focusedOutput.reasons.autoSubmitUnsupported",
  secure_input_active: "focusedOutput.reasons.secureInputActive",
  secure_field: "focusedOutput.reasons.secureField",
  handy_owned_target: "focusedOutput.reasons.handyOwnedTarget",
  no_focused_target: "focusedOutput.reasons.noFocusedTarget",
  target_not_editable: "focusedOutput.reasons.targetNotEditable",
  initial_selection_not_collapsed:
    "focusedOutput.reasons.initialSelectionNotCollapsed",
  target_unsupported: "focusedOutput.reasons.targetUnsupported",
  target_changed: "focusedOutput.reasons.targetChanged",
  physical_pointer_activity: "focusedOutput.reasons.physicalPointerActivity",
  destructive_user_edit: "focusedOutput.reasons.destructiveUserEdit",
  caret_moved: "focusedOutput.reasons.caretMoved",
  selection_changed: "focusedOutput.reasons.selectionChanged",
  unsafe_keyboard_command: "focusedOutput.reasons.unsafeKeyboardCommand",
  ime_composition_unsupported:
    "focusedOutput.reasons.imeCompositionUnsupported",
  mixed_input_unavailable: "focusedOutput.reasons.mixedInputUnavailable",
  target_closed: "focusedOutput.reasons.targetClosed",
  monitor_unavailable: "focusedOutput.reasons.monitorUnavailable",
  backend_disconnected: "focusedOutput.reasons.backendDisconnected",
  injection_denied: "focusedOutput.reasons.injectionDenied",
  injection_partial: "focusedOutput.reasons.injectionPartial",
  injection_ambiguous: "focusedOutput.reasons.injectionAmbiguous",
  injection_failed: "focusedOutput.reasons.injectionFailed",
  receipt_timeout: "focusedOutput.reasons.receiptTimeout",
  final_conflict: "focusedOutput.reasons.finalConflict",
  history_unavailable: "focusedOutput.reasons.historyUnavailable",
  stream_failed: "focusedOutput.reasons.streamFailed",
  cancelled: "focusedOutput.reasons.cancelled",
  platform_unsupported: "focusedOutput.reasons.platformUnsupported",
  already_active: "focusedOutput.reasons.alreadyActive",
};

export const focusedOutputStatusKey: Record<FocusedOutputStatus, string> = {
  armed: "focusedOutput.statuses.armed",
  streaming: "focusedOutput.statuses.streaming",
  fallback: "focusedOutput.statuses.fallback",
  invalidated: "focusedOutput.statuses.invalidated",
  conflict: "focusedOutput.statuses.conflict",
  completed: "focusedOutput.statuses.completed",
  cancelled: "focusedOutput.statuses.cancelled",
  faulted: "focusedOutput.statuses.faulted",
};

export const focusedOutputBackendKey: Record<FocusedOutputBackend, string> = {
  windows: "focusedOutput.capability.backend.values.windows",
  mac_os: "focusedOutput.capability.backend.values.macOs",
  linux_at_spi: "focusedOutput.capability.backend.values.linuxAtSpi",
  test: "focusedOutput.capability.backend.values.test",
};

export const focusedOutputSafetyKey: Record<FocusedOutputSafetyLevel, string> =
  {
    verified_control: "focusedOutput.capability.safety.values.verifiedControl",
    guarded_focused_control:
      "focusedOutput.capability.safety.values.guardedFocusedControl",
    unavailable: "focusedOutput.capability.safety.values.unavailable",
  };

export const insertionTransportKey: Record<InsertionTransport, string> = {
  windows_unicode_send_input:
    "focusedOutput.capability.insertionRoute.values.windowsUnicodeSendInput",
  mac_ax_selected_text:
    "focusedOutput.capability.insertionRoute.values.macAxSelectedText",
  mac_cg_event_unicode:
    "focusedOutput.capability.insertionRoute.values.macCgEventUnicode",
  at_spi_editable_text:
    "focusedOutput.capability.insertionRoute.values.atSpiEditableText",
  linux_focused_keyboard:
    "focusedOutput.capability.insertionRoute.values.linuxFocusedKeyboard",
  test: "focusedOutput.capability.insertionRoute.values.test",
};

export const receiptConfidenceKey: Record<ReceiptConfidence, string> = {
  verified: "focusedOutput.capability.receiptConfidence.values.verified",
  posted: "focusedOutput.capability.receiptConfidence.values.posted",
};

export const mixedInputSupportKey: Record<MixedInputSupport, string> = {
  observed_insertions_only:
    "focusedOutput.capability.mixedInputSupport.values.observedInsertionsOnly",
  guarded_keyboard_insertions_only:
    "focusedOutput.capability.mixedInputSupport.values.guardedKeyboardInsertionsOnly",
  unavailable: "focusedOutput.capability.mixedInputSupport.values.unavailable",
};
