import { useEffect, useState, useRef, type ReactNode } from "react";
import { toast, Toaster } from "sonner";
import { useTranslation } from "react-i18next";
import { listen } from "@tauri-apps/api/event";
import { platform } from "@tauri-apps/plugin-os";
import {
  checkAccessibilityPermission,
  checkMicrophonePermission,
} from "tauri-plugin-macos-permissions-api";
import { ModelStateEvent, RecordingErrorEvent } from "./lib/types/events";
import "./App.css";
import AccessibilityPermissions from "./components/AccessibilityPermissions";
import SecureInputWarning from "./components/SecureInputWarning";
import Footer from "./components/footer";
import Onboarding, { AccessibilityOnboarding } from "./components/onboarding";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Sidebar, SidebarSection, SECTIONS_CONFIG } from "./components/Sidebar";
import { WhatsNewGate } from "./components/whats-new";
import { useSettings } from "./hooks/useSettings";
import { useSettingsStore } from "./stores/settingsStore";
import { commands, events, type ShortcutBackendStatus } from "@/bindings";
import { getLanguageDirection, initializeRTL } from "@/lib/utils/rtl";

type OnboardingStep = "accessibility" | "model" | "done";

const MAX_NOTIFIED_FOCUSED_OUTPUT_SESSIONS = 256;

const renderSettingsContent = (section: SidebarSection) => {
  const ActiveComponent =
    SECTIONS_CONFIG[section]?.component || SECTIONS_CONFIG.general.component;
  return <ActiveComponent />;
};

function App() {
  const { t, i18n } = useTranslation();
  const [onboardingStep, setOnboardingStep] = useState<OnboardingStep | null>(
    null,
  );
  // Track if this is a returning user who just needs to grant permissions
  // (vs a new user who needs full onboarding including model selection)
  const [isReturningUser, setIsReturningUser] = useState(false);
  const [currentSection, setCurrentSection] =
    useState<SidebarSection>("general");
  const { settings, updateSetting } = useSettings();
  const direction = getLanguageDirection(i18n.language);
  const refreshAudioDevices = useSettingsStore(
    (state) => state.refreshAudioDevices,
  );
  const refreshOutputDevices = useSettingsStore(
    (state) => state.refreshOutputDevices,
  );
  const setShortcutBackendStatus = useSettingsStore(
    (state) => state.setShortcutBackendStatus,
  );
  const refreshShortcutBackendStatus = useSettingsStore(
    (state) => state.refreshShortcutBackendStatus,
  );
  const hasCompletedPostOnboardingInit = useRef(false);
  const notifiedFocusedOutputSessionsRef = useRef<Set<number> | null>(null);
  if (notifiedFocusedOutputSessionsRef.current === null) {
    notifiedFocusedOutputSessionsRef.current = new Set<number>();
  }
  const notifiedFocusedOutputSessions =
    notifiedFocusedOutputSessionsRef.current;

  useEffect(() => {
    checkOnboardingStatus();
  }, []);

  // Initialize RTL direction when language changes
  useEffect(() => {
    initializeRTL(i18n.language);
  }, [i18n.language]);

  // Subscribe before initializing so an early unavailable status cannot be missed.
  useEffect(() => {
    if (onboardingStep !== "done") return;

    let disposed = false;
    let stopListening: (() => void) | undefined;
    let lastObservedState =
      useSettingsStore.getState().shortcutBackendStatus?.state;

    const applyShortcutBackendStatus = (status: ShortcutBackendStatus) => {
      if (disposed) return;

      const previousState = lastObservedState;
      lastObservedState = status.state;
      setShortcutBackendStatus(status);
      if (previousState !== "unavailable" && status.state === "unavailable") {
        toast.error(i18n.t("settings.general.shortcut.portal.unavailable"));
      }
    };

    const initialize = async () => {
      try {
        try {
          const unlisten = await listen<ShortcutBackendStatus>(
            "shortcut-backend-status-changed",
            (event) => applyShortcutBackendStatus(event.payload),
          );
          if (disposed) {
            unlisten();
            return;
          }
          stopListening = unlisten;
        } catch (error) {
          if (disposed) return;
          console.warn("Failed to listen for shortcut backend status:", error);
        }

        if (disposed) return;

        if (!hasCompletedPostOnboardingInit.current) {
          hasCompletedPostOnboardingInit.current = true;
          void refreshAudioDevices();
          void refreshOutputDevices();

          const [enigoResult, shortcutResult] = await Promise.all([
            commands.initializeEnigo(),
            commands.initializeShortcuts(),
          ]);

          if (enigoResult.status === "error") {
            console.warn("Failed to initialize Enigo:", enigoResult.error);
          }
          if (shortcutResult.status === "error") {
            console.warn(
              "Failed to initialize shortcuts:",
              shortcutResult.error,
            );
          } else {
            applyShortcutBackendStatus(shortcutResult.data);
          }
        }
      } catch (error) {
        console.warn("Failed to initialize application services:", error);
      } finally {
        if (disposed) return;

        await refreshShortcutBackendStatus();
        const refreshedStatus =
          useSettingsStore.getState().shortcutBackendStatus;
        if (refreshedStatus) {
          applyShortcutBackendStatus(refreshedStatus);
        }
      }
    };

    void initialize();

    return () => {
      disposed = true;
      stopListening?.();
    };
  }, [
    onboardingStep,
    refreshAudioDevices,
    refreshOutputDevices,
    refreshShortcutBackendStatus,
    setShortcutBackendStatus,
    i18n,
  ]);

  // Handle keyboard shortcuts for debug mode toggle
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Check for Ctrl+Shift+D (Windows/Linux) or Cmd+Shift+D (macOS)
      const isDebugShortcut =
        event.shiftKey &&
        event.key.toLowerCase() === "d" &&
        (event.ctrlKey || event.metaKey);

      if (isDebugShortcut) {
        event.preventDefault();
        const currentDebugMode = settings?.debug_mode ?? false;
        updateSetting("debug_mode", !currentDebugMode);
      }
    };

    // Add event listener when component mounts
    document.addEventListener("keydown", handleKeyDown);

    // Cleanup event listener when component unmounts
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [settings?.debug_mode, updateSetting]);

  // Listen for recording errors from the backend and show a toast
  useEffect(() => {
    const unlisten = listen<RecordingErrorEvent>("recording-error", (event) => {
      const { error_type, detail } = event.payload;

      if (error_type === "microphone_permission_denied") {
        const currentPlatform = platform();
        const platformKey = `errors.micPermissionDenied.${currentPlatform}`;
        const description = t(platformKey, {
          defaultValue: t("errors.micPermissionDenied.generic"),
        });
        toast.error(t("errors.micPermissionDeniedTitle"), { description });
      } else if (error_type === "no_input_device") {
        toast.error(t("errors.noInputDeviceTitle"), {
          description: t("errors.noInputDevice"),
        });
      } else {
        toast.error(
          t("errors.recordingFailed", { error: detail ?? "Unknown error" }),
        );
      }
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

  // Listen for paste failures and show a toast.
  // The technical error detail is logged to handy.log on the Rust side
  // (see actions.rs `error!("Failed to paste transcription: ...")`),
  // so we show a localized, user-friendly message here instead of the raw error.
  useEffect(() => {
    const unlisten = listen("paste-error", () => {
      toast.error(t("errors.pasteFailedTitle"), {
        description: t("errors.pasteFailed"),
      });
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

  useEffect(() => {
    const markSessionNotified = (sessionId: number) => {
      if (notifiedFocusedOutputSessions.has(sessionId)) return false;

      notifiedFocusedOutputSessions.add(sessionId);
      if (
        notifiedFocusedOutputSessions.size >
        MAX_NOTIFIED_FOCUSED_OUTPUT_SESSIONS
      ) {
        const oldestSessionId = notifiedFocusedOutputSessions
          .values()
          .next().value;
        if (oldestSessionId !== undefined) {
          notifiedFocusedOutputSessions.delete(oldestSessionId);
        }
      }

      return true;
    };
    const unlisten = events.focusedOutputStatusEvent.listen((event) => {
      const status = event.payload;
      if (status.status === "fallback" && status.reason === null) {
        return;
      }

      switch (status.status) {
        case "armed":
        case "streaming":
        case "completed":
        case "cancelled":
          return;
        case "fallback":
          if (!markSessionNotified(status.session_id)) return;
          toast.warning(t("focusedOutput.notifications.fallback.title"), {
            description: t("focusedOutput.notifications.fallback.body"),
          });
          return;
        case "invalidated":
          if (!markSessionNotified(status.session_id)) return;
          toast.warning(t("focusedOutput.notifications.invalidated.title"), {
            description: t("focusedOutput.notifications.invalidated.body"),
          });
          return;
        case "faulted":
          if (!markSessionNotified(status.session_id)) return;
          toast.error(t("focusedOutput.notifications.faulted.title"), {
            description: t("focusedOutput.notifications.faulted.body"),
          });
          return;
        case "conflict":
          if (!markSessionNotified(status.session_id)) return;
          if (status.history_available) {
            toast.warning(t("focusedOutput.notifications.conflict.title"), {
              description: t("focusedOutput.notifications.conflict.body"),
              action: {
                label: t("focusedOutput.notifications.history.action"),
                onClick: () => setCurrentSection("history"),
              },
            });
          } else {
            toast.warning(t("focusedOutput.notifications.conflict.title"), {
              description: `${t(
                "focusedOutput.notifications.conflict.body",
              )} ${t("focusedOutput.notifications.history.unavailable")}`,
            });
          }
          return;
        default: {
          const exhaustive: never = status.status;
          return exhaustive;
        }
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [notifiedFocusedOutputSessions, t]);

  // Listen for transcription failures and show a toast.
  // The payload is the backend error message (also logged to handy.log).
  useEffect(() => {
    const unlisten = listen<string>("transcription-error", (event) => {
      toast.error(t("errors.transcriptionFailedTitle"), {
        description: event.payload,
      });
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

  // Listen for model loading failures and show a toast
  useEffect(() => {
    const unlisten = listen<ModelStateEvent>("model-state-changed", (event) => {
      if (event.payload.event_type === "loading_failed") {
        toast.error(
          t("errors.modelLoadFailed", {
            model:
              event.payload.model_name || t("errors.modelLoadFailedUnknown"),
          }),
          {
            description: event.payload.error,
          },
        );
      }
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

  const revealMainWindowForPermissions = async () => {
    try {
      await commands.showMainWindowCommand();
    } catch (e) {
      console.warn("Failed to show main window for permission onboarding:", e);
    }
  };

  const checkOnboardingStatus = async () => {
    try {
      const settingsResult = await commands.getAppSettings();
      const hasCompletedOnboarding =
        settingsResult.status === "ok" &&
        settingsResult.data.onboarding_completed === true;
      const currentPlatform = platform();

      if (hasCompletedOnboarding) {
        // Returning user - check if they need to grant permissions first
        setIsReturningUser(true);

        if (currentPlatform === "macos") {
          try {
            const [hasAccessibility, hasMicrophone] = await Promise.all([
              checkAccessibilityPermission(),
              checkMicrophonePermission(),
            ]);
            if (!hasAccessibility || !hasMicrophone) {
              await revealMainWindowForPermissions();
              setOnboardingStep("accessibility");
              return;
            }
          } catch (e) {
            console.warn("Failed to check macOS permissions:", e);
            // If we can't check, proceed to main app and let them fix it there
          }
        }

        if (currentPlatform === "windows") {
          try {
            const microphoneStatus =
              await commands.getWindowsMicrophonePermissionStatus();
            if (
              microphoneStatus.supported &&
              microphoneStatus.overall_access === "denied"
            ) {
              await revealMainWindowForPermissions();
              setOnboardingStep("accessibility");
              return;
            }
          } catch (e) {
            console.warn("Failed to check Windows microphone permissions:", e);
            // If we can't check, proceed to main app and let them fix it there
          }
        }

        setOnboardingStep("done");
      } else {
        // New user - start full onboarding
        setIsReturningUser(false);
        setOnboardingStep("accessibility");
      }
    } catch (error) {
      console.error("Failed to check onboarding status:", error);
      setOnboardingStep("accessibility");
    }
  };

  const handleAccessibilityComplete = () => {
    // Returning users already have models, skip to main app
    // New users need to select a model
    setOnboardingStep(isReturningUser ? "done" : "model");
  };

  const handleModelSelected = () => {
    // Transition to main app - user has started a download
    setOnboardingStep("done");
  };

  // Rendered once around every step below (including onboarding) so
  // toast.error() calls surface to the user. sonner renders via a portal, so
  // its position in the tree doesn't affect layout. Without this, errors during
  // onboarding (e.g. a model download failing because blob.handy.computer is
  // unreachable) are silently swallowed and the wizard just appears to "blink".
  const toaster = (
    <Toaster
      theme="system"
      toastOptions={{
        unstyled: true,
        classNames: {
          toast:
            "bg-background border border-mid-gray/20 rounded-lg shadow-lg px-4 py-3 flex items-center gap-3 text-sm",
          title: "font-medium",
          description: "text-mid-gray",
          actionButton:
            "px-2 py-1 text-xs font-medium rounded-lg border bg-mid-gray/10 border-mid-gray/20 hover:bg-background-ui/30 hover:border-logo-primary cursor-pointer whitespace-nowrap",
        },
      }}
    />
  );

  // Still checking onboarding status
  if (onboardingStep === null) {
    return null;
  }

  // Select the content for the current step. The Toaster is rendered once, in a
  // stable wrapper around this node, so crossing between onboarding steps and
  // the main app never remounts it (which would drop any in-flight toast).
  let content: ReactNode;
  if (onboardingStep === "accessibility") {
    content = (
      <AccessibilityOnboarding onComplete={handleAccessibilityComplete} />
    );
  } else if (onboardingStep === "model") {
    content = <Onboarding onModelSelected={handleModelSelected} />;
  } else {
    content = (
      <div
        dir={direction}
        className="h-screen flex flex-col select-none cursor-default"
      >
        <ErrorBoundary context="What's New">
          <WhatsNewGate />
        </ErrorBoundary>
        {/* Main content area that takes remaining space */}
        <div className="flex-1 flex overflow-hidden">
          <Sidebar
            activeSection={currentSection}
            onSectionChange={setCurrentSection}
          />
          {/* Scrollable content area */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex-1 overflow-y-auto">
              <div className="flex flex-col items-center p-4 gap-4">
                <AccessibilityPermissions />
                <SecureInputWarning />
                {renderSettingsContent(currentSection)}
              </div>
            </div>
          </div>
        </div>
        {/* Fixed footer at bottom */}
        <Footer />
      </div>
    );
  }

  return (
    <>
      {toaster}
      {content}
    </>
  );
}

export default App;
