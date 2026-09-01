import React from "react";
import { useTranslation } from "react-i18next";
import { useSettingsStore } from "../../stores/settingsStore";
import { SettingContainer } from "../ui/SettingContainer";
import { GlobalShortcutInput } from "./GlobalShortcutInput";
import { HandyKeysShortcutInput } from "./HandyKeysShortcutInput";
import { PortalShortcutInput } from "./PortalShortcutInput";

interface ShortcutInputProps {
  descriptionMode?: "inline" | "tooltip";
  grouped?: boolean;
  shortcutId: string;
  disabled?: boolean;
}

/**
 * Selects the shortcut input owned by the active runtime backend.
 *
 * The persisted keyboard implementation cannot identify the Wayland portal
 * route, so this component waits for the runtime status before exposing an
 * input. In particular, it must not render the web recorder on first paint.
 */
export const ShortcutInput: React.FC<ShortcutInputProps> = (props) => {
  const { t } = useTranslation();
  const shortcutBackendStatus = useSettingsStore(
    (state) => state.shortcutBackendStatus,
  );

  if (
    !shortcutBackendStatus ||
    shortcutBackendStatus.state === "initializing"
  ) {
    const loadingMessage = shortcutBackendStatus
      ? t("settings.general.shortcut.portal.initializing")
      : t("settings.general.shortcut.portal.loading");

    return (
      <SettingContainer
        title={t(`settings.general.shortcut.bindings.${props.shortcutId}.name`)}
        description={t(
          `settings.general.shortcut.bindings.${props.shortcutId}.description`,
        )}
        descriptionMode={props.descriptionMode}
        grouped={props.grouped}
        disabled
        layout="horizontal"
      >
        <div className="text-sm text-mid-gray">{loadingMessage}</div>
      </SettingContainer>
    );
  }

  if (shortcutBackendStatus.backend === "tauri") {
    return <GlobalShortcutInput {...props} />;
  }

  if (shortcutBackendStatus.backend === "handy_keys") {
    return <HandyKeysShortcutInput {...props} />;
  }

  if (
    shortcutBackendStatus.backend === "xdg_portal" &&
    (shortcutBackendStatus.state === "ready" ||
      shortcutBackendStatus.state === "partial" ||
      shortcutBackendStatus.state === "unavailable")
  ) {
    return <PortalShortcutInput {...props} status={shortcutBackendStatus} />;
  }

  return null;
};
