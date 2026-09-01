import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { commands, type ShortcutBackendStatus } from "@/bindings";
import { Button } from "../ui/Button";
import { SettingContainer } from "../ui/SettingContainer";

const IDENTITY_UNAVAILABLE_MESSAGE =
  "Desktop portal application registration is unavailable";

interface PortalShortcutInputProps {
  descriptionMode?: "inline" | "tooltip";
  grouped?: boolean;
  shortcutId: string;
  disabled?: boolean;
  status: ShortcutBackendStatus;
}

export const PortalShortcutInput: React.FC<PortalShortcutInputProps> = ({
  descriptionMode = "tooltip",
  grouped = false,
  shortcutId,
  disabled = false,
  status,
}) => {
  const { t } = useTranslation();
  const [isConfiguring, setIsConfiguring] = useState(false);

  const configureShortcuts = async () => {
    setIsConfiguring(true);
    try {
      const result = await commands.configureSystemShortcuts();
      if (result.status === "error") {
        console.error("Failed to configure portal shortcuts:", result.error);
      }
      // A successful portal v2 response only means the desktop dialog was
      // launched. The backend status event remains authoritative for choices.
    } catch (error) {
      console.error("Failed to configure portal shortcuts:", error);
    } finally {
      setIsConfiguring(false);
    }
  };

  const translatedName = t(
    `settings.general.shortcut.bindings.${shortcutId}.name`,
  );
  const translatedDescription = t(
    `settings.general.shortcut.bindings.${shortcutId}.description`,
  );
  const bindingDescription =
    status.bindings[shortcutId] ??
    t("settings.general.shortcut.portal.notAssigned");
  const isUnavailable = status.state === "unavailable";
  const unavailableText =
    status.message === IDENTITY_UNAVAILABLE_MESSAGE
      ? t("settings.general.shortcut.portal.identityUnavailable")
      : t("settings.general.shortcut.portal.unavailable");

  return (
    <SettingContainer
      title={translatedName}
      description={translatedDescription}
      descriptionMode={descriptionMode}
      grouped={grouped}
      disabled={disabled}
      layout="horizontal"
    >
      <div className="flex max-w-md flex-col items-end gap-1">
        <div className="flex items-center space-x-1">
          <div className="rounded-md border border-mid-gray/80 bg-mid-gray/10 px-2 py-1 text-sm font-semibold">
            {bindingDescription}
          </div>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={configureShortcuts}
            disabled={disabled || !status.can_configure || isConfiguring}
          >
            {t("settings.general.shortcut.portal.configure")}
          </Button>
        </div>
        {isUnavailable && (
          <div
            className="text-right text-xs text-mid-gray"
            role="status"
            aria-live="polite"
          >
            <div>{unavailableText}</div>
            <div>{t("settings.general.shortcut.portal.fallback")}</div>
          </div>
        )}
      </div>
    </SettingContainer>
  );
};
