import React from "react";
import { useTranslation } from "react-i18next";
import { SettingContainer } from "../../ui/SettingContainer";
import { Dropdown, type DropdownOption } from "../../ui/Dropdown";
import { useSettings } from "../../../hooks/useSettings";
import { useSettingsStore } from "../../../stores/settingsStore";
import { commands } from "@/bindings";
import { toast } from "sonner";

interface KeyboardImplementationSelectorProps {
  descriptionMode?: "tooltip" | "inline";
  grouped?: boolean;
}

export const KeyboardImplementationSelector: React.FC<
  KeyboardImplementationSelectorProps
> = ({ descriptionMode = "tooltip", grouped = false }) => {
  const { t } = useTranslation();
  const { getSetting, isUpdating, refreshSettings } = useSettings();
  const refreshShortcutBackendStatus = useSettingsStore(
    (state) => state.refreshShortcutBackendStatus,
  );
  const keyboardImplementationOptions: DropdownOption[] = [
    {
      value: "tauri",
      label: t("settings.debug.keyboardImplementation.options.system"),
    },
    {
      value: "handy_keys",
      label: t("settings.debug.keyboardImplementation.options.handyKeys"),
    },
  ];
  const currentImplementation =
    getSetting("keyboard_implementation") ?? "tauri";

  const handleSelect = async (value: string) => {
    if (value === currentImplementation) return;

    try {
      const result = await commands.changeKeyboardImplementationSetting(value);

      if (result.status === "error") {
        console.error(
          "Failed to update keyboard implementation:",
          result.error,
        );
        toast.error(String(result.error));
        return;
      }

      // If any bindings were reset due to incompatibility, notify the user
      if (result.data.reset_bindings.length > 0) {
        toast.warning(t("settings.debug.keyboardImplementation.bindingsReset"));
      }
    } catch (error) {
      console.error("Failed to update keyboard implementation:", error);
      toast.error(String(error));
    } finally {
      await Promise.all([refreshSettings(), refreshShortcutBackendStatus()]);
    }
  };

  return (
    <SettingContainer
      title={t("settings.debug.keyboardImplementation.title")}
      description={t("settings.debug.keyboardImplementation.description")}
      descriptionMode={descriptionMode}
      grouped={grouped}
      layout="horizontal"
    >
      <Dropdown
        options={keyboardImplementationOptions}
        selectedValue={currentImplementation}
        onSelect={handleSelect}
        disabled={isUpdating("keyboard_implementation")}
      />
    </SettingContainer>
  );
};
