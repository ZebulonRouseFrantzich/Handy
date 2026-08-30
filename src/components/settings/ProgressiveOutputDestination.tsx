import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useTranslation } from "react-i18next";
import {
  commands,
  events,
  type FocusedOutputCapability,
  type FocusedOutputPermission,
  type FocusedOutputReasonCode,
  type FocusedOutputStatus,
  type FocusedOutputStatusEvent,
  type ProgressiveOutputDestination as ProgressiveOutputDestinationValue,
} from "@/bindings";
import { useSettings } from "../../hooks/useSettings";
import { useOsType } from "../../hooks/useOsType";
import {
  focusedOutputBackendKey,
  focusedOutputReasonKey,
  focusedOutputSafetyKey,
  focusedOutputStatusKey,
  insertionTransportKey,
  mixedInputSupportKey,
  receiptConfidenceKey,
} from "../../utils/focusedOutput";
import { Button } from "../ui/Button";
import { Dropdown, type DropdownOption } from "../ui/Dropdown";
import { SettingContainer } from "../ui/SettingContainer";

type ReadState = "loading" | "ready" | "unavailable";

interface ProgressiveOutputDestinationProps {
  descriptionMode?: "inline" | "tooltip";
  grouped?: boolean;
}

interface DetailRow {
  label: string;
  value: string;
}

const permissionForReason: Partial<
  Record<FocusedOutputReasonCode, FocusedOutputPermission>
> = {
  accessibility_permission_missing: "mac_accessibility",
  input_monitoring_permission_missing: "mac_input_monitoring",
};

const permissionBlockingStatuses: Partial<Record<FocusedOutputStatus, true>> = {
  armed: true,
  streaming: true,
  fallback: true,
  invalidated: true,
  faulted: true,
};

export const ProgressiveOutputDestination: React.FC<
  ProgressiveOutputDestinationProps
> = ({ descriptionMode = "tooltip", grouped = false }) => {
  const { t } = useTranslation();
  const osType = useOsType();
  const { getSetting, updateSetting, isUpdating } = useSettings();
  const destination = getSetting("progressive_output_destination") ?? "overlay";
  const [globalCapability, setGlobalCapability] =
    useState<FocusedOutputCapability | null>(null);
  const [latestStatus, setLatestStatus] =
    useState<FocusedOutputStatusEvent | null>(null);
  const [capabilityReadState, setCapabilityReadState] =
    useState<ReadState>("loading");
  const [statusReadState, setStatusReadState] = useState<ReadState>("loading");
  const [requestingPermission, setRequestingPermission] = useState(false);
  const [permissionRequestReason, setPermissionRequestReason] =
    useState<FocusedOutputReasonCode | null>(null);
  const statusEventVersion = useRef(0);

  const refreshCapability = useCallback(async () => {
    setCapabilityReadState("loading");
    try {
      const capability = await commands.getFocusedOutputCapability();
      setGlobalCapability(capability);
      setCapabilityReadState("ready");
    } catch {
      setGlobalCapability(null);
      setCapabilityReadState("unavailable");
    }
  }, []);

  const refreshDetails = useCallback(async () => {
    const versionBeforeRead = statusEventVersion.current;
    setCapabilityReadState("loading");
    setStatusReadState("loading");

    const [capabilityResult, statusResult] = await Promise.all([
      commands
        .getFocusedOutputCapability()
        .then((value) => ({ status: "ok" as const, value }))
        .catch(() => ({ status: "error" as const })),
      commands
        .getFocusedOutputStatus()
        .then((value) => ({ status: "ok" as const, value }))
        .catch(() => ({ status: "error" as const })),
    ]);

    if (capabilityResult.status === "ok") {
      setGlobalCapability(capabilityResult.value);
      setCapabilityReadState("ready");
    } else {
      setGlobalCapability(null);
      setCapabilityReadState("unavailable");
    }

    if (versionBeforeRead !== statusEventVersion.current) return;

    if (statusResult.status === "ok") {
      setLatestStatus(statusResult.value);
      setStatusReadState("ready");
    } else {
      setLatestStatus(null);
      setStatusReadState("unavailable");
    }
  }, []);

  useEffect(() => {
    const unlisten = events.focusedOutputStatusEvent.listen((event) => {
      statusEventVersion.current += 1;
      setLatestStatus(event.payload);
      setPermissionRequestReason(null);
      setStatusReadState("ready");
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  useEffect(() => {
    void refreshDetails();
  }, [destination, refreshDetails]);

  const selectDestination = async (value: string) => {
    setPermissionRequestReason(null);
    await updateSetting(
      "progressive_output_destination",
      value as ProgressiveOutputDestinationValue,
    );
    await refreshDetails();
  };

  const options: DropdownOption[] = [
    {
      value: "overlay",
      label: t("settings.progressiveOutputDestination.options.overlay.label"),
    },
    {
      value: "focused_field",
      label: t(
        "settings.progressiveOutputDestination.options.focusedField.label",
      ),
    },
  ];

  const selectedDescription =
    destination === "focused_field"
      ? t(
          "settings.progressiveOutputDestination.options.focusedField.description",
        )
      : t("settings.progressiveOutputDestination.options.overlay.description");

  const unknownValue = t(
    "focusedOutput.capability.availability.values.unavailable",
  );
  const checkedAtStartValue = t(
    "focusedOutput.capability.availability.values.targetCheckedAtStart",
  );
  const loadingValue = t("common.loading");
  const capability = latestStatus?.capability ?? globalCapability;
  const reason =
    permissionRequestReason ??
    latestStatus?.reason ??
    capability?.reason_code ??
    null;

  const detailRows = useMemo<DetailRow[]>(() => {
    const hasRuntimeCapability = latestStatus?.capability != null;
    const capabilityPending =
      capabilityReadState === "loading" && !hasRuntimeCapability;
    const capabilityUnavailable =
      capability === null ||
      (capabilityReadState === "unavailable" && !hasRuntimeCapability);
    const capabilityValue = (value: string) =>
      capabilityPending
        ? loadingValue
        : capabilityUnavailable
          ? unknownValue
          : value;
    const routeAbsentValue = t(
      "focusedOutput.capability.insertionRoute.values.none",
    );

    const availabilityValue = capabilityPending
      ? loadingValue
      : capability === null ||
          (capabilityReadState === "unavailable" && !hasRuntimeCapability) ||
          capability.available === false
        ? unknownValue
        : capability.route
          ? t("focusedOutput.capability.availability.values.available")
          : checkedAtStartValue;

    const statusValue =
      statusReadState === "loading"
        ? loadingValue
        : statusReadState === "unavailable"
          ? unknownValue
          : latestStatus
            ? t(focusedOutputStatusKey[latestStatus.status])
            : checkedAtStartValue;

    const applicationValue =
      statusReadState === "loading"
        ? loadingValue
        : statusReadState === "unavailable"
          ? unknownValue
          : latestStatus?.target_application ||
            t("focusedOutput.capability.applicationTarget.values.none");

    const reasonValue =
      capabilityPending || statusReadState === "loading"
        ? loadingValue
        : reason
          ? t(focusedOutputReasonKey[reason])
          : t("focusedOutput.capability.reason.values.none");

    return [
      {
        label: t("focusedOutput.capability.availability.label"),
        value: availabilityValue,
      },
      {
        label: t("focusedOutput.capability.status.label"),
        value: statusValue,
      },
      {
        label: t("focusedOutput.capability.applicationTarget.label"),
        value: applicationValue,
      },
      {
        label: t("focusedOutput.capability.backend.label"),
        value: capabilityValue(
          capability
            ? t(focusedOutputBackendKey[capability.backend])
            : unknownValue,
        ),
      },
      {
        label: t("focusedOutput.capability.safety.label"),
        value: capabilityValue(
          capability
            ? t(focusedOutputSafetyKey[capability.safety_level])
            : unknownValue,
        ),
      },
      {
        label: t("focusedOutput.capability.insertionRoute.label"),
        value: capabilityValue(
          capability?.route
            ? t(insertionTransportKey[capability.route.insertion_transport])
            : routeAbsentValue,
        ),
      },
      {
        label: t("focusedOutput.capability.receiptConfidence.label"),
        value: capabilityValue(
          capability?.route
            ? t(receiptConfidenceKey[capability.route.receipt_confidence])
            : routeAbsentValue,
        ),
      },
      {
        label: t("focusedOutput.capability.mixedInputSupport.label"),
        value: capabilityValue(
          capability
            ? t(mixedInputSupportKey[capability.mixed_input_support])
            : unknownValue,
        ),
      },
      {
        label: t("focusedOutput.capability.submitSupport.label"),
        value: capabilityValue(
          capability?.route
            ? capability.supports_auto_submit
              ? t("focusedOutput.capability.submitSupport.values.supported")
              : t("focusedOutput.capability.submitSupport.values.unsupported")
            : routeAbsentValue,
        ),
      },
      {
        label: t("focusedOutput.capability.reason.label"),
        value: reasonValue,
      },
    ];
  }, [
    capability,
    capabilityReadState,
    checkedAtStartValue,
    latestStatus,
    loadingValue,
    reason,
    statusReadState,
    t,
    unknownValue,
  ]);

  const requestPermission = async (permission: FocusedOutputPermission) => {
    setPermissionRequestReason(null);
    setRequestingPermission(true);
    try {
      const result = await commands.requestFocusedOutputPermission(permission);
      switch (result.status) {
        case "ok":
          setGlobalCapability(result.data);
          setCapabilityReadState("ready");
          break;
        case "error":
          setPermissionRequestReason(result.error);
          break;
        default: {
          const exhaustive: never = result;
          throw new Error(
            `Unexpected focused output permission result: ${String(exhaustive)}`,
          );
        }
      }
    } catch {
      // The refreshed capability below provides a localized, content-free state.
    } finally {
      await refreshCapability();
      setRequestingPermission(false);
    }
  };

  const permissionReason =
    globalCapability !== null
      ? globalCapability.reason_code
      : (latestStatus?.capability?.reason_code ?? latestStatus?.reason);
  const permission = permissionReason
    ? permissionForReason[permissionReason]
    : undefined;
  const permissionBlockedByActivePlan =
    latestStatus !== null &&
    permissionBlockingStatuses[latestStatus.status] === true;
  const permissionKey =
    permission === "mac_accessibility"
      ? "focusedOutput.permissions.macAccessibility"
      : "focusedOutput.permissions.macInputMonitoring";

  return (
    <SettingContainer
      title={t("settings.progressiveOutputDestination.title")}
      description={t("settings.progressiveOutputDestination.description")}
      descriptionMode={descriptionMode}
      grouped={grouped}
      layout="stacked"
    >
      <div className="space-y-3">
        <Dropdown
          options={options}
          selectedValue={destination}
          onSelect={(value) => void selectDestination(value)}
          disabled={isUpdating("progressive_output_destination")}
        />
        <p className="text-sm text-mid-gray">{selectedDescription}</p>

        <section
          aria-live="polite"
          aria-busy={
            capabilityReadState === "loading" || statusReadState === "loading"
          }
        >
          <dl className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
            {detailRows.map(({ label, value }) => (
              <div key={label} className="min-w-0">
                <dt className="font-medium">{label}</dt>
                <dd className="text-mid-gray break-words">{value}</dd>
              </div>
            ))}
          </dl>
        </section>

        {osType === "macos" && permission && (
          <section className="space-y-2" aria-busy={requestingPermission}>
            <h4 className="text-sm font-medium">
              {t(`${permissionKey}.title`)}
            </h4>
            <p className="text-sm text-mid-gray">
              {t(`${permissionKey}.description`)}
            </p>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              disabled={requestingPermission || permissionBlockedByActivePlan}
              onClick={() => void requestPermission(permission)}
            >
              {t(`${permissionKey}.action`)}
            </Button>
            <p className="text-xs text-mid-gray">
              {t(`${permissionKey}.help`)}
            </p>
          </section>
        )}

        <ul className="list-disc space-y-1 ps-5 text-xs text-mid-gray">
          <li>{t("focusedOutput.help.runtimeChecks")}</li>
          <li>{t("focusedOutput.help.coediting")}</li>
          <li>{t("focusedOutput.help.guardedInputRace")}</li>
          <li>{t("focusedOutput.help.guardedSubmitRace")}</li>
          <li>{t("focusedOutput.help.deliveredTextSafety")}</li>
        </ul>
      </div>
    </SettingContainer>
  );
};
