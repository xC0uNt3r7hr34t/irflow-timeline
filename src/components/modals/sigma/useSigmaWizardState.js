import { useMemo } from "react";
import {
  levelsAtOrAboveMinimum,
  minimumSeverityFromLevels,
} from "../../../utils/sigmaScanPresets.mjs";
import { SEV_ORDER, STATUS_LIST } from "./constants.js";

const DEFAULT_LEVELS = {
  critical: true,
  high: true,
  medium: true,
  low: true,
  informational: true,
};

const DEFAULT_STATUSES = {
  stable: true,
  test: true,
  experimental: true,
};

export default function useSigmaWizardState({ modal, phase, ct, status }) {
  return useMemo(() => {
    const levels = modal.levels || DEFAULT_LEVELS;
    const statuses = modal.statuses || DEFAULT_STATUSES;
    const hasRules = (status?.cachedRuleCount || 0) + (status?.customRuleCount || 0) > 0;
    const scanMode = modal.scanMode || "evtx-dir";
    const selectedLevelList = SEV_ORDER.filter((level) => levels[level]);
    const selectedStatusList = STATUS_LIST.filter((ruleStatus) => statuses[ruleStatus]);
    const hayabusaMinSeverity = modal.hayabusaMinSeverity || minimumSeverityFromLevels(selectedLevelList) || "informational";
    const hayabusaLevelList = levelsAtOrAboveMinimum(hayabusaMinSeverity);
    // Single-screen Configure: the rail tracks the phase, not per-step navigation.
    const activeWizardStep = phase === "scanning" ? "scan" : phase === "results" ? "triage" : "config";
    const hasTargetReady = scanMode === "evtx-dir"
      ? (modal.evtxDir?.fileCount || 0) > 0
      : scanMode === "kape-output"
        ? (modal.kapeOutput?.fileCount || 0) > 0
        : !!ct?.dataReady;
    const hasPresetReady = scanMode === "evtx-dir"
      ? hayabusaLevelList.length > 0 && selectedStatusList.length > 0
      : selectedLevelList.length > 0 && selectedStatusList.length > 0;

    return {
      levels,
      statuses,
      hasRules,
      scanMode,
      selectedLevelList,
      selectedStatusList,
      hayabusaMinSeverity,
      hayabusaLevelList,
      activeWizardStep,
      hasTargetReady,
      hasPresetReady,
    };
  }, [ct, modal, phase, status]);
}
