import { useEffect } from "react";
import { sanitizeSigmaScanPresets } from "../../../utils/sigmaScanPresets.mjs";
import {
  applyDetectionSettingsToModal,
  buildDetectionSettingsFromModal,
} from "./sigmaModalHelpers.js";
import { clearIpcSubscription } from "../../../utils/ipc-subscriptions.js";

export default function useSigmaModalBootstrap({ modal, setModal, tle }) {
  useEffect(() => {
    return () => {
      clearIpcSubscription("sigma-progress");
    };
  }, [tle]);

  useEffect(() => {
    if (modal?.type !== "sigma") return;
    if (!modal.status && tle?.sigmaGetStatus) {
      tle.sigmaGetStatus().then((s) => {
        setModal((p) => p?.type === "sigma" ? { ...p, status: s } : p);
      }).catch(() => {});
    }
    if ((modal.availableRepos || []).length === 0 && tle?.sigmaGetRepos) {
      tle.sigmaGetRepos().then((repos) => {
        if (repos && repos.length > 0) {
          const defaults = repos.filter((r) => r.default).map((r) => r.id);
          setModal((p) => p?.type === "sigma" ? { ...p, availableRepos: repos, selectedRepos: p.selectedRepos || defaults } : p);
        }
      }).catch(() => {});
    }
    if (modal.detectionSettings === undefined && tle?.sigmaGetDetectionSettings) {
      tle.sigmaGetDetectionSettings().then((settings) => {
        setModal((p) => p?.type === "sigma" ? applyDetectionSettingsToModal(p, settings) : p);
      }).catch(() => {
        setModal((p) => p?.type === "sigma" ? { ...p, detectionSettings: {}, detectionSettingsLoaded: true } : p);
      });
    }
    if (modal.ruleSuppressions === undefined && tle?.sigmaListRuleSuppressions) {
      tle.sigmaListRuleSuppressions().then((result) => {
        setModal((p) => p?.type === "sigma" ? {
          ...p,
          ruleSuppressions: Array.isArray(result?.suppressions) ? result.suppressions : [],
          ruleSuppressionSync: result?.sync || null,
          ruleSuppressionDraft: p.ruleSuppressionDraft || { ruleId: "", title: "", scopeType: "global", scope: "all cases", reason: "" },
        } : p);
      }).catch(() => {
        setModal((p) => p?.type === "sigma" ? {
          ...p,
          ruleSuppressions: [],
          ruleSuppressionDraft: { ruleId: "", title: "", scopeType: "global", scope: "all cases", reason: "" },
        } : p);
      });
    }
    if (modal.hayabusaStatus === undefined && tle?.sigmaHayabusaStatus) {
      tle.sigmaHayabusaStatus().then((s) => {
        setModal((p) => p?.type === "sigma" ? { ...p, hayabusaStatus: s } : p);
      }).catch(() => {});
    }
    if (modal.scanHistory === undefined && tle?.sigmaListScanHistory) {
      tle.sigmaListScanHistory().then((history) => {
        setModal((p) => p?.type === "sigma" ? { ...p, scanHistory: Array.isArray(history) ? history : [] } : p);
      }).catch(() => {
        setModal((p) => p?.type === "sigma" ? { ...p, scanHistory: [] } : p);
      });
    }
    if (modal.scanHistorySettings === undefined && tle?.sigmaGetScanHistorySettings) {
      tle.sigmaGetScanHistorySettings().then((settings) => {
        setModal((p) => p?.type === "sigma" ? {
          ...p,
          scanHistorySettings: settings || { retentionDays: 0 },
          scanHistoryRetentionDays: settings?.retentionDays ?? 0,
        } : p);
      }).catch(() => {
        setModal((p) => p?.type === "sigma" ? { ...p, scanHistorySettings: { retentionDays: 0 }, scanHistoryRetentionDays: 0 } : p);
      });
    }
    if (modal.scanPresets === undefined && tle?.loadSigmaScanPresets) {
      tle.loadSigmaScanPresets().then((presets) => {
        setModal((p) => p?.type === "sigma" ? { ...p, scanPresets: sanitizeSigmaScanPresets(presets) } : p);
      }).catch(() => {
        setModal((p) => p?.type === "sigma" ? { ...p, scanPresets: [] } : p);
      });
    }
  }, [
    modal?.type,
    modal?.status,
    modal?.availableRepos?.length,
    modal?.detectionSettings,
    modal?.ruleSuppressions,
    modal?.hayabusaStatus,
    modal?.scanHistory,
    modal?.scanHistorySettings,
    modal?.scanPresets,
    tle,
    setModal,
  ]);

  useEffect(() => {
    if (modal?.type !== "sigma" || !modal.detectionSettingsView || !modal.detectionSettingsLoaded || !tle?.sigmaSaveDetectionSettings) return;
    const current = buildDetectionSettingsFromModal(modal);
    const saved = modal.detectionSettings || {};
    if (JSON.stringify(current) === JSON.stringify(saved)) return;
    if (!modal.detectionSettingsSaving) {
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        detectionSettingsSaving: true,
        detectionSettingsNotice: "Saving detection defaults...",
      } : p);
    }
    const timer = setTimeout(async () => {
      try {
        const result = await tle.sigmaSaveDetectionSettings(current);
        if (result?.__ipcError || result?.error) throw new Error(result.message || result.error || "Failed to save detection settings");
        setModal((p) => p?.type === "sigma" ? {
          ...p,
          detectionSettings: result,
          detectionSettingsSaving: false,
          detectionSettingsNotice: "Detection defaults auto-saved.",
        } : p);
      } catch (e) {
        setModal((p) => p?.type === "sigma" ? {
          ...p,
          detectionSettingsSaving: false,
          error: e?.message || "Failed to auto-save detection settings",
        } : p);
      }
    }, 900);
    return () => clearTimeout(timer);
  }, [modal, tle, setModal]);
}
