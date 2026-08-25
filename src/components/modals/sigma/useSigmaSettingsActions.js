import { buildDetectionSettingsFromModal } from "./sigmaModalHelpers.js";
import { clearIpcSubscription, replaceIpcSubscription } from "../../../utils/ipc-subscriptions.js";

export default function useSigmaSettingsActions({ modal, setModal, tle, selectedRepos, availableRepos }) {
  const handleSaveDetectionSettings = async () => {
    if (!tle?.sigmaSaveDetectionSettings) return;
    setModal((p) => ({ ...p, detectionSettingsSaving: true, detectionSettingsNotice: null, error: null }));
    try {
      const saved = await tle.sigmaSaveDetectionSettings(buildDetectionSettingsFromModal(modal));
      if (saved?.__ipcError || saved?.error) throw new Error(saved.message || saved.error || "Failed to save detection settings");
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        detectionSettings: saved,
        detectionSettingsSaving: false,
        detectionSettingsNotice: "Detection defaults saved.",
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, detectionSettingsSaving: false, error: e?.message || "Failed to save detection settings" }));
    }
  };

  const handleAddRuleSuppression = () => {
    const draft = modal.ruleSuppressionDraft || {};
    const ruleId = String(draft.ruleId || "").trim();
    const title = String(draft.title || "").trim();
    if (!ruleId && !title) {
      setModal((p) => ({ ...p, error: "Enter a rule ID or title before adding a suppression." }));
      return;
    }
    const scopeType = draft.scopeType === "case" ? "case" : "global";
    const entry = {
      id: `supp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      ruleId,
      title,
      scopeType,
      scope: String(draft.scope || (scopeType === "global" ? "all cases" : "case")).trim() || (scopeType === "global" ? "all cases" : "case"),
      reason: String(draft.reason || "").trim(),
      enabled: true,
      source: "analyst",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    setModal((p) => ({
      ...p,
      ruleSuppressions: [...(p.ruleSuppressions || []), entry],
      ruleSuppressionDraft: { ruleId: "", title: "", scopeType: "global", scope: "all cases", reason: "" },
      detectionSettingsNotice: "Suppression added. Save suppressions to apply it.",
      error: null,
    }));
  };

  const handleUpdateRuleSuppression = (id, patch) => {
    setModal((p) => ({
      ...p,
      ruleSuppressions: (p.ruleSuppressions || []).map((entry) => entry.id === id ? { ...entry, ...patch, updatedAt: new Date().toISOString() } : entry),
      detectionSettingsNotice: "Suppression changes are not saved yet.",
    }));
  };

  const handleRemoveRuleSuppression = (id) => {
    setModal((p) => ({
      ...p,
      ruleSuppressions: (p.ruleSuppressions || []).filter((entry) => entry.id !== id),
      detectionSettingsNotice: "Suppression removed locally. Save suppressions to apply it.",
    }));
  };

  const handleSaveRuleSuppressions = async () => {
    if (!tle?.sigmaSaveRuleSuppressions) return;
    setModal((p) => ({ ...p, ruleSuppressionsSaving: true, detectionSettingsNotice: null, error: null }));
    try {
      const result = await tle.sigmaSaveRuleSuppressions(modal.ruleSuppressions || []);
      if (result?.__ipcError || result?.error) throw new Error(result.message || result.error || "Failed to save rule suppressions");
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        ruleSuppressions: Array.isArray(result.suppressions) ? result.suppressions : [],
        ruleSuppressionSync: result.sync || null,
        ruleSuppressionsSaving: false,
        detectionSettingsNotice: result.sync?.synced
          ? `Disabled/noisy rules saved and synced to ${result.noisyRulesPath || "Hayabusa config"}.`
          : `Disabled/noisy rules saved${result.sync?.error ? `; Hayabusa sync skipped: ${result.sync.error}` : "."}`,
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, ruleSuppressionsSaving: false, error: e?.message || "Failed to save rule suppressions" }));
    }
  };

  const handleDownload = async () => {
    const repoIds = selectedRepos || availableRepos.filter((r) => r.default).map((r) => r.id);
    if (repoIds.length === 0) return;
    setModal((p) => ({ ...p, downloading: true, error: null }));
    replaceIpcSubscription("sigma-progress", tle.onSigmaProgress, (prog) => {
      setModal((p) => p?.type === "sigma" ? { ...p, progress: prog } : p);
    });
    try {
      const res = await tle.sigmaUpdateRules(repoIds);
      const newStatus = await tle.sigmaGetStatus();
      setModal((p) => ({ ...p, downloading: false, status: newStatus, ruleInfo: res, progress: null }));
    } catch (e) {
      setModal((p) => ({ ...p, downloading: false, error: e?.message || "Download failed" }));
    }
  };

  const handleLoadRuleInfo = async () => {
    try {
      const info = await tle.sigmaGetRules();
      setModal((p) => p?.type === "sigma" ? { ...p, ruleInfo: info } : p);
    } catch (_) {}
  };

  const handleImportCustom = async () => {
    try {
      const res = await tle.sigmaImportCustom();
      if (res?.success) {
        const newStatus = await tle.sigmaGetStatus();
        setModal((p) => ({ ...p, status: newStatus }));
      }
    } catch (_) {}
  };

  const handleOpenCustomDir = async () => {
    try {
      await tle.sigmaOpenCustomDir();
    } catch (_) {}
  };

  const appendHayabusaUpdateProgress = (prog, mode) => {
    const lines = Array.isArray(prog?.lines)
      ? prog.lines
      : prog?.text
        ? [prog.text]
        : [];
    setModal((p) => {
      if (p?.type !== "sigma") return p;
      const merged = [...(p.hayabusaUpdateLog || [])];
      for (const line of lines) {
        const clean = String(line || "").trim();
        if (!clean || merged[merged.length - 1] === clean) continue;
        merged.push(clean);
      }
      return {
        ...p,
        progress: prog,
        hayabusaUpdateMode: mode,
        hayabusaUpdateRuleDiff: prog?.ruleDiff || p.hayabusaUpdateRuleDiff || null,
        hayabusaUpdateLog: merged.slice(-120),
      };
    });
  };

  const startHayabusaUpdateProgress = (mode) => {
    replaceIpcSubscription("sigma-progress", tle.onSigmaProgress, (prog) => appendHayabusaUpdateProgress(prog, mode));
  };

  const handleDownloadHayabusa = async () => {
    if (!tle?.sigmaHayabusaDownload) return;
    setModal((p) => ({ ...p, hayabusaDownloading: true, hayabusaUpdateMode: "install", hayabusaUpdateLog: ["Starting Hayabusa install..."], hayabusaUpdateResult: null, error: null }));
    startHayabusaUpdateProgress("install");
    try {
      const result = await tle.sigmaHayabusaDownload();
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, hayabusaDownloading: false, hayabusaStatus: result, hayabusaUpdateResult: { type: "install", ...result }, progress: null }));
    } catch (e) {
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, hayabusaDownloading: false, error: e?.message || "Download failed", progress: null }));
    }
  };

  const handleUpdateHayabusaRules = async () => {
    if (!tle?.sigmaHayabusaUpdateRules) return;
    setModal((p) => ({ ...p, hayabusaUpdating: true, hayabusaUpdateMode: "rules", hayabusaUpdateLog: ["Starting Hayabusa rule update..."], hayabusaUpdateResult: null, hayabusaUpdateRuleDiff: null, error: null }));
    startHayabusaUpdateProgress("rules");
    try {
      const result = await tle.sigmaHayabusaUpdateRules();
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, hayabusaUpdating: false, hayabusaUpdateResult: { type: "rules", ...result }, hayabusaUpdateRuleDiff: result?.ruleDiff || p.hayabusaUpdateRuleDiff || null, progress: null }));
    } catch (e) {
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, hayabusaUpdating: false, error: e?.message || "Rule update failed", progress: null }));
    }
  };

  const handleUpdateHayabusa = async () => {
    if (!tle?.sigmaHayabusaUpdate) return;
    setModal((p) => ({ ...p, hayabusaDownloading: true, hayabusaUpdateMode: "binary", hayabusaUpdateLog: ["Checking current Hayabusa version..."], hayabusaUpdateResult: null, error: null }));
    startHayabusaUpdateProgress("binary");
    try {
      const result = await tle.sigmaHayabusaUpdate();
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, hayabusaDownloading: false, hayabusaStatus: result, hayabusaUpdateResult: { type: "binary", ...result }, progress: null }));
    } catch (e) {
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, hayabusaDownloading: false, error: e?.message || "Update failed", progress: null }));
    }
  };

  return {
    handleSaveDetectionSettings,
    handleAddRuleSuppression,
    handleUpdateRuleSuppression,
    handleRemoveRuleSuppression,
    handleSaveRuleSuppressions,
    handleDownload,
    handleLoadRuleInfo,
    handleImportCustom,
    handleOpenCustomDir,
    handleDownloadHayabusa,
    handleUpdateHayabusaRules,
    handleUpdateHayabusa,
  };
}
