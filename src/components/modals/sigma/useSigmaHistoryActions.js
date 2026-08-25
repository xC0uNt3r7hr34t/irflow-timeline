import { formatNumber } from "../../../utils/format.js";
import { confirm } from "../../../store/useConfirmStore.js";

export default function useSigmaHistoryActions({ modal, setModal, tle, sigmaResultsRef }) {
  const refreshScanHistory = async () => {
    if (!tle?.sigmaListScanHistory) return [];
    try {
      const history = await tle.sigmaListScanHistory();
      const rows = Array.isArray(history) ? history : [];
      setModal((p) => p?.type === "sigma" ? { ...p, scanHistory: rows, scanHistoryLoading: false } : p);
      return rows;
    } catch (e) {
      setModal((p) => p?.type === "sigma" ? { ...p, scanHistory: [], scanHistoryLoading: false, error: e?.message || "Failed to load scan history" } : p);
      return [];
    }
  };

  const handleShowScanHistory = async () => {
    setModal((p) => ({ ...p, scanHistoryView: true, detectionSettingsView: false, scanHistoryLoading: p.scanHistory === undefined }));
    if (modal.scanHistory === undefined) await refreshScanHistory();
  };

  const handleOpenHistoryRecord = async (record) => {
    if (!record?.id || !tle?.sigmaGetScanHistory) return;
    setModal((p) => ({ ...p, scanHistoryLoading: true, error: null }));
    try {
      const res = await tle.sigmaGetScanHistory(record.id, 2000);
      if (res?.__ipcError || res?.error) throw new Error(res.message || res.error || "Failed to open scan history");
      const historyJobId = res.jobId || `history:${record.id}`;
      sigmaResultsRef.current = {
        eventRows: res.eventRowsPreview || [],
        isDirScan: res.scanType === "evtx-dir",
        isKapeOutput: res.scanType === "kape-output",
        isHistory: true,
        sourceRowMode: "result",
        jobId: historyJobId,
        historyId: record.id,
        triageAggregates: res.triageAggregates || null,
      };
      const triageState = res.triageState || {};
      setModal((p) => ({
        ...p,
        phase: "results",
        jobId: historyJobId,
        historyId: record.id,
        scanHistoryLoading: false,
        scanHistoryView: true,
        sigmaView: "dashboard",
        sigmaReviewedRules: triageState.reviewedRules || {},
        sigmaFalsePositiveRules: triageState.falsePositiveRules || {},
        sigmaTaggedRules: triageState.taggedRules || {},
        sigmaBookmarkedRules: triageState.bookmarkedRules || {},
        htmlReportContent: null,
        results: {
          matches: res.matches || [],
          stats: res.stats || {},
          errors: res.errors || [],
          warnings: res.warnings || [],
          eventRowCount: res.eventRowCount || 0,
          evtxFiles: res.evtxFiles || [],
          hasHtmlReport: !!res.hasHtmlReport,
          historyId: record.id,
          triageAggregates: res.triageAggregates || null,
          historyRecord: res,
        },
        progress: null,
      }));
    } catch (e) {
      setModal((p) => ({ ...p, scanHistoryLoading: false, error: e?.message || "Failed to open scan history" }));
    }
  };

  const handleDeleteHistoryRecord = async (record) => {
    if (!record?.id || !tle?.sigmaDeleteScanHistory) return;
    setModal((p) => ({ ...p, scanHistoryDeleting: record.id, error: null }));
    try {
      const res = await tle.sigmaDeleteScanHistory(record.id);
      if (res?.__ipcError || res?.error) throw new Error(res.message || res.error || "Failed to delete scan history");
      await refreshScanHistory();
      setModal((p) => p?.type === "sigma" ? { ...p, scanHistoryDeleting: null } : p);
    } catch (e) {
      setModal((p) => ({ ...p, scanHistoryDeleting: null, error: e?.message || "Failed to delete scan history" }));
    }
  };

  const handleClearScanHistory = async () => {
    if (!tle?.sigmaClearScanHistory) return;
    const count = (modal.scanHistory || []).length;
    if (count > 0) {
      const ok = await confirm({
        title: "Clear scan history",
        message: `Clear all ${count.toLocaleString()} saved detection scans? This removes persisted result stores and reports.`,
        confirmLabel: "Clear All",
        destructive: true,
      });
      if (!ok) return;
    }
    setModal((p) => ({ ...p, scanHistoryLoading: true, scanHistoryNotice: null, error: null }));
    try {
      const res = await tle.sigmaClearScanHistory();
      if (res?.__ipcError || res?.error) throw new Error(res.message || res.error || "Failed to clear scan history");
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        scanHistory: [],
        scanHistoryLoading: false,
        scanHistoryNotice: `Cleared ${formatNumber(res?.cleared || 0)} saved scan${(res?.cleared || 0) === 1 ? "" : "s"}.`,
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, scanHistoryLoading: false, error: e?.message || "Failed to clear scan history" }));
    }
  };

  const handleSaveScanHistoryRetention = async () => {
    if (!tle?.sigmaSaveScanHistorySettings) return;
    const retentionDays = Math.max(0, Math.min(3650, Number.parseInt(modal.scanHistoryRetentionDays ?? 0, 10) || 0));
    setModal((p) => ({ ...p, scanHistorySavingSettings: true, scanHistoryNotice: null, error: null }));
    try {
      const settings = await tle.sigmaSaveScanHistorySettings({ retentionDays });
      if (settings?.__ipcError || settings?.error) throw new Error(settings.message || settings.error || "Failed to save retention setting");
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        scanHistorySettings: settings,
        scanHistoryRetentionDays: settings.retentionDays,
        scanHistorySavingSettings: false,
        scanHistoryNotice: settings.retentionDays > 0
          ? `Retention set to ${settings.retentionDays} day${settings.retentionDays === 1 ? "" : "s"}.`
          : "Retention disabled; scan history is kept until manually deleted or the 200-record cap is reached.",
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, scanHistorySavingSettings: false, error: e?.message || "Failed to save retention setting" }));
    }
  };

  const handlePruneScanHistory = async () => {
    if (!tle?.sigmaPruneScanHistory) return;
    const retentionDays = Math.max(0, Number.parseInt(modal.scanHistoryRetentionDays ?? modal.scanHistorySettings?.retentionDays ?? 0, 10) || 0);
    if (retentionDays <= 0) {
      setModal((p) => ({ ...p, error: "Set retention to at least 1 day before deleting old scans." }));
      return;
    }
    const ok = await confirm({
      title: "Prune scan history",
      message: `Delete saved scans older than ${retentionDays} day${retentionDays === 1 ? "" : "s"}?`,
      confirmLabel: "Delete",
      destructive: true,
    });
    if (!ok) return;
    setModal((p) => ({ ...p, scanHistoryLoading: true, scanHistoryNotice: null, error: null }));
    try {
      const res = await tle.sigmaPruneScanHistory(retentionDays);
      if (res?.__ipcError || res?.error) throw new Error(res.message || res.error || "Failed to delete old scans");
      const rows = await refreshScanHistory();
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        scanHistory: rows,
        scanHistoryLoading: false,
        scanHistoryNotice: `Deleted ${formatNumber(res?.deleted || 0)} old scan${(res?.deleted || 0) === 1 ? "" : "s"}.`,
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, scanHistoryLoading: false, error: e?.message || "Failed to delete old scans" }));
    }
  };

  const handleExportHistoryPackage = async (record) => {
    if (!record?.id || !tle?.sigmaExportScanPackage) return;
    setModal((p) => ({ ...p, scanHistoryExporting: record.id, scanHistoryNotice: null, error: null }));
    try {
      const res = await tle.sigmaExportScanPackage(record.id);
      if (res?.canceled) {
        setModal((p) => p?.type === "sigma" ? { ...p, scanHistoryExporting: null } : p);
        return;
      }
      if (res?.__ipcError || res?.error) throw new Error(res.message || res.error || "Failed to export scan package");
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        scanHistoryExporting: null,
        scanHistoryNotice: `Exported scan package: ${res.path}`,
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, scanHistoryExporting: null, error: e?.message || "Failed to export scan package" }));
    }
  };

  return {
    refreshScanHistory,
    handleShowScanHistory,
    handleOpenHistoryRecord,
    handleDeleteHistoryRecord,
    handleClearScanHistory,
    handleSaveScanHistoryRetention,
    handlePruneScanHistory,
    handleExportHistoryPackage,
  };
}
