const { dialog } = require("electron");
const { openDialogOptions } = require("../../utils/open-dialog");

module.exports = function registerSigmaHistoryHandlers(ctx) {
  const {
    safeHandle,
    _activeWindow,
    scanHistory,
    SigmaResultStore,
    _triageAggregatesForStore,
  } = ctx;

  safeHandle("sigma-list-scan-history", () => {
    return scanHistory.listScanHistory();
  });

  safeHandle("sigma-get-scan-history", (event, { historyId, previewLimit } = {}) => {
    const record = scanHistory.getScanHistory(historyId);
    if (!record) return { error: "Scan history record not found" };
    let preview = [];
    if (record.resultDbPath) {
      const store = SigmaResultStore.open(record.resultDbPath);
      try {
        preview = store.getPreview(Math.max(1, Math.min(Number(previewLimit) || 2000, 5000)));
      } finally {
        store.close();
      }
    }
    const summary = scanHistory.summarizeRecord(record);
    const triageAggregates = record.triageAggregates || _triageAggregatesForStore(record.resultDbPath);
    return {
      ...record,
      ...summary,
      jobId: `history:${record.id}`,
      eventRowsPreview: preview,
      eventRowCount: record.eventRowCount || record.totalMatches || preview.length,
      hasHtmlReport: summary?.hasHtmlReport || false,
      triageState: scanHistory.normalizeTriageState(record.triageState),
      triageAggregates,
    };
  });

  safeHandle("sigma-delete-scan-history", (event, { historyId } = {}) => {
    return scanHistory.deleteScanHistory(historyId);
  });

  safeHandle("sigma-clear-scan-history", () => {
    return scanHistory.clearScanHistory();
  });

  safeHandle("sigma-get-scan-history-settings", () => {
    return scanHistory.getScanHistorySettings();
  });

  safeHandle("sigma-save-scan-history-settings", (event, { settings } = {}) => {
    return scanHistory.saveScanHistorySettings(settings || {});
  });

  safeHandle("sigma-prune-scan-history", (event, { retentionDays } = {}) => {
    return scanHistory.pruneScanHistory({ retentionDays });
  });

  safeHandle("sigma-update-scan-triage", (event, { historyId, triageState } = {}) => {
    return scanHistory.updateScanTriage(historyId, triageState || {});
  });

  safeHandle("sigma-export-scan-package", async (event, { historyId } = {}) => {
    const record = scanHistory.getScanHistory(historyId);
    if (!record) return { error: "Scan history record not found" };
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showOpenDialog(win, openDialogOptions({
      properties: ["openDirectory", "createDirectory"],
      title: "Export Scan Package",
      message: "Choose a folder where IRFlow should create the scan package",
    }));
    if (result.canceled || !result.filePaths?.length) return { canceled: true };
    return scanHistory.exportScanPackage(historyId, result.filePaths[0]);
  });
};
