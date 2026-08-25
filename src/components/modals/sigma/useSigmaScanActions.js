import { formatNumber } from "../../../utils/format.js";
import {
  BUILTIN_SIGMA_SCAN_PRESETS,
  levelsAtOrAboveMinimum,
  sanitizeSigmaScanPresets,
  summarizeSigmaScanPreset,
} from "../../../utils/sigmaScanPresets.mjs";
import { SEV_ORDER, STATUS_LIST } from "./constants.js";
import {
  JS_SIGMA_LARGE_TAB_ROWS,
  JS_SIGMA_MAX_ROWS_PER_QUERY,
  activeSuppressedRuleIdsFromModal,
} from "./sigmaModalHelpers.js";
import { clearIpcSubscription, replaceIpcSubscription } from "../../../utils/ipc-subscriptions.js";

export default function useSigmaScanActions({
  modal,
  setModal,
  tle,
  ct,
  levels,
  statuses,
  hasRules,
  selectedStatusList,
  hayabusaMinSeverity,
  refreshScanHistory,
  sigmaResultsRef,
}) {
  const buildCompatibilityScanOptions = (scanJobId) => {
    const selLevels = SEV_ORDER.filter((l) => levels[l]);
    const selStatuses = STATUS_LIST.filter((s) => statuses[s]);
    const activePreset = [...BUILTIN_SIGMA_SCAN_PRESETS, ...sanitizeSigmaScanPresets(modal.scanPresets || [])]
      .find((preset) => preset.id === modal.activeScanPresetId);
    return {
      scanJobId,
      levels: selLevels,
      statuses: selStatuses,
      categories: modal.selectedCategories || null,
      disabledRuleIds: activeSuppressedRuleIdsFromModal(modal),
      maxRowsPerQuery: JS_SIGMA_MAX_ROWS_PER_QUERY,
      presetId: modal.activeScanPresetId || null,
      presetName: modal.activeScanPresetName || activePreset?.name || null,
      presetSummary: activePreset ? summarizeSigmaScanPreset(activePreset) : null,
      // Analyst format override (null = auto-detect). Set via the format control
      // in the scan config UI; backend falls back to auto-detection when null.
      formatOverride: modal.formatOverride || null,
    };
  };

  const handleScan = async () => {
    const selLevels = SEV_ORDER.filter((l) => levels[l]);
    const selStatuses = STATUS_LIST.filter((s) => statuses[s]);
    if (selLevels.length === 0) {
      setModal((p) => ({ ...p, error: "Select at least one severity before scanning." }));
      return;
    }
    if (selStatuses.length === 0) {
      setModal((p) => ({ ...p, error: "Select at least one rule status before scanning." }));
      return;
    }
    if ((ct?.totalRows || 0) >= JS_SIGMA_LARGE_TAB_ROWS && !modal.largeJsSigmaScanConfirmed) {
      setModal((p) => ({
        ...p,
        largeJsSigmaScanConfirmed: true,
        error: `Large imported-tab JS Sigma scan detected (${formatNumber(ct.totalRows || 0)} rows). Use the "Fast high-confidence only" preset (or fewer severity levels) for much faster results; raw EVTX + Hayabusa is faster when available. Click Scan Imported Tab again to continue; each logsource group is capped at ${formatNumber(JS_SIGMA_MAX_ROWS_PER_QUERY)} candidate rows.`,
      }));
      return;
    }
    const scanJobId = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    setModal((p) => ({ ...p, phase: "scanning", scanJobId, progress: { pct: 0, text: "Starting scan..." }, error: null }));
    replaceIpcSubscription("sigma-progress", tle.onSigmaProgress, (prog) => {
      setModal((p) => p?.type === "sigma" ? { ...p, progress: prog } : p);
    });
    try {
      const res = await tle.sigmaScan(ct.id, { ...buildCompatibilityScanOptions(scanJobId), sourceName: ct?.name || `Tab ${ct?.id || ""}`, sourcePath: ct?.filePath || "" });
      if (res?.__ipcError) throw new Error(res.message || "Scan failed");
      sigmaResultsRef.current = { eventRows: res.eventRowsPreview || [], sourceRowMode: "timeline", jobId: res.jobId, historyId: res.historyId || null, triageAggregates: res.triageAggregates || null };
      setModal((p) => ({ ...p, phase: "results", sigmaView: "dashboard", sigmaReviewedRules: {}, sigmaFalsePositiveRules: {}, sigmaTaggedRules: {}, sigmaBookmarkedRules: {}, jobId: res.jobId, historyId: res.historyId || null, scanJobId: null, results: { matches: res.matches, stats: res.stats, errors: res.errors, warnings: res.warnings || [], eventRowCount: res.eventRowCount || 0, historyId: res.historyId || null, triageAggregates: res.triageAggregates || null }, progress: null }));
      refreshScanHistory();
    } catch (e) {
      setModal((p) => ({ ...p, phase: "config", scanJobId: null, error: e?.cancelled ? "Scan cancelled" : (e?.message || "Scan failed"), progress: null }));
    }
  };

  const handleSelectEvtxDir = async () => {
    if (!tle?.sigmaSelectEvtxDir) return;
    try {
      const info = await tle.sigmaSelectEvtxDir();
      if (info) setModal((p) => ({ ...p, evtxDir: info, scanPreflight: null }));
    } catch (_) {}
  };

  const handleSelectKapeOutput = async () => {
    if (!tle?.sigmaSelectKapeOutput) return;
    try {
      const info = await tle.sigmaSelectKapeOutput();
      if (info?.__ipcError) throw new Error(info.message || "Failed to select EvtxECmd output files");
      if (info) setModal((p) => ({ ...p, kapeOutput: info, scanPreflight: null, error: null }));
    } catch (e) {
      setModal((p) => ({ ...p, error: e?.message || "Failed to select EvtxECmd output files" }));
    }
  };

  const handleSelectKapeOutputFolder = async () => {
    if (!tle?.sigmaSelectKapeOutputFolder) return;
    try {
      const info = await tle.sigmaSelectKapeOutputFolder();
      if (info?.__ipcError) throw new Error(info.message || "Failed to find EvtxECmd output files");
      if (info) setModal((p) => ({ ...p, kapeOutput: info, scanPreflight: null, error: null }));
    } catch (e) {
      setModal((p) => ({ ...p, error: e?.message || "Failed to find EvtxECmd output files" }));
    }
  };

  const buildDirectoryScanOptions = () => {
    const parseList = (s) => (s || "").split(",").map((v) => v.trim()).filter(Boolean);
    const selLevels = levelsAtOrAboveMinimum(modal.hayabusaMinSeverity || hayabusaMinSeverity);
    const selStatuses = STATUS_LIST.filter((s) => statuses[s]);
    const selCategories = modal.selectedCategories || null;
    const activePreset = [...BUILTIN_SIGMA_SCAN_PRESETS, ...sanitizeSigmaScanPresets(modal.scanPresets || [])]
      .find((preset) => preset.id === modal.activeScanPresetId);
    return {
      levels: selLevels,
      statuses: selStatuses,
      categories: selCategories,
      presetId: modal.activeScanPresetId || null,
      presetName: modal.activeScanPresetName || activePreset?.name || null,
      presetSummary: activePreset ? summarizeSigmaScanPreset(activePreset) : null,
      ruleSet: modal.ruleSet || "all",
      recoverRecords: modal.recoverRecords || false,
      timelineStart: (modal.timelineStart || "").trim() || undefined,
      timelineEnd: (modal.timelineEnd || "").trim() || undefined,
      utc: modal.utc || false,
      provenRules: modal.provenRules || false,
      enableNoisy: modal.enableNoisy || false,
      enableDeprecated: modal.enableDeprecated || false,
      enableUnsupported: modal.enableUnsupported || false,
      eidFilter: modal.eidFilter || false,
      enableAllRules: modal.enableAllRules || false,
      scanAllEvtxFiles: modal.scanAllEvtxFiles || false,
      geoIpDir: modal.geoIpEnabled && (modal.geoIpDir || "").trim() ? (modal.geoIpDir || "").trim() : undefined,
      outputMode: modal.outputMode || "csv",
      profile: modal.profile || "verbose",
      rulesPath: (modal.rulesPath || "").trim() || undefined,
      rulesConfig: (modal.rulesConfig || "").trim() || undefined,
      includeTags: parseList(modal.includeTags),
      excludeTags: parseList(modal.excludeTags),
      includeComputers: parseList(modal.includeComputers),
      excludeComputers: parseList(modal.excludeComputers),
      includeEids: parseList(modal.includeEids),
      excludeEids: parseList(modal.excludeEids),
      disabledRuleIds: activeSuppressedRuleIdsFromModal(modal),
    };
  };

  const validateDirectoryScanSetup = async (dirPath, options) => {
    if (!tle?.sigmaValidateScanDirectory) return { ok: true, errors: [], warnings: [], summary: {} };
    const preflight = await tle.sigmaValidateScanDirectory(dirPath, options);
    if (preflight?.__ipcError) throw new Error(preflight.message || "Scan validation failed");
    return preflight;
  };

  const handleValidateDirectoryScan = async () => {
    const dirInfo = modal.evtxDir;
    if (!dirInfo?.dirPath) return;
    if (selectedStatusList.length === 0) {
      setModal((p) => ({ ...p, error: "Select at least one rule status before validating the scan." }));
      return;
    }
    setModal((p) => ({ ...p, preflightChecking: true, error: null }));
    try {
      const preflight = await validateDirectoryScanSetup(dirInfo.dirPath, buildDirectoryScanOptions());
      setModal((p) => ({ ...p, preflightChecking: false, scanPreflight: preflight, error: preflight.ok ? null : "Fix scan setup before scanning." }));
    } catch (e) {
      setModal((p) => ({ ...p, preflightChecking: false, error: e?.message || "Scan validation failed" }));
    }
  };

  const handleScanDirectory = async () => {
    const dirInfo = modal.evtxDir;
    if (!dirInfo?.dirPath || !tle?.sigmaScanDirectory) return;
    const options = buildDirectoryScanOptions();
    if (!options.levels?.length) {
      setModal((p) => ({ ...p, error: "Select a minimum severity before scanning." }));
      return;
    }
    if (!options.statuses?.length) {
      setModal((p) => ({ ...p, error: "Select at least one rule status before scanning." }));
      return;
    }
    setModal((p) => ({ ...p, preflightChecking: true, error: null }));
    let preflight;
    try {
      preflight = await validateDirectoryScanSetup(dirInfo.dirPath, options);
      if (!preflight.ok) {
        setModal((p) => ({ ...p, preflightChecking: false, scanPreflight: preflight, error: "Fix scan setup before scanning." }));
        return;
      }
    } catch (e) {
      setModal((p) => ({ ...p, preflightChecking: false, error: e?.message || "Scan validation failed" }));
      return;
    }
    const scanJobId = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    setModal((p) => ({ ...p, phase: "scanning", scanJobId, preflightChecking: false, scanPreflight: preflight, progress: { phase: "discovering", text: "Scanning directory..." }, error: null }));
    replaceIpcSubscription("sigma-progress", tle.onSigmaProgress, (prog) => {
      setModal((p) => p?.type === "sigma" ? { ...p, progress: prog } : p);
    });
    try {
      const res = await tle.sigmaScanDirectory(dirInfo.dirPath, { ...options, scanJobId });
      if (res?.__ipcError) throw new Error(res.message || "Directory scan failed");
      if (res?.cancelled) {
        setModal((p) => ({ ...p, phase: "config", scanJobId: null, error: "Scan cancelled", progress: null }));
        return;
      }
      sigmaResultsRef.current = { eventRows: res.eventRowsPreview || [], isDirScan: true, sourceRowMode: "result", jobId: res.jobId, historyId: res.historyId || null, triageAggregates: res.triageAggregates || null };
      setModal((p) => ({ ...p, phase: "results", sigmaView: "dashboard", sigmaReviewedRules: {}, sigmaFalsePositiveRules: {}, sigmaTaggedRules: {}, sigmaBookmarkedRules: {}, jobId: res.jobId, historyId: res.historyId || null, scanJobId: null, results: { matches: res.matches, stats: res.stats, errors: res.errors, warnings: res.warnings || [], eventRowCount: res.eventRowCount || 0, evtxFiles: res.evtxFiles, hasHtmlReport: res.hasHtmlReport || false, historyId: res.historyId || null, triageAggregates: res.triageAggregates || null }, progress: null }));
      refreshScanHistory();
    } catch (e) {
      setModal((p) => ({ ...p, phase: "config", scanJobId: null, error: e?.message || "Directory scan failed", progress: null }));
    }
  };

  const handleScanKapeOutput = async () => {
    const info = modal.kapeOutput;
    if (!info?.paths?.length || !tle?.sigmaScanKapeOutput) return;
    const options = buildCompatibilityScanOptions(`scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
    if (!options.levels?.length) {
      setModal((p) => ({ ...p, error: "Select at least one severity before scanning." }));
      return;
    }
    if (!options.statuses?.length) {
      setModal((p) => ({ ...p, error: "Select at least one rule status before scanning." }));
      return;
    }
    if (!hasRules) {
      setModal((p) => ({ ...p, error: "Download or import Sigma compatibility rules before scanning EvtxECmd output files." }));
      return;
    }
    const scanJobId = options.scanJobId;
    setModal((p) => ({ ...p, phase: "scanning", scanJobId, progress: { pct: 0, text: "Starting EvtxECmd output scan..." }, error: null }));
    replaceIpcSubscription("sigma-progress", tle.onSigmaProgress, (prog) => {
      setModal((p) => p?.type === "sigma" ? { ...p, progress: prog } : p);
    });
    try {
      const res = await tle.sigmaScanKapeOutput(info.paths, options);
      if (res?.__ipcError) throw new Error(res.message || "EvtxECmd output scan failed");
      if (res?.cancelled) {
        setModal((p) => ({ ...p, phase: "config", scanJobId: null, error: "Scan cancelled", progress: null }));
        return;
      }
      sigmaResultsRef.current = { eventRows: res.eventRowsPreview || [], isKapeOutput: true, sourceRowMode: "result", jobId: res.jobId, historyId: res.historyId || null, triageAggregates: res.triageAggregates || null };
      setModal((p) => ({ ...p, phase: "results", sigmaView: "dashboard", sigmaReviewedRules: {}, sigmaFalsePositiveRules: {}, sigmaTaggedRules: {}, sigmaBookmarkedRules: {}, jobId: res.jobId, historyId: res.historyId || null, scanJobId: null, results: { matches: res.matches, stats: res.stats, errors: res.errors, warnings: res.warnings || [], eventRowCount: res.eventRowCount || 0, files: res.files || [], historyId: res.historyId || null, triageAggregates: res.triageAggregates || null }, progress: null }));
      refreshScanHistory();
    } catch (e) {
      setModal((p) => ({ ...p, phase: "config", scanJobId: null, error: e?.message || "EvtxECmd output scan failed", progress: null }));
    }
  };

  const handleCancelScan = async () => {
    const id = modal.scanJobId;
    clearIpcSubscription("sigma-progress");
    if (id && tle?.sigmaCancelScan) {
      try { await tle.sigmaCancelScan(id); } catch (_) {}
    }
    setModal((p) => ({ ...p, phase: "config", scanJobId: null, progress: null }));
  };

  const handleCloseModal = () => {
    const id = modal?.scanJobId;
    clearIpcSubscription("sigma-progress");
    if (id && tle?.sigmaCancelScan) {
      try { tle.sigmaCancelScan(id); } catch (_) {}
    }
    setModal(null);
  };

  const handleRunMetrics = async (type) => {
    const dirInfo = modal.evtxDir;
    if (!dirInfo?.dirPath) return;
    if (modal.metricsData?.[type]) {
      setModal((p) => ({ ...p, metricsTab: p.metricsTab === type ? null : type }));
      return;
    }
    setModal((p) => ({ ...p, metricsLoading: type, metricsTab: type }));
    try {
      const api = { logon: tle?.sigmaLogonSummary, computer: tle?.sigmaComputerMetrics, eid: tle?.sigmaEidMetrics, log: tle?.sigmaLogMetrics, pivot: tle?.sigmaPivotKeywords, base64: tle?.sigmaExtractBase64 };
      const result = await api[type]?.(dirInfo.dirPath);
      setModal((p) => ({ ...p, metricsLoading: null, metricsData: { ...(p.metricsData || {}), [type]: result } }));
    } catch (e) {
      setModal((p) => ({ ...p, metricsLoading: null, error: e?.message || `${type} metrics failed` }));
    }
  };

  return {
    handleScan,
    handleSelectEvtxDir,
    handleSelectKapeOutput,
    handleSelectKapeOutputFolder,
    handleValidateDirectoryScan,
    handleScanDirectory,
    handleScanKapeOutput,
    handleCancelScan,
    handleCloseModal,
    handleRunMetrics,
  };
}
