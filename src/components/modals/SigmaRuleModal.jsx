import { Fragment, useState, useRef, useCallback } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { formatBytes, formatNumber } from "../../utils/format.js";
import { Modal } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";
import { SigmaModalContext } from "./sigma/SigmaModalContext.js";
import SigmaConfigWizard from "./sigma/SigmaConfigWizard.jsx";
import SigmaModalFooter from "./sigma/SigmaModalFooter.jsx";
import SigmaResultsView from "./sigma/SigmaResultsView.jsx";
import useSigmaHistoryActions from "./sigma/useSigmaHistoryActions.js";
import SigmaScanProgress from "./sigma/SigmaScanProgress.jsx";
import useSigmaModalBootstrap from "./sigma/useSigmaModalBootstrap.js";
import useSigmaResultActions from "./sigma/useSigmaResultActions.js";
import useSigmaScanActions from "./sigma/useSigmaScanActions.js";
import useSigmaSettingsActions from "./sigma/useSigmaSettingsActions.js";
import useSigmaWizardState from "./sigma/useSigmaWizardState.js";
import {
  sevColorsFor,
  WIZARD_STEPS,
} from "./sigma/constants.js";
import {
  BUILTIN_SIGMA_SCAN_PRESETS,
  applySigmaScanPresetState,
  buildSigmaScanPresetFromModal,
  sanitizeSigmaScanPresets,
  summarizeSigmaScanPreset,
} from "../../utils/sigmaScanPresets.mjs";
import {
  JS_SIGMA_LARGE_TAB_ROWS,
  JS_SIGMA_MAX_ROWS_PER_QUERY,
  compactPath,
  formatDuration,
  formatScanDate,
  wrapTextStyle,
} from "./sigma/sigmaModalHelpers.js";

export default function SigmaRuleModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const refreshCallback = useUIStore((s) => s.refreshCallback);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const SEV_COLORS = sevColorsFor(th);
  const tle = typeof window !== "undefined" ? window.tle : null;
  const updateActiveTab = useTabStore((s) => s.updateActiveTab);
  const sigmaResultsRef = useRef(null); // holds full eventRows outside React state

  const up = useCallback((key, val) => {
    updateActiveTab({ [key]: val });
  }, [updateActiveTab]);

  const fetchData = useCallback((tab) => {
    if (refreshCallback) refreshCallback(tab);
  }, [refreshCallback]);

  const ms = useModalChrome();
  useSigmaModalBootstrap({ modal, setModal, tle });

  // Drag + resize state
  const dragRef = useRef(null);
  const [pos, setPos] = useState({ x: null, y: null });
  const [size, setSize] = useState({ w: 660, h: null });
  const onDragStart = useCallback((e) => {
    if (e.target.closest("button, input, select, textarea, a")) return;
    const rect = e.currentTarget.closest("[data-modal-box]").getBoundingClientRect();
    dragRef.current = { startX: e.clientX - rect.left, startY: e.clientY - rect.top, dragging: true };
    const onMove = (ev) => {
      if (!dragRef.current?.dragging) return;
      setPos({ x: ev.clientX - dragRef.current.startX, y: ev.clientY - dragRef.current.startY });
    };
    const onUp = () => { if (dragRef.current) dragRef.current.dragging = false; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, []);
  const onResizeStart = useCallback((e) => {
    e.preventDefault(); e.stopPropagation();
    const box = e.currentTarget.closest("[data-modal-box]");
    const startW = box.offsetWidth, startH = box.offsetHeight;
    const startX = e.clientX, startY = e.clientY;
    const onMove = (ev) => {
      setSize({ w: Math.max(400, startW + (ev.clientX - startX)), h: Math.max(300, startH + (ev.clientY - startY)) });
    };
    const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, []);

  if (!modal || modal.type !== "sigma") return null;

  const phase = modal.phase || "config";
  const status = modal.status || null;
  const ruleInfo = modal.ruleInfo || null;
  const levels = modal.levels || { critical: true, high: true, medium: true, low: true, informational: true };
  const statuses = modal.statuses || { stable: true, test: true, experimental: true };
  const progress = modal.progress || null;
  const results = modal.results || null;
  const expandedRule = modal.expandedRule || null;
  const downloading = modal.downloading || false;
  const error = modal.error || null;
  const availableRepos = modal.availableRepos || [];
  const selectedRepos = modal.selectedRepos || null; // null = defaults not loaded yet
  const {
    hasRules,
    scanMode,
    selectedLevelList,
    selectedStatusList,
    hayabusaMinSeverity,
    hayabusaLevelList,
    activeWizardStep,
    hasTargetReady,
    hasPresetReady,
  } = useSigmaWizardState({ modal, phase, ct, status });

  /* ── Handlers ─────────────────────────────────────────────────────── */

  const {
    refreshScanHistory,
    handleShowScanHistory,
    handleOpenHistoryRecord,
    handleDeleteHistoryRecord,
    handleClearScanHistory,
    handleSaveScanHistoryRetention,
    handlePruneScanHistory,
    handleExportHistoryPackage,
  } = useSigmaHistoryActions({ modal, setModal, tle, sigmaResultsRef });

  const {
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
  } = useSigmaSettingsActions({ modal, setModal, tle, selectedRepos, availableRepos });

  const persistScanPresets = async (presets) => {
    const clean = sanitizeSigmaScanPresets(presets);
    if (tle?.saveSigmaScanPresets) await tle.saveSigmaScanPresets(clean);
    return clean;
  };

  const handleApplyScanPreset = (preset) => {
    setModal((p) => p?.type === "sigma" ? applySigmaScanPresetState(p, preset) : p);
  };

  const handleSaveScanPreset = async () => {
    const name = (modal.newScanPresetName || "").trim();
    if (!name) {
      setModal((p) => ({ ...p, error: "Enter a scan preset name before saving." }));
      return;
    }
    try {
      const existing = sanitizeSigmaScanPresets(modal.scanPresets || []);
      const match = existing.find((preset) => preset.name.toLowerCase() === name.toLowerCase());
      const nextPreset = buildSigmaScanPresetFromModal(modal, {
        name,
        id: match?.id,
        createdAt: match?.createdAt,
      });
      const nextPresets = match
        ? existing.map((preset) => preset.id === match.id ? nextPreset : preset)
        : [nextPreset, ...existing];
      const saved = await persistScanPresets(nextPresets);
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        scanPresets: saved,
        newScanPresetName: "",
        activeScanPresetId: nextPreset.id,
        activeScanPresetName: nextPreset.name,
        error: null,
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, error: e?.message || "Failed to save scan preset" }));
    }
  };

  const handleDeleteScanPreset = async (presetId) => {
    try {
      const nextPresets = sanitizeSigmaScanPresets(modal.scanPresets || []).filter((preset) => preset.id !== presetId);
      const saved = await persistScanPresets(nextPresets);
      setModal((p) => p?.type === "sigma" ? {
        ...p,
        scanPresets: saved,
        activeScanPresetId: p.activeScanPresetId === presetId ? null : p.activeScanPresetId,
        activeScanPresetName: p.activeScanPresetId === presetId ? null : p.activeScanPresetName,
        error: null,
      } : p);
    } catch (e) {
      setModal((p) => ({ ...p, error: e?.message || "Failed to delete scan preset" }));
    }
  };

  const {
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
  } = useSigmaScanActions({
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
  });

  const {
    handleShowInTimeline,
    handleTagMatches,
    handleBookmarkMatches,
    handleMarkRuleReviewed,
    handleMarkRuleFalsePositive,
    handleOpenExactMatchesAsTab,
    handleExportCSV,
    handleExportJSON,
    handleOpenAsTab,
  } = useSigmaResultActions({
    modal,
    setModal,
    tle,
    ct,
    th,
    up,
    fetchData,
    updateActiveTab,
    sigmaResultsRef,
    results,
  });

  /* ── Render helpers ───────────────────────────────────────────────── */

  const sevBadge = (level) => (
    <span style={{ display: "inline-block", padding: "1px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.04em", background: `${SEV_COLORS[level] || th.sev.low}22`, color: SEV_COLORS[level] || th.sev.low, border: `1px solid ${SEV_COLORS[level] || th.sev.low}44` }}>{level}</span>
  );

  const mitreBadge = (tag) => (
    <span key={tag} style={{ display: "inline-block", padding: "1px 5px", borderRadius: 3, fontSize: 8, fontWeight: 600, background: `${th.accent}18`, color: th.accent, border: `1px solid ${th.accent}33`, marginRight: 3 }}>{tag}</span>
  );

  const checkbox = (label, checked, onChange) => (
    <label style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: th.text, cursor: "pointer", marginRight: 8 }}>
      <input type="checkbox" checked={checked} onChange={onChange} style={{ accentColor: th.accent }} /> {label}
    </label>
  );

  const renderRuleDiffSummary = (ruleDiff, isFinal = true) => {
    if (!ruleDiff) return null;
    const stats = [
      { label: "Added", value: ruleDiff.addedCount || 0, color: th.sev.clean },
      { label: "Removed", value: ruleDiff.removedCount || 0, color: th.sev.critical },
      { label: "Changed", value: ruleDiff.changedCount || 0, color: th.sev.med },
      { label: "Current", value: ruleDiff.currentRuleCount || 0, color: th.text },
    ];
    const samples = [
      { label: "Added", files: ruleDiff.addedRules || [], overflow: ruleDiff.addedOverflow || 0, color: th.sev.clean },
      { label: "Removed", files: ruleDiff.removedRules || [], overflow: ruleDiff.removedOverflow || 0, color: th.sev.critical },
      { label: "Changed", files: ruleDiff.changedRules || [], overflow: ruleDiff.changedOverflow || 0, color: th.sev.med },
    ].filter((section) => section.files.length > 0 || section.overflow > 0);

    return (
      <div style={{ margin: "6px 10px 2px", border: `1px solid ${th.border}55`, borderRadius: 8, background: `${th.bgInput || th.bg}66`, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(74px, 1fr))", gap: 1, borderBottom: `1px solid ${th.border}33` }}>
          {stats.map((item) => (
            <div key={item.label} style={{ padding: "7px 8px", background: `${item.color}0f`, minWidth: 0 }}>
              <div style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.04em" }}>{item.label}</div>
              <div style={{ fontSize: 14, color: item.color, fontWeight: 800, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis" }}>{formatNumber(item.value)}</div>
            </div>
          ))}
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", padding: "6px 8px", fontSize: 9, color: th.textMuted }}>
          <span>Last update: <strong style={{ color: th.textDim }}>{formatScanDate(ruleDiff.lastUpdateTime)}</strong></span>
          {ruleDiff.latestRuleMtime && <span>Latest rule file: <strong style={{ color: th.textDim }}>{formatScanDate(ruleDiff.latestRuleMtime)}</strong></span>}
        </div>
        {samples.length > 0 ? (
          <div style={{ display: "grid", gap: 4, padding: "0 8px 8px" }}>
            {samples.map((section) => (
              <div key={section.label} style={{ display: "grid", gridTemplateColumns: "64px minmax(0, 1fr)", gap: 6, alignItems: "start", fontSize: 9 }}>
                <span style={{ color: section.color, fontWeight: 700 }}>{section.label}</span>
                <span style={{ color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={[...section.files, section.overflow ? `+${section.overflow} more` : ""].filter(Boolean).join("\n")}>
                  {section.files.slice(0, 6).join(", ")}{section.overflow > 0 ? `, +${formatNumber(section.overflow)} more` : ""}
                </span>
              </div>
            ))}
          </div>
        ) : isFinal ? (
          <div style={{ padding: "0 8px 8px", fontSize: 9, color: th.textMuted }}>No rule file changes detected.</div>
        ) : null}
      </div>
    );
  };

  const renderPreflightPanel = (preflight) => {
    if (!preflight) return null;
    const errors = preflight.errors || [];
    const warnings = preflight.warnings || [];
    const summary = preflight.summary || {};
    const hasIssues = errors.length > 0 || warnings.length > 0;
    const color = errors.length > 0 ? th.sev.critical : warnings.length > 0 ? th.sev.med : th.sev.clean;
    const ruleFreshness = summary.hayabusaRulesCurrent === true
      ? "rules current"
      : summary.hayabusaRulesCurrent === false
        ? "rules stale/missing"
        : "rule freshness unknown";
    return (
      <div style={{ marginBottom: 8, padding: "8px 10px", borderRadius: 8, border: `1px solid ${color}44`, background: `${color}10`, fontFamily: "-apple-system, sans-serif" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: hasIssues ? 6 : 0, fontSize: 10, color: th.textDim, flexWrap: "wrap" }}>
          <strong style={{ color }}>{errors.length > 0 ? "Scan setup blocked" : warnings.length > 0 ? "Scan setup warnings" : "Scan setup ready"}</strong>
          {summary.presetName && <span title={summary.presetSummary || summary.presetName}>Preset: {summary.presetName}</span>}
          <span>{formatNumber(summary.evtxFileCount || 0)} EVTX file{(summary.evtxFileCount || 0) === 1 ? "" : "s"}</span>
          <span>{summary.hayabusaInstalled ? `Hayabusa ${summary.hayabusaVersion || ""}`.trim() : "Hayabusa not installed"}</span>
          {summary.hayabusaRuleCount != null && <span>{formatNumber(summary.hayabusaRuleCount)} Hayabusa rule{summary.hayabusaRuleCount === 1 ? "" : "s"}</span>}
          <span>{ruleFreshness}</span>
          {summary.selectedLevels?.length > 0 && <span>{summary.selectedLevels.join(", ")} severity</span>}
          {summary.selectedStatuses?.length > 0 && <span>{summary.selectedStatuses.join(", ")} status</span>}
          <span>{summary.ruleSet || "all"} rules</span>
          <span>{summary.profile || "verbose"} profile</span>
          {summary.customRuleCount != null && <span>{formatNumber(summary.customRuleCount)} custom rule{summary.customRuleCount === 1 ? "" : "s"}</span>}
          {summary.geoIpFileCount != null && <span>{formatNumber(summary.geoIpFileCount)} GeoIP DB{summary.geoIpFileCount === 1 ? "" : "s"}</span>}
        </div>
        {summary.presetSummary && (
          <div style={{ fontSize: 10, color: th.textMuted, lineHeight: 1.45, marginBottom: hasIssues ? 4 : 0 }}>
            Preset summary: {summary.presetSummary}
          </div>
        )}
        {errors.map((item, i) => (
          <div key={`e-${i}`} style={{ fontSize: 10, color: th.sev.critical, lineHeight: 1.45 }}>{item}</div>
        ))}
        {warnings.map((item, i) => (
          <div key={`w-${i}`} style={{ fontSize: 10, color: th.sev.med, lineHeight: 1.45 }}>{item}</div>
        ))}
      </div>
    );
  };

  const renderScanPresetPanel = () => {
    const savedPresets = sanitizeSigmaScanPresets(modal.scanPresets || []);
    const activeId = modal.activeScanPresetId || null;
    const renderPresetButton = (preset) => {
      const active = activeId === preset.id;
      const accent = preset.id === "full-hunt" ? th.sev.custom : preset.id === "fast-high-confidence" ? th.sev.clean : th.accent;
      return (
        <button
          key={preset.id}
          onClick={() => handleApplyScanPreset(preset)}
          title={summarizeSigmaScanPreset(preset)}
          style={{
            minHeight: 52,
            padding: "7px 9px",
            borderRadius: 8,
            textAlign: "left",
            cursor: "pointer",
            background: active ? `${accent}18` : th.panelBg,
            border: `1px solid ${active ? accent + "66" : th.border + "44"}`,
            fontFamily: "-apple-system,sans-serif",
            minWidth: 0,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
            <span style={{ width: 8, height: 8, borderRadius: 999, background: active ? accent : "transparent", border: `1px solid ${active ? accent : th.textMuted}`, flexShrink: 0 }} />
            <span style={{ color: active ? th.text : th.textDim, fontSize: 11, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{preset.name}</span>
          </div>
          <div style={{ marginLeft: 14, marginTop: 3, color: active ? accent : th.textMuted, fontSize: 8, lineHeight: 1.3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {summarizeSigmaScanPreset(preset)}
          </div>
        </button>
      );
    };

    return (
      <div style={{ ...ms.fg }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 5 }}>
          <label style={{ ...ms.lb, margin: 0 }}>Scan Preset</label>
          {modal.activeScanPresetName && (
            <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              Active: {modal.activeScanPresetName}
            </span>
          )}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 6 }}>
          {BUILTIN_SIGMA_SCAN_PRESETS.map(renderPresetButton)}
        </div>
        {savedPresets.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 6 }}>
            {savedPresets.map((preset) => {
              const active = activeId === preset.id;
              return (
                <div key={preset.id} style={{ display: "inline-flex", alignItems: "stretch", minWidth: 0, maxWidth: "100%", border: `1px solid ${active ? th.accent + "66" : th.border + "44"}`, borderRadius: 6, overflow: "hidden", background: active ? `${th.accent}12` : th.panelBg }}>
                  <button onClick={() => handleApplyScanPreset(preset)} title={`${summarizeSigmaScanPreset(preset)}${preset.updatedAt ? `\nUpdated ${formatScanDate(preset.updatedAt)}` : ""}`} style={{ ...ms.bsm, border: "none", borderRadius: 0, minWidth: 0, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: active ? th.accent : th.textDim }}>
                    {preset.name}
                  </button>
                  <button onClick={() => handleDeleteScanPreset(preset.id)} title="Delete preset" style={{ ...ms.bsm, border: "none", borderLeft: `1px solid ${th.border}44`, borderRadius: 0, color: th.sev.critical, padding: "2px 7px" }}>
                    &times;
                  </button>
                </div>
              );
            })}
          </div>
        )}
        <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 7 }}>
          <input
            type="text"
            placeholder="Save current profile as..."
            value={modal.newScanPresetName || ""}
            onChange={(e) => setModal((p) => ({ ...p, newScanPresetName: e.target.value }))}
            onKeyDown={(e) => { if (e.key === "Enter") handleSaveScanPreset(); }}
            style={{ ...ms.ip, flex: 1, minWidth: 160 }}
          />
          <button onClick={handleSaveScanPreset} style={{ ...ms.bsm, flex: "none" }}>Save Preset</button>
        </div>
      </div>
    );
  };

  const renderScanReadinessPanel = () => {
    const mode = scanMode;
    const isEvtx = mode === "evtx-dir";
    const isKapeOutput = mode === "kape-output";
    const issues = [];
    const warnings = [];
    const ruleCount = (status?.cachedRuleCount || 0) + (status?.customRuleCount || 0);
    const hayabusaRuleCount = modal.hayabusaStatus?.ruleState?.hayabusaRuleCount
      || modal.hayabusaUpdateRuleDiff?.currentRuleCount
      || 0;

    if (selectedStatusList.length === 0) issues.push("No rule statuses selected");
    if (isEvtx) {
      if (!modal.evtxDir?.fileCount) issues.push("No EVTX directory selected");
      if (!modal.hayabusaStatus?.installed) warnings.push("Hayabusa will install on first scan");
      if (modal.hayabusaStatus?.installed && hayabusaRuleCount === 0) warnings.push("Hayabusa rules missing");
      if (modal.hayabusaStatus?.ruleState?.hayabusaRulesLastUpdate) {
        const ageDays = Math.floor((Date.now() - Date.parse(modal.hayabusaStatus.ruleState.hayabusaRulesLastUpdate)) / 86400000);
        if (Number.isFinite(ageDays) && ageDays > 30) warnings.push(`Hayabusa rules ${ageDays} days old`);
      }
      if ((modal.ruleSet || "all") === "all" && !modal.provenRules && !modal.eidFilter) warnings.push("Broad rule scope");
    } else if (isKapeOutput) {
      if (!modal.kapeOutput?.fileCount) issues.push("No EvtxECmd output files selected");
      if (!hasRules) issues.push("No Sigma rules cached");
      if (selectedLevelList.length === 0) issues.push("No severities selected");
      if (Number(modal.kapeOutput?.totalBytes || 0) >= 1024 * 1024 * 1024) warnings.push("Large JS compatibility scan");
    } else {
      if (!ct?.dataReady) issues.push("No imported tab loaded");
      if (!hasRules) issues.push("No Sigma rules cached");
      if (selectedLevelList.length === 0) issues.push("No severities selected");
      if ((ct?.totalRows || 0) >= JS_SIGMA_LARGE_TAB_ROWS) warnings.push("Large JS compatibility scan");
    }
    if (modal.scanPreflight?.errors?.length) issues.push(`${modal.scanPreflight.errors.length} preflight error${modal.scanPreflight.errors.length === 1 ? "" : "s"}`);
    if (modal.scanPreflight?.warnings?.length) warnings.push(`${modal.scanPreflight.warnings.length} preflight warning${modal.scanPreflight.warnings.length === 1 ? "" : "s"}`);

    const color = issues.length > 0 ? th.sev.critical : warnings.length > 0 ? th.sev.med : th.sev.clean;
    const items = isEvtx
      ? [
          ["Target", modal.evtxDir?.fileCount ? `${formatNumber(modal.evtxDir.fileCount)} EVTX files` : "not selected"],
          ["Preset", modal.activeScanPresetName || "custom"],
          ["Engine", modal.hayabusaStatus?.installed ? `Hayabusa ${modal.hayabusaStatus.version || ""}`.trim() : "auto-install"],
          ["Severity", `${hayabusaMinSeverity}+`],
          ["Statuses", selectedStatusList.length ? selectedStatusList.join(", ") : "none"],
          ["Rules", hayabusaRuleCount ? `${formatNumber(hayabusaRuleCount)} Hayabusa rules` : (modal.ruleSet || "all")],
          ["Profile", modal.profile || "verbose"],
        ]
      : isKapeOutput
        ? [
            ["Target", modal.kapeOutput?.fileCount ? `${formatNumber(modal.kapeOutput.fileCount)} EvtxECmd file${modal.kapeOutput.fileCount === 1 ? "" : "s"}` : "not selected"],
            ["Engine", "JS Sigma compatibility"],
            ["Severity", selectedLevelList.length ? selectedLevelList.join(", ") : "none"],
            ["Statuses", selectedStatusList.length ? selectedStatusList.join(", ") : "none"],
            ["Rules", ruleCount ? `${formatNumber(ruleCount)} cached/custom` : "none"],
            ["Row cap", `${formatNumber(JS_SIGMA_MAX_ROWS_PER_QUERY)} per logsource`],
            ["Categories", modal.selectedCategories ? `${modal.selectedCategories.length} selected` : "all"],
          ]
      : [
          ["Target", ct?.dataReady ? `${ct?.name || "current tab"} (${formatNumber(ct.totalRows || 0)} rows)` : "not ready"],
          ["Engine", "JS Sigma compatibility"],
          ["Severity", selectedLevelList.length ? selectedLevelList.join(", ") : "none"],
          ["Statuses", selectedStatusList.length ? selectedStatusList.join(", ") : "none"],
          ["Rules", ruleCount ? `${formatNumber(ruleCount)} cached/custom` : "none"],
          ["Row cap", `${formatNumber(JS_SIGMA_MAX_ROWS_PER_QUERY)} per logsource`],
          ["Categories", modal.selectedCategories ? `${modal.selectedCategories.length} selected` : "all"],
        ];

    return (
      <div style={{ ...ms.fg, padding: "8px 10px", borderRadius: 8, border: `1px solid ${color}44`, background: `${color}0d` }}>
        <div style={{ display: "flex", alignItems: "baseline", flexWrap: "wrap", gap: "3px 8px", marginBottom: 6 }}>
          <span style={{ color, fontSize: 11, fontWeight: 800, fontFamily: "-apple-system,sans-serif", flexShrink: 0 }}>{issues.length ? "Scan needs attention" : warnings.length ? "Scan ready with warnings" : "Scan ready"}</span>
          {modal.activeScanPresetName && <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", minWidth: 0, ...wrapTextStyle }}>{modal.activeScanPresetName}</span>}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 210px), 1fr))", gap: "8px 12px", alignItems: "start" }}>
          {items.map(([label, value]) => (
            <div
              key={label}
              style={{
                minWidth: 0,
                gridColumn: ["Target", "Engine"].includes(label) ? "span 2" : "auto",
              }}
            >
              <div style={{ color: th.textMuted, fontSize: 8, textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.04em", marginBottom: 1 }}>{label}</div>
              <div title={String(value)} style={{ color: th.textDim, fontSize: 10, lineHeight: 1.28, fontFamily: "'SF Mono',Menlo,monospace", ...wrapTextStyle }}>{value}</div>
            </div>
          ))}
        </div>
        {(issues.length > 0 || warnings.length > 0) && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 7 }}>
            {issues.map((item) => <span key={`i-${item}`} style={{ fontSize: 9, color: th.sev.critical, border: `1px solid ${th.sev.critical}44`, borderRadius: 4, padding: "1px 5px", background: th.sev.critical + "12" }}>{item}</span>)}
            {warnings.map((item) => <span key={`w-${item}`} style={{ fontSize: 9, color: th.sev.med, border: `1px solid ${th.sev.med}44`, borderRadius: 4, padding: "1px 5px", background: th.sev.med + "12" }}>{item}</span>)}
          </div>
        )}
      </div>
    );
  };

  const renderWizardProgress = () => {
    const activeIdx = WIZARD_STEPS.findIndex((step) => step.id === activeWizardStep);
    return (
      <div style={{ display: "grid", gridTemplateColumns: `repeat(${WIZARD_STEPS.length}, minmax(0, 1fr))`, gap: 6, marginBottom: 12 }}>
        {WIZARD_STEPS.map((step, idx) => {
          const active = step.id === activeWizardStep;
          const complete = idx < activeIdx;
          const color = active ? th.accent : complete ? th.sev.clean : th.textMuted;
          return (
            <div
              key={step.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                minWidth: 0,
                padding: "6px 7px",
                borderRadius: 8,
                border: `1px solid ${active ? th.accent + "66" : complete ? th.sev.clean + "44" : th.border + "33"}`,
                background: active ? `${th.accent}16` : complete ? th.sev.clean + "0d" : th.panelBg,
                color,
                fontFamily: "-apple-system,sans-serif",
              }}
            >
              <span style={{ width: 16, height: 16, borderRadius: 999, border: `1px solid ${color}88`, display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 800, flexShrink: 0 }}>
                {complete ? "\u2713" : idx + 1}
              </span>
              <span style={{ fontSize: 10, fontWeight: active ? 800 : 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{step.label}</span>
            </div>
          );
        })}
      </div>
    );
  };

  const renderScanHistoryList = () => {
    const history = modal.scanHistory || [];
    const retentionDays = Math.max(0, Number.parseInt(modal.scanHistoryRetentionDays ?? modal.scanHistorySettings?.retentionDays ?? 0, 10) || 0);
    const totalStoreBytes = history.reduce((sum, record) => sum + (Number(record.resultStoreSizeBytes || record.historyStorageSizeBytes || 0) || 0), 0);
    const managementPanel = (
      <div style={{ border: `1px solid ${th.border}66`, borderRadius: 8, background: `${th.panelBg}66`, padding: "9px 10px", marginBottom: 10 }}>
        {modal.scanHistoryNotice && (
          <div style={{ marginBottom: 8, padding: "5px 8px", borderRadius: 6, border: `1px solid ${th.sev.clean}44`, background: th.sev.clean + "12", color: th.sev.clean, fontSize: 10, fontFamily: "-apple-system,sans-serif" }}>
            {modal.scanHistoryNotice}
          </div>
        )}
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <div style={{ minWidth: 130 }}>
            <div style={{ color: th.textMuted, fontSize: 8, textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.04em" }}>Saved scans</div>
            <div style={{ color: th.text, fontSize: 12, fontWeight: 800 }}>{formatNumber(history.length)}</div>
          </div>
          <div style={{ minWidth: 150 }}>
            <div style={{ color: th.textMuted, fontSize: 8, textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.04em" }}>Result store size</div>
            <div style={{ color: th.text, fontSize: 12, fontWeight: 800 }}>{formatBytes(totalStoreBytes || 0)}</div>
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 6, marginLeft: "auto", color: th.textDim, fontSize: 10, fontFamily: "-apple-system,sans-serif" }}>
            Keep
            <input
              type="number"
              min="0"
              max="3650"
              value={retentionDays}
              onChange={(e) => setModal((p) => ({ ...p, scanHistoryRetentionDays: e.target.value }))}
              style={{ ...ms.ip, width: 62, padding: "4px 6px", fontSize: 10 }}
            />
            days
          </label>
          <button onClick={handleSaveScanHistoryRetention} disabled={modal.scanHistorySavingSettings} style={{ ...ms.bsm, opacity: modal.scanHistorySavingSettings ? 0.55 : 1 }}>
            {modal.scanHistorySavingSettings ? "Saving..." : "Save Retention"}
          </button>
          <button onClick={handlePruneScanHistory} disabled={retentionDays <= 0 || modal.scanHistoryLoading || history.length === 0} style={{ ...ms.bsm, opacity: retentionDays > 0 && history.length > 0 ? 1 : 0.45 }}>
            Delete Old Scans
          </button>
          <button onClick={handleClearScanHistory} disabled={modal.scanHistoryLoading || history.length === 0} style={{ ...ms.bsm, color: history.length ? th.sev.critical : th.textMuted, border: `1px solid ${history.length ? th.sev.critical + "44" : th.border}` }}>
            Clear All History
          </button>
        </div>
        <div style={{ color: th.textMuted, fontSize: 9, marginTop: 6, fontFamily: "-apple-system,sans-serif" }}>
          Set retention to 0 to keep scan history until manual deletion or the 200-record cap.
        </div>
      </div>
    );
    if (modal.scanHistoryLoading) {
      return (
        <Fragment>
          {managementPanel}
          <div style={{ padding: 20, textAlign: "center", color: th.textMuted, fontSize: 12 }}>Loading previous scans...</div>
        </Fragment>
      );
    }
    if (history.length === 0) {
      return (
        <Fragment>
          {managementPanel}
          <div style={{ padding: 20, textAlign: "center", color: th.textMuted, fontSize: 12, border: `1px dashed ${th.border}`, borderRadius: 8 }}>
            No previous scans yet. Completed EVTX Folder scans and Current Timeline Tab scans will appear here.
          </div>
        </Fragment>
      );
    }
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {managementPanel}
        {history.map((record) => {
          const isDeleting = modal.scanHistoryDeleting === record.id;
          const isExporting = modal.scanHistoryExporting === record.id;
          const engineColor = record.scanType === "evtx-dir" ? th.sev.custom : record.scanType === "kape-output" ? th.sev.info : th.accent;
          const detectionRows = record.eventRowCount || record.evtxTotalRows || record.totalMatches || 0;
          const stats = record.scanType === "evtx-dir"
            ? [
                [`${formatNumber(record.matchedRules || 0)}`, "rules matched"],
                [`${formatNumber(record.totalMatches || detectionRows || 0)}`, "detections"],
                [`${formatNumber(detectionRows)}`, "detection rows"],
                [`${formatNumber(record.evtxFiles || 0)}`, "EVTX files"],
                [formatBytes(record.evtxTotalBytes || 0), "bytes scanned"],
                [formatDuration(record.runtimeMs || record.stats?.runtimeMs || 0), "runtime"],
                [formatBytes(record.resultStoreSizeBytes || 0), "result store"],
              ]
            : record.scanType === "kape-output"
              ? [
                  [`${formatNumber(record.matchedRules || 0)}`, "rules matched"],
                  [`${formatNumber(record.totalMatches || detectionRows || 0)}`, "detections"],
                  [`${formatNumber(record.rowsScanned || 0)}`, "rows scanned"],
                  [`${formatNumber(record.stats?.sourceFiles || 0)}`, "EvtxECmd files"],
                  [formatBytes(record.stats?.sourceBytes || 0), "bytes scanned"],
                  [formatDuration(record.runtimeMs || record.stats?.runtimeMs || 0), "runtime"],
                  [formatBytes(record.resultStoreSizeBytes || 0), "result store"],
                ]
            : [
                [`${formatNumber(record.matchedRules || 0)}`, "rules matched"],
                [`${formatNumber(record.totalMatches || detectionRows || 0)}`, "detections"],
                [`${formatNumber(record.rowsScanned || 0)}`, "rows scanned"],
                [formatDuration(record.runtimeMs || record.stats?.runtimeMs || 0), "runtime"],
                [formatBytes(record.resultStoreSizeBytes || 0), "result store"],
              ];
          return (
            <div key={record.id} style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 12px", background: `${th.panelBg}55` }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 4, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 12, color: th.text, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>{record.scanType === "evtx-dir" ? "EVTX Folder Scan" : record.scanType === "kape-output" ? "EvtxECmd Output Scan" : "Current Timeline Tab Scan"}</span>
                    <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, background: `${engineColor}18`, color: engineColor, border: `1px solid ${engineColor}33` }}>{record.engine || "Sigma"}</span>
                    {record.hayabusaVersion && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{record.hayabusaVersion}</span>}
                    {record.hayabusaRuleCount > 0 && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{formatNumber(record.hayabusaRuleCount)} rules</span>}
                    <span style={{ fontSize: 9, color: th.textMuted, marginLeft: "auto" }}>{formatScanDate(record.createdAt)}</span>
                  </div>
                  <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 6 }} title={record.targetPath || record.targetName}>
                    {compactPath(record.targetPath || record.targetName)}
                  </div>
                  <div style={{ display: "flex", gap: 5, flexWrap: "wrap", fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                    {stats.map(([value, label]) => (
                      <span key={label} style={{ padding: "2px 6px", borderRadius: 6, border: `1px solid ${th.border}44`, background: `${th.panelBg}66` }}>
                        <strong style={{ color: th.text }}>{value}</strong> {label}
                      </span>
                    ))}
                    {record.ruleLastUpdate && <span>Rules updated {formatScanDate(record.ruleLastUpdate).split(",")[0]}</span>}
                    {!record.hasResultStore && <span style={{ color: th.sev.critical }}>result store missing</span>}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                  <button onClick={() => handleOpenHistoryRecord(record)} disabled={!record.hasResultStore || isDeleting || modal.scanHistoryLoading} style={{ ...ms.bsm, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, opacity: record.hasResultStore && !isDeleting ? 1 : 0.45 }}>
                    Open
                  </button>
                  <button onClick={() => handleExportHistoryPackage(record)} disabled={!record.hasResultStore || isDeleting || isExporting || modal.scanHistoryLoading} style={{ ...ms.bsm, opacity: record.hasResultStore && !isExporting ? 1 : 0.45 }}>
                    {isExporting ? "Exporting..." : "Export Package"}
                  </button>
                  <button onClick={() => handleDeleteHistoryRecord(record)} disabled={isDeleting || modal.scanHistoryLoading} style={{ ...ms.bsm, color: isDeleting ? th.textMuted : th.sev.critical, border: `1px solid ${isDeleting ? th.border : th.sev.critical + "44"}` }}>
                    {isDeleting ? "Deleting..." : "Delete"}
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  const modalContext = {
    modal,
    setModal,
    ct,
    th,
    tle,
    ms,
    phase,
    status,
    ruleInfo,
    levels,
    statuses,
    progress,
    results,
    expandedRule,
    downloading,
    availableRepos,
    selectedRepos,
    hasRules,
    scanMode,
    selectedLevelList,
    selectedStatusList,
    hayabusaMinSeverity,
    hayabusaLevelList,
    activeWizardStep,
    hasTargetReady,
    hasPresetReady,
    sigmaResultsRef,
    sevBadge,
    mitreBadge,
    checkbox,
    renderRuleDiffSummary,
    renderPreflightPanel,
    renderScanPresetPanel,
    renderScanReadinessPanel,
    renderWizardProgress,
    renderScanHistoryList,
    refreshScanHistory,
    handleShowScanHistory,
    handleOpenHistoryRecord,
    handleDeleteHistoryRecord,
    handleSaveDetectionSettings,
    handleApplyScanPreset,
    handleSaveScanPreset,
    handleDeleteScanPreset,
    handleAddRuleSuppression,
    handleUpdateRuleSuppression,
    handleRemoveRuleSuppression,
    handleSaveRuleSuppressions,
    handleDownload,
    handleLoadRuleInfo,
    handleImportCustom,
    handleOpenCustomDir,
    handleScan,
    handleSelectEvtxDir,
    handleSelectKapeOutput,
    handleSelectKapeOutputFolder,
    handleDownloadHayabusa,
    handleUpdateHayabusaRules,
    handleUpdateHayabusa,
    handleValidateDirectoryScan,
    handleScanDirectory,
    handleScanKapeOutput,
    handleCancelScan,
    handleCloseModal,
    handleRunMetrics,
    handleShowInTimeline,
    handleTagMatches,
    handleBookmarkMatches,
    handleMarkRuleReviewed,
    handleMarkRuleFalsePositive,
    handleOpenExactMatchesAsTab,
    handleExportCSV,
    handleExportJSON,
    handleOpenAsTab,
  };

  /* ── Layout ───────────────────────────────────────────────────────── */

  // Hard-lock against accidental dismissal: backdrop clicks are ignored
  // (closeOnOverlay=false) and Escape is ignored (closeOnEscape=false) so an
  // in-progress scan / results session isn't lost. Close only via the ✕ / footer.
  return (
    <Modal bare onClose={handleCloseModal} closeOnOverlay={false} closeOnEscape={false}>
    <SigmaModalContext.Provider value={modalContext}>
    <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: pos.x != null ? "flex-start" : "center", justifyContent: pos.x != null ? "flex-start" : "center" }}>
      <div data-modal-box onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: size.w, maxWidth: pos.x != null ? "none" : "94vw", height: size.h || undefined, maxHeight: pos.x != null ? "none" : "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)", position: pos.x != null ? "absolute" : "relative", left: pos.x != null ? pos.x : undefined, top: pos.y != null ? pos.y : undefined }}>
        {/* Header — draggable (double-click to reset position) */}
        <div onMouseDown={onDragStart} onDoubleClick={() => { setPos({ x: null, y: null }); setSize({ w: 660, h: null }); }} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "move", userSelect: "none" }}>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Sigma Scan</h3>
          <button onClick={handleCloseModal} aria-label="Close" style={{ background: "none", border: "none", color: th.textDim, cursor: "pointer", fontSize: 16, padding: 4 }}>&times;</button>
        </div>

        {/* Body */}
        <div style={{ padding: "16px 20px", overflow: "auto", flex: 1 }}>
          {error && <div style={{ padding: "6px 10px", background: `${th.danger}18`, border: `1px solid ${th.danger}44`, borderRadius: 6, color: th.danger, fontSize: 11, marginBottom: 12 }}>{error}</div>}
          {phase !== "config" && renderWizardProgress()}

          <SigmaConfigWizard />
          <SigmaScanProgress />
          <SigmaResultsView />
        </div>

        <SigmaModalFooter />
        {/* Resize handle — bottom-right corner */}
        <div onMouseDown={onResizeStart} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize" }}>
          <svg width="10" height="10" viewBox="0 0 10 10" style={{ position: "absolute", right: 3, bottom: 3, opacity: 0.3 }}>
            <path d="M9 1L1 9M9 4L4 9M9 7L7 9" stroke={th.textMuted} strokeWidth="1.2" strokeLinecap="round"/>
          </svg>
        </div>
      </div>
    </div>
    </SigmaModalContext.Provider>
    </Modal>
  );
}
