import { useCallback } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal, ErrorState } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";

/**
 * Convert a theme color (hex, rgb/rgba, or anything else) to an `rgba(r,g,b,a)`
 * string with the given alpha. Resilient to short hex (#abc), 8-char hex,
 * existing rgb/rgba, or unrecognised values — returns a safe gray fallback
 * instead of crashing. Replaces inline `.match(/../g).map(...)` calls that
 * crashed on null-match (issue caught during pre-release audit).
 */
function hexToRgba(color, alpha) {
  if (!color || typeof color !== "string") return `rgba(128,128,128,${alpha})`;
  if (color.startsWith("rgb")) {
    const inner = color.match(/rgba?\(([^)]+)\)/);
    if (!inner) return `rgba(128,128,128,${alpha})`;
    const parts = inner[1].split(",").map((s) => s.trim());
    const [r, g, b] = parts;
    if (r == null || g == null || b == null) return `rgba(128,128,128,${alpha})`;
    return `rgba(${r},${g},${b},${alpha})`;
  }
  if (color.startsWith("#")) {
    let hex = color.slice(1);
    if (hex.length === 3) hex = hex.split("").map((c) => c + c).join("");
    if (hex.length === 8) hex = hex.slice(0, 6); // strip alpha if present
    if (hex.length !== 6) return `rgba(128,128,128,${alpha})`;
    const pairs = hex.match(/../g);
    if (!pairs) return `rgba(128,128,128,${alpha})`;
    const [r, g, b] = pairs.map((h) => parseInt(h, 16));
    if ([r, g, b].some(Number.isNaN)) return `rgba(128,128,128,${alpha})`;
    return `rgba(${r},${g},${b},${alpha})`;
  }
  return `rgba(128,128,128,${alpha})`;
}

// Human-readable labels for the path-class tags on a window's Top Directories.
const PATH_CLASS_LABELS = { "servicing-churn": "OS churn", system: "Windows", "program-files": "Program Files", "user-profile": "User", "temp-cache": "Temp/Cache" };

export default function HeatmapModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const activeTab = useTabStore((s) => s.activeTab);
  const setTabs = useTabStore((s) => s.setTabs);

  const up = useCallback((key, value) => {
    setTabs((prev) => prev.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)));
  }, [activeTab, setTabs]);

  const ms = useModalChrome();

  if (!modal || modal.type !== "heatmap" || !ct) return null;

  const { data, loading } = modal;


  const viewMode = modal.hmView || "both";
  const getModeBuckets = (d, mode) => {
    if (!d) return [];
    if (mode === "created") return d.createdBuckets || [];
    if (mode === "modified") return d.modifiedBuckets || [];
    return d.combinedBuckets || [];
  };
  const getModeMatrixData = (d, mode) => {
    if (!d) return { matrix: Array.from({ length: 7 }, () => new Array(24).fill(0)), byMonth: {} };
    if (mode === "created") return { matrix: d.createdDowHourMatrix || d.dowHourMatrix || Array.from({ length: 7 }, () => new Array(24).fill(0)), byMonth: d.createdDowHourByMonth || d.dowHourByMonth || {} };
    if (mode === "modified") return { matrix: d.modifiedDowHourMatrix || Array.from({ length: 7 }, () => new Array(24).fill(0)), byMonth: d.modifiedDowHourByMonth || {} };
    return { matrix: d.combinedDowHourMatrix || d.createdDowHourMatrix || d.dowHourMatrix || Array.from({ length: 7 }, () => new Array(24).fill(0)), byMonth: d.combinedDowHourByMonth || {} };
  };
  const getSuspiciousWindowState = (d, mode, selId) => {
    const windows = (d?.suspiciousWindows || []).filter((w) => mode === "both" ? true : w.mode === mode);
    if (windows.length === 0) return { windows, selected: null, selectedIndex: -1 };
    const foundIdx = selId ? windows.findIndex((w) => `${w.mode}:${w.bucket}` === selId) : -1;
    const selectedIndex = foundIdx >= 0 ? foundIdx : 0;
    return { windows, selected: windows[selectedIndex], selectedIndex };
  };
  const applyHeatmapWindow = (win) => {
    if (!win?.column || !win?.from || !win?.to) return;
    const existing = { ...(ct.dateRangeFilters || {}) };
    delete existing["Created0x10"];
    delete existing["LastModified0x10"];
    up("dateRangeFilters", { ...existing, [win.column]: { from: win.from, to: win.to } });
    setModal(null);
  };
  const tagHeatmapWindow = async (win) => {
    if (!win?.column || !win?.from || !win?.to) return;
    const tag = win.mode === "modified" ? "Modified Burst" : "Created Burst";
    const tagColor = win.mode === "modified" ? "#6cb6ff" : (th.accent);
    const result = await tle.bulkTagByTimeRange(ct.id, win.column, [{ from: win.from, to: win.to, tag }]);
    const td = await tle.getAllTagData(ct.id);
    const nrt = {};
    for (const { rowid, tag: rowTag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(rowTag); }
    up("rowTags", nrt);
    up("tagColors", { ...(ct.tagColors || {}), [tag]: tagColor });
    setModal((p) => p ? { ...p, hmTagMsg: `Tagged ${(result?.taggedCount || 0).toLocaleString()} rows as "${tag}"` } : p);
    setTimeout(() => setModal((p) => p ? { ...p, hmTagMsg: null } : p), 3000);
  };

  const copyReport = () => {
    if (!data) return;
    const d = data;
    const dayNames = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    const matrixExport = getModeMatrixData(d, viewMode);
    const matrix = matrixExport.matrix || [];
    const modeLabel = viewMode === "both" ? "combined" : viewMode;
    const reportTopPeriods = getModeBuckets(d, viewMode).slice().sort((a, b) => b.count - a.count).slice(0, 10);
    const t19 = (s) => (s ? String(s).slice(0, 19) : "N/A");
    const v = d.verdict;
    const lines = [
      "=== File Activity Heatmap ===",
      "Timestamp basis: $STANDARD_INFORMATION ($SI / 0x10) Created + Modified, UTC.",
      "  $SI is user-settable and can be timestomped \u2014 corroborate flagged windows with the",
      "  Timestomping Detector ($SI vs $FN) and the USN journal ($J).",
      "",
    ];
    if (v) {
      lines.push("--- Verdict ---",
        `Severity: ${v.severity.toUpperCase()} (score ${v.severityScore}/100)   Confidence: ${v.confidence}`,
        v.headline, "", v.narrative, "");
      if (v.factors && v.factors.length) {
        lines.push("Factors:");
        v.factors.forEach((f) => lines.push(`  - ${f.label}: ${f.detail}`));
        lines.push("");
      }
      if (v.mitre && v.mitre.length) {
        lines.push("MITRE ATT&CK (candidate techniques):");
        v.mitre.forEach((m) => lines.push(`  - ${m.technique} ${m.name} [${m.confidence}] \u2014 ${m.evidence}`));
        lines.push("");
      }
    }
    lines.push(
      `Total Creations: ${(d.totalCreated || 0).toLocaleString()}`,
      `Total Modifications: ${(d.totalModified || 0).toLocaleString()}`,
      `Time Range (UTC): ${t19(d.timeRange?.earliest)} \u2014 ${t19(d.timeRange?.latest)}`,
      d.timeRange?.focusEarliest && d.timeRange?.focusLatest ? `Focus Range (UTC): ${t19(d.timeRange.focusEarliest)} \u2014 ${t19(d.timeRange.focusLatest)}` : "",
      `Bucket Size: ${d.bucketSize || "hourly"}`, "",
    );
    if (d.peakCreated) lines.push(`Peak Created: ${d.peakCreated.bucket} (${d.peakCreated.count.toLocaleString()} files)`);
    if (d.peakModified) lines.push(`Peak Modified: ${d.peakModified.bucket} (${d.peakModified.count.toLocaleString()} files)`);
    if ((d.suspiciousWindows || []).length > 0) {
      lines.push("", "Suspicious Windows:");
      d.suspiciousWindows.slice(0, 10).forEach((w, i) => {
        lines.push(`  ${i + 1}. ${w.bucket} [${w.mode}] score=${w.score} count=${w.count.toLocaleString()} ${w.weekend ? "weekend" : ""} ${w.offHours ? "off-hours" : ""}`.trim());
        const sb = w.scoreBreakdown;
        if (sb) {
          const b = [`baseline ${sb.baselineDamped}`];
          if (sb.riskyBoost > 0) b.push(`+ risky ${sb.riskyBoost}`);
          if (sb.deletedBoost > 0) b.push(`+ freed ${sb.deletedBoost}`);
          if (sb.siFnBoost > 0) b.push(`+ SI<FN ${sb.siFnBoost}`);
          lines.push(`       score ${sb.total} = ${b.join(" ")} (admitted: ${sb.admittedBy})`);
        }
        if (w.timestompSuspected) lines.push(`       possible timestomping: ${(w.uSecZerosCount || 0).toLocaleString()} zeroed-subsec, ${(w.siFnCount || 0).toLocaleString()} SI<FN`);
        if (w.minuteProfile) lines.push(`       peak ${w.minuteProfile.peakPerMin.toLocaleString()} files/min @ ${w.minuteProfile.peakMinute} ($SI-derived), active ${w.minuteProfile.activeMinutes} min`);
      });
    }
    if (reportTopPeriods.length > 0) {
      lines.push("", `Top ${modeLabel} Activity Periods:`);
      reportTopPeriods.forEach((p, i) => lines.push(`  ${i + 1}. ${p.bucket} (${p.count.toLocaleString()})`));
    }
    lines.push("", `Day-of-Week \u00D7 Hour Activity (${modeLabel}, UTC):`);
    if (matrix.length > 0) {
      lines.push("Hour:     " + Array.from({ length: 24 }, (_, h) => String(h).padStart(2, " ")).join(" "));
      matrix.forEach((row, dow) => {
        lines.push(dayNames[dow].padEnd(10) + row.map((c) => String(c).padStart(2, " ")).join(" "));
      });
    }
    navigator.clipboard?.writeText(lines.join("\n"));
  };

  const footerSuspiciousState = getSuspiciousWindowState(data, viewMode, modal.hmSelWin);
  const footerSelectedWindow = footerSuspiciousState.selected;

  return (
    <DraggableResizableModal defaultWidth={920} minWidth={420} minHeight={280} onClose={() => setModal(null)}>
      {({ startDrag, width: rw }) => (<>
        {/* Header */}
        <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, border: `1px solid ${th.accent}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round"><rect x="3" y="3" width="7" height="7" rx="1" fill={th.accent + "44"}/><rect x="14" y="3" width="7" height="7" rx="1" fill={th.accent + "22"}/><rect x="3" y="14" width="7" height="7" rx="1" fill={th.accent + "66"}/><rect x="14" y="14" width="7" height="7" rx="1" fill={th.accent + "88"}/></svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>File Activity Heatmap</h3>
              <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Visualize file creation and modification patterns over time</p>
            </div>
          </div>
          <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, fontSize: 18, cursor: "pointer", padding: "4px 8px", lineHeight: 1 }}>{"\u2715"}</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
          {loading && (() => {
            const hp = modal.hmProgress;
            const pct = hp?.pct ?? 0;
            const detail = hp?.detail || "Initializing analysis...";
            return (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <div style={{ width: 20, height: 20, border: `2px solid ${th.accent}`, borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, width: 300 }}>
                  <span style={{ color: th.textDim, fontSize: 13, fontFamily: "-apple-system, sans-serif" }}>{detail}</span>
                  <div style={{ width: "100%", height: 6, borderRadius: 3, background: th.border + "44", overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 3, background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`, width: `${pct}%`, transition: "width var(--m-slow) ease" }} />
                  </div>
                  <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>{pct}%</span>
                </div>
              </div>
            );
          })()}

          {!loading && modal.error && (
            <ErrorState message={modal.error} />
          )}

          {!loading && !modal.error && data && isIpcError(data) && (
            <div style={{ textAlign: "center", padding: 40, color: th.danger, fontSize: 13 }}>{ipcErrorMessage(data)}</div>
          )}

          {!loading && !modal.error && data && !isIpcError(data) && (() => {
            const d = data;
            const showCreated = viewMode === "both" || viewMode === "created";
            const showModified = viewMode === "both" || viewMode === "modified";
            const rangeMode = modal.hmRangeMode || ((d.timeRange?.focusEarliest && d.timeRange?.focusLatest) ? "focus" : "full");
            const bucketStamp = (bucket) => d.bucketSize === "daily" ? `${bucket} 00:00:00` : `${bucket}:00:00`;
            const bucketRange = (bucket) => d.bucketSize === "daily" ? { from: `${bucket} 00:00:00`, to: `${bucket} 23:59:59` } : { from: `${bucket}:00:00`, to: `${bucket}:59:59` };
            const bucketInRange = (bucket, from, to) => {
              const ts = bucketStamp(bucket);
              if (from && ts < from) return false;
              if (to && ts > to) return false;
              return true;
            };

            const allBuckets = new Map();
            if (showCreated) (d.createdBuckets || []).forEach((b) => { const e = allBuckets.get(b.bucket) || { bucket: b.bucket, created: 0, modified: 0 }; e.created = b.count; allBuckets.set(b.bucket, e); });
            if (showModified) (d.modifiedBuckets || []).forEach((b) => { const e = allBuckets.get(b.bucket) || { bucket: b.bucket, created: 0, modified: 0 }; e.modified = b.count; allBuckets.set(b.bucket, e); });
            const rawChartData = Array.from(allBuckets.values()).sort((a, b) => a.bucket.localeCompare(b.bucket));
            let chartData = rangeMode === "focus" && d.timeRange?.focusEarliest && d.timeRange?.focusLatest
              ? rawChartData.filter((b) => bucketInRange(b.bucket, d.timeRange.focusEarliest, d.timeRange.focusLatest))
              : rawChartData;
            if (chartData.length === 0) chartData = rawChartData;

            if (chartData.length > 300) {
              const factor = Math.ceil(chartData.length / 300);
              const downsampled = [];
              for (let i = 0; i < chartData.length; i += factor) {
                const chunk = chartData.slice(i, i + factor);
                downsampled.push({ bucket: chunk[0].bucket, created: chunk.reduce((s, c) => s + c.created, 0), modified: chunk.reduce((s, c) => s + c.modified, 0) });
              }
              chartData = downsampled;
            }

            const maxCount = Math.max(...chartData.map((b) => Math.max(b.created, b.modified)), 1);
            const chartW = Math.max(rw - 80, 600);
            const chartH = 140;
            const barW = Math.max(1, Math.min(6, (chartW - 20) / chartData.length - 1));

            const hmMonth = modal.hmMonth || "all";
            const matrixData = getModeMatrixData(d, viewMode);
            const allMatrix = matrixData.matrix || Array.from({ length: 7 }, () => new Array(24).fill(0));
            const monthMap = matrixData.byMonth || {};
            const availableMonths = Object.keys(monthMap).sort();
            const matrix = hmMonth === "all" ? allMatrix : (monthMap[hmMonth] || Array.from({ length: 7 }, () => new Array(24).fill(0)));
            const maxCell = Math.max(...matrix.flat(), 1);
            const cellCounts = matrix.flat().filter((c) => c > 0);
            const cellSorted = [...cellCounts].sort((a, b) => a - b);
            const cellMed = cellSorted.length > 0 ? (cellSorted.length % 2 === 0 ? (cellSorted[cellSorted.length / 2 - 1] + cellSorted[cellSorted.length / 2]) / 2 : cellSorted[Math.floor(cellSorted.length / 2)]) : 0;
            const cellMad = (() => { const devs = cellCounts.map((v) => Math.abs(v - cellMed)).sort((a, b) => a - b); return devs.length > 0 ? (devs.length % 2 === 0 ? (devs[devs.length / 2 - 1] + devs[devs.length / 2]) / 2 : devs[Math.floor(devs.length / 2)]) : 1; })() || 1;
            const cellZThreshold = 1.25;
            const dayLabels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

            const topPeriods = getModeBuckets(d, viewMode).slice().sort((a, b) => b.count - a.count).slice(0, 10);
            const suspiciousState = getSuspiciousWindowState(d, viewMode, modal.hmSelWin);
            const suspiciousWindows = suspiciousState.windows;
            const selectedWindow = suspiciousState.selected;
            const modeTitle = viewMode === "both" ? "Combined" : viewMode === "modified" ? "Modification" : "Creation";
            // Bridge the matrix (recurring dow×hour pattern) to the ranked list: in hourly mode, map the
            // selected window to its dow/hour cell so the analyst sees where the ranked burst falls.
            const isDaily = d.bucketSize === "daily";
            const selFrom = selectedWindow?.from || "";
            // Only cross-highlight when the matrix is showing a month the selected window belongs to
            // (the matrix can be filtered by month), and only in hourly mode (no hour in daily windows).
            const selMonthOk = hmMonth === "all" || selFrom.slice(0, 7) === hmMonth;
            const selWinHour = (!isDaily && selMonthOk && selFrom.length >= 13) ? parseInt(selFrom.slice(11, 13), 10) : null;
            const selWinDow = (selWinHour !== null && Number.isFinite(selWinHour) && selFrom.length >= 10)
              ? (() => { const dt = new Date(selFrom.slice(0, 10) + "T00:00:00Z"); return Number.isFinite(dt.getTime()) ? dt.getUTCDay() : null; })()
              : null;
            const describeWindow = (win) => {
              if (!win) return [];
              const notes = [];
              if (win.weekend) notes.push("weekend");
              if (win.offHours) notes.push("off-hours");
              if ((win.riskyExtensionCount || 0) > 0) notes.push(`${win.riskyExtensionCount.toLocaleString()} risky files`);
              if ((win.deletedCount || 0) > 0) notes.push(`${win.deletedCount.toLocaleString()} freed records`);
              return notes;
            };
            const windowDetails = describeWindow(selectedWindow);

            return (<>
              {/* Incident verdict — severity reflects impact; confidence is gated on forgery-resistant
                  corroboration so a $SI-only / timestomped burst is never presented as authoritative. */}
              {d.verdict && (() => {
                const v = d.verdict;
                const sevColor = (v.severity === "critical" || v.severity === "high") ? th.danger : v.severity === "medium" ? th.warning : v.severity === "low" ? th.accent : th.textMuted;
                const confColor = v.confidence === "corroborated" ? (th.success || "#3fb950") : v.confidence === "low" ? th.danger : v.confidence === "weak" ? th.warning : th.textMuted;
                return (
                  <div style={{ marginBottom: 14, padding: "12px 14px", borderRadius: 10, background: `${sevColor}10`, border: `1px solid ${sevColor}33` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                      <span style={{ padding: "2px 9px", borderRadius: 999, fontSize: 10, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.06em", color: sevColor, background: `${sevColor}1e`, border: `1px solid ${sevColor}55` }}>{v.severity}</span>
                      <span title="How far the $SI-derived conclusion can be trusted — 'corroborated' requires forgery-resistant USN/EVTX backing." style={{ padding: "2px 9px", borderRadius: 999, fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: confColor, background: `${confColor}18`, border: `1px solid ${confColor}44`, cursor: "help" }}>confidence: {v.confidence}</span>
                      <span title="Activity is bucketed on $STANDARD_INFORMATION ($SI / 0x10) timestamps, which are user-settable and can be timestomped. Corroborate with $FN (Timestomping Detector) and the USN journal." style={{ padding: "2px 9px", borderRadius: 999, fontSize: 9, fontWeight: 600, letterSpacing: "0.03em", color: th.textMuted, background: `${th.border}22`, border: `1px solid ${th.border}33`, cursor: "help" }}>$SI-derived</span>
                      {v.severityScore > 0 && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>score {v.severityScore}/100</span>}
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", lineHeight: 1.4, marginBottom: 6 }}>{v.headline}</div>
                    <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>{v.narrative}</div>
                    {(v.factors?.length ?? 0) > 0 && (
                      <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {v.factors.map((f, i) => (
                          <span key={i} title={f.detail} style={{ padding: "3px 8px", borderRadius: 8, fontSize: 9, fontWeight: 600, fontFamily: "-apple-system, sans-serif", color: f.severity === "high" ? th.danger : f.severity === "medium" ? th.warning : th.textDim, background: `${th.border}22`, border: `1px solid ${th.border}33`, cursor: "help" }}>{f.label}</span>
                        ))}
                      </div>
                    )}
                    {(v.mitre?.length ?? 0) > 0 && (
                      <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
                        <span style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>MITRE</span>
                        {v.mitre.map((m, i) => (
                          <span key={i} title={`${m.name} — ${m.evidence} (${m.confidence})`} style={{ padding: "3px 8px", borderRadius: 8, fontSize: 9, fontWeight: 700, fontFamily: "'SF Mono',Menlo,monospace", color: th.accent, background: `${th.accent}14`, border: `1px solid ${th.accent}33`, cursor: "help" }}>{m.technique}</span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Summary cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>File Creations</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(d.totalCreated || 0).toLocaleString()}</div>
                  {d.peakCreated && <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif" }}>Peak: {d.peakCreated.bucket} ({d.peakCreated.count.toLocaleString()})</div>}
                </div>
                <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: "#6cb6ff", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>File Modifications</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(d.totalModified || 0).toLocaleString()}</div>
                  {d.peakModified && <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif" }}>Peak: {d.peakModified.bucket} ({d.peakModified.count.toLocaleString()})</div>}
                </div>
                <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: th.textDim, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Full Span</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{(d.timeRange?.earliest || "").slice(0, 10)}</div>
                  <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2 }}>to {(d.timeRange?.latest || "").slice(0, 10)} ({d.bucketSize} buckets)</div>
                </div>
                <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                  <div style={{ fontSize: 10, color: th.warning, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Investigation Focus</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{(d.timeRange?.focusEarliest || d.timeRange?.earliest || "").slice(0, 10)}</div>
                  <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2 }}>to {(d.timeRange?.focusLatest || d.timeRange?.latest || "").slice(0, 10)} ({(d.suspiciousWindows || []).length} suspicious windows)</div>
                </div>
              </div>

              {/* Activity Timeline Chart */}
              <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Activity Timeline</span>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    {(d.timeRange?.focusEarliest && d.timeRange?.focusLatest) && (
                      <div style={{ display: "flex", gap: 4 }}>
                        {["focus", "full"].map((m) => (
                          <button key={m} onClick={() => setModal((p) => p ? { ...p, hmRangeMode: m } : p)} style={{ padding: "3px 9px", fontSize: 10, fontWeight: 600, borderRadius: 6, border: `1px solid ${rangeMode === m ? (th.warning) : th.border}44`, background: rangeMode === m ? `${th.warning}22` : "transparent", color: rangeMode === m ? (th.warning) : th.textMuted, cursor: "pointer", fontFamily: "-apple-system, sans-serif", textTransform: "capitalize" }}>{m}</button>
                        ))}
                      </div>
                    )}
                    <div style={{ display: "flex", gap: 4 }}>
                    {["created", "modified", "both"].map((m) => (
                      <button key={m} onClick={() => setModal((p) => p ? { ...p, hmView: m } : p)} style={{ padding: "3px 10px", fontSize: 10, fontWeight: 600, borderRadius: 6, border: `1px solid ${viewMode === m ? th.accent : th.border}44`, background: viewMode === m ? `${th.accent}22` : "transparent", color: viewMode === m ? th.accent : th.textMuted, cursor: "pointer", fontFamily: "-apple-system, sans-serif", textTransform: "capitalize" }}>{m}</button>
                    ))}
                    </div>
                  </div>
                </div>
                {(() => {
                  if (chartData.length === 0) return <div style={{ textAlign: "center", padding: 20, color: th.textMuted, fontSize: 12 }}>No activity data</div>;
                  const xAxisH = 24;
                  const plotH = chartH - 10;
                  const plotW = chartW - 10;
                  const maxLbls = Math.max(2, Math.min(12, Math.floor(chartW / 80)));
                  const labelStep = Math.max(1, Math.ceil(chartData.length / maxLbls));
                  const axisLabels = [];
                  for (let i = 0; i < chartData.length; i += labelStep) axisLabels.push({ idx: i, label: chartData[i].bucket });
                  return (
                    <svg width={chartW} height={chartH + xAxisH} style={{ display: "block" }}>
                      <defs>
                        <linearGradient id="hm-cr" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={th.accent} stopOpacity="0.9"/><stop offset="100%" stopColor={th.accent} stopOpacity="0.3"/></linearGradient>
                        <linearGradient id="hm-md" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#6cb6ff" stopOpacity="0.7"/><stop offset="100%" stopColor="#6cb6ff" stopOpacity="0.2"/></linearGradient>
                      </defs>
                      {chartData.map((b, i) => {
                        const x = (i / chartData.length) * plotW + 5;
                        const createdH = maxCount > 0 ? (b.created / maxCount) * plotH : 0;
                        const modifiedH = maxCount > 0 ? (b.modified / maxCount) * plotH : 0;
                        const bucketMatches = suspiciousWindows.filter((w) => w.bucket === b.bucket);
                        const hasMatch = bucketMatches.length > 0;
                        const topMatch = bucketMatches.length > 0 ? bucketMatches.reduce((a, c) => c.score > a.score ? c : a, bucketMatches[0]) : null;
                        return (
                          <g key={i} onClick={hasMatch ? (() => {
                            setModal((p) => {
                              if (!p) return p;
                              const curId = p.hmSelWin;
                              const curIdx = bucketMatches.findIndex((w) => `${w.mode}:${w.bucket}` === curId);
                              const next = curIdx >= 0 ? bucketMatches[(curIdx + 1) % bucketMatches.length] : topMatch;
                              return { ...p, hmSelWin: `${next.mode}:${next.bucket}` };
                            });
                          }) : undefined} style={{ cursor: hasMatch ? "pointer" : "default" }}>
                            {showModified && modifiedH > 0 && <rect x={x} y={chartH - modifiedH - 2} width={Math.max(barW, 1)} height={modifiedH} fill="url(#hm-md)" rx="1"><title>{b.bucket} (UTC) — Modified: {b.modified.toLocaleString()}</title></rect>}
                            {showCreated && createdH > 0 && <rect x={showModified ? x + barW + 1 : x} y={chartH - createdH - 2} width={Math.max(barW, 1)} height={createdH} fill="url(#hm-cr)" rx="1"><title>{b.bucket} (UTC) — Created: {b.created.toLocaleString()}</title></rect>}
                            {hasMatch && <rect x={x - 1} y={2} width={showCreated && showModified ? Math.max(barW * 2 + 2, 4) : Math.max(barW + 2, 4)} height={chartH - 1} fill="none" stroke={th.warning} strokeOpacity="0.35" strokeDasharray="2,2" rx="2" />}
                          </g>
                        );
                      })}
                      <line x1="5" y1={chartH} x2={chartW - 5} y2={chartH} stroke={th.border + "44"} strokeWidth="1" />
                      {axisLabels.map((l) => {
                        const x = (l.idx / chartData.length) * plotW + 5;
                        return (
                          <g key={l.idx}>
                            <line x1={x} y1={chartH} x2={x} y2={chartH + 4} stroke={th.border + "66"} strokeWidth="1" />
                            <text x={x} y={chartH + 15} fill={th.textMuted} fontSize="8" fontFamily="'SF Mono',Menlo,monospace" textAnchor="middle">{l.label}</text>
                          </g>
                        );
                      })}
                      <text x={chartW - 5} y={chartH + 15} fill={th.textMuted + "88"} fontSize="7" fontFamily="-apple-system,sans-serif" textAnchor="end">UTC</text>
                    </svg>
                  );
                })()}
              </div>

              {/* Day-of-Week x Hour Heatmap */}
              <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Day-of-Week x Hour {viewMode === "both" ? "Combined" : viewMode === "modified" ? "Modification" : "Creation"} Activity <span style={{ fontSize: 9, fontWeight: 500, color: th.textMuted }}>(UTC)</span></span>
                  {availableMonths.length > 1 && (
                    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <button onClick={() => setModal((p) => p ? { ...p, hmMonth: "all" } : p)} style={{ padding: "3px 8px", fontSize: 9, fontWeight: 600, borderRadius: 6, border: `1px solid ${hmMonth === "all" ? th.accent : th.border}44`, background: hmMonth === "all" ? `${th.accent}22` : "transparent", color: hmMonth === "all" ? th.accent : th.textMuted, cursor: "pointer", fontFamily: "'SF Mono',Menlo,monospace" }}>All</button>
                      <select value={hmMonth === "all" ? "" : hmMonth} onChange={(e) => setModal((p) => p ? { ...p, hmMonth: e.target.value || "all" } : p)}
                        style={{ padding: "3px 22px 3px 6px", fontSize: 9, fontWeight: 600, borderRadius: 6, border: `1px solid ${hmMonth !== "all" ? th.accent : th.border}44`, background: hmMonth !== "all" ? `${th.accent}22` : "transparent", color: hmMonth !== "all" ? th.accent : th.textMuted, cursor: "pointer", fontFamily: "'SF Mono',Menlo,monospace", appearance: "none", backgroundImage: `url("data:image/svg+xml,%3Csvg width='8' height='5' viewBox='0 0 8 5' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1l3 3 3-3' stroke='%23888' stroke-width='1.2' stroke-linecap='round'/%3E%3C/svg%3E")`, backgroundRepeat: "no-repeat", backgroundPosition: "right 6px center" }}>
                        <option value="">Select month</option>
                        {availableMonths.map((m) => <option key={m} value={m}>{m}</option>)}
                      </select>
                    </div>
                  )}
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <div style={{ display: "flex", gap: 2, paddingLeft: 40 }}>
                    {Array.from({ length: 24 }, (_, h) => (
                      <div key={h} style={{ width: 28, textAlign: "center", fontSize: 8, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{String(h).padStart(2, "0")}</div>
                    ))}
                  </div>
                  {matrix.map((row, dow) => (
                    <div key={dow} style={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <div style={{ width: 36, fontSize: 10, color: th.textDim, fontWeight: 500, textAlign: "right", paddingRight: 4, fontFamily: "-apple-system, sans-serif" }}>{dayLabels[dow]}</div>
                      {row.map((count, hour) => {
                        const intensity = maxCell > 0 ? count / maxCell : 0;
                        const isWeekend = dow === 0 || dow === 6;
                        const isOffHours = hour < 6 || hour >= 22;
                        const cellZ = count > 0 ? (count - cellMed) / (1.4826 * cellMad) : 0;
                        const suspicious = (isWeekend || isOffHours) && cellZ >= cellZThreshold;
                        const isSelectedCell = selWinDow === dow && selWinHour === hour;
                        return (
                          <div key={hour} title={`${dayLabels[dow]} ${String(hour).padStart(2, "0")}:00 \u2014 ${count.toLocaleString()} files${isSelectedCell ? " \u00b7 selected window's day/hour slot (this cell aggregates all matching days)" : ""}`} style={{ width: 28, height: 22, borderRadius: 3, background: count === 0 ? `${th.border}22` : suspicious ? hexToRgba(th.danger, Math.max(0.15, intensity * 0.9)) : hexToRgba(th.accent, Math.max(0.08, intensity * 0.85)), display: "flex", alignItems: "center", justifyContent: "center", fontSize: 8, color: intensity > 0.4 ? "#fff" : "transparent", fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace", transition: "background var(--m-base)", cursor: "default", outline: isSelectedCell ? `2px solid ${th.accent}` : "none", outlineOffset: isSelectedCell ? "1px" : 0, boxShadow: isSelectedCell ? `0 0 0 1px ${th.modalBg}` : "none" }}>
                            {count > 0 && intensity > 0.3 ? (count > 999 ? `${(count/1000).toFixed(0)}k` : count) : ""}
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 8, display: "flex", gap: 16, flexWrap: "wrap", fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 4 }}><div style={{ width: 10, height: 10, borderRadius: 2, background: `${th.accent}66` }} /> Normal activity</span>
                  <span style={{ display: "flex", alignItems: "center", gap: 4 }}><div style={{ width: 10, height: 10, borderRadius: 2, background: `${th.danger}66` }} /> Weekend / off-hours concentration</span>
                  {selWinDow !== null && <span style={{ display: "flex", alignItems: "center", gap: 4 }}><div style={{ width: 10, height: 10, borderRadius: 2, background: "transparent", outline: `2px solid ${th.accent}`, outlineOffset: -1 }} /> Selected window&rsquo;s slot</span>}
                </div>
                <div style={{ marginTop: 6, fontSize: 9, color: th.textMuted, lineHeight: 1.45, fontFamily: "-apple-system, sans-serif" }}>
                  This matrix shows the <strong style={{ color: th.textDim }}>recurring</strong> day-of-week × hour-of-day pattern (a cell aggregates every matching hour across the range). Red = a statistical outlier <em>among matrix cells</em> — a coarse heat indicator, <strong style={{ color: th.textDim }}>distinct</strong> from the per-time-bucket “Suspicious Windows” ranking below.
                  {isDaily && <> Timeline &amp; suspicious windows are <strong style={{ color: th.textDim }}>day-resolution</strong> (span &gt; 90 days), so off-hours timing is not scored for windows even though this matrix keeps hour resolution.</>}
                </div>
              </div>

              {/* Suspicious Windows */}
              {suspiciousWindows.length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
                    <div>
                      <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Suspicious Windows</div>
                      <div style={{ marginTop: 3, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Ranked by statistical burst score, off-hours/weekend timing, risky extension ratio, and deletion rate.</div>
                    </div>
                    <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>{suspiciousWindows.length} ranked {viewMode === "both" ? "windows" : `${viewMode} windows`}</div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: rw > 980 ? "minmax(0, 1.15fr) minmax(300px, 0.85fr)" : "1fr", gap: 12 }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 280, overflow: "auto", paddingRight: 2 }}>
                      {suspiciousWindows.map((win, idx) => {
                        const active = idx === suspiciousState.selectedIndex;
                        const notes = describeWindow(win);
                        return (
                          <button key={`${win.mode}-${win.bucket}-${idx}`} onClick={() => setModal((p) => p ? { ...p, hmSelWin: `${win.mode}:${win.bucket}` } : p)}
                            style={{ width: "100%", textAlign: "left", padding: "10px 12px", borderRadius: 10, border: `1px solid ${active ? (th.warning) : `${th.border}33`}`, background: active ? `${th.warning}14` : `${th.border}10`, cursor: "pointer", transition: "all var(--m-fast)" }}>
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                                <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: win.mode === "modified" ? "#6cb6ff" : th.accent, fontFamily: "-apple-system, sans-serif" }}>{win.mode}</span>
                                <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{win.bucket}</span>
                              </div>
                              <span style={{ fontSize: 10, fontWeight: 700, color: th.warning, fontFamily: "'SF Mono',Menlo,monospace" }}>score {win.score.toFixed(2)}</span>
                            </div>
                            <div style={{ marginTop: 5, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                              <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{win.count.toLocaleString()} files</span>
                              <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{notes.join(" \u2022 ") || "volume spike"}</span>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                    <div style={{ padding: "12px", borderRadius: 10, border: `1px solid ${th.border}33`, background: `${th.border}12`, minHeight: 220 }}>
                      {selectedWindow ? (<>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                          <div>
                            <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: selectedWindow.mode === "modified" ? "#6cb6ff" : th.accent, fontFamily: "-apple-system, sans-serif" }}>{selectedWindow.mode} window</div>
                            <div style={{ marginTop: 3, fontSize: 13, fontWeight: 700, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{selectedWindow.bucket}</div>
                          </div>
                          <div style={{ textAlign: "right" }}>
                            <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Suspicion score</div>
                            <div style={{ fontSize: 18, fontWeight: 700, color: th.warning, fontFamily: "'SF Mono',Menlo,monospace" }}>{selectedWindow.score.toFixed(2)}</div>
                          </div>
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginBottom: 10 }}>
                          <div style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22` }}>
                            <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Window</div>
                            <div style={{ fontSize: 10, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{selectedWindow.from?.slice(0, 19)} to {selectedWindow.to?.slice(0, 19)}</div>
                          </div>
                          <div style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22` }}>
                            <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{selectedWindow.mode === "modified" ? "Modification Count" : "Creation Count"}</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{selectedWindow.count.toLocaleString()}</div>
                          </div>
                          <div style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22` }}>
                            <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Risky Extensions</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(selectedWindow.riskyExtensionCount || 0).toLocaleString()}</div>
                          </div>
                          <div title={"MFT records currently marked not-in-use (InUse='False') whose $SI timestamp falls in this window — NOT confirmed deletions during the window. The actual deletion time is recorded in the USN journal ($J), not the MFT."} style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22`, cursor: "help" }}>
                            <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Freed Records {"ⓘ"}</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{(selectedWindow.deletedCount || 0).toLocaleString()}</div>
                          </div>
                        </div>
                        {/* Tier 7: minute-level burst profile + transparent score decomposition */}
                        {(() => {
                          const sb = selectedWindow.scoreBreakdown;
                          const mp = selectedWindow.minuteProfile;
                          if (!sb && !mp) return null;
                          const forged = !!selectedWindow.timestompSuspected;
                          // Additive top-line that closes exactly: total = post-churn baseline + boosts.
                          const parts = [`${sb ? sb.baselineDamped : 0}`];
                          if (sb && sb.riskyBoost > 0) parts.push(`+ risky ${sb.riskyBoost}`);
                          if (sb && sb.deletedBoost > 0) parts.push(`+ freed ${sb.deletedBoost}`);
                          if (sb && sb.siFnBoost > 0) parts.push(`+ SI<FN ${sb.siFnBoost}`);
                          const baseParts = sb ? [`robust-Z ${sb.zContribution}`] : [];
                          if (sb && sb.weekendBonus) baseParts.push(`+ weekend ${sb.weekendBonus}`);
                          if (sb && sb.offHoursBonus) baseParts.push(`+ off-hours ${sb.offHoursBonus}`);
                          if (sb && sb.volumeBonus) baseParts.push(`+ volume ${sb.volumeBonus}`);
                          return (
                            <div style={{ marginBottom: 10, padding: "8px 11px", borderRadius: 8, background: `${th.border}10`, border: `1px solid ${th.border}22` }}>
                              {mp && (
                                <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", marginBottom: sb ? 7 : 0 }}>
                                  <span style={{ color: forged ? th.textMuted : th.accent, fontWeight: 700 }}>{mp.peakPerMin.toLocaleString()}</span> files/min peak at <span style={{ fontFamily: "'SF Mono',Menlo,monospace" }}>{mp.peakMinute}</span>{isDaily ? " (busiest minute within the day)" : " (minute bin)"} · active across {mp.activeMinutes.toLocaleString()} min{forged ? " — $SI-derived; these timings may be forged" : ""}
                                </div>
                              )}
                              {sb && (<>
                                <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Score breakdown</div>
                                <div style={{ fontSize: 10, color: th.text, fontFamily: "'SF Mono',Menlo,monospace", lineHeight: 1.5 }}>{sb.total} = {parts.join(" ")}</div>
                                <div style={{ marginTop: 3, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>
                                  baseline {sb.baseline} = {baseParts.join(" ")}{sb.churnFactor < 1 ? ` · × churn ${sb.churnFactor} → ${sb.baselineDamped}` : ""}. Admitted: {sb.admittedBy === "statistical-outlier" ? `statistical outlier (robust-Z ≥ ${sb.admissionThreshold})` : "high-volume bucket"}.
                                </div>
                              </>)}
                            </div>
                          );
                        })()}
                        {/* Tier 5: possible timestomping — elevated $SI<$FN density means the timestamps placing activity here may be forged */}
                        {selectedWindow.timestompSuspected && (
                          <div style={{ marginBottom: 10, padding: "8px 11px", borderRadius: 8, background: `${th.danger}14`, border: `1px solid ${th.danger}44`, display: "flex", gap: 8, alignItems: "flex-start" }}>
                            <span style={{ color: th.danger, fontSize: 12, lineHeight: 1.3, flexShrink: 0 }}>{"⚠"}</span>
                            <span style={{ fontSize: 10, lineHeight: 1.45, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>
                              <strong style={{ color: th.danger }}>Possible timestomping in this window.</strong> {(selectedWindow.uSecZerosCount || 0).toLocaleString()} file{selectedWindow.uSecZerosCount === 1 ? "" : "s"} have zeroed sub-second $SI timestamps (a hallmark of timestomping tools){(selectedWindow.siFnCount || 0) > 0 ? `, and ${selectedWindow.siFnCount.toLocaleString()} have $SI earlier than $FN (SI<FN)` : ""}. Bulk copies from FAT/exFAT can also zero sub-seconds, so corroborate: run the Timestomping Detector ($SI vs $FN) from the menu and cross-check the USN journal.
                            </span>
                          </div>
                        )}
                        {/* Tier 6: explain the score down-weight whenever OS/servicing churn materially reduced it */}
                        {(selectedWindow.systemRatio || 0) >= 0.15 && (
                          <div style={{ marginBottom: 10, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>
                            {Math.round((selectedWindow.systemRatio || 0) * 100)}% of files here are in OS/servicing-churn paths (e.g. Windows Update / WinSxS) — burst score down-weighted accordingly (risky/timestomp signals are not).
                          </div>
                        )}
                        {/* Cross-artifact corroboration: the $SI axis is forgeable; USN ($J) + EVTX are the forgery-resistant cross-check */}
                        {selectedWindow.corroboration ? (() => {
                          const cor = selectedWindow.corroboration;
                          const green = th.success || "#3fb950";
                          const lvlMeta = ({
                            strong: { label: "USN + EVTX corroborated", color: green },
                            corroborated: { label: "Corroborated", color: green },
                            uncorroborated: { label: "Not corroborated by USN/EVTX", color: th.danger },
                            none: { label: "No companion artifacts", color: th.textMuted },
                          })[cor.level] || { label: cor.level, color: th.textMuted };
                          return (
                            <div style={{ marginBottom: 10, padding: "9px 11px", borderRadius: 8, background: `${th.border}10`, border: `1px solid ${th.border}22` }}>
                              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: (cor.usn || cor.evtx) ? 8 : 0 }}>
                                <span style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>Cross-Artifact Corroboration</span>
                                <span style={{ padding: "2px 8px", borderRadius: 999, fontSize: 9, fontWeight: 700, color: lvlMeta.color, background: `${lvlMeta.color}1e`, border: `1px solid ${lvlMeta.color}44` }}>{lvlMeta.label}</span>
                              </div>
                              {cor.usn && (
                                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: cor.evtx ? 6 : 0 }}>
                                  {[["USN deletes", cor.usn.fileDelete], ["content writes", cor.usn.contentWrite], ["USN creates", cor.usn.fileCreate], ["renames", cor.usn.renameNew]].map(([k, v]) => (
                                    <span key={k} style={{ fontSize: 9, color: th.textDim, padding: "3px 7px", borderRadius: 6, background: `${th.panelBg}88`, border: `1px solid ${th.border}22`, fontFamily: "-apple-system, sans-serif" }}>{(v || 0).toLocaleString()} {k}</span>
                                  ))}
                                </div>
                              )}
                              {cor.evtx && (
                                <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>
                                  <span style={{ fontWeight: 700, color: cor.evtx.processCreations > 0 ? green : th.textMuted }}>{(cor.evtx.processCreations || 0).toLocaleString()}</span> process-creation event{cor.evtx.processCreations === 1 ? "" : "s"} (EVTX) in this window
                                  {(cor.evtx.sampleProcesses || []).length > 0 && (
                                    <div style={{ marginTop: 4, display: "flex", flexDirection: "column", gap: 2 }}>
                                      {cor.evtx.sampleProcesses.slice(0, 3).map((p, idx) => (
                                        <span key={idx} title={p} style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p}</span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })() : ((d.correlation && (d.correlation.usnAvailable || d.correlation.evtxAvailable)) ? null : (
                          <div style={{ marginBottom: 10, padding: "8px 11px", borderRadius: 8, background: `${th.border}0e`, border: `1px dashed ${th.border}33`, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>
                            Open the matching <strong style={{ color: th.textDim }}>USN journal ($J)</strong> or <strong style={{ color: th.textDim }}>EVTX</strong> tab to corroborate this $SI-derived window against forgery-resistant evidence.
                          </div>
                        ))}
                        {windowDetails.length > 0 && (
                          <div style={{ marginBottom: 10, display: "flex", flexWrap: "wrap", gap: 6 }}>
                            {windowDetails.map((note, idx) => (
                              <span key={`${note}-${idx}`} style={{ padding: "3px 7px", borderRadius: 999, fontSize: 9, fontWeight: 600, color: th.warning, background: `${th.warning}18`, border: `1px solid ${th.warning}33`, fontFamily: "-apple-system, sans-serif" }}>{note}</span>
                            ))}
                          </div>
                        )}
                        <div style={{ marginBottom: 10 }}>
                          <div style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 5 }}>Top Directories</div>
                          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                            {(selectedWindow.topDirectories || []).length > 0 ? selectedWindow.topDirectories.map((dir, idx) => (
                              <div key={`${dir.path || "(blank)"}-${idx}`} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>
                                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 6 }}>
                                  <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{dir.path || "(blank path)"}</span>
                                  {dir.class && dir.class !== "other" && (
                                    <span style={{ flexShrink: 0, fontSize: 8, fontWeight: 600, padding: "1px 5px", borderRadius: 999, fontFamily: "-apple-system, sans-serif", color: dir.class === "servicing-churn" ? th.textMuted : th.textDim, background: `${th.border}22`, border: `1px solid ${th.border}33` }}>{PATH_CLASS_LABELS[dir.class] || dir.class}</span>
                                  )}
                                </span>
                                <span style={{ color: th.accent, fontWeight: 700, flexShrink: 0 }}>{dir.count.toLocaleString()}</span>
                              </div>
                            )) : <div style={{ fontSize: 10, color: th.textMuted }}>No path breakout available.</div>}
                          </div>
                        </div>
                        <div style={{ marginBottom: 12 }}>
                          <div style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 5 }}>Top Extensions</div>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                            {(selectedWindow.topExtensions || []).length > 0 ? selectedWindow.topExtensions.map((item, idx) => (
                              <span key={`${item.ext}-${idx}`} style={{ padding: "4px 7px", borderRadius: 8, fontSize: 9, color: th.text, background: `${th.panelBg}88`, border: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace" }}>{item.ext} ({item.count})</span>
                            )) : <span style={{ fontSize: 10, color: th.textMuted }}>No extension breakout available.</span>}
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                          <button onClick={() => applyHeatmapWindow(selectedWindow)} style={ms.bs}>Filter Grid to Window</button>
                          <button onClick={() => tagHeatmapWindow(selectedWindow)} style={{ ...ms.bp, background: `${th.warning}22`, color: th.warning, borderColor: `${th.warning}44` }}>Tag Window</button>
                          {(d.timeRange?.focusEarliest && d.timeRange?.focusLatest) && (
                            <button onClick={() => setModal((p) => p ? { ...p, hmRangeMode: "focus" } : p)} style={ms.bs}>Use Focus View</button>
                          )}
                        </div>
                      </>) : (
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", minHeight: 180, textAlign: "center", color: th.textMuted, fontSize: 12 }}>Select a suspicious window to inspect its path and extension context.</div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* USN Deletion Activity — deletion timing the $SI axis cannot show ($J FileDelete events) */}
              {(d.usnDeletionWindows || []).length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 4 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>USN Deletion Activity</div>
                    <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>from USN journal ($J)</div>
                  </div>
                  <div style={{ marginBottom: 10, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>
                    Hours with the most <strong style={{ color: th.textDim }}>FileDelete</strong> events, stamped at the moment of deletion — the MFT $SI heatmap above cannot show this (a deleted record keeps its original $SI times). User-driven only (OS/defrag/replication churn excluded).
                  </div>
                  {(() => {
                    const maxDel = Math.max(...d.usnDeletionWindows.map((w) => w.count), 1);
                    return d.usnDeletionWindows.slice().sort((a, b) => b.count - a.count).map((w, i) => (
                      <div key={`${w.bucket}-${i}`} title={`${w.from} — ${w.to} (UTC)`} style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 0", fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>
                        <span style={{ width: 120, flexShrink: 0, color: th.text }}>{w.bucket}</span>
                        <div style={{ flex: 1, minWidth: 0, height: 14, borderRadius: 4, background: `${th.border}22`, overflow: "hidden" }}>
                          <div style={{ width: `${(w.count / maxDel) * 100}%`, height: "100%", borderRadius: 4, background: `linear-gradient(90deg, ${th.danger}aa, ${th.danger}55)` }} />
                        </div>
                        <span style={{ width: 80, flexShrink: 0, textAlign: "right", fontSize: 10, color: th.danger, fontWeight: 600 }}>{w.count.toLocaleString()} deleted</span>
                      </div>
                    ));
                  })()}
                </div>
              )}

              {/* Top Activity Hours */}
              {topPeriods.length > 0 && (
                <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 8 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Top {modeTitle} Periods</div>
                    <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>Volume-ranked. Click a highlighted row to inspect its suspicious-window context.</div>
                  </div>
                  {topPeriods.map((h, i) => {
                    const maxH = topPeriods[0]?.count || 1;
                    const suspiciousMatches = suspiciousWindows.filter((win) => win.bucket === h.bucket);
                    const isSuspicious = suspiciousMatches.length > 0;
                    const topSuspMatch = isSuspicious ? suspiciousMatches.reduce((a, c) => c.score > a.score ? c : a, suspiciousMatches[0]) : null;
                    const periodRange = bucketRange(h.bucket);
                    return (
                      <div key={i} onClick={isSuspicious ? (() => {
                        setModal((p) => {
                          if (!p) return p;
                          const curId = p.hmSelWin;
                          const curIdx = suspiciousMatches.findIndex((w) => `${w.mode}:${w.bucket}` === curId);
                          const next = curIdx >= 0 ? suspiciousMatches[(curIdx + 1) % suspiciousMatches.length] : topSuspMatch;
                          return { ...p, hmSelWin: `${next.mode}:${next.bucket}` };
                        });
                      }) : undefined} title={isSuspicious ? (suspiciousMatches.length > 1 ? "Click to cycle between created/modified windows" : "Inspect suspicious-window details") : `${periodRange.from} \u2014 ${periodRange.to}`} style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 0", fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace", cursor: isSuspicious ? "pointer" : "default" }}>
                        <span style={{ width: 20, textAlign: "right", color: th.textMuted, fontSize: 10, fontWeight: 600 }}>{i + 1}</span>
                        <span style={{ width: 120, flexShrink: 0, color: th.text }}>{h.bucket}</span>
                        <div style={{ flex: 1, minWidth: 0, height: 14, borderRadius: 4, background: `${th.border}22`, overflow: "hidden" }}>
                          <div style={{ width: `${(h.count / maxH) * 100}%`, height: "100%", borderRadius: 4, background: isSuspicious ? `linear-gradient(90deg, ${th.warning}aa, ${th.warning}55)` : `linear-gradient(90deg, ${th.accent}88, ${th.accent}44)` }} />
                        </div>
                        <span style={{ width: 60, flexShrink: 0, textAlign: "right", fontSize: 10, color: th.accent, fontWeight: 600 }}>{h.count.toLocaleString()}</span>
                        {isSuspicious && <span style={{ padding: "2px 6px", borderRadius: 999, fontSize: 8, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", background: `${th.warning}18`, color: th.warning, border: `1px solid ${th.warning}33` }}>ranked</span>}
                      </div>
                    );
                  })}
                </div>
              )}
            </>);
          })()}
        </div>

        {/* Footer */}
        {!loading && data && !isIpcError(data) && (
          <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", gap: 10, justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
            <div style={{ minHeight: 18, fontSize: 10, color: modal.hmTagMsg ? (th.success || th.accent) : th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
              {modal.hmTagMsg || (footerSelectedWindow ? `Selected ${footerSelectedWindow.mode} window ${footerSelectedWindow.bucket}` : "Select a suspicious window to filter or tag the underlying rows.")}
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              {footerSelectedWindow && <button onClick={() => applyHeatmapWindow(footerSelectedWindow)} style={ms.bs}>Filter Grid</button>}
              {footerSelectedWindow && <button onClick={() => tagHeatmapWindow(footerSelectedWindow)} style={{ ...ms.bs, color: th.warning, borderColor: `${th.warning}55` }}>Tag Window</button>}
              <button onClick={copyReport} style={ms.bs}>Copy Summary</button>
              <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
            </div>
          </div>
        )}
      </>)}
    </DraggableResizableModal>
  );
}
