import { BkmkIcon, CheckboxIcon } from "./icons.jsx";
import { formatNumber } from "../utils/format.js";
import { applyColors } from "../utils/color-rules.js";
import useUIStore from "../store/useUIStore.js";
import { toast } from "../store/useToastStore.js";
import { isIpcError, ipcErrorMessage } from "../utils/ipc-result.js";
import {
  isAiHistorySourceFormat,
  aiHistoryDetailCellValue,
  aiHistoryDetailPinnedFields,
  aiHistoryDetailHeaderOrder,
} from "../utils/ai-history-profile.js";
import { HISTOGRAM_GRANULARITIES } from "../constants/ui-controls.js";
import { ROW_HEIGHT, HEADER_HEIGHT, FILTER_HEIGHT, BKMK_COL_WIDTH, CHECKBOX_COL_WIDTH, TAG_COL_WIDTH_MIN, VT_COL_WIDTH, EVIDENCE_COL_WIDTH, EVIDENCE_COL_MIN_WIDTH } from "../constants/grid.js";
import { pillToneFor } from "../utils/evidence-pills.js";
import { isRowSelected } from "../utils/row-selection.js";
import { Badge, Tooltip, Loading } from "./primitives/index.js";

export default function VirtualGrid({
  th, ct, tle, up, tabs,
  // Grid state
  isGrouped, isImporting, importingTabs, importQueue,
  displayRows, rows, visible, skeletonIndices,
  totalCount, totalH, physicalH, pageOffset, si, tw, rowOffset,
  allVisH, pinnedH, scrollH, pinnedOffsets,
  selectedRows, allRowsSelected, selectionCount,
  selectedColumn, setSelectedColumn,
  selectedRow, selectedRowData, detailVisible,
  compiledColors,
  // Handlers
  handleScroll, scrollRef, handleSort, handleHeaderDblClick, handleBookmark,
  handleRowClick, handleCheckboxToggle, handleSelectAllRows, openGridContextMenu,
  handleGroupSelectAll, getGroupCheckState,
  expandGroup, collapseGroup, loadMoreGroupRows, getRowAt,
  pinColumn, unpinColumn, addGroupBy, removeGroupBy, reorderColumn, autoFitColumn,
  onDetailResizeStart, onHistResizeStart, copyCell,
  renderCell, fmtCell, gw, getRowBg,
  // Filter state
  filterDropdown, setFilterDropdown, dateRangeDropdown, setDateRangeDropdown,
  contextMenu, setContextMenu, cellContextMenu, setCellContextMenu,
  rowContextMenu, setRowContextMenu, cellPopup, setCellPopup,
  headerDragOver, setHeaderDragOver,
  // Resize state
  resizingCol, setResizingCol, resizeX, setResizeX, resizeW, setResizeW,
  tagColWidth, setTagColWidth,
  // Search
  // Histogram
  histogramVisible, histogramCol, setHistogramCol,
  histogramData, histogramLoaded,
  histContainerRef, histContainerWidth,
  histBrushRef, histSvgRectRef, histBrushOverlayRef, histBrushLabelRef, histBarGeomRef,
  // Extract progress
  extracting, extractProgress,
  // Detail panel
  detailPanelRef, detailPanelHeight,
  onFilterToSession,
  onCorrelateWorkspace,
  // Import progress component
  ImportProgress,
  // Sorting timer
  sortTimerRef, justResizedRef,
  // Search highlighting
  searchLoading,
  fontSize
}) {
  const setModal = useUIStore((s) => s.setModal);
  const histogramHeight = useUIStore((s) => s.histogramHeight);
  const histGranularity = useUIStore((s) => s.histGranularity);
  const setHistGranularity = useUIStore((s) => s.setHistGranularity);
  const setHistogramVisible = useUIStore((s) => s.setHistogramVisible);
  const detailPanelOpen = useUIStore((s) => s.detailPanelOpen);
  const setDetailPanelOpen = useUIStore((s) => s.setDetailPanelOpen);
  const indexTotal = ct?.indexesTotal || 0;
  const indexPct = indexTotal > 0 ? Math.round(((ct?.indexesBuilt || 0) / indexTotal) * 100) : 0;
  const ftsTotal = ct?.ftsTotal || 0;
  const ftsPct = ftsTotal > 0 ? Math.round(((ct?.ftsIndexed || 0) / ftsTotal) * 100) : 0;

  // Hoisted sticky-cell offsets — these were redeclared inline in 6+ places
  // across header, filter row, and data rows (one redeclaration per visible
  // row × per cell type). Computing once per render is cleaner and saves
  // a small but non-zero per-row cost in the hot grid path.
  const vtW = ct?.columnWidths?.["__vt__"] || VT_COL_WIDTH;
  const bkmkBase = isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH);
  const leftBase = bkmkBase + tagColWidth + (ct?.vtEnrichment ? vtW : 0);
  // Sticky cells need an opaque base in both axes. Translucent backgrounds let
  // horizontally scrolled columns and vertically scrolled rows remain legible
  // underneath, which looks like duplicated/overlapping header content.
  const stickyHeaderBg = th.headerBg;
  const stickyFilterBg = th.bg;
  // Structural (non-data) sticky columns rendered in each data row, for an accurate
  // aria-colcount: bookmark + checkbox + tags, plus VT and Evidence when present.
  const _hasEvidenceCol = !!(ct?.evidencePillsByRowid && Object.keys(ct.evidencePillsByRowid).length > 0);
  const _structuralColCount = 3 + (ct?.vtEnrichment ? 1 : 0) + (_hasEvidenceCol ? 1 : 0);
  const activateOnKey = (event, action) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    action(event);
  };

  return (
    <>
      {/* Timeline Histogram — glass, brush-select, hourly toggle */}
      {histogramVisible && ct?.dataReady && ct?.tsColumns?.size > 0 && (() => {
        const effectiveHistCol = histogramCol && ct.tsColumns.has(histogramCol) ? histogramCol : [...ct.tsColumns][0];
        const HIST_H = histogramHeight, Y_AXIS_W = 44, X_AXIS_H = 18, CHART_PAD_T = 4, HEADER_BAR = 28;
        const svgH = HIST_H - HEADER_BAR;
        const chartH = svgH - X_AXIS_H - CHART_PAD_T;
        const isHourly = histGranularity === "hour";
        const bucketLabel = isHourly ? "hour" : "day";
        // Brush helpers — DOM-only during drag for zero-rerender performance
        const getBarIdx = (e) => {
          const r = histSvgRectRef.current || (e.currentTarget || e.target?.closest?.("svg"))?.getBoundingClientRect();
          if (!r) return 0;
          const cw = r.width - Y_AXIS_W;
          const bw = cw / (histogramData.length || 1);
          return Math.max(0, Math.min(histogramData.length - 1, Math.floor((e.clientX - r.left - Y_AXIS_W) / bw)));
        };
        const brushFrom = (d) => isHourly ? d + ":00:00" : d + " 00:00:00";
        const brushTo = (d) => isHourly ? d + ":59:59" : d + " 23:59:59";
        // Update brush overlay position via direct DOM (no React re-render)
        const updateBrushDOM = (lo, hi) => {
          const g = histBarGeomRef.current;
          const overlay = histBrushOverlayRef.current;
          const label = histBrushLabelRef.current;
          if (overlay) {
            const bx = g.yAxisW + lo * g.barW;
            const bw = (hi - lo + 1) * g.barW;
            overlay.setAttribute("x", bx);
            overlay.setAttribute("width", bw);
            overlay.setAttribute("y", g.chartPadT);
            overlay.setAttribute("height", g.chartH);
            overlay.style.display = "";
          }
          if (label) {
            const bx = g.yAxisW + lo * g.barW;
            const bw = (hi - lo + 1) * g.barW;
            label.setAttribute("x", bx + bw / 2);
            label.setAttribute("y", g.chartPadT - 3);
            label.textContent = (histogramData[lo]?.day || "") + (lo !== hi ? ` \u2014 ${histogramData[hi]?.day || ""}` : "");
            label.style.display = "";
          }
        };
        const hideBrushDOM = () => {
          if (histBrushOverlayRef.current) histBrushOverlayRef.current.style.display = "none";
          if (histBrushLabelRef.current) histBrushLabelRef.current.style.display = "none";
        };
        const onSvgDown = (e) => {
          if (e.button !== 0 || !histogramData.length) return;
          if (e.currentTarget) histSvgRectRef.current = e.currentTarget.getBoundingClientRect();
          const idx = getBarIdx(e);
          histBrushRef.current = { startIdx: idx, endIdx: idx, active: true };
          updateBrushDOM(idx, idx);
          e.currentTarget.style.cursor = "col-resize";
        };
        const onSvgMove = (e) => {
          if (!histBrushRef.current.active) return;
          const idx = getBarIdx(e);
          if (idx === histBrushRef.current.endIdx) return; // skip if same bar
          histBrushRef.current = { ...histBrushRef.current, endIdx: idx };
          const lo = Math.min(histBrushRef.current.startIdx, idx);
          const hi = Math.max(histBrushRef.current.startIdx, idx);
          updateBrushDOM(lo, hi);
        };
        const onSvgUp = (e) => {
          if (!histBrushRef.current.active || !histogramData.length) return;
          const end = getBarIdx(e);
          const lo = Math.min(histBrushRef.current.startIdx, end), hi = Math.max(histBrushRef.current.startIdx, end);
          if (lo === hi) {
            const d = histogramData[lo];
            if (d) up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [effectiveHistCol]: { from: brushFrom(d.day), to: brushTo(d.day) } });
          } else {
            const dLo = histogramData[lo], dHi = histogramData[hi];
            if (dLo && dHi) up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [effectiveHistCol]: { from: brushFrom(dLo.day), to: brushTo(dHi.day) } });
          }
          histBrushRef.current = { startIdx: null, endIdx: null, active: false };
          hideBrushDOM();
          histSvgRectRef.current = null;
          if (e.currentTarget) e.currentTarget.style.cursor = "crosshair";
        };
        return (
          <div id="hist-container" ref={histContainerRef} style={{ height: HIST_H, padding: "4px 12px 0", background: `linear-gradient(180deg, ${th.panelBg}ee, ${th.panelBg}cc)`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", borderBottom: `1px solid ${th.border}44`, flexShrink: 0, position: "relative", overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3, height: HEADER_BAR - 6 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "2px 8px", background: `${th.panelBg}88`, borderRadius: 6, border: `1px solid ${th.border}33` }}>
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2"><rect x="3" y="12" width="4" height="9" rx="1" /><rect x="10" y="6" width="4" height="15" rx="1" /><rect x="17" y="3" width="4" height="18" rx="1" /></svg>
                <span style={{ color: th.textDim, fontSize: 11, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Timeline</span>
              </div>
              <select value={effectiveHistCol || ""} onChange={(e) => { setHistogramCol(e.target.value); histBrushRef.current = { startIdx: null, endIdx: null, active: false }; hideBrushDOM(); }}
                style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 11, padding: "3px 6px", borderRadius: 4, cursor: "pointer", outline: "none" }}>
                {[...ct.tsColumns].map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              {/* Granularity toggle */}
              <div style={{ display: "flex", background: th.btnBg, borderRadius: 6, border: `1px solid ${th.btnBorder}`, overflow: "hidden" }}>
                {HISTOGRAM_GRANULARITIES.map((granularity) => (
                  <button key={granularity.value} onClick={() => { setHistGranularity(granularity.value); histBrushRef.current = { startIdx: null, endIdx: null, active: false }; hideBrushDOM(); }}
                    style={{ minHeight: 24, padding: "2px 8px", fontSize: 11, fontWeight: histGranularity === granularity.value ? 600 : 400, background: histGranularity === granularity.value ? th.accent + "22" : "transparent", color: histGranularity === granularity.value ? th.accent : th.textMuted, border: "none", cursor: "pointer", fontFamily: "-apple-system,sans-serif" }}>{granularity.label}</button>
                ))}
              </div>
              {histogramData.length > 0 && (
                <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
                  {histogramData[0]?.day} — {histogramData[histogramData.length - 1]?.day} ({histogramData.length} {bucketLabel}{histogramData.length !== 1 ? "s" : ""})
                </span>
              )}
              {ct.dateRangeFilters?.[effectiveHistCol] && (
                <button onClick={() => {
                  const next = { ...(ct.dateRangeFilters || {}) };
                  delete next[effectiveHistCol];
                  up("dateRangeFilters", next);
                }} style={{ minHeight: 24, background: `${th.warning}22`, border: `1px solid ${th.warning}4D`, color: th.warning, cursor: "pointer", fontSize: 11, padding: "2px 8px", borderRadius: 3, marginLeft: "auto", fontFamily: "-apple-system,sans-serif" }}>
                  Clear filter
                </button>
              )}
              <button onClick={() => setHistogramVisible(false)} aria-label="Hide histogram" title="Hide histogram" style={{ width: 26, height: 26, background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 11, marginLeft: ct.dateRangeFilters?.[effectiveHistCol] ? 4 : "auto", padding: 0 }}>{"\u2715"}</button>
            </div>
            {histogramData.length > 0 ? (
              <svg width="100%" height={svgH} style={{ display: "block", overflow: "visible", cursor: "crosshair", userSelect: "none" }}
                onMouseDown={onSvgDown} onMouseMove={onSvgMove} onMouseUp={onSvgUp} onMouseLeave={(e) => { if (histBrushRef.current.active) { histBrushRef.current = { startIdx: null, endIdx: null, active: false }; hideBrushDOM(); if (e.currentTarget) e.currentTarget.style.cursor = "crosshair"; } }}>
                {(() => {
                  const maxCnt = Math.max(...histogramData.map((d) => d.cnt), 1);
                  const rawStep = maxCnt / 4;
                  const mag = Math.pow(10, Math.floor(Math.log10(rawStep || 1)));
                  const step = Math.ceil(rawStep / mag) * mag || 1;
                  const yTicks = [];
                  for (let v = 0; v <= maxCnt; v += step) yTicks.push(v);
                  if (yTicks[yTicks.length - 1] < maxCnt) yTicks.push(yTicks[yTicks.length - 1] + step);
                  const yMax = yTicks[yTicks.length - 1] || 1;
                  const chartW = Math.max(200, (histContainerWidth || (typeof window !== "undefined" ? window.innerWidth : 800)) - 24 - Y_AXIS_W);
                  const barW = Math.max(1, chartW / histogramData.length);
                  const gap = barW > 4 ? 1 : 0;
                  const maxLabels = Math.floor(chartW / (isHourly ? 90 : 70));
                  const labelStep = Math.max(1, Math.ceil(histogramData.length / maxLabels));
                  const gridColor = th.histGrid;
                  const textColor = th.textMuted;
                  // Cache bar geometry for DOM-based brush updates (no re-renders during drag)
                  histBarGeomRef.current = { barW, yAxisW: Y_AXIS_W, chartPadT: CHART_PAD_T, chartH, len: histogramData.length };
                  const heatColor = (ratio) => {
                    const t = Math.max(0, Math.min(1, ratio));
                    return `rgb(${Math.round(30 + t * 202)},${Math.round(40 + t * 53)},${Math.round(56 - t * 14)})`;
                  };
                  // Active date filter check
                  const activeFilter = ct.dateRangeFilters?.[effectiveHistCol];
                  const filterFrom = activeFilter?.from?.slice(0, isHourly ? 13 : 10);
                  const filterTo = activeFilter?.to?.slice(0, isHourly ? 13 : 10);

                  return (<>
                    {yTicks.map((v) => {
                      const y = CHART_PAD_T + chartH - (v / yMax) * chartH;
                      return <g key={`y-${v}`}>
                        <line x1={Y_AXIS_W} y1={y} x2={Y_AXIS_W + chartW} y2={y} stroke={gridColor} strokeWidth={1} strokeOpacity={0.6} />
                        <text x={Y_AXIS_W - 4} y={y + 3} textAnchor="end" fill={textColor} fontSize={9} fontFamily="-apple-system,sans-serif">{v >= 1000 ? `${(v/1000).toFixed(v >= 10000 ? 0 : 1)}k` : v}</text>
                      </g>;
                    })}
                    {histogramData.map((d, i) => {
                      const h = Math.max(1, (d.cnt / yMax) * chartH);
                      const x = Y_AXIS_W + i * barW + gap;
                      const y = CHART_PAD_T + chartH - h;
                      const isFiltered = filterFrom && filterTo && d.day >= filterFrom && d.day <= filterTo;
                      const ratio = d.cnt / maxCnt;
                      const fill = isFiltered ? th.warning : heatColor(ratio);
                      return <rect key={i} x={x} y={y} width={Math.max(1, barW - gap * 2)} height={h}
                        fill={fill} rx={barW > 6 ? 2 : 0}
                        style={{ transition: "fill var(--m-fast) var(--ease-out)", pointerEvents: "none" }}>
                        <title>{d.day}: {d.cnt.toLocaleString()} events</title>
                      </rect>;
                    })}
                    {/* Brush selection overlay — positioned via DOM refs for zero-rerender drag */}
                    <rect ref={histBrushOverlayRef} x={0} y={CHART_PAD_T} width={0} height={chartH}
                      fill={th.accent + "15"} stroke={th.accent} strokeWidth={1} strokeDasharray="3 2" rx={2}
                      style={{ pointerEvents: "none", display: "none" }} />
                    <text ref={histBrushLabelRef} x={0} y={CHART_PAD_T - 3} textAnchor="middle"
                      fill={th.accent} fontSize={8} fontWeight="600" fontFamily="-apple-system,sans-serif"
                      style={{ pointerEvents: "none", display: "none" }} />
                    <line x1={Y_AXIS_W} y1={CHART_PAD_T + chartH} x2={Y_AXIS_W + chartW} y2={CHART_PAD_T + chartH} stroke={gridColor} strokeWidth={1} />
                    {histogramData.map((d, i) => {
                      if (i % labelStep !== 0 && i !== histogramData.length - 1) return null;
                      const x = Y_AXIS_W + i * barW + barW / 2;
                      if (isHourly) {
                        const p = d.day.split(" ");
                        const dateParts = (p[0] || "").split("-");
                        const label = dateParts.length === 3 ? `${dateParts[1]}/${dateParts[2]} ${p[1] || ""}:00` : d.day;
                        return <text key={`xl-${i}`} x={x} y={svgH - 2} textAnchor="middle" fill={textColor} fontSize={7} fontFamily="-apple-system,sans-serif">{label}</text>;
                      }
                      const parts = d.day.split("-");
                      const label = parts.length === 3 ? `${parts[1]}/${parts[2]}` : d.day;
                      return <text key={`xl-${i}`} x={x} y={svgH - 2} textAnchor="middle" fill={textColor} fontSize={8} fontFamily="-apple-system,sans-serif">{label}</text>;
                    })}
                  </>);
                })()}
              </svg>
            ) : (
              <div style={{ height: svgH, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>{histogramLoaded ? "No timestamp data to display" : "Loading histogram..."}</span>
              </div>
            )}
            {/* Drag handle */}
            <div onMouseDown={onHistResizeStart} style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 6, cursor: "row-resize", zIndex: 2 }}>
              <div style={{ width: 36, height: 3, borderRadius: 2, background: th.textMuted + "55", margin: "2px auto 0" }} />
            </div>
          </div>
        );
      })()}

      {/* Content area */}
      {isImporting ? (
        <ImportProgress th={th} info={importingTabs[ct.id]} />
      ) : ct && ct.dataReady ? (
        <>
          {/* Grid */}
          <div
            id="timeline-grid"
            role="grid"
            aria-label="Timeline events"
            aria-rowcount={(ct?.totalFiltered || 0) + 1}
            aria-colcount={_structuralColCount + pinnedH.length + scrollH.length}
            aria-multiselectable={true}
            tabIndex={selectedRow === null ? 0 : -1}
            style={{ flex: 1, overflow: "auto", position: "relative", WebkitAppRegion: "no-drag", contain: "layout style paint", willChange: "transform" }}
            ref={scrollRef}
            onScroll={handleScroll}
          >
            {/* Non-blocking build banner — the grid stays fully interactive while column
                indexes build in the background (queries work via WAL + lazy _ensureIndex,
                search via LIKE). pointerEvents:none so it never intercepts clicks. */}
            {ct && ct.dataReady && !ct.indexesReady && !ct.indexError && (
              <div style={{ position: "absolute", left: "50%", bottom: 14, transform: "translateX(-50%)", zIndex: 50, pointerEvents: "none", display: "flex", alignItems: "center", gap: 10, padding: "7px 14px", borderRadius: 8, background: (th.panelBg || th.bg) + "f2", border: `1px solid ${th.border}`, boxShadow: "0 4px 16px rgba(0,0,0,0.35)", fontFamily: "-apple-system, sans-serif", maxWidth: "90%" }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" style={{ animation: "tle-pulse 2s ease-in-out infinite", flexShrink: 0 }}>
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.accent) + "18"} />
                </svg>
                <span style={{ color: th.text, fontSize: 12, fontWeight: 600, whiteSpace: "nowrap" }}>
                  {indexTotal ? `Building column indexes… ${ct.indexesBuilt || 0}/${indexTotal}` : "Preparing column indexes…"}
                </span>
                <span style={{ color: th.textMuted, fontSize: 11, whiteSpace: "nowrap" }}>grid is usable now</span>
                {indexTotal > 0 && (
                  <div style={{ width: 70, height: 3, borderRadius: 2, background: (th.textMuted) + "33", overflow: "hidden", flexShrink: 0 }}>
                    <div style={{ height: "100%", borderRadius: 2, background: th.accent, transition: "width var(--m-slow) ease", width: `${indexPct}%` }} />
                  </div>
                )}
              </div>
            )}
            {/* Non-blocking search-index banner — grid stays interactive; search uses the
                substring (LIKE) scan until this finishes. pointerEvents:none = click-through. */}
            {ct && ct.dataReady && ct.indexesReady && ftsTotal > 0 && !ct.ftsReady && !ct.ftsError && (
              <div style={{ position: "absolute", left: "50%", bottom: 14, transform: "translateX(-50%)", zIndex: 50, pointerEvents: "none", display: "flex", alignItems: "center", gap: 10, padding: "7px 14px", borderRadius: 8, background: (th.panelBg || th.bg) + "f2", border: `1px solid ${th.border}`, boxShadow: "0 4px 16px rgba(0,0,0,0.35)", fontFamily: "-apple-system, sans-serif", maxWidth: "90%" }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" style={{ animation: "tle-pulse 2s ease-in-out infinite", flexShrink: 0 }}>
                  <circle cx="11" cy="11" r="8" fill={(th.accent) + "18"} />
                  <path d="M21 21l-4.35-4.35" strokeLinecap="round" />
                </svg>
                <span style={{ color: th.text, fontSize: 12, fontWeight: 600, whiteSpace: "nowrap" }}>
                  {ct.ftsOptimizing ? "Optimizing search index…" : `Building search index… ${ftsPct}%`}
                </span>
                <span style={{ color: th.textMuted, fontSize: 11, whiteSpace: "nowrap" }}>search uses substring scan meanwhile</span>
                <div style={{ width: 70, height: 3, borderRadius: 2, background: (th.textMuted) + "33", overflow: "hidden", flexShrink: 0 }}>
                  <div style={{ height: "100%", borderRadius: 2, background: th.accent, transition: "width var(--m-slow) ease", width: `${ftsPct}%` }} />
                </div>
              </div>
            )}
            {/* Resident data extraction overlay */}
            {extracting && extractProgress && (
              <div style={{ position: "absolute", inset: 0, zIndex: 50, background: (th.bg) + "e6", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, backdropFilter: "blur(6px)", WebkitBackdropFilter: "blur(6px)" }}
                onClick={(e) => e.stopPropagation()} onMouseDown={(e) => e.stopPropagation()}>
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}>
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" fill={(th.accent) + "18"} />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                </svg>
                <div style={{ color: th.text, fontSize: 15, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                  Extracting Resident Data
                </div>
                <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif", textAlign: "center", maxWidth: 320, lineHeight: 1.5 }}>
                  {extractProgress.total > 0
                    ? `${extractProgress.percent}% — ${extractProgress.processed.toLocaleString()} / ${extractProgress.total.toLocaleString()} records`
                    : "Preparing..."}
                </div>
                {extractProgress.total > 0 && (
                  <div style={{ width: 220, height: 4, borderRadius: 2, background: (th.textMuted) + "33", overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 2, background: th.accent, transition: "width var(--m-slow) ease", width: `${extractProgress.percent}%` }} />
                  </div>
                )}
              </div>
            )}
            <div style={{ minWidth: tw }}>
              {/* Header */}
              <div role="row" aria-rowindex={1} style={{ display: "flex", position: "sticky", top: 0, zIndex: 10, background: stickyHeaderBg, borderBottom: `2px solid ${th.borderAccent}` }}>
                {/* # column - always sticky */}
                <div role="columnheader" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 2, width: isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), minWidth: isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), height: HEADER_HEIGHT, color: th.textMuted, fontSize: 11, fontWeight: 600, position: "sticky", left: 0, zIndex: 13, background: stickyHeaderBg }}>
                  <span>#</span>
                  {!isGrouped && <button type="button" onClick={handleSelectAllRows}
                    aria-label={selectionCount > 0 && allRowsSelected && selectedRows.size === 0 ? "Deselect all filtered rows" : "Select all filtered rows"}
                    aria-pressed={selectionCount > 0 && allRowsSelected && selectedRows.size === 0}
                    title={selectionCount > 0 && allRowsSelected && selectedRows.size === 0 ? "Deselect all filtered rows" : "Select all filtered rows"}
                    style={{ width: 26, height: 26, display: "inline-flex", alignItems: "center", justifyContent: "center", background: "none", border: "none", cursor: "pointer", marginLeft: 2, padding: 0 }}>
                    <CheckboxIcon checked={selectionCount > 0 && allRowsSelected && selectedRows.size === 0} indeterminate={selectionCount > 0 && !(allRowsSelected && selectedRows.size === 0)} />
                  </button>}
                </div>
                {/* Tags column header — sticky, resizable, standard style */}
                <div
                  data-col-header="__tags__"
                  role="columnheader"
                  aria-sort={ct.sortCol === "__tags__" ? (ct.sortDir === "asc" ? "ascending" : "descending") : "none"}
                  tabIndex={0}
                  onKeyDown={(e) => activateOnKey(e, () => handleSort("__tags__"))}
                  onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: "__tags__" }); return; } handleSort("__tags__"); }}
                  onDoubleClick={() => { clearTimeout(sortTimerRef.current); }}
                  onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
                  style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: tagColWidth, minWidth: tagColWidth, boxSizing: "border-box", padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: `1px solid ${th.border}`, position: "sticky", left: isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), zIndex: 12, background: stickyHeaderBg, overflow: "hidden" }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>Tags</span>
                  {ct.sortCol === "__tags__" && <span style={{ fontSize: 11, color: th.accent, marginLeft: 3 }}>{ct.sortDir === "asc" ? "▲" : "▼"}</span>}
                  <div onMouseDown={(e) => {
                    e.preventDefault(); e.stopPropagation();
                    const startX = e.clientX, startW = tagColWidth;
                    const onMove = (ev) => setTagColWidth(Math.max(TAG_COL_WIDTH_MIN, startW + ev.clientX - startX));
                    const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                    document.addEventListener("mousemove", onMove);
                    document.addEventListener("mouseup", onUp);
                  }}
                    onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); }}
                    style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize" }} />
                </div>
                {/* VT verdict column header — only when enrichment data exists */}
                {ct.vtEnrichment && (() => {
                  
                  return <div title="VirusTotal verdict (from IOC enrichment)"
                    role="columnheader"
                    aria-sort={ct.sortCol === "__vt__" ? (ct.sortDir === "asc" ? "ascending" : "descending") : "none"}
                    tabIndex={0}
                    onKeyDown={(e) => activateOnKey(e, () => handleSort("__vt__"))}
                    onClick={() => handleSort("__vt__")}
                    style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 2, height: HEADER_HEIGHT, width: vtW, minWidth: 40, boxSizing: "border-box", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: `1px solid ${th.border}`, position: "sticky", left: (isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH)) + tagColWidth, zIndex: 12, background: stickyHeaderBg, cursor: "pointer", userSelect: "none", overflow: "hidden" }}>
                    VirusTotal
                    {ct.sortCol === "__vt__" && <span style={{ fontSize: 11, color: th.accent }}>{ct.sortDir === "asc" ? "▲" : "▼"}</span>}
                    <div onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); setResizingCol("__vt__"); setResizeX(e.clientX); setResizeW(vtW); }}
                      style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", background: resizingCol === "__vt__" ? th.borderAccent : "transparent" }} />
                  </div>;
                })()}
                {/* Evidence pills column header — only when persistence/lateral analysis populated pills */}
                {(() => {
                  const pillsMap = ct.evidencePillsByRowid;
                  if (!pillsMap || Object.keys(pillsMap).length === 0) return null;
                  const evW = ct.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;
                  
                  
                  return <div title={`Evidence pills (${Object.keys(pillsMap).length} rows tagged) — derived from analysis modal output`}
                    role="columnheader"
                    style={{ display: "flex", alignItems: "center", gap: 4, height: HEADER_HEIGHT, width: evW, minWidth: EVIDENCE_COL_MIN_WIDTH, boxSizing: "border-box", padding: "0 8px", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: `1px solid ${th.border}`, position: "sticky", left: leftBase, zIndex: 12, background: stickyHeaderBg, userSelect: "none", overflow: "hidden" }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
                      Evidence
                      {ct.evidencePillFilter && <span style={{ marginLeft: 4, fontSize: 11, padding: "1px 4px", borderRadius: 3, background: th.accent + "22", color: th.accent, fontWeight: 500 }}>{ct.evidencePillFilter}</span>}
                    </span>
                    {ct.evidencePillFilter && <button onClick={(e) => { e.stopPropagation(); up("evidencePillFilter", null); }}
                      style={{ width: 24, height: 24, background: "none", border: "none", color: th.accent, cursor: "pointer", fontSize: 11, padding: 0, flexShrink: 0, lineHeight: 1 }} aria-label="Clear pill focus" title="Clear pill focus">✕</button>}
                    <button onClick={(e) => { e.stopPropagation(); up("evidencePillsByRowid", {}); up("evidencePillFilter", null); }}
                      style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 11, padding: "0 2px", flexShrink: 0, lineHeight: 1 }} aria-label="Clear all evidence pills" title="Clear all evidence pills">✕</button>
                    <div onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); setResizingCol("__evidence__"); setResizeX(e.clientX); setResizeW(evW); }}
                      style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", background: resizingCol === "__evidence__" ? th.borderAccent : "transparent" }} />
                  </div>;
                })()}
                {/* Pinned columns */}
                {pinnedH.map((h) => (
                  <div key={h} data-col-header={h} role="columnheader" aria-sort={ct?.sortCol === h ? (ct?.sortDir === "asc" ? "ascending" : "descending") : "none"} tabIndex={0}
                    onKeyDown={(e) => activateOnKey(e, () => handleSort(h))}
                    draggable onDragStart={(e) => { if (e.button === 2) { e.preventDefault(); return; } e.dataTransfer.setData("text/column-name", h); e.dataTransfer.effectAllowed = "move"; }}
                    onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setHeaderDragOver(h); }}
                    onDragLeave={() => setHeaderDragOver((prev) => prev === h ? null : prev)}
                    onDrop={(e) => { e.preventDefault(); e.stopPropagation(); setHeaderDragOver(null); const src = e.dataTransfer.getData("text/column-name"); if (src && src !== h) reorderColumn(src, h); }}
                    onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); return; } if (e.altKey) { e.preventDefault(); e.stopPropagation(); setSelectedColumn?.(selectedColumn === h ? null : h); return; } handleSort(h); }}
                    onDoubleClick={() => handleHeaderDblClick(h)}
                    onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
                    style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}` : `1px solid ${th.border}`, borderLeft: selectedColumn === h ? `2px solid ${th.accent}` : headerDragOver === h ? `2px solid ${th.accent}` : "2px solid transparent", position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 12, background: selectedColumn === h ? `linear-gradient(${th.accent}30, ${th.accent}30), ${stickyHeaderBg}` : headerDragOver === h ? `linear-gradient(${th.accent}1a, ${th.accent}1a), ${stickyHeaderBg}` : stickyHeaderBg, overflow: "hidden", transition: "background var(--m-fast) var(--ease-out), border-left-color var(--m-fast) var(--ease-out)" }}>
                    <button type="button" onClick={(e) => { e.stopPropagation(); unpinColumn(h); }} aria-label={`Unpin ${h}`}
                      style={{ width: 24, height: 24, padding: 0, background: "none", border: "none", fontSize: 11, marginRight: 3, cursor: "pointer", opacity: 0.8, flexShrink: 0 }} title="Unpin">📌</button>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{h}</span>
                    {ct.tsColumns.has(h) && <span aria-label="Timestamp column" style={{ fontSize: 11, marginRight: 2, opacity: 0.8 }}>⏱</span>}
                    {ct.sortCol === h && <span style={{ fontSize: 11, color: th.accent, marginLeft: 3 }}>{ct.sortDir === "asc" ? "▲" : "▼"}</span>}
                    <div onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); setResizingCol(h); setResizeX(e.clientX); setResizeW(gw(h)); }}
                      onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); autoFitColumn(h); }}
                      style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", background: resizingCol === h ? th.borderAccent : "transparent" }} />
                  </div>
                ))}
                {/* Scrollable columns */}
                {scrollH.map((h) => (
                  <div key={h} data-col-header={h} role="columnheader" aria-sort={ct?.sortCol === h ? (ct?.sortDir === "asc" ? "ascending" : "descending") : "none"} tabIndex={0}
                    onKeyDown={(e) => activateOnKey(e, () => handleSort(h))}
                    draggable onDragStart={(e) => { if (e.button === 2) { e.preventDefault(); return; } e.dataTransfer.setData("text/column-name", h); e.dataTransfer.effectAllowed = "move"; }}
                    onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setHeaderDragOver(h); }}
                    onDragLeave={() => setHeaderDragOver((prev) => prev === h ? null : prev)}
                    onDrop={(e) => { e.preventDefault(); e.stopPropagation(); setHeaderDragOver(null); const src = e.dataTransfer.getData("text/column-name"); if (src && src !== h) reorderColumn(src, h); }}
                    onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); return; } if (e.altKey) { e.preventDefault(); e.stopPropagation(); setSelectedColumn?.(selectedColumn === h ? null : h); return; } handleSort(h); }}
                    onDoubleClick={() => handleHeaderDblClick(h)}
                    onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
                    style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: `1px solid ${th.border}`, borderLeft: selectedColumn === h ? `2px solid ${th.accent}` : headerDragOver === h ? `2px solid ${th.accent}` : "2px solid transparent", position: "relative", overflow: "hidden", background: selectedColumn === h ? `${th.accent}30` : headerDragOver === h ? `${th.accent}1a` : undefined, transition: "background var(--m-fast) var(--ease-out), border-left-color var(--m-fast) var(--ease-out)" }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{h}</span>
                    {ct.tsColumns.has(h) && <span aria-label="Timestamp column" style={{ fontSize: 11, marginRight: 2, opacity: 0.8 }}>⏱</span>}
                    {ct.sortCol === h && <span style={{ fontSize: 11, color: th.accent, marginLeft: 3 }}>{ct.sortDir === "asc" ? "▲" : "▼"}</span>}
                    <div onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); setResizingCol(h); setResizeX(e.clientX); setResizeW(gw(h)); }}
                      onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); autoFitColumn(h); }}
                      style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", background: resizingCol === h ? th.borderAccent : "transparent" }} />
                  </div>
                ))}
              </div>

              {/* Filters */}
              <div style={{ display: "flex", position: "sticky", top: HEADER_HEIGHT, zIndex: 10, background: stickyFilterBg, borderBottom: `1px solid ${th.border}` }}>
                {/* # filter placeholder */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), minWidth: isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), height: FILTER_HEIGHT, position: "sticky", left: 0, zIndex: 11, background: stickyFilterBg }}>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" /></svg>
                </div>
                {/* Tags filter cell — standard layout with text input + dropdown */}
                {(() => {
                  const hasCbf = ct.tagFilter && (Array.isArray(ct.tagFilter) ? ct.tagFilter.length > 0 : true);
                  const hasTextFilter = !!(ct.columnFilters["__tags__"]);
                  const hasFilter = !!(hasTextFilter || hasCbf);
                  const isDis = ct.disabledFilters?.has("__tags__");
                  return (
                    <div style={{ width: tagColWidth, minWidth: tagColWidth, boxSizing: "border-box", padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}`, position: "sticky", left: isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), zIndex: 11, background: stickyFilterBg }}>
                      {hasFilter && <button onClick={() => { const s = new Set(ct.disabledFilters || []); if (s.has("__tags__")) s.delete("__tags__"); else s.add("__tags__"); up("disabledFilters", s); }}
                        aria-label={isDis ? "Enable Tags filter" : "Disable Tags filter"}
                        style={{ width: 24, height: 24, background: "none", border: "none", cursor: "pointer", padding: 0, color: isDis ? th.danger : th.success, fontSize: 11, flexShrink: 0, lineHeight: 1 }} title={isDis ? "Enable filter" : "Disable filter"}>{isDis ? "⊘" : "⊙"}</button>}
                      <input aria-label="Filter Tags" value={ct.columnFilters["__tags__"] || ""} onChange={(e) => up("columnFilters", { ...ct.columnFilters, "__tags__": e.target.value })} placeholder="Filter..."
                        style={{ flex: 1, background: th.bgInput, border: `1px solid ${hasCbf ? th.borderAccent : th.border}`, borderRadius: 3, color: th.text, fontSize: 11, padding: "3px 4px", outline: "none", fontFamily: "inherit", minWidth: 0, opacity: isDis ? 0.4 : 1, textDecoration: isDis ? "line-through" : "none" }} />
                      <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === "__tags__" ? null : { colName: "__tags__", x: rect.left, y: rect.bottom + 2 }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px", color: hasCbf ? th.borderAccent : th.textDim, fontSize: 12, flexShrink: 0, lineHeight: 1 }} title="Filter by tags">▼</button>
                    </div>
                  );
                })()}
                {/* VT verdict filter cell — only when enrichment data exists */}
                {ct.vtEnrichment && (() => {
                  const hasCbf = ct.checkboxFilters?.["__vt__"]?.length > 0;
                  const hasFilter = hasCbf;
                  const isDis = ct.disabledFilters?.has("__vt__");
                  return (
                    <div style={{ width: ct.columnWidths?.["__vt__"] || VT_COL_WIDTH, minWidth: 40, boxSizing: "border-box", padding: "0 1px", display: "flex", alignItems: "center", justifyContent: "flex-end", height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}`, position: "sticky", left: (isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH)) + tagColWidth, zIndex: 11, background: stickyFilterBg }}>
                      {hasFilter && <button onClick={() => { const s = new Set(ct.disabledFilters || []); if (s.has("__vt__")) s.delete("__vt__"); else s.add("__vt__"); up("disabledFilters", s); }}
                        aria-label={isDis ? "Enable VirusTotal filter" : "Disable VirusTotal filter"}
                        style={{ width: 24, height: 24, background: "none", border: "none", cursor: "pointer", padding: 0, color: isDis ? th.danger : th.success, fontSize: 11, flexShrink: 0, lineHeight: 1 }} title={isDis ? "Enable filter" : "Disable filter"}>{isDis ? "⊘" : "⊙"}</button>}
                      <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === "__vt__" ? null : { colName: "__vt__", x: rect.left, y: rect.bottom + 2 }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 4px", color: hasFilter ? th.borderAccent : th.textDim, fontSize: 12, flexShrink: 0, lineHeight: 1 }} title="Filter by VT verdict">▼</button>
                    </div>
                  );
                })()}
                {/* Evidence pills filter cell — placeholder spacer (no filter UI yet) */}
                {(() => {
                  const pillsMap = ct.evidencePillsByRowid;
                  if (!pillsMap || Object.keys(pillsMap).length === 0) return null;
                  const evW = ct.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;
                  
                  
                  return (
                    <div style={{ width: evW, minWidth: EVIDENCE_COL_MIN_WIDTH, boxSizing: "border-box", padding: "0 6px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}`, position: "sticky", left: leftBase, zIndex: 11, background: stickyFilterBg, fontSize: 11, color: ct.evidencePillFilter ? th.accent : th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                      {ct.evidencePillFilter ? `Focus: ${ct.evidencePillFilter}` : `${Object.keys(pillsMap).length} tagged`}
                    </div>
                  );
                })()}
                {/* Pinned filter cells */}
                {pinnedH.map((h) => {
                  const hasCbf = ct.checkboxFilters?.[h]?.length > 0;
                  const isTs = ct.tsColumns?.has(h);
                  const hasDr = ct.dateRangeFilters?.[h];
                  const hasFilter = !!(ct.columnFilters[h] || hasCbf);
                  const isDis = ct.disabledFilters?.has(h);
                  return (
                    <div key={h} style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}` : `1px solid ${th.border}`, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 11, background: stickyFilterBg }}>
                      {hasFilter && <button onClick={() => { const s = new Set(ct.disabledFilters || []); if (s.has(h)) s.delete(h); else s.add(h); up("disabledFilters", s); }}
                        aria-label={`${isDis ? "Enable" : "Disable"} ${h} filter`}
                        style={{ width: 24, height: 24, background: "none", border: "none", cursor: "pointer", padding: 0, color: isDis ? th.danger : th.success, fontSize: 11, flexShrink: 0, lineHeight: 1 }} title={isDis ? "Enable filter" : "Disable filter"}>{isDis ? "⊘" : "⊙"}</button>}
                      <input aria-label={`Filter ${h}`} value={ct.columnFilters[h] || ""} onChange={(e) => up("columnFilters", { ...ct.columnFilters, [h]: e.target.value })} placeholder="Filter..."
                        style={{ flex: 1, background: th.bgInput, border: `1px solid ${hasCbf ? th.borderAccent : th.border}`, borderRadius: 3, color: th.text, fontSize: 11, padding: "3px 4px", outline: "none", fontFamily: "inherit", minWidth: 0, opacity: isDis ? 0.4 : 1, textDecoration: isDis ? "line-through" : "none" }} />
                      {isTs && <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setDateRangeDropdown(dateRangeDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2, from: hasDr?.from || "", to: hasDr?.to || "" }); }}
                        aria-label={`Date range filter for ${h}`}
                        style={{ width: 24, height: 24, background: "none", border: "none", cursor: "pointer", padding: 0, color: hasDr ? th.warning : th.textMuted, fontSize: 11, flexShrink: 0, lineHeight: 1 }} title="Date range filter">⏱</button>}
                      <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2 }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px", color: hasCbf ? th.borderAccent : th.textDim, fontSize: 12, flexShrink: 0, lineHeight: 1 }} title="Filter by values">▼</button>
                    </div>
                  );
                })}
                {/* Scrollable filter cells */}
                {scrollH.map((h) => {
                  const hasCbf = ct.checkboxFilters?.[h]?.length > 0;
                  const isTs = ct.tsColumns?.has(h);
                  const hasDr = ct.dateRangeFilters?.[h];
                  const hasFilter = !!(ct.columnFilters[h] || hasCbf);
                  const isDis = ct.disabledFilters?.has(h);
                  return (
                    <div key={h} style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}` }}>
                      {hasFilter && <button onClick={() => { const s = new Set(ct.disabledFilters || []); if (s.has(h)) s.delete(h); else s.add(h); up("disabledFilters", s); }}
                        aria-label={`${isDis ? "Enable" : "Disable"} ${h} filter`}
                        style={{ width: 24, height: 24, background: "none", border: "none", cursor: "pointer", padding: 0, color: isDis ? th.danger : th.success, fontSize: 11, flexShrink: 0, lineHeight: 1 }} title={isDis ? "Enable filter" : "Disable filter"}>{isDis ? "⊘" : "⊙"}</button>}
                      <input aria-label={`Filter ${h}`} value={ct.columnFilters[h] || ""} onChange={(e) => up("columnFilters", { ...ct.columnFilters, [h]: e.target.value })} placeholder="Filter..."
                        style={{ flex: 1, background: th.bgInput, border: `1px solid ${hasCbf ? th.borderAccent : th.border}`, borderRadius: 3, color: th.text, fontSize: 11, padding: "3px 4px", outline: "none", fontFamily: "inherit", minWidth: 0, opacity: isDis ? 0.4 : 1, textDecoration: isDis ? "line-through" : "none" }} />
                      {isTs && <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setDateRangeDropdown(dateRangeDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2, from: hasDr?.from || "", to: hasDr?.to || "" }); }}
                        aria-label={`Date range filter for ${h}`}
                        style={{ width: 24, height: 24, background: "none", border: "none", cursor: "pointer", padding: 0, color: hasDr ? th.warning : th.textMuted, fontSize: 11, flexShrink: 0, lineHeight: 1 }} title="Date range filter">⏱</button>}
                      <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2 }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px", color: hasCbf ? th.borderAccent : th.textDim, fontSize: 12, flexShrink: 0, lineHeight: 1 }} title="Filter by values">▼</button>
                    </div>
                  );
                })}
              </div>

              {/* Virtual rows */}
              <div style={{ height: physicalH ?? totalH, position: "relative" }}>
                {visible.map((item, vi) => {
                  const ai = si + vi;

                  // ── Grouped mode: group header ──
                  if (isGrouped && item.type === "group") {
                    const isExpanded = ct.expandedGroups?.[item.pathKey] !== undefined;
                    const indent = (item.depth || 0) * 20 + 12;
                    const gcs = isExpanded ? getGroupCheckState(ai, item.depth) : null;
                    return (
                      <div key={`g-${item.pathKey}`} role="row" tabIndex={0}
                        aria-expanded={isExpanded}
                        onKeyDown={(e) => activateOnKey(e, () => isExpanded ? collapseGroup(item.pathKey) : expandGroup(item.pathKey, item.filters, item.depth + 1))}
                        onClick={() => isExpanded ? collapseGroup(item.pathKey) : expandGroup(item.pathKey, item.filters, item.depth + 1)}
                        style={{ display: "flex", alignItems: "center", height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT - (pageOffset || 0), width: tw, boxSizing: "border-box", background: th.bgAlt, cursor: "pointer", borderBottom: `1px solid ${th.border}`, paddingLeft: indent, gap: 8 }}>
                        {isExpanded && gcs && gcs.total > 0 && (
                          <button type="button" onClick={(e) => { e.stopPropagation(); handleGroupSelectAll(ai); }}
                            aria-label={`Select all rows in ${item.colName} ${item.value || "empty"}`}
                            style={{ width: 26, height: 26, padding: 0, border: "none", background: "none", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", flexShrink: 0 }}>
                            <CheckboxIcon
                              checked={gcs.selected === gcs.total}
                              indeterminate={gcs.selected > 0 && gcs.selected < gcs.total} />
                          </button>
                        )}
                        <span style={{ color: th.accent, fontSize: 11, width: 14, textAlign: "center", flexShrink: 0 }}>{isExpanded ? "▼" : "▶"}</span>
                        <span style={{ color: th.text, fontSize: 12, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{item.colName}:</span>
                        <span style={{ color: th.text, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{item.value || "(empty)"}</span>
                        <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>— {formatNumber(item.count)} rows</span>
                      </div>
                    );
                  }

                  // ── Grouped mode: "load more" indicator ──
                  if (isGrouped && item.type === "more") {
                    const indent = (item.depth || 0) * 20 + 32;
                    const remaining = item.total - item.loaded;
                    return (
                      <div key={`m-${item.pathKey}`} style={{ height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT - (pageOffset || 0), display: "flex", alignItems: "center", paddingLeft: indent, color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif", gap: 8 }}>
                        <span style={{ fontStyle: "italic" }}>Showing {formatNumber(item.loaded)} of {formatNumber(item.total)}</span>
                        <button onClick={() => loadMoreGroupRows(item.pathKey, false)}
                          style={{ minHeight: 24, background: th.accent + "22", color: th.accent, border: `1px solid ${th.accent}44`, borderRadius: 3, padding: "2px 8px", fontSize: 11, cursor: "pointer", fontFamily: "inherit" }}>
                          Load more ({formatNumber(Math.min(remaining, 100000))})</button>
                        {remaining > 100000 && <button onClick={() => loadMoreGroupRows(item.pathKey, true)}
                          style={{ minHeight: 24, background: th.warning + "22", color: th.warning, border: `1px solid ${th.warning}44`, borderRadius: 3, padding: "2px 8px", fontSize: 11, cursor: "pointer", fontFamily: "inherit" }}>
                          Load all ({formatNumber(remaining)})</button>}
                      </div>
                    );
                  }

                  // ── Data row (both grouped and ungrouped) ──
                  const rowDepth = isGrouped ? (item.depth || 0) : 0;
                  const row = isGrouped ? item.data : item;
                  if (!row || !row.__idx) return null;
                  const rTags = ct.rowTags?.[row.__idx] || [];
                  const cm = applyColors(row, compiledColors);
                  const bm = ct.bookmarkedSet?.has(row.__idx);
                  const sel = isRowSelected(selectedRows, allRowsSelected, row.__idx);
                  const rowBg = getRowBg(ai, row, sel, cm, bm);

                  // Evidence pill focus: dim rows that don't carry the active pill
                  const _pillFilter = ct.evidencePillFilter;
                  const _pillDimmed = _pillFilter && !(ct.evidencePillsByRowid?.[row.__idx] || []).some(p => p.text === _pillFilter);

                  // Opaque base for sticky cells (selection/bookmark overlays are semi-transparent)
                  const stickyBase = cm ? cm.bg : (ai % 2 === 0 ? th.rowEven : th.rowOdd);
                  const stickyOverlay = sel ? `inset 0 0 0 9999px ${th.selection}` : bm ? `inset 0 0 0 9999px ${th.bookmark}` : "none";

                  return (
                    <div key={row.__idx} data-row-id={row.__idx} data-row-index={ai} role="row" aria-rowindex={ai + 2} aria-selected={!!sel}
                      tabIndex={selectedRow === ai || (selectedRow === null && vi === 0) ? 0 : -1}
                      onKeyDown={(e) => activateOnKey(e, (keyEvent) => handleRowClick(ai, keyEvent))}
                      onClick={(e) => handleRowClick(ai, e)}
                      onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
                      style={{ display: "flex", height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT - (pageOffset || 0), width: tw, boxSizing: "border-box",
                        background: rowBg, color: cm ? cm.fg : th.text, borderBottom: `1px solid ${th.cellBorder}`,
                        boxShadow: sel ? `inset 2px 0 0 0 ${th.borderAccent}` : "none", cursor: "default",
                        paddingLeft: isGrouped ? 16 : 0, opacity: _pillDimmed ? 0.25 : 1, transition: "opacity var(--m-base)" }}>
                      {/* Bookmark - always sticky */}
                      <div role="gridcell" style={{ display: "flex", alignItems: "center", justifyContent: "center", width: isGrouped ? 26 : BKMK_COL_WIDTH, minWidth: isGrouped ? 26 : BKMK_COL_WIDTH, boxSizing: "border-box", position: "sticky", left: isGrouped ? 16 : 0, zIndex: 3, background: stickyBase, boxShadow: stickyOverlay }}>
                        <button type="button" aria-label={`${bm ? "Remove" : "Add"} bookmark for row ${ai + 1}`} aria-pressed={!!bm}
                          onClick={(e) => { e.stopPropagation(); handleBookmark(row.__idx); }}
                          style={{ width: 26, height: 26, padding: 0, display: "flex", alignItems: "center", justifyContent: "center", background: "none", border: "none", cursor: "pointer" }}>
                          <BkmkIcon filled={bm} />
                        </button>
                      </div>
                      {/* Checkbox cell */}
                      <div role="gridcell" style={{ display: "flex", alignItems: "center", justifyContent: "center", width: CHECKBOX_COL_WIDTH, minWidth: CHECKBOX_COL_WIDTH, boxSizing: "border-box", position: "sticky", left: isGrouped ? 42 : BKMK_COL_WIDTH, zIndex: 3, background: stickyBase, boxShadow: stickyOverlay }}>
                        <button type="button" aria-label={`${sel ? "Deselect" : "Select"} row ${ai + 1}`} aria-pressed={!!sel}
                          onClick={(e) => { e.stopPropagation(); handleCheckboxToggle(ai); }}
                          style={{ width: 26, height: 26, padding: 0, display: "flex", alignItems: "center", justifyContent: "center", background: "none", border: "none", cursor: "pointer" }}>
                          <CheckboxIcon checked={sel} />
                        </button>
                      </div>
                      {/* Tags cell — sticky */}
                      <div role="gridcell" style={{ display: "flex", alignItems: "center", gap: 2, width: tagColWidth, minWidth: tagColWidth, boxSizing: "border-box", padding: "0 4px", overflow: "hidden", borderRight: `1px solid ${th.cellBorder}`, position: "sticky", left: isGrouped ? 42 + CHECKBOX_COL_WIDTH : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH), zIndex: 2, background: stickyBase, boxShadow: stickyOverlay }}>
                        {rTags.map((tag) => (
                          <span key={tag} style={{ padding: "0 4px", borderRadius: 3, fontSize: 11, background: ((ct.tagColors || {})[tag] || th.textMuted) + "33", color: (ct.tagColors || {})[tag] || th.textDim, whiteSpace: "nowrap", lineHeight: "18px" }}>{tag}</span>
                        ))}
                      </div>
                      {/* VT verdict cell — sticky, after tags */}
                      {ct.vtEnrichment && (() => {
                        const vte = ct.vtEnrichment;
                        // Collect all IOC verdicts for this row + track worst for badge
                        let worstVerdict = null, worstScore = "", worstUrl = null;
                        const iocDetails = [];
                        for (const tag of rTags) {
                          if (!tag.startsWith("IOC: ")) continue;
                          const iocRaw = tag.slice(5);
                          const vtr = vte.results[iocRaw];
                          if (!vtr) continue;
                          iocDetails.push({ ioc: iocRaw, verdict: vtr.verdict, score: vtr.score, url: vtr.vtUrl, threatLabel: vtr.threatLabel });
                          if (vtr.verdict === "malicious" && worstVerdict !== "malicious") { worstVerdict = "malicious"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
                          else if (vtr.verdict === "suspicious" && worstVerdict !== "malicious" && worstVerdict !== "suspicious") { worstVerdict = "suspicious"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
                          else if (vtr.verdict === "clean" && !worstVerdict) { worstVerdict = "clean"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
                          else if (vtr.verdict === "not_found" && !worstVerdict) { worstVerdict = "not_found"; worstScore = vtr.score; worstUrl = vtr.vtUrl; }
                          else if (vtr.verdict === "error" && !worstVerdict) { worstVerdict = "error"; worstScore = vtr.score || "Error"; worstUrl = vtr.vtUrl; }
                          else if (vtr.verdict === "unsupported" && !worstVerdict) { worstVerdict = "unsupported"; worstScore = vtr.score || "N/A"; worstUrl = null; }
                          else if (vtr.verdict === "private" && !worstVerdict) { worstVerdict = "private"; worstScore = vtr.score || "Private"; worstUrl = null; }
                        }
                        const vtColor = worstVerdict === "malicious" ? th.danger : worstVerdict === "suspicious" ? th.warning : worstVerdict === "clean" ? th.success : worstVerdict === "error" ? th.danger : th.textMuted;
                        const tooltip = iocDetails.length > 0 ? iocDetails.map((d) => `${d.ioc} → ${d.verdict} (${d.score})${d.threatLabel ? ` [${d.threatLabel}]` : ""}`).join("\n") : "";
                        const worstThreat = iocDetails.find((d) => d.verdict === worstVerdict && d.threatLabel)?.threatLabel || null;
                        
                        return (
                          <div role="gridcell" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 3, width: vtW, minWidth: 40, boxSizing: "border-box", borderRight: `1px solid ${th.cellBorder}`, position: "sticky", left: (isGrouped ? 42 + CHECKBOX_COL_WIDTH : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH)) + tagColWidth, zIndex: 2, background: stickyBase, boxShadow: stickyOverlay, overflow: "hidden" }}>
                            {worstVerdict && (
                              <Tooltip content={tooltip} maxWidth={420}>
                                <span
                                  onClick={worstUrl ? (e) => { e.stopPropagation(); window.open(worstUrl, "_blank"); } : undefined}
                                  style={{ fontSize: 11, padding: "1px 4px", borderRadius: 3, fontWeight: 700, fontFamily: "'SF Mono', Menlo, monospace",
                                    background: `${vtColor}22`, color: vtColor, border: `1px solid ${vtColor}44`, lineHeight: "14px",
                                    cursor: worstUrl ? "pointer" : "default", flexShrink: 0 }}>
                                  {worstScore}
                                </span>
                              </Tooltip>
                            )}
                            {worstThreat && vtW > 90 && (
                              <Tooltip content={worstThreat}>
                                <span style={{ fontSize: 11, color: vtColor, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontStyle: "italic" }}>{worstThreat}</span>
                              </Tooltip>
                            )}
                          </div>
                        );
                      })()}
                      {/* Evidence pills cell — sticky, after VT */}
                      {(() => {
                        const pillsMap = ct.evidencePillsByRowid;
                        if (!pillsMap || Object.keys(pillsMap).length === 0) return null;
                        const evW = ct.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;
                        
                        
                        const rowPills = pillsMap[row.__idx];
                        return (
                          <div role="gridcell" style={{ display: "flex", alignItems: "center", gap: 3, width: evW, minWidth: EVIDENCE_COL_MIN_WIDTH, boxSizing: "border-box", padding: "0 6px", overflow: "hidden", borderRight: `1px solid ${th.cellBorder}`, position: "sticky", left: leftBase, zIndex: 2, background: stickyBase, boxShadow: stickyOverlay }}>
                            {rowPills && rowPills.map((p, pi) => (
                              <Badge key={pi} size="sm" tone={pillToneFor(p.type)} title={`${p.type} — click to highlight`}
                                style={{ cursor: "pointer" }}
                                onClick={(ev) => { ev.stopPropagation(); up("evidencePillFilter", ct.evidencePillFilter === p.text ? null : p.text); }}>
                                {p.text}
                              </Badge>
                            ))}
                          </div>
                        );
                      })()}
                      {/* Pinned data cells */}
                      {pinnedH.map((h) => (
                        <div key={h} data-cell-col={h} role="gridcell" onDoubleClick={() => setCellPopup({ column: h, value: row[h] || "" })} title={fmtCell(h, row[h])}
                          onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.stopPropagation(); setCellContextMenu({ x: e.clientX, y: e.clientY, colName: h, cellValue: row[h] || "" }); } }}
                          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
                          style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}44` : `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 2, background: selectedColumn === h ? `linear-gradient(${th.accent}26, ${th.accent}26), ${stickyBase}` : stickyBase, boxShadow: stickyOverlay }}>
                          {renderCell(h, row[h])}
                        </div>
                      ))}
                      {/* Scrollable data cells */}
                      {scrollH.map((h) => (
                        <div key={h} data-cell-col={h} role="gridcell" onDoubleClick={() => setCellPopup({ column: h, value: row[h] || "" })} title={fmtCell(h, row[h])}
                          onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.stopPropagation(); setCellContextMenu({ x: e.clientX, y: e.clientY, colName: h, cellValue: row[h] || "" }); } }}
                          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
                          style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5, background: selectedColumn === h ? `${th.accent}1f` : undefined }}>
                          {renderCell(h, row[h])}
                        </div>
                      ))}
                    </div>
                  );
                })}
                {/* Skeleton placeholder rows shown during fast scroll when data is loading */}
                {skeletonIndices.length > 0 && skeletonIndices.map((ai) => (
                  <div key={`sk-${ai}`} style={{ display: "flex", alignItems: "center", height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT - (pageOffset || 0), width: tw, boxSizing: "border-box", borderBottom: `1px solid ${th.cellBorder}`, background: ai % 2 === 0 ? th.rowEven : th.rowOdd, gap: 12, paddingLeft: BKMK_COL_WIDTH + tagColWidth + 8 }}>
                    <div style={{ width: 50, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 130, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 40, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 90, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 70, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 180, height: 8, background: th.border, borderRadius: 3 }} />
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Row Detail Panel */}
          {detailVisible && (
            <div ref={detailPanelRef} style={{ height: detailPanelHeight, borderTop: `1px solid ${th.borderAccent}66`, background: th.bg, boxShadow: `0 -8px 24px rgba(0,0,0,0.18), 0 -1px 0 ${th.borderAccent}22`, display: "flex", flexDirection: "column", flexShrink: 0, position: "relative" }}>
              {/* Drag handle for resizing */}
              <div onMouseDown={onDetailResizeStart} style={{ position: "absolute", top: -4, left: 0, right: 0, height: 8, cursor: "row-resize", zIndex: 20, display: "flex", justifyContent: "center", alignItems: "flex-end", paddingBottom: 1 }}>
                <div style={{ width: 36, height: 3, borderRadius: 2, background: th.textMuted + "55" }} />
              </div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "4px 12px", background: th.toolbarBg, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", borderBottom: `1px solid ${th.glassBorder}`, flexShrink: 0 }}>
                <span style={{ color: th.accent, fontSize: 11, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                  Row Detail — Row {selectedRow + 1} (ID: {selectedRowData.__idx})
                  {selectedRowData.LineNumber ? ` · line ${selectedRowData.LineNumber}` : ""}
                </span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  {onFilterToSession && selectedRowData.SessionId && isAiHistorySourceFormat(ct?.sourceFormat) && (
                    <button
                      type="button"
                      onClick={() => onFilterToSession(selectedRowData.SessionId)}
                      title="Filter grid to this SessionId"
                      style={{ background: th.bgAlt, border: `1px solid ${th.border}`, color: th.accent, cursor: "pointer", fontSize: 10, padding: "2px 8px", borderRadius: 4 }}
                    >
                      Filter session
                    </button>
                  )}
                  {onCorrelateWorkspace && (selectedRowData.Workspace || selectedRowData.SourceFile) && isAiHistorySourceFormat(ct?.sourceFormat) && (
                    <button
                      type="button"
                      onClick={() => onCorrelateWorkspace(selectedRowData.Workspace, selectedRowData.SourceFile)}
                      title="Filter open Prefetch, EVTX, or Amcache tabs by this workspace path"
                      style={{ background: th.bgAlt, border: `1px solid ${th.border}`, color: th.accent, cursor: "pointer", fontSize: 10, padding: "2px 8px", borderRadius: 4 }}
                    >
                      Correlate path
                    </button>
                  )}
                  {selectedRowData.SourceFile && tle?.openAiSource && (
                    <button
                      type="button"
                      onClick={async () => {
                        const r = await tle.openAiSource(selectedRowData.SourceFile, selectedRowData.LineNumber || "");
                        if (isIpcError(r)) toast.error("Open source failed", { detail: ipcErrorMessage(r) });
                      }}
                      title="Open source file in the default app (JSONL line shown in header when available)"
                      style={{ background: th.bgAlt, border: `1px solid ${th.border}`, color: th.text, cursor: "pointer", fontSize: 10, padding: "2px 8px", borderRadius: 4 }}
                    >
                      Open source
                    </button>
                  )}
                  <button onClick={() => setDetailPanelOpen(false)} aria-label="Close row detail" title="Close row detail" style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, padding: "2px 6px" }}>✕</button>
                </div>
              </div>
              <div style={{ flex: 1, overflow: "auto", padding: "4px 12px" }}>
                {isAiHistorySourceFormat(ct?.sourceFormat) && aiHistoryDetailPinnedFields(selectedRowData).length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, padding: "6px 0 10px", marginBottom: 6, borderBottom: `1px solid ${th.border}` }}>
                    {aiHistoryDetailPinnedFields(selectedRowData).map(({ field, label, value }) => (
                      <span
                        key={field}
                        title={`${label}: ${value}`}
                        style={{
                          fontSize: 10,
                          padding: "2px 8px",
                          borderRadius: 4,
                          background: th.bgAlt,
                          border: `1px solid ${th.border}`,
                          color: th.text,
                          fontFamily: "-apple-system, sans-serif",
                        }}
                      >
                        <span style={{ color: th.textMuted, marginRight: 4 }}>{label}</span>
                        <span style={{ fontFamily: "'SF Mono', Menlo, monospace" }}>{value}</span>
                      </span>
                    ))}
                  </div>
                )}
                {(isAiHistorySourceFormat(ct?.sourceFormat) ? aiHistoryDetailHeaderOrder(ct.headers) : ct.headers).map((h) => (
                  <div key={h} style={{ display: "flex", gap: 12, padding: "3px 0", borderBottom: `1px solid ${th.bgAlt}`, alignItems: "flex-start" }}>
                    <span style={{ width: 180, minWidth: 180, fontWeight: 600, color: ct.hiddenColumns.has(h) ? th.textMuted : th.textDim, fontSize: 11, flexShrink: 0, fontFamily: "-apple-system, sans-serif" }}>
                      {h}{ct.hiddenColumns.has(h) && <span style={{ fontSize: 11, marginLeft: 4, color: th.textMuted }}>(hidden)</span>}
                    </span>
                    <span style={{ flex: 1, color: th.text, fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
                      {isAiHistorySourceFormat(ct?.sourceFormat)
                        ? aiHistoryDetailCellValue(selectedRowData, h) || fmtCell(h, selectedRowData[h])
                        : fmtCell(h, selectedRowData[h])}
                    </span>
                    <button aria-label={`Copy ${h} value`} onClick={() => copyCell(selectedRowData[h], h)} style={{ width: 26, height: 26, background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 11, flexShrink: 0, padding: 0 }} title="Copy value">
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Warning placeholder removed — no row cap */}
        </>
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}><Loading /></div>
      )}
    </>
  );
}
