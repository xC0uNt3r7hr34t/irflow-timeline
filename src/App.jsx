import { lazy, Suspense, useState, useEffect, useRef, useCallback, useMemo, Fragment } from "react";
import { createPortal } from "react-dom";
// ── Extracted constants ──────────────────────────────────────────
import { ROW_HEIGHT, HEADER_HEIGHT, FILTER_HEIGHT, OVERSCAN, VIRTUAL_WINDOW, VIRTUAL_AHEAD, QUERY_DEBOUNCE, DETAIL_PANEL_HEIGHT_DEFAULT, DETAIL_PANEL_MIN_HEIGHT, DETAIL_PANEL_MAX_HEIGHT, TAG_COL_WIDTH_DEFAULT, TAG_COL_WIDTH_MIN, BKMK_COL_WIDTH, CHECKBOX_COL_WIDTH, VT_COL_WIDTH, EVIDENCE_COL_WIDTH, VT_COMPATIBLE_RE, MAX_PHYSICAL_H } from "./constants/grid.js";
import { THEMES } from "./constants/themes.js";
import { DT_FORMATS, TIMEZONES } from "./constants/datetime.js";
import { TAG_PRESETS } from "./constants/presets.js";

// ── Extracted utilities ──────────────────────────────────────────
import { formatBytes, formatNumber } from "./utils/format.js";
import { formatDateTime } from "./utils/datetime.js";
import { isIpcCancelled, isIpcError, ipcErrorMessage } from "./utils/ipc-result";
import { compileColorRules, applyColors, buildTimelineColorRules } from "./utils/color-rules.js";
import { detectKapeProfile, isChainsawDataset, isChainsawProcessDataset, isChainsawLogonDataset } from "./utils/dataset-detect.js";
import {
  checkboxFilterActive,
  isAiHistorySourceFormat,
  aiHistoryQueryIpcOptions,
  normalizeCheckboxFilterValues,
  resolveAiWorkspacePath,
  buildWorkspaceCorrelationTargets,
} from "./utils/ai-history-profile.js";
import { handleOpenFileDialogResult } from "./utils/open-file-result.js";
import { IOC_CATEGORY_PATTERNS } from "./utils/ioc-parsing.js";
import { getGridBodyViewportHeight, getGridContentWidth, getRowScrollTarget, getVisibleRowRange } from "./utils/grid-layout.js";
import { getSelectedRowCount, isRowSelected, selectRowIds, toggleRowSelection } from "./utils/row-selection.js";
import { effectiveSearchTerm, isSearchTooShort } from "./utils/search.js";
import { mod } from "./utils/shortcut-label.js";

// ── Extracted components ─────────────────────────────────────────
import { BkmkIcon, CheckboxIcon } from "./components/icons.jsx";
import TabBar from "./components/TabBar.jsx";
import FilterBar, { SearchOptionsBar } from "./components/FilterBar.jsx";
import StatusBar from "./components/StatusBar.jsx";
import SelectionBar from "./components/SelectionBar.jsx";
import { Overlay, ColorModal, ColModal, ShortModal, SheetModal, ImportProgress, makeModalStyles } from "./components/InlineModals.jsx";
import { ConfirmDialog, ToastContainer, Loading } from "./components/primitives/index.js";
import useToastStore, { toast } from "./store/useToastStore.js";
import { ProcessAnalyzerRoot } from "./components/process-analyzer/index.js";
import {
  openColumnStatsModal,
  openIocLoadModal,
  openLateralMovementModal,
	  openProximityModal,
	  openSigmaModal,
  openSimpleModal,
  openStackingModal,
  openAiWorkspaceCorrelateModal,
  openAiHistoryProfileScanModal,
  updateModal,
} from "./modals/modalRegistry.js";
import { HOME_CAPABILITY_LAUNCHERS, buildLateralMovementCols } from "./utils/analyzer-launch.js";

// ── Custom hooks ────────────────────────────────────────────────
import useColumnOps from "./hooks/useColumnOps.js";

// ── Zustand stores ───────────────────────────────────────────────
import useUIStore from "./store/useUIStore.js";
import useTabStore from "./store/useTabStore.js";
import useGridInteractionStore from "./store/useGridInteractionStore.js";
import packageJson from "../package.json";

const APP_VERSION = packageJson.version;
const APP_DESCRIPTION = packageJson.description;

const MenuBar = lazy(() => import("./components/MenuBar.jsx"));
const VirtualGrid = lazy(() => import("./components/VirtualGrid.jsx"));
const LateralMovementModal = lazy(() => import("./components/modals/LateralMovementModal.jsx"));
const TriageCollectionModal = lazy(() => import("./components/modals/TriageCollectionModal.jsx"));
const PersistenceModal = lazy(() => import("./components/modals/PersistenceModal.jsx"));
const RansomwareModal = lazy(() => import("./components/modals/RansomwareModal.jsx"));
const UsnAnalysisModal = lazy(() => import("./components/modals/UsnAnalysisModal.jsx"));
const IocModal = lazy(() => import("./components/modals/IocModal.jsx"));
const GapAnalysisModal = lazy(() => import("./components/modals/GapAnalysisModal.jsx"));
const LogSourceCoverageModal = lazy(() => import("./components/modals/LogSourceCoverageModal.jsx"));
const BurstAnalysisModal = lazy(() => import("./components/modals/BurstAnalysisModal.jsx"));
const TimestompingModal = lazy(() => import("./components/modals/TimestompingModal.jsx"));
const HeatmapModal = lazy(() => import("./components/modals/HeatmapModal.jsx"));
const AdsModal = lazy(() => import("./components/modals/AdsModal.jsx"));
const StackingModal = lazy(() => import("./components/modals/StackingModal.jsx"));
const ColumnStatsModal = lazy(() => import("./components/modals/ColumnStatsModal.jsx"));
const PresetsModal = lazy(() => import("./components/modals/PresetsModal.jsx"));
const EditFilterModal = lazy(() => import("./components/modals/EditFilterModal.jsx"));
const BulkActionsModal = lazy(() => import("./components/modals/BulkActionsModal.jsx"));
const QuickHelpModal = lazy(() => import("./components/modals/QuickHelpModal.jsx"));
const SigmaRuleModal = lazy(() => import("./components/modals/SigmaRuleModal.jsx"));
const RdpBitmapCacheModal = lazy(() => import("./components/modals/RdpBitmapCacheModal.jsx"));
const AiHistoryProfileScanModal = lazy(() => import("./components/modals/AiHistoryProfileScanModal.jsx"));
const AiHistoryExtractModal = lazy(() => import("./components/modals/AiHistoryExtractModal.jsx"));
const AiWorkspaceCorrelateModal = lazy(() => import("./components/modals/AiWorkspaceCorrelateModal.jsx"));
const AiHistoryScopeModal = lazy(() => import("./components/modals/AiHistoryScopeModal.jsx"));
const AiSecretsModal = lazy(() => import("./components/modals/AiSecretsModal.jsx"));

function ModalChunkFallback({ th }) {
  return (
    <Overlay th={th}>
      <Loading label="Loading tool…" size="md" />
    </Overlay>
  );
}

function ShellChunkFallback({ th, label = "Loading controls…" }) {
  return (
    <div style={{ height: 42, display: "flex", alignItems: "center", padding: "0 14px", borderBottom: `1px solid ${th.border}`, background: th.panelBg }}>
      <Loading label={label} variant="compact" />
    </div>
  );
}

const rowIdFilterSignature = (rowIdFilter) => {
  if (!Array.isArray(rowIdFilter) || rowIdFilter.length === 0) return "";
  const first = rowIdFilter[0];
  const mid = rowIdFilter[Math.floor(rowIdFilter.length / 2)];
  const last = rowIdFilter[rowIdFilter.length - 1];
  let checksum = 0;
  for (const value of rowIdFilter) {
    const id = Number(value) || 0;
    checksum = (checksum + ((id * 2654435761) >>> 0)) >>> 0;
  }
  return `${rowIdFilter.length}:${first}:${mid}:${last}:${checksum}`;
};

const debugRightClick = (message, data = {}) => {
  try {
    if (typeof window !== "undefined") {
      window.tle?.debugLog?.({ scope: "RIGHTCLICK", message, data });
    }
  } catch {}
};

/** Header-only widths — cheap first paint after a multi-GB import. */
function fastColumnWidths(headers) {
  const cw = {};
  for (const h of headers) {
    cw[h] = Math.max(80, Math.min(h.length * 8 + 36, 400));
  }
  return cw;
}

function measureColumnWidths(headers, initialRows) {
  const cw = {};
  const sampleRows = initialRows.slice(0, 100);
  headers.forEach((h) => {
    const hLen = h.length * 8 + 36;
    const lengths = sampleRows.map((r) => (r[h] || "").length).filter((l) => l > 0);
    const meanLen = lengths.length > 0 ? lengths.reduce((a, b) => a + b, 0) / lengths.length : 0;
    const meanPx = meanLen * 6.5 + 16;
    cw[h] = Math.max(80, Math.min(Math.max(hLen, Math.round(meanPx)), 400));
  });
  return cw;
}

const LARGE_TAB_HISTOGRAM_DEFER_MS = 60_000;

function fetchLimitForTab(tab) {
  return VIRTUAL_WINDOW;
}

function fetchAheadForLimit(limit) {
  return Math.max(100, Math.min(VIRTUAL_AHEAD, Math.floor((limit || VIRTUAL_WINDOW) / 3)));
}

function rowWindowCovers(rowOffset, rowCount, firstVisibleRow, visibleRowCount) {
  const start = rowOffset || 0;
  const end = start + (rowCount || 0);
  return firstVisibleRow >= start && firstVisibleRow + visibleRowCount <= end;
}

// ── Main App ───────────────────────────────────────────────────────
export default function App() {
  // ── Zustand: tab state ──────────────────────────────────────────
  const tabs = useTabStore((s) => s.tabs);
  const setTabs = useTabStore((s) => s.setTabs);
  const activeTab = useTabStore((s) => s.activeTab);
  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const tabFilter = useTabStore((s) => s.tabFilter);
  const setTabFilter = useTabStore((s) => s.setTabFilter);
  const importingTabs = useTabStore((s) => s.importingTabs);
  const setImportingTabs = useTabStore((s) => s.setImportingTabs);
  const importQueue = useTabStore((s) => s.importQueue);
  const setImportQueue = useTabStore((s) => s.setImportQueue);

  // ── Zustand: UI state ───────────────────────────────────────────
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const setRefreshCallback = useUIStore((s) => s.setRefreshCallback);
  const dragOver = useUIStore((s) => s.dragOver);
  const setDragOver = useUIStore((s) => s.setDragOver);
  const themeName = useUIStore((s) => s.themeName);
  const setThemeName = useUIStore((s) => s.setThemeName);
  const fontSize = useUIStore((s) => s.fontSize);
  const setFontSize = useUIStore((s) => s.setFontSize);
  const timezone = useUIStore((s) => s.timezone);
  const setTimezone = useUIStore((s) => s.setTimezone);
  const dateTimeFormat = useUIStore((s) => s.dateTimeFormat);
  const setDateTimeFormat = useUIStore((s) => s.setDateTimeFormat);
  const detailPanelOpen = useUIStore((s) => s.detailPanelOpen);
  const setDetailPanelOpen = useUIStore((s) => s.setDetailPanelOpen);
  const detailPanelHeight = useUIStore((s) => s.detailPanelHeight);
  const setDetailPanelHeight = useUIStore((s) => s.setDetailPanelHeight);
  const histogramVisible = useUIStore((s) => s.histogramVisible);
  const setHistogramVisible = useUIStore((s) => s.setHistogramVisible);
  const histogramHeight = useUIStore((s) => s.histogramHeight);
  const setHistogramHeight = useUIStore((s) => s.setHistogramHeight);
  const histGranularity = useUIStore((s) => s.histGranularity);
  const setHistGranularity = useUIStore((s) => s.setHistGranularity);
  const fileMenuOpen = useUIStore((s) => s.fileMenuOpen);
  const setFileMenuOpen = useUIStore((s) => s.setFileMenuOpen);
  const viewMenuOpen = useUIStore((s) => s.viewMenuOpen);
  const setViewMenuOpen = useUIStore((s) => s.setViewMenuOpen);
  const toolsOpen = useUIStore((s) => s.toolsOpen);
  const setToolsOpen = useUIStore((s) => s.setToolsOpen);
  const toolsMenuExpanded = useUIStore((s) => s.toolsMenuExpanded);
  const setToolsMenuExpanded = useUIStore((s) => s.setToolsMenuExpanded);
  const actionsMenuOpen = useUIStore((s) => s.actionsMenuOpen);
  const setActionsMenuOpen = useUIStore((s) => s.setActionsMenuOpen);
  const helpMenuOpen = useUIStore((s) => s.helpMenuOpen);
  const setHelpMenuOpen = useUIStore((s) => s.setHelpMenuOpen);
  // ── Grid interaction state (from store) ──────────────────────────
  const selectedRows = useGridInteractionStore((s) => s.selectedRows);
  const setSelectedRows = useGridInteractionStore((s) => s.setSelectedRows);
  const allRowsSelected = useGridInteractionStore((s) => s.allRowsSelected);
  const setAllRowsSelected = useGridInteractionStore((s) => s.setAllRowsSelected);
  const selectionTabId = useGridInteractionStore((s) => s.selectionTabId);
  const setSelectionTabId = useGridInteractionStore((s) => s.setSelectionTabId);
  const selectAllScopeSignature = useGridInteractionStore((s) => s.selectAllScopeSignature);
  const setSelectAllScopeSignature = useGridInteractionStore((s) => s.setSelectAllScopeSignature);
  const lastClickedRow = useGridInteractionStore((s) => s.lastClickedRow);
  const setLastClickedRow = useGridInteractionStore((s) => s.setLastClickedRow);
  const detailPanelRef = useRef(null);
  const detailResizeStartY = useRef(0);
  const detailResizeStartH = useRef(0);
  const copiedMsg = useGridInteractionStore((s) => s.copiedMsg);
  const setCopiedMsg = useGridInteractionStore((s) => s.setCopiedMsg);
  const cellPopup = useGridInteractionStore((s) => s.cellPopup);
  const setCellPopup = useGridInteractionStore((s) => s.setCellPopup);
  const [searchMatchIdx, setSearchMatchIdx] = useState(-1);
  const searchMatchIdxRef = useRef(-1);
  const searchNavigationPendingRef = useRef(false);
  const [searchMatchPosition, setSearchMatchPosition] = useState(-1);
  const [highlightMatchCount, setHighlightMatchCount] = useState(0);
  const [hiddenSelectionCount, setHiddenSelectionCount] = useState(0);
  const resizingCol = useGridInteractionStore((s) => s.resizingCol);
  const setResizingCol = useGridInteractionStore((s) => s.setResizingCol);
  const resizeX = useGridInteractionStore((s) => s.resizeX);
  const setResizeX = useGridInteractionStore((s) => s.setResizeX);
  const resizeW = useGridInteractionStore((s) => s.resizeW);
  const setResizeW = useGridInteractionStore((s) => s.setResizeW);
  const justResizedRef = useRef(false);

  // ── Context menus + dropdowns (from stores) ────────────────────────
  const contextMenu = useGridInteractionStore((s) => s.contextMenu);
  const setContextMenu = useGridInteractionStore((s) => s.setContextMenu);
  const rowContextMenu = useGridInteractionStore((s) => s.rowContextMenu);
  const setRowContextMenu = useGridInteractionStore((s) => s.setRowContextMenu);
  const cellContextMenu = useGridInteractionStore((s) => s.cellContextMenu);
  const setCellContextMenu = useGridInteractionStore((s) => s.setCellContextMenu);
  const selectedColumn = useGridInteractionStore((s) => s.selectedColumn);
  const setSelectedColumn = useGridInteractionStore((s) => s.setSelectedColumn);
  const searchLoading = useGridInteractionStore((s) => s.searchLoading);
  const setSearchLoading = useGridInteractionStore((s) => s.setSearchLoading);
  // Track search elapsed seconds — used by StatusBar to show extended feedback
  // ("Searching N rows… 3s") for slow LIKE-on-concat scans on huge datasets.
  // Without this, multi-second searches look like a frozen app.
  const [searchElapsed, setSearchElapsed] = useState(0);
  useEffect(() => {
    if (!searchLoading) { setSearchElapsed(0); return; }
    const start = Date.now();
    const id = setInterval(() => setSearchElapsed(Math.floor((Date.now() - start) / 1000)), 500);
    return () => clearInterval(id);
  }, [searchLoading]);
  const tagColWidth = useGridInteractionStore((s) => s.tagColWidth);
  const setTagColWidth = useGridInteractionStore((s) => s.setTagColWidth);
  const [groupDragOver, setGroupDragOver] = useState(false);
  const [groupReorderDrag, setGroupReorderDrag] = useState(null);

  // ── UI state (from useUIStore) ─────────────────────────────────────
  const filterDropdown = useUIStore((s) => s.filterDropdown);
  const setFilterDropdown = useUIStore((s) => s.setFilterDropdown);
  const dateRangeDropdown = useUIStore((s) => s.dateRangeDropdown);
  const setDateRangeDropdown = useUIStore((s) => s.setDateRangeDropdown);
  const crossFind = useUIStore((s) => s.crossFind);
  const setCrossFind = useUIStore((s) => s.setCrossFind);
  const crossTabCounts = useUIStore((s) => s.crossTabCounts);
  const setCrossTabCounts = useUIStore((s) => s.setCrossTabCounts);
  const crossTabOpen = useUIStore((s) => s.crossTabOpen);
  const setCrossTabOpen = useUIStore((s) => s.setCrossTabOpen);
  const extracting = useUIStore((s) => s.extracting);
  const setExtracting = useUIStore((s) => s.setExtracting);
  const extractProgress = useUIStore((s) => s.extractProgress);
  const setExtractProgress = useUIStore((s) => s.setExtractProgress);
  const checkingForUpdates = useUIStore((s) => s.checkingForUpdates);
  const setCheckingForUpdates = useUIStore((s) => s.setCheckingForUpdates);
  const updaterPopup = useUIStore((s) => s.updaterPopup);
  const setUpdaterPopup = useUIStore((s) => s.setUpdaterPopup);
  const recentFiles = useUIStore((s) => s.recentFiles);
  const setRecentFiles = useUIStore((s) => s.setRecentFiles);
  const filterPresets = useUIStore((s) => s.filterPresets);
  const setFilterPresets = useUIStore((s) => s.setFilterPresets);
  const proximityFilter = useUIStore((s) => s.proximityFilter);
  const setProximityFilter = useUIStore((s) => s.setProximityFilter);
  const colMgrSearch = useUIStore((s) => s.colMgrSearch);
  const setColMgrSearch = useUIStore((s) => s.setColMgrSearch);
  const histogramCol = useUIStore((s) => s.histogramCol);
  const setHistogramCol = useUIStore((s) => s.setHistogramCol);
  const histogramData = useUIStore((s) => s.histogramData);
  const setHistogramData = useUIStore((s) => s.setHistogramData);
  const histogramLoaded = useUIStore((s) => s.histogramLoaded);
  const setHistogramLoaded = useUIStore((s) => s.setHistogramLoaded);
  const histogramCache = useRef({}); // { [tabId]: { sig, data } }
  const histDeferUntilRef = useRef({}); // tabId -> epoch ms — defer histogram after large import
  const searchCache = useRef({}); // { [tabId]: { [sig]: { rows, rowOffset, totalFiltered, bookmarkedSet, rowTags } } }
  const histResizeStartY = useRef(0);
  const histResizeStartH = useRef(0);
  const histBrushRef = useRef({ startIdx: null, endIdx: null, active: false });
  const histSvgRectRef = useRef(null);
  const histBrushOverlayRef = useRef(null); // DOM ref for brush overlay rect
  const histBrushLabelRef = useRef(null);   // DOM ref for brush label text
  const histBarGeomRef = useRef({ barW: 1, yAxisW: 44, chartPadT: 4, chartH: 100, len: 0 }); // cached bar geometry for DOM updates
  const [histContainerWidth, setHistContainerWidth] = useState(0);
  const histContainerRef = useRef(null);
  const headerDragOver = useGridInteractionStore((s) => s.headerDragOver);
  const setHeaderDragOver = useGridInteractionStore((s) => s.setHeaderDragOver);
  const [colMgrDragOver, setColMgrDragOver] = useState(null);

  // Filter dropdown internal state (stays local — ephemeral, reset on each open)
  const [fdValues, setFdValues] = useState([]);
  const [fdSampled, setFdSampled] = useState(false);
  const [fdLoading, setFdLoading] = useState(false);
  const [fdSearch, setFdSearch] = useState("");
  const [fdSelected, setFdSelected] = useState(new Set());
  const [fdRegex, setFdRegex] = useState(false);
  const [fdValueMeta, setFdValueMeta] = useState({ totalDistinct: 0, truncated: false });

  const scrollRef = useRef(null);
  const scrollTopRef = useRef(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(typeof window !== "undefined" ? window.innerHeight : 800);
  const rafScroll = useRef(null);
  // Mirrors the per-render scroll mapping (physical<->logical) so callbacks/effects
  // outside the render block can read the current scaleFactor without stale closures.
  const scrollMapRef = useRef({ scaleFactor: 1, logicalScrollTop: 0, pageOffset: 0, physicalH: 0, totalH: 0 });
  const handleScroll = useCallback((e) => {
    if (rafScroll.current) return;
    const top = e.target.scrollTop;
    scrollTopRef.current = top;
    rafScroll.current = requestAnimationFrame(() => {
      rafScroll.current = null;
      setScrollTop(scrollTopRef.current);
    });
  }, []);

  // Track window resize / zoom changes so the grid adapts
  useEffect(() => {
    const onResize = () => setViewportH(window.innerHeight);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);
  const queryTimer = useRef(null);
  const fetchId = useRef(0); // Monotonic counter to discard stale query results
  const ctRef = useRef(null);
  // Latest-closure refs for handlers invoked by the mount-only native-menu IPC effect
  // (deps [tle]). Without these, that effect captures the FIRST render's handlers (when
  // tabs=[]), so the native macOS menu's "Close Tab" wiped every tab and Save/Load
  // Session / Reset Columns / Check for Updates silently no-op'd. Updated each render.
  const closeTabRef = useRef(null);
  const handleSaveSessionRef = useRef(null);
  const handleLoadSessionRef = useRef(null);
  const resetColumnWidthsRef = useRef(null);
  const handleCheckForUpdatesRef = useRef(null);
  const displayRowsRef = useRef([]);
  const isGroupedRef = useRef(false);
  const gridLayoutRef = useRef({
    pinnedH: [],
    scrollH: [],
    pinnedOffsets: { offsets: {}, totalWidth: 0 },
    tagColWidth: TAG_COL_WIDTH_DEFAULT,
    hasEvidencePills: false,
  });
  const rightClickFired = useRef(false);
  const pendingModifiedRightClick = useRef(null);
  const [pendingRestores, setPendingRestores] = useState({});
  // Auto-restore: null = not yet checked; false = no autosave found; object = autosave available
  const [autoRestorable, setAutoRestorable] = useState(null);
  const pendingRestoresRef = useRef({});
  // Home-screen capability intent: set when the user clicks an analyzer tile, consumed
  // at import-complete to auto-open that analyzer. A ref (not state) so the import-complete
  // listener always reads the current value without re-registering.
  const pendingCapabilityRef = useRef(null);
  // Triage-collection hand-off. TriageCollectionModal queues a batch of imports and
  // records the tab ids; once every one of them is terminal (complete OR failed) we open
  // the Lateral Movement Tracker across the successful ones. Tracked here rather than in
  // the modal because the modal closes as soon as the batch is queued.
  const triageBatchRef = useRef(null);
  const pendingTriageBatch = useUIStore((s) => s.pendingTriageBatch);
  const setPendingTriageBatch = useUIStore((s) => s.setPendingTriageBatch);
  useEffect(() => {
    if (!pendingTriageBatch) return;
    triageBatchRef.current = {
      ...pendingTriageBatch,
      pending: new Set((pendingTriageBatch.items || []).map((i) => i.tabId)),
      succeeded: [],
    };
    setPendingTriageBatch(null);
  }, [pendingTriageBatch]);

  /**
   * Mark one tab of the active triage batch terminal. When the last one lands, launch the
   * Lateral Movement Tracker across every tab that imported successfully.
   */
  const _settleTriageBatch = (tabId, ok, tabInfo) => {
    const batch = triageBatchRef.current;
    if (!batch || !batch.pending.has(tabId)) return;
    batch.pending.delete(tabId);
    if (ok) batch.succeeded.push(tabInfo);
    if (batch.pending.size > 0) return;
    triageBatchRef.current = null;
    // The batch is done; retire its "Cancel remaining" toast so it cannot outlive the work.
    if (batch.toastId != null) useToastStore.getState().dismiss(batch.toastId);

    // Sigma lane. Both lanes can be selected, and two modals cannot occupy the screen at
    // once — so if lateral movement is also running, offer Sigma as a toast action rather
    // than stealing focus. The directory arrives pre-authorized and pre-counted, so the
    // wizard opens ready to scan.
    const offerSigma = (viaToast) => {
      if (!batch.sigmaEvtxDir) return;
      const open = () => setModal(openSigmaModal({ scanMode: "evtx-dir", evtxDir: batch.sigmaEvtxDir }));
      if (!viaToast) { open(); return; }
      toast.info("Sigma scan ready", {
        detail: `${batch.sigmaEvtxDir.fileCount} EVTX files from this collection.`,
        ttl: 0,
        actionLabel: "Run Sigma scan",
        onAction: open,
      });
    };

    if (!batch.analyzeAfter || batch.succeeded.length === 0) {
      if (batch.succeeded.length === 0) toast.error("Triage import failed", { detail: "No artifacts could be imported." });
      else offerSigma(false);
      return;
    }
    offerSigma(true);
    // Analyse the richest tab first and correlate the rest through multi-source; the
    // analyzer detects each tab's format independently, so raw EVTX and parsed EvtxECmd
    // can safely sit in the same run.
    const ranked = [...batch.succeeded].sort((a, b) => (b.rowCount || 0) - (a.rowCount || 0));
    const primary = ranked[0];
    const others = ranked.slice(1).map((t) => t.tabId);
    setActiveTab(primary.tabId);
    const { cols, chainsawSyntheticTarget } = buildLateralMovementCols(primary.headers || []);
    setModal(openLateralMovementModal(cols, {
      chainsawSyntheticTarget,
      autoStart: true,
      lmMultiSource: others.length > 0,
      lmSelectedTabIds: others,
    }));
    toast.info("Analyzing collection", {
      detail: `Lateral movement across ${ranked.length} artifact${ranked.length === 1 ? "" : "s"}.`,
    });
  };

  // tabId -> source filePath, captured at import-start so a failed import can offer one-click retry.
  const importPathsRef = useRef({});

  const ct = tabs.find((t) => t.id === activeTab);
  ctRef.current = ct;
  const tle = typeof window !== "undefined" ? window.tle : null;
  const runOpenFileDialog = useCallback(async () => {
    if (!tle) return null;
    const r = await tle.openFileDialog();
    handleOpenFileDialogResult(tle, setModal, r);
    return r;
  }, [tle, setModal]);
  const runImportPaths = useCallback(async (paths) => {
    if (!tle || !paths?.length) return;
    const r = await tle.importFiles(paths);
    if (r?.scopePending) handleOpenFileDialogResult(tle, setModal, r);
  }, [tle, setModal]);
  const th = THEMES[themeName];
  const isGrouped = ct?.groupByColumns?.length > 0;
  const handleCheckForUpdates = async () => {
    if (!tle?.checkForUpdates || checkingForUpdates) return;
    setUpdaterPopup({
      phase: "checking",
      message: "Looking for a newer IRFlow Timeline build...",
      detail: "",
      percent: 0,
      version: null,
      releaseNotes: "",
    });
    setCheckingForUpdates(true);
    try {
      await tle.checkForUpdates();
    } catch (err) {
      setUpdaterPopup({
        phase: "error",
        message: err?.message || "The update check failed.",
        detail: "",
        percent: 0,
        version: null,
        releaseNotes: "",
      });
    }
    finally {
      setCheckingForUpdates(false);
    }
  };
  const handleInstallUpdate = async () => {
    if (!tle?.installUpdate) return;
    setUpdaterPopup((prev) => prev ? {
      ...prev,
      phase: "installing",
      message: "Closing IRFlow Timeline to apply the update...",
      detail: "The app will restart if the update installer starts successfully.",
    } : prev);
    try {
      await tle.installUpdate();
    } catch (err) {
      setUpdaterPopup({
        phase: "error",
        message: err?.message || "The update could not be installed.",
        detail: "",
        percent: 0,
        version: null,
        releaseNotes: "",
      });
    }
  };

  useEffect(() => { pendingRestoresRef.current = pendingRestores; }, [pendingRestores]);

  // ── Export helpers ────────────────────────────────────────────────
  const up = useTabStore((s) => s.up);

  const filterToAiSession = useCallback((sessionId) => {
    if (!ct?.id || !sessionId) return;
    const id = String(sessionId).trim();
    if (!id) return;
    up("columnFilters", { ...(ct.columnFilters || {}), SessionId: id });
    toast.success("Session filter applied", { detail: `Column filter: SessionId contains “${id.length > 48 ? `${id.slice(0, 48)}…` : id}”` });
  }, [ct, up]);

  const correlateAiWorkspace = useCallback((workspace, sourceFile) => {
    const pathStr = resolveAiWorkspacePath(workspace, sourceFile);
    if (!pathStr) {
      toast.warning("No workspace path", { detail: "This row has no resolvable Workspace path to correlate." });
      return;
    }
    const targets = buildWorkspaceCorrelationTargets(useTabStore.getState().tabs, pathStr);
    if (targets.length === 1) {
      const t = targets[0];
      useTabStore.getState().setActiveTab(t.tabId);
      useTabStore.getState().updateTab(t.tabId, {
        columnFilters: { [t.column]: t.value },
        searchHighlight: false,
      });
      toast.success("Correlation filter applied", { detail: `${t.kind}: ${t.hint}` });
      return;
    }
    setModal(openAiWorkspaceCorrelateModal({ path: pathStr, targets }));
  }, [setModal]);

  // ── Export helpers ────────────────────────────────────────────────
  const _downloadFile = (content, filename, mime) => {
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const _toCSV = (rows) => {
    if (!rows.length) return "";
    const keys = Object.keys(rows[0]);
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    return [keys.join(","), ...rows.map((r) => keys.map((k) => esc(r[k])).join(","))].join("\n");
  };

  // ── Query backend ────────────────────────────────────────────────
  const activeFilters = useCallback((tab) => {
    const dis = tab.disabledFilters || new Set();
    const normalizeCbf = (cbf) => Object.fromEntries(
      Object.entries(cbf || {}).map(([k, v]) => [k, normalizeCheckboxFilterValues(v)]),
    );
    if (dis.size === 0) {
      return { columnFilters: tab.columnFilters, checkboxFilters: normalizeCbf(tab.checkboxFilters) };
    }
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: normalizeCbf(Object.fromEntries(
        Object.entries(tab.checkboxFilters || {}).filter(([k]) => !dis.has(k)),
      )),
    };
  }, []);

  // Canonical filter contract shared by the grid, selection actions, DB-backed
  // range selection, and search navigation. Sort is intentionally separate:
  // changing sort order must not change which rows "select all" refers to.
  const currentFilterOptions = useMemo(() => {
    if (!ct) return null;
    const { columnFilters, checkboxFilters } = activeFilters(ct);
    const rawSearch = ct.searchHighlight ? "" : (ct.searchTerm || "");
    const effectiveSearch = effectiveSearchTerm(rawSearch);
    return {
      searchTerm: effectiveSearch,
      searchMode: ct.searchMode,
      searchCondition: ct.searchCondition || "contains",
      columnFilters,
      checkboxFilters,
      bookmarkedOnly: !!ct.showBookmarkedOnly,
      tagFilter: (ct.disabledFilters || new Set()).has("__tags__")
        ? null
        : (ct.tagFilter || null),
      rowIdFilter: ct.rowIdFilter || null,
      dateRangeFilters: ct.dateRangeFilters || {},
      advancedFilters: ct.advancedFilters || [],
    };
  }, [
    ct?.id,
    ct?.searchHighlight,
    ct?.searchTerm,
    ct?.searchMode,
    ct?.searchCondition,
    ct?.columnFilters,
    ct?.checkboxFilters,
    ct?.showBookmarkedOnly,
    ct?.disabledFilters,
    ct?.tagFilter,
    ct?.rowIdFilter,
    ct?.dateRangeFilters,
    ct?.advancedFilters,
    activeFilters,
  ]);

  const currentFilterScopeSignature = useMemo(() => {
    if (!ct || !currentFilterOptions) return "";
    return JSON.stringify({
      tabId: ct.id,
      totalFiltered: ct.totalFiltered || 0,
      ...currentFilterOptions,
      rowIdFilter: rowIdFilterSignature(ct.rowIdFilter),
    });
  }, [ct?.id, ct?.totalFiltered, ct?.rowIdFilter, currentFilterOptions]);

  const clearRowSelection = useCallback(() => {
    setAllRowsSelected(false);
    setSelectionTabId(null);
    setSelectAllScopeSignature(null);
    setSelectedRows(new Set());
    setLastClickedRow(null);
    setHiddenSelectionCount(0);
  }, [
    setAllRowsSelected,
    setSelectionTabId,
    setSelectAllScopeSignature,
    setSelectedRows,
    setLastClickedRow,
  ]);

  // Programmatic tab changes (cross-tab search, closing a tab, import restore)
  // bypass TabBar's per-tab restoration. Never let stable row IDs from one
  // SQLite database silently become selections in another.
  useEffect(() => {
    if (selectionTabId && ct?.id && selectionTabId !== ct.id) clearRowSelection();
  }, [selectionTabId, ct?.id, clearRowSelection]);

  // Select-all is bound to the exact filter population that was visible when
  // it was activated. A later filter change clears it instead of silently
  // retargeting a different (potentially destructive) population.
  useEffect(() => {
    if (!allRowsSelected || !currentFilterScopeSignature) return;
    if (!selectAllScopeSignature) {
      setSelectAllScopeSignature(currentFilterScopeSignature);
      return;
    }
    if (selectAllScopeSignature !== currentFilterScopeSignature) {
      clearRowSelection();
      toast.info("Selection cleared because the filtered view changed.");
    }
  }, [
    allRowsSelected,
    selectAllScopeSignature,
    currentFilterScopeSignature,
    setSelectAllScopeSignature,
    clearRowSelection,
  ]);

  // Explicit selections persist across filters and sorts. Resolve their
  // visible/hidden split in SQLite so the UI never implies that hidden rows
  // were dropped from the selection.
  useEffect(() => {
    if (!tle || !ct || !currentFilterOptions || (selectionTabId && selectionTabId !== ct.id) || allRowsSelected || selectedRows.size === 0) {
      setHiddenSelectionCount(0);
      return;
    }
    let cancelled = false;
    tle.countRowsByIdsMatching(ct.id, [...selectedRows], currentFilterOptions)
      .then((result) => {
        if (cancelled || isIpcError(result)) return;
        const matching = Math.max(0, Math.min(selectedRows.size, Number(result?.matching) || 0));
        setHiddenSelectionCount(selectedRows.size - matching);
      })
      .catch(() => {
        if (!cancelled) setHiddenSelectionCount(0);
      });
    return () => { cancelled = true; };
  }, [
    tle,
    ct?.id,
    currentFilterOptions,
    currentFilterScopeSignature,
    selectionTabId,
    allRowsSelected,
    selectedRows,
  ]);

  const fetchData = useCallback(async (tab, centerRow = 0) => {
    if (!tle || !tab) return;
    // Stale request prevention: capture current fetch ID before async work
    const myFetchId = ++fetchId.current;
    // Skip query for single-character searches (too broad, expensive on large datasets)
    const rawSearch = tab.searchHighlight ? "" : tab.searchTerm;
    const effectiveSearch = effectiveSearchTerm(rawSearch);
    const { columnFilters, checkboxFilters } = activeFilters(tab);
    const rowIdSig = rowIdFilterSignature(tab.rowIdFilter);
    // Build cache key for this query configuration
    const cacheKey = `${effectiveSearch}|${tab.searchMode}|${tab.sortCol}|${tab.sortDir}|${tab.showBookmarkedOnly}|${tab.searchCondition || "contains"}|${tab.tagFilter || ""}|${rowIdSig}|${JSON.stringify(tab.dateRangeFilters)}|${JSON.stringify(tab.advancedFilters)}|${JSON.stringify(columnFilters)}|${JSON.stringify(checkboxFilters)}`;
    if (tab.groupByColumns?.length > 0) {
      const groupCol = tab.groupByColumns[0];
      const groupData = await tle.getGroupValues(tab.id, groupCol, {
        searchTerm: effectiveSearch, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters, checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        parentFilters: [],
      });
      if (fetchId.current !== myFetchId) return; // Stale — newer fetch in flight
      if (isIpcCancelled(groupData)) {
        setSearchLoading(false);
        return;
      }
      if (isIpcError(groupData)) {
        toast.error("Group failed", { detail: ipcErrorMessage(groupData, "Could not load groups") });
        setSearchLoading(false);
        return;
      }
      const safeGroupData = Array.isArray(groupData) ? groupData : [];
      setTabs((prev) => prev.map((t) =>
        t.id === tab.id ? { ...t, groupData: safeGroupData, expandedGroups: {}, dataReady: true } : t
      ));
      setSearchLoading(false);
      return;
    }
    // Check search cache (instant FL/HL toggle and tab switching)
    const tabCache = searchCache.current[tab.id];
    if (tabCache && tabCache[cacheKey] && centerRow === 0) {
      const cached = tabCache[cacheKey];
      setTabs((prev) => prev.map((t) =>
        t.id === tab.id ? { ...t, rows: cached.rows, rowOffset: cached.rowOffset, totalFiltered: cached.totalFiltered, bookmarkedSet: cached.bookmarkedSet, rowTags: cached.rowTags, dataReady: true } : t
      ));
      setSearchLoading(false);
      return;
    }
    const aiHist = isAiHistorySourceFormat(tab.sourceFormat);
    const fetchLimit = fetchLimitForTab(tab);
    const knownTotal = Number.isFinite(tab.totalFiltered) && tab.totalFiltered > 0
      ? tab.totalFiltered
      : (Number.isFinite(tab.totalRows) ? tab.totalRows : 0);
    const maxOffset = knownTotal > fetchLimit ? knownTotal - fetchLimit : 0;
    const fetchOffset = Math.max(0, Math.min(maxOffset, centerRow - Math.floor(fetchLimit / 2)));
    const result = await tle.queryRows(tab.id, {
      offset: fetchOffset, limit: fetchLimit,
      ...(aiHist ? aiHistoryQueryIpcOptions() : {}),
      sortCol: tab.sortCol, sortDir: tab.sortDir,
      searchTerm: effectiveSearch, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
      columnFilters, checkboxFilters,
      bookmarkedOnly: tab.showBookmarkedOnly,
      tagFilter: (tab.disabledFilters || new Set()).has("__tags__") ? null : (tab.tagFilter || null),
      rowIdFilter: tab.rowIdFilter || null,
      dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
    });
    if (fetchId.current !== myFetchId) return; // Stale — newer fetch in flight
    if (isIpcCancelled(result)) {
      setSearchLoading(false);
      return;
    }
    // A worker/SQL failure resolves queryRows with {__ipcError} (it is NOT a rejection),
    // so guard before caching/writing tab state — otherwise the grid blanks to `undefined`
    // rows and the failed result poisons the filter-signature cache (re-shown on FL/HL
    // toggle), swallowing the message. Surface the error and keep the previously loaded rows.
    if (isIpcError(result) || !Array.isArray(result?.rows)) {
      setSearchLoading(false);
      toast.error("Query failed", { detail: ipcErrorMessage(result, "Could not load rows") });
      return;
    }
    // Cache only initial/filter loads (centerRow===0), NOT scroll-driven fetches,
    // to prevent stale offset data from being returned on scroll-back
    if (centerRow === 0) {
      if (!searchCache.current[tab.id]) searchCache.current[tab.id] = {};
      const tc = searchCache.current[tab.id];
      const keys = Object.keys(tc);
      if (keys.length >= 4) delete tc[keys[0]];
      tc[cacheKey] = { rows: result.rows, rowOffset: fetchOffset, totalFiltered: result.totalFiltered, bookmarkedSet: new Set(result.bookmarkedRows), rowTags: result.rowTags || {} };
    }
    setTabs((prev) => prev.map((t) =>
      t.id === tab.id ? { ...t, rows: result.rows, rowOffset: fetchOffset, totalFiltered: result.totalFiltered, bookmarkedSet: new Set(result.bookmarkedRows), rowTags: result.rowTags || {}, dataReady: true } : t
    ));
    setSearchLoading(false);
  }, [tle]);

  // Expose fetchData to extracted modals via the UI store
  useEffect(() => { setRefreshCallback(fetchData); }, [fetchData, setRefreshCallback]);

  const debouncedFetch = useCallback((tab) => {
    if (queryTimer.current) clearTimeout(queryTimer.current);
    queryTimer.current = setTimeout(() => fetchData(tab), QUERY_DEBOUNCE);
  }, [fetchData]);

  // Cleanup debounce timer on unmount to prevent stale callbacks
  useEffect(() => () => {
    if (queryTimer.current) clearTimeout(queryTimer.current);
    if (rafScroll.current) cancelAnimationFrame(rafScroll.current);
  }, []);

  // Debounced deps (typing: search term, column filters) — use useMemo to avoid JSON.stringify per render
  const debouncedDeps = useMemo(() => {
    const cf = ct?.columnFilters;
    return `${ct?.searchTerm}|${ct?.searchMode}|${cf ? Object.keys(cf).sort().map(k => `${k}=${cf[k]}`).join(",") : ""}`;
  }, [ct?.searchTerm, ct?.searchMode, ct?.columnFilters]);
  const prevDebouncedDeps = useRef(debouncedDeps);
  const lastFilterTabId = useRef(null); // distinguishes in-tab filter changes from tab switches

  // Immediate deps (discrete actions: sort, bookmark toggle, checkbox filters, grouping, date range, highlight)
  const immediateDeps = useMemo(() => {
    const cbf = ct?.checkboxFilters;
    // Signature must reflect the actual selected VALUES, not just how many — otherwise
    // changing a column's filter from one value to another of the same count (e.g. IP A → IP B)
    // produces an identical signature and the refetch effect never fires. Mirrors drfSig below.
    const cbfSig = cbf ? Object.keys(cbf).sort().map(k => `${k}:${[...(cbf[k] || [])].sort().join("|")}`).join(",") : "";
    const gbSig = ct?.groupByColumns ? ct.groupByColumns.join(",") : "";
    const drSig = ct?.dateRangeFilters ? Object.keys(ct.dateRangeFilters).sort().map(k => { const r = ct.dateRangeFilters[k]; return `${k}=${r.from || ""}-${r.to || ""}`; }).join(",") : "";
    const dfSig = ct?.disabledFilters ? [...ct.disabledFilters].sort().join(",") : "";
    const afSig = ct?.advancedFilters?.map(f => `${f.column}:${f.operator}:${f.value}:${f.logic}`).join(",") || "";
    const rowIdSig = rowIdFilterSignature(ct?.rowIdFilter);
    return `${ct?.sortCol}|${ct?.sortDir}|${ct?.showBookmarkedOnly}|${cbfSig}|${gbSig}|${drSig}|${ct?.searchHighlight}|${ct?.searchCondition}|${dfSig}|${ct?.tagFilter || ""}|${afSig}|${rowIdSig}`;
  }, [ct?.sortCol, ct?.sortDir, ct?.showBookmarkedOnly, ct?.checkboxFilters, ct?.groupByColumns, ct?.dateRangeFilters, ct?.searchHighlight, ct?.searchCondition, ct?.disabledFilters, ct?.tagFilter, ct?.advancedFilters, ct?.rowIdFilter]);

  useEffect(() => {
    if (!ct || !ct.dataReady) return;
    // A filter/search/sort change re-fetches with centerRow=0, resetting the window to
    // row 0. If the user had scrolled down and the result set shrinks, si/ei would point
    // past the now-smaller dataset → blank grid. Snap the scroll to top — but only for an
    // in-tab change, not a tab switch (TabBar restores per-tab scroll on switch).
    const sameTab = lastFilterTabId.current === ct.id;
    lastFilterTabId.current = ct.id;
    if (prevDebouncedDeps.current !== debouncedDeps) {
      prevDebouncedDeps.current = debouncedDeps;
      setSearchLoading(true);
      debouncedFetch(ct);
    } else {
      if (queryTimer.current) clearTimeout(queryTimer.current);
      setSearchLoading(true);
      fetchData(ct);
    }
    if (sameTab) {
      setScrollTop(0);
      scrollTopRef.current = 0;
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
    }
  }, [debouncedDeps, immediateDeps]);

  // Histogram data fetch (with per-tab cache for instant tab switching)
  const histogramTimer = useRef(null);
  useEffect(() => {
    if (histogramTimer.current) clearTimeout(histogramTimer.current);
    if (!histogramVisible || !ct?.dataReady || !ct?.tsColumns?.size || !tle) { setHistogramData([]); setHistogramLoaded(false); return; }
    if (ct.isLargeFile && (histDeferUntilRef.current[ct.id] || 0) > Date.now()) {
      setHistogramLoaded(false);
      return;
    }
    const hCol = histogramCol && ct.tsColumns.has(histogramCol) ? histogramCol : [...ct.tsColumns][0];
    if (!hCol) return;
    const sig = `${ct.id}:${hCol}:${histGranularity}:${ct.totalFiltered}:${ct.searchTerm}:${ct.searchMode}:${ct.showBookmarkedOnly}:${rowIdFilterSignature(ct.rowIdFilter)}:${JSON.stringify(ct.dateRangeFilters)}:${JSON.stringify(ct.advancedFilters)}`;
    const cached = histogramCache.current[ct.id];
    if (cached && cached.sig === sig) { setHistogramData(cached.data); setHistogramLoaded(true); return; }
    if (cached) setHistogramData(cached.data); // show stale data while refreshing
    setHistogramLoaded(false);
    histogramTimer.current = setTimeout(async () => {
      const af = activeFilters(ct);
      const effectiveSearch = effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm);
      const data = await tle.getHistogramData(ct.id, hCol, {
        searchTerm: effectiveSearch, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, rowIdFilter: ct.rowIdFilter || null,
        dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        granularity: histGranularity,
      });
      const result = isIpcError(data) || !Array.isArray(data) ? [] : data;
      if (isIpcCancelled(data)) return;
      histogramCache.current[ct.id] = { sig, data: result };
      setHistogramData(result);
      setHistogramLoaded(true);
    }, 400);
    return () => { if (histogramTimer.current) clearTimeout(histogramTimer.current); };
  }, [histogramVisible, histogramCol, histGranularity, ct?.id, ct?.totalFiltered, ct?.searchTerm, ct?.searchMode, ct?.showBookmarkedOnly, ct?.rowIdFilter, JSON.stringify(ct?.dateRangeFilters), JSON.stringify(ct?.advancedFilters)]); // eslint-disable-line

  // Histogram container width tracking via ResizeObserver
  useEffect(() => {
    const el = histContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) setHistContainerWidth(w);
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [histogramVisible]);

  // ── Scroll-driven window fetch (server-side virtual scrolling) ──
  const scrollFetchTimer = useRef(null);
  useEffect(() => {
    if (!ct || !ct.dataReady || isGrouped) return;
    const scrollRow = Math.floor(scrollMapRef.current.logicalScrollTop / ROW_HEIGHT);
    const rowOffset = ct.rowOffset || 0;
    const loadedRows = ct.rows?.length || 0;
    const windowEnd = rowOffset + loadedRows;
    const visibleRows = Math.max(60, Math.ceil((scrollRef.current?.clientHeight || 0) / ROW_HEIGHT) + OVERSCAN);
    const fetchLimit = fetchLimitForTab(ct);
    const ahead = fetchAheadForLimit(Math.max(loadedRows, fetchLimit));
    const cacheCoversViewport = rowWindowCovers(rowOffset, loadedRows, scrollRow, visibleRows);
    const fullZeroBasedCache = rowOffset === 0 && loadedRows >= (ct.totalFiltered || 0);
    const needsFetch = !cacheCoversViewport
      || scrollRow < rowOffset + ahead
      || scrollRow + visibleRows > windowEnd - ahead;
    if (!needsFetch || fullZeroBasedCache) return;
    if (scrollFetchTimer.current) clearTimeout(scrollFetchTimer.current);
    scrollFetchTimer.current = setTimeout(() => fetchData(ct, scrollRow), 50);
  }, [scrollTop, ct?.rowOffset, ct?.rows?.length, ct?.totalFiltered, isGrouped]);

  // ── Group expand/collapse (multi-level) ─────────────────────────
  const expandGroup = useCallback(async (pathKey, parentFilters, depth) => {
    if (!tle || !ctRef.current) return;
    const tab = ctRef.current;
    const groupCols = tab.groupByColumns || [];
    const nextLevel = depth;

    if (nextLevel < groupCols.length) {
      // Expand into sub-groups
      const nextCol = groupCols[nextLevel];
      const af = activeFilters(tab);
      const subGroups = await tle.getGroupValues(tab.id, nextCol, {
        searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        parentFilters,
      });
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tab.id) return t;
        return { ...t, expandedGroups: { ...t.expandedGroups, [pathKey]: { subGroups: subGroups || [], depth: nextLevel } } };
      }));
    } else {
      // Leaf level — fetch actual rows (initial batch)
      const af = activeFilters(tab);
      const aiHistGroup = isAiHistorySourceFormat(tab.sourceFormat);
      const GROUP_BATCH = aiHistGroup ? fetchLimitForTab(tab) : 100000;
      const result = await tle.queryRows(tab.id, {
        offset: 0, limit: GROUP_BATCH,
        ...(aiHistGroup ? aiHistoryQueryIpcOptions() : {}),
        sortCol: tab.sortCol, sortDir: tab.sortDir,
        searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        groupFilters: parentFilters,
      });
      if (!result || result.__ipcError || !Array.isArray(result.rows)) return;
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tab.id) return t;
        const newBm = new Set(t.bookmarkedSet);
        (result.bookmarkedRows || []).forEach((id) => newBm.add(id));
        const newTags = { ...t.rowTags, ...(result.rowTags || {}) };
        return { ...t, bookmarkedSet: newBm, rowTags: newTags, expandedGroups: { ...t.expandedGroups, [pathKey]: { rows: result.rows, totalFiltered: result.totalFiltered, groupFilters: parentFilters } } };
      }));
    }
  }, [tle]);

  // Load more rows for an expanded group (append next batch or load all remaining)
  const loadMoreGroupRows = useCallback(async (pathKey, loadAll) => {
    if (!tle || !ctRef.current) return;
    const tab = ctRef.current;
    const existing = tab.expandedGroups?.[pathKey];
    if (!existing || !existing.rows || !existing.groupFilters) return;
    const aiHistGroup = isAiHistorySourceFormat(tab.sourceFormat);
    const GROUP_BATCH = aiHistGroup ? fetchLimitForTab(tab) : 100000;
    const loaded = existing.rows.length;
    const remaining = existing.totalFiltered - loaded;
    if (remaining <= 0) return;
    const af = activeFilters(tab);
    const result = await tle.queryRows(tab.id, {
      offset: loaded, limit: loadAll ? Math.min(remaining, aiHistGroup ? fetchLimitForTab(tab) : remaining) : GROUP_BATCH,
      ...(aiHistGroup ? aiHistoryQueryIpcOptions() : {}),
      sortCol: tab.sortCol, sortDir: tab.sortDir,
      searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: tab.showBookmarkedOnly,
      rowIdFilter: tab.rowIdFilter || null,
      dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
      groupFilters: existing.groupFilters,
    });
    if (!result || result.__ipcError || !Array.isArray(result.rows)) return;
    setTabs((prev) => prev.map((t) => {
      if (t.id !== tab.id) return t;
      const eg = t.expandedGroups[pathKey];
      if (!eg) return t;
      const newBm = new Set(t.bookmarkedSet);
      (result.bookmarkedRows || []).forEach((id) => newBm.add(id));
      const newTags = { ...t.rowTags, ...(result.rowTags || {}) };
      return { ...t, bookmarkedSet: newBm, rowTags: newTags, expandedGroups: { ...t.expandedGroups, [pathKey]: { ...eg, rows: [...eg.rows, ...result.rows] } } };
    }));
  }, [tle]);

  const collapseGroup = useCallback((pathKey) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      // Remove this key and all children
      const eg = {};
      for (const k of Object.keys(t.expandedGroups)) {
        if (k !== pathKey && !k.startsWith(pathKey + "|||")) eg[k] = t.expandedGroups[k];
      }
      return { ...t, expandedGroups: eg };
    }));
  }, [activeTab]);

  // ── Column operations (extracted to useColumnOps hook) ──────────
  const { pinColumn, unpinColumn, addGroupBy, removeGroupBy, resetColumnWidths, autoFitColumn, autoFitAllColumns, reorderColumn } = useColumnOps();

  // ── Cross-tab find ─────────────────────────────────────────────
  const handleCrossFind = useCallback(async (term) => {
    if (!tle || !term.trim() || tabs.length === 0) return;
    const results = [];
    for (const tab of tabs) {
      if (!tab.dataReady) continue;
      const count = await tle.searchCount(tab.id, term, "mixed");
      results.push({ tabId: tab.id, name: tab.name, count });
    }
    setCrossFind({ term, results });
  }, [tle, tabs]);

  // Auto cross-tab counts when searching with 2+ tabs
  const crossTabTimer = useRef(null);
  useEffect(() => {
    if (crossTabTimer.current) clearTimeout(crossTabTimer.current);
    const term = ct?.searchTerm?.trim();
    const readyTabs = tabs.filter((t) => t.dataReady);
    if (isSearchTooShort(term) || !term || readyTabs.length < 2 || !tle) { setCrossTabCounts(null); return; }
    setCrossTabOpen(true);
    crossTabTimer.current = setTimeout(async () => {
      const mode = ct?.searchMode || "mixed";
      const cond = ct?.searchCondition || "contains";
      const results = [];
      for (const tab of readyTabs) {
        const count = await tle.searchCount(tab.id, term, mode, cond);
        results.push({ tabId: tab.id, name: tab.name, count });
      }
      setCrossTabCounts({ term, mode, cond, results });
    }, 600);
    return () => { if (crossTabTimer.current) clearTimeout(crossTabTimer.current); };
  }, [ct?.searchTerm, ct?.searchMode, tabs.length, tle]); // eslint-disable-line

  // ── Electron IPC listeners (register once, clean up on unmount) ──
  useEffect(() => {
    if (!tle) return;
    const unsubs = [];
    const listen = (subscribe, cb) => {
      const unsub = subscribe?.(cb);
      if (typeof unsub === "function") unsubs.push(unsub);
    };

    // Load recent files on startup
    tle.getRecentFiles().then((files) => setRecentFiles(files || [])).catch(() => {});
    listen(tle.onRecentFilesUpdated, (files) => setRecentFiles(files || []));

    listen(tle.onImportStart, ({ tabId, fileName, filePath, fileSize }) => {
      if (filePath) importPathsRef.current[tabId] = filePath;
      setImportingTabs((prev) => ({ ...prev, [tabId]: { fileName, rowsImported: 0, percent: 0, status: "importing", fileSize: fileSize || 0 } }));
      setTabs((prev) => [...prev, {
        id: tabId, name: fileName, filePath, headers: [], rows: [], totalRows: 0, totalFiltered: 0,
        tsColumns: new Set(), numericColumns: new Set(), searchTerm: "", searchMode: "mixed", searchCondition: "contains",
        columnFilters: {}, checkboxFilters: {}, sortCol: null, sortDir: "asc", colorRules: [],
        hiddenColumns: new Set(), bookmarkedSet: new Set(), showBookmarkedOnly: false, rowOffset: 0,
        columnWidths: {}, columnOrder: [], pinnedColumns: [], groupByColumns: [], groupData: [], expandedGroups: {},
        rowTags: {}, tagColors: { ...TAG_PRESETS }, tagFilter: null, rowIdFilter: null, rowIdFilterLabel: null,
        dateRangeFilters: {}, searchHighlight: false, disabledFilters: new Set(),
        advancedFilters: [],
        usnResolveStats: null,
        evtxMessageMode: null,
        messagesDeferred: false,
        importing: true, dataReady: false,
      }]);
      setActiveTab(tabId);
      // Bind a home-screen capability intent (if armed and not yet bound) to THIS import,
      // so its analyzer opens on this exact tab even if other imports finish first.
      if (pendingCapabilityRef.current && pendingCapabilityRef.current.tabId == null) {
        pendingCapabilityRef.current.tabId = tabId;
      }
    });
    listen(tle.onImportProgress, ({ tabId, fileName, rowsImported, percent, phase, bytesRead, totalBytes, statusDetail }) => {
      if (!tabId) return;
      const normalizedPercent = Number.isFinite(percent) ? percent : 0;
      setImportingTabs((prev) => ({
        ...prev,
        [tabId]: {
          ...(prev[tabId] || { fileName: fileName || "", status: "importing" }),
          fileName: prev[tabId]?.fileName || fileName || "",
          rowsImported,
          percent: normalizedPercent,
          phase: phase || (normalizedPercent >= 100 ? "finalizing" : "parsing"),
          bytesRead,
          totalBytes,
          statusDetail: statusDetail || "",
          status: normalizedPercent >= 100 ? "indexing" : "importing",
        },
      }));
    });
    listen(tle.onImportComplete, ({ tabId, fileName, headers, rowCount, tsColumns, numericColumns, initialRows, totalFiltered, emptyColumns, sourceFormat, evtxMessageMode, messagesDeferred, resolveStats, bookmarkedRowIds, rowTags, tagColors, importWarning, importNotice, isLargeFile, initialRowsDeferred }) => {
      delete importPathsRef.current[tabId];
      if (importWarning) {
        const warnTitle = isAiHistorySourceFormat(sourceFormat) ? "AI history import"
          : (sourceFormat === "registry" || String(importWarning).includes("hive") ? "Dirty registry hive" : "Import warning");
        toast.warning(warnTitle, { detail: importWarning });
      }
      if (importNotice) toast.info("AI history import", { detail: importNotice });
      const largeTab = !!isLargeFile || rowCount >= 2_500_000 || (isAiHistorySourceFormat(sourceFormat) && rowCount >= 50_000);
      if (largeTab) {
        histDeferUntilRef.current[tabId] = Date.now() + LARGE_TAB_HISTOGRAM_DEFER_MS;
        toast.info("Large timeline loaded", {
          detail: `${formatNumber(rowCount)} rows ready. Wait for indexes to finish before heavy column filters; search uses LIKE until FTS is skipped on files over 5 GB.`,
          ttl: 12000,
        });
      }
      const cw = largeTab ? fastColumnWidths(headers) : measureColumnWidths(headers, initialRows);
      const saved = pendingRestoresRef.current[tabId];
      const applyTabImport = (columnWidths) => setTabs((prev) => prev.map((t) => {
        if (t.id !== tabId) return t;
        const base = { ...t, name: fileName, headers, rows: initialRows, rowOffset: 0, totalRows: rowCount, totalFiltered,
          tsColumns: new Set(tsColumns || []), numericColumns: new Set(numericColumns || []),
          columnWidths: saved ? { ...columnWidths, ...saved.columnWidths } : columnWidths, importing: false, dataReady: true, isLargeFile: largeTab,
          bookmarkedSet: new Set(bookmarkedRowIds || []),
          rowTags: rowTags || {},
          tagColors: tagColors ? { ...TAG_PRESETS, ...tagColors } : { ...TAG_PRESETS },
          sourceFormat: sourceFormat || null,
          evtxMessageMode: evtxMessageMode || null,
          messagesDeferred: !!messagesDeferred,
          aiSecretTriage: saved?.aiSecretTriage || {},
          aiSecretSalt: saved?.aiSecretSalt || "",
          usnResolveStats: sourceFormat === "raw-usnjrnl" ? (resolveStats || null) : null };
        if (!saved) {
          // Auto-detect KAPE / AI history profiles (including ai-history-* imports)
          const kp = detectKapeProfile(headers);
          const autoHidden = kp?.showAllColumns
            ? new Set()
            : new Set(emptyColumns || []);
          if (kp) {
            const order = (kp.columnOrder || []).filter((h) => headers.includes(h));
            const rest = headers.filter((h) => !order.includes(h));
            const autoRules = kp.autoColorColumn && headers.includes(kp.autoColorColumn)
              ? buildTimelineColorRules(initialRows, kp.autoColorColumn, true)
              : [];
            if (!kp.showAllColumns) {
              const kpHidden = (kp.hiddenColumns || []).filter((h) => headers.includes(h));
              kpHidden.forEach((h) => autoHidden.add(h));
            }
            const sortPatch = kp.defaultSortCol && headers.includes(kp.defaultSortCol)
              ? { sortCol: kp.defaultSortCol, sortDir: kp.defaultSortDir || "asc" }
              : {};
            return { ...base, _detectedProfile: kp.name,
              hiddenColumns: autoHidden,
              columnOrder: [...order, ...rest],
              colorRules: autoRules,
              ...sortPatch,
            };
          }
          // Raw binary parsers (MFT, USN Journal): show all columns, only hide empty
          if (sourceFormat) {
            return { ...base, hiddenColumns: autoHidden };
          }
          return { ...base, hiddenColumns: autoHidden };
        }
        return { ...base,
          tagColors: saved.tagColors || { ...TAG_PRESETS },
          columnFilters: saved.columnFilters || {},
          checkboxFilters: saved.checkboxFilters || {},
          colorRules: saved.colorRules || [],
          hiddenColumns: new Set(saved.hiddenColumns || []),
          pinnedColumns: saved.pinnedColumns || [], columnOrder: saved.columnOrder || [],
          sortCol: saved.sortCol, sortDir: saved.sortDir || "asc",
          searchTerm: saved.searchTerm || "", searchMode: saved.searchMode || "mixed", searchCondition: saved.searchCondition || "contains",
          groupByColumns: saved.groupByColumns || [],
          showBookmarkedOnly: saved.showBookmarkedOnly || false,
          rowIdFilter: null,
          rowIdFilterLabel: null,
          dateRangeFilters: saved.dateRangeFilters || {},
          advancedFilters: saved.advancedFilters || [],
          searchHighlight: saved.searchHighlight || false,
          vtEnrichment: saved.vtEnrichment || null,
          aiSecretTriage: saved.aiSecretTriage || {},
          aiSecretSalt: saved.aiSecretSalt || "",
        };
      }));
      applyTabImport(cw);
      if (initialRowsDeferred || (isAiHistorySourceFormat(sourceFormat) && rowCount > 0 && (!initialRows || initialRows.length === 0))) {
        const deferLimit = fetchLimitForTab({ sourceFormat });
        tle.queryRows(tabId, {
          offset: 0,
          limit: deferLimit,
          sortCol: null,
          sortDir: "asc",
          ...aiHistoryQueryIpcOptions(),
        }).then((result) => {
          if (!result || result.__ipcError) return;
          setTabs((prev) => prev.map((t) =>
            t.id === tabId ? {
              ...t,
              rows: result.rows,
              rowOffset: 0,
              totalFiltered: result.totalFiltered,
              bookmarkedSet: new Set(result.bookmarkedRows || []),
              rowTags: result.rowTags || {},
            } : t,
          ));
        }).catch(() => {});
      }
      if (largeTab && initialRows.length > 0) {
        const refine = () => {
          const refined = measureColumnWidths(headers, initialRows);
          setTabs((prev) => prev.map((t) => {
            if (t.id !== tabId) return t;
            return { ...t, columnWidths: saved ? { ...refined, ...saved.columnWidths } : refined };
          }));
        };
        if (typeof requestIdleCallback === "function") requestIdleCallback(refine, { timeout: 3000 });
        else setTimeout(refine, 0);
      }
      setImportingTabs((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
      // Restore bookmarks and tags from session
      if (saved) {
        (async () => {
          if (saved.bookmarkedRowIds?.length) await tle.setBookmarks(tabId, saved.bookmarkedRowIds, true);
          if (saved.tags && Object.keys(saved.tags).length > 0) await tle.bulkAddTags(tabId, saved.tags);
          setPendingRestores((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
        })().catch((err) => {
          console.error("Session restore error for tab", tabId, err);
          setPendingRestores((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
        });
      }

      // ── Home-screen capability launch ───────────────────────────────────────
      // If this import was kicked off from a home-screen capability tile, open that
      // analyzer now that the tab is ready (dataReady was set true above). This fires
      // at import-COMPLETE when dataReady is true. Column mappings are pre-detected so
      // analyzers that need them (Process Inspector, Lateral Movement) never open with
      // an empty schema. Format-specific analyzers fall back to a toast + the grid.
      // Triage batch bookkeeping — must run before the capability hand-off so a batch
      // launch and a home-tile launch can never both fire for the same tab.
      _settleTriageBatch(tabId, true, { tabId, headers, rowCount, sourceFormat: sourceFormat || null });

      const pendingCap = pendingCapabilityRef.current;
      if (pendingCap && pendingCap.tabId === tabId) {
        pendingCapabilityRef.current = null;
        const launcher = HOME_CAPABILITY_LAUNCHERS[pendingCap.capability];
        if (launcher) {
          const launchTab = { id: tabId, headers, sourceFormat: sourceFormat || null, dataReady: true };
          if (launcher.compatible(launchTab)) {
            setActiveTab(tabId);
            setModal(launcher.buildModal(launchTab));
          } else if (launcher.incompatibleHint) {
            toast.warning(launcher.incompatibleHint);
          }
        }
      }
    });
    listen(tle.onImportQueue, ({ pending }) => {
      setImportQueue(pending || []);
    });
    listen(tle.onImportError, ({ tabId, error }) => {
      const errText = String(error || "");
      const userCanceled = /job cancel|extraction cancel|canceled|cancelled/i.test(errText);
      // Drop the pending home-tile capability intent only if THIS (the bound) import failed.
      if (pendingCapabilityRef.current?.tabId === tabId) pendingCapabilityRef.current = null;
      // A failed member must still settle, or the batch would wait forever for it.
      _settleTriageBatch(tabId, false, null);
      setImportingTabs((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
      setTabs((prev) => prev.filter((t) => t.id !== tabId));
      if (userCanceled) return;
      // Offer one-click retry instead of silent data loss — the source path was captured at import-start.
      const failedPath = importPathsRef.current[tabId];
      delete importPathsRef.current[tabId];
      toast.error("Import failed", {
        detail: errText,
        dedupeKey: failedPath ? `import-error:${failedPath}` : `import-error:${errText}`,
        ...(failedPath ? { actionLabel: "Retry import", onAction: () => tle?.importFiles([failedPath]) } : {}),
      });
    });
    listen(tle.onIndexProgress, ({ tabId, built, total, done, currentCol, error }) => {
      if (!tabId) return;
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, indexesReady: done, indexesBuilt: built, indexesTotal: total, indexCurrentCol: currentCol || null, indexError: error || null } : t
      ));
      // Surface background-build failure instead of silently dismissing the overlay.
      if (error) toast.warning("Column indexing didn't finish", { detail: `Sorting and filtering may be slower than usual.\n\n${String(error)}` });
    });
    listen(tle.onFtsProgress, ({ tabId, indexed, total, done, optimizing, error, skipped }) => {
      if (!tabId) return;
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, ftsReady: done, ftsIndexed: indexed, ftsTotal: total, ftsOptimizing: !!optimizing, ftsError: error || null } : t
      ));
      if (error) toast.warning("Search index unavailable", { detail: `Full-text search falls back to a slower full-table scan.\n\n${String(error)}` });
      else if (skipped) toast.warning("Search index skipped (large file)", { detail: "Full-text search uses a substring scan (slower on very large datasets). Sorting and filtering still use column indexes." });
    });
    listen(tle.onExtractResidentProgress, ({ processed, total, percent }) => {
      setExtractProgress({ processed, total, percent });
    });
    listen(tle.onUsnPathsUpdated, ({ tabId, resolveStats }) => {
      // MFT was loaded after USN Journal — paths have been re-resolved
      delete searchCache.current[tabId];
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, usnResolveStats: resolveStats || t.usnResolveStats || null } : t
      ));
      tle.queryRows(tabId, { offset: 0, limit: VIRTUAL_WINDOW, sortCol: null, sortDir: "asc" }).then((result) => {
        if (!result || result.__ipcError) return;
        setTabs((prev) => prev.map((t) =>
          t.id === tabId ? { ...t, rows: result.rows, rowOffset: 0, totalFiltered: result.totalFiltered, usnResolveStats: resolveStats || t.usnResolveStats || null } : t
        ));
      }).catch(() => {});
    });
    listen(tle.onRwProgress, (p) => {
      setModal(updateModal("ransomware", (prev) => (prev.phase === "scanning" || prev.phase === "loading") ? { rwProgress: p } : null));
    });
    listen(tle.onHmProgress, (p) => {
      setModal(updateModal("heatmap", (prev) => prev.loading ? { hmProgress: p } : null));
    });
    listen(tle.onUpdaterState, (state) => {
      setUpdaterPopup((prev) => ({
        phase: state?.phase || "idle",
        message: state?.message || "",
        detail: state?.detail || "",
        percent: Number.isFinite(state?.percent) ? state.percent : (prev?.percent || 0),
        transferred: Number.isFinite(state?.transferred) ? state.transferred : (prev?.transferred || 0),
        total: Number.isFinite(state?.total) ? state.total : (prev?.total || 0),
        bytesPerSecond: Number.isFinite(state?.bytesPerSecond) ? state.bytesPerSecond : (prev?.bytesPerSecond || 0),
        version: state?.version || null,
        releaseNotes: typeof state?.releaseNotes === "string" ? state.releaseNotes : "",
      }));
      if (state?.phase !== "checking") setCheckingForUpdates(false);
    });
    listen(tle.onSheetSelection, ({ tabId, fileName, filePath, sheets }) => {
      setModal(openSimpleModal("sheets", { tabId, fileName, filePath, sheets }));
    });
    listen(tle.onTriggerOpen, () => { runOpenFileDialog(); });
    listen(tle.onTriggerExport, () => {
      const cur = ctRef.current;
      if (cur) {
        const af = activeFilters(cur);
        tle.exportFiltered(cur.id, {
          searchTerm: effectiveSearchTerm(cur.searchHighlight ? "" : cur.searchTerm), searchMode: cur.searchMode, searchCondition: cur.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: cur.showBookmarkedOnly, sortCol: cur.sortCol, sortDir: cur.sortDir,
          tagFilter: (cur.disabledFilters || new Set()).has("__tags__") ? null : (cur.tagFilter || null),
          rowIdFilter: cur.rowIdFilter || null,
          dateRangeFilters: cur.dateRangeFilters || {},
          advancedFilters: cur.advancedFilters || [],
        });
      }
    });
    listen(tle.onTriggerGenerateReport, () => {
      const cur = ctRef.current;
      if (cur?.dataReady) tle.generateReport(cur.id, cur.name, cur.tagColors || {}, cur.vtEnrichment || null);
    });
    listen(tle.onTriggerSearch, () => document.getElementById("gs")?.focus());
    listen(tle.onTriggerBookmarkToggle, () => {
      const cur = ctRef.current;
      if (cur) setTabs((prev) => prev.map((t) => t.id === cur.id ? { ...t, showBookmarkedOnly: !t.showBookmarkedOnly } : t));
    });
    listen(tle.onTriggerColumnManager, () => { setColMgrSearch(""); setModal(openSimpleModal("columns")); });
    listen(tle.onTriggerColorRules, () => setModal(openSimpleModal("colors")));
    listen(tle.onTriggerShortcuts, () => setModal(openSimpleModal("shortcuts")));
    listen(tle.onTriggerCrossFind, () => setModal(openSimpleModal("crossfind")));
    listen(tle.onTriggerSaveSession, () => handleSaveSessionRef.current?.());
    listen(tle.onTriggerLoadSession, () => handleLoadSessionRef.current?.());
    listen(tle.onTriggerCloseTab, () => { const cur = ctRef.current; if (cur) closeTabRef.current?.(cur.id); });
    listen(tle.onTriggerCloseAllTabs, () => { setTabs((prev) => { prev.forEach((t) => tle.closeTab(t.id)); return []; }); setActiveTab(null); });
    listen(tle.onTriggerCheckForUpdates, () => {
      setHelpMenuOpen(false);
      handleCheckForUpdatesRef.current?.();
    });

    // Tools menu handlers
    listen(tle.onSetDatetimeFormat, (fmt) => setDateTimeFormat(fmt));
    listen(tle.onSetTimezone, (tz) => setTimezone(tz));
    listen(tle.onSetFontSize, (val) => {
      if (val === "increase") setFontSize((s) => Math.min(18, s + 1));
      else if (val === "decrease") setFontSize((s) => Math.max(9, s - 1));
      else if (typeof val === "number") setFontSize(val);
    });
    listen(tle.onTriggerResetColumns, () => resetColumnWidthsRef.current?.());
    listen(tle.onSetTheme, (name) => setThemeName(name));
    listen(tle.onTriggerHistogram, () => setHistogramVisible((v) => !v));
    listen(tle.onTriggerVtSettings, () => {
      const cur = ctRef.current;
      if (cur?.dataReady) setModal(openIocLoadModal({ vtConfigExpanded: true }));
    });

    // Load saved filter presets
    tle.loadFilterPresets().then((p) => setFilterPresets(p || [])).catch(() => {});

    return () => {
      for (const unsub of unsubs.splice(0)) {
        try { unsub(); } catch {}
      }
    };
  }, [tle]);

  const markRightClickHandled = useCallback(() => {
    rightClickFired.current = true;
    setTimeout(() => { rightClickFired.current = false; }, 500);
  }, []);

  const shouldCloseContextBackdrop = useCallback((e) => (
    e.button === 0 && !e.ctrlKey && !e.metaKey && !rightClickFired.current
  ), []);

  const renderContextPortal = useCallback((node) => {
    if (typeof document === "undefined" || !document.body) return node;
    return createPortal(node, document.body);
  }, []);

  const inferGridColumnAtPoint = useCallback((x) => {
    const scroller = scrollRef.current;
    const tab = ctRef.current;
    if (!scroller || !tab) return null;

    const rect = scroller.getBoundingClientRect();
    const relX = x - rect.left;
    if (relX < 0 || relX > rect.width) return null;

    const layout = gridLayoutRef.current || {};
    const fixedLeadingW = isGroupedRef.current
      ? (16 + 26 + CHECKBOX_COL_WIDTH)
      : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH);
    let stickyCursor = fixedLeadingW;

    if (relX < stickyCursor) return null;

    const tagW = layout.tagColWidth || TAG_COL_WIDTH_DEFAULT;
    if (relX >= stickyCursor && relX < stickyCursor + tagW) return "__tags__";
    stickyCursor += tagW;

    if (tab.vtEnrichment) stickyCursor += tab.columnWidths?.["__vt__"] || VT_COL_WIDTH;
    if (layout.hasEvidencePills) stickyCursor += tab.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;

    for (const h of layout.pinnedH || []) {
      const left = layout.pinnedOffsets?.offsets?.[h];
      const w = tab.columnWidths?.[h] || 150;
      if (Number.isFinite(left) && relX >= left && relX < left + w) return h;
    }

    const contentX = scroller.scrollLeft + relX;
    let cursor = layout.pinnedOffsets?.totalWidth || stickyCursor;
    for (const h of layout.scrollH || []) {
      const w = tab.columnWidths?.[h] || 150;
      if (contentX >= cursor && contentX < cursor + w) return h;
      cursor += w;
    }

    return null;
  }, []);

  const openRowContextMenuFromIndex = useCallback((x, y, rowIndex, cellColumn = null) => {
    const tab = ctRef.current;
    if (!tab || rowIndex < 0) {
      debugRightClick("geometry row failed: no tab or invalid row index", { x, y, rowIndex, hasTab: !!tab });
      return false;
    }

    const dRows = displayRowsRef.current || [];
    const offset = isGroupedRef.current ? 0 : (tab.rowOffset || 0);
    const item = dRows[rowIndex - offset];
    if (!item) {
      debugRightClick("geometry row failed: no cached row", { x, y, rowIndex, offset, localIndex: rowIndex - offset, cachedRows: dRows.length });
      return false;
    }
    if (isGroupedRef.current && item.type && item.type !== "row") {
      debugRightClick("geometry row failed: non-row grouped item", { x, y, rowIndex, itemType: item.type });
      return false;
    }

    const row = isGroupedRef.current ? (item.data || item) : item;
    if (!row || row.__idx == null) {
      debugRightClick("geometry row failed: missing row id", { x, y, rowIndex });
      return false;
    }

    const rTags = (tab.rowTags || {})[row.__idx] || [];
    setContextMenu(null);
    setCellContextMenu(null);
    setRowContextMenu({
      x, y,
      rowId: row.__idx,
      rowIndex,
      currentTags: rTags,
      row,
      cellColumn,
      cellValue: cellColumn ? (row[cellColumn] || "") : "",
    });
    markRightClickHandled();
    debugRightClick("opened row context menu from geometry", { x, y, rowIndex, rowId: row.__idx, cellColumn });
    return true;
  }, [markRightClickHandled, setCellContextMenu, setContextMenu, setRowContextMenu]);

  const openGridContextMenuFromGeometry = useCallback((x, y) => {
    const scroller = scrollRef.current;
    if (!scroller) {
      debugRightClick("geometry failed: no scroller", { x, y });
      return false;
    }

    const rect = scroller.getBoundingClientRect();
    if (x < rect.left || x > rect.right || y < rect.top || y > rect.bottom) {
      debugRightClick("geometry failed: point outside scroller", {
        x, y,
        rect: { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom },
      });
      return false;
    }

    const relY = y - rect.top;
    if (relY >= 0 && relY <= HEADER_HEIGHT) {
      const colName = inferGridColumnAtPoint(x);
      if (!colName) {
        debugRightClick("geometry header failed: no column", { x, y, relY });
        return false;
      }
      setRowContextMenu(null);
      setCellContextMenu(null);
      setContextMenu({ x, y, colName });
      markRightClickHandled();
      debugRightClick("opened column context menu from geometry", { x, y, colName });
      return true;
    }

    if (relY <= HEADER_HEIGHT + FILTER_HEIGHT) {
      debugRightClick("geometry ignored filter row", { x, y, relY });
      return false;
    }

    const logicalTop = scrollMapRef.current.logicalScrollTop || scroller.scrollTop || 0;
    const rowIndex = Math.floor((logicalTop + relY - HEADER_HEIGHT - FILTER_HEIGHT) / ROW_HEIGHT);
    return openRowContextMenuFromIndex(x, y, rowIndex, inferGridColumnAtPoint(x));
  }, [inferGridColumnAtPoint, markRightClickHandled, openRowContextMenuFromIndex, setCellContextMenu, setContextMenu, setRowContextMenu]);

  // Shared handler for Command/Ctrl-click context menu shortcuts.
  // Returns true when the point resolves to a grid header/row and opens one of our menus.
  const handleNativeRightClick = useCallback((x, y, targetEl = null) => {
    const eventTarget = targetEl?.nodeType === 1 ? targetEl : targetEl?.parentElement;
    const pointEls = typeof document !== "undefined" && document.elementsFromPoint
      ? document.elementsFromPoint(x, y)
      : [];
    const candidates = [eventTarget, ...pointEls, document.elementFromPoint(x, y)].filter(Boolean);
    const targetName = eventTarget?.tagName || eventTarget?.nodeName || null;

    let headerEl = null;
    let rowEl = null;
    let cellEl = null;
    for (const candidate of candidates) {
      if (!candidate?.closest) continue;
      headerEl = candidate.closest("[data-col-header]");
      if (headerEl) break;
      rowEl = candidate.closest("[data-row-id]");
      if (rowEl) {
        cellEl = candidate.closest("[data-cell-col]");
        break;
      }
    }

    // Column header context shortcut
    if (headerEl) {
      setRowContextMenu(null);
      setCellContextMenu(null);
      setContextMenu({ x, y, colName: headerEl.dataset.colHeader });
      markRightClickHandled();
      debugRightClick("opened column context menu from dom target", {
        x, y,
        colName: headerEl.dataset.colHeader,
        targetName,
        candidateCount: candidates.length,
      });
      return true;
    }

    // Data row context shortcut
    if (!rowEl) {
      debugRightClick("dom target missed; falling back to geometry", { x, y, targetName, candidateCount: candidates.length });
      return openGridContextMenuFromGeometry(x, y);
    }

    const rowId = rowEl.dataset.rowId;
    const rowIndex = parseInt(rowEl.dataset.rowIndex, 10);
    const cellCol = cellEl ? cellEl.dataset.cellCol : null;

    const tab = ctRef.current;
    if (!tab) {
      debugRightClick("dom row failed: no active tab", { x, y, rowId, rowIndex, cellCol });
      return false;
    }

    const dRows = displayRowsRef.current;
    const tab2 = ctRef.current;
    const offset = isGroupedRef.current ? 0 : (tab2?.rowOffset || 0);
    const item = dRows[rowIndex - offset];
    if (!item) {
      debugRightClick("dom row failed: no cached row", { x, y, rowId, rowIndex, offset, localIndex: rowIndex - offset, cachedRows: dRows?.length || 0 });
      return false;
    }
    const row = isGroupedRef.current ? (item.data || item) : item;
    if (!row || String(row.__idx) !== String(rowId)) {
      debugRightClick("dom row failed: row id mismatch", { x, y, rowId, rowIndex, cachedRowId: row?.__idx });
      return false;
    }

    const rTags = (tab.rowTags || {})[row.__idx] || [];
    setContextMenu(null);
    setCellContextMenu(null);
    setRowContextMenu({
      x, y,
      rowId: row.__idx,
      rowIndex,
      currentTags: rTags,
      row,
      cellColumn: cellCol,
      cellValue: cellCol ? (row[cellCol] || "") : "",
    });
    markRightClickHandled();
    debugRightClick("opened row context menu from dom target", { x, y, rowId: row.__idx, rowIndex, cellCol });
    return true;
  }, [markRightClickHandled, openGridContextMenuFromGeometry, setCellContextMenu, setContextMenu, setRowContextMenu]);

  // Supported grid context-menu shortcut: Command-click on macOS (Ctrl-click elsewhere).
  // Plain secondary-click handling is intentionally disabled after unreliable
  // external-trackpad behavior; this path is explicit and stable.
  useEffect(() => {
    const onModifiedPrimaryPointer = (e) => {
      const modifiedPrimaryClick = e.button === 0 && (e.ctrlKey || e.metaKey);
      if (!modifiedPrimaryClick) return;

      if (rightClickFired.current) {
        e.preventDefault();
        e.stopPropagation();
        return;
      }

      const isDownEvent = e.type === "pointerdown" || e.type === "mousedown";
      const isUpEvent = e.type === "pointerup" || e.type === "mouseup";

      // Wait until pointerup/mouseup so the later synthetic click does not
      // overwrite or immediately close the native menu.
      if (modifiedPrimaryClick && isDownEvent) {
        pendingModifiedRightClick.current = { x: e.clientX, y: e.clientY, target: e.target, at: Date.now() };
        debugRightClick("document command context pending", {
          type: e.type,
          x: e.clientX,
          y: e.clientY,
          button: e.button,
          buttons: e.buttons,
          ctrlKey: e.ctrlKey,
          metaKey: e.metaKey,
          targetName: e.target?.tagName || e.target?.nodeName || null,
        });
        e.preventDefault();
        e.stopPropagation();
        return;
      }

      debugRightClick("document command context", {
        type: e.type,
        x: e.clientX,
        y: e.clientY,
        button: e.button,
        buttons: e.buttons,
        ctrlKey: e.ctrlKey,
        metaKey: e.metaKey,
        targetName: e.target?.tagName || e.target?.nodeName || null,
      });

      if (modifiedPrimaryClick && isUpEvent) {
        const pending = pendingModifiedRightClick.current;
        pendingModifiedRightClick.current = null;
        const x = Number.isFinite(pending?.x) ? pending.x : e.clientX;
        const y = Number.isFinite(pending?.y) ? pending.y : e.clientY;
        const target = pending?.target || e.target;
        markRightClickHandled();
        setTimeout(() => {
          debugRightClick("document command context open", { type: e.type, x, y });
          handleNativeRightClick(x, y, target);
        }, 0);
        e.preventDefault();
        e.stopPropagation();
        return;
      }
    };
    const eventTypes = ["pointerdown", "mousedown", "pointerup", "mouseup"];
    eventTypes.forEach((type) => document.addEventListener(type, onModifiedPrimaryPointer, true));
    return () => eventTypes.forEach((type) => document.removeEventListener(type, onModifiedPrimaryPointer, true));
  }, [handleNativeRightClick, markRightClickHandled]);

  useEffect(() => {
    const onClickAfterSecondary = (e) => {
      if (!rightClickFired.current) return;
      e.preventDefault();
      e.stopPropagation();
    };
    document.addEventListener("click", onClickAfterSecondary, true);
    return () => document.removeEventListener("click", onClickAfterSecondary, true);
  }, []);

  useEffect(() => {
    if (contextMenu) debugRightClick("column context menu render", { x: contextMenu.x, y: contextMenu.y, colName: contextMenu.colName });
  }, [contextMenu]);

  useEffect(() => {
    if (rowContextMenu) {
      debugRightClick("row context menu render", {
        x: rowContextMenu.x,
        y: rowContextMenu.y,
        rowId: rowContextMenu.rowId,
        rowIndex: rowContextMenu.rowIndex,
        cellColumn: rowContextMenu.cellColumn,
      });
    }
  }, [rowContextMenu]);

  useEffect(() => {
    if (cellContextMenu) debugRightClick("cell context menu render", { x: cellContextMenu.x, y: cellContextMenu.y, colName: cellContextMenu.colName });
  }, [cellContextMenu]);

  // ── Handlers ─────────────────────────────────────────────────────
  const sortTimerRef = useRef(null);
  const handleSort = (col) => {
    if (justResizedRef.current || !ct) return;
    // Delay sort so double-click (auto-fit) can cancel it
    clearTimeout(sortTimerRef.current);
    sortTimerRef.current = setTimeout(() => {
      if (ct.sortCol === col) up("sortDir", ct.sortDir === "asc" ? "desc" : "asc");
      else { up("sortCol", col); up("sortDir", "asc"); }
    }, 250);
  };
  const handleHeaderDblClick = (col) => {
    clearTimeout(sortTimerRef.current);
    autoFitColumn(col);
  };

  const handleBookmark = async (rowId) => {
    if (!tle || !ct) return;
    const isNowBookmarked = await tle.toggleBookmark(ct.id, rowId);
    const newSet = new Set(ct.bookmarkedSet);
    isNowBookmarked ? newSet.add(rowId) : newSet.delete(rowId);
    up("bookmarkedSet", newSet);
  };

  const handleExport = async () => {
    if (!tle || !ct) return;
    const visSet = new Set(ct.headers.filter((h) => !ct.hiddenColumns.has(h)));
    if (isAiHistorySourceFormat(ct.sourceFormat) && ct.headers.includes("FullText")) visSet.add("FullText");
    const visHeaders = ct.headers.filter((h) => visSet.has(h));
    const af = activeFilters(ct);
    await tle.exportFiltered(ct.id, {
      sortCol: ct.sortCol, sortDir: ct.sortDir, searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly, visibleHeaders: visHeaders,
      tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
      rowIdFilter: ct.rowIdFilter || null,
      dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
    });
  };

  const handleExtractResident = async () => {
    if (!tle || !ct || extracting) return;
    setExtracting(true);
    setExtractProgress({ processed: 0, total: 0, percent: 0 });
    try {
      const result = await tle.extractResidentData(ct.id);
      if (result?.canceled) {
        // User cancelled the folder picker
      } else if (result?.error) {
        toast.error("Extraction failed", { detail: String(result.error) });
      } else if (result) {
        toast.success(`Extracted ${result.extractedCount.toLocaleString()} resident files`, { detail: `From ${result.totalRecords.toLocaleString()} MFT records.\n\nOutput: ${result.outputDir}${result.skippedErrors > 0 ? `\n\n${result.skippedErrors} records skipped due to errors.` : ""}`, ttl: 8000 });
      }
    } catch (err) {
      toast.error("Extraction failed", { detail: err?.message || String(err) });
    } finally {
      setExtracting(false);
      setExtractProgress(null);
    }
  };

  const closeTab = async (id) => {
    if (tle) await tle.closeTab(id);
    delete histogramCache.current[id];
    delete searchCache.current[id];
    delete histDeferUntilRef.current[id];
    const rem = tabs.filter((t) => t.id !== id);
    setTabs(rem);
    if (activeTab === id) setActiveTab(rem.length ? rem[rem.length - 1].id : null);
  };

  // ── Temporal Proximity Search ──────────────────────────────────
  const applyProximity = useCallback((tsCol, pivotRaw, windowMs, label) => {
    const normalized = (pivotRaw || "").replace(" ", "T");
    const pivotMs = Date.parse(normalized);
    if (isNaN(pivotMs)) return;
    const fmt = (ms) => {
      const d = new Date(ms);
      const pad = (n) => String(n).padStart(2, "0");
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    };
    up("dateRangeFilters", { ...(ct?.dateRangeFilters || {}), [tsCol]: { from: fmt(pivotMs - windowMs), to: fmt(pivotMs + windowMs) } });
    setProximityFilter({ tsCol, pivotRaw, windowMs, label });
    setModal(null);
  }, [ct, up]);

  // ── Session save/load ──────────────────────────────────────────
  // Build a session payload from the current tabs. Shared by save/auto-save.
  const buildSessionPayload = useCallback(async () => {
    const sessionTabs = [];
    for (const tab of tabs) {
      if (!tab.dataReady) continue;
      const bookmarkIds = await tle.getBookmarkedIds(tab.id);
      const tagData = await tle.getAllTagData(tab.id);
      const tags = {};
      for (const { rowid, tag } of tagData) {
        if (!tags[rowid]) tags[rowid] = [];
        tags[rowid].push(tag);
      }
      sessionTabs.push({
        filePath: tab.filePath, name: tab.name,
        bookmarkedRowIds: bookmarkIds, tags, tagColors: tab.tagColors || {},
        columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters,
        colorRules: tab.colorRules, hiddenColumns: [...tab.hiddenColumns],
        pinnedColumns: tab.pinnedColumns, columnWidths: tab.columnWidths, columnOrder: tab.columnOrder || [],
        sortCol: tab.sortCol, sortDir: tab.sortDir,
        searchTerm: tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        groupByColumns: tab.groupByColumns, showBookmarkedOnly: tab.showBookmarkedOnly,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [], searchHighlight: tab.searchHighlight || false,
        vtEnrichment: tab.vtEnrichment || null,
        aiSecretTriage: tab.aiSecretTriage || {},
        aiSecretSalt: tab.aiSecretSalt || "",
      });
    }
    return { version: 1, savedAt: new Date().toISOString(), activeTabIndex: tabs.findIndex((t) => t.id === activeTab), tabs: sessionTabs };
  }, [tle, tabs, activeTab]);

  // Restore an already-loaded session payload (shared by manual + auto-restore).
  const restoreFromSession = useCallback(async (session) => {
    if (!session || session.error) {
      if (session?.error) toast.error("Failed to load session", { detail: String(session.error) });
      return false;
    }
    if (session.version !== 1) { toast.error("Unsupported session version"); return false; }
    for (const tab of tabs) await tle.closeTab(tab.id);
    setTabs([]); setActiveTab(null);
    const restoreMap = {};
    for (const savedTab of session.tabs) {
      const result = await tle.importFileForRestore(savedTab.filePath, savedTab.sheetName);
      if (result.error) { toast.warning(`Skipping "${savedTab.name}"`, { detail: String(result.error) }); continue; }
      restoreMap[result.tabId] = savedTab;
    }
    setPendingRestores(restoreMap);
    return true;
  }, [tle, tabs]);

  const handleSaveSession = useCallback(async () => {
    if (!tle || tabs.length === 0) return;
    const payload = await buildSessionPayload();
    await tle.saveSession(payload);
  }, [tle, tabs, buildSessionPayload]);

  const handleLoadSession = useCallback(async () => {
    if (!tle) return;
    const session = await tle.loadSession();
    await restoreFromSession(session);
  }, [tle, restoreFromSession]);

  // Keep native-menu handler refs current so the mount-only IPC effect always invokes
  // the latest closures (never a stale tabs=[] version). See ref declarations above.
  useEffect(() => {
    closeTabRef.current = closeTab;
    handleSaveSessionRef.current = handleSaveSession;
    handleLoadSessionRef.current = handleLoadSession;
    resetColumnWidthsRef.current = resetColumnWidths;
    handleCheckForUpdatesRef.current = handleCheckForUpdates;
  });

  // ── Auto-save: every 30s, snapshot the in-flight investigation to userData/autosave.tle ──
  // Survives crashes; protects against losing tags/bookmarks/filters during a long forensic run.
  useEffect(() => {
    if (!tle?.autoSaveSession || tabs.length === 0) return;
    const dataReadyTabs = tabs.filter((t) => t.dataReady);
    if (dataReadyTabs.length === 0) return;
    const id = setInterval(async () => {
      try {
        const payload = await buildSessionPayload();
        if (payload.tabs.length > 0) await tle.autoSaveSession(payload);
      } catch { /* swallow — autosave failures must never disrupt analysis */ }
    }, 30000);
    return () => clearInterval(id);
  }, [tle, tabs, buildSessionPayload]);

  // ── Auto-restore prompt on launch ──
  // Check for an autosave file on first mount; expose it via `autoRestorable` so
  // the empty-state UI can offer a Restore button. Only triggers when there are
  // no current tabs (we don't want to prompt mid-investigation).
  useEffect(() => {
    if (!tle?.loadAutoSave) return;
    let cancelled = false;
    tle.loadAutoSave().then((data) => {
      if (cancelled) return;
      if (data && !data.error && Array.isArray(data.tabs) && data.tabs.length > 0) {
        setAutoRestorable(data);
      } else {
        setAutoRestorable(false);
      }
    }).catch(() => { if (!cancelled) setAutoRestorable(false); });
    return () => { cancelled = true; };
  }, [tle]);

  const handleAutoRestore = useCallback(async () => {
    if (!autoRestorable || autoRestorable === false) return;
    const ok = await restoreFromSession(autoRestorable);
    if (ok) {
      setAutoRestorable(false);
      try { await tle.clearAutoSave(); } catch { /* ignore */ }
    }
  }, [autoRestorable, restoreFromSession, tle]);

  const handleDismissAutoRestore = useCallback(async () => {
    setAutoRestorable(false);
    try { await tle?.clearAutoSave?.(); } catch { /* ignore */ }
  }, [tle]);

  // ── Computed headers ─────────────────────────────────────────────
  const allVisH = useMemo(() => {
    if (!ct) return [];
    const visSet = new Set(ct.headers.filter((h) => !ct.hiddenColumns.has(h)));
    if (ct.columnOrder?.length > 0) {
      const ordered = ct.columnOrder.filter((h) => visSet.has(h));
      const orderSet = new Set(ct.columnOrder);
      const rest = [...visSet].filter((h) => !orderSet.has(h));
      return [...ordered, ...rest];
    }
    return [...visSet];
  }, [ct?.headers, ct?.hiddenColumns, ct?.columnOrder]);

  const pinnedH = useMemo(() => {
    if (!ct) return [];
    const visSet = new Set(allVisH);
    return (ct.pinnedColumns || []).filter((h) => visSet.has(h));
  }, [ct?.pinnedColumns, allVisH]);

  const scrollH = useMemo(() => {
    const pinSet = new Set(pinnedH);
    return allVisH.filter((h) => !pinSet.has(h));
  }, [allVisH, pinnedH]);

  const hasEvidencePills = !!ct?.evidencePillsByRowid && Object.keys(ct.evidencePillsByRowid).length > 0;
  const pinnedOffsets = useMemo(() => {
    const offsets = {};
    const vtW = ct?.columnWidths?.["__vt__"] || VT_COL_WIDTH;
    const evW = ct?.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH;
    let x = (isGrouped ? (16 + 26 + CHECKBOX_COL_WIDTH) : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH)) + tagColWidth + (ct?.vtEnrichment ? vtW : 0) + (hasEvidencePills ? evW : 0); // after # + checkbox + Tags + VT + Evidence
    for (const h of pinnedH) {
      offsets[h] = x;
      x += (ct?.columnWidths[h] || 150);
    }
    return { offsets, totalWidth: x };
  }, [pinnedH, ct?.columnWidths, tagColWidth, isGrouped, ct?.vtEnrichment, hasEvidencePills]);

  gridLayoutRef.current = {
    pinnedH,
    scrollH,
    pinnedOffsets,
    tagColWidth,
    hasEvidencePills,
  };

  // ── Grouped items (multi-level) ─────────────────────────────────
  const groupedItems = useMemo(() => {
    if (!isGrouped || !ct?.groupData?.length) return null;
    const groupCols = ct.groupByColumns;
    const eg = ct.expandedGroups || {};
    const items = [];

    const buildLevel = (groups, depth, parentPath, parentFilters) => {
      const colName = groupCols[depth];
      for (const group of groups) {
        const pathKey = parentPath ? `${parentPath}|||${group.val}` : `${group.val}`;
        const filters = [...parentFilters, { col: colName, value: group.val }];
        items.push({ type: "group", value: group.val, count: group.cnt, depth, pathKey, filters, colName });
        const expanded = eg[pathKey];
        if (expanded) {
          if (expanded.subGroups) {
            // Sub-group level
            buildLevel(expanded.subGroups, depth + 1, pathKey, filters);
          } else if (expanded.rows) {
            // Leaf rows
            for (const row of expanded.rows) items.push({ type: "row", data: row, depth: depth + 1 });
            if (expanded.rows.length < expanded.totalFiltered)
              items.push({ type: "more", pathKey, loaded: expanded.rows.length, total: expanded.totalFiltered, depth: depth + 1 });
          }
        }
      }
    };

    buildLevel(ct.groupData, 0, "", []);
    return items;
  }, [isGrouped, ct?.groupData, ct?.expandedGroups, ct?.groupByColumns]);

  // ── Virtual scroll ───────────────────────────────────────────────
  const rows = ct?.rows || [];
  const displayRows = isGrouped && groupedItems ? groupedItems : rows;
  displayRowsRef.current = displayRows;
  isGroupedRef.current = isGrouped;

  // Get a row by absolute index (accounts for windowed offset in flat mode)
  const getRowAt = useCallback((absIdx) => {
    if (isGrouped) return displayRows[absIdx] || null;
    const localIdx = absIdx - (ct?.rowOffset || 0);
    return (localIdx >= 0 && localIdx < rows.length) ? rows[localIdx] : null;
  }, [isGrouped, displayRows, rows, ct?.rowOffset]);

  const getDataRowAt = useCallback((absIdx) => {
    const item = getRowAt(absIdx);
    if (!item) return null;
    if (isGrouped) return item.type === "row" ? item.data : null;
    return item;
  }, [getRowAt, isGrouped]);

  const getRowIdAt = useCallback((absIdx) => {
    const row = getDataRowAt(absIdx);
    const rowId = Number(row?.__idx);
    return Number.isInteger(rowId) && rowId > 0 ? rowId : null;
  }, [getDataRowAt]);

  const lastClickedRowData = useMemo(
    () => lastClickedRow === null ? null : getDataRowAt(lastClickedRow),
    [lastClickedRow, getDataRowAt],
  );
  const selectionBelongsToCurrentTab = !selectionTabId || selectionTabId === ct?.id;
  // The visual position can change after sorting; membership is keyed by row ID.
  const selectedRow = selectionBelongsToCurrentTab && lastClickedRow !== null
    && isRowSelected(selectedRows, allRowsSelected, lastClickedRowData?.__idx)
    ? lastClickedRow
    : null;
  const selectedRowData = selectedRow === null ? null : lastClickedRowData;

  const handleRowClick = async (ai, e) => {
    // Skip if this click was a Cmd+Click / Ctrl+Click that triggered the context menu
    if (rightClickFired.current) return;
    const rowId = getRowIdAt(ai);
    if (rowId === null) return;
    if (e.shiftKey && lastClickedRow !== null) {
      // Shift+Click: range select
      const from = Math.min(lastClickedRow, ai);
      const to = Math.max(lastClickedRow, ai);
      let rowIds = [];
      if (isGrouped) {
        for (let i = from; i <= to; i++) {
          const id = getRowIdAt(i);
          if (id !== null) rowIds.push(id);
        }
      } else {
        try {
          const result = await tle.getRowIdsInRange(ct.id, {
            ...currentFilterOptions,
            sortCol: ct.sortCol,
            sortDir: ct.sortDir,
            offset: from,
            limit: to - from + 1,
          });
          if (isIpcError(result) || !Array.isArray(result?.rowIds)) {
            throw new Error(ipcErrorMessage(result, "Could not resolve the selected range"));
          }
          rowIds = result.rowIds;
        } catch (err) {
          toast.error("Range selection failed", { detail: String(err?.message || err) });
          return;
        }
      }
      if (rowIds.length === 0) return;
      setSelectionTabId(ct.id);
      setSelectedRows((prev) => {
        return selectRowIds(prev, allRowsSelected, rowIds);
      });
    } else if (e.ctrlKey || e.ctrlKey) {
      // Cmd/Ctrl+Click: toggle individual
      setSelectionTabId(ct.id);
      setSelectedRows((prev) => toggleRowSelection(prev, allRowsSelected, rowId));
      setLastClickedRow(ai);
    } else {
      // Plain click: single select
      setAllRowsSelected(false);
      setSelectionTabId(ct.id);
      setSelectAllScopeSignature(null);
      setSelectedRows(new Set([rowId]));
      setLastClickedRow(ai);
    }
    setDetailPanelOpen(true);
  };

  const handleCheckboxToggle = (ai) => {
    const rowId = getRowIdAt(ai);
    if (rowId === null) return;
    setSelectionTabId(ct.id);
    setSelectedRows((prev) => toggleRowSelection(prev, allRowsSelected, rowId));
    setLastClickedRow(ai);
  };

  const handleGroupSelectAll = (groupHeaderAi) => {
    if (!displayRows) return;
    const groupItem = displayRows[groupHeaderAi];
    if (!groupItem || groupItem.type !== "group") return;
    const baseDepth = groupItem.depth;
    const rowIds = [];
    for (let j = groupHeaderAi + 1; j < displayRows.length; j++) {
      const child = displayRows[j];
      if (child.type === "group" && child.depth <= baseDepth) break;
      if (child.type === "row" && child.data?.__idx) rowIds.push(child.data.__idx);
    }
    if (rowIds.length === 0) return;
    setSelectionTabId(ct.id);
    const allSelected = rowIds.every((rowId) =>
      isRowSelected(selectedRows, allRowsSelected, rowId));
    setSelectedRows((prev) => {
      const next = new Set(prev);
      for (const value of rowIds) {
        const rowId = Number(value);
        if (allRowsSelected) {
          if (allSelected) next.add(rowId);
          else next.delete(rowId);
        } else if (allSelected) {
          next.delete(rowId);
        } else {
          next.add(rowId);
        }
      }
      return next;
    });
  };

  const getGroupCheckState = (groupAi, depth) => {
    if (!displayRows) return { total: 0, selected: 0 };
    let total = 0, selected = 0;
    for (let j = groupAi + 1; j < displayRows.length; j++) {
      const c = displayRows[j];
      if (c.type === "group" && c.depth <= depth) break;
      if (c.type === "row") {
        total++;
        if (isRowSelected(selectedRows, allRowsSelected, c.data?.__idx)) selected++;
      }
    }
    return { total, selected };
  };

  const detailVisible = detailPanelOpen && selectedRowData !== null;
  const totalCount = isGrouped ? displayRows.length : (ct?.totalFiltered || 0);
  const selectionCount = selectionBelongsToCurrentTab
    ? getSelectedRowCount(
      selectedRows,
      allRowsSelected,
      ct?.totalFiltered || 0,
    )
    : 0;
  const allFilteredRowsSelected = (ct?.totalFiltered || 0) > 0
    && selectionBelongsToCurrentTab
    && allRowsSelected
    && selectedRows.size === 0;
  const handleSelectAllRows = () => {
    if (isGrouped || !ct?.totalFiltered) return;
    const everyRowSelected = allFilteredRowsSelected;
    setAllRowsSelected(!everyRowSelected);
    setSelectionTabId(everyRowSelected ? null : ct.id);
    setSelectAllScopeSignature(everyRowSelected ? null : currentFilterScopeSignature);
    setSelectedRows(new Set());
    if (everyRowSelected) setLastClickedRow(null);
  };
  const selectionFilterOptions = useMemo(() => {
    if (selectionCount === 0 || !currentFilterOptions) return null;
    if (allRowsSelected) {
      return {
        ...currentFilterOptions,
        excludedRowIds: [...selectedRows],
      };
    }
    return { rowIdFilter: [...selectedRows] };
  }, [selectionCount, currentFilterOptions, allRowsSelected, selectedRows]);
  const rowOffset = ct?.rowOffset || 0;
  const totalH = totalCount * ROW_HEIGHT;
  // The scroll container has already shrunk around the detail panel. Only remove
  // the sticky header/filter rows to get the usable data-row viewport.
  const gridViewportH = scrollRef.current?.clientHeight || (viewportH - 190);
  const vh = getGridBodyViewportHeight(
    gridViewportH,
    HEADER_HEIGHT + FILTER_HEIGHT,
    ROW_HEIGHT,
  );
  // Physical container is clamped at MAX_PHYSICAL_H to stay below Chromium's ~16.7M LayoutUnit ceiling.
  // When totalH exceeds the cap, scaleFactor maps physical scrollTop -> logical scrollTop linearly.
  // pageOffset shifts each rendered row's `top` so it lands at the correct visual position
  // inside the (clamped) container, despite rows being keyed off logical indices.
  const physicalH = Math.min(totalH, MAX_PHYSICAL_H);
  const physMaxScroll = Math.max(1, physicalH - vh);
  const logMaxScroll = Math.max(1, totalH - vh);
  const scaleFactor = totalH > physicalH ? logMaxScroll / physMaxScroll : 1;
  const logicalScrollTop = scaleFactor === 1 ? scrollTop : Math.min(logMaxScroll, scrollTop * scaleFactor);
  const pageOffset = logicalScrollTop - scrollTop;
  scrollMapRef.current = { scaleFactor, logicalScrollTop, pageOffset, physicalH, totalH };
  const { start: visibleRowStart, end: visibleRowEnd } = getVisibleRowRange({
    totalCount,
    logicalScrollTop,
    viewportHeight: vh,
    rowHeight: ROW_HEIGHT,
  });
  const si = Math.max(0, Math.floor(logicalScrollTop / ROW_HEIGHT) - OVERSCAN);
  const ei = Math.min(totalCount, Math.ceil((logicalScrollTop + vh) / ROW_HEIGHT) + OVERSCAN);
  // For grouped mode: direct slice. For flat mode: map to windowed cache via rowOffset.
  const visible = useMemo(() => isGrouped
    ? displayRows.slice(si, ei)
    : rows.slice(Math.max(0, si - rowOffset), Math.max(0, ei - rowOffset)),
    [isGrouped, displayRows, rows, si, ei, rowOffset]);

  // Skeleton rows for positions outside the cached window (shown during fast scroll)
  const skeletonIndices = useMemo(() => {
    if (isGrouped || visible.length >= (ei - si)) return [];
    const cacheStart = rowOffset;
    const cacheEnd = rowOffset + rows.length;
    const indices = [];
    for (let i = si; i < ei; i++) {
      if (i < cacheStart || i >= cacheEnd) indices.push(i);
    }
    return indices;
  }, [isGrouped, visible.length, si, ei, rowOffset, rows.length]);

  const compiledColors = useMemo(() => compileColorRules(ct?.colorRules || []), [ct?.colorRules]);
  const gw = (col) => ct?.columnWidths[col] || 150;
  const fmtCell = (h, val) => (dateTimeFormat && ct?.tsColumns?.has(h)) ? formatDateTime(val, dateTimeFormat, timezone) : (val || "");
  const copyCell = useCallback((val, colName) => {
    const text = colName != null && colName !== "" ? fmtCell(colName, val) : (val || "");
    navigator.clipboard?.writeText(text);
    setCopiedMsg(true);
    setTimeout(() => setCopiedMsg(false), 1200);
  }, [dateTimeFormat, timezone, ct?.tsColumns]);
  const hlTerm = ct?.searchHighlight ? (effectiveSearchTerm(ct?.searchTerm).trim() || null) : null;
  const hlRegex = useMemo(() => {
    if (!hlTerm) return null;
    try {
      if (ct?.searchMode === "regex") return new RegExp(`(${hlTerm})`, "gi");
      // For multi-word mixed/AND, highlight each word separately
      const words = hlTerm.split(/\s+/).filter(Boolean).map((w) =>
        w.replace(/^[+\-"]|"$/g, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      ).filter(Boolean);
      if (words.length === 0) return null;
      return new RegExp(`(${words.join("|")})`, "gi");
    } catch { return null; }
  }, [hlTerm, ct?.searchMode]);
  // IOC highlight regex — built from matched IOC values stored after IOC scan
  const iocRegex = useMemo(() => {
    const patterns = ct?.iocHighlights;
    if (!patterns || patterns.length === 0) return null;
    try {
      // Sort longest first so longer IOCs match before shorter substrings
      const sorted = [...patterns].sort((a, b) => b.length - a.length);
      const escaped = sorted.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      return new RegExp(`(${escaped.join("|")})`, "gi");
    } catch { return null; }
  }, [ct?.iocHighlights]);
  const iocTestRegex = useMemo(() => iocRegex ? new RegExp(iocRegex.source, "i") : null, [iocRegex]);
  // Pre-built combined regex for when both highlight + IOC are active (avoids per-cell RegExp creation)
  const combinedHlRegex = useMemo(() => {
    if (!hlRegex || !iocRegex) return null;
    try { return new RegExp(`${iocRegex.source}|${hlRegex.source}`, "gi"); } catch { return null; }
  }, [hlRegex, iocRegex]);
  const _hlStyle = { background: "rgba(210,153,34,0.5)", color: "inherit", borderRadius: 2, padding: "0 1px" };
  const _iocStyle = { background: "rgba(240,136,62,0.45)", color: "inherit", borderRadius: 2, padding: "0 1px", fontWeight: 600 };
  const renderCell = (h, val) => {
    const text = fmtCell(h, val);
    if (!text || (!hlRegex && !iocRegex)) return text;
    // Single highlight source — use fast split path
    if (hlRegex && !iocRegex) {
      const splits = text.split(hlRegex);
      if (splits.length <= 1) return text;
      return <>{splits.map((seg, i) => i % 2 === 1
        ? <mark key={i} style={_hlStyle}>{seg}</mark>
        : seg
      )}</>;
    }
    if (iocRegex && !hlRegex) {
      const splits = text.split(iocRegex);
      if (splits.length <= 1) return text;
      return <>{splits.map((seg, i) => i % 2 === 1
        ? <mark key={i} style={_iocStyle}>{seg}</mark>
        : seg
      )}</>;
    }
    // Both active — use pre-built combined regex, color by match type
    if (!combinedHlRegex) return text;
    combinedHlRegex.lastIndex = 0; // reset instead of cloning
    const parts = [];
    let lastIndex = 0;
    let m;
    while ((m = combinedHlRegex.exec(text)) !== null) {
      if (m.index > lastIndex) parts.push(text.slice(lastIndex, m.index));
      const isIoc = iocTestRegex.test(m[0]);
      parts.push(<mark key={m.index} style={isIoc ? _iocStyle : _hlStyle}>{m[0]}</mark>);
      lastIndex = combinedHlRegex.lastIndex;
      if (m[0].length === 0) { combinedHlRegex.lastIndex++; }
    }
    if (lastIndex === 0) return text;
    if (lastIndex < text.length) parts.push(text.slice(lastIndex));
    return <>{parts}</>;
  };
  const tw = useMemo(() => getGridContentWidth({
    visibleColumns: allVisH,
    columnWidths: ct?.columnWidths,
    leadingWidth: isGrouped
      ? (16 + 26 + CHECKBOX_COL_WIDTH)
      : (BKMK_COL_WIDTH + CHECKBOX_COL_WIDTH),
    tagWidth: tagColWidth,
    vtWidth: ct?.vtEnrichment
      ? (ct?.columnWidths?.["__vt__"] || VT_COL_WIDTH)
      : 0,
    evidenceWidth: hasEvidencePills
      ? (ct?.columnWidths?.["__evidence__"] || EVIDENCE_COL_WIDTH)
      : 0,
  }), [
    allVisH,
    ct?.columnWidths,
    tagColWidth,
    isGrouped,
    ct?.vtEnrichment,
    hasEvidencePills,
  ]);

  // Reset search navigation whenever its result population changes.
  useEffect(() => {
    searchMatchIdxRef.current = -1;
    setSearchMatchIdx(-1);
    setSearchMatchPosition(-1);
  }, [
    ct?.searchTerm,
    ct?.totalFiltered,
    ct?.searchHighlight,
    ct?.searchMode,
    ct?.searchCondition,
    ct?.sortCol,
    ct?.sortDir,
    currentFilterScopeSignature,
  ]);

  // Highlight mode leaves the grid unfiltered, so its match total must be
  // counted separately. LIMIT 0 keeps all row data in SQLite.
  useEffect(() => {
    if (!tle || !ct?.searchHighlight || !effectiveSearchTerm(ct?.searchTerm) || isGrouped || !currentFilterOptions) {
      setHighlightMatchCount(0);
      return;
    }
    let cancelled = false;
    setHighlightMatchCount(-1);
    const timer = setTimeout(async () => {
      try {
        const result = await tle.queryRows(ct.id, {
          ...currentFilterOptions,
          offset: 0,
          limit: 0,
          searchTerm: ct.searchTerm,
          searchMode: ct.searchMode,
          searchCondition: ct.searchCondition || "contains",
        });
        if (!cancelled) {
          setHighlightMatchCount(
            isIpcError(result) ? 0 : Math.max(0, Number(result?.totalFiltered) || 0),
          );
        }
      } catch {
        if (!cancelled) setHighlightMatchCount(0);
      }
    }, QUERY_DEBOUNCE);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [
    tle,
    ct?.id,
    ct?.searchHighlight,
    ct?.searchTerm,
    ct?.searchMode,
    ct?.searchCondition,
    isGrouped,
    currentFilterOptions,
    currentFilterScopeSignature,
  ]);

  const scrollToRow = useCallback((idx) => {
    if (!scrollRef.current) return;
    const sf = scrollMapRef.current.scaleFactor || 1;
    const target = getRowScrollTarget({
      rowIndex: idx,
      rowHeight: ROW_HEIGHT,
      logicalScrollTop: scrollMapRef.current.logicalScrollTop || 0,
      viewportHeight: scrollRef.current.clientHeight,
      stickyHeight: HEADER_HEIGHT + FILTER_HEIGHT,
    });
    // Map the logical row target back to the capped physical scroll range.
    if (target !== null) scrollRef.current.scrollTop = target / sf;

    // Prefetch SQL window when jumping via keyboard/search (same margin as scroll-driven fetch).
    if (!isGrouped && ct?.dataReady) {
      const offset = ct.rowOffset || 0;
      const loadedRows = ct.rows?.length || 0;
      const windowEnd = offset + loadedRows;
      const visibleRows = Math.max(60, Math.ceil((scrollRef.current?.clientHeight || 0) / ROW_HEIGHT) + OVERSCAN);
      const ahead = fetchAheadForLimit(Math.max(loadedRows, fetchLimitForTab(ct)));
      const cacheCoversViewport = rowWindowCovers(offset, loadedRows, idx, visibleRows);
      const fullZeroBasedCache = offset === 0 && loadedRows >= (ct.totalFiltered || 0);
      const needsFetch = !cacheCoversViewport
        || idx < offset + ahead
        || idx + visibleRows > windowEnd - ahead;
      if (needsFetch && !fullZeroBasedCache) {
        fetchData(ct, idx);
      }
    }
  }, [ct, isGrouped, fetchData]);

  // Process Inspector grid pivot: after filters land, scroll/select the source create event.
  useEffect(() => {
    const focusId = ct?.pendingFocusRowId;
    if (!ct?.dataReady || !focusId || isGrouped) return;
    const rows = ct.rows || [];
    const local = rows.findIndex((r) => Number(r?.__idx) === Number(focusId));
    if (local < 0) return; // not in current window yet — wait for next fetch
    const absIdx = (ct.rowOffset || 0) + local;
    up("pendingFocusRowId", null);
    setSelectedRows(new Set([Number(focusId)]));
    setLastClickedRow(absIdx);
    requestAnimationFrame(() => scrollToRow(absIdx));
  }, [ct?.pendingFocusRowId, ct?.rows, ct?.rowOffset, ct?.dataReady, isGrouped]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectSingleRowAt = async (idx, knownRowId = null) => {
    let rowId = Number(knownRowId);
    if (!Number.isSafeInteger(rowId) || rowId <= 0) rowId = getRowIdAt(idx);
    const rowWasCached = getRowIdAt(idx) !== null;
    if (rowId === null) {
      try {
        const result = await tle.getRowIdsInRange(ct.id, {
          ...currentFilterOptions,
          sortCol: ct.sortCol,
          sortDir: ct.sortDir,
          offset: idx,
          limit: 1,
        });
        if (isIpcError(result) || !Array.isArray(result?.rowIds)) {
          throw new Error(ipcErrorMessage(result, "Could not resolve the row"));
        }
        rowId = Number(result.rowIds[0]);
      } catch (err) {
        toast.error("Row navigation failed", { detail: String(err?.message || err) });
        return false;
      }
    }
    if (!Number.isSafeInteger(rowId) || rowId <= 0) return false;
    if (!rowWasCached) await fetchData(ct, idx);
    setAllRowsSelected(false);
    setSelectionTabId(ct.id);
    setSelectAllScopeSignature(null);
    setSelectedRows(new Set([rowId]));
    setLastClickedRow(idx);
    setDetailPanelOpen(true);
    return true;
  };

  const navigateSearch = async (dir) => {
    const total = ct?.totalFiltered || 0;
    if (!effectiveSearchTerm(ct?.searchTerm) || isGrouped || searchNavigationPendingRef.current) return;
    searchNavigationPendingRef.current = true;
    try {
      if (ct.searchHighlight) {
        const result = await tle.findSearchMatch(ct.id, {
          ...currentFilterOptions,
          sortCol: ct.sortCol,
          sortDir: ct.sortDir,
          currentIndex: searchMatchIdxRef.current,
          direction: dir,
          matchSearchTerm: ct.searchTerm,
          matchSearchMode: ct.searchMode,
          matchSearchCondition: ct.searchCondition || "contains",
        });
        if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
        if (!Number.isSafeInteger(result?.index) || result.index < 0) {
          setHighlightMatchCount(0);
          return;
        }
        searchMatchIdxRef.current = result.index;
        setSearchMatchIdx(result.index);
        setSearchMatchPosition(result.position);
        setHighlightMatchCount(result.totalMatches);
        if (!await selectSingleRowAt(result.index, result.rowId)) return;
        requestAnimationFrame(() => scrollToRow(result.index));
        return;
      }
      if (total === 0) return;
      let next;
      const currentIndex = searchMatchIdxRef.current;
      if (dir === 1) next = currentIndex < total - 1 ? currentIndex + 1 : 0;
      else next = currentIndex > 0 ? currentIndex - 1 : total - 1;
      searchMatchIdxRef.current = next;
      setSearchMatchIdx(next);
      setSearchMatchPosition(next);
      if (!await selectSingleRowAt(next)) return;
      requestAnimationFrame(() => scrollToRow(next));
    } catch (err) {
      toast.error("Search navigation failed", { detail: String(err?.message || err) });
    } finally {
      searchNavigationPendingRef.current = false;
    }
  };

  // ── Column resize ────────────────────────────────────────────────
  useEffect(() => {
    if (!resizingCol || !ct) return;
    const onMove = (e) => {
      const nw = Math.max(60, resizeW + (e.clientX - resizeX));
      up("columnWidths", { ...ct.columnWidths, [resizingCol]: nw });
    };
    const onUp = () => { justResizedRef.current = true; setResizingCol(null); requestAnimationFrame(() => { justResizedRef.current = false; }); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
  }, [resizingCol, resizeX, resizeW]);

  // ── Detail panel resize (DOM-direct for smooth dragging) ───────
  const onDetailResizeStart = (e) => {
    e.preventDefault();
    const startY = e.clientY;
    const startH = detailPanelHeight;
    detailResizeStartY.current = startY;
    detailResizeStartH.current = startH;
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    const panel = detailPanelRef.current;
    const scrollEl = scrollRef.current;
    const onMove = (ev) => {
      const delta = detailResizeStartY.current - ev.clientY;
      const newH = Math.min(DETAIL_PANEL_MAX_HEIGHT, Math.max(DETAIL_PANEL_MIN_HEIGHT, detailResizeStartH.current + delta));
      if (panel) panel.style.height = newH + "px";
      if (scrollEl) scrollEl.style.flex = "1";
    };
    const onUp = (ev) => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      const delta = detailResizeStartY.current - ev.clientY;
      const finalH = Math.min(DETAIL_PANEL_MAX_HEIGHT, Math.max(DETAIL_PANEL_MIN_HEIGHT, detailResizeStartH.current + delta));
      setDetailPanelHeight(finalH);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // ── Histogram resize (DOM-direct for smooth dragging) ───────────
  const onHistResizeStart = (e) => {
    e.preventDefault();
    histResizeStartY.current = e.clientY;
    histResizeStartH.current = histogramHeight;
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    const onMove = (ev) => {
      const delta = ev.clientY - histResizeStartY.current;
      const newH = Math.min(500, Math.max(80, histResizeStartH.current + delta));
      // Direct DOM update for smoothness
      const el = document.getElementById("hist-container");
      if (el) el.style.height = newH + "px";
      const svg = el?.querySelector("svg");
      if (svg) svg.setAttribute("height", newH - 30);
    };
    const onUp = (ev) => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      const delta = ev.clientY - histResizeStartY.current;
      const finalH = Math.min(500, Math.max(80, histResizeStartH.current + delta));
      setHistogramHeight(finalH);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // ── Filter dropdown data ─────────────────────────────────────────
  const loadFilterValues = useCallback(async (colName, searchText, preselectAll, useRegex = false) => {
    const tab = ctRef.current;
    if (!tle || !tab) return;
    if (tab.isLargeFile && !tab.indexesReady) {
      toast.warning("Indexes still building", {
        detail: "Column filter lists on large timelines are safest after the toolbar shows indexes ready. Showing values may use a row sample.",
        ttl: 8000,
      });
    }
    setFdLoading(true);
    setFdSampled(false);
    try {
      const af = activeFilters(tab);
      const result = await tle.getColumnUniqueValues(tab.id, colName, {
        searchTerm: effectiveSearchTerm(tab.searchHighlight ? "" : tab.searchTerm), searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly, filterText: searchText, filterRegex: useRegex,
        tagFilter: (tab.disabledFilters || new Set()).has("__tags__") ? null : (tab.tagFilter || null),
        rowIdFilter: tab.rowIdFilter || null,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
      });
      if (isIpcCancelled(result)) {
        setFdLoading(false);
        return;
      }
      const vals = isIpcError(result)
        ? []
        : Array.isArray(result) ? result : Array.isArray(result?.values) ? result.values : [];
      setFdSampled(Boolean(result?.sampled || vals.sampled));
      setFdValueMeta({
        totalDistinct: Array.isArray(result) ? vals.length : Number(result?.totalDistinct || vals.length),
        truncated: !Array.isArray(result) && Boolean(result?.truncated),
      });
      setFdValues(vals);
      // Pre-select all values when no existing filter (so user unchecks to exclude)
      if (preselectAll) {
        setFdSelected(new Set(vals.map((v) => v.val)));
      } else if (searchText) {
        // When searching, trim selection to only visible values so Apply works correctly
        const visible = new Set(vals.map((v) => v.val));
        setFdSelected((prev) => new Set([...prev].filter((v) => visible.has(v))));
      }
    } catch {
      setFdValues([]);
      setFdSampled(false);
      setFdValueMeta({ totalDistinct: 0, truncated: false });
    }
    setFdLoading(false);
  }, [tle]);

  useEffect(() => {
    if (!filterDropdown) {
      setFdValues([]);
      setFdSearch("");
      setFdSelected(new Set());
      setFdRegex(false);
      setFdSampled(false);
      setFdValueMeta({ totalDistinct: 0, truncated: false });
      return;
    }
    setFdSampled(false);
    if (filterDropdown.colName === "__tags__") {
      // Tags filter — load tags from DB
      const existing = ct?.tagFilter;
      // Handle both array tagFilter (checkbox selection) and string tagFilter ("Show Only IOC Matches" button)
      const hasExisting = existing && (Array.isArray(existing) ? existing.length > 0 : typeof existing === "string");
      const existingSet = hasExisting
        ? new Set(Array.isArray(existing) ? existing : [existing])
        : new Set();
      setFdSelected(existingSet);
      setFdSearch("");
      setFdRegex(false);
      (async () => {
        setFdLoading(true);
        const tags = await tle.getAllTags(ct.id);
        const vals = (tags || []).map((t) => ({ val: t.tag, cnt: t.cnt }));
        setFdValues(vals);
        setFdValueMeta({ totalDistinct: vals.length, truncated: false });
        setFdLoading(false);
      })().catch(() => { setFdLoading(false); });
      return;
    }
    if (filterDropdown.colName === "__vt__") {
      // VT verdict filter — load VT verdict tags from DB
      const existing = ct?.checkboxFilters?.["__vt__"];
      const hasExisting = existing?.length > 0;
      setFdSelected(hasExisting ? new Set(existing) : new Set());
      setFdSearch("");
      setFdRegex(false);
      (async () => {
        setFdLoading(true);
        const tags = await tle.getAllTags(ct.id);
        const vals = (tags || []).filter((t) => t.tag.startsWith("VT:")).map((t) => ({ val: t.tag, cnt: t.cnt }));
        setFdValues(vals);
        setFdValueMeta({ totalDistinct: vals.length, truncated: false });
        setFdLoading(false);
      })().catch(() => { setFdLoading(false); });
      return;
    }
    if (filterDropdown.colName === "__vt__") {
      // VT verdict filter — load VT verdict tags from DB
      const existing = ct?.checkboxFilters?.["__vt__"];
      const hasExisting = existing?.length > 0;
      setFdSelected(hasExisting ? new Set(existing) : new Set());
      setFdSearch("");
      setFdRegex(false);
      (async () => {
        setFdLoading(true);
        const tags = await tle.getAllTags(ct.id);
        const vals = (tags || []).filter((t) => t.tag.startsWith("VT:")).map((t) => ({ val: t.tag, cnt: t.cnt }));
        setFdValues(vals);
        setFdLoading(false);
      })().catch(() => { setFdLoading(false); });
      return;
    }
    const existing = ct?.checkboxFilters?.[filterDropdown.colName];
    const hasExisting = checkboxFilterActive(existing);
    setFdSelected(hasExisting ? new Set(normalizeCheckboxFilterValues(existing)) : new Set());
    setFdSearch("");
    setFdRegex(false);
    loadFilterValues(filterDropdown.colName, "", !hasExisting, false);
  }, [filterDropdown?.colName]);

  useEffect(() => {
    if (!filterDropdown) return;
    if (filterDropdown.colName === "__tags__" || filterDropdown.colName === "__vt__") return; // Tags/VT don't support search-while-typing
    const t = setTimeout(() => loadFilterValues(filterDropdown.colName, fdSearch, false, fdRegex), 300);
    return () => clearTimeout(t);
  }, [fdSearch, fdRegex]);

  const applyCheckboxFilter = () => {
    if (!filterDropdown) return;
    const colName = filterDropdown.colName;
    // Tags filter — apply as tagFilter array
    // Unlike regular columns, "all tags selected" still means "show only tagged rows" (not all rows)
    if (colName === "__tags__") {
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        if (fdSelected.size === 0) return { ...t, tagFilter: null };
        return { ...t, tagFilter: [...fdSelected] };
      }));
      setFilterDropdown(null);
      return;
    }
    if (colName === "__vt__") {
      // VT filter — like tags, "all selected" still means "show only VT-tagged rows"
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        const newCbf = { ...t.checkboxFilters };
        if (fdSelected.size === 0) delete newCbf["__vt__"];
        else newCbf["__vt__"] = [...fdSelected];
        return { ...t, checkboxFilters: newCbf };
      }));
      setFilterDropdown(null);
      return;
    }
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const newCbf = { ...t.checkboxFilters };
      // "All selected = no filter" only when NOT searching (search narrows the list, so all-checked means the user wants only those values)
      if (fdSelected.size === 0 || (!fdSearch && fdSelected.size === fdValues.length)) delete newCbf[colName];
      else newCbf[colName] = [...fdSelected];
      return { ...t, checkboxFilters: newCbf };
    }));
    setFilterDropdown(null);
  };

  // ── Whole-column copy ────────────────────────────────────────────
  // Pull EVERY value of one column for the current filtered/searched view (full
  // dataset, not just the loaded window) and put it on the clipboard, one per line.
  // distinct:true → unique + sorted (ready to dedup/paste IPs, hostnames, etc.).
  // Defined BEFORE the keyboard-shortcuts effect that lists it in deps — a const
  // referenced in a dep array must be initialized first (else a TDZ crash at render).
  const copyColumnValues = useCallback(async (colName, { distinct = false } = {}) => {
    if (!tle || !ct || !colName) return;
    try {
      const af = activeFilters(ct);
      const res = await tle.getColumnValues(ct.id, colName, {
        searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly,
        tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
        rowIdFilter: ct.rowIdFilter || null,
        dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        sortCol: ct.sortCol || null,
        sortDir: ct.sortDir || "asc",
        distinct,
      });
      if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
      const values = res?.values || [];
      if (values.length === 0) { toast.info("No values to copy in that column for the current view."); return; }
      let copyValues = (dateTimeFormat && ct.tsColumns?.has(colName))
        ? values.map((v) => formatDateTime(v, dateTimeFormat, timezone))
        : values;
      if (distinct) {
        const seen = new Set();
        copyValues = copyValues.filter((v) => {
          const key = String(v ?? "");
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
      }
      await navigator.clipboard?.writeText(copyValues.join("\n"));
      setCopiedMsg(true);
      setTimeout(() => setCopiedMsg(false), 1200);
      const label = distinct ? "unique value" : "value";
      toast.success(`Copied ${formatNumber(copyValues.length)} ${label}${copyValues.length === 1 ? "" : "s"} from "${colName}"${res?.truncated ? " (truncated at 1,000,000)" : ""}`);
    } catch (err) {
      toast.error("Couldn't copy column", { detail: String(err?.message || err) });
    }
  }, [tle, ct, activeFilters, setCopiedMsg, dateTimeFormat, timezone]);

  const copySelectedRows = useCallback(async () => {
    if (!tle || !ct || selectionCount === 0) return;
    const hdrs = ct.headers.filter((h) => !ct.hiddenColumns?.has(h));
    const maxClipboardRows = 100_000;
    let selectedData = [];
    let truncated = false;

    try {
      if (!allRowsSelected) {
        const requestedIds = [...selectedRows].slice(0, maxClipboardRows);
        selectedData = await tle.getRowsByIds(ct.id, requestedIds);
        if (isIpcError(selectedData) || !Array.isArray(selectedData)) {
          throw new Error(ipcErrorMessage(selectedData, "Could not load selected rows"));
        }
        truncated = selectionCount > selectedData.length;
      } else {
        const { columnFilters, checkboxFilters } = activeFilters(ct);
        const rawSearch = ct.searchHighlight ? "" : ct.searchTerm;
        const effectiveSearch = rawSearch && rawSearch.trim().length < 2 ? "" : rawSearch;
        const batchSize = 10_000;
        let offset = 0;

        while (offset < (ct.totalFiltered || 0) && selectedData.length < maxClipboardRows) {
          const result = await tle.queryRows(ct.id, {
            offset,
            limit: batchSize,
            sortCol: ct.sortCol,
            sortDir: ct.sortDir,
            searchTerm: effectiveSearch,
            searchMode: ct.searchMode,
            searchCondition: ct.searchCondition || "contains",
            columnFilters,
            checkboxFilters,
            bookmarkedOnly: ct.showBookmarkedOnly,
            tagFilter: (ct.disabledFilters || new Set()).has("__tags__")
              ? null
              : (ct.tagFilter || null),
            rowIdFilter: ct.rowIdFilter || null,
            dateRangeFilters: ct.dateRangeFilters || {},
            advancedFilters: ct.advancedFilters || [],
          });
          if (isIpcError(result) || !Array.isArray(result?.rows)) {
            throw new Error(ipcErrorMessage(result, "Could not load selected rows"));
          }
          if (result.rows.length === 0) break;
          for (const row of result.rows) {
            if (!selectedRows.has(Number(row.__idx))) selectedData.push(row);
            if (selectedData.length >= maxClipboardRows) break;
          }
          offset += result.rows.length;
        }
        truncated = selectionCount > selectedData.length;
      }

      const lines = [hdrs.join("\t")];
      for (const row of selectedData) {
        lines.push(hdrs.map((h) =>
          String(row[h] || "").replace(/\t/g, " ").replace(/\r?\n/g, " ")
        ).join("\t"));
      }
      await navigator.clipboard?.writeText(lines.join("\n"));
      setCopiedMsg(true);
      setTimeout(() => setCopiedMsg(false), 1200);
      toast.success(`Copied ${formatNumber(selectedData.length)} selected row${selectedData.length === 1 ? "" : "s"}${truncated ? " (clipboard limit: 100,000; use Export for the full view)" : ""}`);
    } catch (err) {
      toast.error("Couldn't copy selected rows", { detail: String(err?.message || err) });
    }
  }, [
    tle,
    ct,
    selectionCount,
    allRowsSelected,
    selectedRows,
    activeFilters,
    setCopiedMsg,
  ]);

  // ── Keyboard shortcuts ───────────────────────────────────────────
  useEffect(() => {
    const h = (e) => {
      const mod = e.metaKey || e.ctrlKey;
      const target = e.target;
      const isTextControl = target instanceof HTMLElement
        && (target.matches("input, textarea, select") || target.isContentEditable);
      if (mod && e.key === "w") { e.preventDefault(); const cur = ctRef.current; if (cur) closeTabRef.current?.(cur.id); return; }
      if (mod && e.key === "s") { e.preventDefault(); handleSaveSessionRef.current?.(); }
      if (mod && e.shiftKey && e.key === "O") { e.preventDefault(); handleLoadSessionRef.current?.(); }
      if (mod && e.key === "o") { e.preventDefault(); runOpenFileDialog(); }
      if (mod && e.key === "f" && !e.shiftKey) { e.preventDefault(); document.getElementById("gs")?.focus(); }
      if (mod && e.shiftKey && e.key === "f") { e.preventDefault(); setModal(openSimpleModal("crossfind")); }
      if (mod && e.key === "e") { e.preventDefault(); handleExport(); }
      if (mod && e.key === "b") { e.preventDefault(); if (ct) up("showBookmarkedOnly", !ct.showBookmarkedOnly); }
      if (mod && e.key === "r") { e.preventDefault(); resetColumnWidthsRef.current?.(); }
      if (mod && (e.key === "?" || e.key === "/")) { e.preventDefault(); setModal(openSimpleModal("shortcuts")); return; }
      // ⌘⇧A / Ctrl+Shift+A — select an entire column (toggle). Targets the open column
      // menu's column, else the sorted column, else the first visible column.
      if (mod && e.shiftKey && (e.key === "A" || e.key === "a") && ct) {
        e.preventDefault();
        const visible = (ct.headers || []).filter((h) => !ct.hiddenColumns?.has(h));
        const target = (contextMenu?.colName && contextMenu.colName !== "__tags__") ? contextMenu.colName
          : (ct.sortCol && visible.includes(ct.sortCol)) ? ct.sortCol
          : visible[0] || null;
        if (target) setSelectedColumn(selectedColumn === target ? null : target);
        return;
      }
      // ⌘C with a selected column but no selected rows → copy that whole column's values.
      if (mod && e.key === "c" && selectedColumn && selectionCount === 0 && ct) {
        const sel = window.getSelection();
        if (sel && sel.toString().trim().length > 0) return;
        e.preventDefault();
        copyColumnValues(selectedColumn, { distinct: false });
        return;
      }
      if (mod && e.key === "c" && selectionCount > 0 && ct) {
        // If user has text selected in the DOM (e.g., detail panel cell), let native copy handle it
        const sel = window.getSelection();
        if (sel && sel.toString().trim().length > 0) return;
        e.preventDefault();
        copySelectedRows();
        return;
      }
      if (e.key === "Escape") {
        if (cellPopup) { setCellPopup(null); return; }
        if (modal?.type === "aiSecrets") {
          if (modal.tagMenuGroup) setModal((prev) => (prev?.type === "aiSecrets" ? { ...prev, tagMenuGroup: null, tagDraft: "" } : prev));
          return;
        }
        if (modal) { setModal(null); return; }
        if (filterDropdown) { setFilterDropdown(null); return; }
        if (dateRangeDropdown) { setDateRangeDropdown(null); return; }
        if (contextMenu) { setContextMenu(null); return; }
        if (cellContextMenu) { setCellContextMenu(null); return; }
        if (rowContextMenu) { setRowContextMenu(null); return; }
        if (fileMenuOpen) { setFileMenuOpen(false); return; }
        if (viewMenuOpen) { setViewMenuOpen(false); return; }
        if (toolsOpen) { setToolsOpen(false); return; }
        if (actionsMenuOpen) { setActionsMenuOpen(false); return; }
        if (helpMenuOpen) { setHelpMenuOpen(false); return; }
        if (detailPanelOpen && selectionCount > 0) { setDetailPanelOpen(false); return; }
        if (selectedColumn) { setSelectedColumn(null); return; }
        if (selectionCount > 0) {
          clearRowSelection();
          return;
        }
      }
      // Open context menu for selected row (Shift+F10 = standard context menu key)
      if (e.key === "F10" && e.shiftKey && lastClickedRow !== null && ct) {
        e.preventDefault();
        const item = getRowAt(lastClickedRow);
        const row = isGrouped ? (item?.data || item) : item;
        if (row && row.__idx) {
          const rTags = (ct.rowTags || {})[row.__idx] || [];
          // Position near the selected row using the scroll container
          const scrollEl = scrollRef.current;
          const rect = scrollEl ? scrollEl.getBoundingClientRect() : { left: 200, top: 200 };
          const yPos = rect.top + (lastClickedRow * ROW_HEIGHT) - scrollMapRef.current.logicalScrollTop + HEADER_HEIGHT + FILTER_HEIGHT + ROW_HEIGHT / 2;
          setRowContextMenu({ x: rect.left + 100, y: Math.min(Math.max(yPos, rect.top + 40), window.innerHeight - 300), rowId: row.__idx, rowIndex: lastClickedRow, currentTags: rTags, row });
        }
      }
      // Find next/prev: Ctrl+Right/Left or F3/Shift+F3
      if ((mod && e.key === "ArrowRight") || (e.key === "F3" && !e.shiftKey)) { e.preventDefault(); navigateSearch(1); }
      if ((mod && e.key === "ArrowLeft") || (e.key === "F3" && e.shiftKey)) { e.preventDefault(); navigateSearch(-1); }
      if (!isGrouped && !isTextControl && e.key === "ArrowDown" && lastClickedRow !== null && !mod) {
        e.preventDefault();
        const total = ct?.totalFiltered || rows.length;
        const next = Math.min(total - 1, lastClickedRow + 1);
        void selectSingleRowAt(next).then((selected) => {
          if (selected) requestAnimationFrame(() => {
            scrollToRow(next);
            requestAnimationFrame(() => scrollRef.current?.querySelector(`[data-row-index="${next}"]`)?.focus({ preventScroll: true }));
          });
        });
      }
      if (!isGrouped && !isTextControl && e.key === "ArrowUp" && lastClickedRow !== null && !mod) {
        e.preventDefault();
        const next = Math.max(0, lastClickedRow - 1);
        void selectSingleRowAt(next).then((selected) => {
          if (selected) requestAnimationFrame(() => {
            scrollToRow(next);
            requestAnimationFrame(() => scrollRef.current?.querySelector(`[data-row-index="${next}"]`)?.focus({ preventScroll: true }));
          });
        });
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [ct, activeTab, selectedRows, allRowsSelected, selectionCount, lastClickedRow, ct?.totalFiltered, isGrouped, getRowAt, searchMatchIdx, navigateSearch, selectedColumn, setSelectedColumn, copyColumnValues, copySelectedRows, contextMenu, clearRowSelection]);



  // ── Modal styles (shared by all modals) ───────────────────────
  const ms = makeModalStyles(th);

  // ── Helper: compute row background ───────────────────────────────
  const getRowBg = (ai, _row, sel, cm, bm) => {
    if (sel) return th.selection;
    if (cm) return cm.bg;
    if (bm) return th.bookmark;
    return ai % 2 === 0 ? th.rowEven : th.rowOdd;
  };


  // ── Empty state ──────────────────────────────────────────────────
  if (tabs.length === 0) {
    // Launch a capability from the home screen: remember the user's intent, open the
    // file picker, and (on import-complete) auto-open the matching analyzer with
    // pre-detected columns. If the user cancels the dialog, drop the intent so it can't
    // fire on a later, unrelated import.
    const launchCapabilityFromHome = async (capKey) => {
      // Arm the intent unbound; onImportStart binds it to the first import that begins
      // after arming (the one this dialog kicks off), so a later/parallel import can't
      // consume it and fire the analyzer on the wrong tab.
      pendingCapabilityRef.current = { capability: capKey, tabId: null };
      try {
        const res = await runOpenFileDialog();
        if (res == null) pendingCapabilityRef.current = null; // null === user canceled
      } catch {
        pendingCapabilityRef.current = null;
      }
    };

    // Capability tiles for the command-center home canvas. Each analyzer tile picks a
    // file and then auto-opens its analyzer (via pendingCapabilityRef → import-complete
    // → HOME_CAPABILITY_LAUNCHERS). `chip` states the input the analyzer needs; `outcome`
    // is the bottom hint describing what you get. Sigma scans raw EVTX with no import;
    // Open & Explore just drops you in the grid.
    const homeTiles = [
      { title: "Process Inspector", desc: "Process-chain threat scoring & execution-tree analysis", color: th.accent, capability: "processInspector", chip: "Sysmon · 4688", outcome: "Open → process tree", onClick: () => launchCapabilityFromHome("processInspector"),
        icon: <><path d="M12 3v5"/><path d="M12 8L6 12v3"/><path d="M12 8l6 4v3"/><rect x="9" y="2" width="6" height="4" rx="1"/><rect x="3" y="15" width="6" height="4" rx="1"/><rect x="15" y="15" width="6" height="4" rx="1"/></> },
      { title: "Lateral Movement", desc: "Cross-host pivots · RDP, WinRM & remote execution", color: th.accent, capability: "lateralMovement", chip: "4624 / 4625", outcome: "Open → pivot graph", onClick: () => launchCapabilityFromHome("lateralMovement"),
        icon: <><circle cx="5" cy="12" r="2.4"/><circle cx="19" cy="5" r="2.4"/><circle cx="19" cy="19" r="2.4"/><path d="M7 11l10-5M7 13l10 5"/></> },
      { title: "Persistence", desc: "Autostart, services, tasks, WMI & COM hijacks", color: th.accent, capability: "persistence", chip: "7045 / 4698", outcome: "Open → autoruns", onClick: () => launchCapabilityFromHome("persistence"),
        icon: <><path d="M12 21V9"/><circle cx="12" cy="6" r="3"/><path d="M5 13H3m4.5 5L6 19.5M18 13h2m-3.5 5l1.5 1.5"/></> },
      { title: "Sigma · Hayabusa", desc: "Sigma detection over raw EVTX — no import needed", color: th.accent, outcome: "Scan a directory →", ready: true, onClick: () => setModal(openSigmaModal({ scanMode: "evtx-dir" })),
        icon: <><circle cx="12" cy="12" r="9"/><path d="M12 4v8l5 3"/></> },
      { title: "Collect AI Artifacts", desc: "Claude, Codex, Cursor, ChatGPT & more — scan this Mac or a triage folder into one AI history timeline.", color: th.accent, chip: "Mac / folder", outcome: "Scan → AI timeline", onClick: () => setModal(openAiHistoryProfileScanModal()),
        icon: <><path d="M11 3l1.7 4.4L17 9l-4.3 1.6L11 15l-1.7-4.4L5 9l4.3-1.6z"/><path d="M17.6 14l.7 1.8 1.7.7-1.7.7-.7 1.8-.7-1.8-1.7-.7 1.7-.7z"/></> },
      { title: "Master File Table", desc: "Ransomware mass-encryption, in-place rewrites & recovery-target deletion across the $MFT", color: th.accent, capability: "mft", chip: "Raw $MFT", outcome: "Open → ransomware scan", onClick: () => launchCapabilityFromHome("mft"),
        icon: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><rect x="10" y="11" width="4" height="4" rx="1"/><path d="M10.5 11V9.5a1.5 1.5 0 0 1 3 0V11"/></> },
      { title: "USN Journal", desc: "Renames, deletions, exfil staging & self-deletion from the $J journal", color: th.accent, capability: "usn", chip: "$J / USN", outcome: "Open → journal triage", onClick: () => launchCapabilityFromHome("usn"),
        icon: <><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></> },
      { title: "Open & Explore", desc: "Just browse a large CSV / TSV / XLSX in a fast grid — filter, search & sort. No analyzer needed.", color: th.accent, chip: "Any file", outcome: "Open any file →", onClick: () => runOpenFileDialog(),
        icon: <><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18M15 3v18"/></> },
    ];
    return (
      <div onContextMenu={(e) => e.preventDefault()} style={{ display: "flex", height: "100vh", background: th.bg, fontFamily: "'SF Mono',Menlo,monospace", WebkitAppRegion: "drag", overflow: "hidden", position: "relative" }}
        onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; setDragOver(true); }}
        onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setDragOver(false); }}
        onDrop={(e) => { e.preventDefault(); setDragOver(false); pendingCapabilityRef.current = null; /* drag = "just open", not a tile launch → drop any armed capability so it can't fire on this import */ const files = [...e.dataTransfer.files]; if (files.length > 0 && tle) { const paths = files.map((f) => tle.getPathForFile(f)).filter(Boolean); if (paths.length > 0) runImportPaths(paths); } }}>
        <div style={{ width: 360, flexShrink: 0, display: "flex", flexDirection: "column", alignItems: "stretch", padding: "26px 24px 18px", borderRight: `1px solid ${th.border}`, background: th.panelBg, overflowY: "auto", WebkitAppRegion: "no-drag", zIndex: 2 }}>
          {/* IRFlow Logo — shield with timeline pulse */}
          <svg width="52" height="59" viewBox="0 0 64 72" fill="none" style={{ marginBottom: 14 }}>
            {/* Shield body */}
            <path d="M32 4L6 16v20c0 16.5 11.2 31.2 26 36 14.8-4.8 26-19.5 26-36V16L32 4z" fill={`${th.accent}18`} stroke={th.accent} strokeWidth="1.8" strokeLinejoin="round" />
            {/* Timeline pulse across shield */}
            <polyline points="14,40 22,40 25,28 29,48 33,22 37,44 40,34 42,40 50,40" fill="none" stroke={th.accent} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            {/* Clock tick marks at top of shield */}
            <circle cx="32" cy="20" r="6" fill="none" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="32" y1="15.5" x2="32" y2="17" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="32" y1="23" x2="32" y2="24.5" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="27.5" y1="20" x2="29" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="35" y1="20" x2="36.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            {/* Clock hands */}
            <line x1="32" y1="20" x2="32" y2="17.5" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
            <line x1="32" y1="20" x2="34.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
          </svg>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: th.text, margin: 0, fontFamily: "-apple-system, 'SF Pro Display', sans-serif", letterSpacing: "-0.01em" }}>IRFlow <span style={{ color: th.accent }}>Timeline</span></h1>
          <p style={{ color: th.textDim, fontSize: 14, letterSpacing: "0.14em", textTransform: "uppercase", margin: "10px 0 6px", fontWeight: 600 }}>DFIR Timeline Analysis for macOS</p>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "stretch", width: "100%", marginTop: 26, WebkitAppRegion: "no-drag" }}>
            <button onClick={() => runOpenFileDialog()} style={{ padding: "14px 48px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 8, fontSize: 16, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
              onMouseEnter={(e) => { e.currentTarget.style.filter = "brightness(1.1)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.filter = ""; }}>Open File</button>
	          </div>

          {/* Auto-restore prompt — shown when an autosave from a previous session is found */}
          {autoRestorable && autoRestorable !== false && (
            <div style={{ marginTop: 28, width: "100%", maxWidth: 480, padding: "12px 16px", background: th.warning + "12", border: `1px solid ${th.warning}55`, borderRadius: 10, display: "flex", alignItems: "center", gap: 12, WebkitAppRegion: "no-drag" }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0 }}>
                <path d="M12 8v4l3 2" /><circle cx="12" cy="12" r="9" />
              </svg>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ color: th.text, fontSize: 12, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                  Restore previous session?
                </div>
                <div style={{ color: th.textDim, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>
                  {autoRestorable.tabs?.length || 0} tab{autoRestorable.tabs?.length === 1 ? "" : "s"} · auto-saved {(() => { try { const d = new Date(autoRestorable.savedAt); const mins = Math.round((Date.now() - d.getTime()) / 60000); return mins < 1 ? "just now" : mins < 60 ? `${mins} min ago` : `${Math.round(mins/60)} hr ago`; } catch { return "recently"; } })()}
                </div>
              </div>
              <button onClick={handleAutoRestore} style={{ padding: "6px 14px", background: th.warning, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif", transition: "background var(--m-base) var(--ease-out)", flexShrink: 0 }}>Restore</button>
              <button onClick={handleDismissAutoRestore} aria-label="Dismiss" style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "4px 6px", lineHeight: 1, flexShrink: 0 }}>✕</button>
            </div>
          )}

          {/* Recent Files */}
          {recentFiles.length > 0 && (
            <div style={{ marginTop: 24, width: "100%", maxWidth: 420, WebkitAppRegion: "no-drag" }}>
              <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8, fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>Recent Files</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 180, overflow: "auto" }}>
                {recentFiles.slice(0, 8).map((fp, i) => {
                  const fileName = fp.split("/").pop();
                  const dirPath = fp.substring(0, fp.lastIndexOf("/"));
                  return (
                    <button key={i} onClick={() => runImportPaths([fp])}
                      style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: "transparent", border: "none", borderRadius: 6, cursor: "pointer", textAlign: "left", transition: "background var(--m-fast)", width: "100%" }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = th.textMuted + "12"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ flexShrink: 0 }}>
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
                      </svg>
                      <div style={{ flex: 1, overflow: "hidden" }}>
                        <div style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fileName}</div>
                        <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{dirPath}</div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <p style={{ color: th.textMuted, fontSize: 11, marginTop: "auto", paddingTop: 20 }}>{mod("O")} open · {mod("F")} search · {mod("B")} bookmarks · {mod("E")} export</p>
          <p style={{ color: th.textMuted, fontSize: 11, marginTop: 20, fontFamily: "-apple-system, sans-serif" }}>Created by <span style={{ color: th.textDim }}>Renzon Cruz</span> | <span style={{ color: th.accent }}>@r3nzsec</span></p>
        </div>

        {/* ── MAIN CANVAS — capability command center over a faint, honest data motif ── */}
        <div style={{ flex: 1, position: "relative", overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <svg aria-hidden="true" style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none", zIndex: 0 }} viewBox="0 0 1000 700" preserveAspectRatio="xMidYMid slice">
            <line x1="56" y1="568" x2="944" y2="568" stroke={th.accent} strokeWidth="1" opacity="0.12" />
            {Array.from({ length: 44 }).map((_, i) => {
              const x = 56 + i * 20.4;
              const h = 14 + Math.round(78 * Math.abs(Math.sin(i * 0.7) * Math.cos(i * 0.31 + 0.6)));
              const burst = i > 19 && i < 26;
              return <rect key={i} x={x} y={568 - h} width="11" height={h} rx="2" fill={burst ? th.danger : th.accent} opacity={burst ? 0.16 : 0.08} />;
            })}
          </svg>
          {/* Lateral-movement host graph — a faint, on-brand motif. DOM-anchored to the
              bottom-right corner (NOT the slice-scaled full-canvas viewBox) so it stays in
              genuinely empty space and can't drift under the top-row tiles like the old
              network motif did. Decorative only: aria-hidden + pointer-events:none. */}
          <svg aria-hidden="true" width="460" height="340" viewBox="0 0 460 340" fill="none"
            style={{ position: "absolute", bottom: 64, right: 28, pointerEvents: "none", zIndex: 0, opacity: 0.6 }}>
            <g opacity="0.22">
              {/* edges — green = "active" pivot paths echoing the analyzer, rest muted */}
              {[
                ["60,95", "165,62", th.accent], ["60,95", "150,150", th.accent],
                ["150,150", "250,120", th.sev.clean], ["165,62", "250,120", th.sev.clean],
                ["72,215", "150,150", th.accent], ["72,215", "255,215", th.accent],
                ["250,120", "255,215", th.accent], ["250,120", "388,72", th.accent],
                ["250,120", "398,158", th.sev.clean], ["255,215", "384,248", th.accent],
              ].map(([a, b, c], i) => {
                const [x1, y1] = a.split(","), [x2, y2] = b.split(",");
                return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={c} strokeWidth="1.3" />;
              })}
              {/* local hosts — rounded "machine" nodes */}
              {[[60, 95], [165, 62], [150, 150], [72, 215], [255, 215], [250, 120, true]].map(([cx, cy, hub], i) => {
                const w = hub ? 22 : 17, h = hub ? 17 : 13;
                return <rect key={i} x={cx - w / 2} y={cy - h / 2} width={w} height={h} rx="3"
                  fill={th.accent + "22"} stroke={th.accent} strokeWidth="1.3" />;
              })}
              {/* remote hosts — dashed targets with an alert tick, far right */}
              {[[388, 72], [398, 158], [384, 248]].map(([cx, cy], i) => (
                <g key={i}>
                  <circle cx={cx} cy={cy} r="13" fill="none" stroke={th.danger} strokeWidth="1.3" strokeDasharray="3 3" />
                  <rect x={cx - 5} y={cy - 4} width="10" height="8" rx="1.5" fill={th.danger + "33"} stroke={th.danger} strokeWidth="1" />
                  <path d={`M${cx + 9} ${cy - 14} l4 7 h-8 z`} fill={th.danger} opacity="0.8" />
                </g>
              ))}
            </g>
          </svg>
          <div style={{ position: "relative", zIndex: 1, flex: 1, overflowY: "auto", padding: "52px 52px 40px" }}>
            <div style={{ WebkitAppRegion: "no-drag", maxWidth: 980 }}>
              <h1 style={{ fontSize: 27, fontWeight: 700, color: th.text, margin: 0, fontFamily: "-apple-system, 'SF Pro Display', sans-serif", letterSpacing: "-0.015em" }}>Start an investigation</h1>
              <p style={{ fontSize: 13, color: th.textDim, margin: "9px 0 0", fontFamily: "-apple-system, sans-serif", maxWidth: 620, lineHeight: 1.55 }}>Drop a timeline anywhere in this window, or launch a capability below. SQLite-backed · built for 30–50GB+ files · CSV / TSV / XLSX / EVTX / Plaso / $MFT / $J.</p>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 14, marginTop: 26 }}>
                {homeTiles.map((t, i) => (
                  <button key={i} onClick={t.onClick}
                    style={{ textAlign: "left", display: "flex", flexDirection: "column", gap: 9, padding: "15px 16px 14px", background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 12, cursor: "pointer", transition: "all var(--m-base) var(--ease-out)", position: "relative", minHeight: 132 }}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = t.color + "66"; e.currentTarget.style.background = t.color + "0e"; e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.boxShadow = `0 10px 28px ${t.color}1f`; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = th.glassBorder; e.currentTarget.style.background = th.glassBg; e.currentTarget.style.transform = "none"; e.currentTarget.style.boxShadow = "none"; }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div style={{ width: 36, height: 36, borderRadius: 10, background: t.color + "1a", border: `1px solid ${t.color}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke={t.color} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{t.icon}</svg>
                      </div>
                      {t.ready
                        ? <span style={{ fontSize: 8, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.07em", color: th.sev.clean, background: th.sev.clean + "1a", border: `1px solid ${th.sev.clean}44`, borderRadius: 5, padding: "2px 6px" }}>Ready</span>
                        : t.chip && <span title="Input this analyzer needs" style={{ fontSize: 9, fontWeight: 600, color: th.textDim, background: th.textMuted + "14", border: `1px solid ${th.glassBorder}`, borderRadius: 5, padding: "2px 7px", whiteSpace: "nowrap", fontFamily: "-apple-system, sans-serif" }}>{t.chip}</span>}
                    </div>
                    <div style={{ fontSize: 13.5, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{t.title}</div>
                    <div style={{ fontSize: 11, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45, flex: 1 }}>{t.desc}</div>
                    <div style={{ fontSize: 10, color: t.color, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{t.outcome}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Drop overlay — shown across the whole window while dragging files */}
        {dragOver && (
          <div style={{ position: "absolute", inset: 0, zIndex: 20, display: "flex", alignItems: "center", justifyContent: "center", background: th.overlay, backdropFilter: "blur(3px)", WebkitBackdropFilter: "blur(3px)", pointerEvents: "none" }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, padding: "36px 60px", border: `2px dashed ${th.borderAccent}`, borderRadius: 16, background: th.selection }}>
              <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              <div style={{ color: th.accent, fontSize: 18, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>Drop files to import</div>
              <div style={{ color: th.textDim, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>CSV · TSV · XLSX · EVTX · Plaso · $MFT · $J</div>
            </div>
          </div>
        )}
        {/* Modal overlay — must render even in empty state for EVTX scanning */}
        <Suspense fallback={<ModalChunkFallback th={th} />}>
          {modal?.type === "sigma" && <SigmaRuleModal />}
          {modal?.type === "rdpBitmapCache" && <RdpBitmapCacheModal />}
          {modal?.type === "aiHistoryProfileScan" && <AiHistoryProfileScanModal />}
          {modal?.type === "aiHistoryExtract" && <AiHistoryExtractModal />}
          {modal?.type === "aiWorkspaceCorrelate" && <AiWorkspaceCorrelateModal th={th} />}
          {modal?.type === "aiHistoryScope" && <AiHistoryScopeModal />}
          {modal?.type === "aiSecrets" && <AiSecretsModal th={th} />}
        </Suspense>
	      </div>
    );
  }

  // ── Main render ──────────────────────────────────────────────────
  const isImporting = ct?.importing && importingTabs[ct?.id];
  const activeCheckboxCount = ct
    ? Object.keys(ct.checkboxFilters || {}).filter((k) => checkboxFilterActive(ct.checkboxFilters[k])).length
    : 0;
  const activeColumnFilterCount = ct ? Object.values(ct.columnFilters || {}).filter(Boolean).length : 0;
  const activeDateFilterCount = ct ? Object.keys(ct.dateRangeFilters || {}).length : 0;
  const activeAdvFilterCount = ct?.advancedFilters?.length || 0;
  const hasSearch = ct?.searchTerm?.trim() && !ct?.searchHighlight;
  const hasBookmarkFilter = !!ct?.showBookmarkedOnly;
  const hasTagFilter = !!ct?.tagFilter;
  const hasRowIdFilter = Array.isArray(ct?.rowIdFilter) && ct.rowIdFilter.length > 0;
  const totalActiveFilters = activeCheckboxCount + activeColumnFilterCount + activeDateFilterCount + activeAdvFilterCount + (hasSearch ? 1 : 0) + (hasBookmarkFilter ? 1 : 0) + (hasTagFilter ? 1 : 0) + (hasRowIdFilter ? 1 : 0);
  const clearAllFilters = () => {
    setTabs((prev) => prev.map((t) => t.id !== ct.id ? t : {
      ...t, searchTerm: "", columnFilters: {}, checkboxFilters: {},
      dateRangeFilters: {}, advancedFilters: [], showBookmarkedOnly: false,
      tagFilter: null, rowIdFilter: null, rowIdFilterLabel: null,
      searchHighlight: false, disabledFilters: new Set(),
    }));
  };

  return (
    <div onContextMenu={(e) => e.preventDefault()}
      onDragOver={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; setDragOver(true); }}
      onDragLeave={(e) => { if (e.currentTarget.contains(e.relatedTarget)) return; setDragOver(false); }}
      onDrop={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); setDragOver(false); const files = [...e.dataTransfer.files]; if (files.length > 0 && tle) { const paths = files.map((f) => tle.getPathForFile(f)).filter(Boolean); if (paths.length > 0) runImportPaths(paths); } }}
      style={{ display: "flex", flexDirection: "column", height: "100vh", background: th.bg, color: th.text, fontFamily: "'SF Mono','Fira Code',Menlo,monospace", fontSize: fontSize, overflow: "hidden" }}>
      <style>{`
        :root {
          --m-fast: 120ms;
          --m-base: 160ms;
          --m-slow: 240ms;
          --m-modal: 180ms;
          --ease-out: cubic-bezier(0.32, 0.72, 0, 1);
          --ease-out-soft: cubic-bezier(0.4, 0, 0.2, 1);
        }
        @keyframes tle-spin { to { transform: rotate(360deg) } }
        @keyframes tle-pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.6; transform: scale(0.95); } }
        @keyframes tle-modal-in { from { opacity: 0; transform: scale(0.97) translateY(8px); } to { opacity: 1; transform: scale(1) translateY(0); } }
        @keyframes tle-overlay-in { from { opacity: 0; } to { opacity: 1; } }
        ::-webkit-scrollbar { width: 14px; height: 14px; }
        ::-webkit-scrollbar-track { background: ${th.bg}; }
        ::-webkit-scrollbar-thumb { background: ${th.textMuted}; border-radius: 7px; border: 3px solid ${th.bg}; }
        ::-webkit-scrollbar-thumb:hover { background: ${th.textDim}; }
        ::-webkit-scrollbar-corner { background: ${th.bg}; }
        .tle-tb { transition: background var(--m-base) var(--ease-out), color var(--m-base) var(--ease-out); }
        .tle-tb:hover { background: ${th.glassHover} !important; }
        .tle-tab { transition: background var(--m-base) var(--ease-out), box-shadow var(--m-base) var(--ease-out); }
        .tle-tab:hover { background: ${th.glassHover} !important; }
        .pt-row { transition: background var(--m-base) var(--ease-out); }
        .pt-row:not(.pt-sel):hover { background: ${th.glassHover} !important; }
        input, select, textarea { transition: box-shadow var(--m-base) var(--ease-out), border-color var(--m-base) var(--ease-out); }
        input:not([type="color"]):not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="file"]):focus-visible,
        select:focus-visible,
        textarea:focus-visible { box-shadow: 0 0 0 2px ${th.accent}40; }
        /* Keyboard focus ring for buttons, links, and ARIA widgets. box-shadow is used
           (not outline) so it shows even on elements that set inline outline:none, and
           :focus-visible keeps mouse clicks ring-free. */
        button:focus-visible,
        a[href]:focus-visible,
        [role="button"]:focus-visible,
        [role="menuitem"]:focus-visible,
        [role="tab"]:focus-visible,
        [role="checkbox"]:focus-visible,
        [tabindex]:not([tabindex="-1"]):focus-visible { box-shadow: 0 0 0 2px ${th.accent}cc; border-radius: 4px; }
        .tle-settings-toggle,
        .tle-status-toggle { display: none !important; }
        @media (max-width: 1200px) {
          .tle-menubar-shell { gap: 6px !important; }
          .tle-menubar-left { min-width: 0; }
          .tle-toolbar-settings { display: none !important; }
          .tle-toolbar-settings[data-open="true"] {
            display: flex !important;
            position: absolute;
            top: calc(100% + 4px);
            right: 12px;
            z-index: 170;
            padding: 7px 8px !important;
            box-shadow: 0 12px 40px rgba(0,0,0,0.45);
          }
          .tle-settings-backdrop { display: block !important; }
          .tle-settings-toggle { display: inline-flex !important; }
          .tle-status-details { display: none !important; }
          .tle-status-details[data-open="true"] {
            display: flex !important;
            position: absolute;
            right: 8px;
            bottom: calc(100% + 5px);
            z-index: 170;
            max-width: calc(100vw - 16px);
            flex-wrap: wrap;
            padding: 8px 10px;
            background: ${th.modalBg}f2;
            border: 1px solid ${th.glassBorder};
            border-radius: 8px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.45);
          }
          .tle-status-toggle { display: inline-flex !important; }
          .tle-status-path { max-width: 260px !important; }
        }
        @media (max-width: 900px) {
          .tle-menubar-shell { flex-wrap: wrap; }
          .tle-search-slot {
            order: 3;
            flex: 1 0 100% !important;
            max-width: none !important;
          }
          .tle-search-slot > * { max-width: none !important; }
          .tle-indexing-indicator { margin-left: auto; }
          .tle-status-path { max-width: 150px !important; }
          .tle-search-options { gap: 6px 10px !important; }
          .tle-search-condition-options {
            flex: 1 1 100%;
            overflow-x: auto;
            padding-bottom: 2px;
          }
        }
        /* Respect the OS "reduce motion" setting — kill modal/toast/spin/pulse animations. */
        @media (prefers-reduced-motion: reduce) {
          *, *::before, *::after {
            animation-duration: 0.001ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.001ms !important;
          }
        }
      `}</style>

      {/* Drop overlay — shown when dragging files over the app */}
      {dragOver && (
        <div style={{ position: "fixed", inset: 0, zIndex: 9999, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}>
          <div style={{ padding: "40px 60px", border: `3px dashed ${th.accent}`, borderRadius: 14, background: `${th.bg}DD`, textAlign: "center" }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>+</div>
            <div style={{ color: th.accent, fontSize: 16, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Drop files to import</div>
            <div style={{ color: th.textMuted, fontSize: 11, marginTop: 4, fontFamily: "-apple-system, sans-serif" }}>CSV · TSV · XLSX · EVTX · Plaso · Raw $MFT · $J</div>
            <div style={{ color: th.textMuted, fontSize: 10, marginTop: 2, fontFamily: "-apple-system, sans-serif", opacity: 0.7 }}>Extensionless files auto-detected by content</div>
          </div>
        </div>
      )}

      {/* ── MenuBar + FilterBar ──────────────────────────────────── */}
      <Suspense fallback={<ShellChunkFallback th={th} />}>
        <MenuBar
          th={th} ct={ct} tabs={tabs} tle={tle}
          handleExport={handleExport} handleSaveSession={handleSaveSession} handleLoadSession={handleLoadSession}
          handleCheckForUpdates={handleCheckForUpdates} handleExtractResident={handleExtractResident}
          closeTab={closeTab} resetColumnWidths={resetColumnWidths} up={up} activeFilters={activeFilters}
          allFilteredRowsSelected={allFilteredRowsSelected} selectedRowData={selectedRowData} isGrouped={isGrouped}
          handleSelectAllRows={handleSelectAllRows}
          proximityFilter={proximityFilter} setProximityFilter={setProximityFilter}
          searchLoading={searchLoading} checkingForUpdates={checkingForUpdates} extracting={extracting}
          recentFiles={recentFiles} setRecentFiles={setRecentFiles}
          copiedMsg={copiedMsg} setCopiedMsg={setCopiedMsg}
          setColMgrSearch={setColMgrSearch}
          searchBar={
            <FilterBar th={th} ct={ct} up={up} isGrouped={isGrouped}
              searchLoading={searchLoading} searchMatchIdx={searchMatchIdx}
              searchMatchPosition={searchMatchPosition}
              highlightMatchCount={highlightMatchCount}
              navigateSearch={navigateSearch} />
          }
        />
      </Suspense>
      <SearchOptionsBar th={th} ct={ct} up={up} />


      {/* Cross-tab search results (auto-shown with 2+ tabs and active search) */}
      {crossTabCounts && crossTabOpen && crossTabCounts.results.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 12px", background: th.panelBg, borderBottom: `1px solid ${th.border}`, flexShrink: 0, overflowX: "auto" }}>
          <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap", marginRight: 4 }}>Across tabs:</span>
          {crossTabCounts.results.map((r) => (
            <button key={r.tabId} onClick={() => { if (r.count > 0) { setActiveTab(r.tabId); setTabs((prev) => prev.map((t) => t.id === r.tabId ? { ...t, searchTerm: crossTabCounts.term, searchMode: crossTabCounts.mode } : t)); } }}
              style={{ display: "flex", alignItems: "center", gap: 3, padding: "1px 8px", borderRadius: 10, border: `1px solid ${r.count > 0 ? th.borderAccent + "66" : th.border}`, background: r.tabId === activeTab ? th.selection : "transparent", cursor: r.count > 0 ? "pointer" : "default", fontSize: 10, color: r.count > 0 ? th.text : th.textMuted, whiteSpace: "nowrap" }}>
              <span style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis" }}>{r.name}</span>
              <span style={{ color: r.count > 0 ? th.success : th.textMuted, fontWeight: 600 }}>{formatNumber(r.count)}</span>
            </button>
          ))}
          <span style={{ color: th.textMuted, fontSize: 10, marginLeft: 4 }}>
            Total: {formatNumber(crossTabCounts.results.reduce((s, r) => s + r.count, 0))}
          </span>
          <button onClick={() => setCrossTabOpen(false)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, marginLeft: "auto", padding: "0 4px" }}>✕</button>
        </div>
      )}

      {/* ── TabBar ────────────────────────────────────────────── */}
      <TabBar
        th={th}
        scrollTop={scrollTop} selectedRows={selectedRows} allRowsSelected={allRowsSelected}
        selectionTabId={selectionTabId} selectAllScopeSignature={selectAllScopeSignature} lastClickedRow={lastClickedRow}
        setScrollTop={setScrollTop} setSelectedRows={setSelectedRows} setAllRowsSelected={setAllRowsSelected}
        setSelectionTabId={setSelectionTabId} setSelectAllScopeSignature={setSelectAllScopeSignature} setLastClickedRow={setLastClickedRow}
        setProximityFilter={setProximityFilter} scrollRef={scrollRef} closeTab={closeTab}
      />

      {/* Group Panel */}
      {ct && ct.dataReady && (
        <div
          onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setGroupDragOver(true); }}
          onDragLeave={() => setGroupDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setGroupDragOver(false); const col = e.dataTransfer.getData("text/column-name"); if (col) addGroupBy(col); }}
          style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 12px",
            background: groupDragOver ? th.accentSubtle : th.panelBg,
            borderBottom: `1px solid ${th.border}`, minHeight: 28, flexShrink: 0, transition: "background var(--m-base)",
            border: groupDragOver ? `1px dashed ${th.accent}` : undefined,
            borderRadius: groupDragOver ? 4 : 0, margin: groupDragOver ? "2px 4px" : 0 }}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={groupDragOver ? th.accent : isGrouped ? th.accent : th.textMuted} strokeWidth="2" style={{ flexShrink: 0 }}>
            <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
          </svg>
          {groupDragOver && !isGrouped ? (
            <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Drop here to group by column</span>
          ) : isGrouped ? (<>
            {(ct.groupByColumns || []).map((col, i) => (
              <span key={col} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                {i > 0 && <span style={{ color: th.textMuted, fontSize: 9 }}>›</span>}
                <span draggable
                  onDragStart={(e) => { e.stopPropagation(); e.dataTransfer.setData("text/group-reorder", col); setGroupReorderDrag(col); }}
                  onDragEnd={() => setGroupReorderDrag(null)}
                  onDragOver={(e) => { if (groupReorderDrag && groupReorderDrag !== col) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; } }}
                  onDrop={(e) => { e.preventDefault(); e.stopPropagation(); const dragCol = e.dataTransfer.getData("text/group-reorder"); if (dragCol && dragCol !== col) { setTabs((prev) => prev.map((t) => { if (t.id !== ct.id) return t; const cols = [...(t.groupByColumns || [])]; const fromIdx = cols.indexOf(dragCol); const toIdx = cols.indexOf(col); if (fromIdx < 0 || toIdx < 0) return t; cols.splice(fromIdx, 1); cols.splice(toIdx, 0, dragCol); return { ...t, groupByColumns: cols, expandedGroups: {}, groupData: [] }; })); setGroupReorderDrag(null); } }}
                  style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", background: groupReorderDrag === col ? `${th.accent}44` : `${th.accent}22`, border: `1px solid ${th.accent}4D`, borderRadius: 4, color: th.accent, fontSize: 10, fontWeight: 500, fontFamily: "'Segoe UI', system-ui, sans-serif", cursor: "grab" }}>
                  {col}
                  <button onClick={() => removeGroupBy(col)} style={{ background: "none", border: "none", color: th.accent, cursor: "pointer", fontSize: 9, padding: 0, lineHeight: 1, opacity: 0.7 }} title={`Remove ${col} grouping`}>✕</button>
                </span>
              </span>
            ))}
            <button onClick={() => setTabs((prev) => prev.map((t) => t.id === ct.id ? { ...t, groupByColumns: [], expandedGroups: {}, groupData: [] } : t))} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 9, padding: "1px 4px", fontFamily: "'Segoe UI', system-ui, sans-serif" }} title="Clear all grouping">Clear</button>
          </>) : (
            <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Drag a column header here to group</span>
          )}
          {totalActiveFilters > 0 && (
            <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 8, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
              <span style={{ color: th.borderAccent }}>
                {totalActiveFilters} filter{totalActiveFilters > 1 ? "s" : ""} active
                {activeCheckboxCount > 0 ? ` (${activeCheckboxCount} value)` : ""}
              </span>
              <button onClick={clearAllFilters} style={{ background: (th.danger) + "18", border: `1px solid ${(th.danger)}55`, borderRadius: 4, color: th.danger, cursor: "pointer", fontSize: 10, padding: "1px 8px", fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>Clear All</button>
            </span>
          )}
        </div>
      )}


      {/* EVTX fast-message mode notice */}
      {ct?.messagesDeferred && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 14px", background: `${th.warning}0d`, borderBottom: `1px solid ${(th.warning)}22`, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>
          </svg>
          <span style={{ color: th.textDim }}>
            Large EVTX fast import is active. The Message column uses compact structured summaries; full analyzer fields are preserved.
          </span>
        </div>
      )}

      <SelectionBar
        th={th}
        selectionCount={selectionCount}
        hiddenSelectionCount={hiddenSelectionCount}
        allRowsSelected={allRowsSelected}
        onCopy={() => { void copySelectedRows(); }}
        onBulkActions={() => setModal({
          type: "bulkActions",
          scope: "selection",
          selectionFilterOptions,
          selectionCount,
        })}
        onClear={clearRowSelection}
      />

      {/* ── VirtualGrid (histogram + grid + detail panel) ──────── */}
      <Suspense fallback={<Loading label="Loading grid…" size="md" />}>
        <VirtualGrid
          th={th} ct={ct} tle={tle} up={up} tabs={tabs}
          isGrouped={isGrouped} isImporting={isImporting} importingTabs={importingTabs} importQueue={importQueue}
          displayRows={displayRows} rows={rows} visible={visible} skeletonIndices={skeletonIndices}
          totalCount={totalCount} totalH={totalH} physicalH={physicalH} pageOffset={pageOffset} si={si} tw={tw} rowOffset={rowOffset}
          allVisH={allVisH} pinnedH={pinnedH} scrollH={scrollH} pinnedOffsets={pinnedOffsets}
          selectedRows={selectedRows} allRowsSelected={allRowsSelected} selectionCount={selectionCount}
          lastClickedRow={lastClickedRow} setLastClickedRow={setLastClickedRow}
          selectedColumn={selectedColumn} setSelectedColumn={setSelectedColumn}
          selectedRow={selectedRow} selectedRowData={selectedRowData} detailVisible={detailVisible}
          compiledColors={compiledColors}
          handleScroll={handleScroll} scrollRef={scrollRef}
          handleSort={handleSort} handleHeaderDblClick={handleHeaderDblClick}
          handleBookmark={handleBookmark}
          handleRowClick={handleRowClick} handleCheckboxToggle={handleCheckboxToggle}
          handleSelectAllRows={handleSelectAllRows}
          openGridContextMenu={handleNativeRightClick}
          handleGroupSelectAll={handleGroupSelectAll} getGroupCheckState={getGroupCheckState}
          expandGroup={expandGroup} collapseGroup={collapseGroup}
          loadMoreGroupRows={loadMoreGroupRows} getRowAt={getRowAt}
          pinColumn={pinColumn} unpinColumn={unpinColumn}
          addGroupBy={addGroupBy} removeGroupBy={removeGroupBy}
          reorderColumn={reorderColumn} autoFitColumn={autoFitColumn}
          onDetailResizeStart={onDetailResizeStart} onHistResizeStart={onHistResizeStart}
          copyCell={copyCell}
          renderCell={renderCell} fmtCell={fmtCell} gw={gw} getRowBg={getRowBg}
          filterDropdown={filterDropdown} setFilterDropdown={setFilterDropdown}
          dateRangeDropdown={dateRangeDropdown} setDateRangeDropdown={setDateRangeDropdown}
          contextMenu={contextMenu} setContextMenu={setContextMenu}
          cellContextMenu={cellContextMenu} setCellContextMenu={setCellContextMenu}
          rowContextMenu={rowContextMenu} setRowContextMenu={setRowContextMenu}
          cellPopup={cellPopup} setCellPopup={setCellPopup}
          headerDragOver={headerDragOver} setHeaderDragOver={setHeaderDragOver}
          resizingCol={resizingCol} setResizingCol={setResizingCol}
          resizeX={resizeX} setResizeX={setResizeX}
          resizeW={resizeW} setResizeW={setResizeW}
          tagColWidth={tagColWidth} setTagColWidth={setTagColWidth}
          histogramVisible={histogramVisible} histogramCol={histogramCol} setHistogramCol={setHistogramCol}
          histogramData={histogramData} histogramLoaded={histogramLoaded}
          histContainerRef={histContainerRef} histContainerWidth={histContainerWidth}
          histBrushRef={histBrushRef} histSvgRectRef={histSvgRectRef}
          histBrushOverlayRef={histBrushOverlayRef} histBrushLabelRef={histBrushLabelRef}
          histBarGeomRef={histBarGeomRef}
          extracting={extracting} extractProgress={extractProgress}
          detailPanelRef={detailPanelRef} detailPanelHeight={detailPanelHeight}
          onFilterToSession={isAiHistorySourceFormat(ct?.sourceFormat) ? filterToAiSession : undefined}
          onCorrelateWorkspace={isAiHistorySourceFormat(ct?.sourceFormat) ? correlateAiWorkspace : undefined}
          ImportProgress={ImportProgress}
          sortTimerRef={sortTimerRef} justResizedRef={justResizedRef}
          searchLoading={searchLoading} fontSize={fontSize}
        />
      </Suspense>


      {/* ── StatusBar ─────────────────────────────────────────── */}
      <StatusBar
        th={th} ct={ct} isGrouped={isGrouped}
        selectionCount={selectionCount}
        copiedMsg={copiedMsg} setCopiedMsg={setCopiedMsg}
        pinnedH={pinnedH} allVisH={allVisH}
        searchLoading={searchLoading} searchElapsed={searchElapsed}
        visibleRowStart={visibleRowStart} visibleRowEnd={visibleRowEnd}
        activeCheckboxCount={activeCheckboxCount}
        totalActiveFilters={totalActiveFilters} clearAllFilters={clearAllFilters} up={up}
      />

      {updaterPopup && (() => {
        const phase = updaterPopup.phase || "checking";
        const progress = Math.max(0, Math.min(100, Number(updaterPopup.percent) || 0));
        const accent = phase === "error"
          ? (th.danger)
          : phase === "downloaded"
            ? (th.success)
            : th.accent;
        const title = phase === "checking"
          ? "Checking for Updates"
          : phase === "downloading"
            ? `Downloading ${updaterPopup.version || "Update"}`
            : phase === "downloaded"
              ? "Update Ready"
              : phase === "installing"
                ? "Installing Update"
                : phase === "no-update"
                  ? "No Updates Available"
                  : phase === "not-configured"
                    ? "Updates Not Configured"
                    : "Update Status";
        const detailText = phase === "downloading"
          ? [
              `${progress.toFixed(progress >= 10 ? 0 : 1)}% downloaded`,
              updaterPopup.total ? `${formatBytes(updaterPopup.transferred || 0)} of ${formatBytes(updaterPopup.total)}` : "",
              updaterPopup.bytesPerSecond ? `${formatBytes(updaterPopup.bytesPerSecond)}/s` : "",
            ].filter(Boolean).join("  •  ")
          : updaterPopup.detail || "";
        const releaseNotes = String(updaterPopup.releaseNotes || "").trim().slice(0, 500);
        return (
          <div style={{ position: "fixed", right: 18, bottom: 18, width: 360, maxWidth: "calc(100vw - 32px)", background: `linear-gradient(160deg, ${th.modalBg}f2, ${th.panelBg}f2)`, border: `1px solid ${accent}66`, borderRadius: 14, boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", zIndex: 160, overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ padding: "12px 14px 10px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, background: `linear-gradient(135deg, ${accent}14, transparent)` }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                <div style={{ width: 28, height: 28, borderRadius: 14, display: "flex", alignItems: "center", justifyContent: "center", background: `${accent}18`, color: accent, flexShrink: 0 }}>
                  {phase === "downloaded" ? (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  ) : phase === "error" ? (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="15" y1="9" x2="9" y2="15" />
                      <line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                  ) : (
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" style={{ animation: phase === "checking" || phase === "downloading" || phase === "installing" ? "tle-spin 1.1s linear infinite" : "none" }}>
                      <path d="M21 12a9 9 0 1 1-2.64-6.36" />
                      <polyline points="21 3 21 9 15 9" />
                    </svg>
                  )}
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: th.text, fontSize: 14, fontWeight: 700, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{title}</div>
                  {updaterPopup.version && phase !== "no-update" && phase !== "checking" && (
                    <div style={{ color: th.textMuted, fontSize: 11, marginTop: 2, fontFamily: "'SF Mono', Menlo, monospace" }}>Version {updaterPopup.version}</div>
                  )}
                </div>
              </div>
              {["downloaded", "no-update", "not-configured", "error"].includes(phase) && (
                <button onClick={() => setUpdaterPopup(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, lineHeight: 1, padding: 0, flexShrink: 0 }}>✕</button>
              )}
            </div>

            <div style={{ padding: "12px 14px 14px" }}>
              <div style={{ color: th.text, fontSize: 13, lineHeight: 1.45, fontFamily: "-apple-system, sans-serif" }}>
                {updaterPopup.message || (phase === "checking" ? "Checking for updates..." : "")}
              </div>
              {detailText && <div style={{ color: th.textMuted, fontSize: 11, lineHeight: 1.45, marginTop: 6, fontFamily: "-apple-system, sans-serif" }}>{detailText}</div>}

              {phase === "downloading" && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ height: 8, borderRadius: 999, overflow: "hidden", background: `${th.border}44`, border: `1px solid ${th.border}22` }}>
                    <div style={{ width: `${progress}%`, height: "100%", background: `linear-gradient(90deg, ${th.accent}, ${th.accentHover || th.accent})`, transition: "width var(--m-base) ease" }} />
                  </div>
                </div>
              )}

              {phase === "downloaded" && (
                <div style={{ marginTop: 12, padding: "10px 11px", borderRadius: 10, background: `${th.success}14`, border: `1px solid ${(th.success)}33`, color: th.text, fontSize: 12, lineHeight: 1.45, fontFamily: "-apple-system, sans-serif" }}>
                  Restart required. Install the update to apply the new version to the app currently open.
                </div>
              )}

              {releaseNotes && phase !== "checking" && phase !== "installing" && (
                <div style={{ marginTop: 12, maxHeight: 112, overflow: "auto", padding: "10px 11px", borderRadius: 10, background: `${th.border}12`, border: `1px solid ${th.border}22`, color: th.textMuted, fontSize: 11, lineHeight: 1.45, whiteSpace: "pre-wrap", fontFamily: "-apple-system, sans-serif" }}>
                  {releaseNotes}
                </div>
              )}

              {["downloaded", "no-update", "not-configured", "error"].includes(phase) && (
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
                  {phase === "downloaded" ? (
                    <>
                      <button onClick={() => setUpdaterPopup(null)} style={ms.bs}>Later</button>
                      <button onClick={handleInstallUpdate} style={ms.bp}>Restart and Install</button>
                    </>
                  ) : (
                    <button onClick={() => setUpdaterPopup(null)} style={ms.bs}>Close</button>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* Modals */}
      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Stacking / Value Frequency Analysis */}
        {modal?.type === "stacking" && ct && <StackingModal />}
        {/* Column Stats Modal */}
        {modal?.type === "columnStats" && ct && <ColumnStatsModal />}
        {/* Filter Presets Modal */}
        {modal?.type === "presets" && ct && <PresetsModal />}
        {modal?.type === "colors" && ct && <ColorModal th={th} ct={ct} up={up} ms={ms} />}
        {modal?.type === "columns" && ct && <ColModal th={th} ct={ct} up={up} ms={ms} colMgrSearch={colMgrSearch} setColMgrSearch={setColMgrSearch} colMgrDragOver={colMgrDragOver} setColMgrDragOver={setColMgrDragOver} />}
        {modal?.type === "shortcuts" && <ShortModal th={th} ms={ms} />}
        {modal?.type === "quickHelp" && <QuickHelpModal />}
      </Suspense>
      {modal?.type === "about" && (
        <Overlay th={th}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 40, marginBottom: 8 }}>⌬</div>
            <h2 style={{ margin: "0 0 4px", fontSize: 20, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>IRFlow Timeline</h2>
            <div style={{ fontSize: 12, color: th.textMuted, marginBottom: 16, fontFamily: "-apple-system, sans-serif" }}>Version {APP_VERSION}</div>
            <div style={{ textAlign: "left", background: th.bgAlt, borderRadius: 8, padding: 16, marginBottom: 16 }}>
              <p style={{ margin: "0 0 8px", fontSize: 12, color: th.text, lineHeight: 1.6, fontFamily: "-apple-system, sans-serif" }}>
                {APP_DESCRIPTION}
              </p>
              <p style={{ margin: "0 0 8px", fontSize: 12, color: th.text, lineHeight: 1.6, fontFamily: "-apple-system, sans-serif" }}>
                Native ingestion covers CSV, TSV, XLS/XLSX, Plaso, raw $MFT and $UsnJrnl, plus EVTX through bounded 64 KiB chunk reads up to the format's approximately 4 GiB limit. AI evidence includes prompts, responses, tool calls, shell commands, and bounded tool output from supported assistants.
              </p>
              <p style={{ margin: 0, fontSize: 12, color: th.text, lineHeight: 1.6, fontFamily: "-apple-system, sans-serif" }}>
                Built-in investigation includes Sigma and Hayabusa detection, process trees, lateral movement, persistence, ransomware and NTFS analytics, AI secret exposure hunting, IOC and VirusTotal enrichment, RDP bitmap recovery, tagging, and reporting.
              </p>
            </div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: th.text, marginBottom: 8, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Author</div>
              <div style={{ fontSize: 13, color: th.text, marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Renzon Cruz</div>
              <div style={{ display: "flex", justifyContent: "center", gap: 16 }}>
                <a href="#" onClick={(e) => { e.preventDefault(); window.tle?.openExternal("https://www.linkedin.com/in/renzoncruz"); }}
                  style={{ fontSize: 12, color: th.accent, textDecoration: "none", cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>LinkedIn</a>
                <a href="#" onClick={(e) => { e.preventDefault(); window.tle?.openExternal("https://x.com/r3nzsec"); }}
                  style={{ fontSize: 12, color: th.accent, textDecoration: "none", cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Twitter</a>
                <a href="#" onClick={(e) => { e.preventDefault(); window.tle?.openExternal("https://github.com/r3nzsec/irflow-timeline"); }}
                  style={{ fontSize: 12, color: th.accent, textDecoration: "none", cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>GitHub</a>
              </div>
            </div>
            <button onClick={() => setModal(null)} style={ms.bp}>OK</button>
          </div>
        </Overlay>
      )}
      {modal?.type === "sheets" && <SheetModal th={th} ms={ms} tle={tle} />}
      {modal?.type === "tags" && ct && (
        <Overlay th={th}>
          <h3 style={ms.mh}>Manage Tags</h3>
          <div style={{ maxHeight: "50vh", overflow: "auto", marginBottom: 12 }}>
            {Object.entries(ct.tagColors || {}).map(([tag, color]) => (
              <div key={tag} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0", borderBottom: `1px solid ${th.bgAlt}` }}>
                <input type="color" value={color} onChange={(e) => up("tagColors", { ...ct.tagColors, [tag]: e.target.value })}
                  style={{ width: 20, height: 16, border: "none", cursor: "pointer", borderRadius: 3, padding: 0 }} />
                <span style={{ flex: 1, color: th.text, fontSize: 12 }}>{tag}</span>
                <button onClick={() => { const tc = { ...ct.tagColors }; delete tc[tag]; up("tagColors", tc); }}
                  style={{ background: "none", border: "none", color: th.danger, cursor: "pointer", fontSize: 12 }}>✕</button>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <input id="new-tag-input" placeholder="New tag name..." style={ms.ip} onKeyDown={(e) => {
              if (e.key === "Enter" && e.target.value.trim()) {
                const name = e.target.value.trim();
                if (!ct.tagColors[name]) up("tagColors", { ...ct.tagColors, [name]: th.sev.low });
                e.target.value = "";
              }
            }} />
            <button onClick={() => {
              const inp = document.getElementById("new-tag-input");
              const name = inp?.value?.trim();
              if (name && !ct.tagColors[name]) { up("tagColors", { ...ct.tagColors, [name]: th.sev.low }); inp.value = ""; }
            }} style={ms.bp}>Add</button>
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
          </div>
        </Overlay>
      )}

      {/* Cross-tab Find */}
      {modal?.type === "crossfind" && (
        <Overlay th={th}>
          <h3 style={ms.mh}>Find Across All Tabs</h3>
          <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
            <input id="cf-input" autoFocus defaultValue={crossFind?.term || ""} placeholder="Search term..."
              onKeyDown={(e) => { if (e.key === "Enter") handleCrossFind(e.target.value); }}
              style={{ flex: 1, background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, padding: "8px 10px", outline: "none", fontFamily: "inherit" }} />
            <button onClick={() => { const v = document.getElementById("cf-input")?.value; if (v) handleCrossFind(v); }}
              style={ms.bp}>Search</button>
          </div>
          {crossFind?.results && (
            <div style={{ maxHeight: "50vh", overflow: "auto" }}>
              {crossFind.results.length === 0 && <p style={{ color: th.textMuted, fontSize: 12 }}>No tabs open</p>}
              {crossFind.results.map((r) => (
                <div key={r.tabId}
                  onClick={() => {
                    if (r.count > 0) {
                      setActiveTab(r.tabId);
                      setTabs((prev) => prev.map((t) => t.id === r.tabId ? { ...t, searchTerm: crossFind.term, searchMode: "mixed" } : t));
                      setModal(null);
                    }
                  }}
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 10px", borderBottom: `1px solid ${th.bgAlt}`,
                    cursor: r.count > 0 ? "pointer" : "default", borderRadius: 4 }}
                  onMouseEnter={(e) => { if (r.count > 0) e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                  <span style={{ color: r.count > 0 ? th.text : th.textMuted, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 300 }}>{r.name}</span>
                  <span style={{ color: r.count > 0 ? th.success : th.textMuted, fontSize: 12, fontWeight: 600, flexShrink: 0, marginLeft: 12 }}>
                    {r.count > 0 ? `${formatNumber(r.count)} hits` : "0"}
                  </span>
                </div>
              ))}
              <div style={{ marginTop: 8, color: th.textMuted, fontSize: 11 }}>
                Total: {formatNumber(crossFind.results.reduce((s, r) => s + r.count, 0))} matches across {crossFind.results.filter((r) => r.count > 0).length} tab{crossFind.results.filter((r) => r.count > 0).length !== 1 ? "s" : ""}
              </div>
            </div>
          )}
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button onClick={() => setModal(null)} style={ms.bs}>Close</button>
          </div>
        </Overlay>
      )}

      {/* Temporal Proximity Search Modal */}
      {modal?.type === "proximity" && ct && (() => {
        const { pivotRow, pivotCol } = modal;
        const tsCols = [...(ct.tsColumns || new Set())];
        const selCol = modal.selCol ?? pivotCol ?? tsCols[0];
        const customN = modal.customN ?? 5;
        const customU = modal.customU ?? "m";
        const pivotVal = pivotRow?.[selCol] ?? "";
        const PROX_PRESETS = [
          { label: "±30s", ms: 30_000, short: "30s" },
          { label: "±1m", ms: 60_000, short: "1m" },
          { label: "±5m", ms: 300_000, short: "5m" },
          { label: "±15m", ms: 900_000, short: "15m" },
          { label: "±30m", ms: 1_800_000, short: "30m" },
          { label: "±1h", ms: 3_600_000, short: "1h" },
          { label: "±4h", ms: 14_400_000, short: "4h" },
          { label: "±1d", ms: 86_400_000, short: "1d" },
        ];
        const unitMs = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
        const customMs = (Number(customN) || 0) * (unitMs[customU] || 60_000);
        return (
          <Overlay th={th}>
            <h3 style={ms.mh}>Find Nearby Events</h3>
            <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 6, padding: "8px 10px", marginBottom: 12 }}>
              <div style={{ ...ms.lb, marginBottom: 2 }}>Pivot Timestamp</div>
              <div style={{ color: th.text, fontSize: 12, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", wordBreak: "break-all" }}>
                {pivotVal || <span style={{ color: th.textMuted, fontStyle: "italic" }}>(empty — select a timestamp column)</span>}
              </div>
            </div>
            {tsCols.length > 1 && (
              <div style={ms.fg}>
                <label style={ms.lb}>Timestamp Column</label>
                <select value={selCol} onChange={(e) => setModal((p) => ({ ...p, selCol: e.target.value }))} style={ms.sl}>
                  {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            )}
            <div style={ms.fg}>
              <label style={ms.lb}>Time Window</label>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 4 }}>
                {PROX_PRESETS.map((p) => (
                  <button key={p.label} disabled={!pivotVal}
                    onClick={() => applyProximity(selCol, pivotVal, p.ms, p.short)}
                    onMouseEnter={(e) => { if (pivotVal) e.currentTarget.style.borderColor = th.accent; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = th.btnBorder; }}
                    style={{ padding: "5px 12px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: pivotVal ? th.text : th.textMuted, fontSize: 12, cursor: pivotVal ? "pointer" : "not-allowed", fontFamily: "-apple-system,sans-serif", transition: "border-color var(--m-base)" }}>
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>Custom Window</label>
              <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 4 }}>
                <span style={{ color: th.textDim, fontSize: 12 }}>±</span>
                <input type="number" min="1" value={customN}
                  onChange={(e) => setModal((p) => ({ ...p, customN: e.target.value }))}
                  style={{ ...ms.ip, width: 70 }} />
                <select value={customU} onChange={(e) => setModal((p) => ({ ...p, customU: e.target.value }))} style={{ ...ms.sl, width: 100 }}>
                  <option value="s">seconds</option>
                  <option value="m">minutes</option>
                  <option value="h">hours</option>
                  <option value="d">days</option>
                </select>
                <button disabled={!pivotVal || customMs <= 0}
                  onClick={() => applyProximity(selCol, pivotVal, customMs, `${customN}${customU}`)}
                  style={{ ...ms.bp, opacity: (!pivotVal || customMs <= 0) ? 0.5 : 1, cursor: (!pivotVal || customMs <= 0) ? "not-allowed" : "pointer" }}>
                  Apply
                </button>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 6 }}>
              <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
            </div>
          </Overlay>
        );
      })()}

      {/* Find Duplicates Modal */}
      {modal?.type === "findDuplicates" && ct && (() => {
        const selCol = modal.selCol || ct.headers?.[0] || "";
        const result = modal.result;
        const loading = modal.loading;
        const handleFindDuplicates = async () => {
          setModal((p) => ({ ...p, loading: true, result: null }));
          const af = activeFilters(ct);
          const uniqueResult = await tle.getColumnUniqueValues(ct.id, selCol, {
            searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
            columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
            bookmarkedOnly: ct.showBookmarkedOnly, limit: 50000,
            tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
            rowIdFilter: ct.rowIdFilter || null,
            dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
          });
          const values = Array.isArray(uniqueResult) ? uniqueResult : (uniqueResult?.values || []);
          const dupes = values.filter((v) => v.cnt > 1);
          setModal((p) => ({
            ...p,
            loading: false,
            result: {
              dupes,
              totalValues: Number(uniqueResult?.totalDistinct || values.length),
              truncated: Boolean(uniqueResult?.truncated),
            },
          }));
        };
        return (
          <Overlay th={th}>
            <h3 style={ms.mh}>Find Duplicates</h3>
            <div style={ms.fg}>
              <label style={ms.lb}>Column</label>
              <select value={selCol} onChange={(e) => setModal((p) => ({ ...p, selCol: e.target.value, result: null }))} style={ms.sl}>
                {(ct.headers || []).filter((h) => !ct.hiddenColumns?.has(h)).map((h) => <option key={h} value={h}>{h}</option>)}
              </select>
            </div>
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <button onClick={handleFindDuplicates} disabled={loading} style={{ ...ms.bp, opacity: loading ? 0.6 : 1 }}>
                {loading ? "Scanning..." : "Find Duplicates"}
              </button>
            </div>
            {result && (
              <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 6, padding: "10px 12px", marginBottom: 12 }}>
                {result.truncated && (
                  <div role="status" style={{ fontSize: 11, color: th.warning, marginBottom: 8 }}>
                    Showing results from the top 50,000 of {formatNumber(result.totalValues)} distinct values. Narrow the timeline before treating this as exhaustive.
                  </div>
                )}
                {result.dupes.length > 0 ? (<>
                  <div style={{ fontSize: 12, color: th.text, marginBottom: 6 }}>
                    Found <b style={{ color: th.accent }}>{result.dupes.length}</b> values with duplicates
                    ({result.dupes.reduce((s, d) => s + d.cnt, 0)} total rows)
                  </div>
                  <div style={{ maxHeight: 200, overflow: "auto", fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                    {result.dupes.slice(0, 100).map((d, i) => (
                      <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "2px 0", borderBottom: `1px solid ${th.border}22` }}>
                        <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 320 }}>{d.val || "(empty)"}</span>
                        <span style={{ color: th.textMuted, flexShrink: 0, marginLeft: 8 }}>×{d.cnt}</span>
                      </div>
                    ))}
                    {result.dupes.length > 100 && <div style={{ color: th.textMuted, padding: "4px 0", fontStyle: "italic" }}>...and {result.dupes.length - 100} more</div>}
                  </div>
                </>) : (
                  <div style={{ fontSize: 12, color: th.success }}>No duplicates found — all values in this column are unique.</div>
                )}
              </div>
            )}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
              {result && result.dupes.length > 0 && (
                <button onClick={() => {
                  const dupeVals = result.dupes.map((d) => d.val == null || d.val === "" ? "" : String(d.val));
                  const existing = { ...(ct.checkboxFilters || {}) };
                  existing[selCol] = dupeVals;
                  up("checkboxFilters", existing);
                  setModal(null);
                }} style={ms.bp}>Filter to Duplicates</button>
              )}
            </div>
          </Overlay>
        );
      })()}

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Known-Bad IOC Matching Modal */}
        {modal?.type === "ioc" && ct && <IocModal />}

        {/* Gap Analysis Modal */}
        {modal?.type === "gapAnalysis" && ct && <GapAnalysisModal />}
      </Suspense>

      {/* Cell Detail Popup */}
      {cellPopup && (() => {
        // Timestamp converter: detect if value is a valid date
        const cpVal = cellPopup.value || "";
        const cpDate = cpVal ? new Date(cpVal) : null;
        const cpIsTs = cpDate && !isNaN(cpDate.getTime()) && ct?.tsColumns?.has(cellPopup.column);
        // PowerShell Base64 decoder: detect -enc/-EncodedCommand
        const cpEncMatch = cpVal.match(/(?:\s|^)(?:-e|-enc|-encodedcommand|-en|-ec)\s+([A-Za-z0-9+/=]{20,})/i);
        let cpDecoded = null;
        if (cpEncMatch) {
          try {
            const b64 = cpEncMatch[1];
            const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
            // PowerShell uses UTF-16LE encoding
            const decoded = new TextDecoder("utf-16le").decode(bytes);
            // Only accept if result is mostly printable ASCII/unicode
            if (decoded && /[\x20-\x7e]/.test(decoded)) cpDecoded = decoded;
          } catch { /* invalid base64 */ }
        }
        return (
        <div onClick={() => setCellPopup(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, backdropFilter: "blur(4px)" }}>
          <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "92vw", maxHeight: "80vh", display: "flex", flexDirection: "column", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${th.border}` }}>
              <span style={{ color: th.textDim, fontSize: 12, fontWeight: 600 }}>{cellPopup.column}</span>
              <div style={{ display: "flex", gap: 6 }}>
                <button onClick={() => copyCell(cellPopup.value, cellPopup.column)} style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 11, padding: "4px 10px", cursor: "pointer", display: "flex", alignItems: "center", gap: 4 }}>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                  Copy
                </button>
                <button onClick={() => setCellPopup(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px", lineHeight: 1 }}>✕</button>
              </div>
            </div>
            <div style={{ padding: "16px", overflow: "auto", maxHeight: "calc(80vh - 50px)" }}>
              <pre style={{ color: th.text, fontSize: 12, fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, lineHeight: 1.5 }}>{fmtCell(cellPopup.column, cpVal) || <span style={{ color: th.textMuted, fontStyle: "italic" }}>(empty)</span>}</pre>
              {/* Timestamp Converter */}
              {cpIsTs && (() => {
                const epoch = Math.floor(cpDate.getTime() / 1000);
                const epochMs = cpDate.getTime();
                const utc = cpDate.toISOString();
                const localFull = cpDate.toLocaleString("en-US", { dateStyle: "full", timeStyle: "long" });
                const localIso = cpDate.toLocaleString("sv-SE", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).replace(" ", "T");
                const ms3 = String(cpDate.getMilliseconds()).padStart(3, "0");
                const dayOfWeek = cpDate.toLocaleDateString("en-US", { weekday: "long", timeZone: "UTC" });
                // NTFS filetime: 100-nanosecond intervals since 1601-01-01
                const ntfsEpochOffset = 11644473600n;
                const ntfsFiletime = (BigInt(epochMs) / 1000n + ntfsEpochOffset) * 10000000n;
                const formats = [
                  ["UTC (ISO 8601)", utc],
                  ["UTC", `${cpDate.toISOString().replace("T", " ").replace("Z", "")} UTC`],
                  ["Local", localFull],
                  ["Local (ISO)", localIso],
                  ["Unix Epoch", String(epoch)],
                  ["Unix Epoch (ms)", String(epochMs)],
                  ["NTFS Filetime", ntfsFiletime.toString()],
                  ["Day of Week (UTC)", dayOfWeek],
                ];
                // Add configured timezone if set
                if (timezone && timezone !== "local" && timezone !== "UTC") {
                  try {
                    const tzFmt = cpDate.toLocaleString("en-US", { timeZone: timezone, dateStyle: "medium", timeStyle: "long" });
                    formats.splice(3, 0, [timezone, tzFmt]);
                  } catch { /* invalid tz */ }
                }
                return (
                  <div style={{ marginTop: 12, padding: "10px 12px", background: th.accentSubtle, border: `1px solid ${th.accent}33`, borderRadius: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                      <span style={{ fontSize: 11, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>Timestamp Converter</span>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 12px", alignItems: "baseline" }}>
                      {formats.map(([label, val]) => (
                        <Fragment key={label}>
                          <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif", textAlign: "right", whiteSpace: "nowrap" }}>{label}</span>
                          <span onClick={() => { navigator.clipboard?.writeText(val); setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200); }}
                            style={{ color: th.text, fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", cursor: "pointer", padding: "1px 4px", borderRadius: 3, wordBreak: "break-all" }}
                            title="Click to copy"
                            onMouseEnter={(e) => { e.currentTarget.style.background = th.glassBg; }}
                            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                            {val}
                          </span>
                        </Fragment>
                      ))}
                    </div>
                  </div>
                );
              })()}
              {/* Decoded PowerShell */}
              {cpDecoded && (
                <div style={{ marginTop: 12, padding: "10px 12px", background: `${th.danger}11`, border: `1px solid ${th.danger}33`, borderRadius: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontSize: 11, color: th.danger, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Decoded PowerShell (-enc)</span>
                    <button onClick={() => { navigator.clipboard?.writeText(cpDecoded); setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200); }}
                      style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 10, padding: "2px 8px", cursor: "pointer", display: "flex", alignItems: "center", gap: 3 }}>
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                      Copy
                    </button>
                  </div>
                  <pre style={{ color: th.text, fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, lineHeight: 1.5 }}>{cpDecoded}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
        );
      })()}

      {/* Filter Dropdown */}
      {filterDropdown && (
        <>
          <div aria-hidden="true" onClick={() => setFilterDropdown(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
          <div role="dialog" aria-modal="true" aria-label={`Filter values for ${filterDropdown.colName}`} onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "fixed", left: filterDropdown.dx ?? Math.min(filterDropdown.x, window.innerWidth - 400), top: filterDropdown.dy ?? Math.min(filterDropdown.y, window.innerHeight - 440), width: 380, height: 420, minWidth: 260, minHeight: 200, maxWidth: "90vw", maxHeight: "90vh", background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 10, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", zIndex: 200, display: "flex", flexDirection: "column", overflow: "hidden", resize: "both", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ padding: "4px 8px", flexShrink: 0, display: "flex", alignItems: "center", gap: 6, borderBottom: `1px solid ${th.border}`, cursor: "grab", userSelect: "none" }}
              onMouseDown={(e) => {
                if (e.button !== 0) return;
                e.preventDefault();
                e.stopPropagation();
                const panel = e.currentTarget.parentElement;
                const rect = panel.getBoundingClientRect();
                const ox = e.clientX - rect.left, oy = e.clientY - rect.top;
                const onMove = (ev) => { ev.preventDefault(); panel.style.left = (ev.clientX - ox) + "px"; panel.style.top = (ev.clientY - oy) + "px"; };
                const onUp = (ev) => {
                  ev.stopPropagation();
                  document.removeEventListener("mousemove", onMove);
                  document.removeEventListener("mouseup", onUp, true);
                };
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", onUp, true);
              }}>
              <span style={{ color: th.textDim, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", flex: 1 }}>Filter — {filterDropdown.colName === "__tags__" ? "Tags" : filterDropdown.colName === "__vt__" ? "VT Verdict" : filterDropdown.colName}</span>
              <button aria-label="Close value filter" onClick={() => setFilterDropdown(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, width: 26, height: 26, padding: 0, lineHeight: 1 }}>✕</button>
            </div>
            <div style={{ padding: "8px 8px 4px", flexShrink: 0, display: "flex", gap: 4 }}>
              <input value={fdSearch} onChange={(e) => setFdSearch(e.target.value)} placeholder={fdRegex ? "Regex pattern..." : "Search values..."} autoFocus
                style={{ flex: 1, background: th.bgInput, border: `1px solid ${fdRegex && fdSearch ? (() => { try { new RegExp(fdSearch); return th.btnBorder; } catch { return th.danger; } })() : th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "5px 8px", outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
              <button onClick={() => setFdRegex((v) => !v)} title="Toggle regex mode"
                style={{ padding: "3px 7px", background: fdRegex ? th.accentSubtle : th.btnBg, border: `1px solid ${fdRegex ? th.accent : th.btnBorder}`, borderRadius: 4, color: fdRegex ? th.accent : th.textMuted, fontSize: 11, cursor: "pointer", fontFamily: "monospace", fontWeight: 600, flexShrink: 0 }}>.*</button>
            </div>
            <div style={{ display: "flex", gap: 4, padding: "2px 8px 4px", flexShrink: 0 }}>
              <button onClick={() => setFdSelected(new Set(fdValues.map((v) => v.val)))} style={ms.bsm}>Select All</button>
              <button onClick={() => setFdSelected(new Set())} style={ms.bsm}>Clear</button>
              <span style={{ flex: 1 }} />
              <span role="status" style={{ color: fdValueMeta.truncated ? th.warning : th.textMuted, fontSize: 11, alignSelf: "center" }}>
                {fdSampled
                  ? `${formatNumber(fdValues.length)} sampled values`
                  : fdValueMeta.truncated
                  ? `Top ${formatNumber(fdValues.length)} of ${formatNumber(fdValueMeta.totalDistinct)}${fdSearch ? " — refine search" : " — search for more"}`
                  : `${formatNumber(fdValueMeta.totalDistinct)} values`}
              </span>
            </div>
            <div style={{ flex: 1, overflow: "auto", padding: "0 4px" }}>
              {fdLoading ? (
                <Loading />
              ) : fdValues.length === 0 ? (
                <div style={{ padding: 16, textAlign: "center", color: th.textMuted, fontSize: 11 }}>No values found</div>
              ) : (
                fdValues.map((v) => (
                  <label key={v.val ?? "__empty"} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", cursor: "pointer", borderRadius: 3, fontSize: 11, color: th.text }}>
                    <input type="checkbox" checked={fdSelected.has(v.val)} onChange={() => { const s = new Set(fdSelected); s.has(v.val) ? s.delete(v.val) : s.add(v.val); setFdSelected(s); }}
                      style={{ accentColor: th.borderAccent, width: 18, height: 18, flexShrink: 0 }} />
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.val || "(empty)"}</span>
                    <span style={{ color: th.textMuted, fontSize: 10, flexShrink: 0 }}>{formatNumber(v.cnt)}</span>
                  </label>
                ))
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, padding: "6px 8px", borderTop: `1px solid ${th.border}` }}>
              <button onClick={() => {
                if (filterDropdown.colName === "__tags__") { up("tagFilter", null); setFilterDropdown(null); return; }
                const newCbf = { ...ct.checkboxFilters }; delete newCbf[filterDropdown.colName]; up("checkboxFilters", newCbf); setFilterDropdown(null);
              }} style={ms.bsm}>Reset</button>
              <button onClick={() => setFilterDropdown(null)} style={ms.bsm}>Cancel</button>
              <button onClick={applyCheckboxFilter} style={{ padding: "4px 11px", minHeight: 26, background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 4, fontSize: 11, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Apply</button>
            </div>
          </div>
        </>
      )}

      {/* Date Range Dropdown */}
      {dateRangeDropdown && (
        <>
          <div aria-hidden="true" onClick={() => setDateRangeDropdown(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
          <div role="dialog" aria-modal="true" aria-label={`Date range for ${dateRangeDropdown.colName}`} onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "fixed", left: Math.min(dateRangeDropdown.x, window.innerWidth - 300), top: Math.min(dateRangeDropdown.y, window.innerHeight - 220), width: 290, background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 10, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", zIndex: 200, padding: 12, animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
            <div style={{ color: th.textDim, fontSize: 11, marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Date Range — {dateRangeDropdown.colName}</div>
            <div style={{ marginBottom: 8 }}>
              <label style={{ display: "block", color: th.textMuted, fontSize: 11, marginBottom: 2, fontFamily: "-apple-system, sans-serif" }}>From</label>
              <input type="datetime-local" value={dateRangeDropdown.from} onChange={(e) => setDateRangeDropdown({ ...dateRangeDropdown, from: e.target.value })}
                style={{ width: "100%", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "4px 6px", outline: "none", fontFamily: "inherit", boxSizing: "border-box", colorScheme: themeName }} />
            </div>
            <div style={{ marginBottom: 10 }}>
              <label style={{ display: "block", color: th.textMuted, fontSize: 11, marginBottom: 2, fontFamily: "-apple-system, sans-serif" }}>To</label>
              <input type="datetime-local" value={dateRangeDropdown.to} onChange={(e) => setDateRangeDropdown({ ...dateRangeDropdown, to: e.target.value })}
                style={{ width: "100%", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "4px 6px", outline: "none", fontFamily: "inherit", boxSizing: "border-box", colorScheme: themeName }} />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 6 }}>
              <button onClick={() => {
                const newDrf = { ...ct.dateRangeFilters };
                delete newDrf[dateRangeDropdown.colName];
                up("dateRangeFilters", newDrf);
                setDateRangeDropdown(null);
              }} style={ms.bsm}>Clear</button>
              <button onClick={() => setDateRangeDropdown(null)} style={ms.bsm}>Cancel</button>
              <button onClick={() => {
                const newDrf = { ...ct.dateRangeFilters };
                if (dateRangeDropdown.from || dateRangeDropdown.to) {
                  newDrf[dateRangeDropdown.colName] = {};
                  if (dateRangeDropdown.from) newDrf[dateRangeDropdown.colName].from = dateRangeDropdown.from;
                  if (dateRangeDropdown.to) newDrf[dateRangeDropdown.colName].to = dateRangeDropdown.to;
                } else {
                  delete newDrf[dateRangeDropdown.colName];
                }
                up("dateRangeFilters", newDrf);
                setDateRangeDropdown(null);
              }} style={{ padding: "4px 11px", minHeight: 26, background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 4, fontSize: 11, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Apply</button>
            </div>
          </div>
        </>
      )}

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Log Source Coverage Map Modal */}
        {modal?.type === "logSourceCoverage" && ct && <LogSourceCoverageModal />}

        {/* Burst Detection Modal */}
        {modal?.type === "burstAnalysis" && ct && <BurstAnalysisModal />}
      </Suspense>

      {/* Merge Tabs Modal */}
      {modal?.type === "mergeTabs" && (() => {
        const tabOptions = modal.tabOptions || [];
        const checkedTabs = tabOptions.filter((t) => t.checked);
        const totalMergeRows = checkedTabs.reduce((s, t) => s + t.rowCount, 0);
        const canMerge = checkedTabs.length >= 2 && checkedTabs.every((t) => t.selectedTsCol);
        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg + "f2", border: `1px solid ${th.glassBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", animation: "tle-modal-in var(--m-modal) var(--ease-out)" }}>
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Merge Tabs</h3>
                  <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                    Combine {checkedTabs.length} tab{checkedTabs.length !== 1 ? "s" : ""} into a unified timeline ({formatNumber(totalMergeRows)} rows)
                  </p>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>{"\u2715"}</button>
              </div>
              <div style={{ flex: 1, overflow: "auto", padding: "12px 20px" }}>
                {tabOptions.map((t, i) => (
                  <div key={t.tabId} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0", borderBottom: `1px solid ${th.border}22` }}>
                    <input type="checkbox" checked={t.checked}
                      onChange={() => setModal((p) => {
                        const opts = [...p.tabOptions];
                        opts[i] = { ...opts[i], checked: !opts[i].checked };
                        return { ...p, tabOptions: opts };
                      })}
                      style={{ accentColor: th.accent }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.tabName}</div>
                      <div style={{ fontSize: 10, color: th.textMuted }}>{formatNumber(t.rowCount)} rows</div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <span style={{ fontSize: 10, color: th.textMuted }}>Timestamp:</span>
                      <select value={t.selectedTsCol}
                        onChange={(e) => setModal((p) => {
                          const opts = [...p.tabOptions];
                          opts[i] = { ...opts[i], selectedTsCol: e.target.value };
                          return { ...p, tabOptions: opts };
                        })}
                        disabled={!t.checked}
                        style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "2px 6px", outline: "none", maxWidth: 160 }}>
                        {t.tsColumns.length === 0 && <option value="">No timestamp columns</option>}
                        {t.tsColumns.map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </div>
                  </div>
                ))}
                {checkedTabs.length < 2 && (
                  <div style={{ padding: "12px 0", color: th.warning, fontSize: 11, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                    Select at least 2 tabs to merge.
                  </div>
                )}
              </div>
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                <button disabled={!canMerge} onClick={async () => {
                  setModal(null);
                  const mergedTabId = `tab_merged_${Date.now()}`;
                  const srcs = checkedTabs.map((t) => ({ tabId: t.tabId, tabName: t.tabName, tsCol: t.selectedTsCol }));
                  await tle.mergeTabs(mergedTabId, srcs);
                }}
                  style={{ ...ms.bp, opacity: canMerge ? 1 : 0.5, cursor: canMerge ? "pointer" : "not-allowed" }}>
                  Merge {checkedTabs.length} Tabs ({formatNumber(totalMergeRows)} rows)
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Edit Filter Modal */}
        {modal?.type === "editFilter" && ct && <EditFilterModal />}

        {/* Bulk Actions Modal */}
        {modal?.type === "bulkActions" && ct && (
          <BulkActionsModal
            fetchData={fetchData}
            selectionFilterOptions={selectionFilterOptions}
            selectionCount={selectionCount}
          />
        )}
      </Suspense>

      {/* Process Analyzer (provider + modal) */}
      <ProcessAnalyzerRoot activeFilters={activeFilters} />

      {/* Themed confirm dialog (replaces window.confirm) */}
      <ConfirmDialog />

      {/* Themed toast notifications (replaces alert() and inline message flashes) */}
      <ToastContainer />

      <Suspense fallback={<ModalChunkFallback th={th} />}>
        {/* Lateral Movement Modal */}
        {modal?.type === "lateralMovement" && ct && <LateralMovementModal />}
        {modal?.type === "triageCollection" && <TriageCollectionModal />}

        {/* Persistence Analyzer Modal */}
        {modal?.type === "persistence" && ct && <PersistenceModal />}

        {/* Ransomware MFT Analysis Modal */}
        {modal?.type === "ransomware" && ct && <RansomwareModal />}

        {/* Timestomping Detector Modal */}
        {modal?.type === "timestomping" && ct && <TimestompingModal />}

        {/* File Activity Heatmap Modal */}
        {modal?.type === "heatmap" && ct && <HeatmapModal />}
        {modal?.type === "sigma" && <SigmaRuleModal />}
        {modal?.type === "rdpBitmapCache" && <RdpBitmapCacheModal />}
        {modal?.type === "aiHistoryProfileScan" && <AiHistoryProfileScanModal />}
        {modal?.type === "aiHistoryExtract" && <AiHistoryExtractModal />}
        {modal?.type === "aiWorkspaceCorrelate" && <AiWorkspaceCorrelateModal th={th} />}
        {modal?.type === "aiHistoryScope" && <AiHistoryScopeModal />}
        {modal?.type === "aiSecrets" && <AiSecretsModal th={th} />}

        {/* ADS Analyzer Modal */}
        {modal?.type === "ads" && ct && <AdsModal />}

        {/* USN Journal Analysis Modal */}
        {modal?.type === "usnAnalysis" && ct && <UsnAnalysisModal />}
      </Suspense>

      {/* Ransomware MFT Analysis Modal */}
      {modal?.type === "ransomware" && ct && (() => {
        const { phase, encryptedExt, ransomNotePattern, data, loading, scanData } = modal;
        const usnTabs = tabs.filter((t) => t.id !== ct.id && t.dataReady && t.sourceFormat === "raw-usnjrnl");
        const autoUsnTab = usnTabs[0] || null;

        const handleScan = async () => {
          setModal((p) => ({ ...p, phase: "scanning", rwProgress: null }));
          try {
            const result = await tle.scanRansomwareExtensions(ct.id);
            if (result?.error) {
              setModal((p) => p?.type === "ransomware" ? ({ ...p, phase: "input", error: result.error }) : p);
            } else {
              setModal((p) => p?.type === "ransomware" ? ({ ...p, phase: "input", scanData: result }) : p);
            }
          } catch (e) {
            setModal((p) => p?.type === "ransomware" ? ({ ...p, phase: "input", error: e.message }) : p);
          }
        };

        const handleAnalyze = async () => {
          const ext = (encryptedExt || "").trim();
          if (!ext) return;
          setModal((p) => ({ ...p, phase: "loading", loading: true, rwProgress: null }));
          try {
            const resolvedUsnTabId = modal.usnTabId === "__none__" ? null : (modal.usnTabId || autoUsnTab?.id || null);
            const result = await tle.analyzeRansomware(ct.id, ext, (ransomNotePattern || "").trim(), modal.noteMatchMode || "exact", resolvedUsnTabId);
            if (result?.error) {
              setModal((p) => p?.type === "ransomware" ? ({ ...p, phase: "input", loading: false, error: result.error }) : p);
            } else {
              setModal((p) => p?.type === "ransomware" ? ({ ...p, phase: "results", loading: false, data: result, rwSelDirs: new Set(), rwSelNotes: new Set(), rwSelSusp: new Set(), rwSelFirst: new Set(), rwSelPairs: new Set(), rwSelAF: new Set(), rwSelUsn: new Set(), rwSortDirs: null, rwSortNotes: null, rwSortSusp: null, rwSortFirst: null, rwSortPairs: null, rwExpandedRow: null, rwShowPivots: false, rwPivotMsg: null }) : p);
            }
          } catch (e) {
            setModal((p) => p?.type === "ransomware" ? ({ ...p, phase: "input", loading: false, error: e.message }) : p);
          }
        };

        const fmtBytes = (b) => {
          if (!b || b <= 0) return "0 B";
          const u = ["B", "KB", "MB", "GB", "TB"];
          const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
          return `${(b / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${u[i]}`;
        };
        const fmtDur = (m) => {
          if (!m || m <= 0) return "0 min";
          if (m < 60) return `${m} min`;
          const h = Math.floor(m / 60);
          return h < 24 ? `${h}h ${m % 60}m` : `${Math.floor(m / 1440)}d ${Math.floor((m % 1440) / 60)}h`;
        };

        const copyReport = () => {
          if (!data) return;
          const d = data;
          const lines = [
            "=== Ransomware MFT Analysis ===",
            `Encrypted Extension: ${encryptedExt}`,
            ransomNotePattern ? `Ransom Note: ${ransomNotePattern}${modal.noteMatchMode && modal.noteMatchMode !== "exact" ? ` (${modal.noteMatchMode})` : ""}` : null, "",
            `Encrypted Files: ${(d.encryptedCount || 0).toLocaleString()}`,
            `Total Size: ${fmtBytes(d.totalEncryptedSizeBytes)}`,
            `Duration: ${fmtDur(d.durationMinutes)}`,
            `Rate: ${(d.filesPerMinute || 0).toFixed(1)} files/minute`, "",
            d.firstEncrypted ? `First Encrypted: ${d.firstEncrypted.fileName}\n  Path: ${d.firstEncrypted.parentPath}\n  Time: ${d.firstEncrypted.timestamp}` : null,
            d.lastEncrypted ? `Last Encrypted: ${d.lastEncrypted.fileName}\n  Path: ${d.lastEncrypted.parentPath}\n  Time: ${d.lastEncrypted.timestamp}` : null, "",
          ];
          if (d.timingEvidence) {
            const te = d.timingEvidence;
            lines.push("Timing Evidence:");
            if (te.timelineBasis) lines.push(`  Timeline Basis: ${te.timelineBasis.label} (${te.timelineBasis.column})`);
            if (te.suspiciousWindowBasis?.timestamp) lines.push(`  Payload Anchor: ${te.suspiciousWindowBasis.label} (${te.suspiciousWindowBasis.column}) @ ${te.suspiciousWindowBasis.timestamp}`);
            if (te.start?.preferred?.timestamp) lines.push(`  Start Preference: ${te.start.preferred.label} @ ${te.start.preferred.timestamp}${te.start.skewMinutes ? ` (skew ${te.start.skewMinutes} min)` : ""}`);
            if (te.end?.preferred?.timestamp) lines.push(`  End Preference: ${te.end.preferred.label} @ ${te.end.preferred.timestamp}${te.end.skewMinutes ? ` (skew ${te.end.skewMinutes} min)` : ""}`);
            lines.push("");
          }
          // Original pair detection
          if (d.originalPairs && (d.originalPairs.confirmedPairs > 0 || d.originalPairs.likelyPairs > 0)) {
            lines.push("Original-to-Encrypted Pairs:", `  Confirmed: ${d.originalPairs.confirmedPairs}`, `  Likely: ${d.originalPairs.likelyPairs}`, `  Pair Rate: ${Math.round(d.originalPairs.pairRate * 100)}%`, "");
          }
          // Forensic indicators with observed/inferred
          if (d.forensicIndicators?.length > 0) {
            lines.push("Forensic Indicators:");
            d.forensicIndicators.forEach(fi => lines.push(`  [${fi.basis}] ${fi.text}`));
            lines.push("");
          }
          lines.push(
            `Ransom Notes: ${d.ransomNoteCount} dropped`,
            `Deleted Encrypted Files: ${d.deletedEncrypted}`,
            `Timestomped Files: ${d.timestompedCount}`,
            `Payload Candidates: ${(d.suspiciousFiles || []).length}`, "",
          );
          // Top scored payloads
          if (d.suspiciousFiles?.length > 0) {
            lines.push("Top Payload Candidates:");
            d.suspiciousFiles.slice(0, 5).forEach(sf => {
              const sigs = (sf.signals || []).map(s => s.text).join(", ");
              lines.push(`  [${Math.round((sf.score || 0) * 100)}] ${sf.fileName} — ${sf.parentPath} (${sf.confidence || "unknown"}${sigs ? ": " + sigs : ""})`);
            });
            lines.push("");
          }
          // File type impact
          lines.push("File Type Impact:");
          (d.fileTypeBreakdown || []).slice(0, 10).forEach((t) => lines.push(`  ${t.ext}: ${t.count.toLocaleString()} (${((t.count / d.encryptedCount) * 100).toFixed(1)}%)`));
          lines.push("");
          // Business impact
          if (d.businessImpact?.length > 0) {
            lines.push("Business Impact:");
            d.businessImpact.filter(c => c.category !== "Other").forEach(c => lines.push(`  ${c.category}: ${c.count.toLocaleString()} (${Math.round(c.percentage * 100)}%)`));
            lines.push("");
          }
          // Backup recovery
          if (d.backupRecoveryTotal > 0) {
            lines.push(`Backup/Recovery Artifacts: ${d.backupRecoveryTotal} files affected`);
            (d.backupRecoveryImpact || []).forEach(r => lines.push(`  ${r.subtype} (${r.ext}): ${r.count}`));
            lines.push("");
          }
          // Anti-forensics
          if (d.antiForensics) {
            const af = d.antiForensics;
            const afTotal = (af.deletedEncrypted?.length || 0) + (af.timestomped?.length || 0) + (af.cleanup?.length || 0) + (af.drops?.length || 0);
            if (afTotal > 0) {
              lines.push("Anti-Forensics:");
              if (af.deletedEncrypted?.length) lines.push(`  Deleted Encrypted: ${af.deletedEncrypted.length}`);
              if (af.timestomped?.length) lines.push(`  Timestomped in Window: ${af.timestomped.length}`);
              if (af.cleanup?.length) lines.push(`  Cleanup Artifacts: ${af.cleanup.length}`);
              if (af.drops?.length) lines.push(`  Suspicious Drops: ${af.drops.length}`);
              lines.push("");
            }
          }
          // USN enrichment
          if (d.usnEnrichment) {
            const usn = d.usnEnrichment;
            lines.push("USN Journal Correlation:");
            if (usn.preciseStartTime) lines.push(`  Precise Start: ${usn.preciseStartTime}`);
            lines.push(`  Rename Events: ${usn.renameCount}`, `  Data Overwrites: ${usn.overwriteTotal}`, `  Deletions: ${usn.deleteTotal}`, "");
          }
          // Directories
          lines.push("Affected Subtrees:");
          (d.topDirectories || []).slice(0, 10).forEach((dir) => {
            const enc = dir.encryptedCount || dir.count || 0;
            const total = dir.totalCount || enc;
            const ratio = total > 0 ? Math.round((enc / total) * 100) : 0;
            lines.push(`  ${dir.path} (${enc.toLocaleString()} / ${total.toLocaleString()} — ${ratio}%)`);
          });
          navigator.clipboard?.writeText(lines.filter((l) => l !== null).join("\n"));
        };

        const exportPdf = async () => {
          if (!data) return;
          const d = data;
          const esc = (s) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
          const tblRow = (cells, isHeader) => {
            const tag = isHeader ? "th" : "td";
            return `<tr>${cells.map(c => `<${tag}>${esc(c)}</${tag}>`).join("")}</tr>`;
          };
          const section = (title, content) => `<div class="section"><h2>${esc(title)}</h2>${content}</div>`;
          const statBox = (val, label, color) => `<div class="stat" style="border-top:3px solid ${color}"><div class="stat-val" style="color:${color}">${esc(val)}</div><div class="stat-label">${esc(label)}</div></div>`;

          let body = `<div class="header"><h1>Ransomware MFT Analysis Report</h1><div class="meta">Extension: <code>${esc(encryptedExt)}</code>${ransomNotePattern ? ` &nbsp;|&nbsp; Note: <code>${esc(ransomNotePattern)}</code>` : ""}${modal.noteMatchMode && modal.noteMatchMode !== "exact" ? ` (${esc(modal.noteMatchMode)})` : ""} &nbsp;|&nbsp; Generated: ${new Date().toISOString().replace("T", " ").slice(0, 19)}</div></div>`;

          // Stats
          body += `<div class="stats">${statBox((d.encryptedCount || 0).toLocaleString(), "Encrypted Files", "#f85149")}${statBox(fmtBytes(d.totalEncryptedSizeBytes), "Total Size", "#58a6ff")}${statBox(fmtDur(d.durationMinutes), "Duration", "#d29922")}${statBox((d.filesPerMinute || 0).toFixed(1), "Files/min", "#58a6ff")}</div>`;

          // Blast radius
          if (d.blastRadius) {
            const br = d.blastRadius;
            body += section("Blast Radius", `<p><strong>${Math.round((br.encryptedPct || 0) * 100)}%</strong> of files encrypted (${(br.encryptedCount || 0).toLocaleString()} / ${(br.totalFiles || 0).toLocaleString()}) &nbsp;—&nbsp; Severity: <span class="badge ${br.severity || "medium"}">${(br.severity || "unknown").toUpperCase()}</span></p>`);
          }

          // Timeline
          if (d.firstEncrypted && d.lastEncrypted) {
            body += section("Encryption Timeline", `<table>${tblRow(["", "File", "Path", "Timestamp"], true)}${tblRow(["First", d.firstEncrypted.fileName, d.firstEncrypted.parentPath, d.firstEncrypted.timestamp])}${tblRow(["Last", d.lastEncrypted.fileName, d.lastEncrypted.parentPath, d.lastEncrypted.timestamp])}</table>`);
          }

          // Top directories
          if (d.topDirectories?.length > 0) {
            const dirRows = d.topDirectories.slice(0, 15).map(dir => {
              const enc = dir.encryptedCount || dir.count || 0;
              const total = dir.totalCount || enc;
              return tblRow([dir.path, enc.toLocaleString(), total.toLocaleString(), total > 0 ? Math.round((enc / total) * 100) + "%" : "—"]);
            }).join("");
            body += section(`Affected Directories (${d.topDirectories.length})`, `<table>${tblRow(["Path", "Encrypted", "Total", "Ratio"], true)}${dirRows}</table>`);
          }

          // Ransom notes
          if (d.ransomNoteCount > 0 && d.ransomNotes?.length > 0) {
            const noteRows = d.ransomNotes.slice(0, 20).map(n => tblRow([n.fileName, n.parentPath, n.created || "—"])).join("");
            body += section(`Ransom Notes (${d.ransomNoteCount})`, `<table>${tblRow(["File", "Path", "Created"], true)}${noteRows}</table>`);
          }

          // Suspicious payloads
          if (d.suspiciousFiles?.length > 0) {
            const sfRows = d.suspiciousFiles.slice(0, 20).map(sf => {
              const sigs = (sf.signals || []).map(s => s.text).join(", ");
              return tblRow([Math.round((sf.score || 0) * 100) + "", sf.confidence || "—", sf.fileName, sf.parentPath, sf.created || "—", sigs]);
            }).join("");
            body += section(`Suspicious Payload Candidates (${d.suspiciousFiles.length})`, `<table>${tblRow(["Score", "Confidence", "File", "Path", "Created", "Signals"], true)}${sfRows}</table>`);
          }

          // Original-encrypted pairs
          if (d.originalPairs && (d.originalPairs.confirmedPairs > 0 || d.originalPairs.likelyPairs > 0)) {
            body += section("Original-Encrypted Pairs", `<p>Confirmed: <strong>${d.originalPairs.confirmedPairs}</strong> &nbsp;|&nbsp; Likely: <strong>${d.originalPairs.likelyPairs}</strong> &nbsp;|&nbsp; Pair Rate: <strong>${Math.round(d.originalPairs.pairRate * 100)}%</strong></p>`);
          }

          // Forensic indicators
          if (d.forensicIndicators?.length > 0) {
            const fiRows = d.forensicIndicators.map(fi => `<div class="pill ${fi.basis}">${esc(fi.text)}<span class="basis">${fi.basis}</span></div>`).join("");
            body += section("Forensic Indicators", `<div class="pills">${fiRows}</div>`);
          }

          // File type breakdown
          if (d.fileTypeBreakdown?.length > 0) {
            const ftRows = d.fileTypeBreakdown.slice(0, 15).map(t => tblRow([t.ext, t.count.toLocaleString(), ((t.count / d.encryptedCount) * 100).toFixed(1) + "%"])).join("");
            body += section("File Type Impact", `<table>${tblRow(["Extension", "Count", "%"], true)}${ftRows}</table>`);
          }

          // Business impact
          if (d.businessImpact?.length > 0) {
            const biRows = d.businessImpact.filter(c => c.category !== "Other").map(c => tblRow([c.category, c.count.toLocaleString(), Math.round(c.percentage * 100) + "%"])).join("");
            body += section("Business Impact", `<table>${tblRow(["Category", "Files", "%"], true)}${biRows}</table>`);
          }

          // Anti-forensics
          if (d.antiForensics) {
            const af = d.antiForensics;
            const afTotal = (af.deletedEncrypted?.length || 0) + (af.timestomped?.length || 0) + (af.cleanup?.length || 0) + (af.drops?.length || 0);
            if (afTotal > 0) {
              let afContent = `<div class="stats">${statBox(String(af.deletedEncrypted?.length || 0), "Deleted Encrypted", "#f85149")}${statBox(String(af.timestomped?.length || 0), "Timestomped", "#d29922")}${statBox(String(af.cleanup?.length || 0), "Cleanup Artifacts", "#e85d2a")}${statBox(String(af.drops?.length || 0), "Suspicious Drops", "#da3633")}</div>`;
              body += section("Anti-Forensics & Cleanup", afContent);
            }
          }

          // USN enrichment
          if (d.usnEnrichment) {
            const usn = d.usnEnrichment;
            let usnContent = `<div class="stats">${statBox(String(usn.renameCount), "Rename Events", "#58a6ff")}${statBox(String(usn.overwriteTotal), "Data Overwrites", "#d29922")}${statBox(String(usn.deleteTotal), "Deletions", "#f85149")}</div>`;
            if (usn.preciseStartTime) usnContent += `<p>Precise encryption start: <code>${esc(usn.preciseStartTime)}</code></p>`;
            body += section("USN Journal Correlation", usnContent);
          }

          // Theme-aware CSS — adapts to current dark/light mode
          const isDark = themeName === "dark";
          const c = {
            bg: isDark ? "#0d1117" : "#ffffff",
            bgAlt: isDark ? "#161b22" : "#f7f5f3",
            text: isDark ? "#e6edf3" : "#1c1917",
            textDim: isDark ? "#c9d1d9" : "#44403c",
            textMuted: isDark ? "#8b949e" : "#78716c",
            border: isDark ? "#30363d" : "#e0dbd6",
            borderSub: isDark ? "#21262d" : "#e7e5e4",
            accent: th.accent,
            danger: th.danger || "#f85149",
            warning: th.warning || "#d29922",
            code: isDark ? "#58a6ff" : "#0969da",
            stripeBg: isDark ? "#0d111722" : "#faf8f611",
          };
          const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Ransomware Analysis — ${esc(encryptedExt)}</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:${c.bg};color:${c.text};font-family:"Segoe UI",system-ui,Helvetica,sans-serif;font-size:12px;padding:32px 40px;line-height:1.5}
.header{margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid ${c.border}}
h1{font-size:20px;font-weight:700;color:${c.text};margin-bottom:6px}
.meta{font-size:11px;color:${c.textMuted}}
code{background:${c.bgAlt};padding:2px 6px;border-radius:4px;font-family:"Cascadia Code","Consolas","Courier New",monospace;font-size:11px;color:${c.code}}
.stats{display:flex;gap:10px;margin:12px 0 16px}
.stat{flex:1;background:${c.bgAlt};border:1px solid ${c.border};border-radius:8px;padding:14px 10px;text-align:center}
.stat-val{font-size:20px;font-weight:700;line-height:1.2}
.stat-label{font-size:9px;text-transform:uppercase;letter-spacing:0.05em;color:${c.textMuted};margin-top:4px}
.section{margin-bottom:20px}
h2{font-size:13px;font-weight:600;color:${c.text};margin-bottom:8px;padding:6px 10px;background:${c.bgAlt};border-radius:6px;border-left:3px solid ${c.accent}}
table{width:100%;border-collapse:collapse;font-size:11px;font-family:"Cascadia Code","Consolas","Courier New",monospace}
th{text-align:left;padding:6px 10px;background:${c.bgAlt};color:${c.textMuted};font-weight:600;border-bottom:1px solid ${c.border};font-size:10px;text-transform:uppercase;letter-spacing:0.05em}
td{padding:5px 10px;border-bottom:1px solid ${c.borderSub};color:${c.textDim};word-break:break-all}
tr:nth-child(even) td{background:${c.stripeBg}}
.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;color:#fff}
.badge.critical{background:${c.danger}}.badge.high{background:${c.accent}}.badge.medium{background:${c.warning}}.badge.low{background:${c.textMuted}}
.pills{display:flex;flex-wrap:wrap;gap:6px}
.pill{padding:4px 10px;border-radius:6px;font-size:10px;background:${c.bgAlt};border:1px solid ${c.border};display:flex;align-items:center;gap:6px}
.pill.observed{border-color:${c.code}55}.pill.inferred{border-style:dashed;border-color:${c.warning}55}
.basis{font-size:8px;text-transform:uppercase;padding:1px 4px;border-radius:3px;background:${c.border};color:${c.textMuted}}
p{margin:8px 0;color:${c.textDim};font-size:12px}
strong{color:${c.text}}
.footer{margin-top:24px;padding-top:12px;border-top:1px solid ${c.border};color:${c.textMuted};font-size:10px;text-align:center}
@page{margin:12mm}
</style></head><body>${body}<div class="footer">IRFlow Timeline — Ransomware MFT Analysis Report</div></body></html>`;

          setModal((p) => ({ ...p, rwPivotMsg: "Generating PDF..." }));
          try {
            const result = await tle.exportRansomwarePdf(html, `ransomware_${encryptedExt.replace(/[^a-zA-Z0-9]/g, "")}_report.pdf`);
            setModal((p) => p ? { ...p, rwPivotMsg: result ? `PDF saved to ${result.filePath.split("/").pop()}` : null } : p);
          } catch (e) {
            setModal((p) => p ? { ...p, rwPivotMsg: `Export failed: ${e.message}` } : p);
          }
          setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 4000);
        };

        const rowStyle = (i) => ({
          display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 11,
          background: i % 2 === 0 ? "transparent" : `${th.border}15`,
          borderBottom: `1px solid ${th.border}22`, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace",
        });

        const cbStyle = (checked) => ({
          width: 14, height: 14, borderRadius: 4, flexShrink: 0, cursor: "pointer",
          background: checked ? (th.accent) : "transparent",
          border: `1.5px solid ${checked ? th.accent : th.border}`,
          display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s",
        });

        const toggleSet = (key, idx) => setModal((p) => {
          if (!p) return p;
          const s = new Set(p[key]); s.has(idx) ? s.delete(idx) : s.add(idx); return { ...p, [key]: s };
        });

        const toggleAll = (key, count) => setModal((p) => {
          if (!p) return p;
          const cur = p[key] || new Set();
          return { ...p, [key]: cur.size === count ? new Set() : new Set(Array.from({ length: count }, (_, i) => i)) };
        });

        const copySelected = () => {
          const lines = [];
          const selFirst = modal.rwSelFirst || new Set();
          const selPairs = modal.rwSelPairs || new Set();
          const selDirs = modal.rwSelDirs || new Set();
          const selNotes = modal.rwSelNotes || new Set();
          const selSusp = modal.rwSelSusp || new Set();
          const selAF = modal.rwSelAF || new Set();
          const selUsn = modal.rwSelUsn || new Set();
          if (selFirst.size > 0 && data?.firstEncryptedFiles) {
            lines.push("=== First Encrypted Files ===");
            lines.push("Entry#\tFileName\tParentPath\tTimestamp\tSize");
            data.firstEncryptedFiles.forEach((f, i) => { if (selFirst.has(i)) lines.push(`#${f.entryNumber}\t${f.fileName}\t${f.parentPath}\t${(f.timestamp || "").slice(0, 19)}\t${f.fileSize || ""}`); });
            lines.push("");
          }
          if (selPairs.size > 0 && data?.originalPairs?.samplePairs) {
            lines.push("=== Original-to-Encrypted Pairs ===");
            lines.push("Original\tEncrypted\tPath\tStatus");
            data.originalPairs.samplePairs.slice(0, 30).forEach((p, i) => { if (selPairs.has(i)) lines.push(`${p.originalFile}\t${p.encryptedFile}\t${p.parentPath}\t${p.originalDeleted ? "DELETED" : "ABSENT"}`); });
            lines.push("");
          }
          if (selDirs.size > 0 && data?.topDirectories) {
            lines.push("=== Affected Subtrees ===");
            data.topDirectories.slice(0, 15).forEach((d, i) => {
              if (!selDirs.has(i)) return;
              const enc = d.encryptedCount || d.count || 0;
              const total = d.totalCount || enc;
              lines.push(`${d.path || "(root)"}\t${enc}/${total}\t${total > 0 ? Math.round((enc/total)*100) : 0}%`);
            });
            lines.push("");
          }
          if (selNotes.size > 0 && data?.ransomNotes) {
            lines.push("=== Ransom Note Locations ===");
            data.ransomNotes.slice(0, 50).forEach((n, i) => { if (selNotes.has(i)) lines.push(`#${n.entryNumber}\t${n.fileName}\t${n.parentPath}\t${(n.created || "").slice(0, 19)}`); });
            lines.push("");
          }
          if (selSusp.size > 0 && data?.suspiciousFiles) {
            lines.push("=== Payload Candidates ===");
            lines.push("Score\tConfidence\tExt\tFileName\tParentPath\tCreated\tSignals");
            data.suspiciousFiles.forEach((s, i) => { if (selSusp.has(i)) lines.push(`${Math.round((s.score || 0) * 100)}\t${s.confidence || ""}\t${s.extension}\t${s.fileName}\t${s.parentPath}\t${(s.created || "").slice(0, 19)}\t${(s.signals || []).map(sig => sig.text).join(", ")}${s.zoneId ? "\t[WEB]" : ""}`); });
            lines.push("");
          }
          if (selAF.size > 0 && data?.antiForensics) {
            lines.push("=== Anti-Forensics ===");
            let gi = 0;
            const cats = [
              { label: "Deleted Encrypted", items: data.antiForensics.deletedEncrypted || [] },
              { label: "Timestomped", items: data.antiForensics.timestomped || [] },
              { label: "Cleanup", items: data.antiForensics.cleanup || [] },
              { label: "Drops", items: data.antiForensics.drops || [] },
            ];
            for (const cat of cats) {
              for (const item of cat.items) {
                if (selAF.has(gi)) lines.push(`[${cat.label}]\t#${item.entryNumber}\t${item.fileName}\t${item.parentPath}\t${(item.created || item.lastModified || "").slice(0, 19)}`);
                gi++;
              }
            }
            lines.push("");
          }
          if (selUsn.size > 0 && data?.usnEnrichment?.renameSamples) {
            lines.push("=== USN Rename Events ===");
            data.usnEnrichment.renameSamples.forEach((r, i) => { if (selUsn.has(i)) lines.push(`${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath || ""}`); });
            lines.push("");
          }
          if (lines.length > 0) navigator.clipboard?.writeText(lines.join("\n"));
        };

        const totalSelected = ((modal.rwSelDirs || new Set()).size + (modal.rwSelNotes || new Set()).size + (modal.rwSelSusp || new Set()).size + (modal.rwSelFirst || new Set()).size + (modal.rwSelPairs || new Set()).size + (modal.rwSelAF || new Set()).size + (modal.rwSelUsn || new Set()).size);

        // Draggable + resizable panel state
        const defW = phase === "results" ? 860 : (scanData ? 640 : 520), defH = phase === "results" ? Math.round(window.innerHeight * 0.88) : (scanData ? 520 : 380);
        const rw = modal.rwW || defW, rh = modal.rwH || defH;
        const rx = modal.rwX ?? Math.round((window.innerWidth - rw) / 2);
        const ry = modal.rwY ?? Math.round((window.innerHeight - rh) / 2);

        const startRwDrag = (e) => {
          e.preventDefault();
          const sx = e.clientX - rx, sy = e.clientY - ry;
          const onMove = (ev) => setModal((p) => p ? { ...p, rwX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), rwY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p);
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const startRwResize = (e, edge) => {
          e.preventDefault(); e.stopPropagation();
          const sx = e.clientX, sy = e.clientY, sw = rw, sh = rh, sleft = rx, stop = ry;
          const onMove = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            setModal((p) => {
              if (!p) return p;
              let nw = sw, nh = sh, nx = sleft, ny = stop;
              if (edge.includes("r")) nw = Math.max(420, sw + dx);
              if (edge.includes("b")) nh = Math.max(280, sh + dy);
              if (edge.includes("l")) { nw = Math.max(420, sw - dx); nx = sleft + sw - nw; }
              if (edge.includes("t")) { nh = Math.max(280, sh - dy); ny = stop + sh - nh; }
              return { ...p, rwW: nw, rwH: nh, rwX: nx, rwY: ny };
            });
          };
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const rwEdge = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

        // Sort + column resize for ransomware tables
        const handleRwSort = (stateKey, colKey) => setModal((p) => {
          if (!p) return p;
          const cur = p[stateKey];
          const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
          return { ...p, [stateKey]: { col: colKey, dir: newDir } };
        });
        const sortRwArr = (arr, sortState) => {
          if (!sortState || !arr) return arr;
          return [...arr].sort((a, b) => {
            const va = (a[sortState.col] || "").toString().toLowerCase();
            const vb = (b[sortState.col] || "").toString().toLowerCase();
            return sortState.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
          });
        };
        const rwSortArrow = (stateKey, colKey) => {
          const s = modal[stateKey]; const active = s?.col === colKey; const dir = active ? s.dir : null;
          return (
            <svg width="8" height="10" viewBox="0 0 8 10" style={{ marginLeft: 3, flexShrink: 0, opacity: active ? 1 : 0.25, transition: "opacity 0.15s" }}>
              <path d="M4 1L7 4H1Z" fill={dir === "asc" ? (th.accent) : th.textMuted} opacity={dir === "asc" ? 1 : 0.4} />
              <path d="M4 9L1 6H7Z" fill={dir === "desc" ? (th.accent) : th.textMuted} opacity={dir === "desc" ? 1 : 0.4} />
            </svg>
          );
        };
        // Column resize for ransomware
        const defNotesW = [60, 120, 240, 140];
        const defSuspW = [50, 120, 240, 140];
        const notesW = modal.rwNotesColW || defNotesW;
        const suspW = modal.rwSuspColW || defSuspW;
        const startRwColResize = (stateKey, defaults, colIdx, e) => {
          e.preventDefault(); e.stopPropagation();
          const startX = e.clientX, startW = (modal[stateKey] || defaults)[colIdx];
          const onMove = (ev) => setModal((p) => { if (!p) return p; const w = [...(p[stateKey] || defaults)]; w[colIdx] = Math.max(30, startW + (ev.clientX - startX)); return { ...p, [stateKey]: w }; });
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };
        const rwResH = { position: "absolute", right: -2, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 };
        const rwHdrCol = (w, label, stateKey, colKey, resizeKey, defW, colIdx) => (
          <div style={{ width: w, flexShrink: 0, position: "relative", cursor: "pointer", display: "flex", alignItems: "center", userSelect: "none" }} onClick={() => handleRwSort(stateKey, colKey)}>
            {label}{rwSortArrow(stateKey, colKey)}
            <div onMouseDown={(e) => { e.stopPropagation(); startRwColResize(resizeKey, defW, colIdx, e); }} style={rwResH} />
          </div>
        );

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, zIndex: 100, backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)", WebkitAppRegion: "no-drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "absolute", left: rx, top: ry, width: rw, height: rh, background: th.modalBg + "f2", border: `1px solid ${th.modalBorder}88`, borderRadius: 14, padding: 0, display: "flex", flexDirection: "column", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)" }}>
              {/* Resize handles — edges */}
              <div onMouseDown={(e) => startRwResize(e, "t")} style={rwEdge("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startRwResize(e, "b")} style={rwEdge("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startRwResize(e, "l")} style={rwEdge("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startRwResize(e, "r")} style={rwEdge("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              {/* Resize handles — corners */}
              <div onMouseDown={(e) => startRwResize(e, "tl")} style={rwEdge("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startRwResize(e, "tr")} style={rwEdge("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startRwResize(e, "bl")} style={rwEdge("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startRwResize(e, "br")} style={rwEdge("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

              {/* Header — draggable, glass gradient */}
              <div onMouseDown={startRwDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.danger || "#f85149"}33, ${th.danger || "#f85149"}11)`, border: `1px solid ${th.danger || "#f85149"}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.danger || "#f85149"} strokeWidth="1.8" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.danger || "#f85149") + "18"}/><rect x="10" y="9" width="4" height="5" rx="1"/><circle cx="12" cy="7.5" r="2.5" fill="none"/></svg>
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.01em" }}>Ransomware MFT Analysis</h3>
                    <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Identify encrypted files, ransom notes, and suspicious activity</p>
                  </div>
                </div>
                <button onClick={() => setModal(null)} style={{ background: `${th.border}22`, border: `1px solid ${th.border}33`, color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "4px 8px", borderRadius: 6, lineHeight: 1 }}>✕</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {/* Input phase */}
                {phase === "input" && (<>
                  {/* MFT format warning */}
                  {ct?.sourceFormat && ct.sourceFormat !== "raw-mft" && (
                    <div style={{ marginBottom: 10, padding: "8px 12px", background: `${th.warning || "#d29922"}0a`, border: `1px solid ${th.warning || "#d29922"}22`, borderRadius: 8, fontSize: 10, color: th.warning || "#d29922", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                      This tab was not imported as raw MFT data. Results may be unreliable — timestamps and columns may not match MFT semantics.
                    </div>
                  )}
                  {/* Auto-detect scan */}
                  {!scanData && (
                    <div style={{ marginBottom: 14, padding: "14px 16px", background: `linear-gradient(135deg, ${th.accent}08, ${th.panelBg}cc)`, border: `1px solid ${th.accent}22`, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Auto-detect ransomware indicators</div>
                        <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif", marginTop: 2 }}>Scan MFT for suspicious extensions and ransom note patterns</div>
                      </div>
                      <button onClick={handleScan} style={{ ...ms.bp, borderRadius: 8, fontSize: 11, padding: "6px 16px" }}>Scan MFT</button>
                    </div>
                  )}

                  {/* Scan results — extension candidates (multi-select) */}
                  {scanData?.candidates?.length > 0 && (() => {
                    const selExts = new Set(encryptedExt.split(/[,;|]+/).map(s => s.trim()).filter(Boolean).map(s => s.startsWith(".") ? s : "." + s));
                    const toggleExt = (ext) => setModal((p) => {
                      const cur = new Set((p.encryptedExt || "").split(/[,;|]+/).map(s => s.trim()).filter(Boolean).map(s => s.startsWith(".") ? s : "." + s));
                      if (cur.has(ext)) cur.delete(ext); else cur.add(ext);
                      return { ...p, encryptedExt: [...cur].join(", ") };
                    });
                    return (
                    <div style={{ marginBottom: 14 }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                        <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Detected Encrypted Extensions</span>
                        {selExts.size > 1 && <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{selExts.size} selected</span>}
                      </div>
                      <div style={{ maxHeight: 180, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        {scanData.candidates.map((c, i) => {
                          const sel = selExts.has(c.extension);
                          const scoreColor = c.score >= 0.7 ? (th.danger || "#f85149") : c.score >= 0.4 ? (th.warning || "#d29922") : th.accent;
                          return (
                            <div key={i} onClick={() => toggleExt(c.extension)}
                              style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 12px", fontSize: 11, borderBottom: `1px solid ${th.border}15`, cursor: "pointer", background: sel ? `${th.accent}12` : (i % 2 === 0 ? "transparent" : `${th.border}08`), borderLeft: sel ? `3px solid ${th.accent}` : "3px solid transparent", transition: "all 0.15s" }}>
                              <div style={{ width: 14, height: 14, borderRadius: 4, flexShrink: 0, background: sel ? th.accent : "transparent", border: `1.5px solid ${sel ? th.accent : th.border}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                                {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                              </div>
                              <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, background: `${scoreColor}22`, color: scoreColor, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", minWidth: 28, textAlign: "center" }}>{Math.round(c.score * 100)}</span>
                              <span style={{ fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", fontWeight: 600, color: th.text, minWidth: 80 }}>{c.extension}</span>
                              <span style={{ color: th.textDim, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{c.fileCount.toLocaleString()} files</span>
                              {c.peakMinuteCount > 0 && <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>peak {c.peakMinuteCount.toLocaleString()}/min</span>}
                              {c.samplePaths?.[0] && <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0, textAlign: "right" }}>{c.samplePaths[0]}</span>}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                    );
                  })()}

                  {/* Scan results — ransom note candidates */}
                  {scanData?.noteCandidates?.length > 0 && (
                    <div style={{ marginBottom: 14 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: th.warning || "#d29922", textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 6 }}>Detected Ransom Note Patterns</div>
                      <div style={{ maxHeight: 130, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        {scanData.noteCandidates.map((n, i) => {
                          const sel = ransomNotePattern === n.fileName;
                          return (
                            <div key={i} onClick={() => setModal((p) => ({ ...p, ransomNotePattern: n.fileName }))}
                              style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", fontSize: 11, borderBottom: `1px solid ${th.border}15`, cursor: "pointer", background: sel ? `${(th.warning || "#d29922")}12` : (i % 2 === 0 ? "transparent" : `${th.border}08`), borderLeft: sel ? `3px solid ${th.warning || "#d29922"}` : "3px solid transparent" }}>
                              <span style={{ fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", fontWeight: 600, color: th.text, minWidth: 120 }}>{n.fileName}</span>
                              <span style={{ color: th.textDim, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{n.dirCount} dirs</span>
                              {n.timeSpanMinutes != null && <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{n.timeSpanMinutes < 60 ? `${n.timeSpanMinutes} min` : n.timeSpanMinutes < 1440 ? `${Math.round(n.timeSpanMinutes / 60)}h` : `${Math.round(n.timeSpanMinutes / 1440)}d`} span</span>}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* No candidates found message */}
                  {scanData && scanData.candidates?.length === 0 && (
                    <div style={{ marginBottom: 14, padding: "10px 14px", background: `${(th.success || "#3fb950")}08`, border: `1px solid ${(th.success || "#3fb950")}22`, borderRadius: 8, fontSize: 11, color: th.textDim, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>No suspicious extensions detected — enter extension manually below.</div>
                  )}

                  {/* Manual input — always shown, acts as override */}
                  <div style={{ marginBottom: 10, padding: scanData ? "10px 0 0" : 0, borderTop: scanData ? `1px solid ${th.border}22` : "none" }}>
                    {scanData && <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 6 }}>Manual Override</div>}
                    <div style={ms.fg}>
                      <label style={ms.lb}>Encrypted File Extension</label>
                      <input value={encryptedExt} onChange={(e) => setModal((p) => ({ ...p, encryptedExt: e.target.value }))}
                        onKeyDown={(e) => { if (e.key === "Enter" && encryptedExt.trim()) handleAnalyze(); }}
                        placeholder=".locked  or  .locked, .encrypted" style={ms.ip} autoFocus={!scanData} />
                      {!scanData && (
                        <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
                          {[".locked", ".encrypted", ".enc", ".crypt", ".WNCRY", ".cerber", ".locky", ".ryuk"].map((ext) => (
                            <button key={ext} onClick={() => setModal((p) => ({ ...p, encryptedExt: ext }))}
                              style={{ padding: "3px 8px", background: encryptedExt === ext ? th.accent : th.btnBg, color: encryptedExt === ext ? "#fff" : th.textDim, border: `1px solid ${encryptedExt === ext ? th.accent : th.btnBorder}`, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                              {ext}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                    <div style={ms.fg}>
                      <label style={ms.lb}>Ransom Note Filename (optional)</label>
                      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                        <input value={ransomNotePattern} onChange={(e) => setModal((p) => ({ ...p, ransomNotePattern: e.target.value }))}
                          onKeyDown={(e) => { if (e.key === "Enter" && encryptedExt.trim()) handleAnalyze(); }}
                          placeholder={modal.noteMatchMode === "multi" ? "README.txt, DECRYPT.html" : modal.noteMatchMode === "regex" ? "README.*\\.txt" : "README.txt"} style={{ ...ms.ip, flex: 1 }} />
                        <select value={modal.noteMatchMode || "exact"} onChange={(e) => setModal((p) => ({ ...p, noteMatchMode: e.target.value }))} style={{ ...ms.sl, width: 110, fontSize: 10, padding: "4px 6px" }}>
                          <option value="exact">Exact</option>
                          <option value="contains">Contains</option>
                          <option value="regex">Regex</option>
                          <option value="multi">Multiple</option>
                        </select>
                      </div>
                    </div>
                    {(() => { return usnTabs.length > 0 ? (
                      <div style={ms.fg}>
                        <label style={ms.lb}>USN Journal Tab (optional enrichment)</label>
                        <select value={modal.usnTabId || "__none__"} onChange={(e) => setModal((p) => ({ ...p, usnTabId: e.target.value || "__none__" }))} style={ms.sl}>
                          <option value="__none__">None</option>
                          {usnTabs.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                        </select>
                      </div>
                    ) : (
                      <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif", fontStyle: "italic", marginTop: 2 }}>Load a USN Journal ($J) for more precise encryption timing</div>
                    ); })()}
                  </div>
                  {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
                </>)}

                {/* Scanning phase */}
                {phase === "scanning" && (
                  <div style={{ textAlign: "center", padding: "60px 40px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1 }}>
                    <div style={{ width: 56, height: 56, borderRadius: 14, background: `linear-gradient(135deg, ${th.accent}22, ${th.accent}08)`, border: `1px solid ${th.accent}22`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}>
                        <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                      </svg>
                    </div>
                    <div style={{ color: th.text, fontSize: 13, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 4 }}>Scanning MFT</div>
                    <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 16 }}>{modal.rwProgress?.detail || "Detecting ransomware indicators..."}</div>
                    <div style={{ width: 280, maxWidth: "100%" }}>
                      <div style={{ height: 6, background: th.border, borderRadius: 3, overflow: "hidden", marginBottom: 8 }}>
                        <div style={{ height: "100%", width: "100%", background: th.accent, borderRadius: 3, transformOrigin: "left", transform: `scaleX(${Math.min((modal.rwProgress?.pct || 0) / 100, 1)})`, transition: "transform 0.3s ease" }} />
                      </div>
                      <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{modal.rwProgress?.pct || 0}%</div>
                    </div>
                  </div>
                )}

                {/* Loading phase */}
                {phase === "loading" && (
                  <div style={{ textAlign: "center", padding: "60px 40px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1 }}>
                    <div style={{ width: 56, height: 56, borderRadius: 14, background: `linear-gradient(135deg, ${th.danger || "#f85149"}22, ${th.danger || "#f85149"}08)`, border: `1px solid ${th.danger || "#f85149"}22`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={th.danger || "#f85149"} strokeWidth="1.5" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}>
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.danger || "#f85149") + "18"} />
                      </svg>
                    </div>
                    <div style={{ color: th.text, fontSize: 13, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 4 }}>Analyzing MFT</div>
                    <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 16 }}>{modal.rwProgress?.detail || "Scanning for ransomware activity..."}</div>
                    <div style={{ width: 280, maxWidth: "100%" }}>
                      <div style={{ height: 6, background: th.border, borderRadius: 3, overflow: "hidden", marginBottom: 8 }}>
                        <div style={{ height: "100%", width: "100%", background: th.danger || "#f85149", borderRadius: 3, transformOrigin: "left", transform: `scaleX(${Math.min((modal.rwProgress?.pct || 0) / 100, 1)})`, transition: "transform 0.3s ease" }} />
                      </div>
                      <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{modal.rwProgress?.pct || 0}%</div>
                    </div>
                  </div>
                )}

                {/* Results phase */}
                {phase === "results" && data && (<>
                  {data.encryptedCount === 0 ? (
                    <div style={{ textAlign: "center", padding: "60px 20px", display: "flex", flexDirection: "column", alignItems: "center" }}>
                      <div style={{ width: 56, height: 56, borderRadius: 14, background: `linear-gradient(135deg, ${th.success || "#3fb950"}22, ${th.success || "#3fb950"}08)`, border: `1px solid ${th.success || "#3fb950"}22`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke={th.success || "#3fb950"} strokeWidth="2.5" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>
                      </div>
                      <div style={{ color: th.text, fontSize: 14, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>No encrypted files found</div>
                      <p style={{ color: th.textMuted, fontSize: 12, fontFamily: "'Segoe UI', system-ui, sans-serif", marginTop: 4 }}>No files with extension <span style={{ fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.accent }}>{encryptedExt}</span> were detected in this MFT.</p>
                    </div>
                  ) : (<>
                    {/* Section 1: Summary Stats */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6, marginBottom: 16 }}>
                      {[
                        { val: (data.encryptedCount || 0).toLocaleString(), label: "encrypted files", color: th.danger || "#f85149" },
                        { val: fmtBytes(data.totalEncryptedSizeBytes), label: "total size", color: th.accent },
                        { val: fmtDur(data.durationMinutes), label: "duration", color: th.warning || "#d29922" },
                        { val: (data.filesPerMinute || 0).toFixed(1), label: "files/min", color: th.accent },
                      ].map((c, i) => (
                        <div key={i} style={{ textAlign: "center", padding: "12px 8px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 10, border: `1px solid ${th.border}33` }}>
                          <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}>{c.val}</div>
                          <div style={{ fontSize: 9, color: c.color + "bb", marginTop: 4, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", fontWeight: 500 }}>{c.label}</div>
                        </div>
                      ))}
                    </div>

                    {/* Section 2: First/Last Encrypted */}
                    {data.firstEncrypted && data.lastEncrypted && (
                      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                        {[
                          { label: "First Encrypted", data: data.firstEncrypted, color: th.danger || "#f85149" },
                          { label: "Last Encrypted", data: data.lastEncrypted, color: th.warning || "#d29922" },
                        ].map((card) => (
                          <div key={card.label} style={{ flex: 1, minWidth: 0, padding: "12px 14px", background: `linear-gradient(135deg, ${card.color}08, ${th.panelBg}ee)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)", borderRadius: 10, border: `1px solid ${card.color}22`, borderLeft: `3px solid ${card.color}`, overflow: "hidden" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                              <span style={{ padding: "2px 8px", background: `linear-gradient(135deg, ${card.color}33, ${card.color}15)`, color: card.color, borderRadius: 5, fontSize: 9, fontWeight: 700, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "0.05em", textTransform: "uppercase" }}>{card.label}</span>
                            </div>
                            <div style={{ fontSize: 13, color: th.text, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{card.data.fileName}</div>
                            <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", marginTop: 3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{card.data.parentPath}</div>
                            <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", marginTop: 2 }}>{card.data.timestamp}</div>
                          </div>
                        ))}
                      </div>
                    )}

                    {data.timingEvidence && (() => {
                      const te = data.timingEvidence;
                      const renderTimingCard = (title, snap, color) => (
                        <div style={{ minWidth: 0, padding: "10px 12px", background: `linear-gradient(135deg, ${color}08, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${color}22`, borderLeft: `3px solid ${color}` }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                            <span style={{ fontSize: 9, fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{title}</span>
                            {snap?.skewMinutes > 0 && <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>skew {snap.skewMinutes}m</span>}
                          </div>
                          <div style={{ display: "grid", gap: 4 }}>
                            {(snap?.sources || []).map((src) => (
                              <div key={`${title}-${src.column}-${src.label}`} style={{ display: "grid", gridTemplateColumns: "96px 1fr", gap: 8, fontSize: 10, alignItems: "baseline" }}>
                                <span style={{ color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{src.label}</span>
                                <span style={{ color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{src.timestamp}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                      return (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ display: "grid", gridTemplateColumns: "1.05fr 1fr 1fr", gap: 8 }}>
                            <div style={{ minWidth: 0, padding: "10px 12px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, borderRadius: 10, border: `1px solid ${th.border}33` }}>
                              <div style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 8 }}>Timestamp Evidence</div>
                              {te.timelineBasis && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Timeline</div>
                                  <div style={{ fontSize: 11, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{te.timelineBasis.label} ({te.timelineBasis.column})</div>
                                </div>
                              )}
                              {te.suspiciousWindowBasis?.timestamp && (
                                <div style={{ marginBottom: 8 }}>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Payload Anchor</div>
                                  <div style={{ fontSize: 11, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{te.suspiciousWindowBasis.label} ({te.suspiciousWindowBasis.column})</div>
                                  <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", marginTop: 2 }}>{te.suspiciousWindowBasis.timestamp}</div>
                                </div>
                              )}
                              {te.filterWindow?.from && te.filterWindow?.to && (
                                <div>
                                  <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Grid Filter Window</div>
                                  <div style={{ fontSize: 10, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{te.filterWindow.column}</div>
                                  <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", marginTop: 2 }}>{te.filterWindow.from} {"->"} {te.filterWindow.to}</div>
                                </div>
                              )}
                            </div>
                            {renderTimingCard("Encryption Start", te.start, th.danger || "#f85149")}
                            {renderTimingCard("Encryption End", te.end, th.warning || "#d29922")}
                          </div>
                        </div>
                      );
                    })()}

                    {/* Section 2b: First Encrypted Files (Encryption Spread) */}
                    {data.firstEncryptedFiles?.length > 0 && (() => {
                      const shown = data.firstEncryptedFiles;
                      const selF = modal.rwSelFirst || new Set();
                      const allF = selF.size === shown.length;
                      const defFirstW = [60, 140, 240, 140, 70];
                      const firstW = modal.rwFirstColW || defFirstW;
                      const fmtSz = (b) => { const n = parseInt(b) || 0; if (n < 1024) return `${n} B`; if (n < 1048576) return `${(n/1024).toFixed(1)} KB`; return `${(n/1048576).toFixed(1)} MB`; };
                      return (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div onClick={() => toggleAll("rwSelFirst", shown.length)} style={cbStyle(allF)}>
                              {allF && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                            </div>
                            <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Encryption Spread — First {shown.length} Files</span>
                          </div>
                        </div>
                        <div style={{ maxHeight: 220, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                            <div style={{ width: 14, flexShrink: 0 }} />
                            {rwHdrCol(firstW[0], "Entry#", "rwSortFirst", "entryNumber", "rwFirstColW", defFirstW, 0)}
                            {rwHdrCol(firstW[1], "FileName", "rwSortFirst", "fileName", "rwFirstColW", defFirstW, 1)}
                            <div style={{ flex: 1, display: "flex", alignItems: "center", cursor: "pointer", userSelect: "none" }} onClick={() => handleRwSort("rwSortFirst", "parentPath")}>ParentPath{rwSortArrow("rwSortFirst", "parentPath")}</div>
                            {rwHdrCol(firstW[3], "Timestamp", "rwSortFirst", "timestamp", "rwFirstColW", defFirstW, 3)}
                            {rwHdrCol(firstW[4], "Size", "rwSortFirst", "fileSize", "rwFirstColW", defFirstW, 4)}
                          </div>
                          {sortRwArr(shown, modal.rwSortFirst).map((f, i) => {
                            const sel = selF.has(i);
                            const isExp = modal.rwExpandedRow?.section === "first" && modal.rwExpandedRow?.idx === i;
                            return (<Fragment key={i}>
                            <div onClick={() => toggleSet("rwSelFirst", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}0a`), borderBottom: `1px solid ${th.border}15`, cursor: "pointer" }}>
                              <div style={cbStyle(sel)}>
                                {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                              </div>
                              <span onClick={(e) => { e.stopPropagation(); setModal((p) => ({ ...p, rwExpandedRow: isExp ? null : { section: "first", idx: i } })); }} style={{ width: firstW[0], flexShrink: 0, color: th.accent, fontWeight: 600, fontSize: 10, cursor: "pointer", textDecoration: "underline", textDecorationStyle: "dotted" }}>#{f.entryNumber}</span>
                              <span style={{ width: firstW[1], flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.fileName}</span>
                              <span style={{ flex: 1, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.parentPath}</span>
                              <span style={{ width: firstW[3], flexShrink: 0, color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{(f.timestamp || "").slice(0, 19)}</span>
                              <span style={{ width: firstW[4], flexShrink: 0, color: th.textMuted, fontSize: 10, textAlign: "right" }}>{f.fileSize != null ? fmtSz(f.fileSize) : ""}</span>
                            </div>
                            {isExp && (
                              <div style={{ padding: "6px 10px 6px 42px", background: `${th.panelBg}dd`, borderBottom: `1px solid ${th.border}22`, fontSize: 9, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.textDim }}>
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 16px" }}>
                                  <span>Created (SI): {f.created0x10 || "—"}</span><span>Modified (SI): {f.timestamp || "—"}</span>
                                  <span>Record Change: {f.recordChange0x10 || "—"}</span><span>Created (FN): {f.created0x30 || "—"}</span>
                                  <span>Modified (FN): {f.lastMod0x30 || "—"}</span>
                                </div>
                              </div>
                            )}
                            </Fragment>);
                          })}
                        </div>
                      </div>
                      );
                    })()}

                    {/* Section 2c: Original-to-Encrypted Pair Detection */}
                    {data.originalPairs && (data.originalPairs.confirmedPairs > 0 || data.originalPairs.likelyPairs > 0) && (() => {
                      const op = data.originalPairs;
                      const rateColor = op.pairRate >= 0.8 ? (th.danger || "#f85149") : op.pairRate >= 0.5 ? (th.warning || "#d29922") : th.accent;
                      const shownPairs = op.samplePairs || [];
                      const selP = modal.rwSelPairs || new Set();
                      const allP = selP.size === shownPairs.length;
                      return (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Original-to-Encrypted Pair Detection</span>
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, marginBottom: 8 }}>
                          <div style={{ textAlign: "center", padding: "8px 6px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, borderRadius: 8, border: `1px solid ${th.border}33` }}>
                            <div style={{ fontSize: 18, fontWeight: 700, color: th.danger || "#f85149", fontFamily: "'Segoe UI', system-ui, sans-serif", lineHeight: 1 }}>{op.confirmedPairs}</div>
                            <div style={{ fontSize: 8, color: th.textMuted, marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", fontWeight: 500 }}>confirmed pairs</div>
                          </div>
                          <div style={{ textAlign: "center", padding: "8px 6px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, borderRadius: 8, border: `1px solid ${th.border}33` }}>
                            <div style={{ fontSize: 18, fontWeight: 700, color: th.warning || "#d29922", fontFamily: "'Segoe UI', system-ui, sans-serif", lineHeight: 1 }}>{op.likelyPairs}</div>
                            <div style={{ fontSize: 8, color: th.textMuted, marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", fontWeight: 500 }}>likely pairs</div>
                          </div>
                          <div style={{ textAlign: "center", padding: "8px 6px", background: `linear-gradient(160deg, ${rateColor}08, ${th.panelBg}cc)`, borderRadius: 8, border: `1px solid ${rateColor}33` }}>
                            <div style={{ fontSize: 18, fontWeight: 700, color: rateColor, fontFamily: "'Segoe UI', system-ui, sans-serif", lineHeight: 1 }}>{Math.round(op.pairRate * 100)}%</div>
                            <div style={{ fontSize: 8, color: rateColor + "bb", marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", fontWeight: 500 }}>pair rate</div>
                          </div>
                        </div>
                        {shownPairs.length > 0 && (
                        <div style={{ maxHeight: 160, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                            <div style={{ width: 14, flexShrink: 0 }} />
                            <div style={{ width: 130, flexShrink: 0 }}>Original</div>
                            <div style={{ width: 150, flexShrink: 0 }}>Encrypted</div>
                            <div style={{ flex: 1 }}>Path</div>
                            <div style={{ width: 55, flexShrink: 0 }}>Status</div>
                          </div>
                          {shownPairs.slice(0, 30).map((p, i) => {
                            const sel = selP.has(i);
                            return (
                            <div key={i} onClick={() => toggleSet("rwSelPairs", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}0a`), borderBottom: `1px solid ${th.border}15`, cursor: "pointer" }}>
                              <div style={cbStyle(sel)}>
                                {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                              </div>
                              <span style={{ width: 130, flexShrink: 0, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10 }}>{p.originalFile}</span>
                              <span style={{ width: 150, flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10 }}>{p.encryptedFile}</span>
                              <span style={{ flex: 1, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10 }}>{p.parentPath}</span>
                              <span style={{ width: 55, flexShrink: 0 }}>
                                <span style={{ padding: "1px 5px", borderRadius: 4, fontSize: 8, fontWeight: 700, color: "#fff", background: p.originalDeleted ? (th.danger || "#f85149") : (th.warning || "#d29922") }}>{p.originalDeleted ? "DELETED" : "ABSENT"}</span>
                              </span>
                            </div>
                            );
                          })}
                        </div>
                        )}
                      </div>
                      );
                    })()}

                    {/* Section 3: Forensic Indicators — with observed/inferred labels */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6, marginBottom: 8 }}>
                      {[
                        { val: data.ransomNoteCount, label: "ransom notes", color: data.ransomNoteCount > 0 ? (th.warning || "#d29922") : th.textDim, active: data.ransomNoteCount > 0 },
                        { val: data.deletedEncrypted, label: "deleted encrypted", color: data.deletedEncrypted > 0 ? (th.danger || "#f85149") : th.textDim, active: data.deletedEncrypted > 0 },
                        { val: data.timestompedCount, label: "timestomped", color: data.timestompedCount > 0 ? (th.danger || "#f85149") : th.textDim, active: data.timestompedCount > 0 },
                        { val: (data.suspiciousFiles || []).length, label: "suspicious exes", color: (data.suspiciousFiles || []).length > 0 ? (th.danger || "#f85149") : th.textDim, active: (data.suspiciousFiles || []).length > 0 },
                      ].map((c, i) => (
                        <div key={i} style={{ textAlign: "center", padding: "10px 6px", background: c.active ? `linear-gradient(160deg, ${c.color}12, ${th.panelBg}cc)` : `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 10, border: `1px solid ${c.active ? c.color + "33" : th.border + "33"}` }}>
                          <div style={{ fontSize: 20, fontWeight: 700, color: c.color, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}>{c.val}</div>
                          <div style={{ fontSize: 9, color: c.active ? c.color + "bb" : th.textMuted, marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", fontWeight: 500 }}>{c.label}</div>
                        </div>
                      ))}
                    </div>
                    {/* Forensic indicator pills — observed vs inferred */}
                    {data.forensicIndicators?.length > 0 && (
                      <div style={{ marginBottom: 16, padding: "8px 12px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                          <span style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Evidence</span>
                          <span style={{ fontSize: 8, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                            <span style={{ color: th.accent }}>&#9679;</span> Observed
                            <span style={{ margin: "0 4px" }}>|</span>
                            <span style={{ color: th.textMuted }}>&#9675;</span> Inferred
                          </span>
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {data.forensicIndicators.map((fi, i) => {
                            const pc = { execution: th.danger || "#f85149", correlation: th.accent || "#58a6ff", context: th.textMuted || "#8b949e" };
                            const color = pc[fi.type] || th.textMuted;
                            const isInferred = fi.basis === "inferred";
                            return (
                              <span key={i} title={isInferred ? "Inferred from pattern analysis" : "Directly observed in data"} style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, background: `${color}${isInferred ? "0c" : "18"}`, color, fontWeight: 500, fontFamily: "'Segoe UI', system-ui, sans-serif", border: `1px ${isInferred ? "dashed" : "solid"} ${color}33`, opacity: isInferred ? 0.85 : 1 }}>
                                {fi.text}
                              </span>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Section 4: File Type Impact Breakdown */}
                    {data.fileTypeBreakdown && data.fileTypeBreakdown.length > 0 && (() => {
                      const types = data.fileTypeBreakdown;
                      const maxCount = types[0]?.count || 1;
                      const dc = th.danger || "#f85149";
                      // Color palette for file types
                      const typeColors = { ".docx": "#2b7cd3", ".doc": "#2b7cd3", ".xlsx": "#1d7044", ".xls": "#1d7044", ".pptx": "#c43e1c", ".ppt": "#c43e1c", ".pdf": "#e44d26", ".jpg": "#e8a838", ".jpeg": "#e8a838", ".png": "#a855f7", ".gif": "#f472b6", ".zip": "#d29922", ".rar": "#d29922", ".7z": "#d29922", ".sql": "#3b82f6", ".db": "#3b82f6", ".csv": "#10b981", ".txt": "#6b7280", ".xml": "#f97316", ".json": "#f97316", ".html": "#e44d26", ".py": "#3776ab", ".js": "#f7df1e", ".cpp": "#659ad2", ".java": "#ed8b00", ".psd": "#31a8ff", ".ai": "#ff9a00", ".dwg": "#e51937", ".bak": "#8b5cf6", ".vmdk": "#607078", ".vhdx": "#607078" };
                      const getColor = (ext) => typeColors[ext] || th.accent;
                      return (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                            <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>File Type Impact</span>
                            <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{types.length} types</span>
                          </div>
                          <div style={{ display: "flex", gap: 8, overflow: "hidden" }}>
                            {/* Horizontal bar chart */}
                            <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "8px 0", maxHeight: 200, overflow: "auto" }}>
                              {types.map((t, i) => {
                                const pct = Math.max(2, (t.count / maxCount) * 100);
                                const c = getColor(t.ext);
                                return (
                                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 12px", fontSize: 11 }}>
                                    <span style={{ width: 70, flexShrink: 0, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", fontSize: 10, color: c, fontWeight: 600, textAlign: "right", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.ext}</span>
                                    <div style={{ flex: 1, minWidth: 0, height: 14, borderRadius: 4, background: `${th.border}15`, overflow: "hidden", position: "relative" }}>
                                      <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pct}%`, borderRadius: 4, background: `linear-gradient(90deg, ${c}88, ${c}44)`, transition: "width 0.3s" }} />
                                    </div>
                                    <span style={{ width: 40, flexShrink: 0, textAlign: "right", fontSize: 10, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{t.count.toLocaleString()}</span>
                                  </div>
                                );
                              })}
                            </div>
                            {/* Top types summary */}
                            <div style={{ width: 150, flexShrink: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "10px 12px", display: "flex", flexDirection: "column", justifyContent: "center", gap: 4, overflow: "hidden" }}>
                              <div style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 2 }}>Top Types</div>
                              {types.slice(0, 6).map((t, i) => {
                                const c = getColor(t.ext);
                                const pct = ((t.count / data.encryptedCount) * 100).toFixed(1);
                                return (
                                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                                    <div style={{ width: 8, height: 8, borderRadius: 2, background: c, flexShrink: 0 }} />
                                    <span style={{ fontSize: 10, color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.ext}</span>
                                    <span style={{ fontSize: 10, color: th.text, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif", flexShrink: 0 }}>{pct}%</span>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Section 4b: Business Impact Assessment */}
                    {data.businessImpact?.length > 0 && (() => {
                      const cats = data.businessImpact.filter(c => c.category !== "Other");
                      if (cats.length === 0) return null;
                      const maxCat = cats[0]?.count || 1;
                      const catColors = { "Documents": "#2b7cd3", "Spreadsheets": "#1d7044", "Presentations": "#c43e1c", "Email & Messaging": "#e8a838", "Databases": "#8b5cf6", "Archives": "#d29922", "Source Code": "#10b981", "Images & Design": "#a855f7", "Audio & Video": "#f472b6", "Virtual Machines": "#607078", "Backups & Recovery": "#ef4444", "CAD & Engineering": "#e51937" };
                      return (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                            <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Business Impact Assessment</span>
                            <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{cats.length} categories</span>
                          </div>
                          <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10, padding: "8px 0", maxHeight: 200, overflow: "auto" }}>
                            {cats.map((c, i) => {
                              const pct = Math.max(2, (c.count / maxCat) * 100);
                              const color = catColors[c.category] || th.accent;
                              return (
                                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 12px", fontSize: 11 }}>
                                  <div style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
                                  <span style={{ width: 110, flexShrink: 0, fontFamily: "'Segoe UI', system-ui, sans-serif", fontSize: 10, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.category}</span>
                                  <div style={{ flex: 1, minWidth: 0, height: 14, borderRadius: 4, background: `${th.border}15`, overflow: "hidden", position: "relative" }}>
                                    <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pct}%`, borderRadius: 4, background: `linear-gradient(90deg, ${color}88, ${color}44)`, transition: "width 0.3s" }} />
                                  </div>
                                  <span style={{ width: 50, flexShrink: 0, textAlign: "right", fontSize: 10, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{c.count.toLocaleString()}</span>
                                  <span style={{ width: 36, flexShrink: 0, textAlign: "right", fontSize: 9, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{Math.round(c.percentage * 100)}%</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })()}

                    {/* Section 4c: Backup & Recovery Artifacts */}
                    {data.backupRecoveryTotal > 0 && (() => {
                      const items = data.backupRecoveryImpact || [];
                      const dc = th.danger || "#f85149";
                      return (
                        <div style={{ marginBottom: 16, padding: "12px 14px", background: `linear-gradient(135deg, ${dc}08, ${th.panelBg}ee)`, border: `1px solid ${dc}22`, borderRadius: 10, borderLeft: `3px solid ${dc}` }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={dc} strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                              <span style={{ fontSize: 10, fontWeight: 700, color: dc, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Backup & Recovery Artifacts Affected</span>
                            </div>
                            <span style={{ fontSize: 10, color: dc, fontWeight: 600, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{data.backupRecoveryTotal.toLocaleString()} files</span>
                          </div>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                            {items.map((item, i) => (
                              <div key={i} style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", background: `${dc}12`, borderRadius: 6, border: `1px solid ${dc}22` }}>
                                <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{item.subtype}</span>
                                <span style={{ fontSize: 10, fontWeight: 600, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{item.ext}</span>
                                <span style={{ fontSize: 9, color: dc, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{item.count.toLocaleString()}</span>
                              </div>
                            ))}
                          </div>
                          <div style={{ marginTop: 6, fontSize: 10, color: dc + "cc", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Recovery capability may be impacted — verify backup integrity</div>
                        </div>
                      );
                    })()}

                    {/* Section 5: Encryption Timeline */}
                    {data.timeline && data.timeline.length > 0 && (() => {
                      const CHART_H = 110;
                      let buckets = data.timeline;
                      if (buckets.length > 300) {
                        const factor = Math.ceil(buckets.length / 300);
                        const merged = [];
                        for (let i = 0; i < buckets.length; i += factor) {
                          const slice = buckets.slice(i, i + factor);
                          merged.push({ bucket: slice[0].bucket, count: slice.reduce((s, b) => s + b.count, 0) });
                        }
                        buckets = merged;
                      }
                      const maxCnt = Math.max(...buckets.map((b) => b.count), 1);
                      const peakBucket = buckets.reduce((a, b) => b.count > a.count ? b : a, buckets[0]);
                      const dc = th.danger || "#f85149";
                      return (
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                            <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Encryption Timeline</span>
                            {peakBucket && <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>peak: <span style={{ color: dc, fontWeight: 600 }}>{peakBucket.count.toLocaleString()}</span> files at {peakBucket.bucket}</span>}
                          </div>
                          <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden", padding: "12px 8px 6px" }}>
                            <svg width="100%" height={CHART_H} viewBox={`0 0 ${buckets.length} ${CHART_H}`} preserveAspectRatio="none" style={{ display: "block" }}>
                              <defs>
                                <linearGradient id="rwBarGrad" x1="0" y1="0" x2="0" y2="1">
                                  <stop offset="0%" stopColor={dc} stopOpacity="0.95" />
                                  <stop offset="100%" stopColor={dc} stopOpacity="0.4" />
                                </linearGradient>
                              </defs>
                              {buckets.map((b, i) => {
                                const h = Math.max(0.5, (b.count / maxCnt) * (CHART_H - 6));
                                return <rect key={i} x={i} y={CHART_H - h} width={0.85} height={h} fill="url(#rwBarGrad)" rx={0.2} />;
                              })}
                            </svg>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: th.textMuted, marginTop: 6, padding: "0 2px", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                              <span>{buckets[0]?.bucket}</span>
                              <span>{buckets[buckets.length - 1]?.bucket}</span>
                            </div>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Section 5: Top Affected Subtrees */}
                    {data.topDirectories && data.topDirectories.length > 0 && (() => {
                      const shown = data.topDirectories.slice(0, 15);
                      const selD = modal.rwSelDirs || new Set();
                      const allD = selD.size === shown.length;
                      const maxEnc = shown[0]?.encryptedCount || shown[0]?.count || 1;
                      return (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div onClick={() => toggleAll("rwSelDirs", shown.length)} style={cbStyle(allD)}>
                              {allD && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                            </div>
                            <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Affected Subtrees</span>
                          </div>
                          <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{data.topDirectories.length} subtrees</span>
                        </div>
                        <div style={{ maxHeight: 220, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                          {shown.map((dir, i) => {
                            const enc = dir.encryptedCount || dir.count || 0;
                            const total = dir.totalCount || enc;
                            const ratio = dir.ratio ?? (total > 0 ? enc / total : 0);
                            const pctBar = Math.max(1, (enc / maxEnc) * 100);
                            const ratioPct = Math.round(ratio * 100);
                            const ratioColor = ratioPct >= 90 ? (th.danger || "#f85149") : ratioPct >= 50 ? (th.warning || "#d29922") : th.accent;
                            const sel = selD.has(i);
                            return (
                              <div key={i} onClick={() => toggleSet("rwSelDirs", i)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", fontSize: 11, borderBottom: `1px solid ${th.border}15`, position: "relative", cursor: "pointer", background: sel ? `${th.accent}0a` : "transparent" }}>
                                <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pctBar}%`, background: `linear-gradient(90deg, ${ratioColor}12, ${ratioColor}04)`, borderRadius: i === 0 ? "10px 0 0 0" : 0 }} />
                                <div style={{ ...cbStyle(sel), position: "relative" }}>
                                  {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                                </div>
                                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.textDim, position: "relative", fontSize: 10 }}>{dir.path || "(root)"}</span>
                                {dir.childDirCount > 1 && <span style={{ position: "relative", fontSize: 8, color: th.textMuted, padding: "1px 4px", background: `${th.border}22`, borderRadius: 3, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{dir.childDirCount} dirs</span>}
                                <span style={{ fontWeight: 600, color: th.text, fontSize: 10, whiteSpace: "nowrap", position: "relative", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", padding: "1px 6px", background: `${th.border}22`, borderRadius: 4 }}>{enc.toLocaleString()} / {total.toLocaleString()}</span>
                                <span style={{ position: "relative", fontSize: 9, fontWeight: 700, color: ratioColor, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", minWidth: 32, textAlign: "right" }}>{ratioPct}%</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                      );
                    })()}

                    {/* Section 6: Ransom Notes */}
                    {data.ransomNotes && data.ransomNotes.length > 0 && (() => {
                      const shownN = data.ransomNotes.slice(0, 50);
                      const selN = modal.rwSelNotes || new Set();
                      const allN = selN.size === shownN.length;
                      return (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div onClick={() => toggleAll("rwSelNotes", shownN.length)} style={cbStyle(allN)}>
                              {allN && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                            </div>
                            <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Ransom Note Locations</span>
                          </div>
                          <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{data.ransomNoteCount} found</span>
                        </div>
                        <div style={{ maxHeight: 180, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                          {/* Column header */}
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                            <div style={{ width: 14, flexShrink: 0 }} />
                            {rwHdrCol(notesW[0], "Entry#", "rwSortNotes", "entryNumber", "rwNotesColW", defNotesW, 0)}
                            {rwHdrCol(notesW[1], "FileName", "rwSortNotes", "fileName", "rwNotesColW", defNotesW, 1)}
                            <div style={{ flex: 1, display: "flex", alignItems: "center", cursor: "pointer", userSelect: "none" }} onClick={() => handleRwSort("rwSortNotes", "parentPath")}>ParentPath{rwSortArrow("rwSortNotes", "parentPath")}</div>
                            {rwHdrCol(notesW[3], "Created", "rwSortNotes", "created", "rwNotesColW", defNotesW, 3)}
                          </div>
                          {sortRwArr(shownN, modal.rwSortNotes).map((note, i) => {
                            const sel = selN.has(i);
                            return (
                            <div key={i} onClick={() => toggleSet("rwSelNotes", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}0a`), borderBottom: `1px solid ${th.border}15`, cursor: "pointer" }}>
                              <div style={cbStyle(sel)}>
                                {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                              </div>
                              <span style={{ width: notesW[0], flexShrink: 0, color: th.warning || "#d29922", fontWeight: 600, fontSize: 10 }}>#{note.entryNumber}</span>
                              <span style={{ width: notesW[1], flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{note.fileName}</span>
                              <span style={{ flex: 1, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{note.parentPath}</span>
                              <span style={{ width: notesW[3], flexShrink: 0, color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{(note.created || "").slice(0, 19)}</span>
                            </div>
                            );
                          })}
                          {data.ransomNoteCount > 50 && <div style={{ padding: "6px 10px", fontSize: 10, color: th.textMuted, textAlign: "center", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>...and {(data.ransomNoteCount - 50).toLocaleString()} more</div>}
                        </div>
                      </div>
                      );
                    })()}

                    {/* Section 7: Scored Payload Candidates */}
                    {data.suspiciousFiles && data.suspiciousFiles.length > 0 && (() => {
                      const selS = modal.rwSelSusp || new Set();
                      const allS = selS.size === data.suspiciousFiles.length;
                      const topConf = data.suspiciousFiles[0]?.confidence;
                      const confColor = topConf === "confirmed" ? (th.danger || "#f85149") : topConf === "likely" ? (th.warning || "#d29922") : th.textMuted;
                      const expanded = modal.rwExpandedRow;
                      return (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div onClick={() => toggleAll("rwSelSusp", data.suspiciousFiles.length)} style={cbStyle(allS)}>
                              {allS && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                            </div>
                            <span style={{ fontSize: 10, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Payload Candidates</span>
                            {topConf && <span style={{ fontSize: 8, padding: "1px 6px", borderRadius: 3, background: `${confColor}22`, color: confColor, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", fontWeight: 600, border: `1px solid ${confColor}44`, textTransform: "uppercase", letterSpacing: "0.05em" }}>{topConf}</span>}
                          </div>
                          <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{"\u00B1"}30 min window</span>
                        </div>
                        <div style={{ maxHeight: 280, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                            <div style={{ width: 14, flexShrink: 0 }} />
                            <div style={{ width: 32, flexShrink: 0 }}>Score</div>
                            {rwHdrCol(suspW[0], "Ext", "rwSortSusp", "extension", "rwSuspColW", defSuspW, 0)}
                            {rwHdrCol(suspW[1], "FileName", "rwSortSusp", "fileName", "rwSuspColW", defSuspW, 1)}
                            <div style={{ flex: 1, display: "flex", alignItems: "center", cursor: "pointer", userSelect: "none" }} onClick={() => handleRwSort("rwSortSusp", "parentPath")}>ParentPath{rwSortArrow("rwSortSusp", "parentPath")}</div>
                            {rwHdrCol(suspW[3], "Created", "rwSortSusp", "created", "rwSuspColW", defSuspW, 3)}
                            <div style={{ width: 50 }} />
                          </div>
                          {sortRwArr(data.suspiciousFiles, modal.rwSortSusp).map((sf, i) => {
                            const sel = selS.has(i);
                            const sc = sf.score || 0;
                            const scoreColor = sc >= 0.6 ? (th.danger || "#f85149") : sc >= 0.35 ? (th.warning || "#d29922") : sc >= 0.15 ? th.accent : th.textMuted;
                            const isExpanded = expanded?.section === "susp" && expanded?.idx === i;
                            return (<Fragment key={i}>
                            <div onClick={() => toggleSet("rwSelSusp", i)} style={{ ...rowStyle(i), background: sel ? `${th.accent}0a` : (sc >= 0.35 ? `linear-gradient(90deg, ${scoreColor}08, transparent)` : (i % 2 === 0 ? "transparent" : `${th.border}0a`)), borderBottom: `1px solid ${th.border}15`, borderLeft: `2px solid ${sc >= 0.35 ? scoreColor + "66" : "transparent"}`, cursor: "pointer", flexWrap: "wrap" }}>
                              <div style={cbStyle(sel)}>
                                {sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                              </div>
                              <span style={{ padding: "1px 5px", borderRadius: 4, fontSize: 9, fontWeight: 700, background: `${scoreColor}22`, color: scoreColor, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", minWidth: 28, textAlign: "center", width: 32, flexShrink: 0 }}>{Math.round(sc * 100)}</span>
                              <span onClick={(e) => { e.stopPropagation(); setModal((p) => ({ ...p, rwExpandedRow: isExpanded ? null : { section: "susp", idx: i } })); }} style={{ width: suspW[0], flexShrink: 0, color: th.danger || "#f85149", fontWeight: 600, fontSize: 10, cursor: "pointer", textDecoration: "underline", textDecorationStyle: "dotted" }}>{sf.extension}</span>
                              <span style={{ width: suspW[1], flexShrink: 0, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sf.fileName}</span>
                              <span style={{ flex: 1, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sf.parentPath}</span>
                              <span style={{ width: suspW[3], flexShrink: 0, color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{(sf.created || "").slice(0, 19)}</span>
                              <div style={{ display: "flex", gap: 3, width: 50, flexShrink: 0, justifyContent: "flex-end" }}>
                                {sf.zoneId && <span style={{ padding: "1px 4px", borderRadius: 3, fontSize: 7, fontWeight: 700, color: "#fff", background: th.danger || "#f85149" }}>WEB</span>}
                                {sf.inUse === "False" && <span style={{ padding: "1px 4px", borderRadius: 3, fontSize: 7, fontWeight: 700, color: "#fff", background: th.warning || "#d29922" }}>DEL</span>}
                                {sf.siFN === "True" && <span style={{ padding: "1px 4px", borderRadius: 3, fontSize: 7, fontWeight: 700, color: "#fff", background: "#a855f7" }}>TS</span>}
                              </div>
                              {/* Evidence signal pills */}
                              {sf.signals?.length > 0 && (
                                <div style={{ width: "100%", paddingLeft: 28, display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}>
                                  {sf.signals.map((sig, si) => {
                                    const pc = { execution: th.danger || "#f85149", correlation: th.accent || "#58a6ff", context: th.textMuted || "#8b949e" };
                                    const c = pc[sig.type] || th.textMuted;
                                    return <span key={si} title={sig.basis === "inferred" ? "Inferred" : "Observed"} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${c}${sig.basis === "inferred" ? "0c" : "15"}`, color: c, fontFamily: "'Segoe UI', system-ui, sans-serif", border: `1px ${sig.basis === "inferred" ? "dashed" : "solid"} ${c}22`, opacity: sig.basis === "inferred" ? 0.8 : 1 }}>{sig.text}</span>;
                                  })}
                                </div>
                              )}
                            </div>
                            {/* Expandable timestamp detail */}
                            {isExpanded && (
                              <div style={{ padding: "6px 10px 6px 42px", background: `${th.panelBg}dd`, borderBottom: `1px solid ${th.border}22`, fontSize: 9, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.textDim }}>
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 16px" }}>
                                  <span>Created (SI): {sf.created || "—"}</span><span>Modified (SI): {sf.lastModified || "—"}</span>
                                  <span>Record Change: {sf.recordChange0x10 || "—"}</span><span>Created (FN): {sf.created0x30 || "—"}</span>
                                  <span>Modified (FN): {sf.lastMod0x30 || "—"}</span>
                                </div>
                              </div>
                            )}
                            </Fragment>);
                          })}
                        </div>
                        {/* Click any row entry# to expand timestamps */}
                        <div style={{ fontSize: 8, color: th.textMuted, marginTop: 3, fontFamily: "'Segoe UI', system-ui, sans-serif", fontStyle: "italic" }}>Click extension to expand timestamps</div>
                      </div>
                      );
                    })()}

                    {/* Section 8: Anti-Forensics & Cleanup */}
                    {data.antiForensics && (data.antiForensics.deletedEncrypted?.length > 0 || data.antiForensics.timestomped?.length > 0 || data.antiForensics.cleanup?.length > 0 || data.antiForensics.drops?.length > 0) && (() => {
                      const af = data.antiForensics;
                      const dc = th.danger || "#f85149";
                      const wc = th.warning || "#d29922";
                      const cats = [
                        { key: "deletedEncrypted", label: "Deleted Encrypted", items: af.deletedEncrypted || [], color: dc },
                        { key: "timestomped", label: "Timestomped in Window", items: af.timestomped || [], color: "#a855f7" },
                        { key: "cleanup", label: "Cleanup Artifacts", items: af.cleanup || [], color: wc },
                        { key: "drops", label: "Suspicious Drops", items: af.drops || [], color: th.accent },
                      ].filter(c => c.items.length > 0);
                      const selAF = modal.rwSelAF || new Set();
                      let afIdx = 0;
                      return (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={dc} strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                          <span style={{ fontSize: 10, fontWeight: 700, color: dc, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Anti-Forensics & Cleanup</span>
                        </div>
                        {/* Summary bar */}
                        <div style={{ display: "grid", gridTemplateColumns: `repeat(${cats.length}, 1fr)`, gap: 6, marginBottom: 8 }}>
                          {cats.map((c) => (
                            <div key={c.key} style={{ textAlign: "center", padding: "6px", background: `${c.color}08`, borderRadius: 8, border: `1px solid ${c.color}22` }}>
                              <div style={{ fontSize: 16, fontWeight: 700, color: c.color, fontFamily: "'Segoe UI', system-ui, sans-serif", lineHeight: 1 }}>{c.items.length}</div>
                              <div style={{ fontSize: 8, color: c.color + "bb", marginTop: 2, textTransform: "uppercase", letterSpacing: "0.04em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{c.label}</div>
                            </div>
                          ))}
                        </div>
                        {/* Collapsible details */}
                        <div style={{ maxHeight: 200, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                          {cats.map((cat) => {
                            const startIdx = afIdx;
                            return cat.items.map((item, ii) => {
                              const gi = afIdx++;
                              const sel = selAF.has(gi);
                              return (
                                <div key={`${cat.key}-${ii}`} onClick={() => toggleSet("rwSelAF", gi)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 10px", fontSize: 10, borderBottom: `1px solid ${th.border}12`, cursor: "pointer", background: sel ? `${th.accent}0a` : (gi % 2 === 0 ? "transparent" : `${th.border}08`), borderLeft: `2px solid ${cat.color}44` }}>
                                  <div style={cbStyle(sel)}>{sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}</div>
                                  <span style={{ fontSize: 7, padding: "1px 4px", borderRadius: 3, background: `${cat.color}22`, color: cat.color, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif", textTransform: "uppercase", flexShrink: 0 }}>{cat.label.split(" ")[0]}</span>
                                  <span style={{ color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", fontSize: 9, flexShrink: 0 }}>#{item.entryNumber}</span>
                                  <span style={{ color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{item.fileName}</span>
                                  <span style={{ flex: 1, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{item.parentPath}</span>
                                  <span style={{ color: th.textMuted, fontSize: 9, whiteSpace: "nowrap", flexShrink: 0, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{(item.created || item.lastModified || "").slice(0, 19)}</span>
                                </div>
                              );
                            });
                          })}
                        </div>
                      </div>
                      );
                    })()}

                    {/* Section 9: USN Journal Correlation */}
                    {data.usnEnrichment && (() => {
                      const usn = data.usnEnrichment;
                      const ac = th.accent;
                      return (
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: ac, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>USN Journal Correlation</span>
                        </div>
                        {/* Precise start callout */}
                        {usn.preciseStartTime && data.firstEncrypted?.timestamp && usn.preciseStartTime !== data.firstEncrypted.timestamp && (
                          <div style={{ marginBottom: 8, padding: "8px 12px", background: `${ac}08`, border: `1px solid ${ac}22`, borderRadius: 8, borderLeft: `3px solid ${ac}` }}>
                            <div style={{ fontSize: 10, color: ac, fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>USN places encryption start at <span style={{ fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{usn.preciseStartTime}</span></div>
                            <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif", marginTop: 2 }}>MFT LastModified shows <span style={{ fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{data.firstEncrypted.timestamp}</span></div>
                          </div>
                        )}
                        {/* Summary stats */}
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, marginBottom: 8 }}>
                          {[
                            { val: usn.renameCount, label: "rename events", color: ac },
                            { val: usn.overwriteTotal, label: "data overwrites", color: th.warning || "#d29922" },
                            { val: usn.deleteTotal, label: "deletions", color: th.danger || "#f85149" },
                          ].map((c, i) => (
                            <div key={i} style={{ textAlign: "center", padding: "8px 6px", background: `${c.color}08`, borderRadius: 8, border: `1px solid ${c.color}22` }}>
                              <div style={{ fontSize: 18, fontWeight: 700, color: c.color, fontFamily: "'Segoe UI', system-ui, sans-serif", lineHeight: 1 }}>{c.val.toLocaleString()}</div>
                              <div style={{ fontSize: 8, color: c.color + "bb", marginTop: 3, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{c.label}</div>
                            </div>
                          ))}
                        </div>
                        {/* Overwrite burst mini-timeline */}
                        {usn.overwriteBuckets?.length > 0 && (() => {
                          const bkts = usn.overwriteBuckets;
                          const maxC = Math.max(...bkts.map(b => b.count), 1);
                          return (
                            <div style={{ marginBottom: 8, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10, padding: "8px 8px 4px" }}>
                              <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, marginBottom: 4, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Data Overwrite Burst Pattern</div>
                              <svg width="100%" height="50" viewBox={`0 0 ${bkts.length} 50`} preserveAspectRatio="none" style={{ display: "block" }}>
                                {bkts.map((b, i) => { const h = Math.max(0.5, (b.count / maxC) * 44); return <rect key={i} x={i} y={50 - h} width={0.85} height={h} fill={(th.warning || "#d29922") + "88"} rx={0.2} />; })}
                              </svg>
                              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: th.textMuted, marginTop: 2, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                <span>{bkts[0]?.bucket}</span><span>{bkts[bkts.length - 1]?.bucket}</span>
                              </div>
                            </div>
                          );
                        })()}
                        {/* Sample rename events */}
                        {usn.renameSamples?.length > 0 && (
                          <div style={{ maxHeight: 140, overflow: "auto", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1 }}>
                              <div style={{ width: 14, flexShrink: 0 }} />
                              <div style={{ width: 130, flexShrink: 0 }}>Timestamp</div>
                              <div style={{ flex: 1 }}>FileName</div>
                              <div style={{ width: 200, flexShrink: 0 }}>Path</div>
                            </div>
                            {usn.renameSamples.map((r, i) => {
                              const sel = (modal.rwSelUsn || new Set()).has(i);
                              return (
                                <div key={i} onClick={() => toggleSet("rwSelUsn", i)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 10px", fontSize: 10, borderBottom: `1px solid ${th.border}12`, cursor: "pointer", background: sel ? `${th.accent}0a` : (i % 2 === 0 ? "transparent" : `${th.border}08`), fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                  <div style={cbStyle(sel)}>{sel && <svg width="10" height="10" viewBox="0 0 12 12"><polyline points="2 6 5 9 10 3" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}</div>
                                  <span style={{ width: 130, flexShrink: 0, color: th.textMuted, fontSize: 9 }}>{(r.timestamp || "").slice(0, 19)}</span>
                                  <span style={{ flex: 1, color: th.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.name}</span>
                                  <span style={{ width: 200, flexShrink: 0, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.parentPath || ""}</span>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                      );
                    })()}
                  </>)}
                </>)}
              </div>

              {/* Footer — glass */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                {phase === "input" && (<>
                  <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                  <button onClick={handleAnalyze} disabled={!encryptedExt.trim() || loading} style={{ ...ms.bp, opacity: !encryptedExt.trim() ? 0.5 : 1 }}>Analyze</button>
                </>)}
                {phase === "scanning" && <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Scanning...</span>}
                {phase === "loading" && <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Analyzing...</span>}
                {phase === "results" && (<>
                  <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                    <button onClick={() => setModal((p) => ({ ...p, phase: "input", data: null }))} style={ms.bs}>Back</button>
                    {/* Pivot actions menu */}
                    {data && data.encryptedCount > 0 && (
                      <div style={{ position: "relative" }}>
                        <button onClick={() => setModal((p) => ({ ...p, rwShowPivots: !p.rwShowPivots }))} style={{ ...ms.bs, display: "flex", alignItems: "center", gap: 4, fontSize: 10 }}>
                          Pivots <svg width="8" height="5" viewBox="0 0 8 5" style={{ marginLeft: 2 }}><path d="M0 0L4 5L8 0" fill={th.textMuted} /></svg>
                        </button>
                        {modal.rwShowPivots && (
                          <div style={{ position: "absolute", bottom: "100%", left: 0, marginBottom: 4, minWidth: 240, background: th.modalBg, border: `1px solid ${th.border}66`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.4)", zIndex: 10, padding: "4px 0", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                            {/* Tag encrypted files (multi-extension aware) */}
                            <button onClick={async () => {
                              try {
                                const exts = (data.extensions || [encryptedExt]);
                                const extFilters = exts.map((e, ei) => ({ column: "Extension", operator: "equals", value: e, logic: ei === 0 ? "AND" : "OR" }));
                                await tle.bulkTagFiltered(ct.id, "Encrypted", { advancedFilters: extFilters });
                                const td = await tle.getAllTagData(ct.id); const nrt = {}; for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); } up("rowTags", nrt);
                                const nc = { ...(ct.tagColors || {}), Encrypted: "#f85149" }; up("tagColors", nc);
                                setModal((p) => ({ ...p, rwPivotMsg: `Tagged ${data.encryptedCount.toLocaleString()} files as "Encrypted"`, rwShowPivots: false }));
                                setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 3000);
                              } catch {}
                            }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                              Tag Encrypted Files ({data.encryptedCount.toLocaleString()})
                            </button>
                            {/* Filter grid to encryption window */}
                            {(data.timingEvidence?.filterWindow?.from || data.firstEncrypted?.timestamp) && (data.timingEvidence?.filterWindow?.to || data.lastEncrypted?.timestamp) && (
                              <button onClick={() => {
                                const filterCol = (data.timingEvidence?.filterWindow?.column && ct.headers?.includes(data.timingEvidence.filterWindow.column))
                                  ? data.timingEvidence.filterWindow.column
                                  : (ct.headers?.find((h) => h === "LastModified0x10") || "LastModified0x10");
                                const from = data.timingEvidence?.filterWindow?.from || data.firstEncrypted.timestamp;
                                const to = data.timingEvidence?.filterWindow?.to || data.lastEncrypted.timestamp;
                                up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [filterCol]: { from, to } });
                                setModal(null);
                              }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                                Filter Grid to Encryption Window
                              </button>
                            )}
                            {/* Open top directory */}
                            {data.topDirectories?.[0] && (
                              <button onClick={() => {
                                const topDir = (data.topDirectories[0].path || "").replace(/^\.\\/, "");
                                up("searchTerm", "");
                                up("advancedFilters", [
                                  { column: "ParentPath", operator: "equals", value: topDir, logic: "AND" },
                                  { column: "ParentPath", operator: "starts_with", value: `${topDir}\\`, logic: "OR" },
                                ]);
                                setModal(null);
                              }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                                Open Top Directory in Grid
                              </button>
                            )}
                            {/* Tag ransom notes */}
                            {data.ransomNoteCount > 0 && ransomNotePattern && (
                              <button onClick={async () => {
                                try {
                                  const tagMap = {};
                                  (data.ransomNotes || []).forEach((note) => {
                                    if (note.rowId != null) tagMap[note.rowId] = ["Ransom Note"];
                                  });
                                  await tle.bulkAddTags(ct.id, tagMap);
                                  const td = await tle.getAllTagData(ct.id); const nrt = {}; for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); } up("rowTags", nrt);
                                  const nc = { ...(ct.tagColors || {}), "Ransom Note": "#d29922" }; up("tagColors", nc);
                                  setModal((p) => ({ ...p, rwPivotMsg: `Tagged ${Object.keys(tagMap).length} files as "Ransom Note"`, rwShowPivots: false }));
                                  setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 3000);
                                } catch {}
                              }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                                Tag Ransom Note Files ({data.ransomNoteCount})
                              </button>
                            )}
                            {/* Tag payload candidates */}
                            {data.suspiciousFiles?.filter(s => s.score >= 0.35).length > 0 && (
                              <button onClick={async () => {
                                try {
                                  const cands = data.suspiciousFiles.filter(s => s.score >= 0.35);
                                  const tagMap = {};
                                  cands.forEach((cand) => {
                                    if (cand.rowId != null) tagMap[cand.rowId] = ["Payload"];
                                  });
                                  await tle.bulkAddTags(ct.id, tagMap);
                                  const td = await tle.getAllTagData(ct.id); const nrt = {}; for (const { rowid, tag } of td) { if (!nrt[rowid]) nrt[rowid] = []; nrt[rowid].push(tag); } up("rowTags", nrt);
                                  const nc = { ...(ct.tagColors || {}), Payload: "#da3633" }; up("tagColors", nc);
                                  setModal((p) => ({ ...p, rwPivotMsg: `Tagged ${Object.keys(tagMap).length} files as "Payload"`, rwShowPivots: false }));
                                  setTimeout(() => setModal((p) => p ? { ...p, rwPivotMsg: null } : p), 3000);
                                } catch {}
                              }} style={{ display: "block", width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                                Tag Payload Candidates ({data.suspiciousFiles.filter(s => s.score >= 0.35).length})
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  {/* Pivot feedback toast */}
                  {modal.rwPivotMsg && (
                    <span style={{ fontSize: 10, color: th.accent, fontWeight: 500, fontFamily: "'Segoe UI', system-ui, sans-serif", animation: "tle-fadeIn 0.2s" }}>{modal.rwPivotMsg}</span>
                  )}
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, display: "flex", alignItems: "center", gap: 4 }}>Copy Selected <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 8, background: th.accent, color: "#fff", fontWeight: 700, lineHeight: "14px" }}>{totalSelected}</span></button>}
                    {data && data.encryptedCount > 0 && <button onClick={copyReport} style={ms.bs}>Copy Summary</button>}
                    {data && data.encryptedCount > 0 && <button onClick={exportPdf} style={{ ...ms.bs, display: "flex", alignItems: "center", gap: 4 }}><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><polyline points="9 15 12 18 15 15"/></svg>Export PDF</button>}
                    <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                  </div>
                </>)}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Timestomping Detector Modal */}
      {modal?.type === "timestomping" && ct && (() => {
        const { data, loading } = modal;

        const sevColors = { critical: th.danger || "#f85149", high: th.warning || "#E85D2A", medium: "#d29922", low: th.textMuted || "#9a9590" };
        const sevLabels = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

        const fmtDelta = (h) => {
          if (!h || h <= 0) return "< 1h";
          if (h < 24) return `${h.toFixed(1)}h`;
          if (h < 8760) return `${(h / 24).toFixed(1)}d`;
          return `${(h / 8760).toFixed(1)}y`;
        };

        const rowStyle = (i) => ({
          display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 11,
          background: i % 2 === 0 ? "transparent" : `${th.border}15`,
          borderBottom: `1px solid ${th.border}22`, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace",
        });

        const cbStyle = (checked) => ({
          width: 14, height: 14, borderRadius: 4, flexShrink: 0, cursor: "pointer",
          background: checked ? (th.accent) : "transparent",
          border: `1.5px solid ${checked ? th.accent : th.border}`,
          display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s",
        });

        const toggleSet = (key, idx) => setModal((p) => {
          if (!p) return p;
          const s = new Set(p[key]); s.has(idx) ? s.delete(idx) : s.add(idx); return { ...p, [key]: s };
        });

        const toggleAll = (key, count) => setModal((p) => {
          if (!p) return p;
          const cur = p[key] || new Set();
          return { ...p, [key]: cur.size === count ? new Set() : new Set(Array.from({ length: count }, (_, i) => i)) };
        });

        const copyReport = () => {
          if (!data) return;
          const d = data;
          const lines = [
            "=== Timestomp Indicator Report ===",
            `Potential Indicators: ${(d.totalTimestomped || 0).toLocaleString()} kept from ${(d.rawSiFnCount || 0).toLocaleString()} raw SI<FN hits (${(d.suppressedCount || 0).toLocaleString()} suppressed)`,
            `High Confidence: ${d.highConfidenceCount || 0}`,
            `Likely: ${d.likelyCount || 0}`,
            `Context / Low Confidence: ${d.contextCount || 0}`,
            `Critical Severity: ${d.criticalCount || 0}`,
            `High Severity: ${d.highCount || 0}`,
            `Medium Severity: ${d.mediumCount || 0}`,
            `Low Severity: ${d.lowCount || 0}`, "",
          ];
          if (d.criticalCount > 0) {
            lines.push("Critical Files:");
            d.files.filter((f) => f.severity === "critical").forEach((f) => lines.push(`  ${f.fileName} — ${f.parentPath} — Delta: ${fmtDelta(f.maxDeltaHours)}`));
            lines.push("");
          }
          lines.push("Top Directories:");
          (d.topDirectories || []).slice(0, 10).forEach((dir) => lines.push(`  ${dir.path || "(root)"} (${dir.count} files)`));
          lines.push("", "Extension Breakdown:");
          (d.extensionBreakdown || []).slice(0, 10).forEach((e) => lines.push(`  ${e.extension || "(none)"}: ${e.count}`));
          navigator.clipboard?.writeText(lines.join("\n"));
        };

        const copySelected = () => {
          const selFiles = modal.tsSelFiles || new Set();
          const selDirs = modal.tsSelDirs || new Set();
          const lines = [];
          if (selFiles.size > 0 && data?.files) {
            lines.push("=== Potential Timestomp Indicators ===");
            lines.push("Severity\tConfidence\tFileName\tExtension\tParentPath\tSI Created\tFN Created\tDelta\tIndicators");
            data.files.forEach((f, i) => { if (selFiles.has(i)) lines.push(`${f.severity}\t${f.confidence}\t${f.fileName}\t${f.extension}\t${f.parentPath}\t${(f.siCreated || "").slice(0, 19)}\t${(f.fnCreated || "").slice(0, 19)}\t${fmtDelta(f.maxDeltaHours)}\t${(f.indicators || []).join(", ")}`); });
            lines.push("");
          }
          if (selDirs.size > 0 && data?.topDirectories) {
            lines.push("=== Top Directories ===");
            data.topDirectories.forEach((d, i) => { if (selDirs.has(i)) lines.push(`${d.path || "(root)"}\t${d.count}`); });
          }
          if (lines.length > 0) navigator.clipboard?.writeText(lines.join("\n"));
        };

        const totalSelected = ((modal.tsSelFiles || new Set()).size + (modal.tsSelDirs || new Set()).size);

        const defW = 940, defH = Math.round(window.innerHeight * 0.88);
        const rw = modal.rwW || defW, rh = modal.rwH || defH;
        const rx = modal.rwX ?? Math.round((window.innerWidth - rw) / 2);
        const ry = modal.rwY ?? Math.round((window.innerHeight - rh) / 2);

        const startDrag = (e) => {
          e.preventDefault();
          const sx = e.clientX - rx, sy = e.clientY - ry;
          const onMove = (ev) => setModal((p) => p ? { ...p, rwX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), rwY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p);
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const startResize = (e, edge) => {
          e.preventDefault(); e.stopPropagation();
          const sx = e.clientX, sy = e.clientY, sw = rw, sh = rh, sleft = rx, stop = ry;
          const onMove = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            setModal((p) => {
              if (!p) return p;
              let nw = sw, nh = sh, nx = sleft, ny = stop;
              if (edge.includes("r")) nw = Math.max(420, sw + dx);
              if (edge.includes("b")) nh = Math.max(280, sh + dy);
              if (edge.includes("l")) { nw = Math.max(420, sw - dx); nx = sleft + sw - nw; }
              if (edge.includes("t")) { nh = Math.max(280, sh - dy); ny = stop + sh - nh; }
              return { ...p, rwW: nw, rwH: nh, rwX: nx, rwY: ny };
            });
          };
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const edgeStyle = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

        // Resizable column helpers
        const defTsW = [10, 180, 50, 240, 80, 140, 140, 55];
        const tsW = modal.tsColW || defTsW;
        const startColResize = (stateKey, defaults, colIdx, e) => {
          e.preventDefault(); e.stopPropagation();
          const startX = e.clientX, startW = (modal[stateKey] || defaults)[colIdx];
          const onMove = (ev) => setModal((p) => { if (!p) return p; const w = [...(p[stateKey] || defaults)]; w[colIdx] = Math.max(30, startW + (ev.clientX - startX)); return { ...p, [stateKey]: w }; });
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };
        const resH = { position: "absolute", right: -2, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 };

        // Sort helpers for Timestomping
        const handleTsSort = (colKey) => setModal((p) => {
          if (!p) return p;
          const cur = p.tsSort;
          const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
          return { ...p, tsSort: { col: colKey, dir: newDir } };
        });
        const sortTsArr = (arr) => {
          const s = modal.tsSort;
          if (!s || !arr) return arr;
          return [...arr].sort((a, b) => {
            const va = (a[s.col] || "").toString().toLowerCase();
            const vb = (b[s.col] || "").toString().toLowerCase();
            return s.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
          });
        };
        const tsSort = modal.tsSort;
        const tsSortArrow = (colKey) => {
          const active = tsSort?.col === colKey; const dir = active ? tsSort.dir : null;
          return (
            <svg width="8" height="10" viewBox="0 0 8 10" style={{ marginLeft: 3, flexShrink: 0, opacity: active ? 1 : 0.25, transition: "opacity 0.15s" }}>
              <path d="M4 1L7 4H1Z" fill={dir === "asc" ? (th.accent) : th.textMuted} opacity={dir === "asc" ? 1 : 0.4} />
              <path d="M4 9L1 6H7Z" fill={dir === "desc" ? (th.accent) : th.textMuted} opacity={dir === "desc" ? 1 : 0.4} />
            </svg>
          );
        };
        const tsHdrCol = (w, label, colKey, colIdx) => (
          <div style={{ width: w, flexShrink: 0, position: "relative", cursor: "pointer", display: "flex", alignItems: "center", userSelect: "none" }} onClick={() => handleTsSort(colKey)}>
            {label}{tsSortArrow(colKey)}
            <div onMouseDown={(e) => { e.stopPropagation(); startColResize("tsColW", defTsW, colIdx, e); }} style={resH} />
          </div>
        );

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, zIndex: 100, backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)", WebkitAppRegion: "no-drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "absolute", left: rx, top: ry, width: rw, height: rh, background: th.modalBg + "f2", border: `1px solid ${th.modalBorder}88`, borderRadius: 14, padding: 0, display: "flex", flexDirection: "column", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)" }}>
              {/* Resize handles */}
              <div onMouseDown={(e) => startResize(e, "t")} style={edgeStyle("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "b")} style={edgeStyle("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "l")} style={edgeStyle("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "r")} style={edgeStyle("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "tl")} style={edgeStyle("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "tr")} style={edgeStyle("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "bl")} style={edgeStyle("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "br")} style={edgeStyle("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

              {/* Header */}
              <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.warning || "#E85D2A"}33, ${th.warning || "#E85D2A"}11)`, border: `1px solid ${th.warning || "#E85D2A"}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.warning || "#E85D2A"} strokeWidth="1.8" strokeLinecap="round"><circle cx="12" cy="12" r="10" fill={(th.warning || "#E85D2A") + "18"}/><polyline points="12 6 12 12 16 14"/><circle cx="19" cy="5" r="2" fill={th.danger || "#f85149"} stroke="none"/></svg>
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.01em" }}>Timestomp Indicator Review</h3>
                    <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Score likely timestomp indicators from SI &lt; FN plus NTFS confidence heuristics</p>
                  </div>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, fontSize: 18, cursor: "pointer", padding: "4px 8px", lineHeight: 1 }}>{"\u2715"}</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {loading && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                    <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.warning || "#E85D2A"}33, ${th.warning || "#E85D2A"}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <div style={{ width: 20, height: 20, border: `2px solid ${th.warning || "#E85D2A"}`, borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                    </div>
                    <span style={{ color: th.textDim, fontSize: 13, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Scoring timestomp indicators...</span>
                  </div>
                )}

                {!loading && data && data.error && (
                  <div style={{ textAlign: "center", padding: 40, color: th.danger || "#f85149", fontSize: 13 }}>{data.error}</div>
                )}

                {!loading && data && !data.error && data.totalTimestomped === 0 && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12 }}>
                    <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.success || "#4ade80"}33, ${th.success || "#4ade80"}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.success || "#4ade80"} strokeWidth="2" strokeLinecap="round"><path d="M20 6L9 17l-5-5"/></svg>
                    </div>
                    <span style={{ color: th.textDim, fontSize: 13, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>No high-confidence timestomp indicators detected</span>
                  </div>
                )}

                {!loading && data && !data.error && data.totalTimestomped > 0 && (() => {
                  const d = data;
                  const files = d.files || [];
                  const selFiles = modal.tsSelFiles || new Set();
                  const selDirs = modal.tsSelDirs || new Set();

                  return (<>
                    {/* Summary cards */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                      {[
                        { label: "Potential Indicators", value: d.totalTimestomped.toLocaleString(), sub: `${d.rawSiFnCount.toLocaleString()} raw SI<FN · ${d.suppressedCount.toLocaleString()} suppressed`, color: th.warning || "#E85D2A" },
                        { label: "High Confidence", value: d.highConfidenceCount.toLocaleString(), sub: "Stacked indicators + suspicious context", color: th.danger || "#f85149" },
                        { label: "Likely", value: d.likelyCount.toLocaleString(), sub: "Strong timestamp mismatch patterns", color: th.warning || "#E85D2A" },
                        { label: "Context", value: d.contextCount.toLocaleString(), sub: "Weak / lower-confidence indicators", color: th.textDim },
                      ].map((c, i) => (
                        <div key={i} style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                          <div style={{ fontSize: 10, color: c.color, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{c.label}</div>
                          <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.02em" }}>{c.value}</div>
                          <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{c.sub}</div>
                        </div>
                      ))}
                    </div>

                    {/* Severity distribution bar */}
                    <div style={{ padding: "10px 14px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16 }}>
                      <div style={{ fontSize: 10, color: th.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Severity Distribution</div>
                      <div style={{ display: "flex", height: 18, borderRadius: 6, overflow: "hidden", border: `1px solid ${th.border}33` }}>
                        {[
                          { count: d.criticalCount, color: sevColors.critical, label: "Critical" },
                          { count: d.highCount, color: sevColors.high, label: "High" },
                          { count: d.mediumCount, color: sevColors.medium, label: "Medium" },
                          { count: d.lowCount, color: sevColors.low, label: "Low" },
                        ].filter((s) => s.count > 0).map((s, i) => (
                          <div key={i} title={`${s.label}: ${s.count}`} style={{ flex: s.count, background: `linear-gradient(180deg, ${s.color}cc, ${s.color}88)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 600, color: "#fff", textShadow: "0 1px 2px rgba(0,0,0,0.4)", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                            {s.count > 0 && d.totalTimestomped > 0 && (s.count / d.totalTimestomped * 100) >= 8 ? `${s.label} ${s.count}` : ""}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Detailed files table */}
                    <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <div onClick={() => toggleAll("tsSelFiles", files.length)} style={cbStyle(selFiles.size === files.length && files.length > 0)}>
                            {selFiles.size === files.length && files.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                          </div>
                          <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Potential Timestomp Indicators ({files.length.toLocaleString()}{d.totalTimestomped > files.length ? ` of ${d.totalTimestomped.toLocaleString()}` : ""})</span>
                        </div>
                      </div>
                      <div style={{ maxHeight: 320, overflow: "auto" }}>
                        {/* Header row */}
                        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                          <div style={{ width: 14, flexShrink: 0 }} />
                          {tsHdrCol(tsW[0], "Sev", "severity", 0)}
                          {tsHdrCol(tsW[1], "FileName", "fileName", 1)}
                          {tsHdrCol(tsW[2], "Ext", "extension", 2)}
                          {tsHdrCol(tsW[3], "ParentPath", "parentPath", 3)}
                          {tsHdrCol(tsW[4], "Stomped", "stompedFields", 4)}
                          {tsHdrCol(tsW[5], "SI Created (fake)", "siCreated", 5)}
                          {tsHdrCol(tsW[6], "FN Created (real)", "fnCreated", 6)}
                          {tsHdrCol(tsW[7], "Delta", "maxDeltaHours", 7)}
                        </div>
                        {sortTsArr(files).map((f, i) => (
                          <div key={i} onClick={() => toggleSet("tsSelFiles", i)} style={{ ...rowStyle(i), cursor: "pointer", background: f.severity === "critical" ? `${sevColors.critical}11` : i % 2 === 0 ? "transparent" : `${th.border}15`, minWidth: "fit-content" }}>
                            <div style={cbStyle(selFiles.has(i))}>
                              {selFiles.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                            </div>
                            <div style={{ width: tsW[0], height: 10, borderRadius: "50%", background: sevColors[f.severity] || sevColors.low, flexShrink: 0 }} title={sevLabels[f.severity]} />
                            <div style={{ width: tsW[1], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: f.severity === "critical" ? (th.danger || "#f85149") : th.text }} title={f.fileName}>{f.fileName}</div>
                            <div style={{ width: tsW[2], flexShrink: 0, color: th.textDim }} title={f.extension}>{f.extension}</div>
                            <div style={{ width: tsW[3], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                            <div style={{ width: tsW[4], flexShrink: 0, display: "flex", gap: 3, flexWrap: "wrap" }}>
                              {(f.stompedFields || []).map((sf) => (
                                <span key={sf} style={{ fontSize: 8, padding: "1px 4px", borderRadius: 3, background: `${sevColors[f.severity]}22`, color: sevColors[f.severity], fontWeight: 600, whiteSpace: "nowrap" }}>{sf.slice(0, 3)}</span>
                              ))}
                            </div>
                            <div style={{ width: tsW[5], flexShrink: 0, color: th.danger || "#f85149", fontSize: 10 }} title={f.siCreated}>{(f.siCreated || "").slice(0, 19)}</div>
                            <div style={{ width: tsW[6], flexShrink: 0, color: th.success || "#4ade80", fontSize: 10 }} title={f.fnCreated}>{(f.fnCreated || "").slice(0, 19)}</div>
                            <div style={{ width: tsW[7], flexShrink: 0, fontWeight: 600, color: f.maxDeltaHours > 8760 ? sevColors.high : f.maxDeltaHours > 720 ? sevColors.medium : th.textDim }}>{fmtDelta(f.maxDeltaHours)}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Top Directories + Extension Breakdown side by side */}
                    <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                      {/* Top Directories */}
                      <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div onClick={() => toggleAll("tsSelDirs", (d.topDirectories || []).length)} style={cbStyle(selDirs.size === (d.topDirectories || []).length && (d.topDirectories || []).length > 0)}>
                              {selDirs.size === (d.topDirectories || []).length && (d.topDirectories || []).length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                            </div>
                            <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Top Directories</span>
                          </div>
                        </div>
                        <div style={{ maxHeight: 200, overflow: "auto", padding: "4px 0" }}>
                          {(d.topDirectories || []).map((dir, i) => {
                            const maxC = (d.topDirectories || [])[0]?.count || 1;
                            return (
                              <div key={i} onClick={() => toggleSet("tsSelDirs", i)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 12px", cursor: "pointer", fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                <div style={cbStyle(selDirs.has(i))}>
                                  {selDirs.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                                </div>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 2 }}>
                                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={dir.path}>{dir.path || "(root)"}</span>
                                    <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: `${th.warning || "#E85D2A"}22`, color: th.warning || "#E85D2A", fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{dir.count}</span>
                                  </div>
                                  <div style={{ height: 4, borderRadius: 2, background: `${th.border}33`, overflow: "hidden" }}>
                                    <div style={{ width: `${(dir.count / maxC) * 100}%`, height: "100%", borderRadius: 2, background: `linear-gradient(90deg, ${th.warning || "#E85D2A"}88, ${th.warning || "#E85D2A"}44)` }} />
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      {/* Extension Breakdown */}
                      <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                        <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Extension Breakdown</span>
                        </div>
                        <div style={{ maxHeight: 200, overflow: "auto", padding: "4px 0" }}>
                          {(d.extensionBreakdown || []).map((eb, i) => {
                            const maxC = (d.extensionBreakdown || [])[0]?.count || 1;
                            const isExec = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".sys",".drv"].includes((eb.extension || "").toLowerCase());
                            return (
                              <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 12px", fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 2 }}>
                                    <span style={{ color: isExec ? (th.danger || "#f85149") : th.text, fontWeight: isExec ? 600 : 400 }}>{eb.extension || "(none)"}</span>
                                    <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: isExec ? `${th.danger || "#f85149"}22` : `${th.accent}22`, color: isExec ? (th.danger || "#f85149") : th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{eb.count}</span>
                                  </div>
                                  <div style={{ height: 4, borderRadius: 2, background: `${th.border}33`, overflow: "hidden" }}>
                                    <div style={{ width: `${(eb.count / maxC) * 100}%`, height: "100%", borderRadius: 2, background: isExec ? `linear-gradient(90deg, ${th.danger || "#f85149"}88, ${th.danger || "#f85149"}44)` : `linear-gradient(90deg, ${th.accent}88, ${th.accent}44)` }} />
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </>);
                })()}
              </div>

              {/* Footer */}
              {!loading && data && !data.error && (
                <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", gap: 10, justifyContent: "flex-end", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                  {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, position: "relative" }}>Copy Selected <span style={{ marginLeft: 4, fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}33`, color: th.accent }}>{totalSelected}</span></button>}
                  {data && data.totalTimestomped > 0 && <button onClick={copyReport} style={ms.bs}>Copy Summary</button>}
                  {data && data.totalTimestomped > 0 && <button onClick={async () => {
                    await tle.bulkTagFiltered(ct.id, "Timestomp Indicator", {
                      checkboxFilters: { EntryNumber: (data.files || []).map((f) => String(f.entryNumber)) },
                    });
                    setModal(null);
                  }} style={{ ...ms.bp, background: th.warning || "#E85D2A" }}>Tag Indicators</button>}
                  <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* File Activity Heatmap Modal */}
      {modal?.type === "heatmap" && ct && (() => {
        const { data, loading } = modal;

        const defW = 920, defH = Math.round(window.innerHeight * 0.88);
        const rw = modal.rwW || defW, rh = modal.rwH || defH;
        const rx = modal.rwX ?? Math.round((window.innerWidth - rw) / 2);
        const ry = modal.rwY ?? Math.round((window.innerHeight - rh) / 2);

        const startDrag = (e) => {
          e.preventDefault();
          const sx = e.clientX - rx, sy = e.clientY - ry;
          const onMove = (ev) => setModal((p) => p ? { ...p, rwX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), rwY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p);
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const startResize = (e, edge) => {
          e.preventDefault(); e.stopPropagation();
          const sx = e.clientX, sy = e.clientY, sw = rw, sh = rh, sleft = rx, stop = ry;
          const onMove = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            setModal((p) => {
              if (!p) return p;
              let nw = sw, nh = sh, nx = sleft, ny = stop;
              if (edge.includes("r")) nw = Math.max(420, sw + dx);
              if (edge.includes("b")) nh = Math.max(280, sh + dy);
              if (edge.includes("l")) { nw = Math.max(420, sw - dx); nx = sleft + sw - nw; }
              if (edge.includes("t")) { nh = Math.max(280, sh - dy); ny = stop + sh - nh; }
              return { ...p, rwW: nw, rwH: nh, rwX: nx, rwY: ny };
            });
          };
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const edgeStyle = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

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
        const applyHeatmapWindow = (window) => {
          if (!window?.column || !window?.from || !window?.to) return;
          // Reset any existing heatmap-related time filters to avoid over-constraining
          const existing = { ...(ct.dateRangeFilters || {}) };
          delete existing["Created0x10"];
          delete existing["LastModified0x10"];
          up("dateRangeFilters", { ...existing, [window.column]: { from: window.from, to: window.to } });
          setModal(null);
        };
        const tagHeatmapWindow = async (window) => {
          if (!window?.column || !window?.from || !window?.to) return;
          const tag = window.mode === "modified" ? "Modified Burst" : "Created Burst";
          const tagColor = window.mode === "modified" ? "#6cb6ff" : (th.accent || "#E85D2A");
          const result = await tle.bulkTagByTimeRange(ct.id, window.column, [{ from: window.from, to: window.to, tag }]);
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
          const lines = [
            "=== File Activity Heatmap ===",
            `Total Creations: ${(d.totalCreated || 0).toLocaleString()}`,
            `Total Modifications: ${(d.totalModified || 0).toLocaleString()}`,
            `Time Range: ${d.timeRange?.earliest || "N/A"} — ${d.timeRange?.latest || "N/A"}`,
            d.timeRange?.focusEarliest && d.timeRange?.focusLatest ? `Focus Range: ${d.timeRange.focusEarliest} — ${d.timeRange.focusLatest}` : null,
            `Bucket Size: ${d.bucketSize || "hourly"}`, "",
          ];
          if (d.peakCreated) lines.push(`Peak Created: ${d.peakCreated.bucket} (${d.peakCreated.count.toLocaleString()} files)`);
          if (d.peakModified) lines.push(`Peak Modified: ${d.peakModified.bucket} (${d.peakModified.count.toLocaleString()} files)`);
          if ((d.suspiciousWindows || []).length > 0) {
            lines.push("", "Suspicious Windows:");
            d.suspiciousWindows.slice(0, 10).forEach((w, i) => lines.push(`  ${i + 1}. ${w.bucket} [${w.mode}] score=${w.score} count=${w.count.toLocaleString()} ${w.weekend ? "weekend" : ""} ${w.offHours ? "off-hours" : ""}`.trim()));
          }
          if (reportTopPeriods.length > 0) {
            lines.push("", `Top ${modeLabel} Activity Periods:`);
            reportTopPeriods.forEach((p, i) => lines.push(`  ${i + 1}. ${p.bucket} (${p.count.toLocaleString()})`));
          }
          lines.push("", `Day-of-Week × Hour Activity (${modeLabel}):`);
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
          <div style={{ position: "fixed", inset: 0, background: th.overlay, zIndex: 100, backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)", WebkitAppRegion: "no-drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "absolute", left: rx, top: ry, width: rw, height: rh, background: th.modalBg + "f2", border: `1px solid ${th.modalBorder}88`, borderRadius: 14, padding: 0, display: "flex", flexDirection: "column", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)" }}>
              {/* Resize handles */}
              <div onMouseDown={(e) => startResize(e, "t")} style={edgeStyle("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "b")} style={edgeStyle("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "l")} style={edgeStyle("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "r")} style={edgeStyle("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "tl")} style={edgeStyle("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "tr")} style={edgeStyle("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "bl")} style={edgeStyle("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "br")} style={edgeStyle("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

              {/* Header */}
              <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, border: `1px solid ${th.accent}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round"><rect x="3" y="3" width="7" height="7" rx="1" fill={th.accent + "44"}/><rect x="14" y="3" width="7" height="7" rx="1" fill={th.accent + "22"}/><rect x="3" y="14" width="7" height="7" rx="1" fill={th.accent + "66"}/><rect x="14" y="14" width="7" height="7" rx="1" fill={th.accent + "88"}/></svg>
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.01em" }}>File Activity Heatmap</h3>
                    <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Visualize file creation and modification patterns over time</p>
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
                        <span style={{ color: th.textDim, fontSize: 13, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{detail}</span>
                        <div style={{ width: "100%", height: 6, borderRadius: 3, background: th.border + "44", overflow: "hidden" }}>
                          <div style={{ height: "100%", borderRadius: 3, background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`, width: `${pct}%`, transition: "width 0.4s ease" }} />
                        </div>
                        <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{pct}%</span>
                      </div>
                    </div>
                  );
                })()}

                {!loading && data && data.error && (
                  <div style={{ textAlign: "center", padding: 40, color: th.danger || "#f85149", fontSize: 13 }}>{data.error}</div>
                )}

                {!loading && data && !data.error && (() => {
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

                  // Merge buckets for chart
                  const allBuckets = new Map();
                  if (showCreated) (d.createdBuckets || []).forEach((b) => { const e = allBuckets.get(b.bucket) || { bucket: b.bucket, created: 0, modified: 0 }; e.created = b.count; allBuckets.set(b.bucket, e); });
                  if (showModified) (d.modifiedBuckets || []).forEach((b) => { const e = allBuckets.get(b.bucket) || { bucket: b.bucket, created: 0, modified: 0 }; e.modified = b.count; allBuckets.set(b.bucket, e); });
                  const rawChartData = Array.from(allBuckets.values()).sort((a, b) => a.bucket.localeCompare(b.bucket));
                  let chartData = rangeMode === "focus" && d.timeRange?.focusEarliest && d.timeRange?.focusLatest
                    ? rawChartData.filter((b) => bucketInRange(b.bucket, d.timeRange.focusEarliest, d.timeRange.focusLatest))
                    : rawChartData;
                  if (chartData.length === 0) chartData = rawChartData;

                  // Downsample if too many points
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

                  // DOW × Hour matrix — mode-aware with month filtering
                  const hmMonth = modal.hmMonth || "all";
                  const matrixData = getModeMatrixData(d, viewMode);
                  const allMatrix = matrixData.matrix || Array.from({ length: 7 }, () => new Array(24).fill(0));
                  const monthMap = matrixData.byMonth || {};
                  const availableMonths = Object.keys(monthMap).sort();
                  const matrix = hmMonth === "all" ? allMatrix : (monthMap[hmMonth] || Array.from({ length: 7 }, () => new Array(24).fill(0)));
                  const maxCell = Math.max(...matrix.flat(), 1);
                  // Z-score threshold for DOW×Hour cells — aligned with suspicious-window scoring
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
                  const describeWindow = (window) => {
                    if (!window) return [];
                    const notes = [];
                    if (window.weekend) notes.push("weekend");
                    if (window.offHours) notes.push("off-hours");
                    if ((window.riskyExtensionCount || 0) > 0) notes.push(`${window.riskyExtensionCount.toLocaleString()} risky files`);
                    if ((window.deletedCount || 0) > 0) notes.push(`${window.deletedCount.toLocaleString()} deleted`);
                    return notes;
                  };
                  const windowDetails = describeWindow(selectedWindow);

                  return (<>
                    {/* Summary cards */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                      <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        <div style={{ fontSize: 10, color: th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>File Creations</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{(d.totalCreated || 0).toLocaleString()}</div>
                        {d.peakCreated && <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Peak: {d.peakCreated.bucket} ({d.peakCreated.count.toLocaleString()})</div>}
                      </div>
                      <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        <div style={{ fontSize: 10, color: "#6cb6ff", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>File Modifications</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{(d.totalModified || 0).toLocaleString()}</div>
                        {d.peakModified && <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Peak: {d.peakModified.bucket} ({d.peakModified.count.toLocaleString()})</div>}
                      </div>
                      <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        <div style={{ fontSize: 10, color: th.textDim, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Full Span</div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{(d.timeRange?.earliest || "").slice(0, 10)}</div>
                        <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2 }}>to {(d.timeRange?.latest || "").slice(0, 10)} ({d.bucketSize} buckets)</div>
                      </div>
                      <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        <div style={{ fontSize: 10, color: th.warning || "#d29922", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Investigation Focus</div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{(d.timeRange?.focusEarliest || d.timeRange?.earliest || "").slice(0, 10)}</div>
                        <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2 }}>to {(d.timeRange?.focusLatest || d.timeRange?.latest || "").slice(0, 10)} ({(d.suspiciousWindows || []).length} suspicious windows)</div>
                      </div>
                    </div>

                    {/* Activity Timeline Chart */}
                    <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Activity Timeline</span>
                        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                          {(d.timeRange?.focusEarliest && d.timeRange?.focusLatest) && (
                            <div style={{ display: "flex", gap: 4 }}>
                              {["focus", "full"].map((m) => (
                                <button key={m} onClick={() => setModal((p) => p ? { ...p, hmRangeMode: m } : p)} style={{ padding: "3px 9px", fontSize: 10, fontWeight: 600, borderRadius: 6, border: `1px solid ${rangeMode === m ? (th.warning || "#d29922") : th.border}44`, background: rangeMode === m ? `${th.warning || "#d29922"}22` : "transparent", color: rangeMode === m ? (th.warning || "#d29922") : th.textMuted, cursor: "pointer", fontFamily: "'Segoe UI', system-ui, sans-serif", textTransform: "capitalize" }}>{m}</button>
                              ))}
                            </div>
                          )}
                          <div style={{ display: "flex", gap: 4 }}>
                          {["created", "modified", "both"].map((m) => (
                            <button key={m} onClick={() => setModal((p) => p ? { ...p, hmView: m } : p)} style={{ padding: "3px 10px", fontSize: 10, fontWeight: 600, borderRadius: 6, border: `1px solid ${viewMode === m ? th.accent : th.border}44`, background: viewMode === m ? `${th.accent}22` : "transparent", color: viewMode === m ? th.accent : th.textMuted, cursor: "pointer", fontFamily: "'Segoe UI', system-ui, sans-serif", textTransform: "capitalize" }}>{m}</button>
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
                                    // Cycle through matches on repeated clicks
                                    const curId = p.hmSelWin;
                                    const curIdx = bucketMatches.findIndex((w) => `${w.mode}:${w.bucket}` === curId);
                                    const next = curIdx >= 0 ? bucketMatches[(curIdx + 1) % bucketMatches.length] : topMatch;
                                    return { ...p, hmSelWin: `${next.mode}:${next.bucket}` };
                                  });
                                }) : undefined} style={{ cursor: hasMatch ? "pointer" : "default" }}>
                                  {showModified && modifiedH > 0 && <rect x={x} y={chartH - modifiedH - 2} width={Math.max(barW, 1)} height={modifiedH} fill="url(#hm-md)" rx="1"><title>{b.bucket} (UTC) — Modified: {b.modified.toLocaleString()}</title></rect>}
                                  {showCreated && createdH > 0 && <rect x={showModified ? x + barW + 1 : x} y={chartH - createdH - 2} width={Math.max(barW, 1)} height={createdH} fill="url(#hm-cr)" rx="1"><title>{b.bucket} (UTC) — Created: {b.created.toLocaleString()}</title></rect>}
                                  {hasMatch && <rect x={x - 1} y={2} width={showCreated && showModified ? Math.max(barW * 2 + 2, 4) : Math.max(barW + 2, 4)} height={chartH - 1} fill="none" stroke={th.warning || "#d29922"} strokeOpacity="0.35" strokeDasharray="2,2" rx="2" />}
                                </g>
                              );
                            })}
                            <line x1="5" y1={chartH} x2={chartW - 5} y2={chartH} stroke={th.border + "44"} strokeWidth="1" />
                            {axisLabels.map((l) => {
                              const x = (l.idx / chartData.length) * plotW + 5;
                              return (
                                <g key={l.idx}>
                                  <line x1={x} y1={chartH} x2={x} y2={chartH + 4} stroke={th.border + "66"} strokeWidth="1" />
                                  <text x={x} y={chartH + 15} fill={th.textMuted} fontSize="8" fontFamily="'Cascadia Code','Consolas','Courier New',monospace" textAnchor="middle">{l.label}</text>
                                </g>
                              );
                            })}
                            <text x={chartW - 5} y={chartH + 15} fill={th.textMuted + "88"} fontSize="7" fontFamily="'Segoe UI',system-ui,sans-serif" textAnchor="end">UTC</text>
                          </svg>
                        );
                      })()}
                    </div>

                    {/* Day-of-Week × Hour Heatmap */}
                    <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Day-of-Week x Hour {viewMode === "both" ? "Combined" : viewMode === "modified" ? "Modification" : "Creation"} Activity <span style={{ fontSize: 9, fontWeight: 500, color: th.textMuted }}>(UTC)</span></span>
                        {availableMonths.length > 1 && (
                          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            <button onClick={() => setModal((p) => p ? { ...p, hmMonth: "all" } : p)} style={{ padding: "3px 8px", fontSize: 9, fontWeight: 600, borderRadius: 5, border: `1px solid ${hmMonth === "all" ? th.accent : th.border}44`, background: hmMonth === "all" ? `${th.accent}22` : "transparent", color: hmMonth === "all" ? th.accent : th.textMuted, cursor: "pointer", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>All</button>
                            <select value={hmMonth === "all" ? "" : hmMonth} onChange={(e) => setModal((p) => p ? { ...p, hmMonth: e.target.value || "all" } : p)}
                              style={{ padding: "3px 22px 3px 6px", fontSize: 9, fontWeight: 600, borderRadius: 5, border: `1px solid ${hmMonth !== "all" ? th.accent : th.border}44`, background: hmMonth !== "all" ? `${th.accent}22` : "transparent", color: hmMonth !== "all" ? th.accent : th.textMuted, cursor: "pointer", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", appearance: "none", backgroundImage: `url("data:image/svg+xml,%3Csvg width='8' height='5' viewBox='0 0 8 5' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1l3 3 3-3' stroke='%23888' stroke-width='1.2' stroke-linecap='round'/%3E%3C/svg%3E")`, backgroundRepeat: "no-repeat", backgroundPosition: "right 6px center" }}>
                              <option value="">Select month...</option>
                              {availableMonths.map((m) => <option key={m} value={m}>{m}</option>)}
                            </select>
                          </div>
                        )}
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                        {/* Hour labels */}
                        <div style={{ display: "flex", gap: 2, paddingLeft: 40 }}>
                          {Array.from({ length: 24 }, (_, h) => (
                            <div key={h} style={{ width: 28, textAlign: "center", fontSize: 8, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{String(h).padStart(2, "0")}</div>
                          ))}
                        </div>
                        {/* Grid rows */}
                        {matrix.map((row, dow) => (
                          <div key={dow} style={{ display: "flex", alignItems: "center", gap: 2 }}>
                            <div style={{ width: 36, fontSize: 10, color: th.textDim, fontWeight: 500, textAlign: "right", paddingRight: 4, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{dayLabels[dow]}</div>
                            {row.map((count, hour) => {
                              const intensity = maxCell > 0 ? count / maxCell : 0;
                              const isWeekend = dow === 0 || dow === 6;
                              const isOffHours = hour < 6 || hour >= 22;
                              const cellZ = count > 0 ? (count - cellMed) / (1.4826 * cellMad) : 0;
                              const suspicious = (isWeekend || isOffHours) && cellZ >= cellZThreshold;
                              return (
                                <div key={hour} title={`${dayLabels[dow]} ${String(hour).padStart(2, "0")}:00 — ${count.toLocaleString()} files`} style={{ width: 28, height: 22, borderRadius: 3, background: count === 0 ? `${th.border}22` : suspicious ? `rgba(${(th.danger || "#f85149").slice(1).match(/../g).map((h) => parseInt(h, 16)).join(",")}, ${Math.max(0.15, intensity * 0.9)})` : `rgba(${(th.accent).slice(1).match(/../g).map((h) => parseInt(h, 16)).join(",")}, ${Math.max(0.08, intensity * 0.85)})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 8, color: intensity > 0.4 ? "#fff" : "transparent", fontWeight: 600, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", transition: "background 0.15s", cursor: "default" }}>
                                  {count > 0 && intensity > 0.3 ? (count > 999 ? `${(count/1000).toFixed(0)}k` : count) : ""}
                                </div>
                              );
                            })}
                          </div>
                        ))}
                      </div>
                      <div style={{ marginTop: 8, display: "flex", gap: 16, fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                        <span style={{ display: "flex", alignItems: "center", gap: 4 }}><div style={{ width: 10, height: 10, borderRadius: 2, background: `${th.accent}66` }} /> Normal activity</span>
                        <span style={{ display: "flex", alignItems: "center", gap: 4 }}><div style={{ width: 10, height: 10, borderRadius: 2, background: `${th.danger || "#f85149"}66` }} /> Weekend / off-hours concentration</span>
                      </div>
                    </div>

                    {/* Suspicious Windows */}
                    {suspiciousWindows.length > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
                          <div>
                            <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Suspicious Windows</div>
                            <div style={{ marginTop: 3, fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Ranked by statistical burst score, off-hours/weekend timing, risky extension ratio, and deletion rate.</div>
                          </div>
                          <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{suspiciousWindows.length} ranked {viewMode === "both" ? "windows" : `${viewMode} windows`}</div>
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: rw > 980 ? "minmax(0, 1.15fr) minmax(300px, 0.85fr)" : "1fr", gap: 12 }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 280, overflow: "auto", paddingRight: 2 }}>
                            {suspiciousWindows.map((window, idx) => {
                              const active = idx === suspiciousState.selectedIndex;
                              const notes = describeWindow(window);
                              return (
                                <button
                                  key={`${window.mode}-${window.bucket}-${idx}`}
                                  onClick={() => setModal((p) => p ? { ...p, hmSelWin: `${window.mode}:${window.bucket}` } : p)}
                                  style={{
                                    width: "100%",
                                    textAlign: "left",
                                    padding: "10px 12px",
                                    borderRadius: 9,
                                    border: `1px solid ${active ? (th.warning || "#d29922") : `${th.border}33`}`,
                                    background: active ? `${th.warning || "#d29922"}14` : `${th.border}10`,
                                    cursor: "pointer",
                                    transition: "all 0.12s",
                                  }}
                                >
                                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                                      <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: window.mode === "modified" ? "#6cb6ff" : th.accent, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{window.mode}</span>
                                      <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{window.bucket}</span>
                                    </div>
                                    <span style={{ fontSize: 10, fontWeight: 700, color: th.warning || "#d29922", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>score {window.score.toFixed(2)}</span>
                                  </div>
                                  <div style={{ marginTop: 5, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                                    <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{window.count.toLocaleString()} files</span>
                                    <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{notes.join(" • ") || "volume spike"}</span>
                                  </div>
                                </button>
                              );
                            })}
                          </div>
                          <div style={{ padding: "12px", borderRadius: 10, border: `1px solid ${th.border}33`, background: `${th.border}12`, minHeight: 220 }}>
                            {selectedWindow ? (
                              <>
                                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                                  <div>
                                    <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: selectedWindow.mode === "modified" ? "#6cb6ff" : th.accent, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{selectedWindow.mode} window</div>
                                    <div style={{ marginTop: 3, fontSize: 13, fontWeight: 700, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{selectedWindow.bucket}</div>
                                  </div>
                                  <div style={{ textAlign: "right" }}>
                                    <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Burst score</div>
                                    <div style={{ fontSize: 18, fontWeight: 700, color: th.warning || "#d29922", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{selectedWindow.score.toFixed(2)}</div>
                                  </div>
                                </div>
                                <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginBottom: 10 }}>
                                  <div style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22` }}>
                                    <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Window</div>
                                    <div style={{ fontSize: 10, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{selectedWindow.from?.slice(0, 19)} to {selectedWindow.to?.slice(0, 19)}</div>
                                  </div>
                                  <div style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22` }}>
                                    <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{selectedWindow.mode === "modified" ? "Modification Count" : "Creation Count"}</div>
                                    <div style={{ fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{selectedWindow.count.toLocaleString()}</div>
                                  </div>
                                  <div style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22` }}>
                                    <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Risky Extensions</div>
                                    <div style={{ fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{(selectedWindow.riskyExtensionCount || 0).toLocaleString()}</div>
                                  </div>
                                  <div style={{ padding: "8px 9px", borderRadius: 8, background: `${th.panelBg}77`, border: `1px solid ${th.border}22` }}>
                                    <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Deleted Files</div>
                                    <div style={{ fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{(selectedWindow.deletedCount || 0).toLocaleString()}</div>
                                  </div>
                                </div>
                                {windowDetails.length > 0 && (
                                  <div style={{ marginBottom: 10, display: "flex", flexWrap: "wrap", gap: 6 }}>
                                    {windowDetails.map((note, idx) => (
                                      <span key={`${note}-${idx}`} style={{ padding: "3px 7px", borderRadius: 999, fontSize: 9, fontWeight: 600, color: th.warning || "#d29922", background: `${th.warning || "#d29922"}18`, border: `1px solid ${th.warning || "#d29922"}33`, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{note}</span>
                                    ))}
                                  </div>
                                )}
                                <div style={{ marginBottom: 10 }}>
                                  <div style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 5 }}>Top Directories</div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                                    {(selectedWindow.topDirectories || []).length > 0 ? selectedWindow.topDirectories.map((dir, idx) => (
                                      <div key={`${dir.path || "(blank)"}-${idx}`} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, fontSize: 10, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                        <span style={{ color: th.text, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{dir.path || "(blank path)"}</span>
                                        <span style={{ color: th.accent, fontWeight: 700 }}>{dir.count.toLocaleString()}</span>
                                      </div>
                                    )) : <div style={{ fontSize: 10, color: th.textMuted }}>No path breakout available.</div>}
                                  </div>
                                </div>
                                <div style={{ marginBottom: 12 }}>
                                  <div style={{ fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 5 }}>Top Extensions</div>
                                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                                    {(selectedWindow.topExtensions || []).length > 0 ? selectedWindow.topExtensions.map((item, idx) => (
                                      <span key={`${item.ext}-${idx}`} style={{ padding: "4px 7px", borderRadius: 7, fontSize: 9, color: th.text, background: `${th.panelBg}88`, border: `1px solid ${th.border}22`, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{item.ext} ({item.count})</span>
                                    )) : <span style={{ fontSize: 10, color: th.textMuted }}>No extension breakout available.</span>}
                                  </div>
                                </div>
                                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                  <button onClick={() => applyHeatmapWindow(selectedWindow)} style={ms.bs}>Filter Grid to Window</button>
                                  <button onClick={() => tagHeatmapWindow(selectedWindow)} style={{ ...ms.bp, background: `${th.warning || "#d29922"}22`, color: th.warning || "#d29922", borderColor: `${th.warning || "#d29922"}44` }}>Tag Window</button>
                                  {(d.timeRange?.focusEarliest && d.timeRange?.focusLatest) && (
                                    <button onClick={() => setModal((p) => p ? { ...p, hmRangeMode: "focus" } : p)} style={ms.bs}>Use Focus View</button>
                                  )}
                                </div>
                              </>
                            ) : (
                              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", minHeight: 180, textAlign: "center", color: th.textMuted, fontSize: 12 }}>Select a suspicious window to inspect its path and extension context.</div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Top Activity Hours */}
                    {topPeriods.length > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 8 }}>
                          <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Top {modeTitle} Periods</div>
                          <div style={{ fontSize: 9, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Volume-ranked. Click a highlighted row to inspect its suspicious-window context.</div>
                        </div>
                        {topPeriods.map((h, i) => {
                          const maxH = topPeriods[0]?.count || 1;
                          const suspiciousMatches = suspiciousWindows.filter((window) => window.bucket === h.bucket);
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
                            }) : undefined} title={isSuspicious ? (suspiciousMatches.length > 1 ? "Click to cycle between created/modified windows" : "Inspect suspicious-window details") : `${periodRange.from} — ${periodRange.to}`} style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 0", fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", cursor: isSuspicious ? "pointer" : "default" }}>
                              <span style={{ width: 20, textAlign: "right", color: th.textMuted, fontSize: 10, fontWeight: 600 }}>{i + 1}</span>
                              <span style={{ width: 120, flexShrink: 0, color: th.text }}>{h.bucket}</span>
                              <div style={{ flex: 1, minWidth: 0, height: 14, borderRadius: 4, background: `${th.border}22`, overflow: "hidden" }}>
                                <div style={{ width: `${(h.count / maxH) * 100}%`, height: "100%", borderRadius: 4, background: isSuspicious ? `linear-gradient(90deg, ${th.warning || "#d29922"}aa, ${th.warning || "#d29922"}55)` : `linear-gradient(90deg, ${th.accent}88, ${th.accent}44)` }} />
                              </div>
                              <span style={{ width: 60, flexShrink: 0, textAlign: "right", fontSize: 10, color: th.accent, fontWeight: 600 }}>{h.count.toLocaleString()}</span>
                              {isSuspicious && <span style={{ padding: "2px 6px", borderRadius: 999, fontSize: 8, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", background: `${th.warning || "#d29922"}18`, color: th.warning || "#d29922", border: `1px solid ${th.warning || "#d29922"}33` }}>ranked</span>}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </>);
                })()}
              </div>

              {/* Footer */}
              {!loading && data && !data.error && (
                <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", gap: 10, justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                  <div style={{ minHeight: 18, fontSize: 10, color: modal.hmTagMsg ? (th.success || th.accent) : th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                    {modal.hmTagMsg || (footerSelectedWindow ? `Selected ${footerSelectedWindow.mode} window ${footerSelectedWindow.bucket}` : "Select a suspicious window to filter or tag the underlying rows.")}
                  </div>
                  <div style={{ display: "flex", gap: 10 }}>
                    {footerSelectedWindow && <button onClick={() => applyHeatmapWindow(footerSelectedWindow)} style={ms.bs}>Filter Grid</button>}
                    {footerSelectedWindow && <button onClick={() => tagHeatmapWindow(footerSelectedWindow)} style={{ ...ms.bs, color: th.warning || "#d29922", borderColor: `${th.warning || "#d29922"}55` }}>Tag Window</button>}
                    <button onClick={copyReport} style={ms.bs}>Copy Summary</button>
                    <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                  </div>
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* ADS Analyzer Modal */}
      {modal?.type === "ads" && ct && (() => {
        const { data, loading } = modal;

        const zoneColors = { Internet: th.danger || "#f85149", Intranet: "#6cb6ff", Trusted: th.success || "#4ade80", Local: th.textDim || "#9a9590", Restricted: th.warning || "#E85D2A" };

        const rowStyle = (i) => ({
          display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", fontSize: 11,
          background: i % 2 === 0 ? "transparent" : `${th.border}15`,
          borderBottom: `1px solid ${th.border}22`, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace",
        });

        const cbStyle = (checked) => ({
          width: 14, height: 14, borderRadius: 4, flexShrink: 0, cursor: "pointer",
          background: checked ? (th.accent) : "transparent",
          border: `1.5px solid ${checked ? th.accent : th.border}`,
          display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s",
        });

        const toggleSet = (key, idx) => setModal((p) => {
          if (!p) return p;
          const s = new Set(p[key]); s.has(idx) ? s.delete(idx) : s.add(idx); return { ...p, [key]: s };
        });

        const toggleAll = (key, count) => setModal((p) => {
          if (!p) return p;
          const cur = p[key] || new Set();
          return { ...p, [key]: cur.size === count ? new Set() : new Set(Array.from({ length: count }, (_, i) => i)) };
        });

        const copyReport = () => {
          if (!data) return;
          const d = data;
          const lines = [
            "=== ADS Analyzer Report ===",
            `Files with ADS: ${(d.totalWithAds || 0).toLocaleString()}`,
            `ADS Entries: ${(d.totalAdsEntries || 0).toLocaleString()}`,
            `Downloaded Files (Zone.Identifier): ${(d.totalWithZoneId || 0).toLocaleString()}`, "",
            ...(d.summary?.narrative ? [`Summary: ${d.summary.narrative}`, ""] : []),
            "Zone Breakdown:",
            `  Internet: ${d.zoneBreakdown?.internet || 0}`,
            `  Intranet: ${d.zoneBreakdown?.intranet || 0}`,
            `  Trusted: ${d.zoneBreakdown?.trusted || 0}`,
            `  Local: ${d.zoneBreakdown?.local || 0}`,
            `  Restricted: ${d.zoneBreakdown?.restricted || 0}`, "",
          ];
          if ((d.internalHosts || []).length > 0) {
            lines.push("Internal / Private Source Hosts:");
            d.internalHosts.slice(0, 10).forEach((h) => lines.push(`  ${h.host} (${h.count}) [${h.transferSource || "unknown"}]`));
            lines.push("");
          }
          if ((d.archiveLineage || []).length > 0) {
            lines.push("Archive Lineage:");
            d.archiveLineage.slice(0, 10).forEach((a) => lines.push(`  ${a.archiveName} -> ${a.childCount} child files (${a.motwLossCount} MOTW-loss)`));
            lines.push("");
          }
          if ((d.motwSuspicious || []).length > 0) {
            lines.push("Likely MOTW Loss:");
            d.motwSuspicious.slice(0, 15).forEach((m) => lines.push(`  ${m.archiveName} -> ${m.childName} (${m.reason})`));
            lines.push("");
          }
          if ((d.downloadedExecutables || []).length > 0) {
            lines.push("Downloaded Executables:");
            d.downloadedExecutables.forEach((f) => lines.push(`  ${f.fileName} — ${f.parentPath} — ${f.zoneName} — ${f.referrerUrl || "(no referrer)"}`));
            lines.push("");
          }
          if ((d.referrerUrls || []).length > 0) {
            lines.push("Top Referrer URLs:");
            d.referrerUrls.slice(0, 15).forEach((u) => lines.push(`  ${u.url} (${u.count})`));
            lines.push("");
          }
          if ((d.hostUrls || []).length > 0) {
            lines.push("Top Host URLs:");
            d.hostUrls.slice(0, 15).forEach((u) => lines.push(`  ${u.url} (${u.count})`));
          }
          navigator.clipboard?.writeText(lines.join("\n"));
        };

        const copySelected = () => {
          const selExec = modal.adSelExec || new Set();
          const selZone = modal.adSelZone || new Set();
          const selAds = modal.adSelAds || new Set();
          const lines = [];
          if (selExec.size > 0 && data?.downloadedExecutables) {
            lines.push("=== Downloaded Executables ===");
            lines.push("FileName\tExtension\tParentPath\tCreated\tZone\tReferrerUrl");
            data.downloadedExecutables.forEach((f, i) => { if (selExec.has(i)) lines.push(`${f.fileName}\t${f.extension}\t${f.parentPath}\t${(f.created || "").slice(0, 19)}\t${f.zoneName}\t${f.referrerUrl || ""}`); });
            lines.push("");
          }
          if (selZone.size > 0 && data?.zoneIdFiles) {
            lines.push("=== Zone.Identifier Files ===");
            lines.push("FileName\tExtension\tParentPath\tCreated\tZone\tReferrerUrl");
            data.zoneIdFiles.forEach((f, i) => { if (selZone.has(i)) lines.push(`${f.fileName}\t${f.extension}\t${f.parentPath}\t${(f.created || "").slice(0, 19)}\t${f.zoneName}\t${f.referrerUrl || ""}`); });
            lines.push("");
          }
          if (selAds.size > 0 && data?.adsEntries) {
            lines.push("=== ADS Entries ===");
            lines.push("FileName\tParentPath\tCreated\tFileSize");
            data.adsEntries.forEach((f, i) => { if (selAds.has(i)) lines.push(`${f.fileName}\t${f.parentPath}\t${(f.created || "").slice(0, 19)}\t${f.fileSize || ""}`); });
          }
          if (lines.length > 0) navigator.clipboard?.writeText(lines.join("\n"));
        };

        const totalSelected = ((modal.adSelExec || new Set()).size + (modal.adSelZone || new Set()).size + (modal.adSelAds || new Set()).size);

        const defW = 960, defH = Math.round(window.innerHeight * 0.88);
        const rw = modal.rwW || defW, rh = modal.rwH || defH;
        const rx = modal.rwX ?? Math.round((window.innerWidth - rw) / 2);
        const ry = modal.rwY ?? Math.round((window.innerHeight - rh) / 2);

        const startDrag = (e) => {
          e.preventDefault();
          const sx = e.clientX - rx, sy = e.clientY - ry;
          const onMove = (ev) => setModal((p) => p ? { ...p, rwX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), rwY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p);
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const startResize = (e, edge) => {
          e.preventDefault(); e.stopPropagation();
          const sx = e.clientX, sy = e.clientY, sw = rw, sh = rh, sleft = rx, stop = ry;
          const onMove = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            setModal((p) => {
              if (!p) return p;
              let nw = sw, nh = sh, nx = sleft, ny = stop;
              if (edge.includes("r")) nw = Math.max(420, sw + dx);
              if (edge.includes("b")) nh = Math.max(280, sh + dy);
              if (edge.includes("l")) { nw = Math.max(420, sw - dx); nx = sleft + sw - nw; }
              if (edge.includes("t")) { nh = Math.max(280, sh - dy); ny = stop + sh - nh; }
              return { ...p, rwW: nw, rwH: nh, rwX: nx, rwY: ny };
            });
          };
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const edgeStyle = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

        // Resizable column helpers
        const defExecW = [180, 50, 200, 140, 60, 220];
        const defZoneW = [180, 50, 200, 140, 60, 180];
        const defAdsW = [250, 280, 140, 80];
        const execW = modal.adExecColW || defExecW;
        const zoneW = modal.adZoneColW || defZoneW;
        const adsW = modal.adAdsColW || defAdsW;
        const startColResize = (stateKey, defaults, colIdx, e) => {
          e.preventDefault(); e.stopPropagation();
          const startX = e.clientX, startW = (modal[stateKey] || defaults)[colIdx];
          const onMove = (ev) => setModal((p) => { if (!p) return p; const w = [...(p[stateKey] || defaults)]; w[colIdx] = Math.max(30, startW + (ev.clientX - startX)); return { ...p, [stateKey]: w }; });
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };
        const resH = { position: "absolute", right: -2, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 };

        // Sort helpers for ADS tables
        const handleAdSort = (stateKey, colKey) => setModal((p) => {
          if (!p) return p;
          const cur = p[stateKey];
          const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
          return { ...p, [stateKey]: { col: colKey, dir: newDir } };
        });
        const sortAdArr = (arr, sortState) => {
          if (!sortState || !arr) return arr;
          return [...arr].sort((a, b) => {
            const va = (a[sortState.col] || "").toString().toLowerCase();
            const vb = (b[sortState.col] || "").toString().toLowerCase();
            return sortState.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
          });
        };
        const sortArrowAd = (stateKey, colKey) => {
          const s = modal[stateKey]; const active = s?.col === colKey; const dir = active ? s.dir : null;
          return (
            <svg width="10" height="14" viewBox="0 0 10 14" style={{ marginLeft: 4, flexShrink: 0, opacity: active ? 1 : 0.7, transition: "opacity 0.15s" }}>
              <path d="M5 1L9 5.5H1Z" fill={dir === "asc" ? (th.accent) : "#b0a8a0"} opacity={dir === "asc" ? 1 : 0.8} />
              <path d="M5 13L1 8.5H9Z" fill={dir === "desc" ? (th.accent) : "#b0a8a0"} opacity={dir === "desc" ? 1 : 0.8} />
            </svg>
          );
        };
        const adHdrCol = (w, label, stateKey, colKey, resizeKey, defW, colIdx) => (
          <div style={{ width: w, flexShrink: 0, position: "relative", cursor: "pointer", display: "flex", alignItems: "center", userSelect: "none" }} onClick={() => handleAdSort(stateKey, colKey)}>
            {label}{sortArrowAd(stateKey, colKey)}
            <div onMouseDown={(e) => { e.stopPropagation(); startColResize(resizeKey, defW, colIdx, e); }} style={resH} />
          </div>
        );

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, zIndex: 100, backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)", WebkitAppRegion: "no-drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "absolute", left: rx, top: ry, width: rw, height: rh, background: th.modalBg + "f2", border: `1px solid ${th.modalBorder}88`, borderRadius: 14, padding: 0, display: "flex", flexDirection: "column", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)" }}>
              {/* Resize handles */}
              <div onMouseDown={(e) => startResize(e, "t")} style={edgeStyle("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "b")} style={edgeStyle("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "l")} style={edgeStyle("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "r")} style={edgeStyle("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "tl")} style={edgeStyle("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "tr")} style={edgeStyle("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "bl")} style={edgeStyle("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "br")} style={edgeStyle("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

              {/* Header */}
              <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, border: `1px solid ${th.accent}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round"><rect x="4" y="4" width="16" height="16" rx="2" fill={th.accent + "18"}/><path d="M8 8h8"/><path d="M8 12h8" opacity="0.6"/><path d="M8 16h5" opacity="0.3"/></svg>
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.01em" }}>ADS Analyzer</h3>
                    <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Alternate Data Streams, Zone.Identifier, and download forensics</p>
                  </div>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, fontSize: 18, cursor: "pointer", padding: "4px 8px", lineHeight: 1 }}>{"\u2715"}</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {loading && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 16 }}>
                    <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <div style={{ width: 20, height: 20, border: `2px solid ${th.accent}`, borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                    </div>
                    <span style={{ color: th.textDim, fontSize: 13, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Analyzing Alternate Data Streams...</span>
                  </div>
                )}

                {!loading && data && data.error && (
                  <div style={{ textAlign: "center", padding: 40, color: th.danger || "#f85149", fontSize: 13 }}>{data.error}</div>
                )}

                {!loading && data && !data.error && data.totalWithAds === 0 && data.totalAdsEntries === 0 && data.totalWithZoneId === 0 && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12 }}>
                    <div style={{ width: 44, height: 44, borderRadius: 12, background: `linear-gradient(135deg, ${th.textDim}33, ${th.textDim}11)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6M9 12h4"/></svg>
                    </div>
                    <span style={{ color: th.textDim, fontSize: 13, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>No Alternate Data Streams found</span>
                  </div>
                )}

                {!loading && data && !data.error && (data.totalWithAds > 0 || data.totalAdsEntries > 0 || data.totalWithZoneId > 0) && (() => {
                  const d = data;
                  const selExec = modal.adSelExec || new Set();
                  const selZone = modal.adSelZone || new Set();
                  const selAds = modal.adSelAds || new Set();

                  const zb = d.zoneBreakdown || {};
                  const totalZoned = (zb.internet || 0) + (zb.intranet || 0) + (zb.trusted || 0) + (zb.local || 0) + (zb.restricted || 0);
                  const pill = (text, color = th.accent, bg = `${th.accent}22`) => (
                    <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 999, background: bg, color, fontWeight: 700, letterSpacing: "0.01em", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{text}</span>
                  );

                  return (<>
                    {/* Summary cards */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 16 }}>
                      <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        <div style={{ fontSize: 10, color: th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Files with ADS</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{(d.totalWithAds || 0).toLocaleString()}</div>
                      </div>
                      <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10 }}>
                        <div style={{ fontSize: 10, color: th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>ADS Entries</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{(d.totalAdsEntries || 0).toLocaleString()}</div>
                      </div>
                      <div style={{ padding: "14px 16px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${(d.totalWithZoneId || 0) > 0 ? (th.danger || "#f85149") : th.border}33`, borderRadius: 10 }}>
                        <div style={{ fontSize: 10, color: (d.totalWithZoneId || 0) > 0 ? (th.danger || "#f85149") : th.accent, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Downloaded Files</div>
                        <div style={{ fontSize: 22, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{(d.totalWithZoneId || 0).toLocaleString()}</div>
                        <div style={{ fontSize: 10, color: th.textMuted, marginTop: 3, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Zone.Identifier present</div>
                      </div>
                    </div>

                    {d.summary?.narrative && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.accent}33`, borderRadius: 10, padding: "14px 16px", marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 6 }}>
                          <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Download Forensics Summary</span>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                            {d.summary.execCount > 0 && pill(`${d.summary.execCount} exec/script`, th.danger || "#f85149", `${th.danger || "#f85149"}22`)}
                            {d.summary.archiveCount > 0 && pill(`${d.summary.archiveCount} archive`, th.warning || "#d29922", `${th.warning || "#d29922"}22`)}
                            {d.summary.motwLossCount > 0 && pill(`${d.summary.motwLossCount} MOTW loss`, th.danger || "#f85149", `${th.danger || "#f85149"}22`)}
                            {d.summary.internalHostCount > 0 && pill(`${d.summary.internalHostCount} internal host`, "#6cb6ff", "#6cb6ff22")}
                          </div>
                        </div>
                        <div style={{ fontSize: 12, color: th.text, lineHeight: 1.5, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{d.summary.narrative}</div>
                      </div>
                    )}

                    {(d.prioritizedDownloads || []).length > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.warning || "#d29922"}33`, borderRadius: 10, padding: "12px 14px", marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                          <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Prioritized Downloads</span>
                          <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>ranked by extension, location, source, and MOTW context</span>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {d.prioritizedDownloads.slice(0, 8).map((f, i) => (
                            <div key={i} style={{ padding: "8px 10px", borderRadius: 8, border: `1px solid ${th.border}22`, background: `${th.modalBg}55` }}>
                              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                                <div style={{ minWidth: 0, flex: 1 }}>
                                  <div style={{ fontSize: 12, fontWeight: 700, color: f.riskScore >= 4 ? (th.danger || "#f85149") : th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} title={f.fileName}>{f.fileName}</div>
                                  <div style={{ marginTop: 3, fontSize: 10, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} title={f.parentPath}>{f.parentPath}</div>
                                </div>
                                <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                                  {pill(`risk ${f.riskScore}`, f.riskScore >= 4 ? (th.danger || "#f85149") : (th.warning || "#d29922"), f.riskScore >= 4 ? `${th.danger || "#f85149"}22` : `${th.warning || "#d29922"}22`)}
                                  {f.zoneName && pill(f.zoneName, zoneColors[f.zoneName] || th.textDim, `${zoneColors[f.zoneName] || th.textDim}22`)}
                                  {f.transferSource && pill(f.transferSource, f.internalHost ? "#6cb6ff" : th.accent, f.internalHost ? "#6cb6ff22" : `${th.accent}22`)}
                                </div>
                              </div>
                              {(f.riskReasons || []).length > 0 && (
                                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
                                  {f.riskReasons.slice(0, 4).map((r, idx) => <Fragment key={idx}>{pill(r, th.text, `${th.border}33`)}</Fragment>)}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Zone Breakdown */}
                    {totalZoned > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, padding: "14px", marginBottom: 16 }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 10 }}>Zone Distribution</div>
                        <div style={{ display: "flex", height: 22, borderRadius: 6, overflow: "hidden", border: `1px solid ${th.border}33`, marginBottom: 10 }}>
                          {[
                            { label: "Internet", count: zb.internet || 0, color: zoneColors.Internet },
                            { label: "Intranet", count: zb.intranet || 0, color: zoneColors.Intranet },
                            { label: "Trusted", count: zb.trusted || 0, color: zoneColors.Trusted },
                            { label: "Local", count: zb.local || 0, color: zoneColors.Local },
                            { label: "Restricted", count: zb.restricted || 0, color: zoneColors.Restricted },
                          ].filter((z) => z.count > 0).map((z, i) => (
                            <div key={i} title={`${z.label}: ${z.count}`} style={{ flex: z.count, background: `linear-gradient(180deg, ${z.color}cc, ${z.color}88)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 600, color: "#fff", textShadow: "0 1px 2px rgba(0,0,0,0.4)", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                              {(z.count / totalZoned * 100) >= 10 ? `${z.label} ${z.count}` : ""}
                            </div>
                          ))}
                        </div>
                        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                          {[
                            { label: "Internet", count: zb.internet || 0, color: zoneColors.Internet },
                            { label: "Intranet", count: zb.intranet || 0, color: zoneColors.Intranet },
                            { label: "Trusted", count: zb.trusted || 0, color: zoneColors.Trusted },
                            { label: "Local", count: zb.local || 0, color: zoneColors.Local },
                            { label: "Restricted", count: zb.restricted || 0, color: zoneColors.Restricted },
                          ].map((z, i) => (
                            <span key={i} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10, color: th.textDim, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                              <div style={{ width: 8, height: 8, borderRadius: 2, background: z.color }} />
                              {z.label}: {z.count.toLocaleString()} ({totalZoned > 0 ? ((z.count / totalZoned) * 100).toFixed(1) : 0}%)
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Downloaded Executables */}
                    {(d.downloadedExecutables || []).length > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.danger || "#f85149"}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div onClick={() => toggleAll("adSelExec", d.downloadedExecutables.length)} style={cbStyle(selExec.size === d.downloadedExecutables.length && d.downloadedExecutables.length > 0)}>
                              {selExec.size === d.downloadedExecutables.length && d.downloadedExecutables.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                            </div>
                            <span style={{ fontSize: 11, fontWeight: 600, color: th.danger || "#f85149", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Downloaded Executables ({d.downloadedExecutables.length})</span>
                          </div>
                        </div>
                        <div style={{ maxHeight: 220, overflow: "auto" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                            <div style={{ width: 14, flexShrink: 0 }} />
                            {adHdrCol(execW[0], "FileName", "adSortExec", "fileName", "adExecColW", defExecW, 0)}
                            {adHdrCol(execW[1], "Ext", "adSortExec", "extension", "adExecColW", defExecW, 1)}
                            {adHdrCol(execW[2], "ParentPath", "adSortExec", "parentPath", "adExecColW", defExecW, 2)}
                            {adHdrCol(execW[3], "Created", "adSortExec", "created", "adExecColW", defExecW, 3)}
                            {adHdrCol(execW[4], "Zone", "adSortExec", "zoneName", "adExecColW", defExecW, 4)}
                            {adHdrCol(execW[5], "ReferrerUrl", "adSortExec", "referrerUrl", "adExecColW", defExecW, 5)}
                          </div>
                          {sortAdArr(d.downloadedExecutables, modal.adSortExec).map((f, i) => (
                            <div key={i} onClick={() => toggleSet("adSelExec", i)} style={{ ...rowStyle(i), cursor: "pointer", background: f.zone === 3 ? `${(th.danger || "#f85149")}0c` : i % 2 === 0 ? "transparent" : `${th.border}15`, minWidth: "fit-content" }}>
                              <div style={cbStyle(selExec.has(i))}>
                                {selExec.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                              </div>
                              <div style={{ width: execW[0], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.danger || "#f85149", fontWeight: 600 }} title={f.fileName}>{f.fileName}</div>
                              <div style={{ width: execW[1], flexShrink: 0, color: th.textDim }}>{f.extension}</div>
                              <div style={{ width: execW[2], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                              <div style={{ width: execW[3], flexShrink: 0, fontSize: 10, color: th.text }}>{(f.created || "").slice(0, 19)}</div>
                              <div style={{ width: execW[4], flexShrink: 0 }}>
                                <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 4, background: `${zoneColors[f.zoneName] || th.textDim}22`, color: zoneColors[f.zoneName] || th.textDim, fontWeight: 600 }}>{f.zoneName || "?"}</span>
                              </div>
                              <div style={{ width: execW[5], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim, fontSize: 10 }} title={f.referrerUrl}>{f.referrerUrl || ""}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Top Download Dirs + Referrer/Host URLs side by side */}
                    <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                      {/* Top Download Directories */}
                      {(d.topDownloadDirs || []).length > 0 && (
                        <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                          <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                            <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Top Download Directories</span>
                          </div>
                          <div style={{ maxHeight: 200, overflow: "auto", padding: "4px 0" }}>
                            {d.topDownloadDirs.map((dir, i) => {
                              const maxC = d.topDownloadDirs[0]?.count || 1;
                              return (
                                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 12px", fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                  <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 2 }}>
                                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={dir.path}>{dir.path || "(root)"}</span>
                                      <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{dir.count}</span>
                                    </div>
                                    <div style={{ height: 4, borderRadius: 2, background: `${th.border}33`, overflow: "hidden" }}>
                                      <div style={{ width: `${(dir.count / maxC) * 100}%`, height: "100%", borderRadius: 2, background: `linear-gradient(90deg, ${th.accent}88, ${th.accent}44)` }} />
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* Referrer / Host URLs */}
                      {((d.referrerUrls || []).length > 0 || (d.hostUrls || []).length > 0) && (
                        <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                          <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                            <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>URLs from Zone.Identifier</span>
                          </div>
                          <div style={{ maxHeight: 200, overflow: "auto", padding: "8px 12px" }}>
                            {(d.referrerUrls || []).length > 0 && (<>
                              <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Referrer URLs</div>
                              {d.referrerUrls.slice(0, 10).map((u, i) => (
                                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "2px 0", fontSize: 10, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={u.url}>{u.url}</span>
                                  <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{u.count}</span>
                                </div>
                              ))}
                            </>)}
                            {(d.hostUrls || []).length > 0 && (<>
                              <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginTop: 10, marginBottom: 4, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Host URLs</div>
                              {d.hostUrls.slice(0, 10).map((u, i) => (
                                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "2px 0", fontSize: 10, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flex: 1, minWidth: 0 }} title={u.url}>{u.url}</span>
                                  <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, flexShrink: 0, marginLeft: 8 }}>{u.count}</span>
                                </div>
                              ))}
                            </>)}
                          </div>
                        </div>
                      )}
                    </div>

                    {((d.internalHosts || []).length > 0 || (d.sourceClusters || []).length > 0) && (
                      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                        {(d.internalHosts || []).length > 0 && (
                          <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid #6cb6ff33`, borderRadius: 10, overflow: "hidden" }}>
                            <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: "#6cb6ff", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Internal / Private Source Hosts</span>
                            </div>
                            <div style={{ maxHeight: 190, overflow: "auto", padding: "8px 12px" }}>
                              {d.internalHosts.slice(0, 10).map((h, i) => (
                                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "4px 0", fontSize: 10, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>
                                  <span style={{ color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={h.host}>{h.host}</span>
                                  <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                                    {pill(h.transferSource || "network", "#6cb6ff", "#6cb6ff22")}
                                    {pill(String(h.count), th.text, `${th.border}33`)}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {(d.sourceClusters || []).length > 0 && (
                          <div style={{ flex: 1, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, overflow: "hidden" }}>
                            <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Source Clusters</span>
                            </div>
                            <div style={{ maxHeight: 190, overflow: "auto", padding: "8px 12px" }}>
                              {d.sourceClusters.slice(0, 8).map((c, i) => (
                                <div key={i} style={{ padding: "6px 0", borderBottom: i === d.sourceClusters.slice(0, 8).length - 1 ? "none" : `1px solid ${th.border}15` }}>
                                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                                    <span style={{ color: th.text, fontSize: 10, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} title={c.host}>{c.host}</span>
                                    <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                                      {pill(c.transferSource || "network", c.internal ? "#6cb6ff" : th.accent, c.internal ? "#6cb6ff22" : `${th.accent}22`)}
                                      {pill(`${c.count}`, th.text, `${th.border}33`)}
                                    </div>
                                  </div>
                                  {(c.sampleFiles || []).length > 0 && <div style={{ marginTop: 4, fontSize: 9, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} title={c.sampleFiles.join(", ")}>{c.sampleFiles.join(", ")}</div>}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {((d.archiveLineage || []).length > 0 || (d.motwSuspicious || []).length > 0) && (
                      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                        {(d.archiveLineage || []).length > 0 && (
                          <div style={{ flex: 1.2, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.warning || "#d29922"}33`, borderRadius: 10, overflow: "hidden" }}>
                            <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Archive / Extraction Lineage</span>
                            </div>
                            <div style={{ maxHeight: 240, overflow: "auto", padding: "8px 12px" }}>
                              {d.archiveLineage.slice(0, 8).map((a, i) => (
                                <div key={i} style={{ padding: "8px 0", borderBottom: i === d.archiveLineage.slice(0, 8).length - 1 ? "none" : `1px solid ${th.border}15` }}>
                                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                                    <span style={{ color: th.text, fontSize: 10, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} title={a.archiveName}>{a.archiveName}</span>
                                    <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                                      {pill(`${a.childCount} child`, th.text, `${th.border}33`)}
                                      {a.motwLossCount > 0 && pill(`${a.motwLossCount} MOTW loss`, th.danger || "#f85149", `${th.danger || "#f85149"}22`)}
                                    </div>
                                  </div>
                                  <div style={{ marginTop: 4, fontSize: 9, color: th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} title={a.archivePath}>{a.archivePath}</div>
                                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
                                    {a.children.slice(0, 5).map((c, idx) => <Fragment key={idx}>{pill(c.fileName, c.hasZoneId ? th.textDim : (th.warning || "#d29922"), c.hasZoneId ? `${th.border}22` : `${th.warning || "#d29922"}22`)}</Fragment>)}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {(d.motwSuspicious || []).length > 0 && (
                          <div style={{ flex: 0.8, minWidth: 0, background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.danger || "#f85149"}33`, borderRadius: 10, overflow: "hidden" }}>
                            <div style={{ padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: th.danger || "#f85149", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Possible MOTW Loss / Tamper</span>
                            </div>
                            <div style={{ maxHeight: 240, overflow: "auto", padding: "8px 12px" }}>
                              {d.motwSuspicious.slice(0, 10).map((m, i) => (
                                <div key={i} style={{ padding: "7px 0", borderBottom: i === d.motwSuspicious.slice(0, 10).length - 1 ? "none" : `1px solid ${th.border}15` }}>
                                  <div style={{ color: th.text, fontSize: 10, fontWeight: 700, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{m.childName}</div>
                                  <div style={{ marginTop: 3, color: th.textMuted, fontSize: 9, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{m.archiveName}</div>
                                  <div style={{ marginTop: 4, fontSize: 9, color: th.warning || "#d29922", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>{m.reason}</div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {(d.adsAnomalies || []).length > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.warning || "#d29922"}33`, borderRadius: 10, padding: "12px 14px", marginBottom: 16 }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                          <span style={{ fontSize: 11, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Non-Zone ADS Anomalies</span>
                          {pill(`${d.adsAnomalies.length}`, th.warning || "#d29922", `${th.warning || "#d29922"}22`)}
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                          {d.adsAnomalies.slice(0, 8).map((a, i) => <Fragment key={i}>{pill(a.streamName || a.fileName, a.execLike ? (th.danger || "#f85149") : (th.warning || "#d29922"), a.execLike ? `${th.danger || "#f85149"}22` : `${th.warning || "#d29922"}22`)}</Fragment>)}
                        </div>
                      </div>
                    )}

                    {/* Zone.Identifier Files */}
                    {(d.zoneIdFiles || []).length > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div onClick={() => toggleAll("adSelZone", d.zoneIdFiles.length)} style={cbStyle(selZone.size === d.zoneIdFiles.length && d.zoneIdFiles.length > 0)}>
                              {selZone.size === d.zoneIdFiles.length && d.zoneIdFiles.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                            </div>
                            <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>All Zone.Identifier Files ({d.zoneIdFiles.length.toLocaleString()}{d.totalWithZoneId > d.zoneIdFiles.length ? ` of ${d.totalWithZoneId.toLocaleString()}` : ""})</span>
                          </div>
                        </div>
                        <div style={{ maxHeight: 200, overflow: "auto" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                            <div style={{ width: 14, flexShrink: 0 }} />
                            {adHdrCol(zoneW[0], "FileName", "adSortZone", "fileName", "adZoneColW", defZoneW, 0)}
                            {adHdrCol(zoneW[1], "Ext", "adSortZone", "extension", "adZoneColW", defZoneW, 1)}
                            {adHdrCol(zoneW[2], "ParentPath", "adSortZone", "parentPath", "adZoneColW", defZoneW, 2)}
                            {adHdrCol(zoneW[3], "Created", "adSortZone", "created", "adZoneColW", defZoneW, 3)}
                            {adHdrCol(zoneW[4], "Zone", "adSortZone", "zoneName", "adZoneColW", defZoneW, 4)}
                            {adHdrCol(zoneW[5], "ReferrerUrl", "adSortZone", "referrerUrl", "adZoneColW", defZoneW, 5)}
                          </div>
                          {sortAdArr(d.zoneIdFiles, modal.adSortZone).map((f, i) => (
                            <div key={i} onClick={() => toggleSet("adSelZone", i)} style={{ ...rowStyle(i), cursor: "pointer", minWidth: "fit-content" }}>
                              <div style={cbStyle(selZone.has(i))}>
                                {selZone.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                              </div>
                              <div style={{ width: zoneW[0], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text }} title={f.fileName}>{f.fileName}</div>
                              <div style={{ width: zoneW[1], flexShrink: 0, color: th.textDim }}>{f.extension}</div>
                              <div style={{ width: zoneW[2], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                              <div style={{ width: zoneW[3], flexShrink: 0, fontSize: 10, color: th.text }}>{(f.created || "").slice(0, 19)}</div>
                              <div style={{ width: zoneW[4], flexShrink: 0 }}>
                                <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 4, background: `${zoneColors[f.zoneName] || th.textDim}22`, color: zoneColors[f.zoneName] || th.textDim, fontWeight: 600 }}>{f.zoneName || "?"}</span>
                              </div>
                              <div style={{ width: zoneW[5], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim, fontSize: 10 }} title={f.referrerUrl}>{f.referrerUrl || ""}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* ADS Entries */}
                    {(d.adsEntries || []).length > 0 && (
                      <div style={{ background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", border: `1px solid ${th.border}33`, borderRadius: 10, marginBottom: 16, overflow: "hidden" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 12px", borderBottom: `1px solid ${th.border}22` }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div onClick={() => toggleAll("adSelAds", d.adsEntries.length)} style={cbStyle(selAds.size === d.adsEntries.length && d.adsEntries.length > 0)}>
                              {selAds.size === d.adsEntries.length && d.adsEntries.length > 0 && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                            </div>
                            <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>ADS Entries ({d.adsEntries.length.toLocaleString()}{d.totalAdsEntries > d.adsEntries.length ? ` of ${d.totalAdsEntries.toLocaleString()}` : ""})</span>
                          </div>
                        </div>
                        <div style={{ maxHeight: 200, overflow: "auto" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.04em", borderBottom: `1px solid ${th.border}33`, fontFamily: "'Segoe UI', system-ui, sans-serif", position: "sticky", top: 0, background: th.modalBg, zIndex: 1, minWidth: "fit-content" }}>
                            <div style={{ width: 14, flexShrink: 0 }} />
                            {adHdrCol(adsW[0], "FileName", "adSortAds", "fileName", "adAdsColW", defAdsW, 0)}
                            {adHdrCol(adsW[1], "ParentPath", "adSortAds", "parentPath", "adAdsColW", defAdsW, 1)}
                            {adHdrCol(adsW[2], "Created", "adSortAds", "created", "adAdsColW", defAdsW, 2)}
                            {adHdrCol(adsW[3], "FileSize", "adSortAds", "fileSize", "adAdsColW", defAdsW, 3)}
                          </div>
                          {sortAdArr(d.adsEntries, modal.adSortAds).map((f, i) => (
                            <div key={i} onClick={() => toggleSet("adSelAds", i)} style={{ ...rowStyle(i), cursor: "pointer", minWidth: "fit-content" }}>
                              <div style={cbStyle(selAds.has(i))}>
                                {selAds.has(i) && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>}
                              </div>
                              <div style={{ width: adsW[0], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text }} title={f.fileName}>{f.fileName}</div>
                              <div style={{ width: adsW[1], flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }} title={f.parentPath}>{f.parentPath}</div>
                              <div style={{ width: adsW[2], flexShrink: 0, fontSize: 10, color: th.text }}>{(f.created || "").slice(0, 19)}</div>
                              <div style={{ width: adsW[3], flexShrink: 0, color: th.textDim }}>{f.fileSize || ""}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>);
                })()}
              </div>

              {/* Footer */}
              {!loading && data && !data.error && (
                <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", gap: 10, justifyContent: "flex-end", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                  {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, position: "relative" }}>Copy Selected <span style={{ marginLeft: 4, fontSize: 9, padding: "1px 5px", borderRadius: 8, background: `${th.accent}33`, color: th.accent }}>{totalSelected}</span></button>}
                  <button onClick={copyReport} style={ms.bs}>Copy Summary</button>
                  {(data.totalWithZoneId || 0) > 0 && <button onClick={async () => { await tle.bulkTagFiltered(ct.id, "Downloaded", { filters: [{ column: "ZoneIdContents", type: "not_empty" }] }); setModal(null); }} style={{ ...ms.bp, background: th.danger || "#f85149" }}>Tag Downloaded</button>}
                  <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* USN Journal Analysis Modal */}
      {modal?.type === "usnAnalysis" && ct && (() => {
        const { phase, data, loading, error } = modal;
        const usnResolveStats = ct?.sourceFormat === "raw-usnjrnl" ? (ct.usnResolveStats || null) : null;
        const usnResolveTone = (() => {
          if (!usnResolveStats) return null;
          const pct = Number(usnResolveStats.resolvedPercent || 0);
          if (pct >= 90) return { label: "High confidence", color: th.success || "#3fb950" };
          if (pct >= 60) return { label: "Partial coverage", color: th.warning || "#d29922" };
          return { label: "Low confidence", color: th.danger || "#f85149" };
        })();

        const handleAnalyze = async () => {
          if (!modal.startTime) return;
          setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
          try {
            const result = await tle.analyzeUsnJournal(
              ct.id,
              modal.startTime.trim(),
              modal.endTime.trim() || null,
              modal.analyses,
              modal.pathFilter.trim() || null,
              modal.mftTabId || null
            );
            if (result?.error) {
              setModal((p) => p?.type === "usnAnalysis" ? { ...p, phase: "input", loading: false, error: result.error } : p);
            } else {
              const nextExpanded = usnSections.reduce((acc, sec) => {
                acc[sec.key] = getUsnSectionCount(sec.key, result?.[sec.key]) > 0;
                return acc;
              }, {});
              setModal((p) => p?.type === "usnAnalysis" ? { ...p, phase: "results", loading: false, data: result, usnExpanded: nextExpanded, usnIncidentsExpanded: false, usnTimelineExpanded: false, usnLikelyFindingsExpanded: false, usnShowSuppressed: {} } : p);
            }
          } catch (e) {
            setModal((p) => p?.type === "usnAnalysis" ? { ...p, phase: "input", loading: false, error: e.message } : p);
          }
        };

        const toggleAnalysis = (key) => setModal((p) => p ? { ...p, analyses: { ...p.analyses, [key]: !p.analyses[key] } } : p);
        const toggleExpand = (key, canExpand = true) => {
          if (!canExpand) return;
          setModal((p) => p ? { ...p, usnExpanded: { ...p.usnExpanded, [key]: !p.usnExpanded[key] } } : p);
        };

        // Unit 42 warm monochrome palette — graduated from bright (critical) to muted (informational)
        const usnSections = [
          { key: "renames", label: "Rename Activity", desc: "Tracks old \u2192 new filename pairs \u2014 detects masquerading, staging, or anti-forensics", color: "#D4783A", icon: <><path d="M17 3a2.83 2.83 0 0 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></> },
          { key: "deletions", label: "Deletion Activity", desc: "Files removed from disk \u2014 evidence destruction, cleanup scripts, or ransomware traces", color: "#C44D1E", icon: <><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></> },
          { key: "creations", label: "File Creation", desc: "New files written to disk \u2014 payload drops, tool deployment, or lateral movement artifacts", color: "#E8A050", icon: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></> },
          { key: "exfil", label: "Data Exfiltration", desc: "Archive creation (zip/rar/7z) and staging directory activity \u2014 data collection before exfil", color: "#E85D2A", icon: <><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M12 12v4"/><path d="M9 15l3 3 3-3" fill="none"/></> },
          { key: "execution", label: "Execution Artifacts", desc: "Executable files created or modified (.exe, .dll, .ps1, .bat, etc.) \u2014 malware deployment", color: "#FF6B35", icon: <><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></> },
          { key: "persistence", label: "Persistence Paths", desc: "Startup folders, scheduled tasks, GPO scripts, and WMI MOF paths \u2014 filesystem foothold locations", color: "#D45A2A", icon: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></> },
          { key: "suspiciousPaths", label: "Suspicious Paths", desc: "Payload-like files or tampering in Temp, Public, Recycle Bin, ProgramData, Recovery, and media folders", color: "#C96B3C", icon: <><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></> },
          { key: "securityChanges", label: "Security Changes", desc: "NTFS permission modifications \u2014 bulk changes indicate archive extraction or ACL tampering", color: "#B85C38", icon: <><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></> },
          { key: "dataOverwrite", label: "Data Overwrite", desc: "File content modified or extended \u2014 ransomware encryption, config changes, or log tampering", color: "#E87848", icon: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><line x1="9" y1="13" x2="15" y2="13" strokeWidth="2.5"/></> },
          { key: "streamChanges", label: "Stream Changes", desc: "Alternate Data Stream modifications \u2014 Zone.Identifier updates, hidden data, or MOTW changes", color: "#D4956A", icon: <><path d="M4 4h16v16H4z" rx="2"/><path d="M8 8h8M8 12h5" opacity="0.6"/><circle cx="16" cy="16" r="2.5" fill="#D4956A" stroke="none"/></> },
          { key: "closePatterns", label: "Close Patterns", desc: "Files opened then closed without modification \u2014 recon, enumeration, or directory listing", color: "#C8A882", icon: <><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/></> },
        ];
        const getUsnSectionCount = (secKey, sectionData) => {
          if (!sectionData) return 0;
          if (secKey === "exfil") return Number(sectionData.archiveCount || sectionData.archives?.length || 0);
          return Number(sectionData.count || sectionData.events?.length || 0);
        };

        // ── Column definitions per section ──
        const hasCorrelation = !!data?.correlation;
        const hasReasons = (k) => ["execution", "persistence", "suspiciousPaths", "securityChanges", "exfil", "dataOverwrite", "streamChanges", "closePatterns"].includes(k);
        const mftCols = () => hasCorrelation ? [
          { key: "_mftStatus", label: "Status", w: 70, get: (ev) => { const m = ev._mft; if (!m) return "—"; const parts = []; if (m.matchMode === "exact") parts.push("EX"); else if (m.matchMode === "entry-only") parts.push("FB"); if (m.inUse === "False") parts.push("DEL"); if (m.siFn === "True") parts.push("TS"); if (m.zoneId?.trim()) parts.push("DL"); return parts.length > 0 ? parts.join("|") : "OK"; } },
          { key: "_mftSize", label: "Size", w: 72, get: (ev) => { const s = ev._mft?.fileSize; if (!s || s === "0") return ""; const n = parseInt(s, 10); if (isNaN(n)) return s; if (n < 1024) return n + " B"; if (n < 1048576) return (n / 1024).toFixed(1) + " KB"; if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB"; return (n / 1073741824).toFixed(2) + " GB"; } },
        ] : [];
        const getColumns = (secKey) => {
          if (secKey === "renames") return [
            { key: "timestamp", label: "Timestamp", w: 150, get: (ev) => (ev.timestamp || "").slice(0, 19) },
            { key: "oldName", label: "Old Name", flex: 1, get: (ev) => ev.oldName, color: th.danger || "#f85149" },
            { key: "arrow", label: "", w: 20, get: () => "→", noSort: true, noResize: true },
            { key: "newName", label: "New Name", flex: 1, get: (ev) => ev.newName, color: th.success || "#3fb950" },
            { key: "parentPath", label: "Parent Path", flex: 1.5, get: (ev) => ev.parentPath },
            ...mftCols(),
          ];
          const cols = [
            { key: "timestamp", label: "Timestamp", w: 150, get: (ev) => (ev.timestamp || "").slice(0, 19) },
            { key: "name", label: "Name", flex: 1, get: (ev) => ev.name },
          ];
          if (secKey !== "exfil") cols.push({ key: "extension", label: "Ext", w: 60, get: (ev) => ev.extension });
          if ((secKey === "persistence" || secKey === "suspiciousPaths") && (data?.[secKey]?.categories?.length > 0 || data?.[secKey]?.suppressedCount > 0)) {
            cols.push({ key: "heuristicCategory", label: "Class", w: 150, get: (ev) => ev.heuristicCategory || "" });
          }
          cols.push({ key: "parentPath", label: "Parent Path", flex: 1.5, get: (ev) => ev.parentPath });
          if (hasReasons(secKey)) cols.push({ key: "reasons", label: "Reasons", w: 140, get: (ev) => ev.reasons });
          if ((secKey === "persistence" || secKey === "suspiciousPaths") && (data?.[secKey]?.suppressedCount || 0) > 0 && !!modal?.usnShowSuppressed?.[secKey]) {
            cols.push({ key: "suppressionReason", label: "Suppressed", w: 180, get: (ev) => ev.suppressionReason || "" });
          }
          cols.push(...mftCols());
          return cols;
        };

        const copyReport = () => {
          if (!data) return;
          const lines = [
            "=== USN Journal Analysis ===",
            `Time Range: ${data.summary?.startTime || modal.startTime} to ${data.summary?.endTime || modal.endTime}`,
            data.summary?.pathFilter ? `Path Filter: ${data.summary.pathFilter}` : null,
            `Total Events in Window: ${(data.summary?.totalEvents || 0).toLocaleString()}`, "",
          ];
          if (data.narrative?.length > 0) {
            lines.push("--- Investigator Summary ---");
            data.narrative.forEach((n) => lines.push(`  - ${n}`));
            lines.push("");
          }
          if (data.likelyFindings?.length > 0) {
            lines.push(`--- Likely Intrusion Findings: ${data.likelyFindings.length} ---`);
            data.likelyFindings.slice(0, 10).forEach((finding, idx) => {
              lines.push(`  ${idx + 1}. [${String(finding.severity || "info").toUpperCase()}] ${finding.title}`);
              if (finding.summary) lines.push(`    ${finding.summary}`);
              if (finding.rationale) lines.push(`    Why: ${finding.rationale}`);
              if (finding.primaryPath || finding.path) lines.push(`    Path: ${finding.primaryPath || finding.path}`);
              if (finding.start || finding.end) lines.push(`    Time: ${(finding.start || "").slice(0, 19)} -> ${(finding.end || "").slice(0, 19)}`);
              if (finding.evidence?.length) lines.push(`    Evidence: ${finding.evidence.join(", ")}`);
            });
            lines.push("");
          }
          if (data.directoryIncidents?.length > 0) {
            lines.push(`--- Directory Incidents: ${data.directoryIncidents.length} ---`);
            data.directoryIncidents.slice(0, 20).forEach((inc) => {
              lines.push(`  ${inc.title}`);
              lines.push(`    ${inc.start?.slice(0, 19)} -> ${inc.end?.slice(0, 19)} | ${inc.eventCount} events | ${inc.uniqueFiles} files | ${inc.path}`);
              if (inc.reasons?.length) lines.push(`    Reasons: ${inc.reasons.join(", ")}`);
              if (inc.tags?.length) lines.push(`    Tags: ${inc.tags.join(", ")}`);
            });
            lines.push("");
          }
          if (data.timeline?.length > 0) {
            lines.push("--- Merged Storyline ---");
            data.timeline.slice(0, 50).forEach((ev) => lines.push(`  ${ev.timestamp?.slice(0, 19)}\t${ev.reasonLabel}\t${ev.displayName || ev.name}\t${ev.parentPath}${ev.tags?.length ? `\t[${ev.tags.join(", ")}]` : ""}`));
            lines.push("");
          }
          if (data.correlation) {
            const c = data.correlation;
            lines.push("--- MFT Cross-Artifact Correlation ---");
            lines.push(`  MFT Matched: ${c.matched} of ${c.totalUsnEntries} unique file refs`);
            if (c.exactMatched != null || c.fallbackMatched != null) {
              lines.push(`  Exact vs fallback: ${c.exactMatched || 0} exact, ${c.fallbackMatched || 0} entry-only`);
            }
            lines.push(`  Unmatched: ${c.unmatched}`);
            lines.push(`  Deleted Files (InUse=False): ${c.deleted}`);
            lines.push(`  Timestomped (SI<FN): ${c.timestomped}`);
            lines.push(`  Downloaded (Zone.Identifier): ${c.downloaded}`);
            lines.push("");
          }
          if (data.renames) {
            lines.push(`--- Rename Activity: ${data.renames.count} events ---`);
            data.renames.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.oldName} -> ${r.newName}\t${r.parentPath}`));
            lines.push("");
          }
          if (data.deletions) {
            lines.push(`--- Deletion Activity: ${data.deletions.count} events ---`);
            data.deletions.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}`));
            lines.push("");
          }
          if (data.creations) {
            lines.push(`--- File Creation: ${data.creations.count} events ---`);
            data.creations.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}`));
            lines.push("");
          }
          if (data.exfil) {
            lines.push(`--- Data Exfiltration: ${data.exfil.archiveCount} archives ---`);
            data.exfil.archives.slice(0, 50).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}`));
            if (data.exfil.stagingDirectories?.length > 0) {
              lines.push("  Staging Directories:");
              data.exfil.stagingDirectories.forEach((d) => lines.push(`    ${d.directory} (${d.fileCount} files)`));
            }
            lines.push("");
          }
          if (data.execution) {
            lines.push(`--- Execution Artifacts: ${data.execution.count} events ---`);
            data.execution.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
            lines.push("");
          }
          if (data.persistence) {
            lines.push(`--- Persistence Paths: ${data.persistence.count} events ---`);
            if (data.persistence.suppressedCount > 0) {
              const summary = (data.persistence.suppressionSummary || []).map((s) => `${s.label} (${s.count})`).join(", ");
              lines.push(`  Suppressed likely-benign rows: ${data.persistence.suppressedCount}${summary ? ` [${summary}]` : ""}`);
            }
            data.persistence.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
            lines.push("");
          }
          if (data.suspiciousPaths) {
            lines.push(`--- Suspicious Paths: ${data.suspiciousPaths.count} events ---`);
            if (data.suspiciousPaths.suppressedCount > 0) {
              const summary = (data.suspiciousPaths.suppressionSummary || []).map((s) => `${s.label} (${s.count})`).join(", ");
              lines.push(`  Suppressed likely-benign rows: ${data.suspiciousPaths.suppressedCount}${summary ? ` [${summary}]` : ""}`);
            }
            data.suspiciousPaths.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
            lines.push("");
          }
          if (data.securityChanges) {
            lines.push(`--- Security Changes: ${data.securityChanges.count} events ---`);
            if (data.securityChanges.directoryBreakdown?.length > 0) {
              lines.push("  Hotspot Directories:");
              data.securityChanges.directoryBreakdown.slice(0, 20).forEach((d) => lines.push(`    ${d.path} (${d.count} events, ${d.uniqueFiles} unique files)`));
            }
            data.securityChanges.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
            lines.push("");
          }
          if (data.dataOverwrite) {
            lines.push(`--- Data Overwrite: ${data.dataOverwrite.count} events ---`);
            if (data.dataOverwrite.extensionBreakdown?.length > 0) {
              lines.push("  Extension Breakdown:");
              data.dataOverwrite.extensionBreakdown.slice(0, 10).forEach((e) => lines.push(`    ${e.ext} (${e.count})`));
            }
            data.dataOverwrite.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
            lines.push("");
          }
          if (data.streamChanges) {
            lines.push(`--- Stream Changes: ${data.streamChanges.count} events ---`);
            data.streamChanges.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
            lines.push("");
          }
          if (data.closePatterns) {
            lines.push(`--- Close Patterns: ${data.closePatterns.count} events ---`);
            if (data.closePatterns.directoryBreakdown?.length > 0) {
              lines.push("  Enumeration Hotspots:");
              data.closePatterns.directoryBreakdown.slice(0, 10).forEach((d) => lines.push(`    ${d.path} (${d.count})`));
            }
            data.closePatterns.events.slice(0, 100).forEach((r) => lines.push(`  ${(r.timestamp || "").slice(0, 19)}\t${r.name}\t${r.parentPath}\t${r.reasons}`));
            lines.push("");
          }
          navigator.clipboard?.writeText(lines.filter((l) => l !== null).join("\n"));
        };

        // Draggable + resizable
        const defW = phase === "results" ? 960 : 560, defH = phase === "results" ? Math.round(window.innerHeight * 0.88) : 540;
        const uw = modal.usnW || defW, uh = modal.usnH || defH;
        const ux = modal.usnX ?? Math.round((window.innerWidth - uw) / 2);
        const uy = modal.usnY ?? Math.round((window.innerHeight - uh) / 2);
        const startDrag = (e) => { e.preventDefault(); const sx = e.clientX - ux, sy = e.clientY - uy; const onMove = (ev) => setModal((p) => p ? { ...p, usnX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), usnY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p); const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); }; window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp); };
        const startResize = (e, edge) => { e.preventDefault(); e.stopPropagation(); const sx = e.clientX, sy = e.clientY, sw = uw, sh = uh, sleft = ux, stop = uy; const onMove = (ev) => { const dx = ev.clientX - sx, dy = ev.clientY - sy; setModal((p) => { if (!p) return p; let nw = sw, nh = sh, nx = sleft, ny = stop; if (edge.includes("r")) nw = Math.max(480, sw + dx); if (edge.includes("b")) nh = Math.max(300, sh + dy); if (edge.includes("l")) { nw = Math.max(480, sw - dx); nx = sleft + sw - nw; } if (edge.includes("t")) { nh = Math.max(300, sh - dy); ny = stop + sh - nh; } return { ...p, usnW: nw, usnH: nh, usnX: nx, usnY: ny }; }); }; const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); }; window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp); };
        const uEdge = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

        // ── Selection helpers ──
        const totalSelected = Object.values(modal.usnSelected || {}).reduce((sum, s) => sum + (s?.size || 0), 0);
        const usnScopeDir = modal.usnScopeDir || "";
        const usnSiblingDir = modal.usnSiblingDir || "";
        const usnFocusEntry = modal.usnFocusEntry ? String(modal.usnFocusEntry) : "";
        const timelineIncidentKey = modal.usnTimelineIncident || "";
        const likelyFindings = data?.likelyFindings || [];
        const parseUsnTsMs = (v) => {
          if (!v) return NaN;
          const normalized = String(v).replace(" ", "T").replace(/(\.\d{3})\d+/, "$1");
          const ms = Date.parse(normalized);
          return Number.isFinite(ms) ? ms : NaN;
        };
        const parentDirOf = (p) => {
          const s = String(p || "").replace(/[\\\/]+$/, "");
          if (!s) return "";
          const idx = Math.max(s.lastIndexOf("\\"), s.lastIndexOf("/"));
          return idx > 0 ? s.slice(0, idx) : "";
        };
        const withinSiblingScope = (path) => {
          if (!usnSiblingDir) return true;
          const parent = parentDirOf(usnSiblingDir);
          const candidate = String(path || "");
          return !!parent && candidate.startsWith(parent) && candidate !== usnSiblingDir;
        };
        const getUsnSectionView = (secKey) => {
          const sData = data?.[secKey];
          if (!sData) return null;
          const count = getUsnSectionCount(secKey, sData);
          const rawEvents = secKey === "exfil" ? (sData.archives || []) : (sData.events || []);
          const canShowSuppressed = (secKey === "persistence" || secKey === "suspiciousPaths") && Number(sData.suppressedCount || 0) > 0;
          const showSuppressed = canShowSuppressed && !!modal.usnShowSuppressed?.[secKey];
          const suppressedEvents = canShowSuppressed
            ? (sData.suppressedEvents || []).map((ev, idx) => ({ ...ev, _suppressed: true, _suppressedKey: `${secKey}:suppressed:${idx}` }))
            : [];
          const sourceEvents = showSuppressed ? [...rawEvents, ...suppressedEvents] : rawEvents;
          const displayedCount = showSuppressed ? sourceEvents.length : count;
          const cols = getColumns(secKey);

          const sort = modal.usnSort?.[secKey];
          let events = sourceEvents;
          if (usnScopeDir) {
            events = events.filter((ev) => (ev.parentPath || "").startsWith(usnScopeDir));
          }
          if (usnSiblingDir) {
            events = events.filter((ev) => withinSiblingScope(ev.parentPath || ""));
          }
          if (usnFocusEntry) {
            events = events.filter((ev) => String(ev.entryNumber || "") === usnFocusEntry);
          }
          if (sort) {
            const colDef = cols.find((c) => c.key === sort.col);
            if (colDef) {
              events = [...events].sort((a, b) => {
                const va = (colDef.get(a) || "").toString().toLowerCase();
                const vb = (colDef.get(b) || "").toString().toLowerCase();
                return sort.dir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
              });
            }
          }

          const cbFilters = modal.usnCheckboxFilters?.[secKey];
          let isFiltered = false;
          if (cbFilters) {
            Object.entries(cbFilters).forEach(([colKey, selectedSet]) => {
              if (selectedSet?.size > 0) {
                const colDef = cols.find((c) => c.key === colKey);
                if (colDef) {
                  isFiltered = true;
                  events = events.filter((ev) => selectedSet.has((colDef.get(ev) || "").toString()));
                }
              }
            });
          }

          return {
            sData,
            count,
            rawEvents,
            canShowSuppressed,
            showSuppressed,
            suppressedEvents,
            sourceEvents,
            displayedCount,
            cols,
            events,
            isFiltered,
          };
        };
        const copySelected = () => {
          if (!data || totalSelected === 0) return;
          const lines = ["=== USN Journal Analysis — Selected Events ===", ""];
          for (const sec of usnSections) {
            const sel = modal.usnSelected?.[sec.key];
            if (!sel || sel.size === 0) continue;
            const view = getUsnSectionView(sec.key);
            if (!view) continue;
            const visibleRows = view.events.slice(0, 500);
            const selectedRows = visibleRows.filter((_, idx) => sel.has(idx));
            if (selectedRows.length === 0) continue;
            lines.push(`--- ${sec.label} (${selectedRows.length} selected) ---`);
            selectedRows.forEach((ev) => {
              lines.push("  " + view.cols.map((c) => c.get(ev) || "").join("\t"));
            });
            lines.push("");
          }
          navigator.clipboard?.writeText(lines.join("\n"));
        };
        const scopedIncident = timelineIncidentKey ? (data?.directoryIncidents || []).find((d) => d.key === timelineIncidentKey) : null;
        const scopedIncidentStartMs = parseUsnTsMs(scopedIncident?.start);
        const scopedIncidentEndMs = parseUsnTsMs(scopedIncident?.end);
        const filteredTimeline = (data?.timeline || []).filter((ev) => {
          if (scopedIncident) {
            if (ev.parentPath !== scopedIncident.path) return false;
            if (Number.isFinite(scopedIncidentStartMs) && Number.isFinite(scopedIncidentEndMs)) {
              const evMs = parseUsnTsMs(ev.timestamp);
              if (!Number.isFinite(evMs) || evMs < scopedIncidentStartMs || evMs > scopedIncidentEndMs) return false;
            }
          }
          if (usnScopeDir && !(ev.parentPath || "").startsWith(usnScopeDir)) return false;
          if (!withinSiblingScope(ev.parentPath || "")) return false;
          if (usnFocusEntry && String(ev.entryNumber || "") !== usnFocusEntry) return false;
          return true;
        });
        const focusedChain = usnFocusEntry ? (data?.fileChains || []).find((c) => String(c.entryNumber || "") === usnFocusEntry || c.key === usnFocusEntry) : null;
        const visibleIncidents = (data?.directoryIncidents || []).filter((inc) => {
          if (usnScopeDir && inc.path !== usnScopeDir) return false;
          if (!withinSiblingScope(inc.path || "")) return false;
          if (usnFocusEntry) return inc.events?.some((ev) => String(ev.entryNumber || "") === usnFocusEntry);
          return true;
        }).slice(0, 12);
        const timelineRows = filteredTimeline.slice(0, modal.usnTimelineLimit || 120);
        const corrColor = (key) => ({
          downloaded: "#58a6ff",
          timestomp: "#E85D2A",
          "deleted-in-mft": "#C44D1E",
          "persistence-related": "#D4783A",
          "executable-or-script": "#E8A050",
          "archive-staging": "#D4956A",
          "acl-change-burst": "#B85C38",
          "overwrite-burst": "#E87848",
          "rename-burst": "#D4783A",
          "stream-activity": "#D4956A",
        }[key] || "#E8A050");
        const tagPill = (tag, color = "#E8A050") => ({ fontSize: 9, padding: "2px 7px", borderRadius: 999, background: `${color}16`, color, border: `1px solid ${color}28`, fontFamily: "'Segoe UI', system-ui, sans-serif", fontWeight: 600 });
        const incidentSeverity = (score) => score >= 10 ? { label: "High", color: "#E85D2A" } : score >= 6 ? { label: "Medium", color: "#E8A050" } : { label: "Low", color: "#C8A882" };
        const likelyFindingSeverity = (finding) => ({
          critical: { label: "Critical", color: "#C44D1E" },
          high: { label: "High", color: "#E85D2A" },
          medium: { label: "Medium", color: "#E8A050" },
          low: { label: "Low", color: "#C8A882" },
        }[finding?.severity] || incidentSeverity(finding?.priorityScore || 0));
        const clearUsnFocus = () => setModal((p) => p ? { ...p, usnScopeDir: "", usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p);
        const focusUsnDirectory = (dir) => {
          if (!dir) return;
          setModal((p) => p ? { ...p, usnScopeDir: dir, usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p);
        };
        const focusUsnChain = (entryOrKey, incidentKey = "") => {
          if (!entryOrKey) return;
          setModal((p) => p ? { ...p, usnFocusEntry: String(entryOrKey), usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: incidentKey || "" } : p);
        };
        const focusUsnIncidentTimeline = (incidentKey) => {
          if (!incidentKey) return;
          setModal((p) => p ? { ...p, usnTimelineIncident: incidentKey, usnScopeDir: "", usnSiblingDir: "", usnFocusEntry: "" } : p);
        };
        const showUsnParentDirectory = (dir) => {
          const parent = parentDirOf(dir);
          if (!parent) return;
          setModal((p) => p ? { ...p, usnScopeDir: parent, usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p);
        };
        const showUsnSiblingActivity = (dir) => {
          if (!dir) return;
          setModal((p) => p ? { ...p, usnScopeDir: "", usnSiblingDir: dir, usnFocusEntry: "", usnTimelineIncident: "" } : p);
        };
        const copyVisibleUsnIncidentsJson = () => navigator.clipboard?.writeText(JSON.stringify(visibleIncidents, null, 2));
        const hasCorrTag = (tags, key) => Array.isArray(tags) && tags.some((t) => (typeof t === "string" ? t === key : t?.key === key));
        const correlatedMftTabId = data?.correlation?.mftTabId || modal.mftTabId || null;
        const correlatedMftTab = correlatedMftTabId ? tabs.find((t) => t.id === correlatedMftTabId && t.dataReady) : null;
        const adsCapable = correlatedMftTab && (correlatedMftTab.headers?.includes("HasAds") || correlatedMftTab.headers?.includes("ZoneIdContents"));
        const timestompCapable = correlatedMftTab && correlatedMftTab.headers?.includes("SI<FN");
        const ransomwareCapable = correlatedMftTab && correlatedMftTab.headers?.includes("Extension") && correlatedMftTab.headers?.includes("FileName") && correlatedMftTab.headers?.includes("ParentPath") && correlatedMftTab.headers?.includes("LastModified0x10");
        const persistenceTab = tabs.find((t) => t.id !== ct?.id && t.dataReady && (t.headers?.some((h) => /^KeyPath$/i.test(h)) || t.headers?.some((h) => /^EventI[dD]$/i.test(h))));
        const launchAdsFromUsn = () => {
          if (!adsCapable) return;
          setActiveTab(correlatedMftTab.id);
          setModal({ type: "ads", data: null, loading: true });
          tle.analyzeADS(correlatedMftTab.id).then((r) => setModal((p) => p?.type === "ads" ? { ...p, loading: false, data: r, adSelExec: new Set(), adSelZone: new Set(), adSelAds: new Set(), adSortExec: null, adSortZone: null, adSortAds: null } : p));
        };
        const launchTimestompFromUsn = () => {
          if (!timestompCapable) return;
          setActiveTab(correlatedMftTab.id);
          setModal({ type: "timestomping", data: null, loading: true });
          tle.detectTimestomping(correlatedMftTab.id).then((r) => setModal((p) => p?.type === "timestomping" ? { ...p, loading: false, data: r, tsSelFiles: new Set(), tsSelDirs: new Set(), tsSort: null } : p));
        };
        const launchPersistenceFromUsn = () => {
          if (!persistenceTab) return;
          const headers = persistenceTab.headers || [];
          let autoMode = "evtx";
          if (headers.some((h) => /^KeyPath$/i.test(h)) && headers.some((h) => /^ValueName$/i.test(h))) autoMode = "registry";
          else if (headers.some((h) => /^EventI[dD]$/i.test(h))) autoMode = "evtx";
          setActiveTab(persistenceTab.id);
          setModal({ type: "persistence", phase: "config", mode: autoMode, columns: {}, data: null, loading: false, error: null, viewTab: "grouped", searchText: "", severityFilter: "all", categoryFilter: "all", disabledRules: new Set(), customRules: [], showRules: false, addingRule: false, newRule: {}, modalW: 1100, paShowMapping: false, paIntent: "balanced", paPreview: null, paPreviewLoading: true, _paNeedsPreview: true, paFindingsView: "alerts", paSortBy: "triage", paGroupBy: "incident", expandedIncident: null, tlMode: "triage", tlCatFilter: null, tblMode: "triage" });
        };
        const launchRansomwareFromUsn = () => {
          if (!ransomwareCapable) return;
          setActiveTab(correlatedMftTab.id);
          setModal({ type: "ransomware", phase: "input", encryptedExt: "", ransomNotePattern: "", noteMatchMode: "exact", usnTabId: ct.id, data: null, loading: false });
        };

        const renderSection = (sec) => {
          const sectionView = getUsnSectionView(sec.key);
          if (!sectionView) return null;
          const { sData, count, rawEvents, canShowSuppressed, showSuppressed, sourceEvents, displayedCount, cols, events, isFiltered } = sectionView;
          const secStats = data?.sectionStats?.[sec.key] || null;

          // Selection
          const selected = modal.usnSelected?.[sec.key] || new Set();
          const hasVisibleEvents = events.length > 0;
          const isExpanded = hasVisibleEvents ? !!modal.usnExpanded?.[sec.key] : false;
          const visibleCount = Math.min(events.length, 500);
          const allSelected = visibleCount > 0 && selected.size >= visibleCount;
          const toggleRow = (idx) => setModal((p) => {
            if (!p) return p;
            const s = new Set(p.usnSelected?.[sec.key] || []);
            s.has(idx) ? s.delete(idx) : s.add(idx);
            return { ...p, usnSelected: { ...p.usnSelected, [sec.key]: s } };
          });
          const toggleAll = () => setModal((p) => {
            if (!p) return p;
            const s = allSelected ? new Set() : new Set(Array.from({ length: visibleCount }, (_, i) => i));
            return { ...p, usnSelected: { ...p.usnSelected, [sec.key]: s } };
          });

          // Sort handler
          const handleSort = (colKey) => {
            if (cols.find((c) => c.key === colKey)?.noSort) return;
            setModal((p) => {
              if (!p) return p;
              const cur = p.usnSort?.[sec.key];
              const newDir = cur?.col === colKey && cur.dir === "asc" ? "desc" : "asc";
              return { ...p, usnSort: { ...p.usnSort, [sec.key]: { col: colKey, dir: newDir } } };
            });
          };

          // Column resize
          const getW = (colKey, def) => modal.usnColWidths?.[sec.key]?.[colKey] ?? def;
          const startColResize = (e, colKey, startW) => {
            e.preventDefault(); e.stopPropagation();
            const sx = e.clientX;
            const onMove = (ev) => {
              const nw = Math.max(36, startW + (ev.clientX - sx));
              setModal((p) => p ? { ...p, usnColWidths: { ...p.usnColWidths, [sec.key]: { ...(p.usnColWidths?.[sec.key] || {}), [colKey]: nw } } } : p);
            };
            const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
            window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
          };

          // Column style helper — supports custom widths on both fixed and flex columns
          const colStyle = (col, isHeader) => {
            const customW = modal.usnColWidths?.[sec.key]?.[col.key];
            const w = customW || (col.w ? getW(col.key, col.w) : undefined);
            return {
              width: w, flex: w ? undefined : (col.flex || undefined), flexShrink: w ? 0 : undefined,
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              color: isHeader ? th.textMuted : (col.color || (col.key === "parentPath" || col.key === "timestamp" ? th.textDim : th.text)),
              fontSize: isHeader ? 9 : (col.key === "reasons" ? 9 : 11),
            };
          };

          // Filter dropdown button per column
          const filterBtn = (colKey) => {
            if (cols.find((c) => c.key === colKey)?.noSort) return null;
            const hasFilter = modal.usnCheckboxFilters?.[sec.key]?.[colKey]?.size > 0;
            return (
              <button onClick={(e) => {
                e.stopPropagation();
                // Toggle off if already open for this column
                if (usnFd?.secKey === sec.key && usnFd?.colKey === colKey) {
                  setUsnFd(null); return;
                }
                // Precompute unique values once on open
                const colDef = cols.find((c) => c.key === colKey);
                const evts = showSuppressed ? sourceEvents : (rawEvents || []);
                let scopedEvts = evts;
                if (usnScopeDir) {
                  scopedEvts = scopedEvts.filter((ev) => (ev.parentPath || "").startsWith(usnScopeDir));
                }
                if (usnSiblingDir) {
                  scopedEvts = scopedEvts.filter((ev) => withinSiblingScope(ev.parentPath || ""));
                }
                if (usnFocusEntry) {
                  scopedEvts = scopedEvts.filter((ev) => String(ev.entryNumber || "") === usnFocusEntry);
                }
                const valCounts = {};
                (scopedEvts || []).forEach((ev) => { const v = (colDef?.get(ev) || "").toString(); valCounts[v] = (valCounts[v] || 0) + 1; });
                const values = Object.entries(valCounts).map(([val, cnt]) => ({ val, cnt })).sort((a, b) => b.cnt - a.cnt);
                const existing = modal.usnCheckboxFilters?.[sec.key]?.[colKey];
                // Position: center on the column header, not on the button
                const hdrRect = e.currentTarget.parentElement.getBoundingClientRect();
                setUsnFd({ secKey: sec.key, colKey, x: Math.max(8, hdrRect.left - 100), y: hdrRect.bottom + 4, values, search: "", selected: existing ? new Set(existing) : new Set(values.map((v) => v.val)) });
              }}
                style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px",
                  color: hasFilter ? sec.color : "#b0a8a0", fontSize: 11, flexShrink: 0, lineHeight: 1,
                  fontWeight: hasFilter ? 700 : 400, transition: "color 0.15s" }}
                title="Filter by values">▼</button>
            );
          };

          // Glass sub-section style
          const glassSub = { padding: "6px 12px", borderBottom: `1px solid ${th.border}15`, background: `linear-gradient(135deg, ${sec.color}06, transparent)` };
          const pillStyle = { fontSize: 10, padding: "2px 8px", borderRadius: 10, background: `${sec.color}15`, color: sec.color, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", border: `1px solid ${sec.color}18` };

          const secSev = secStats ? incidentSeverity(secStats.priorityScore || 0) : { label: "Info", color: sec.color };
          return (
            <div key={sec.key} style={{ marginBottom: 10, borderRadius: 10, overflow: "hidden", border: `1px solid ${sec.color}18`, background: `linear-gradient(135deg, ${sec.color}04, ${th.modalBg}88)`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", boxShadow: `0 2px 12px ${sec.color}08, 0 0 0 1px rgba(255,255,255,0.02) inset` }}>
              <button onClick={() => toggleExpand(sec.key, hasVisibleEvents)} style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "11px 14px", background: `linear-gradient(135deg, ${sec.color}0a, ${sec.color}04)`, border: "none", borderBottom: isExpanded ? `1px solid ${sec.color}15` : "none", color: th.text, cursor: hasVisibleEvents ? "pointer" : "default", textAlign: "left", fontFamily: "'Segoe UI', system-ui, sans-serif", backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)" }}>
                <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={sec.color} strokeWidth="1.5" strokeLinecap="round" style={{ transform: isExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.15s ease", flexShrink: 0, opacity: hasVisibleEvents ? 1 : 0.4 }}><polyline points="3,1 7,5 3,9" /></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={sec.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: `drop-shadow(0 0 3px ${sec.color}44)` }}>{sec.icon}</svg>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <div style={{ fontSize: 12, fontWeight: 600 }}>{sec.label}</div>
                    {secStats && <span style={{ ...tagPill(secSev.label, secSev.color), textTransform: "uppercase" }}>{secSev.label}</span>}
                    {secStats && <span style={tagPill(`${secStats.eventsPerMinute} evt/min`, "#D4956A")}>{secStats.eventsPerMinute} evt/min</span>}
                    {secStats && <span style={tagPill(`${secStats.uniqueFiles} files`, "#E8A050")}>{secStats.uniqueFiles} files</span>}
                    {Number(sData.suppressedCount || 0) > 0 && <span style={tagPill(`${sData.suppressedCount} suppressed`, "#C8A882")}>{sData.suppressedCount} suppressed</span>}
                  </div>
                  {sec.desc && <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 400, marginTop: 1, lineHeight: 1.3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sec.desc}</div>}
                  {secStats && (
                    <div style={{ fontSize: 9, color: th.textDim, marginTop: 3, lineHeight: 1.35, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      Top hotspot: {secStats.topDirectory?.path || "(unknown)"} • {secStats.topDirectory?.count || 0} events • {secStats.uniqueDirs} dirs
                    </div>
                  )}
                  {Number(sData.suppressedCount || 0) > 0 && (
                    <div style={{ fontSize: 9, color: th.textDim, marginTop: 3, lineHeight: 1.35, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      Noise suppressed: {(sData.suppressionSummary || []).slice(0, 2).map((item) => `${item.label} ×${item.count}`).join(", ") || `${sData.suppressedCount} likely-benign rows hidden`}
                    </div>
                  )}
                </div>
                {canShowSuppressed && (
                  <span
                    onClick={(e) => {
                      e.stopPropagation();
                      setModal((p) => {
                        if (!p) return p;
                        const nextShow = !p.usnShowSuppressed?.[sec.key];
                        const nextFilters = { ...(p.usnCheckboxFilters || {}) };
                        if (!nextShow && nextFilters[sec.key]?.suppressionReason) {
                          const secFilters = { ...(nextFilters[sec.key] || {}) };
                          delete secFilters.suppressionReason;
                          nextFilters[sec.key] = secFilters;
                        }
                        return {
                          ...p,
                          usnShowSuppressed: { ...p.usnShowSuppressed, [sec.key]: nextShow },
                          usnExpanded: {
                            ...p.usnExpanded,
                            [sec.key]: nextShow ? true : (count > 0 ? p.usnExpanded?.[sec.key] : false),
                          },
                          usnCheckboxFilters: nextFilters,
                          usnSelected: { ...p.usnSelected, [sec.key]: new Set() },
                        };
                      });
                      setUsnFd((p) => (p?.secKey === sec.key ? null : p));
                    }}
                    style={{
                      background: showSuppressed ? `${sec.color}22` : `${th.panelBg}aa`,
                      border: `1px solid ${showSuppressed ? `${sec.color}44` : `${th.border}33`}`,
                      color: showSuppressed ? sec.color : th.textDim,
                      cursor: "pointer",
                      fontSize: 10,
                      fontWeight: 600,
                      padding: "5px 9px",
                      borderRadius: 8,
                      fontFamily: "'Segoe UI', system-ui, sans-serif",
                      flexShrink: 0,
                    }}
                    title={showSuppressed ? "Hide likely-benign suppressed rows" : "Reveal suppressed rows for audit"}
                  >
                    {showSuppressed ? "Hide Suppressed" : "Show Suppressed"}
                  </span>
                )}
                {selected.size > 0 && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 8, background: `${th.accent}22`, color: th.accent, fontWeight: 600, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{selected.size} sel</span>}
                <span style={{ fontSize: 10, padding: "2px 10px", borderRadius: 10, background: `linear-gradient(135deg, ${sec.color}28, ${sec.color}18)`, color: sec.color, fontWeight: 600, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", border: `1px solid ${sec.color}22`, boxShadow: `0 0 8px ${sec.color}11` }}>{isFiltered ? `${events.length.toLocaleString()} / ${displayedCount.toLocaleString()}` : displayedCount.toLocaleString()}</span>
              </button>
              {isExpanded && (
                <div style={{ maxHeight: 360, overflow: "auto" }}>
                  {secStats && (
                    <div style={{ ...glassSub, display: "grid", gridTemplateColumns: "1.1fr 0.9fr 0.9fr 1fr", gap: 10, padding: "8px 12px" }}>
                      <div>
                        <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Top Directory</div>
                        <div style={{ fontSize: 10, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{secStats.topDirectory?.path || "(unknown)"}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Burst Rate</div>
                        <div style={{ fontSize: 10, color: th.text }}>{secStats.eventsPerMinute} events/min</div>
                      </div>
                      <div>
                        <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Top Reasons</div>
                        <div style={{ fontSize: 10, color: th.text }}>{(secStats.topReasons || []).map((r) => `${r.label}×${r.count}`).join(", ") || "—"}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>Top Ext</div>
                        <div style={{ fontSize: 10, color: th.text }}>{(secStats.topExtensions || []).map((e) => `${e.ext || "(none)"}×${e.count}`).join(", ") || "—"}</div>
                      </div>
                    </div>
                  )}
                  {/* Category-specific sub-sections */}
                  {sec.key === "execution" && sData.extensionBreakdown?.length > 0 && (
                    <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                      {sData.extensionBreakdown.slice(0, 10).map((eb) => (
                        <span key={eb.ext} style={pillStyle}>{eb.ext} ({eb.count})</span>
                      ))}
                    </div>
                  )}
                  {sec.key === "persistence" && sData.categories?.length > 0 && (
                    <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                      {sData.categories.map((c) => (
                        <span key={c.name} style={pillStyle}>{c.name} ({c.count})</span>
                      ))}
                    </div>
                  )}
                  {(sec.key === "persistence" || sec.key === "suspiciousPaths") && sData.suppressedCount > 0 && (
                    <div style={glassSub}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 4 }}>
                        <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>Noise Suppressed</div>
                        <span style={{ ...pillStyle, background: showSuppressed ? `${sec.color}24` : `${sec.color}15` }}>{showSuppressed ? "Suppressed rows visible" : "Suppressed rows hidden"}</span>
                      </div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <span style={pillStyle}>{sData.suppressedCount} likely-benign rows hidden</span>
                        {(sData.suppressionSummary || []).map((item) => (
                          <span key={item.label} style={pillStyle}>{item.label} ({item.count})</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {sec.key === "suspiciousPaths" && sData.categories?.length > 0 && (
                    <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                      {sData.categories.map((c) => (
                        <span key={c.name} style={pillStyle}>{c.name} ({c.count})</span>
                      ))}
                    </div>
                  )}
                  {sec.key === "suspiciousPaths" && sData.directoryBreakdown?.length > 0 && (
                    <div style={glassSub}>
                      {sData.directoryBreakdown.slice(0, 10).map((d, i) => (
                        <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.textMuted }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                          <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {sec.key === "securityChanges" && sData.directoryBreakdown?.length > 0 && (
                    <div style={glassSub}>
                      <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Hotspot Directories {sData.hotspotCount > 0 && <span style={{ color: sec.color }}>({sData.hotspotCount} with 5+ files)</span>}</div>
                      {sData.directoryBreakdown.slice(0, 15).map((d, i) => (
                        <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: d.uniqueFiles >= 5 ? sec.color : th.textMuted }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                          <span style={{ flexShrink: 0, marginLeft: 12, fontWeight: 600 }}>{d.count} events / {d.uniqueFiles} files</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {sec.key === "exfil" && sData.stagingDirectories?.length > 0 && (
                    <div style={glassSub}>
                      <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Staging Directories</div>
                      {sData.stagingDirectories.map((d, i) => (
                        <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.textMuted }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.directory}</span>
                          <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.fileCount} files</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {sec.key === "dataOverwrite" && sData.extensionBreakdown?.length > 0 && (
                    <div style={{ ...glassSub, display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 12px" }}>
                      {sData.extensionBreakdown.slice(0, 12).map((eb) => (
                        <span key={eb.ext} style={pillStyle}>{eb.ext} ({eb.count})</span>
                      ))}
                    </div>
                  )}
                  {sec.key === "dataOverwrite" && sData.directoryBreakdown?.length > 0 && (
                    <div style={glassSub}>
                      {sData.directoryBreakdown.slice(0, 10).map((d, i) => (
                        <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.textMuted }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                          <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {sec.key === "streamChanges" && sData.directoryBreakdown?.length > 0 && (
                    <div style={glassSub}>
                      {sData.directoryBreakdown.slice(0, 10).map((d, i) => (
                        <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.textMuted }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                          <span style={{ flexShrink: 0, marginLeft: 12, color: sec.color, fontWeight: 600 }}>{d.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {sec.key === "closePatterns" && sData.directoryBreakdown?.length > 0 && (
                    <div style={glassSub}>
                      <div style={{ fontSize: 10, fontWeight: 600, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Enumeration Hotspots {sData.hotspotCount > 0 && <span style={{ color: sec.color }}>({sData.hotspotCount} with 10+ events)</span>}</div>
                      {sData.directoryBreakdown.slice(0, 15).map((d, i) => (
                        <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "2px 0", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: d.count >= 10 ? sec.color : th.textMuted }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{d.path}</span>
                          <span style={{ flexShrink: 0, marginLeft: 12, fontWeight: 600 }}>{d.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {/* Column header — opaque sticky */}
                  <div style={{ display: "flex", alignItems: "center", gap: 0, padding: "0 10px", fontSize: 9, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", borderBottom: `1px solid ${th.border}30`, fontFamily: "'Segoe UI', system-ui, sans-serif", background: th.modalBg || th.panelBg || "#1e2126", position: "sticky", top: 0, zIndex: 2 }}>
                    {/* Select-all checkbox */}
                    <div onClick={toggleAll} style={{ width: 26, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", padding: "6px 0", cursor: "pointer" }}>
                      <div style={{ width: 12, height: 12, borderRadius: 3, background: allSelected ? sec.color : "transparent", border: `1.5px solid ${allSelected ? sec.color : th.border}66`, display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s" }}>
                        {allSelected && <svg width="7" height="7" viewBox="0 0 8 8" fill="none" stroke="#fff" strokeWidth="1.5"><polyline points="1.5,4 3.5,6 6.5,2" /></svg>}
                      </div>
                    </div>
                    {cols.map((col, ci) => (
                      <div key={col.key} style={{ ...colStyle(col, true), display: "flex", alignItems: "center", padding: "6px 4px", cursor: col.noSort ? "default" : "pointer", position: "relative", userSelect: "none" }} onClick={() => handleSort(col.key)}>
                        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{col.label}</span>
                        <span style={{ flexShrink: 0, marginLeft: "auto" }}>{filterBtn(col.key)}</span>
                        {/* Resize handle — all columns except noResize and last column */}
                        {!col.noResize && ci < cols.length - 1 && (
                          <div onMouseDown={(e) => { const rect = e.currentTarget.parentElement.getBoundingClientRect(); startColResize(e, col.key, modal.usnColWidths?.[sec.key]?.[col.key] || (col.w ? getW(col.key, col.w) : Math.round(rect.width))); }} onClick={(e) => e.stopPropagation()}
                            style={{ position: "absolute", right: -2, top: 2, bottom: 2, width: 5, cursor: "col-resize", borderRight: `1px solid ${th.border}22` }}
                            onMouseEnter={(e) => { e.currentTarget.style.borderRight = `2px solid ${sec.color}66`; }}
                            onMouseLeave={(e) => { e.currentTarget.style.borderRight = `1px solid ${th.border}22`; }} />
                        )}
                      </div>
                    ))}
                  </div>
                  {/* Event rows */}
                  {events.slice(0, 500).map((ev, i) => {
                    const isSelected = selected.has(i);
                    return (
                      <div key={i} onClick={() => toggleRow(i)} style={{
                        display: "flex", alignItems: "center", gap: 0, padding: "0 10px", fontSize: 11, cursor: "pointer",
                        fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", borderBottom: `1px solid ${th.border}0c`,
                        background: isSelected ? `${sec.color}12` : (ev._suppressed ? `${th.warning || "#d29922"}0d` : (i % 2 === 0 ? "transparent" : `${th.border}08`)),
                        opacity: ev._suppressed ? 0.86 : 1,
                        transition: "background 0.1s",
                      }}
                        onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = ev._suppressed ? `${th.warning || "#d29922"}14` : `${sec.color}0a`; }}
                        onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = ev._suppressed ? `${th.warning || "#d29922"}0d` : (i % 2 === 0 ? "transparent" : `${th.border}08`); }}
                      >
                        <div style={{ width: 26, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", padding: "4px 0" }}>
                          <div style={{ width: 12, height: 12, borderRadius: 3, background: isSelected ? sec.color : "transparent", border: `1.5px solid ${isSelected ? sec.color : th.border}55`, display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.12s" }}>
                            {isSelected && <svg width="7" height="7" viewBox="0 0 8 8" fill="none" stroke="#fff" strokeWidth="1.5"><polyline points="1.5,4 3.5,6 6.5,2" /></svg>}
                          </div>
                        </div>
                        {cols.map((col) => {
                          const val = col.get(ev) || "";
                          if (col.key === "_mftStatus" && val && val !== "—") {
                            const badges = val.split("|");
                            const badgeColors = { EX: "#58a6ff", FB: "#C8A882", DEL: "#C44D1E", TS: "#E85D2A", DL: "#D4956A", OK: "#E8A050" };
                            return (
                              <span key={col.key} style={{ ...colStyle(col, false), padding: "4px 4px", display: "flex", gap: 3, alignItems: "center" }}>
                                {badges.map((b) => <span key={b} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 4, background: `${badgeColors[b] || th.textMuted}22`, color: badgeColors[b] || th.textMuted, fontWeight: 700, letterSpacing: "0.03em", border: `1px solid ${badgeColors[b] || th.textMuted}33` }}>{b}</span>)}
                              </span>
                            );
                          }
                          return <span key={col.key} style={{ ...colStyle(col, false), padding: "4px 4px" }}>{val}</span>;
                        })}
                      </div>
                    );
                  })}
                  {events.length === 0 && <div style={{ padding: "14px 14px", fontSize: 11, color: th.textMuted, fontStyle: "italic" }}>No events found</div>}
                </div>
              )}
            </div>
          );
        };

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, zIndex: 100, backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)", WebkitAppRegion: "no-drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "absolute", left: ux, top: uy, width: uw, height: uh, background: th.modalBg + "f2", border: `1px solid ${th.modalBorder}88`, borderRadius: 14, padding: 0, display: "flex", flexDirection: "column", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)" }}>
              {/* Resize handles */}
              <div onMouseDown={(e) => startResize(e, "t")} style={uEdge("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "b")} style={uEdge("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "l")} style={uEdge("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "r")} style={uEdge("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "tl")} style={uEdge("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "tr")} style={uEdge("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "bl")} style={uEdge("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "br")} style={uEdge("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

              {/* Header */}
              <div onMouseDown={startDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent || "#58a6ff"}33, ${th.accent || "#58a6ff"}11)`, border: `1px solid ${th.accent || "#58a6ff"}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={th.accent || "#58a6ff"} strokeWidth="1.8" strokeLinecap="round"><rect x="3" y="3" width="18" height="18" rx="2" fill={(th.accent || "#58a6ff") + "18"}/><path d="M7 7h10M7 11h10M7 15h6"/></svg>
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif", letterSpacing: "-0.01em" }}>USN Journal Analysis</h3>
                    <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 10, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Analyze file system activity within a time window</p>
                  </div>
                </div>
                <button onClick={() => setModal(null)} style={{ background: `${th.border}22`, border: `1px solid ${th.border}33`, color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "4px 8px", borderRadius: 6, lineHeight: 1 }}>✕</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {usnResolveStats && (
                  <div style={{ marginBottom: 14, padding: "12px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${usnResolveTone.color}12, ${th.modalBg}88)`, border: `1px solid ${usnResolveTone.color}2a`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
                      <div>
                        <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Path Resolution</div>
                        <div style={{ fontSize: 12, color: th.text, fontWeight: 700 }}>{usnResolveTone.label}</div>
                      </div>
                      <span style={{ ...tagPill(`${Number(usnResolveStats.resolvedPercent || 0)}% resolved`, usnResolveTone.color), textTransform: "uppercase" }}>{Number(usnResolveStats.resolvedPercent || 0)}% resolved</span>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 8, marginBottom: 8 }}>
                      {[
                        { label: "Resolved", value: `${(usnResolveStats.resolved || 0).toLocaleString()} / ${(usnResolveStats.total || 0).toLocaleString()}` },
                        { label: "USN-only", value: (usnResolveStats.selfResolved || 0).toLocaleString() },
                        { label: "MFT-assisted", value: (usnResolveStats.mftResolved || 0).toLocaleString() },
                        { label: "Unresolved", value: (usnResolveStats.unresolved || 0).toLocaleString() },
                      ].map((item) => (
                        <div key={item.label} style={{ padding: "8px 10px", borderRadius: 8, background: `${th.panelBg}88`, border: `1px solid ${th.border}18` }}>
                          <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{item.label}</div>
                          <div style={{ fontSize: 12, color: th.text, fontWeight: 700, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{item.value}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ fontSize: 10, color: th.textDim, lineHeight: 1.45 }}>
                      Directory incidents, path filters, and parent/sibling pivots rely on `ParentPath`. Unresolved rows stay visible in broad counts, but they may be absent from path-scoped views until enough directory history or MFT context is available.
                    </div>
                  </div>
                )}
                {/* Input phase */}
                {phase === "input" && (<>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
                    <div style={ms.fg}>
                      <label style={ms.lb}>Start Time (UTC)</label>
                      <input type="text" value={modal.startTime} onChange={(e) => setModal((p) => ({ ...p, startTime: e.target.value }))} placeholder="YYYY-MM-DD HH:MM:SS" style={{ ...ms.ip, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} autoFocus />
                    </div>
                    <div style={ms.fg}>
                      <label style={ms.lb}>End Time (UTC) — optional</label>
                      <input type="text" value={modal.endTime} onChange={(e) => setModal((p) => ({ ...p, endTime: e.target.value }))} placeholder="YYYY-MM-DD HH:MM:SS" style={{ ...ms.ip, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }} />
                    </div>
                  </div>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Path Filter (optional)</label>
                    <input value={modal.pathFilter} onChange={(e) => setModal((p) => ({ ...p, pathFilter: e.target.value }))} placeholder="e.g. \\Users\\admin" style={ms.ip} />
                  </div>
                  {/* MFT cross-correlation selector */}
                  {(() => {
                    const mftTabs = tabs.filter((t) => t.dataReady && t.sourceFormat === "raw-mft" && t.id !== ct?.id);
                    if (mftTabs.length === 0) return null;
                    return (
                      <div style={{ ...ms.fg, marginTop: 8 }}>
                        <label style={ms.lb}>Correlate with MFT (optional)</label>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <select value={modal.mftTabId || ""} onChange={(e) => setModal((p) => ({ ...p, mftTabId: e.target.value || null }))}
                            style={{ ...ms.ip, flex: 1, cursor: "pointer", appearance: "none", backgroundImage: `url("data:image/svg+xml,%3Csvg width='10' height='6' viewBox='0 0 10 6' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%23888' stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E")`, backgroundRepeat: "no-repeat", backgroundPosition: "right 10px center", paddingRight: 28 }}>
                            <option value="">None — USN-only analysis</option>
                            {mftTabs.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                          </select>
                          {modal.mftTabId && (
                            <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "4px 8px", background: "#E8A05015", border: "1px solid #E8A05033", borderRadius: 6 }}>
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#E8A050" strokeWidth="2" strokeLinecap="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                              <span style={{ fontSize: 10, color: "#E8A050", fontWeight: 600 }}>Linked</span>
                            </div>
                          )}
                        </div>
                        <div style={{ fontSize: 9, color: th.textMuted, marginTop: 3 }}>Enrich USN events with MFT metadata: file size, deletion status, timestomping, Zone.Identifier</div>
                      </div>
                    );
                  })()}
                  <div style={{ marginTop: 14 }}>
                    <label style={ms.lb}>Analyses to Run</label>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, marginTop: 4 }}>
                      {usnSections.map((sec) => (
                        <button key={sec.key} onClick={() => toggleAnalysis(sec.key)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 10px", background: modal.analyses[sec.key] ? `${sec.color}12` : "transparent", border: `1px solid ${modal.analyses[sec.key] ? sec.color + "44" : th.border + "44"}`, borderRadius: 6, color: th.text, cursor: "pointer", fontSize: 11, fontFamily: "'Segoe UI', system-ui, sans-serif", textAlign: "left", transition: "all 0.15s" }}>
                          <div style={{ width: 14, height: 14, borderRadius: 4, flexShrink: 0, background: modal.analyses[sec.key] ? sec.color : "transparent", border: `1.5px solid ${modal.analyses[sec.key] ? sec.color : th.border}`, display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s" }}>
                            {modal.analyses[sec.key] && <svg width="8" height="8" viewBox="0 0 8 8" fill="none" stroke="#fff" strokeWidth="1.5"><polyline points="1.5,4 3.5,6 6.5,2" /></svg>}
                          </div>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={sec.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">{sec.icon}</svg>
                          {sec.label}
                        </button>
                      ))}
                    </div>
                  </div>
                  {error && <div style={{ marginTop: 10, padding: "8px 12px", background: `${th.danger || "#f85149"}15`, border: `1px solid ${th.danger || "#f85149"}33`, borderRadius: 6, color: th.danger || "#f85149", fontSize: 11 }}>{error}</div>}
                </>)}

                {/* Loading phase */}
                {phase === "loading" && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 0", gap: 16 }}>
                    <div style={{ width: 40, height: 40, border: `3px solid ${th.border}33`, borderTopColor: th.accent || "#58a6ff", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                    <span style={{ color: th.textMuted, fontSize: 12, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Analyzing USN Journal...</span>
                  </div>
                )}

                {/* Results phase */}
                {phase === "results" && data && (<>
                  {/* Summary — glass cards */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                    {[
                      { label: "Total Events", value: (data.summary?.totalEvents || 0).toLocaleString(), accent: "#E85D2A" },
                      { label: "Start Time", value: (data.summary?.startTime || "").slice(0, 19), accent: "#E8A050" },
                      { label: "End Time", value: data.summary?.endTime?.startsWith("9999") ? "Open-ended" : (data.summary?.endTime || "").slice(0, 19), accent: "#D4783A" },
                      { label: "Path Filter", value: data.summary?.pathFilter || "All paths", accent: "#C96B3C" },
                    ].map((s) => (
                      <div key={s.label} style={{ padding: "10px 12px", background: `linear-gradient(135deg, ${s.accent}0a, ${th.modalBg}66)`, border: `1px solid ${s.accent}1a`, borderRadius: 10, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", boxShadow: `0 2px 8px ${s.accent}08, 0 0 0 1px rgba(255,255,255,0.02) inset` }}>
                        <div style={{ fontSize: 9, color: `${s.accent}bb`, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 3 }}>{s.label}</div>
                        <div style={{ fontSize: 13, color: th.text, fontWeight: 600, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.value}</div>
                      </div>
                    ))}
                  </div>
                  {/* MFT Correlation Summary */}
                  {data.correlation && (
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: 16 }}>
                      {[
                        { label: "MFT Matched", value: data.correlation.matched.toLocaleString(), accent: "#E8A050", sub: `${data.correlation.exactMatched || 0} exact / ${data.correlation.fallbackMatched || 0} entry-only of ${data.correlation.totalUsnEntries.toLocaleString()} file refs` },
                        { label: "Unmatched", value: data.correlation.unmatched.toLocaleString(), accent: th.textMuted, sub: "not in MFT" },
                        { label: "Deleted Files", value: data.correlation.deleted.toLocaleString(), accent: "#C44D1E", sub: "InUse = False" },
                        { label: "Timestomped", value: data.correlation.timestomped.toLocaleString(), accent: "#E85D2A", sub: "SI < FN" },
                        { label: "Downloaded", value: data.correlation.downloaded.toLocaleString(), accent: "#D4956A", sub: "Zone.Identifier" },
                      ].map((s) => (
                        <div key={s.label} style={{ padding: "10px 12px", background: `linear-gradient(135deg, ${s.accent}0a, ${th.modalBg}66)`, border: `1px solid ${s.accent}1a`, borderRadius: 10, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", boxShadow: `0 2px 8px ${s.accent}08, 0 0 0 1px rgba(255,255,255,0.02) inset` }}>
                          <div style={{ fontSize: 9, color: `${s.accent}bb`, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "'Segoe UI', system-ui, sans-serif", marginBottom: 3 }}>{s.label}</div>
                          <div style={{ fontSize: 15, color: th.text, fontWeight: 700, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{s.value}</div>
                          <div style={{ fontSize: 8, color: th.textMuted, marginTop: 1 }}>{s.sub}</div>
                        </div>
                      ))}
                    </div>
                  )}
                  {(data.narrative?.length > 0 || usnScopeDir || usnSiblingDir || usnFocusEntry || timelineIncidentKey) && (
                    <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${th.accent || "#58a6ff"}10, ${th.modalBg}88)`, border: `1px solid ${(th.accent || "#58a6ff")}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                        <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Investigator Summary</div>
                        {(usnScopeDir || usnSiblingDir || usnFocusEntry || timelineIncidentKey) && <button onClick={clearUsnFocus} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Clear Focus</button>}
                      </div>
                      <div style={{ display: "grid", gap: 5 }}>
                        {(data.narrative || []).map((line, i) => <div key={i} style={{ fontSize: 12, color: th.text, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>• {line}</div>)}
                      </div>
                      {(usnScopeDir || usnSiblingDir || usnFocusEntry || timelineIncidentKey) && (
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
                          {usnScopeDir && <span style={tagPill(`Directory: ${usnScopeDir}`, "#C96B3C")}>Directory: {usnScopeDir}</span>}
                          {usnSiblingDir && <span style={tagPill(`Siblings of: ${usnSiblingDir}`, "#D4956A")}>Siblings of: {usnSiblingDir}</span>}
                          {usnFocusEntry && <span style={tagPill(`Entry: ${usnFocusEntry}`, "#E8A050")}>Entry: {usnFocusEntry}</span>}
                          {timelineIncidentKey && <span style={tagPill("Timeline scoped to incident", "#D4783A")}>Timeline scoped to incident</span>}
                        </div>
                      )}
                      {data.correlationSummary?.length > 0 && (
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
                          {data.correlationSummary.slice(0, 6).map((c) => <span key={c.key} style={tagPill(`${c.label} ×${c.count}`, corrColor(c.key))}>{c.label} ×{c.count}</span>)}
                        </div>
                      )}
                    </div>
                  )}
                  {likelyFindings.length > 0 && (
                    <div style={{ marginBottom: 16, borderRadius: 12, background: `linear-gradient(135deg, ${(th.danger || "#f85149")}0c, ${th.modalBg}88)`, border: `1px solid ${(th.danger || "#f85149")}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", overflow: "hidden" }}>
                      <button
                        onClick={() => setModal((p) => p ? { ...p, usnLikelyFindingsExpanded: !p.usnLikelyFindingsExpanded } : p)}
                        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, width: "100%", padding: "12px 14px", background: "transparent", border: "none", color: th.text, cursor: "pointer", textAlign: "left" }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ transform: modal.usnLikelyFindingsExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.15s ease", flexShrink: 0 }}><polyline points="3,1 7,5 3,9" /></svg>
                          <div>
                            <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Likely Intrusion Findings</div>
                            <div style={{ fontSize: 10, color: th.textDim }}>{likelyFindings.length} ranked starting points built from the strongest USN incidents and file chains</div>
                          </div>
                        </div>
                        <span style={tagPill(`${likelyFindings.length}`, th.danger || "#f85149")}>{likelyFindings.length}</span>
                      </button>
                      {modal.usnLikelyFindingsExpanded && (
                        <div style={{ display: "grid", gap: 10, padding: "0 14px 12px" }}>
                          {likelyFindings.map((finding) => {
                            const sev = likelyFindingSeverity(finding);
                            const findingPath = finding.path || finding.primaryPath || "";
                            const isIncident = finding.sourceType === "directoryIncident";
                            return (
                              <div key={finding.key} style={{ border: `1px solid ${sev.color}28`, borderRadius: 10, padding: "10px 12px", background: `linear-gradient(135deg, ${sev.color}0c, transparent)` }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                                  <span style={{ ...tagPill(sev.label, sev.color), textTransform: "uppercase" }}>{sev.label}</span>
                                  <span style={tagPill(isIncident ? "Directory Incident" : "File Chain", "#D4956A")}>{isIncident ? "Directory Incident" : "File Chain"}</span>
                                  <span style={{ fontSize: 13, color: th.text, fontWeight: 700 }}>{finding.title}</span>
                                  <span style={{ ...tagPill(`Score ${finding.priorityScore || 0}`, "#E8A050") }}>Score {finding.priorityScore || 0}</span>
                                </div>
                                <div style={{ fontSize: 11, color: th.text, marginBottom: 6, lineHeight: 1.45 }}>{finding.summary}</div>
                                <div style={{ fontSize: 10, color: th.textDim, marginBottom: 8, lineHeight: 1.45 }}>{finding.rationale}</div>
                                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                                  {(finding.evidence || []).map((item) => <span key={item} style={tagPill(item, sev.color)}>{item}</span>)}
                                  {(finding.correlationTags || []).slice(0, 4).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                                </div>
                                <div style={{ display: "grid", gridTemplateColumns: "1.4fr 0.8fr", gap: 8, marginBottom: 8 }}>
                                  <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{findingPath || "(path unresolved)"}</div>
                                  <div style={{ fontSize: 10, color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", textAlign: "right" }}>{(finding.start || "").slice(0, 19)}{finding.end ? ` → ${(finding.end || "").slice(0, 19)}` : ""}</div>
                                </div>
                                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                  {isIncident ? (
                                    <>
                                      <button onClick={() => focusUsnIncidentTimeline(finding.sourceKey)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Incident Timeline</button>
                                      <button onClick={() => focusUsnDirectory(finding.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!finding.path}>This Directory</button>
                                      <button onClick={() => focusUsnChain(finding.entryNumber)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!finding.entryNumber}>File Chain</button>
                                    </>
                                  ) : (
                                    <>
                                      <button onClick={() => focusUsnChain(finding.entryNumber || finding.sourceKey)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open File Chain</button>
                                      <button onClick={() => focusUsnDirectory(finding.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!finding.path}>This Directory</button>
                                      <button onClick={() => showUsnParentDirectory(finding.path || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(finding.path || "")}>Parent Directory</button>
                                      <button onClick={() => showUsnSiblingActivity(finding.path || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(finding.path || "")}>Sibling Activity</button>
                                    </>
                                  )}
                                  <button onClick={() => navigator.clipboard?.writeText(JSON.stringify(finding, null, 2))} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Copy JSON</button>
                                  {hasCorrTag(finding.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open ADS</button>}
                                  {hasCorrTag(finding.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Timestomp</button>}
                                  {hasCorrTag(finding.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Persistence</button>}
                                  {(hasCorrTag(finding.correlationTags, "archive-staging") || hasCorrTag(finding.correlationTags, "overwrite-burst") || hasCorrTag(finding.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Ransomware</button>}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}

                  {visibleIncidents.length > 0 && (
                    <div style={{ marginBottom: 16, borderRadius: 12, background: `${th.panelBg}aa`, border: `1px solid ${th.border}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", overflow: "hidden" }}>
                      <button
                        onClick={() => setModal((p) => p ? { ...p, usnIncidentsExpanded: !p.usnIncidentsExpanded } : p)}
                        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, width: "100%", padding: "12px 14px", background: "transparent", border: "none", color: th.text, cursor: "pointer", textAlign: "left" }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ transform: modal.usnIncidentsExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.15s ease", flexShrink: 0 }}><polyline points="3,1 7,5 3,9" /></svg>
                          <div>
                            <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Directory Incidents</div>
                            <div style={{ fontSize: 10, color: th.textDim }}>{visibleIncidents.length} clustered hotspots across the selected window</div>
                          </div>
                        </div>
                        <span style={tagPill(`${visibleIncidents.length}`, "#D4956A")}>{visibleIncidents.length}</span>
                      </button>
                      {modal.usnIncidentsExpanded && (
                        <div style={{ display: "grid", gap: 10, padding: "0 14px 12px" }}>
                          {visibleIncidents.map((inc) => {
                            const sev = incidentSeverity(inc.priorityScore || inc.riskScore || 0);
                            return (
                              <div key={inc.key} style={{ border: `1px solid ${sev.color}28`, borderRadius: 10, padding: "10px 12px", background: `linear-gradient(135deg, ${sev.color}0c, transparent)` }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                                  <span style={{ ...tagPill(sev.label, sev.color), textTransform: "uppercase" }}>{sev.label}</span>
                                  <span style={{ fontSize: 13, color: th.text, fontWeight: 700 }}>{inc.title}</span>
                                  <span style={{ ...tagPill(`${inc.eventCount} events / ${inc.uniqueFiles} files`, "#E8A050") }}>{inc.eventCount} events / {inc.uniqueFiles} files</span>
                                  <span style={{ color: th.textDim, fontSize: 10, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{inc.start?.slice(0, 19)} → {inc.end?.slice(0, 19)}</span>
                                </div>
                                <div style={{ fontSize: 11, color: th.textDim, marginBottom: 8, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{inc.path}</div>
                                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                                  {(inc.reasons || []).slice(0, 4).map((r) => <span key={r} style={tagPill(r, sev.color)}>{r}</span>)}
                                  {(inc.topExtensions || []).slice(0, 3).map((e) => <span key={e.ext} style={tagPill(`${e.ext || "(none)"} ×${e.count}`, "#D4956A")}>{e.ext || "(none)"} ×{e.count}</span>)}
                                  {(inc.correlationTags || []).slice(0, 4).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                                </div>
                                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                  <button onClick={() => focusUsnDirectory(inc.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Show Only This Directory</button>
                                  <button onClick={() => focusUsnIncidentTimeline(inc.key)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Show All Events in Timeline</button>
                                  <button onClick={() => {
                                    const firstEntry = inc.events?.find((ev) => ev.entryNumber)?.entryNumber || "";
                                    focusUsnChain(firstEntry);
                                  }} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!inc.events?.some((ev) => ev.entryNumber)}>Show File Chain</button>
                                  <button onClick={() => showUsnParentDirectory(inc.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(inc.path)}>Show Parent Directory</button>
                                  <button onClick={() => showUsnSiblingActivity(inc.path)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(inc.path)}>Show Sibling Activity</button>
                                  <button onClick={() => navigator.clipboard?.writeText(JSON.stringify(inc, null, 2))} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Copy JSON</button>
                                  {hasCorrTag(inc.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open ADS</button>}
                                  {hasCorrTag(inc.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Timestomp</button>}
                                  {hasCorrTag(inc.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Persistence</button>}
                                  {(hasCorrTag(inc.correlationTags, "archive-staging") || hasCorrTag(inc.correlationTags, "overwrite-burst") || hasCorrTag(inc.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Ransomware</button>}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}

                  {focusedChain && (
                    <div style={{ marginBottom: 16, padding: "12px 14px", borderRadius: 12, background: `linear-gradient(135deg, ${(th.warning || "#d29922")}0f, ${th.modalBg}88)`, border: `1px solid ${(th.warning || "#d29922")}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)" }}>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                        <div>
                          <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Per-File Reconstruction</div>
                          <div style={{ fontSize: 13, color: th.text, fontWeight: 700 }}>{focusedChain.title}</div>
                        </div>
                        <button onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: "" } : p)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Close</button>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 10 }}>
                        {[
                          { label: "Entry", value: focusedChain.entryNumber || "—" },
                          { label: "First Seen", value: focusedChain.firstSeen?.slice(0, 19) || "—" },
                          { label: "Last Seen", value: focusedChain.lastSeen?.slice(0, 19) || "—" },
                          { label: "Events", value: String(focusedChain.eventCount || 0) },
                        ].map((s) => (
                          <div key={s.label} style={{ padding: "8px 10px", borderRadius: 8, background: `${th.panelBg}88`, border: `1px solid ${th.border}18` }}>
                            <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{s.label}</div>
                            <div style={{ fontSize: 12, color: th.text, fontWeight: 700, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{s.value}</div>
                          </div>
                        ))}
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr 1fr 1fr", gap: 10, marginBottom: 10 }}>
                        {[
                          { label: "Primary Directory", value: focusedChain.primaryDirectory || "—" },
                          { label: "Path Variants", value: String(focusedChain.pathTransitions?.length || focusedChain.paths?.length || 0) },
                          { label: "Same-Dir Artifacts", value: String(focusedChain.sameDirectoryChainCount || 0) },
                          { label: "Primary Path", value: focusedChain.primaryPath || "—" },
                        ].map((s) => (
                          <div key={s.label} style={{ padding: "8px 10px", borderRadius: 8, background: `${th.panelBg}88`, border: `1px solid ${th.border}18` }}>
                            <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em" }}>{s.label}</div>
                            <div style={{ fontSize: 11, color: th.text, fontWeight: 600, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.value}</div>
                          </div>
                        ))}
                      </div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
                        {(focusedChain.reasonBuckets || []).map((r) => <span key={r} style={tagPill(r, "#E8A050")}>{r}</span>)}
                        {(focusedChain.correlationTags || []).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                        {(focusedChain.categories || []).map((c) => <span key={c} style={tagPill(c, "#D4783A")}>{c}</span>)}
                      </div>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                        <button onClick={() => focusUsnDirectory(focusedChain.primaryDirectory || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!focusedChain.primaryDirectory}>This Directory</button>
                        <button onClick={() => showUsnParentDirectory(focusedChain.primaryDirectory || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(focusedChain.primaryDirectory || "")}>Parent Directory</button>
                        <button onClick={() => showUsnSiblingActivity(focusedChain.primaryDirectory || "")} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }} disabled={!parentDirOf(focusedChain.primaryDirectory || "")}>Sibling Activity</button>
                        <button onClick={() => navigator.clipboard?.writeText(JSON.stringify(focusedChain, null, 2))} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Copy JSON</button>
                        {hasCorrTag(focusedChain.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open ADS</button>}
                        {hasCorrTag(focusedChain.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Timestomp</button>}
                        {hasCorrTag(focusedChain.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Persistence</button>}
                        {(hasCorrTag(focusedChain.correlationTags, "archive-staging") || hasCorrTag(focusedChain.correlationTags, "overwrite-burst") || hasCorrTag(focusedChain.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Open Ransomware</button>}
                      </div>
                      {focusedChain.renamePairs?.length > 0 && (
                        <div style={{ marginBottom: 10 }}>
                          <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Rename Chain</div>
                          <div style={{ display: "grid", gap: 4 }}>
                            {focusedChain.renamePairs.slice(0, 20).map((r, i) => (
                              <div key={i} style={{ fontSize: 11, color: th.text, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{r.timestamp?.slice(0, 19)} — {r.oldName} → {r.newName}</div>
                            ))}
                          </div>
                        </div>
                      )}
                      {focusedChain.siblingArtifacts?.length > 0 && (
                        <div style={{ marginBottom: 10 }}>
                          <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Other High-Signal Artifacts In This Directory</div>
                          <div style={{ display: "grid", gap: 4 }}>
                            {focusedChain.siblingArtifacts.map((sib) => (
                              <button key={sib.key} onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: sib.key, usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: "" } : p)} style={{ background: `${th.border}10`, border: `1px solid ${th.border}18`, borderRadius: 8, padding: "6px 8px", cursor: "pointer", color: th.text, textAlign: "left", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, fontSize: 11 }}>{sib.title}</span>
                                <span style={{ ...tagPill(`${sib.eventCount} ev`, "#D4956A"), flexShrink: 0 }}>{sib.eventCount} ev</span>
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                      <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Event Sequence</div>
                      <div style={{ display: "grid", gap: 4, maxHeight: 220, overflow: "auto" }}>
                        {(focusedChain.events || []).slice(0, 150).map((ev, i) => (
                          <div key={i} style={{ display: "grid", gridTemplateColumns: "160px 120px 1fr", gap: 8, fontSize: 11, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", color: th.text }}>
                            <span style={{ color: th.textDim }}>{ev.timestamp?.slice(0, 19)}</span>
                            <span style={{ color: "#E8A050" }}>{ev.reasonLabel}</span>
                            <span>{ev.displayName || ev.name}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {timelineRows.length > 0 && (
                    <div style={{ marginBottom: 16, borderRadius: 12, background: `${th.panelBg}aa`, border: `1px solid ${th.border}22`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", overflow: "hidden" }}>
                      <div style={{ display: "flex", alignItems: "stretch", justifyContent: "space-between", gap: 10, padding: "12px 14px" }}>
                        <button
                          onClick={() => setModal((p) => p ? { ...p, usnTimelineExpanded: !p.usnTimelineExpanded } : p)}
                          style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0, background: "transparent", border: "none", color: th.text, cursor: "pointer", textAlign: "left", padding: 0 }}
                        >
                          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" style={{ transform: modal.usnTimelineExpanded ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.15s ease", flexShrink: 0 }}><polyline points="3,1 7,5 3,9" /></svg>
                          <div style={{ minWidth: 0 }}>
                            <div style={{ fontSize: 11, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>Merged USN Storyline</div>
                            <div style={{ fontSize: 10, color: th.textDim }}>{timelineRows.length.toLocaleString()} of {filteredTimeline.length.toLocaleString()} suspicious events shown</div>
                          </div>
                        </button>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                          <span style={tagPill(`${filteredTimeline.length}`, "#D4956A")}>{filteredTimeline.length}</span>
                          {modal.usnTimelineExpanded && filteredTimeline.length > timelineRows.length && <button onClick={() => setModal((p) => p ? { ...p, usnTimelineLimit: (p.usnTimelineLimit || 120) + 120 } : p)} style={{ ...ms.bs, padding: "4px 8px", fontSize: 10 }}>Load More</button>}
                        </div>
                      </div>
                      {modal.usnTimelineExpanded && (
                        <div style={{ display: "grid", gap: 4, maxHeight: 280, overflow: "auto", padding: "0 14px 12px" }}>
                          {timelineRows.map((ev) => (
                            <div key={ev.key} style={{ display: "grid", gridTemplateColumns: "145px 125px 1fr 190px auto auto", gap: 8, alignItems: "center", padding: "6px 8px", borderRadius: 8, border: `1px solid ${th.border}12`, background: `${th.border}08`, color: th.text }}>
                              <span style={{ fontSize: 11, color: th.textDim, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{ev.timestamp?.slice(0, 19)}</span>
                              <span style={{ fontSize: 10, color: "#E8A050", fontWeight: 700 }}>{ev.reasonLabel}</span>
                              <button onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: String(ev.entryNumber || ""), usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: timelineIncidentKey } : p)} style={{ background: "none", border: "none", color: th.text, cursor: "pointer", textAlign: "left", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", padding: 0 }}>{ev.displayName || ev.name}</button>
                              <span style={{ fontSize: 10, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace" }}>{ev.parentPath}</span>
                              <span style={{ display: "flex", gap: 4, flexWrap: "wrap", justifyContent: "flex-end" }}>
                                {(ev.correlationTags || []).slice(0, 3).map((t) => <span key={t.key} style={tagPill(t.label, corrColor(t.key))}>{t.label}</span>)}
                              </span>
                              <span style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
                                <button onClick={() => setModal((p) => p ? { ...p, usnFocusEntry: String(ev.entryNumber || ""), usnScopeDir: "", usnSiblingDir: "", usnTimelineIncident: timelineIncidentKey } : p)} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>File Chain</button>
                                <button onClick={() => setModal((p) => p ? { ...p, usnScopeDir: ev.parentPath || "", usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "" } : p)} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }} disabled={!ev.parentPath}>This Dir</button>
                                <button onClick={() => showUsnParentDirectory(ev.parentPath || "")} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }} disabled={!parentDirOf(ev.parentPath || "")}>Parent</button>
                                <button onClick={() => showUsnSiblingActivity(ev.parentPath || "")} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }} disabled={!parentDirOf(ev.parentPath || "")}>Siblings</button>
                                {hasCorrTag(ev.correlationTags, "downloaded") && adsCapable && <button onClick={launchAdsFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>ADS</button>}
                                {hasCorrTag(ev.correlationTags, "timestomp") && timestompCapable && <button onClick={launchTimestompFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>Timestomp</button>}
                                {hasCorrTag(ev.correlationTags, "persistence-related") && persistenceTab && <button onClick={launchPersistenceFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>Persistence</button>}
                                {(hasCorrTag(ev.correlationTags, "archive-staging") || hasCorrTag(ev.correlationTags, "overwrite-burst") || hasCorrTag(ev.correlationTags, "deleted-in-mft")) && ransomwareCapable && <button onClick={launchRansomwareFromUsn} style={{ ...ms.bs, padding: "3px 6px", fontSize: 9 }}>Ransomware</button>}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  {/* Analysis sections */}
                  {usnSections.map((sec) => renderSection(sec))}

                  {/* Column filter dropdown panel — uses separate state (usnFd) to avoid re-rendering all sections */}
                  {usnFd && (() => {
                    const fd = usnFd;
                    const fdSec = usnSections.find((s) => s.key === fd.secKey);
                    if (!fd.values) return null;

                    const fdSearch = fd.search || "";
                    const fdValues = fdSearch
                      ? fd.values.filter((v) => (v.val || "").toLowerCase().includes(fdSearch.toLowerCase()))
                      : fd.values;
                    const fdSelected = fd.selected || new Set(fd.values.map((v) => v.val));
                    const fdLeft = fd.dx ?? Math.min(fd.x, window.innerWidth - 360);
                    const fdTop = fd.dy ?? Math.min(fd.y, window.innerHeight - 400);
                    // Cap rendered items; the rest are still in fdValues for Select All / count
                    const RENDER_CAP = 200;
                    const fdVisible = fdValues.slice(0, RENDER_CAP);

                    return (
                      <>
                        <div onClick={() => setUsnFd(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
                        <div ref={(el) => { if (el) el.__usnFdPanel = true; }} onClick={(e) => e.stopPropagation()} style={{
                          WebkitAppRegion: "no-drag", position: "fixed",
                          left: fdLeft, top: fdTop,
                          width: 340, height: 380, minWidth: 240, minHeight: 180, maxWidth: "90vw", maxHeight: "90vh",
                          background: th.modalBg, border: `1px solid ${fdSec?.color || th.accent}33`,
                          borderRadius: 10, boxShadow: `0 12px 28px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.03) inset`,
                          zIndex: 200, display: "flex", flexDirection: "column", overflow: "hidden", resize: "both",
                          backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)"
                        }}>
                          {/* Draggable header — uses direct DOM transform for zero-lag dragging */}
                          <div style={{ padding: "6px 10px", flexShrink: 0, display: "flex", alignItems: "center", gap: 6, borderBottom: `1px solid ${th.border}30`, cursor: "grab", userSelect: "none", background: `linear-gradient(135deg, ${fdSec?.color || th.accent}0a, transparent)` }}
                            onMouseDown={(e) => {
                              if (e.button !== 0) return;
                              e.preventDefault();
                              const panel = e.currentTarget.parentElement;
                              const startX = e.clientX, startY = e.clientY;
                              const startLeft = panel.offsetLeft, startTop = panel.offsetTop;
                              const onMove = (ev) => {
                                const nx = startLeft + (ev.clientX - startX);
                                const ny = startTop + (ev.clientY - startY);
                                panel.style.left = nx + "px";
                                panel.style.top = ny + "px";
                              };
                              const onUp = (ev) => {
                                document.removeEventListener("mousemove", onMove);
                                document.removeEventListener("mouseup", onUp);
                                // Persist final position to state
                                const nx = startLeft + (ev.clientX - startX);
                                const ny = startTop + (ev.clientY - startY);
                                setUsnFd((p) => p ? { ...p, dx: nx, dy: ny } : p);
                              };
                              document.addEventListener("mousemove", onMove);
                              document.addEventListener("mouseup", onUp);
                            }}>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={fdSec?.color || th.accent} strokeWidth="1.8" strokeLinecap="round"><polygon points="22,3 2,3 10,12.46 10,19 14,21 14,12.46"/></svg>
                            <span style={{ color: th.textDim, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "'Segoe UI', system-ui, sans-serif", flex: 1 }}>Filter — {(getColumns(fd.secKey).find((c) => c.key === fd.colKey)?.label) || fd.colKey}</span>
                            <button onClick={() => setUsnFd(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, padding: "0 2px", lineHeight: 1 }}>✕</button>
                          </div>
                          {/* Search input */}
                          <div style={{ padding: "8px 8px 4px", flexShrink: 0 }}>
                            <input value={fdSearch} onChange={(e) => setUsnFd((p) => p ? { ...p, search: e.target.value } : p)}
                              placeholder="Search values..." autoFocus
                              style={{ width: "100%", background: th.bgInput || `${th.border}22`, border: `1px solid ${th.border}66`, borderRadius: 5, color: th.text, fontSize: 11, padding: "5px 8px", outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
                          </div>
                          {/* Select All / Clear */}
                          <div style={{ display: "flex", gap: 4, padding: "2px 8px 4px", flexShrink: 0, alignItems: "center" }}>
                            <button onClick={() => setUsnFd((p) => p ? { ...p, selected: new Set(fdValues.map((v) => v.val)) } : p)}
                              style={{ padding: "2px 7px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 4, color: th.textDim, fontSize: 9, cursor: "pointer", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Select All</button>
                            <button onClick={() => setUsnFd((p) => p ? { ...p, selected: new Set() } : p)}
                              style={{ padding: "2px 7px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 4, color: th.textDim, fontSize: 9, cursor: "pointer", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Clear</button>
                            <span style={{ flex: 1 }} />
                            <span style={{ color: th.textMuted, fontSize: 9 }}>{fdValues.length} values</span>
                          </div>
                          {/* Checkbox list — capped at {RENDER_CAP} for performance */}
                          <div style={{ flex: 1, overflow: "auto", padding: "0 4px" }}>
                            {fdValues.length === 0 ? (
                              <div style={{ padding: 16, textAlign: "center", color: th.textMuted, fontSize: 11 }}>No values found</div>
                            ) : (<>
                              {fdVisible.map((v) => (
                                <label key={v.val ?? "__empty"} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 6px", cursor: "pointer", borderRadius: 4, fontSize: 11, color: th.text }}
                                  onMouseEnter={(e) => { e.currentTarget.style.background = `${fdSec?.color || th.accent}0a`; }}
                                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                                  <input type="checkbox" checked={fdSelected.has(v.val)}
                                    onChange={() => {
                                      const s = new Set(fdSelected);
                                      s.has(v.val) ? s.delete(v.val) : s.add(v.val);
                                      setUsnFd((p) => p ? { ...p, selected: s } : p);
                                    }}
                                    style={{ accentColor: fdSec?.color || th.accent, flexShrink: 0 }} />
                                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", fontSize: 10 }}>{v.val || "(empty)"}</span>
                                  <span style={{ color: th.textMuted, fontSize: 9, flexShrink: 0 }}>{v.cnt.toLocaleString()}</span>
                                </label>
                              ))}
                              {fdValues.length > RENDER_CAP && (
                                <div style={{ padding: "6px 6px", fontSize: 9, color: th.textMuted, textAlign: "center", fontStyle: "italic" }}>
                                  Showing top {RENDER_CAP} of {fdValues.length} — use search to narrow
                                </div>
                              )}
                            </>)}
                          </div>
                          {/* Footer buttons */}
                          <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, padding: "6px 8px", borderTop: `1px solid ${th.border}22` }}>
                            <button onClick={() => {
                              // Reset — remove this column's filter
                              setModal((p) => {
                                if (!p) return p;
                                const newF = { ...(p.usnCheckboxFilters || {}) };
                                const secF = { ...(newF[fd.secKey] || {}) };
                                delete secF[fd.colKey];
                                newF[fd.secKey] = secF;
                                return { ...p, usnCheckboxFilters: newF };
                              });
                              setUsnFd(null);
                            }} style={{ padding: "3px 10px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 5, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Reset</button>
                            <button onClick={() => setUsnFd(null)} style={{ padding: "3px 10px", background: "none", border: `1px solid ${th.border}44`, borderRadius: 5, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Cancel</button>
                            <button onClick={() => {
                              // Apply — save selected values as filter, then close
                              const selSet = usnFd?.selected;
                              const totalUniqueCount = usnFd?.values?.length || 0;
                              setModal((p) => {
                                if (!p) return p;
                                const newF = { ...(p.usnCheckboxFilters || {}) };
                                if (!selSet || selSet.size === 0 || selSet.size >= totalUniqueCount) {
                                  const secF = { ...(newF[fd.secKey] || {}) };
                                  delete secF[fd.colKey];
                                  newF[fd.secKey] = secF;
                                } else {
                                  newF[fd.secKey] = { ...(newF[fd.secKey] || {}), [fd.colKey]: selSet };
                                }
                                return { ...p, usnCheckboxFilters: newF, usnSelected: { ...p.usnSelected, [fd.secKey]: new Set() } };
                              });
                              setUsnFd(null);
                            }} style={{ padding: "3px 12px", background: fdSec?.color || th.accent, color: "#fff", border: "none", borderRadius: 5, fontSize: 10, cursor: "pointer", fontWeight: 600, fontFamily: "'Segoe UI', system-ui, sans-serif" }}>Apply</button>
                          </div>
                        </div>
                      </>
                    );
                  })()}
                </>)}
              </div>

              {/* Footer — glass bar */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}18`, display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 8, flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}aa, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)" }}>
                {phase === "input" && (<>
                  <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                  <button onClick={handleAnalyze} disabled={!modal.startTime || !Object.values(modal.analyses).some(Boolean)} style={{ ...ms.bp, opacity: !modal.startTime ? 0.5 : 1 }}>Analyze</button>
                </>)}
                {phase === "loading" && <span style={{ fontSize: 11, color: th.textMuted }}>Running queries...</span>}
                {phase === "results" && (<>
                  {totalSelected > 0 && <span style={{ fontSize: 10, color: th.accent, fontFamily: "'Cascadia Code','Consolas','Courier New',monospace", marginRight: "auto" }}>{totalSelected} selected</span>}
                  <button onClick={() => { setModal((p) => ({ ...p, phase: "input", data: null, usnSelected: {}, usnSort: {}, usnCheckboxFilters: {}, usnLikelyFindingsExpanded: false, usnShowSuppressed: {}, usnScopeDir: "", usnSiblingDir: "", usnFocusEntry: "", usnTimelineIncident: "", usnTimelineLimit: 120 })); setUsnFd(null); }} style={ms.bs}>Back</button>
                  {totalSelected > 0 && <button onClick={copySelected} style={{ ...ms.bs, borderColor: `${th.accent}44`, color: th.accent }}>Copy Selected ({totalSelected})</button>}
                  {visibleIncidents.length > 0 && <button onClick={copyVisibleUsnIncidentsJson} style={ms.bs}>Copy Incidents JSON</button>}
                  <button onClick={copyReport} style={ms.bs}>Copy Summary</button>
                  <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                </>)}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Context Menu */}
      {contextMenu && renderContextPortal(
        <>
          <div onMouseDown={(e) => { if (shouldCloseContextBackdrop(e)) setContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 99998 }} />
          <div onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }} style={{ position: "fixed", left: contextMenu.x, top: contextMenu.y, background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", zIndex: 99999, boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 200, animation: "tle-modal-in var(--m-fast) var(--ease-out)" }}>
            {[
              ...(contextMenu.colName !== "__tags__" ? [
                { label: (ct?.pinnedColumns || []).includes(contextMenu.colName) ? "Unpin Column" : "Pin Column",
                  icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 17v5M9 11l-4 4h14l-4-4V5a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v6z"/></svg>,
                  action: () => (ct?.pinnedColumns || []).includes(contextMenu.colName) ? unpinColumn(contextMenu.colName) : pinColumn(contextMenu.colName) },
                { label: "Hide Column",
                  icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
                  action: () => up("hiddenColumns", new Set([...(ct?.hiddenColumns || []), contextMenu.colName])) },
                null,
              ] : []),
              { label: "Best Fit",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M21 12H3M21 12l-4-4M21 12l-4 4M3 12l4-4M3 12l4 4"/></svg>,
                action: () => autoFitColumn(contextMenu.colName) },
              { label: "Best Fit (All Columns)",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M22 12H2M22 12l-3-3M22 12l-3 3M2 12l3-3M2 12l3 3M12 2v20"/></svg>,
                action: () => autoFitAllColumns() },
              { label: "Reset Column Widths",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>,
                action: () => resetColumnWidths() },
              null,
              { label: "Sort Ascending",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg>,
                action: () => { up("sortCol", contextMenu.colName); up("sortDir", "asc"); } },
              { label: "Sort Descending",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 5v14M19 12l-7 7-7-7"/></svg>,
                action: () => { up("sortCol", contextMenu.colName); up("sortDir", "desc"); } },
              null,
              { label: selectedColumn === contextMenu.colName ? "Deselect Column" : "Select Column",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="8" y="3" width="8" height="18" rx="1" fill={`${th.accent}22`}/><path d="M4 3v18M20 3v18" opacity="0.4"/></svg>,
                action: () => setSelectedColumn(selectedColumn === contextMenu.colName ? null : contextMenu.colName) },
              { label: "Copy Column Values",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>,
                action: () => copyColumnValues(contextMenu.colName, { distinct: false }) },
              { label: "Copy Unique Values",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M20 6L9 17l-5-5"/></svg>,
                action: () => copyColumnValues(contextMenu.colName, { distinct: true }) },
              null,
              { label: "Stack Values", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="3" y="3" width="18" height="4" rx="1"/><rect x="3" y="10" width="14" height="4" rx="1"/><rect x="3" y="17" width="8" height="4" rx="1"/></svg>, action: () => {
                setModal(openStackingModal(contextMenu.colName));
                const af = activeFilters(ct);
                tle.getStackingData(ct.id, contextMenu.colName, {
                  searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                  columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                  bookmarkedOnly: ct.showBookmarkedOnly,
                  tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
                  rowIdFilter: ct.rowIdFilter || null,
                  dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                  sortBy: "count",
                }).then((result) => {
                  if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
                  setModal(updateModal("stacking", { data: result, loading: false, error: null }));
                })
                  .catch((err) => setModal(updateModal("stacking", { loading: false, data: null, error: String(err?.message || err || "Stacking analysis failed") })));
              }},
              null,
              { label: "Column Stats", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="3" y="12" width="4" height="9" rx="1"/><rect x="10" y="6" width="4" height="15" rx="1"/><rect x="17" y="3" width="4" height="18" rx="1"/></svg>, action: () => {
                setModal(openColumnStatsModal(contextMenu.colName));
                const af = activeFilters(ct);
                tle.getColumnStats(ct.id, contextMenu.colName, {
                  searchTerm: effectiveSearchTerm(ct.searchHighlight ? "" : ct.searchTerm), searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                  columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                  bookmarkedOnly: ct.showBookmarkedOnly,
                  tagFilter: (ct.disabledFilters || new Set()).has("__tags__") ? null : (ct.tagFilter || null),
                  rowIdFilter: ct.rowIdFilter || null,
                  dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                }).then((result) => {
                  if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
                  setModal(updateModal("columnStats", { data: result, loading: false, error: null }));
                })
                  .catch((err) => setModal(updateModal("columnStats", { loading: false, data: null, error: String(err?.message || err || "Column statistics failed") })));
              }},
            ].map((item, i) =>
              item === null ? (
                <div key={i} style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
              ) : (
                <button key={i} onClick={() => { item.action(); setContextMenu(null); }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)", letterSpacing: "-0.01em" }}>
                  <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{item.icon}</span>
                  {item.label}
                </button>
              )
            )}
          </div>
        </>
      )}

      {/* Row Context Menu (for tagging) */}
      {rowContextMenu && renderContextPortal(
        <>
          <div onMouseDown={(e) => { if (shouldCloseContextBackdrop(e)) setRowContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 99998 }} />
          <div onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }} style={{ position: "fixed", left: Math.min(rowContextMenu.x, window.innerWidth - 220), top: Math.min(rowContextMenu.y, window.innerHeight - 300), background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", zIndex: 99999, boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 200, animation: "tle-modal-in var(--m-fast) var(--ease-out)" }}>
            {rowContextMenu.cellColumn && (
              <button onClick={() => { copyCell(rowContextMenu.cellValue, rowContextMenu.cellColumn); setRowContextMenu(null); }}
                onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📋</span>
                Copy Cell <span style={{ color: th.textMuted, fontSize: 10, marginLeft: "auto", maxWidth: 80, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{rowContextMenu.cellColumn}</span>
              </button>
            )}
            {selectionCount > 1 && (
              <button onClick={() => {
                setRowContextMenu(null);
                void copySelectedRows();
              }}
                onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📑</span>
                Copy Selected Rows
                <span style={{ color: th.textMuted, fontSize: 10, marginLeft: "auto" }}>{formatNumber(selectionCount)}</span>
              </button>
            )}
            <button onClick={() => {
              if (rowContextMenu.row && ct) {
                const hdrs = ct.headers.filter((h) => !ct.hiddenColumns?.has(h));
                const line = hdrs.map((h) => fmtCell(h, rowContextMenu.row[h] || "").replace(/\t/g, " ")).join("\t");
                navigator.clipboard?.writeText(hdrs.join("\t") + "\n" + line);
                setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200);
              }
              setRowContextMenu(null);
            }}
              onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
              <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📄</span>
              {selectionCount > 1 ? "Copy This Row" : "Copy Row"}
            </button>
            {/* Filter in / Filter out */}
            {rowContextMenu.cellColumn && (
              <>
                <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
                <div style={{ padding: "4px 14px 2px", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Filters</div>
                <button onClick={() => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const newCbf = { ...t.checkboxFilters };
                    newCbf[rowContextMenu.cellColumn] = [rowContextMenu.cellValue];
                    return { ...t, checkboxFilters: newCbf };
                  }));
                  setRowContextMenu(null);
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                  <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg></span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>Filter in {rowContextMenu.cellValue ? String(rowContextMenu.cellValue).slice(0, 40) : "(empty)"}</span>
                </button>
                <button onClick={() => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const af = [...(t.advancedFilters || [])];
                    af.push({ column: rowContextMenu.cellColumn, operator: "not_equals", value: rowContextMenu.cellValue, logic: "AND" });
                    return { ...t, advancedFilters: af };
                  }));
                  setRowContextMenu(null);
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                  <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/><line x1="4" y1="21" x2="20" y2="5"/></svg></span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>Filter out {rowContextMenu.cellValue ? String(rowContextMenu.cellValue).slice(0, 40) : "(empty)"}</span>
                </button>
              </>
            )}
            <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
            {/* Tags — collapsible submenu */}
            {(() => {
              const tagEntries = Object.entries(ct?.tagColors || {});
              const hasExplicitMultiSelection = !allRowsSelected
                && selectionCount > 1
                && selectedRows.has(Number(rowContextMenu.rowId));
              return (
                <div style={{ position: "relative" }}
                  onMouseEnter={(e) => { const sub = e.currentTarget.querySelector("[data-tag-sub]"); if (sub) sub.style.display = "block"; }}
                  onMouseLeave={(e) => { const sub = e.currentTarget.querySelector("[data-tag-sub]"); if (sub) sub.style.display = "none"; }}>
                  <button
                    onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                    <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>🏷</span>
                    Tags{hasExplicitMultiSelection ? ` (${selectionCount} rows)` : ""}
                    <span style={{ marginLeft: "auto", color: th.textMuted, fontSize: 11 }}>▸</span>
                  </button>
                  {/* Tags submenu */}
                  <div data-tag-sub="" style={{ display: "none", position: "absolute", left: "100%", top: -5, background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 160, zIndex: 100000 }}>
                    {tagEntries.map(([tag, color]) => {
                      const hasTg = rowContextMenu.currentTags.includes(tag);
                      return (
                        <button key={tag} onClick={async () => {
                          // Collect target row IDs — all selected rows if multi-selected, otherwise just the clicked row
                          const targetIds = [];
                          if (hasExplicitMultiSelection) {
                            targetIds.push(...selectedRows);
                          } else {
                            targetIds.push(rowContextMenu.rowId);
                          }
                          const newTags = { ...ct.rowTags };
                          for (const rid of targetIds) {
                            const rowTags = newTags[rid] || [];
                            const rowHas = rowTags.includes(tag);
                            if (rowHas) {
                              await tle.removeTag(ct.id, rid, tag);
                              newTags[rid] = rowTags.filter((t) => t !== tag);
                            } else {
                              await tle.addTag(ct.id, rid, tag);
                              newTags[rid] = [...rowTags, tag];
                            }
                          }
                          up("rowTags", newTags);
                          setRowContextMenu(null);
                        }}
                          onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                          onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                          style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                          <span style={{ color, fontSize: 14 }}>{hasTg ? "●" : "○"}</span>
                          <span>{tag}</span>
                        </button>
                      );
                    })}
                    <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
                    <button onClick={() => { setRowContextMenu(null); setModal(openSimpleModal("tags")); }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                      style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 14px", background: "none", border: "none", color: th.textDim, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)" }}>
                      Manage Tags...
                    </button>
                  </div>
                </div>
              );
            })()}
            {/* VT Lookup for cell value */}
            {rowContextMenu.cellValue && (() => {
              const val = String(rowContextMenu.cellValue).trim();
              let vtCat = null;
              for (const [cat, re] of IOC_CATEGORY_PATTERNS) {
                if (re.test(val) && VT_COMPATIBLE_RE.test(cat)) { vtCat = cat; break; }
              }
              if (!vtCat) {
                const domainRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?){1,}$/i;
                if (domainRe.test(val) && val.includes(".")) vtCat = "Domain_Name";
              }
              if (!vtCat) return null;
              return (<>
                <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
                <button onClick={async () => {
                  setRowContextMenu(null);
                  const status = await tle.vtGetApiKey();
                  if (!status?.hasKey) {
                    setCopiedMsg("Set VT API key in IOC Matching"); setTimeout(() => setCopiedMsg(false), 2500);
                    return;
                  }
                  setCopiedMsg("Looking up on VT..."); setTimeout(() => setCopiedMsg(false), 2000);
                  const result = await tle.vtLookupSingle(val, vtCat);
                  if (result?.error) {
                    setCopiedMsg(`VT: ${result.error}`); setTimeout(() => setCopiedMsg(false), 3000);
                  } else if (result?.vtUrl) {
                    setCopiedMsg(`VT: ${result.score} (${result.verdict})`); setTimeout(() => setCopiedMsg(false), 3000);
                    window.open(result.vtUrl, "_blank");
                  } else {
                    setCopiedMsg(`VT: ${result?.score || "N/A"}`); setTimeout(() => setCopiedMsg(false), 3000);
                  }
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>🔍</span>
                  Lookup on VirusTotal
                </button>
              </>);
            })()}
            {/* Decode Base64 PowerShell */}
            {rowContextMenu.cellValue && (() => {
              const cv = String(rowContextMenu.cellValue);
              const encMatch = cv.match(/(?:\s|^)(?:-e|-enc|-encodedcommand|-en|-ec)\s+([A-Za-z0-9+/=]{20,})/i);
              if (!encMatch) return null;
              return (<>
                <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
                <button onClick={() => {
                  try {
                    const bytes = Uint8Array.from(atob(encMatch[1]), (c) => c.charCodeAt(0));
                    const decoded = new TextDecoder("utf-16le").decode(bytes);
                    setRowContextMenu(null);
                    setCellPopup({ column: "Decoded PowerShell (-enc)", value: decoded });
                  } catch {
                    setCopiedMsg("Failed to decode Base64"); setTimeout(() => setCopiedMsg(false), 2000);
                    setRowContextMenu(null);
                  }
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.danger, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>{'</>'}</span>
                  Decode Base64 PowerShell
                </button>
              </>);
            })()}
            {ct?.tsColumns?.size > 0 && (<>
              <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
              <button onClick={() => {
                const tsCols = [...(ct?.tsColumns || new Set())];
                const autoCol = (ct?.sortCol && ct.tsColumns.has(ct.sortCol)) ? ct.sortCol : tsCols[0];
                setRowContextMenu(null);
                setModal(openProximityModal({ pivotRow: rowContextMenu.row, pivotCol: autoCol }));
              }}
                onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "'Segoe UI', system-ui, sans-serif" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>⏱</span>
                Find Nearby Events...
              </button>
            </>)}
          </div>
        </>
      )}

      {/* Cell Context Menu (Cmd+Click) — Filter in / Filter out / Hide column */}
      {cellContextMenu && renderContextPortal(
        <>
          <div onMouseDown={(e) => { if (shouldCloseContextBackdrop(e)) setCellContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 99998 }} />
          <div onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }} style={{ position: "fixed", left: Math.min(cellContextMenu.x, window.innerWidth - 240), top: Math.min(cellContextMenu.y, window.innerHeight - 160), background: themeName === "dark" ? "rgba(28,31,36,0.97)" : "rgba(252,252,254,0.97)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", zIndex: 99999, boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 200, animation: "tle-modal-in var(--m-fast) var(--ease-out)" }}>
            <div style={{ padding: "4px 14px 2px", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Filters</div>
            {[
              { label: `Filter in ${cellContextMenu.cellValue ? String(cellContextMenu.cellValue).slice(0, 40) : "(empty)"}`,
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>,
                action: () => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const newCbf = { ...t.checkboxFilters };
                    newCbf[cellContextMenu.colName] = [cellContextMenu.cellValue];
                    return { ...t, checkboxFilters: newCbf };
                  }));
                }},
              { label: `Filter out ${cellContextMenu.cellValue ? String(cellContextMenu.cellValue).slice(0, 40) : "(empty)"}`,
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.danger} strokeWidth="2" strokeLinecap="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/><line x1="4" y1="21" x2="20" y2="5"/></svg>,
                action: () => {
                  setTabs((prev) => prev.map((t) => {
                    if (t.id !== activeTab) return t;
                    const af = [...(t.advancedFilters || [])];
                    af.push({ column: cellContextMenu.colName, operator: "not_equals", value: cellContextMenu.cellValue, logic: "AND" });
                    return { ...t, advancedFilters: af };
                  }));
                }},
            ].map((item, i) => (
              <button key={i} onClick={() => { item.action(); setCellContextMenu(null); }}
                onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)", letterSpacing: "-0.01em" }}>
                <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{item.icon}</span>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
              </button>
            ))}
            <div style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
            <div style={{ padding: "4px 14px 2px", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Columns</div>
            <button onClick={() => { up("hiddenColumns", new Set([...(ct?.hiddenColumns || []), cellContextMenu.colName])); setCellContextMenu(null); }}
              onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 6, margin: "0 4px", maxWidth: "calc(100% - 8px)", letterSpacing: "-0.01em" }}>
              <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </span>
              Hide column
            </button>
          </div>
        </>
      )}
    </div>
  );
}
