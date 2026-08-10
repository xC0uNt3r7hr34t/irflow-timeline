import { useRef } from "react";
import useTabStore from "../store/useTabStore.js";
import { formatNumber } from "../utils/format.js";

/**
 * TabBar — horizontal tab strip with per-tab scroll position tracking.
 *
 * Props:
 *   th             – theme object
 *   scrollTop      – current scroll position (saved per tab on switch)
 *   selectedRows   – stable selected row IDs (or select-all exceptions)
 *   allRowsSelected – whether the full filtered population is selected
 *   selectAllScopeSignature – filter signature bound to select-all
 *   lastClickedRow – last clicked row index
 *   setScrollTop   – setter for scroll position
 *   setSelectedRows – setter for selected rows
 *   setAllRowsSelected – setter for select-all mode
 *   setLastClickedRow – setter for last clicked row
 *   setProximityFilter – setter for proximity filter
 *   scrollRef      – ref to scroll container (to restore scroll position)
 *   closeTab       – function to close a tab by id
 */
export default function TabBar({
  th,
  scrollTop,
  selectedRows,
  allRowsSelected,
  selectionTabId,
  selectAllScopeSignature,
  lastClickedRow,
  setScrollTop,
  setSelectedRows,
  setAllRowsSelected,
  setSelectionTabId,
  setSelectAllScopeSignature,
  setLastClickedRow,
  setProximityFilter,
  scrollRef,
  closeTab,
}) {
  const tabs = useTabStore((s) => s.tabs);
  const activeTab = useTabStore((s) => s.activeTab);
  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const tabFilter = useTabStore((s) => s.tabFilter);
  const setTabFilter = useTabStore((s) => s.setTabFilter);

  const tabScrollPos = useRef({}); // Per-tab scroll/selection state
  const tabButtonRefs = useRef({});
  const visibleTabs = tabs.filter((t) => !tabFilter || t.name.toLowerCase().includes(tabFilter.toLowerCase()));
  const activeTabIsVisible = visibleTabs.some((t) => t.id === activeTab);

  const activateTab = (tabId) => {
    if (activeTab) tabScrollPos.current[activeTab] = { scrollTop, selectedRows, allRowsSelected, selectionTabId, selectAllScopeSignature, lastClickedRow };
    const saved = tabScrollPos.current[tabId];
    setActiveTab(tabId);
    setScrollTop(saved?.scrollTop || 0);
    setSelectedRows(saved?.selectedRows || new Set());
    setAllRowsSelected(saved?.allRowsSelected || false);
    setSelectionTabId(saved?.selectionTabId || null);
    setSelectAllScopeSignature(saved?.selectAllScopeSignature || null);
    setLastClickedRow(saved?.lastClickedRow ?? null);
    setProximityFilter(null);
    if (saved?.scrollTop && scrollRef.current) {
      requestAnimationFrame(() => { if (scrollRef.current) scrollRef.current.scrollTop = saved.scrollTop; });
    }
  };

  const handleTabKeyDown = (event, index) => {
    let nextIndex = null;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % visibleTabs.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + visibleTabs.length) % visibleTabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = visibleTabs.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    const next = visibleTabs[nextIndex];
    activateTab(next.id);
    requestAnimationFrame(() => tabButtonRefs.current[next.id]?.focus());
  };

  return (
    <div role="tablist" aria-label="Open timelines" style={{ display: "flex", alignItems: "center", gap: 4, padding: "4px 12px", background: th.toolbarBg, backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", borderBottom: `1px solid ${th.glassBorder}`, overflowX: "auto", flexShrink: 0 }}>
      {visibleTabs.map((t, index) => (
        <div className="tle-tab" key={t.id}
          style={{ display: "flex", alignItems: "center", cursor: "pointer", background: t.id === activeTab ? th.glassBg : "transparent", border: t.id === activeTab ? `1px solid ${th.glassBorder}` : "1px solid transparent", borderRadius: 8, boxShadow: t.id === activeTab ? `0 1px 3px rgba(0,0,0,0.15), inset 0 1px 0 ${th.glassBorder}` : "none" }}>
          <button
            ref={(node) => { if (node) tabButtonRefs.current[t.id] = node; }}
            role="tab"
            aria-selected={t.id === activeTab}
            aria-controls="timeline-grid"
            tabIndex={t.id === activeTab || (!activeTabIsVisible && index === 0) ? 0 : -1}
            onClick={() => activateTab(t.id)}
            onKeyDown={(event) => handleTabKeyDown(event, index)}
            style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 5px 5px 12px", minHeight: 28, cursor: "pointer", color: t.id === activeTab ? th.text : th.textDim, fontSize: 12, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", background: "transparent", border: "none" }}>
            {t.importing && <span aria-label="Importing" style={{ color: th.warning }}>⏳</span>}
            {t.id === activeTab && <span aria-hidden="true" style={{ width: 6, height: 6, borderRadius: 3, background: th.accent, flexShrink: 0 }} />}
            <span style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{t.name}</span>
            <span style={{ color: th.textMuted, fontSize: 11 }}>({formatNumber(t.totalRows || 0)})</span>
          </button>
          <button onClick={() => closeTab(t.id)} aria-label={`Close tab ${t.name}`} title={`Close ${t.name}`}
            onMouseEnter={(e) => { e.currentTarget.style.color = th.danger; e.currentTarget.style.background = th.danger + "1f"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = th.textMuted; e.currentTarget.style.background = "none"; }}
            style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 11, width: 26, height: 26, padding: 0, marginRight: 2, borderRadius: 4, transition: "background var(--m-fast) var(--ease-out), color var(--m-fast) var(--ease-out)" }}>✕</button>
        </div>
      ))}
      {tabs.length >= 3 && (
        <div style={{ display: "flex", alignItems: "center", marginLeft: "auto", flexShrink: 0, padding: "0 4px" }}>
          <input value={tabFilter} onChange={(e) => setTabFilter(e.target.value)}
            aria-label="Filter open timelines"
            placeholder="Filter tabs..."
            style={{ width: 110, padding: "3px 7px", background: th.glassBg, border: `1px solid ${th.glassBorder}`, borderRadius: 6, color: th.text, fontSize: 11, outline: "none", fontFamily: "-apple-system, sans-serif" }} />
          {tabFilter && <button aria-label="Clear tab filter" onClick={() => setTabFilter("")} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 11, width: 26, height: 26, padding: 0, marginLeft: 2 }}>✕</button>}
        </div>
      )}
    </div>
  );
}
