import { useCallback } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { formatNumber } from "../../utils/format.js";
import { Modal, ErrorState } from "../primitives/index.js";
import { updateModal } from "../../modals/modalRegistry.js";

export default function StackingModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const ct = useCurrentTab();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const up = useCallback((key, value) => {
    useTabStore.getState().updateActiveTab({ [key]: value });
  }, []);

  // Inline activeFilters helper
  const activeFilters = (tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  };

  if (modal?.type !== "stacking" || !ct) return null;

  const colName = modal.colName;
  const data = modal.data || { totalRows: 0, totalUnique: 0, values: [] };
  const filterText = modal.filterText || "";
  const sortBy = modal.sortBy || "count";
  const mw = modal.modalWidth || 860;
  const vw = modal.valueColW || 420;
  const maxCnt = data.values.length > 0 ? (sortBy === "count" ? (data.values[0]?.cnt || 1) : Math.max(...data.values.map((d) => d.cnt), 1)) : 1;
  const displayed = filterText
    ? data.values.filter((v) => String(v.val ?? "").toLowerCase().includes(filterText.toLowerCase()))
    : data.values;

  // Drag helpers for column and modal resize
  const onValColResize = (e) => {
    e.preventDefault();
    const startX = e.clientX, startW = vw;
    document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
    const onMove = (ev) => { setModal(updateModal("stacking", { valueColW: Math.max(120, startW + ev.clientX - startX) })); };
    const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
  };
  const onModalResize = (e) => {
    e.preventDefault(); e.stopPropagation();
    const startX = e.clientX, startW = mw;
    document.body.style.cursor = "ew-resize"; document.body.style.userSelect = "none";
    const el = document.getElementById("stacking-modal");
    const onMove = (ev) => { const nw = Math.max(500, Math.min(window.innerWidth - 40, startW + (ev.clientX - startX) * 2)); if (el) el.style.width = nw + "px"; };
    const onUp = (ev) => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); const nw = Math.max(500, Math.min(window.innerWidth - 40, startW + (ev.clientX - startX) * 2)); setModal(updateModal("stacking", { modalWidth: nw })); };
    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
  };
  const reloadStack = (col, sort) => {
    const af = activeFilters(ct);
    tle.getStackingData(ct.id, col, {
      searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
      sortBy: sort,
    }).then((result) => {
      if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
      setModal(updateModal("stacking", { data: result, loading: false, error: null }));
    })
      .catch((err) => setModal(updateModal("stacking", { loading: false, data: null, error: String(err?.message || err || "Stacking analysis failed") })));
  };

  return (
    <Modal
      width={mw}
      maxHeight="88vh"
      onClose={() => setModal(null)}
      bodyPadding={0}
      closeOnOverlay={false}
    >
      <div id="stacking-modal" style={{ display: "flex", flexDirection: "column", height: "100%", position: "relative" }}>
        {/* Right edge resize handle */}
        <div onMouseDown={onModalResize} style={{ position: "absolute", top: 12, bottom: 12, right: -3, width: 6, cursor: "ew-resize", zIndex: 1 }} />
        {/* Header — glass */}
        <div style={{ padding: "16px 20px 14px", borderBottom: `1px solid ${th.border}22`, flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, border: `1px solid ${th.accent}33`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="16" y2="12"/><line x1="4" y1="18" x2="10" y2="18"/></svg>
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.3px" }}>Value Frequency Analysis</h3>
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
                  <select value={colName} onChange={(e) => {
                    setModal((p) => ({ ...p, colName: e.target.value, loading: true, filterText: "" }));
                    reloadStack(e.target.value, sortBy);
                  }} style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.textDim, fontSize: 11, padding: "2px 6px", cursor: "pointer", outline: "none" }}>
                    {ct.headers.filter((h) => !ct.hiddenColumns?.has?.(h)).map((h) => <option key={h} value={h}>{h}</option>)}
                  </select>
                </div>
              </div>
            </div>
            <button onClick={() => setModal(null)} style={{ width: 24, height: 24, borderRadius: 12, background: th.textMuted + "15", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", justifyContent: "center", transition: "all var(--m-base)" }}
              onMouseEnter={(ev) => { ev.currentTarget.style.background = (th.danger) + "33"; ev.currentTarget.style.color = th.danger; }}
              onMouseLeave={(ev) => { ev.currentTarget.style.background = th.textMuted + "15"; ev.currentTarget.style.color = th.textMuted; }}>{"\u2715"}</button>
          </div>
          {/* Stats cards */}
          <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
            {[
              { val: data.totalUnique, label: "unique values", color: th.accent, icon: "M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2" },
              { val: data.totalRows, label: "total events", color: th.success, icon: "M4 7h16M4 12h16M4 17h10" },
            ].map((s, i) => (
              <div key={i} style={{ flex: 1, padding: "10px 12px", borderRadius: 8, background: `radial-gradient(ellipse at 30% 0%, ${s.color}11, transparent 70%)`, border: `1px solid ${s.color}22`, position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${s.color}33, transparent)` }} />
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={s.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.6, flexShrink: 0 }}><path d={s.icon}/></svg>
                  <div>
                    <div style={{ fontSize: 16, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace", letterSpacing: "-0.5px" }}>{formatNumber(s.val)}</div>
                    <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>{s.label}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
          {/* Controls pill */}
          <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "6px 10px", background: `${th.panelBg}88`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", borderRadius: 8, border: `1px solid ${th.border}33` }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0 }}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input autoFocus placeholder="Filter values..." value={filterText} onChange={(e) => setModal((p) => ({ ...p, filterText: e.target.value }))}
              style={{ flex: 1, padding: "4px 6px", background: "transparent", border: "none", color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" }} />
            <div style={{ width: 1, height: 16, background: th.border + "44" }} />
            <button onClick={() => {
              const ns = sortBy === "count" ? "value" : "count";
              setModal((p) => ({ ...p, sortBy: ns, loading: true }));
              reloadStack(colName, ns);
            }} style={{ padding: "3px 10px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
              {sortBy === "count" ? "Count \u2193" : "A\u2192Z"}
            </button>
            <button onClick={() => {
              const lines = ["Value\tCount\tPercent"];
              for (const v of displayed) {
                const p = data.totalRows > 0 ? ((v.cnt / data.totalRows) * 100).toFixed(2) : "0";
                lines.push(`${v.val ?? "(empty)"}\t${v.cnt}\t${p}%`);
              }
              navigator.clipboard?.writeText?.(lines.join("\n"));
            }} style={{ padding: "3px 10px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
              Copy
            </button>
          </div>
        </div>
        {/* Table header */}
        <div style={{ display: "flex", padding: "6px 20px", borderBottom: `1px solid ${th.border}33`, background: `${th.bgAlt}cc`, fontSize: 9, color: th.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system,sans-serif" }}>
          <span style={{ width: 40, flexShrink: 0, textAlign: "right", paddingRight: 10 }}>#</span>
          <span style={{ width: vw, flexShrink: 0, position: "relative" }}>
            Value
            <div onMouseDown={onValColResize} style={{ position: "absolute", right: -4, top: 0, bottom: 0, width: 8, cursor: "col-resize" }}>
              <div style={{ position: "absolute", right: 3, top: 2, bottom: 2, width: 2, background: th.border, borderRadius: 2 }} />
            </div>
          </span>
          <span style={{ width: 90, flexShrink: 0, textAlign: "right" }}>Count</span>
          <span style={{ width: 50, flexShrink: 0, textAlign: "right" }}>%</span>
          <span style={{ flex: 1, paddingLeft: 12 }}>Distribution</span>
        </div>
        {/* Scrollable rows */}
        <div style={{ flex: 1, overflow: "auto", minHeight: 0 }}>
          {modal.loading ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40, flexDirection: "column", gap: 8 }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round"><line x1="4" y1="6" x2="20" y2="6" opacity="0.3"/><line x1="4" y1="12" x2="16" y2="12" opacity="0.5"/><line x1="4" y1="18" x2="10" y2="18" opacity="0.7"/></svg>
              <span style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Loading...</span>
            </div>
          ) : modal.error ? (
            <div style={{ padding: 20 }}><ErrorState message={modal.error} /></div>
          ) : displayed.length === 0 ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
              <span style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{filterText ? "No matching values" : "No data"}</span>
            </div>
          ) : displayed.map((v, i) => {
            const pct = data.totalRows > 0 ? (v.cnt / data.totalRows) * 100 : 0;
            const barPct = sortBy === "count" ? (v.cnt / maxCnt) * 100 : pct;
            const valStr = v.val == null || v.val === "" ? "(empty)" : String(v.val);
            const isRare = pct < 1;
            return (
              <div key={i}
                onClick={() => {
                  const val = v.val == null || v.val === "" ? "" : String(v.val);
                  const existing = { ...(ct.checkboxFilters || {}) };
                  existing[colName] = [val];
                  up("checkboxFilters", existing);
                  setModal(null);
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg + "88"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", padding: "5px 20px", cursor: "pointer", borderBottom: `1px solid ${th.border}15`, fontSize: 12, transition: "background var(--m-fast)" }}>
                <span style={{ width: 40, flexShrink: 0, textAlign: "right", paddingRight: 10, color: th.textMuted, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{i + 1}</span>
                <span style={{ width: vw, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: isRare ? th.accent : th.text, fontWeight: isRare ? 500 : 400 }} title={valStr}>{valStr}</span>
                <span style={{ width: 90, flexShrink: 0, textAlign: "right", color: th.text, fontWeight: 500, fontFamily: "'SF Mono',Menlo,monospace", fontSize: 11 }}>{formatNumber(v.cnt)}</span>
                <span style={{ width: 50, flexShrink: 0, textAlign: "right", color: th.textDim, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{pct.toFixed(1)}%</span>
                <div style={{ flex: 1, paddingLeft: 12 }}>
                  <div style={{ height: 12, background: th.border + "22", borderRadius: 6, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${Math.max(1, barPct)}%`, background: isRare ? `linear-gradient(90deg, ${th.danger}CC, ${th.danger}88)` : `linear-gradient(90deg, ${th.accent}BB, ${th.accent}66)`, borderRadius: 6, transition: "width var(--m-base)", boxShadow: isRare ? `0 0 6px ${th.danger}33` : "none" }} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        {/* Footer — glass */}
        <div style={{ padding: "10px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)", fontSize: 11, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
          <span>{filterText ? `${formatNumber(displayed.length)} of ${formatNumber(data.totalUnique)} values shown` : `${formatNumber(data.totalUnique)} unique values`}{data.truncated ? <span style={{ color: th.warning, marginLeft: 6 }}>(top 10k)</span> : ""}</span>
          <span style={{ color: th.textDim, fontSize: 10 }}>Click row to filter</span>
        </div>
      </div>
    </Modal>
  );
}
