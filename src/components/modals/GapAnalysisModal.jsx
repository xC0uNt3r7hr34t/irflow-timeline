import { useCallback } from "react";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { Modal, Button, Input } from "../primitives/index.js";

export default function GapAnalysisModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const refreshCallback = useUIStore((s) => s.refreshCallback);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const activeTab = useTabStore((s) => s.activeTab);
  const setTabs = useTabStore((s) => s.setTabs);

  const up = useCallback((key, value) => {
    setTabs((prev) => prev.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)));
  }, [activeTab, setTabs]);

  const fetchData = useCallback((tab) => {
    if (refreshCallback) refreshCallback(tab);
  }, [refreshCallback]);

  const activeFilters = useCallback((tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  }, []);

  const labelStyle = { display: "block", fontSize: 10, color: th.textDim, marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" };
  const fgStyle = { marginBottom: 10 };
  const slStyle = { width: "100%", padding: "6px 8px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" };

  if (!modal || modal.type !== "gapAnalysis" || !ct) return null;

  const { phase, colName, gapThreshold, data } = modal;
  const tsCols = [...(ct.tsColumns || [])];

  const handleAnalyze = async () => {
    setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
    try {
      const af = activeFilters(ct);
      const result = await tle.getGapAnalysis(ct.id, colName, gapThreshold, {
        searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
        searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
      });
      if (isIpcError(result)) throw new Error(ipcErrorMessage(result));
      setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, phase: "results", loading: false, data: result }) : p);
    } catch (e) {
      setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, phase: "config", loading: false, error: e.message }) : p);
    }
  };

  const handleTagSessions = async () => {
    if (!data?.sessions?.length) return;
    setModal((p) => ({ ...p, tagging: true }));
    try {
      const ranges = data.sessions.map((s) => ({ from: s.from, to: s.to, tag: `Session ${s.idx}` }));
      const result = await tle.bulkTagByTimeRange(ct.id, colName, ranges);
      const sessionColors = [th.sev.info, th.sev.clean, th.sev.custom, th.sev.high, th.sev.med, th.sev.critical, th.sev.critical, th.sev.low];
      const newTagColors = { ...ct.tagColors };
      for (const s of data.sessions) {
        const tag = `Session ${s.idx}`;
        if (!newTagColors[tag]) newTagColors[tag] = sessionColors[(s.idx - 1) % sessionColors.length];
      }
      up("tagColors", newTagColors);
      await fetchData(ct);
      setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, tagging: false, tagged: true, taggedCount: result.taggedCount }) : p);
    } catch {
      setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, tagging: false }) : p);
    }
  };

  const zoomTo = (from, to) => {
    const fromTs = from.length === 16 ? from + ":00" : from;
    const toTs = to.length === 16 ? to + ":59" : to;
    up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [colName]: { from: fromTs, to: toTs } });
    setModal(null);
  };

  const fmtDur = (mins) => {
    if (mins < 60) return `${mins}m`;
    if (mins < 1440) return `${Math.floor(mins / 60)}h ${mins % 60}m`;
    return `${Math.floor(mins / 1440)}d ${Math.floor((mins % 1440) / 60)}h`;
  };

  const rowStyle = (i) => ({
    display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 11,
    background: i % 2 === 0 ? "transparent" : th.rowAlt, cursor: "pointer",
    borderBottom: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace",
  });

  const footer = (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", width: "100%" }}>
      {phase === "config" && (<>
        <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
        <Button onClick={handleAnalyze}>Analyze</Button>
      </>)}
      {phase === "loading" && <span style={{ color: th.textMuted, fontSize: 11 }}>Scanning...</span>}
      {phase === "results" && (<>
        <Button variant="secondary" onClick={() => setModal((p) => ({ ...p, phase: "config", data: null, tagged: false, taggedCount: 0 }))}>Back</Button>
        <div style={{ display: "flex", gap: 6 }}>
          {!modal.tagged && data.sessions.length > 0 && (
            <Button onClick={handleTagSessions} loading={modal.tagging} style={{ background: th.success }}>
              {modal.tagging ? "Tagging..." : `Tag ${data.sessions.length} Sessions`}
            </Button>
          )}
          {modal.tagged && (
            <Button variant="secondary" onClick={() => { up("tagFilter", "Session 1"); setModal(null); }}
              style={{ color: th.accent, borderColor: th.accent + "66" }}>Show Session 1</Button>
          )}
          <Button onClick={() => setModal(null)}>Done</Button>
        </div>
      </>)}
    </div>
  );

  return (
    <Modal
      title="Timeline Gap Analysis"
      subtitle="Detect activity bursts and quiet periods"
      width={600}
      maxHeight="88vh"
      onClose={() => setModal(null)}
      bodyPadding="16px 20px"
      footer={footer}
    >
      {phase === "config" && (<>
        <div style={fgStyle}>
          <label style={labelStyle}>Timestamp Column</label>
          <select value={colName} onChange={(e) => setModal((p) => ({ ...p, colName: e.target.value }))} style={slStyle}>
            {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div style={fgStyle}>
          <label style={labelStyle}>Gap Threshold</label>
          <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
            {[15, 30, 60, 120, 480].map((v) => (
              <Button
                key={v}
                size="sm"
                variant={gapThreshold === v ? "primary" : "secondary"}
                onClick={() => setModal((p) => ({ ...p, gapThreshold: v }))}
              >
                {v < 60 ? `${v}m` : `${v / 60}h`}
              </Button>
            ))}
            <Input
              type="number"
              min="1"
              value={gapThreshold}
              onChange={(e) => setModal((p) => ({ ...p, gapThreshold: Math.max(1, Number(e.target.value) || 60) }))}
              fullWidth={false}
              style={{ width: 70 }}
            />
            <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>minutes</span>
          </div>
        </div>
        {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
      </>)}

      {phase === "loading" && (
        <div style={{ textAlign: "center", padding: 40 }}>
          <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Analyzing timeline for gaps &gt;{gapThreshold}m...</div>
        </div>
      )}

      {phase === "results" && data && (<>
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          {[
            { val: data.sessions.length, label: "sessions", color: th.accent },
            { val: data.gaps.length, label: "gaps detected", color: th.warning },
            { val: data.totalEvents.toLocaleString(), label: "total events", color: th.textDim },
          ].map((c, i) => (
            <div key={i} style={{ flex: 1, textAlign: "center", padding: "12px 8px", background: th.panelBg, borderRadius: 8, border: `1px solid ${th.border}` }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif" }}>{c.val}</div>
              <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
            </div>
          ))}
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={labelStyle}>Sessions ({data.sessions.length})</div>
          <div style={{ maxHeight: 200, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
            {data.sessions.map((s, i) => (
              <div key={s.idx} style={rowStyle(i)} onClick={() => zoomTo(s.from, s.to)}
                onMouseEnter={(e) => e.currentTarget.style.background = th.rowHover}
                onMouseLeave={(e) => e.currentTarget.style.background = i % 2 === 0 ? "transparent" : th.rowAlt}>
                <span style={{ padding: "1px 8px", borderRadius: 3, fontSize: 10, fontWeight: 600, color: "#fff", background: [th.sev.info, th.sev.clean, th.sev.custom, th.sev.high, th.sev.med, th.sev.critical, th.sev.critical, th.sev.low][(s.idx - 1) % 8], fontFamily: "-apple-system, sans-serif" }}>Session {s.idx}</span>
                <span style={{ color: th.textDim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.from} {"\u2014"} {s.to}</span>
                <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{s.eventCount.toLocaleString()} events</span>
                <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(s.durationMinutes)}</span>
              </div>
            ))}
          </div>
        </div>

        {data.gaps.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div style={labelStyle}>Gaps ({data.gaps.length})</div>
            <div style={{ maxHeight: 180, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
              {data.gaps.map((g, i) => (
                <div key={i} style={rowStyle(i)} onClick={() => zoomTo(g.from, g.to)}
                  onMouseEnter={(e) => e.currentTarget.style.background = th.rowHover}
                  onMouseLeave={(e) => e.currentTarget.style.background = i % 2 === 0 ? "transparent" : th.rowAlt}>
                  <span style={{ color: th.danger, fontSize: 13 }}>{"\u23F8"}</span>
                  <span style={{ color: th.textDim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{g.from} {"\u2014"} {g.to}</span>
                  <span style={{ color: th.warning, fontSize: 11, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(g.durationMinutes)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {modal.tagged && (
          <div style={{ padding: "8px 12px", background: `${th.success}15`, border: `1px solid ${th.success}33`, borderRadius: 6, color: th.success, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 10 }}>
            Tagged {modal.taggedCount?.toLocaleString()} rows across {data.sessions.length} sessions
          </div>
        )}
      </>)}
    </Modal>
  );
}
