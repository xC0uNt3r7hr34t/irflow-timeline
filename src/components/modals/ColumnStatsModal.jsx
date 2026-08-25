import useUIStore from "../../store/useUIStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { formatNumber } from "../../utils/format.js";
import { DraggableResizableModal, ErrorState } from "../primitives/index.js";

export default function ColumnStatsModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const ct = useCurrentTab();

  if (modal?.type !== "columnStats" || !ct) return null;

  const colName = modal.colName;
  const data = modal.data;
  const isTs = ct.tsColumns?.has(colName);
  const isNum = ct.numericColumns?.has(colName);
  const fmtSpan = (ms) => {
    if (ms == null) return "";
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  };

  return (
    <DraggableResizableModal
      defaultWidth={620}
      defaultHeight={Math.min(720, Math.round(window.innerHeight * 0.88))}
      minWidth={420}
      minHeight={360}
      onClose={() => setModal(null)}
    >
      {({ startDrag }) => (<>
        {/* Draggable header */}
        <div onMouseDown={startDrag} style={{ padding: "14px 20px", borderBottom: `1px solid ${th.glassBorder}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, cursor: "grab", userSelect: "none", gap: 12 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>Column Statistics</div>
            <div style={{ fontSize: 11, color: th.textDim, marginTop: 2, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              <span style={{ color: th.accent }}>{colName}</span>
              {isTs && <span style={{ marginLeft: 6, fontSize: 9, color: th.textMuted, textTransform: "uppercase" }}>Timestamp</span>}
              {isNum && <span style={{ marginLeft: 6, fontSize: 9, color: th.textMuted, textTransform: "uppercase" }}>Numeric</span>}
            </div>
          </div>
          <button onClick={() => setModal(null)} aria-label="Close" style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 18, padding: "2px 6px", lineHeight: 1, flexShrink: 0 }}>✕</button>
        </div>

        {/* Body */}
        <div style={{ padding: "16px 20px", overflow: "auto", flex: 1, color: th.text, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif" }}>
          {modal.loading ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40, color: th.textMuted, fontSize: 12 }}>Calculating...</div>
          ) : modal.error ? (
            <ErrorState message={modal.error} />
          ) : data && (<>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
              {[
                { label: "Total", value: formatNumber(data.totalRows) },
                { label: "Unique", value: formatNumber(data.uniqueCount) },
                { label: "Empty", value: formatNumber(data.emptyCount) },
                { label: "Fill Rate", value: `${data.fillRate}%` },
              ].map((c) => (
                <div key={c.label} style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 12px", textAlign: "center" }}>
                  <div style={{ fontSize: 18, fontWeight: 700, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{c.value}</div>
                  <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                </div>
              ))}
            </div>
            {isTs && data.tsStats && (
              <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 14px", marginBottom: 12 }}>
                <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", marginBottom: 6 }}>Time Range</div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>
                  <span>{data.tsStats.earliest}</span>
                  <span style={{ color: th.textDim }}>to</span>
                  <span>{data.tsStats.latest}</span>
                </div>
                {data.tsStats.timespanMs != null && (
                  <div style={{ fontSize: 11, color: th.accent, marginTop: 4, textAlign: "center" }}>Span: {fmtSpan(data.tsStats.timespanMs)}</div>
                )}
              </div>
            )}
            {isNum && data.numStats && (
              <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 14px", marginBottom: 12 }}>
                <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", marginBottom: 6 }}>Numeric Range</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, textAlign: "center" }}>
                  {[{ label: "Min", value: data.numStats.min }, { label: "Avg", value: data.numStats.avg }, { label: "Max", value: data.numStats.max }].map((s) => (
                    <div key={s.label}>
                      <div style={{ fontSize: 14, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{s.value}</div>
                      <div style={{ fontSize: 9, color: th.textMuted }}>{s.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", marginBottom: 6 }}>Top {data.topValues.length} Values</div>
            {data.topValues.map((v, i) => {
              const pct = data.totalRows > 0 ? (v.cnt / data.totalRows) * 100 : 0;
              const maxCnt = data.topValues[0]?.cnt || 1;
              const barPct = (v.cnt / maxCnt) * 100;
              return (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", fontSize: 11 }}>
                  <span style={{ flex: "2 1 120px", maxWidth: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, minWidth: 0 }} title={v.val}>{v.val || "(empty)"}</span>
                  <div style={{ flex: "1 1 100px", height: 14, background: th.border + "44", borderRadius: 3, overflow: "hidden", minWidth: 60 }}>
                    <div style={{ height: "100%", width: `${Math.max(1, barPct)}%`, background: th.accent + "99", borderRadius: 3 }} />
                  </div>
                  <span style={{ width: 64, textAlign: "right", color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", flexShrink: 0 }}>{formatNumber(v.cnt)}</span>
                  <span style={{ width: 48, textAlign: "right", color: th.textMuted, fontSize: 10, flexShrink: 0 }}>{pct.toFixed(1)}%</span>
                </div>
              );
            })}
          </>)}
        </div>

        {/* Footer */}
        <div style={{ padding: "10px 20px", borderTop: `1px solid ${th.glassBorder}`, display: "flex", justifyContent: "flex-end", flexShrink: 0 }}>
          <button onClick={() => setModal(null)} style={{ padding: "6px 14px", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, borderRadius: 6, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", transition: "background var(--m-base) var(--ease-out), color var(--m-base) var(--ease-out), border-color var(--m-base) var(--ease-out)" }}>Close</button>
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
