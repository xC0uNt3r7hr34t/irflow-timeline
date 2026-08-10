import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import { toast } from "../../store/useToastStore.js";
import { Overlay, makeModalStyles } from "../InlineModals.jsx";

/**
 * Pick an open tab to filter by workspace path (Prefetch / EVTX / Amcache).
 */
export default function AiWorkspaceCorrelateModal({ th }) {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const setActiveTab = useTabStore((s) => s.setActiveTab);
  const updateTab = useTabStore((s) => s.updateTab);
  const ms = makeModalStyles(th);

  if (modal?.type !== "aiWorkspaceCorrelate") return null;

  const { path, targets = [] } = modal;

  const apply = (target) => {
    setActiveTab(target.tabId);
    updateTab(target.tabId, {
      columnFilters: { [target.column]: target.value },
      searchHighlight: false,
    });
    setModal(null);
    toast.success("Correlation filter applied", {
      detail: `${target.kind}: ${target.column} contains “${target.value}”`,
    });
  };

  return (
    <Overlay th={th}>
      <h3 style={ms.mh}>Correlate workspace path</h3>
      <p style={{ fontSize: 11, color: th.textMuted, margin: "0 0 12px", fontFamily: "monospace", wordBreak: "break-all" }}>
        {path}
      </p>
      {targets.length === 0 ? (
        <p style={{ fontSize: 12, color: th.textDim }}>
          No matching open tabs. Import Prefetch, EVTX/Chainsaw, or Amcache data first.
        </p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {targets.map((t) => (
            <button
              key={`${t.tabId}-${t.column}`}
              type="button"
              onClick={() => apply(t)}
              style={{
                textAlign: "left",
                padding: "8px 10px",
                borderRadius: 8,
                border: `1px solid ${th.border}`,
                background: th.bgAlt,
                color: th.text,
                cursor: "pointer",
                fontSize: 12,
              }}
            >
              <div style={{ fontWeight: 600 }}>{t.kind} — {t.tabName}</div>
              <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2 }}>{t.hint}</div>
            </button>
          ))}
        </div>
      )}
      <div style={{ marginTop: 14, display: "flex", justifyContent: "flex-end" }}>
        <button type="button" onClick={() => setModal(null)} style={ms.bs}>Close</button>
      </div>
    </Overlay>
  );
}
