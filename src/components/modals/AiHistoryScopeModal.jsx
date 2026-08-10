import useUIStore from "../../store/useUIStore.js";
import useTheme from "../../hooks/useTheme.js";
import { toast } from "../../store/useToastStore.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { Modal } from "../primitives/index.js";
import { openAiHistoryScopeModal, openAiHistoryExtractModal } from "../../modals/modalRegistry.js";

/**
 * In-app subagent scope choice (replaces native dialog for Tools → AI Artifacts → AI Apps → …).
 */
export default function AiHistoryScopeModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;

  if (modal?.type !== "aiHistoryScope") return null;

  const {
    tool,
    target,
    label,
    includeSubagents = false,
    busy = false,
    mode = "extract",
    scopeQueue = [],
  } = modal;

  const openNextScope = (queue) => {
    if (!queue?.length) {
      setModal(null);
      return;
    }
    const [next, ...rest] = queue;
    setModal(openAiHistoryScopeModal({
      tool: next.tool,
      target: next.target,
      label: next.label,
      mode: "import",
      scopeQueue: rest,
    }));
  };

  const runExtract = async (withSubagents) => {
    if (mode !== "import") {
      setModal(openAiHistoryExtractModal({
        tool,
        target,
        extractTarget: modal.extractTarget,
        label,
        includeSubagents: withSubagents,
      }));
      return;
    }
    setModal((p) => (p?.type === "aiHistoryScope" ? { ...p, busy: true } : p));
    try {
      if (mode === "import") {
        if (!tle?.importFiles) {
          toast.error("Import unavailable", { detail: "Restart the app to load the latest build." });
          setModal(null);
          return;
        }
        const r = await tle.importFiles([target], {
          items: [{
            path: target,
            opts: {
              aiHistoryTool: tool,
              aiHistoryIncludeSubagents: withSubagents,
            },
          }],
        });
        // safeHandle resolves a failed handler as { __ipcError, message } rather than rejecting,
        // so without this check a failed import falls through to the success toast below.
        if (isIpcError(r)) {
          toast.error(`${label} import failed`, { detail: ipcErrorMessage(r) });
          setModal(null);
          return;
        }
        if (r?.scopePending?.length) {
          openNextScope(r.scopePending);
          return;
        }
        toast.success(label, { detail: "Import queued — watch the tab bar for progress." });
        openNextScope(scopeQueue);
        return;
      }

    } catch (e) {
      toast.error(`${label} extraction failed`, { detail: e?.message || String(e) });
      setModal(null);
    }
  };

  const btn = (primary, disabled) => ({
    padding: "6px 14px",
    borderRadius: 6,
    fontSize: 13,
    cursor: disabled ? "default" : "pointer",
    border: primary ? "none" : `1px solid ${th.border}`,
    background: primary ? th.accent : th.bg,
    color: primary ? "#fff" : th.text,
    opacity: disabled ? 0.5 : 1,
  });

  const detail = tool === "cursor"
    ? "Subagent paths under agent-transcripts/ can add many JSONL lines."
    : "Subagent paths under projects/ or sessions/ can add tens of thousands of JSONL lines.";

  return (
    <Modal
      open
      title="AI history scope"
      subtitle={label}
      width={480}
      onClose={() => { if (!busy) setModal(null); }}
      footer={(
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button type="button" onClick={() => setModal(null)} disabled={busy} style={btn(false, busy)}>Cancel</button>
          <button type="button" onClick={() => runExtract(false)} disabled={busy} style={btn(true, busy)}>
            Main sessions only
          </button>
          <button type="button" onClick={() => runExtract(true)} disabled={busy} style={btn(true, busy)}>
            Include subagents
          </button>
        </div>
      )}
    >
      <p style={{ fontSize: 12, color: th.textMuted, margin: "0 0 12px", lineHeight: 1.5 }}>
        {detail} Main sessions only skips Claude subagent folders, Cursor sidechain lines, and Codex forked threads; include subagents for full coverage.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 12 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: busy ? "default" : "pointer" }}>
          <input
            type="radio"
            name="ai-scope-single"
            checked={!includeSubagents}
            disabled={busy}
            onChange={() => setModal((p) => (p?.type === "aiHistoryScope" ? { ...p, includeSubagents: false } : p))}
            style={{ accentColor: th.accent }}
          />
          Main sessions only (recommended)
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: busy ? "default" : "pointer" }}>
          <input
            type="radio"
            name="ai-scope-single"
            checked={!!includeSubagents}
            disabled={busy}
            onChange={() => setModal((p) => (p?.type === "aiHistoryScope" ? { ...p, includeSubagents: true } : p))}
            style={{ accentColor: th.accent }}
          />
          Include subagents / sidechains
        </label>
      </div>
    </Modal>
  );
}
