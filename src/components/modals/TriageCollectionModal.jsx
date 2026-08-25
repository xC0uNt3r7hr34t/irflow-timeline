import { useEffect, useRef } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTheme from "../../hooks/useTheme.js";
import useModalChrome from "../../hooks/useModalChrome.js";
import { DraggableResizableModal } from "../primitives/index.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { toast } from "../../store/useToastStore.js";
import { updateModal } from "../../modals/modalRegistry.js";

/**
 * TriageCollectionModal — "Open Triage Collection".
 *
 * The analyst points at a KAPE/triage folder; this shows what is inside, ranked by
 * lateral-movement relevance, and imports the selection as timeline tabs.
 *
 * Two independent lanes, because they answer different questions and an analyst may want
 * either, both, or neither:
 *   • Lateral Movement — imports the LM-relevant channels as tabs (pre-checked), then
 *     hands off to the Lateral Movement Tracker.
 *   • EVTX → Sigma     — the existing Hayabusa flow over the whole winevt directory.
 *
 * Artifacts this branch has no parser for are listed but never silently dropped: telling
 * the analyst "290 prefetch files are here, run PECmd" beats pretending they don't exist.
 */
export default function TriageCollectionModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const ms = useModalChrome();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const isActive = modal?.type === "triageCollection";
  const patch = (p) => setModal(updateModal("triageCollection", p));

  // Open the folder picker immediately — the modal has nothing to show until a folder is
  // chosen, so making the analyst click "Browse" first would be a wasted step.
  const pickedRef = useRef(false);
  useEffect(() => {
    if (!isActive || pickedRef.current || modal.phase !== "picking") return;
    pickedRef.current = true;
    (async () => {
      if (!tle?.triageSelectRoot) { patch({ phase: "manifest", error: "Triage import is not available in this window." }); return; }
      const res = await tle.triageSelectRoot();
      if (isIpcError(res)) { setModal(null); toast.error("Could not open that folder", { detail: ipcErrorMessage(res) }); return; }
      if (!res || res.canceled || !res.dir) { setModal(null); return; }
      patch({ phase: "scanning", dir: res.dir });
      const manifest = await tle.triageDiscover(res.dir);
      if (isIpcError(manifest)) { patch({ phase: "manifest", error: ipcErrorMessage(manifest) }); return; }
      if (manifest?.error) { patch({ phase: "manifest", error: manifest.error, manifest: null }); return; }
      // Seed the selection from the manifest's own defaults.
      const selected = new Set(manifest.lanes.lateralMovement.items.filter((i) => i.defaultChecked).map((i) => i.id));
      patch({ phase: "manifest", manifest, selected, error: null });
    })();
  }, [isActive, modal?.phase]);

  if (!isActive) return null;

  const { phase, dir, manifest, error, selected, showAllEvtx } = modal;
  const lm = manifest?.lanes?.lateralMovement;
  const sel = selected instanceof Set ? selected : new Set();

  const toggle = (id) => patch((p) => {
    const s = new Set(p.selected || []);
    s.has(id) ? s.delete(id) : s.add(id);
    return { selected: s };
  });

  const startImport = async () => {
    const paths = [...sel];
    if (paths.length === 0) { toast.info("Nothing selected", { detail: "Pick at least one artifact to import." }); return; }
    patch({ phase: "importing" });
    const res = await tle.triageImport(dir, paths, {
      analyzeAfter: modal.analyzeAfter,
      hostLabel: manifest?.host?.hostname || "",
      // Only ask for a Sigma grant when the analyst actually chose that lane.
      sigmaEvtxDir: modal.includeSigmaLane ? (manifest?.lanes?.evtxSigma?.dir || "") : "",
    });
    if (isIpcError(res) || res?.error) {
      patch({ phase: "manifest" });
      toast.error("Import failed", { detail: isIpcError(res) ? ipcErrorMessage(res) : res.error });
      return;
    }
    if (res.rejectedCount > 0) {
      toast.warning(`${res.rejectedCount} path${res.rejectedCount === 1 ? "" : "s"} skipped`, {
        detail: "They resolved outside the folder you selected.",
      });
    }
    // A persistent toast with a Cancel action: a collection can queue several multi-GB
    // files, so a mis-click must be recoverable. App.jsx dismisses it once the batch
    // settles (see _settleTriageBatch), so it cannot linger after the work is done.
    const toastId = toast.info("Importing collection", {
      detail: `${res.items.length} artifact${res.items.length === 1 ? "" : "s"} queued.`,
      ttl: 0,
      actionLabel: "Cancel remaining",
      onAction: async () => {
        const r = await tle.triageCancelBatch(res.batchId, (res.items || []).map((i) => i.tabId));
        if (isIpcError(r)) { toast.error("Could not cancel", { detail: ipcErrorMessage(r) }); return; }
        toast.warning("Import cancelled", {
          detail: `${r.dropped || 0} queued, ${r.cancelledJobs || 0} in progress.`,
        });
      },
    });

    // App.jsx watches these tab ids and hands off to the Lateral Movement Tracker once
    // every one is terminal. Published in a single write, with the toast id, so the
    // watcher can never consume a half-built batch.
    useUIStore.getState().setPendingTriageBatch({
      ...res,
      analyzeAfter: modal.analyzeAfter,
      hostLabel: manifest?.host?.hostname || "",
      toastId,
    });
    setModal(null);
  };

  const dot = (tier) => "●".repeat(Math.max(1, tier));
  const lbl = { fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" };

  return (
    <DraggableResizableModal
      defaultWidth={720}
      defaultHeight={Math.round(window.innerHeight * 0.8)}
      minWidth={520}
      minHeight={380}
      ariaLabel="Open Triage Collection"
      onClose={() => setModal(null)}
    >
      {({ startDrag, height }) => (<>
        <div onMouseDown={startDrag} style={{ padding: "14px 18px 10px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, cursor: "grab" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Open Triage Collection</h3>
            <p style={{ margin: "2px 0 0", ...lbl }}>{dir || "Select a KAPE / triage folder"}</p>
          </div>
          <button onClick={() => setModal(null)} style={{ width: 24, height: 24, borderRadius: 12, background: th.textMuted + "15", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13 }}>{"✕"}</button>
        </div>

        <div style={{ flex: 1, overflow: "auto", padding: "14px 18px" }}>
          {phase === "scanning" && <div style={{ ...lbl, padding: 20, textAlign: "center" }}>Scanning collection…</div>}

          {error && (
            <div style={{ padding: 12, borderRadius: 8, background: th.danger + "12", border: `1px solid ${th.danger}44`, color: th.text, fontSize: 12, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>{error}</div>
          )}

          {phase === "manifest" && manifest && (<>
            {/* Provenance */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <span style={{ padding: "2px 8px", borderRadius: 4, background: th.accent + "18", color: th.accent, fontSize: 10, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>{manifest.kind.toUpperCase()}</span>
              <span style={{ fontSize: 12, color: th.text, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{manifest.host?.hostname}</span>
              <span style={{ ...lbl }}>host confidence: {manifest.host?.confidence} ({manifest.host?.source})</span>
              <span style={{ ...lbl, marginLeft: "auto" }}>{manifest.stats?.classified} artifacts · {manifest.stats?.elapsedMs}ms</span>
            </div>

            {/* Anything the analyst must know before trusting the attribution. */}
            {(manifest.host?.notes || []).concat(manifest.warnings || []).map((n, i) => (
              <div key={i} style={{ padding: "7px 10px", marginBottom: 6, borderRadius: 6, background: th.warning + "10", border: `1px solid ${th.warning}33`, color: th.textDim, fontSize: 10.5, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>{n}</div>
            ))}

            {/* Lane 1 — Lateral Movement */}
            <div style={{ marginTop: 12, border: `1px solid ${th.border}`, borderRadius: 8, overflow: "hidden" }}>
              <div style={{ padding: "8px 12px", background: th.panelBg, borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", gap: 8 }}>
                <strong style={{ fontSize: 12, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Lateral Movement</strong>
                <span style={lbl}>{sel.size} selected of {lm.items.length} relevant · {lm.totalEvtx} EVTX in collection</span>
              </div>
              {lm.items.length === 0 && <div style={{ ...lbl, padding: 12 }}>No lateral-movement channels found in this collection.</div>}
              {lm.items.filter((i) => showAllEvtx || i.lmTier >= 2 || i.defaultChecked).map((i) => (
                <label key={i.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 12px", borderBottom: `1px solid ${th.border}22`, cursor: i.empty ? "default" : "pointer", opacity: i.empty ? 0.55 : 1 }}>
                  <input type="checkbox" checked={sel.has(i.id)} onChange={() => toggle(i.id)} style={{ accentColor: th.accent, cursor: "pointer" }} />
                  <span style={{ width: 26, color: i.lmTier === 3 ? th.sev.critical : i.lmTier === 2 ? th.sev.high : th.textMuted, fontSize: 9 }}>{dot(i.lmTier)}</span>
                  <span style={{ width: 74, textAlign: "right", ...lbl, fontFamily: "monospace" }}>{i.sizeLabel}</span>
                  <span style={{ flex: 1, fontSize: 11.5, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{i.name}</span>
                  {i.note && <span style={{ ...lbl, fontSize: 9.5 }}>{i.note}</span>}
                </label>
              ))}
              {lm.items.some((i) => i.lmTier < 2 && !i.defaultChecked) && (
                <button onClick={() => patch({ showAllEvtx: !showAllEvtx })} style={{ ...ms.bs, border: "none", background: "transparent", color: th.accent, fontSize: 10, padding: "6px 12px" }}>
                  {showAllEvtx ? "Show fewer channels" : "Show all graded channels"}
                </button>
              )}
            </div>

            {/* Lane 2 — Sigma (unchanged existing flow) */}
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, padding: "8px 12px", border: `1px solid ${th.border}`, borderRadius: 8, cursor: "pointer" }}>
              <input type="checkbox" checked={!!modal.includeSigmaLane} onChange={() => patch((p) => ({ includeSigmaLane: !p.includeSigmaLane }))} style={{ accentColor: th.accent, cursor: "pointer" }} />
              <span style={{ fontSize: 11.5, color: th.text, fontFamily: "-apple-system, sans-serif" }}>EVTX logs → Sigma scan</span>
              <span style={lbl}>{manifest.lanes.evtxSigma.count} files · heavy · opens the Sigma wizard after import</span>
            </label>

            {/* Other importable artifacts */}
            {manifest.artifacts.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ ...lbl, marginBottom: 5 }}>Also importable</div>
                {manifest.artifacts.map((a) => (
                  <label key={a.kind} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 2px", cursor: "pointer" }}>
                    <input type="checkbox"
                      checked={(a.paths || []).every((p) => sel.has(p)) && a.paths.length > 0}
                      onChange={() => patch((p) => {
                        const s = new Set(p.selected || []);
                        const all = (a.paths || []).every((x) => s.has(x));
                        for (const x of a.paths || []) { all ? s.delete(x) : s.add(x); }
                        return { selected: s };
                      })}
                      style={{ accentColor: th.accent, cursor: "pointer" }} />
                    <span style={{ fontSize: 11.5, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{a.label}</span>
                    <span style={lbl}>{a.count > 1 ? `${a.count} files · ` : ""}{a.sizeLabel}{a.heavy ? " · heavy" : ""}</span>
                  </label>
                ))}
              </div>
            )}

            {/* Present but unparseable — informational, never silently dropped */}
            {manifest.info.length > 0 && (
              <div style={{ marginTop: 12, padding: "8px 12px", borderRadius: 8, background: th.bgAlt, border: `1px solid ${th.border}55` }}>
                <div style={{ ...lbl, marginBottom: 4 }}>Present in the collection, no parser in this build</div>
                {manifest.info.slice(0, 10).map((a) => (
                  <div key={a.kind} style={{ display: "flex", gap: 8, fontSize: 10.5, color: th.textDim, fontFamily: "-apple-system, sans-serif", padding: "1px 0" }}>
                    <span style={{ flex: 1 }}>{a.label}</span>
                    <span style={{ ...lbl }}>{a.count > 1 ? `${a.count} · ` : ""}{a.sizeLabel}</span>
                    {a.hint && <span style={{ ...lbl, color: th.accent, minWidth: 150 }}>{a.hint}</span>}
                  </div>
                ))}
              </div>
            )}
          </>)}

          {phase === "importing" && <div style={{ ...lbl, padding: 20, textAlign: "center" }}>Queuing imports…</div>}
        </div>

        <div style={{ padding: "10px 18px", borderTop: `1px solid ${th.border}22`, display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", ...lbl }}>
            <input type="checkbox" checked={!!modal.analyzeAfter} onChange={() => patch((p) => ({ analyzeAfter: !p.analyzeAfter }))} style={{ accentColor: th.accent, cursor: "pointer" }} />
            Run Lateral Movement analysis after import
          </label>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button onClick={() => setModal(null)} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
            <button onClick={startImport} disabled={phase !== "manifest" || sel.size === 0}
              style={{ ...ms.bp, borderRadius: 8, opacity: phase === "manifest" && sel.size > 0 ? 1 : 0.5 }}>
              Import {sel.size || ""}{modal.analyzeAfter ? " + Analyze" : ""}
            </button>
          </div>
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
