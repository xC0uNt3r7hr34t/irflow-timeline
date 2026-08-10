/**
 * ipc/triage-handlers.js — "Open Triage Collection".
 *
 * The analyst picks a KAPE/triage folder, reviews a manifest of what is inside, and
 * imports the artifacts they want as timeline tabs. The Lateral Movement lane then hands
 * off to the Lateral Movement Tracker.
 *
 * Security model (mirrors ipc/sigma-handlers.js): nothing on disk is readable unless the
 * user selected it. The folder dialog is the ONLY place a `triage-root` grant is issued,
 * and every path that comes back from the renderer afterwards is re-checked against that
 * grant. Because PathAuthorizer canonicalises through `fs.realpathSync.native`, a symlink
 * inside the collection that points outside it resolves outside and is rejected.
 */

const fs = require("fs");
const path = require("path");
const { dialog } = require("electron");
const { PathAuthorizer } = require("../utils/path-authorizer");
const { dbg } = require("../logger");
const { discoverTriageCollection } = require("../analyzers/triage-collection");

const TRIAGE_SCOPE = "triage-root";
// The scope sigma-handlers checks before it will scan a directory.
const SCAN_SCOPE = "scan-target";

module.exports = function registerTriageHandlers(safeHandle, safeSend, ctx) {
  const { _activeWindow, enqueueImport, nextTabId } = ctx;
  // Shared with the other IPC modules (see main.js) so a path validated in one scope
  // can be granted in another; scope names keep them isolated otherwise.
  const pathAuthorizer = ctx.pathAuthorizer || new PathAuthorizer();

  /**
   * Grant recursive read access to a folder the user just chose in a dialog.
   * Returns the CANONICAL path — authorize() hands back an entry object, and the
   * renderer needs the realpath'd string to pass back to discover/import.
   */
  function authorizeTriageRoot(dirPath) {
    const entry = pathAuthorizer.authorize(TRIAGE_SCOPE, dirPath, {
      recursive: true,
      label: "Selected triage collection",
    });
    return entry?.path || dirPath;
  }

  /** Throw unless `p` resolves inside a granted root. Returns the canonical path. */
  function assertInsideTriageRoot(p) {
    return pathAuthorizer.assertAuthorized([TRIAGE_SCOPE], p);
  }

  // ── Pick a folder ───────────────────────────────────────────────────────────
  safeHandle("triage-select-root", async () => {
    const res = await dialog.showOpenDialog(_activeWindow(), {
      title: "Select a triage / KAPE collection folder",
      properties: ["openDirectory"],
      buttonLabel: "Scan",
    });
    if (res.canceled || !res.filePaths?.[0]) return { canceled: true };
    const canonical = authorizeTriageRoot(res.filePaths[0]);
    dbg("TRIAGE", "root selected", { dir: canonical });
    return { dir: canonical };
  });

  // ── Build the manifest ──────────────────────────────────────────────────────
  safeHandle("triage-discover", async (event, { dir } = {}) => {
    if (!dir) return { error: "No folder specified." };
    let root;
    try {
      root = assertInsideTriageRoot(dir);
    } catch (e) {
      return { error: e.message || "That folder has not been authorized. Select it in the app first." };
    }
    const manifest = await discoverTriageCollection(root);
    dbg("TRIAGE", "discover", {
      dir: root,
      kind: manifest.kind,
      classified: manifest.stats?.classified,
      ms: manifest.stats?.elapsedMs,
      error: manifest.error || null,
    });
    return manifest;
  });

  // ── Import the selected artifacts ───────────────────────────────────────────
  //
  // Returns immediately with the tab ids it reserved. Progress and completion ride the
  // existing import-start / import-progress / import-complete / import-error channels,
  // so the renderer's normal import UI covers this with no new plumbing; the batchId
  // lets the caller tell which completions belong to this collection.
  safeHandle("triage-import", async (event, { dir, paths, analyzeAfter = false, hostLabel = "", sigmaEvtxDir = "" } = {}) => {
    if (!dir) return { error: "No folder specified." };
    if (!Array.isArray(paths) || paths.length === 0) return { error: "Nothing selected to import." };

    try {
      assertInsideTriageRoot(dir);
    } catch (e) {
      return { error: e.message || "That folder has not been authorized." };
    }

    const batchId = `triage_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    const items = [];
    const rejected = [];

    for (const p of paths) {
      let canonical;
      try {
        // Re-check EVERY path: the renderer supplied these, and only the canonicalised
        // result is ever handed to the import queue.
        canonical = assertInsideTriageRoot(p);
      } catch {
        rejected.push(p);
        continue;
      }
      let stat = null;
      try { stat = fs.statSync(canonical); } catch { /* ignore */ }
      if (!stat?.isFile?.()) { rejected.push(p); continue; }

      const tabId = nextTabId();
      // A readable tab name matters: these land in the Lateral Movement multi-source
      // picker, where "Security" and "TS-LocalSessionManager/Operational" are far more
      // useful than two identically-truncated file names.
      const displayName = buildTabName(hostLabel, canonical);
      items.push({ tabId, path: canonical, displayName });
      enqueueImport(canonical, { tabId, skipRecent: true, displayName, batchId });
    }

    if (rejected.length) {
      dbg("TRIAGE", "import rejected paths outside the authorized root", { count: rejected.length });
    }
    dbg("TRIAGE", "import queued", { batchId, count: items.length, analyzeAfter });

    // Sigma lane: hand the winevt directory to the existing Hayabusa flow. The dialog is
    // the usual source of a `scan-target` grant; here the user already selected an
    // ancestor of this directory, so granting it is legitimate — but only AFTER proving
    // it resolves inside that selection. Pre-computing the file summary means the Sigma
    // wizard opens ready to scan instead of asking the analyst to find the folder again.
    let sigma = null;
    if (sigmaEvtxDir) {
      try {
        const canonicalDir = assertInsideTriageRoot(sigmaEvtxDir);
        const st = fs.statSync(canonicalDir);
        if (!st.isDirectory()) throw new Error("not a directory");
        const { findEvtxFiles } = require("../analyzers/sigma/evtx-scanner");
        pathAuthorizer.authorize(SCAN_SCOPE, canonicalDir, {
          recursive: true,
          label: "EVTX directory from a triage collection",
        });
        const files = findEvtxFiles(canonicalDir);
        sigma = {
          dirPath: canonicalDir,
          fileCount: files.length,
          totalBytes: files.reduce((n, f) => n + (f.size || 0), 0),
          files: files.map((f) => ({ name: f.name, size: f.size })),
        };
        dbg("TRIAGE", "sigma lane prepared", { dir: canonicalDir, fileCount: files.length });
      } catch (e) {
        dbg("TRIAGE", "sigma lane rejected", { error: e?.message });
        sigma = null;
      }
    }

    return {
      batchId,
      items,
      rejectedCount: rejected.length,
      analyzeAfter: !!analyzeAfter,
      sigmaEvtxDir: sigma,
    };
  });

  // ── Cancel a queued batch ───────────────────────────────────────────────────
  // A collection can queue several multi-GB imports; without this the analyst has to
  // wait out a mis-click. Drops everything still queued and cancels whatever is running.
  safeHandle("triage-cancel-batch", async (event, { batchId, tabIds = [] } = {}) => {
    if (!batchId && tabIds.length === 0) return { error: "No batch specified." };
    // Queue items carry batchId (enqueueImport spreads its opts), so pending ones can be
    // dropped wholesale.
    const dropped = typeof ctx.removeQueuedImports === "function" && batchId
      ? ctx.removeQueuedImports((q) => q.batchId === batchId)
      : 0;
    // The RUNNING job is matched on tabId rather than batchId: import jobs are started
    // deep inside importFile and already carry metadata.tabId, and the renderer knows
    // which tabs belong to this batch — so no extra plumbing is needed to tag them.
    const wanted = new Set(tabIds.map(String));
    let cancelledJobs = 0;
    try {
      cancelledJobs = ctx.jobManager?.cancelWhere?.(
        (j) => j?.status === "running" && wanted.has(String(j?.metadata?.tabId)),
      ) || 0;
    } catch (e) {
      dbg("TRIAGE", "cancel-batch job sweep failed", { error: e?.message });
    }
    dbg("TRIAGE", "batch cancelled", { batchId, dropped, cancelledJobs });
    return { dropped, cancelledJobs };
  });
};

/** "<HOST> · Security" — host prefix only when we actually know the host. */
function buildTabName(hostLabel, filePath) {
  const { evtxDisplayName } = require("../analyzers/triage-collection");
  const base = path.basename(filePath);
  const short = /\.evtx$/i.test(base) ? evtxDisplayName(filePath) : base;
  const host = String(hostLabel || "").trim();
  if (!host) return short;
  const name = `${host} · ${short}`;
  return name.length > 60 ? short : name;
}
