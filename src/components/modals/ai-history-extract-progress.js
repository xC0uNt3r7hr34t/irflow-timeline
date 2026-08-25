/** Shared helpers for AI history extract progress modals. */

export const MAX_LOG_LINES = 250;

export function sourceKey(root) {
  return `${root.tool}:${root.path}`;
}

export function shortenPath(p, max = 72) {
  if (!p || p.length <= max) return p || "";
  const tail = p.slice(-max);
  const slash = tail.indexOf("/");
  return slash >= 0 ? `…${tail.slice(slash)}` : `…${tail}`;
}

export function phaseTitle(phase) {
  switch (phase) {
    case "discovering": return "Discovering sources";
    case "extracting": return "Extracting messages";
    case "loading": return "Writing to database";
    case "merging": return "Finalizing";
    case "complete": return "Complete";
    default: return "Extracting";
  }
}

export function appendLog(prev, line) {
  if (!line) return prev;
  const next = [...prev, line];
  return next.length > MAX_LOG_LINES ? next.slice(-MAX_LOG_LINES) : next;
}

/** Merge an IPC progress patch into modal state for profile or single-tool extract. */
export function mergeAiHistoryProgressState(prev, prog, roots) {
  const log = appendLog(prev.progress?.log || [], prog.logLine);
  const sourceStatus = { ...prev.sourceStatus };
  const idxRoot = prog.sourceIndex && roots?.[prog.sourceIndex - 1];
  const statusRoot = idxRoot || (prog.rootPath ? { tool: prog.tool, path: prog.rootPath } : roots?.[0]);
  if (statusRoot) {
    const key = sourceKey(statusRoot);
    if (prog.logLine?.startsWith("✗")) sourceStatus[key] = "error";
    else if (prog.logLine?.startsWith("✓")) sourceStatus[key] = "done";
    else if (prog.phase === "extracting" || prog.phase === "loading") sourceStatus[key] = "active";
  }
  return {
    ...prev,
    scanning: prog.phase !== "complete",
    sourceStatus,
    progress: {
      ...prev.progress,
      phase: prog.phase || prev.progress?.phase,
      percent: Number.isFinite(prog.percent) ? prog.percent : prev.progress?.percent,
      statusDetail: prog.statusDetail || prev.progress?.statusDetail,
      rowsSoFar: prog.rowsSoFar ?? prev.progress?.rowsSoFar,
      filePath: prog.filePath,
      fileIndex: prog.fileIndex,
      fileCount: prog.fileCount,
      sourceIndex: prog.sourceIndex,
      sourceCount: prog.sourceCount,
      label: prog.label,
      log,
    },
  };
}
