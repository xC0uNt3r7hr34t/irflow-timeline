/**
 * ai-history/extract-plan.js — file lists and subagent filtering for extraction progress.
 */

const fs = require("fs");
const path = require("path");

const SUBAGENT_PATH_RE = /(?:^|[\\/])subagents(?:[\\/]|$)/i;

function isSubagentArtifactPath(filePath) {
  if (!filePath) return false;
  return SUBAGENT_PATH_RE.test(String(filePath).replace(/\\/g, "/"));
}

function shouldSkipSubagentPath(filePath, options = {}) {
  if (options.includeSubagents) return false;
  if (options.skipSubagents === false) return false;
  return isSubagentArtifactPath(filePath);
}

function filterSubagentPaths(paths, options = {}) {
  if (options.includeSubagents || options.skipSubagents === false) return paths;
  return paths.filter((p) => !isSubagentArtifactPath(p));
}

/**
 * Drop sub-agent / sidechain message rows when the analyst chose "main sessions only".
 * Complements the folder-level skip: catches inline `isSidechain: true` turns that live
 * inside an otherwise-main session file (Claude Task tool, Cursor sub-agents, …).
 * Returns the input array unchanged when subagents are included (no copy, preserves
 * any meta properties parsers attach to the array).
 * @param {object[]} rows
 * @param {{ includeSubagents?: boolean, skipSubagents?: boolean }} [options]
 */
function filterSidechainRows(rows, options = {}) {
  if (!Array.isArray(rows)) return rows;
  if (options.includeSubagents || options.skipSubagents === false) return rows;
  return rows.filter((r) => r && r.IsSidechain !== "true");
}

/**
 * @param {(fileIndex: number, fileCount: number, filePath: string) => void} [onFileProgress]
 */
function tickFileProgress(onFileProgress, fileIndex, fileCount, filePath) {
  if (typeof onFileProgress === "function") onFileProgress(fileIndex, fileCount, filePath);
}

module.exports = {
  SUBAGENT_PATH_RE,
  isSubagentArtifactPath,
  shouldSkipSubagentPath,
  filterSubagentPaths,
  filterSidechainRows,
  tickFileProgress,
};
