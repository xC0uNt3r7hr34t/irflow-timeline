/**
 * parsers/ai-history/windsurf.js — Windsurf IDE state.vscdb chat extraction.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

const { dbg } = require("../../logger");
const { TOOL_WINDSURF } = require("./schema");
const { listWindsurfUserDataDirs } = require("./artifact-paths");
const { extractVsCodeUserChatDir, buildVsCodeChatImportNotice } = require("./vscode-chat-db");
const { finalizeAiHistoryRows } = require("./row-utils");

function resolveWindsurfUserDir(target) {
  if (!target) return listWindsurfUserDataDirs()[0] || null;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 16; i++) {
    for (const userDir of listWindsurfUserDataDirs()) {
      if (p === userDir || p.startsWith(`${userDir}${path.sep}`)) return userDir;
    }
    if (path.basename(p) === "workspaceStorage" || path.basename(p) === "User") {
      const userDir = path.basename(p) === "User" ? p : path.dirname(p);
      if (fs.existsSync(path.join(userDir, "workspaceStorage"))) return userDir;
    }
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return listWindsurfUserDataDirs()[0] || null;
}

function isWindsurfUserDir(dirPath) {
  const resolved = resolveWindsurfUserDir(dirPath);
  if (!resolved) return false;
  const ws = path.join(resolved, "workspaceStorage");
  const globalDb = path.join(resolved, "globalStorage", "state.vscdb");
  return fs.existsSync(ws) || fs.existsSync(globalDb);
}

async function extractWindsurfPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  const userDir = resolveWindsurfUserDir(target);
  if (!userDir) {
    throw new Error("Not a Windsurf User folder (workspaceStorage / globalStorage/state.vscdb).");
  }

  const { rows, stats } = await extractVsCodeUserChatDir(userDir, TOOL_WINDSURF, attribution, options);
  if (!rows.length) {
    dbg("AIHIST", "windsurf: no messages in state.vscdb", { userDir });
  }

  const { supplementWindsurfCascadePb } = require("./windsurf-cascade");
  const { rows: pbRows, stats: cascadeStats } = supplementWindsurfCascadePb(userDir, attribution, options);
  if (pbRows.length) rows.push(...pbRows);

  const merged = finalizeAiHistoryRows(rows, options);
  if (!merged.length) {
    dbg("AIHIST", "windsurf: no messages in state.vscdb or Cascade .pb inventory", { userDir });
  }
  merged._windsurfStats = stats;
  if (cascadeStats) merged._windsurfCascadeStats = cascadeStats;
  merged._importNotice = buildVsCodeChatImportNotice(TOOL_WINDSURF, stats);
  return merged;
}

module.exports = {
  resolveWindsurfUserDir,
  isWindsurfUserDir,
  extractWindsurfPath,
};
