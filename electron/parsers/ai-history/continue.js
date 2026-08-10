/**
 * parsers/ai-history/continue.js — Continue.dev ~/.continue/sessions/*.json extraction.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

const { dbg } = require("../../logger");
const { TOOL_CONTINUE } = require("./schema");
const { tickFileProgress } = require("./extract-plan");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, finalizeAiHistoryRows } = require("./row-utils");

const CONTINUE_DIR = ".continue";
const SESSIONS_DIR = "sessions";

function continueHome(target) {
  if (!target) return path.join(os.homedir(), CONTINUE_DIR);
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 16; i++) {
    if (path.basename(p) === CONTINUE_DIR) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  if (path.basename(target) === CONTINUE_DIR) return target;
  return null;
}

function isContinueRoot(dirPath) {
  const home = continueHome(dirPath);
  if (!home) return false;
  const sessions = path.join(home, SESSIONS_DIR);
  if (!fs.existsSync(sessions)) return false;
  try {
    const entries = fs.readdirSync(sessions, { withFileTypes: true });
    return entries.some((e) => e.isFile() && e.name.endsWith(".json") && e.name !== "sessions.json");
  } catch {
    return false;
  }
}

function listContinueSessionFiles(continueRoot) {
  const sessions = path.join(continueRoot, SESSIONS_DIR);
  if (!fs.existsSync(sessions)) return [];
  let entries;
  try { entries = fs.readdirSync(sessions, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((e) => e.isFile() && e.name.endsWith(".json") && e.name !== "sessions.json")
    .map((e) => path.join(sessions, e.name));
}

function textFromContinueMessage(msg) {
  if (!msg) return "";
  if (typeof msg === "string") return msg.trim();
  const content = msg.content ?? msg.text;
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content.map((p) => {
      if (typeof p === "string") return p;
      if (p && typeof p === "object") return p.text || p.content || "";
      return "";
    }).filter(Boolean).join("\n").trim();
  }
  return "";
}

// Cap an untrusted session .json before buffering it whole (parity with vscdb-kv 32MB / chatgpt 64MB)
// so a large/inflated Continue session can't OOM the worker.
const MAX_SESSION_JSON_BYTES = 32 * 1024 * 1024;

function extractContinueSessionFile(filePath, attribution = {}) {
  const rows = [];
  let data;
  try {
    if (fs.statSync(filePath).size > MAX_SESSION_JSON_BYTES) { dbg("AIHIST", "skip large continue session", { path: filePath }); return rows; }
    data = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return rows;
  }

  const sessionId = data.sessionId || path.basename(filePath, ".json");
  const workspace = data.workspaceDirectory || data.workspace || "";
  const title = data.title || "";
  const history = Array.isArray(data.history) ? data.history : [];

  let idx = 0;
  for (const item of history) {
    idx += 1;
    if (!item || typeof item !== "object") continue; // null/primitive turn — skip, don't deref
    const message = item.message || item;
    if (!message || typeof message !== "object") continue;
    const role = String(message.role || "").toLowerCase();
    if (role !== "user" && role !== "assistant") continue;
    const text = textFromContinueMessage(message);
    if (!text) continue;

    let tsMs = null;
    if (item.timestamp != null) tsMs = parseIsoTimestamp(item.timestamp);
    if (tsMs == null && data.dateCreated) tsMs = parseIsoTimestamp(data.dateCreated);

    rows.push(makeRow({
      timestamp: tsMs != null ? formatTimestampUtc(tsMs) : "",
      role,
      recordType: role,
      summary: title && idx === 1 ? `${text}` : text,
      sessionId: String(sessionId),
      messageId: String(item.message?.id || idx),
      workspace,
      sourceFile: filePath,
      lineNumber: String(idx),
      user: attribution.user || "",
      host: attribution.host || "",
      tool: TOOL_CONTINUE,
    }, TOOL_CONTINUE));
  }

  return rows;
}

async function extractContinueDir(continueRoot, attribution = {}, options = {}) {
  const files = listContinueSessionFiles(continueRoot);
  const rows = [];
  let fileIndex = 0;
  const { onFileProgress, checkAbort } = options;

  for (const filePath of files) {
    if (typeof checkAbort === "function") checkAbort();
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, files.length, filePath);
    try {
      rows.push(...extractContinueSessionFile(filePath, attribution));
    } catch (e) {
      dbg("AIHIST", "continue session failed", { filePath, err: e.message });
    }
    if (fileIndex % 6 === 0) await new Promise((r) => setImmediate(r));
  }

  return finalizeAiHistoryRows(rows, options);
}

async function extractContinuePath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  let stat;
  try { stat = fs.statSync(target); } catch (e) {
    throw new Error(`Cannot read path: ${e.message}`);
  }

  if (stat.isDirectory()) {
    const root = continueHome(target);
    if (!root || !isContinueRoot(root)) {
      throw new Error("Not a Continue .continue directory (expected sessions/*.json).");
    }
    return extractContinueDir(root, attribution, options);
  }

  if (path.extname(target).toLowerCase() === ".json") {
    const sorted = finalizeAiHistoryRows(extractContinueSessionFile(target, attribution), options);
    for (let i = 0; i < sorted.length; i++) sorted[i].RecordId = String(i + 1);
    return sorted;
  }

  throw new Error("Expected a .continue directory or session .json file.");
}

module.exports = {
  CONTINUE_DIR,
  continueHome,
  isContinueRoot,
  listContinueSessionFiles,
  extractContinueDir,
  extractContinuePath,
};
