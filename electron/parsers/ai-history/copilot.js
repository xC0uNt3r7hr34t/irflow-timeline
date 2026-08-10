/**
 * parsers/ai-history/copilot.js — GitHub Copilot (VS Code) chat session extraction.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { readJsonlBounded } = require("./jsonl-reader");

const { dbg } = require("../../logger");
const { TOOL_COPILOT } = require("./schema");
const { tickFileProgress } = require("./extract-plan");
const { formatTimestampUtc, makeRow, finalizeAiHistoryRows, aiHistoryDedupeKey, dedupeAiHistoryRows } = require("./row-utils");
const { decodeWorkspaceUri, formatWorkspaceDisplay } = require("./workspace-utils");
const { buildCopilotExtractionStats } = require("./import-meta");
const copilotCli = require("./copilot-cli");

const CHAT_SESSIONS_DIR = "chatSessions";
const WORKSPACE_STORAGE = "workspaceStorage";
const GLOBAL_EMPTY_SESSIONS = path.join("globalStorage", "emptyWindowChatSessions");

function copilotRow(fields) {
  return makeRow({ ...fields, tool: fields.tool || TOOL_COPILOT }, TOOL_COPILOT);
}

function listCopilotProductDirs() {
  const { listCopilotUserDirs } = require("./artifact-paths");
  return listCopilotUserDirs().filter((p) => fs.existsSync(p));
}

function defaultCopilotWorkspaceStorage() {
  return require("./artifact-paths").defaultCopilotWorkspaceStorage();
}

function loadWorkspaceMap(workspaceStorageDir) {
  const map = new Map();
  if (!workspaceStorageDir || !fs.existsSync(workspaceStorageDir)) return map;

  let entries;
  try { entries = fs.readdirSync(workspaceStorageDir, { withFileTypes: true }); } catch { return map; }

  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const wsJson = path.join(workspaceStorageDir, e.name, "workspace.json");
    try {
      const data = JSON.parse(fs.readFileSync(wsJson, "utf8"));
      const uri = data.folder || data.workspace || "";
      const decoded = decodeWorkspaceUri(uri);
      map.set(e.name, formatWorkspaceDisplay(decoded, e.name));
    } catch {
      map.set(e.name, e.name);
    }
  }
  return map;
}

function stripMarkdownNoise(text) {
  return String(text || "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractMessageText(message) {
  if (!message) return "";
  if (typeof message === "string") return message.trim();
  if (message.text != null && String(message.text).trim()) return String(message.text).trim();

  const parts = message.parts || message.content;
  if (Array.isArray(parts)) {
    const texts = [];
    for (const p of parts) {
      if (!p) continue;
      if (typeof p === "string" && p.trim()) texts.push(p.trim());
      else if (typeof p === "object") {
        const t = p.text ?? p.content ?? p.value;
        if (t != null && String(t).trim()) texts.push(String(t).trim());
      }
    }
    if (texts.length) return texts.join(" ");
  }

  if (message.content && typeof message.content === "string") {
    return message.content.trim();
  }
  return "";
}

function extractResponseText(response) {
  if (!response) return "";
  if (typeof response === "string") return stripMarkdownNoise(response);

  const parts = Array.isArray(response) ? response : response.value;
  if (!Array.isArray(parts)) {
    return extractMessageText(response);
  }

  const texts = [];
  for (const part of parts) {
    if (!part || typeof part !== "object") continue;
    const kind = part.kind || "";
    if (kind === "markdownContent" || kind === "markdownVuln") {
      const v = part.content?.value ?? part.content;
      if (v != null && String(v).trim()) texts.push(stripMarkdownNoise(String(v)));
    } else if (part.text != null && String(part.text).trim()) {
      texts.push(String(part.text).trim());
    }
  }
  return texts.join(" ").trim();
}

function normalizeRequest(req) {
  if (!req || typeof req !== "object") return null;
  const message = req.message || req.prompt;
  const response = req.response;
  if (!extractMessageText(message) && !extractResponseText(response)) return null;
  return req;
}

function mergeRequests(existing, incoming) {
  const byId = new Map();
  for (const r of existing) {
    const id = r.requestId || r.id;
    if (id) byId.set(String(id), r);
  }
  for (const r of incoming) {
    const norm = normalizeRequest(r);
    if (!norm) continue;
    const id = norm.requestId || norm.id || `req-${byId.size}`;
    norm.requestId = String(id);
    byId.set(String(id), norm);
  }
  return [...byId.values()];
}

function applyJsonlOperation(state, obj) {
  if (!obj || typeof obj !== "object") return;

  if (obj.kind === 0) {
    const snap = obj.v || (Array.isArray(obj.requests) ? obj : null);
    if (snap?.requests && Array.isArray(snap.requests)) {
      state.requests = mergeRequests(state.requests, snap.requests);
      state.snapshot = { ...state.snapshot, ...snap, requests: state.requests };
      return;
    }
    if (obj.request) {
      const legacy = {
        requestId: obj.requestId || obj.modelMessageId || `legacy-${state.requests.length}`,
        message: obj.request,
        response: obj.response,
        timestamp: obj.timestamp,
        modelId: obj.modelId,
      };
      state.requests = mergeRequests(state.requests, [legacy]);
    }
  } else if (obj.kind === 2) {
    const req = obj.v || obj.request;
    if (req && typeof req === "object") {
      state.requests = mergeRequests(state.requests, [req]);
    }
  } else if (obj.kind === 1) {
    state.kind1Lines = (state.kind1Lines || 0) + 1;
    const before = state.requests.length;
    if (obj.v?.requests && Array.isArray(obj.v.requests)) {
      state.requests = mergeRequests(state.requests, obj.v.requests);
    } else if (obj.v && typeof obj.v === "object") {
      if (obj.v.requestId || obj.v.message || obj.v.response) {
        state.requests = mergeRequests(state.requests, [obj.v]);
      } else if (obj.v.request && typeof obj.v.request === "object") {
        state.requests = mergeRequests(state.requests, [{
          requestId: obj.v.requestId || obj.v.id,
          message: obj.v.request,
          response: obj.v.response,
          timestamp: obj.v.timestamp,
          modelId: obj.v.modelId,
        }]);
      }
    }
    if (state.requests.length > before) state.kind1Bodies = (state.kind1Bodies || 0) + 1;
  }
}

function newSnapshotState() {
  return { requests: [], snapshot: null, kind1Lines: 0, kind1Bodies: 0 };
}

function finalizeSnapshotState(state) {
  if (state.requests.length) {
    return {
      sessionId: state.snapshot?.sessionId,
      creationDate: state.snapshot?.creationDate,
      lastMessageDate: state.snapshot?.lastMessageDate,
      requests: state.requests,
      _jsonlMeta: { kind1Lines: state.kind1Lines, kind1Bodies: state.kind1Bodies },
    };
  }
  const snap = state.snapshot;
  if (snap) snap._jsonlMeta = { kind1Lines: state.kind1Lines, kind1Bodies: state.kind1Bodies };
  return snap;
}

function buildSnapshotFromJsonlLines(lines) {
  const state = newSnapshotState();
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let obj;
    try { obj = JSON.parse(trimmed); } catch { continue; }
    applyJsonlOperation(state, obj);
  }
  return finalizeSnapshotState(state);
}

async function readJsonlSnapshot(filePath) {
  // Stream line-by-line through the bounded reader rather than buffering the whole untrusted
  // .jsonl into a lines[] array first — a large/inflated session file would otherwise OOM the worker.
  const state = newSnapshotState();
  await readJsonlBounded(filePath, (obj) => applyJsonlOperation(state, obj));
  return finalizeSnapshotState(state);
}

// Cap untrusted single-file .json sessions before buffering them whole (parity with vscdb-kv 32MB /
// chatgpt 64MB). The .jsonl sibling already streams via readJsonlBounded; this guards the .json path
// so a large/inflated session can't OOM the worker.
const MAX_SESSION_JSON_BYTES = 32 * 1024 * 1024;

function readJsonSnapshot(filePath) {
  let data;
  // Untrusted single-file path: a malformed file (JSON.parse throw) or a literal `null`/primitive
  // must yield null, not crash. The previous `data && ...` short-circuit still fell through to
  // `data.requests` on a null document. Size-gate FIRST so a huge .json is never read into memory.
  try {
    if (fs.statSync(filePath).size > MAX_SESSION_JSON_BYTES) { dbg("AIHIST", "skip large copilot json", { path: filePath }); return null; }
    data = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch { return null; }
  if (!data || typeof data !== "object") return null;
  if (data.kind === 0 && data.v) return data.v;
  if (Array.isArray(data.requests)) return data;
  return null;
}

function sessionIdFromPath(filePath) {
  return path.basename(filePath, path.extname(filePath));
}

function sessionRowsFromSnapshot(snapshot, sourceFile, workspace, attribution) {
  const rows = [];
  const wsDisplay = formatWorkspaceDisplay(workspace, workspace);
  const sessionId = snapshot?.sessionId != null
    ? String(snapshot.sessionId)
    : sessionIdFromPath(sourceFile);
  const sessionFallback = snapshot?.creationDate ?? snapshot?.lastMessageDate ?? null;
  const requests = Array.isArray(snapshot?.requests) ? snapshot.requests : [];

  for (const req of requests) {
    const reqId = req.requestId != null ? String(req.requestId) : "";
    const tsMs = req.timestamp ?? sessionFallback;

    const userText = extractMessageText(req.message);
    if (userText) {
      rows.push(copilotRow({
        timestamp: formatTimestampUtc(tsMs),
        role: "user",
        recordType: "user",
        summary: userText,
        sessionId,
        messageId: reqId,
        workspace: wsDisplay,
        model: req.modelId != null ? String(req.modelId) : "",
        sourceFile,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    const assistantText = extractResponseText(req.response);
    if (assistantText) {
      rows.push(copilotRow({
        timestamp: formatTimestampUtc(tsMs != null ? tsMs + 1 : null),
        role: "assistant",
        recordType: "assistant",
        summary: assistantText,
        sessionId,
        messageId: reqId ? `${reqId}-response` : "",
        parentId: reqId,
        workspace: wsDisplay,
        model: req.modelId != null ? String(req.modelId) : "",
        sourceFile,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }
  }

  return rows;
}

function listSessionFilesInDir(chatSessionsDir) {
  const out = [];
  if (!chatSessionsDir || !fs.existsSync(chatSessionsDir)) return out;
  let entries;
  try { entries = fs.readdirSync(chatSessionsDir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (!e.isFile()) continue;
    const ext = path.extname(e.name).toLowerCase();
    if (ext === ".json" || ext === ".jsonl") out.push(path.join(chatSessionsDir, e.name));
  }
  return out;
}

/** Prefer .jsonl over .json for the same session UUID. */
function pickSessionFiles(files) {
  const byId = new Map();
  for (const fp of files) {
    const id = sessionIdFromPath(fp);
    const ext = path.extname(fp).toLowerCase();
    const prev = byId.get(id);
    if (!prev) {
      byId.set(id, fp);
      continue;
    }
    if (ext === ".jsonl" && path.extname(prev).toLowerCase() !== ".jsonl") {
      byId.set(id, fp);
    }
  }
  return [...byId.values()];
}

function isChatSessionsDir(dirPath) {
  if (!dirPath || path.basename(dirPath) !== CHAT_SESSIONS_DIR) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  return listSessionFilesInDir(dirPath).length > 0
    || fs.existsSync(path.join(path.dirname(dirPath), "workspace.json"));
}

function isCopilotWorkspaceStorageDir(dirPath) {
  if (!dirPath) return false;
  const chatDir = path.join(dirPath, CHAT_SESSIONS_DIR);
  return fs.existsSync(chatDir);
}

function resolveCopilotRoot(target) {
  if (!target) return null;
  const cliRoot = copilotCli.resolveCopilotCliRoot(target);
  if (cliRoot) return cliRoot;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  for (let i = 0; i < 22; i++) {
    if (path.basename(p) === CHAT_SESSIONS_DIR && isChatSessionsDir(p)) {
      return path.dirname(p);
    }
    if (path.basename(p) === WORKSPACE_STORAGE) return p;
    if (path.basename(p) === "emptyWindowChatSessions") {
      return p;
    }
    if (isCopilotWorkspaceStorageDir(p)) return p;
    if (path.basename(p) === "User") {
      const ws = path.join(p, WORKSPACE_STORAGE);
      if (fs.existsSync(ws)) return ws;
    }
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

function countCopilotExtractFiles(root, options = {}) {
  void options;
  const cliRoot = copilotCli.resolveCopilotCliRoot(root);
  if (cliRoot) return copilotCli.countCopilotCliExtractFiles(cliRoot);
  return collectCopilotSessionFiles(root).length;
}

function collectCopilotSessionFiles(root) {
  if (!root || !fs.existsSync(root)) return [];

  const base = path.basename(root);
  if (base === CHAT_SESSIONS_DIR) {
    return pickSessionFiles(listSessionFilesInDir(root));
  }
  if (base === "emptyWindowChatSessions") {
    return pickSessionFiles(listSessionFilesInDir(root));
  }
  if (base === WORKSPACE_STORAGE) {
    const all = [];
    let entries;
    try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return all; }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      all.push(...listSessionFilesInDir(path.join(root, e.name, CHAT_SESSIONS_DIR)));
    }
    const globalDir = path.join(path.dirname(root), GLOBAL_EMPTY_SESSIONS);
    if (fs.existsSync(globalDir)) {
      all.push(...listSessionFilesInDir(globalDir));
    }
    return pickSessionFiles(all);
  }
  if (isCopilotWorkspaceStorageDir(root)) {
    return pickSessionFiles(listSessionFilesInDir(path.join(root, CHAT_SESSIONS_DIR)));
  }

  const resolved = resolveCopilotRoot(root);
  if (resolved && resolved !== root) return collectCopilotSessionFiles(resolved);

  const all = [];
  for (const userDir of listCopilotProductDirs()) {
    const ws = path.join(userDir, WORKSPACE_STORAGE);
    if (fs.existsSync(ws)) all.push(...collectCopilotSessionFiles(ws));
    const globalDir = path.join(userDir, GLOBAL_EMPTY_SESSIONS);
    if (fs.existsSync(globalDir)) all.push(...listSessionFilesInDir(globalDir));
  }
  return pickSessionFiles(all);
}

async function extractSessionFile(filePath, workspace, attribution, stats) {
  stats.sessionsScanned += 1;
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".jsonl") stats.jsonlFiles += 1;
  else stats.jsonFiles += 1;

  let snapshot = ext === ".jsonl"
    ? await readJsonlSnapshot(filePath)
    : readJsonSnapshot(filePath);

  const jsonlSibling = ext === ".json"
    ? filePath.replace(/\.json$/i, ".jsonl")
    : null;
  const requestCount = Array.isArray(snapshot?.requests) ? snapshot.requests.length : 0;
  if (requestCount === 0 && jsonlSibling && fs.existsSync(jsonlSibling)) {
    snapshot = await readJsonlSnapshot(jsonlSibling);
    stats.jsonlSiblingFallback = (stats.jsonlSiblingFallback || 0) + 1;
    stats.jsonlFiles += 1;
  }

  if (!snapshot) return [];

  if (snapshot._jsonlMeta) {
    stats.kind1Lines = (stats.kind1Lines || 0) + snapshot._jsonlMeta.kind1Lines;
    stats.kind1Bodies = (stats.kind1Bodies || 0) + snapshot._jsonlMeta.kind1Bodies;
  }

  const rows = sessionRowsFromSnapshot(snapshot, filePath, workspace, attribution);
  if (rows.length) stats.sessionsWithMessages += 1;
  else {
    stats.emptySessions += 1;
    if (ext === ".jsonl" || stats.jsonlSiblingFallback) stats.emptyAfterJsonlReplay += 1;
  }
  return rows;
}

const isMsgRow = (r) => r.Role === "user" || r.Role === "assistant";

/**
 * Streaming-or-accumulate emitter for session rows. When `onExtractedRows` is set (the streamed
 * worker path) each file's rows go STRAIGHT to the sink — peak heap stays at one file's rows instead
 * of the whole workspace corpus (the prior code accumulated every row, FullText and all, until return).
 * It also remembers each streamed row's dedupe KEY (small strings, not full rows) so the vscdb
 * supplement below can still dedupe session↔vscdb without holding the session rows. In the in-memory
 * path it accumulates into `rows` exactly as before (behaviour byte-identical).
 */
function makeRowEmitter(rows, onExtractedRows) {
  const streamedKeys = onExtractedRows ? new Set() : null;
  let streamMsg = 0;
  const emit = (chunk) => {
    if (!chunk || !chunk.length) return;
    if (onExtractedRows) {
      // Skip rows whose dedupe key already streamed (inter-session dedup — mirrors the in-memory
      // supplement's dedupeAiHistoryRows), then stream straight to the sink. Peak heap = one file's
      // rows + the (small, key-string) Set, not the whole workspace corpus.
      const fresh = [];
      for (const r of chunk) {
        const k = aiHistoryDedupeKey(r);
        if (streamedKeys.has(k)) continue;
        streamedKeys.add(k);
        if (isMsgRow(r)) streamMsg += 1;
        fresh.push(r);
      }
      if (fresh.length) onExtractedRows(fresh);
    } else {
      rows.push(...chunk);
    }
  };
  // msg count: the live counter while streaming, else derived from the accumulated rows.
  const getMsgCount = () => (onExtractedRows ? streamMsg : rows.filter(isMsgRow).length);
  return { emit, streamedKeys, getMsgCount };
}

async function extractChatSessionsDir(chatSessionsDir, workspace, attribution = {}, options = {}) {
  const files = pickSessionFiles(listSessionFilesInDir(chatSessionsDir));
  const rows = [];
  const stats = {
    sessionsScanned: 0,
    sessionsWithMessages: 0,
    emptySessions: 0,
    jsonlFiles: 0,
    jsonFiles: 0,
  };
  const { emit } = makeRowEmitter(rows, options.onExtractedRows);
  let fileIndex = 0;

  for (const filePath of files) {
    fileIndex += 1;
    tickFileProgress(options.onFileProgress, fileIndex, files.length, filePath);
    try {
      emit(await extractSessionFile(filePath, workspace, attribution, stats));
    } catch (e) {
      dbg("AIHIST", "copilot session failed", { path: filePath, err: e.message });
    }
  }

  // Streamed: `rows` is empty (everything went to the sink); the return carries only _copilotStats.
  rows._copilotStats = stats;
  return rows;
}

async function extractWorkspaceStorageDir(storageDir, attribution = {}, options = {}) {
  const wsMap = loadWorkspaceMap(storageDir);
  const rows = [];
  const combinedStats = {
    sessionsScanned: 0,
    sessionsWithMessages: 0,
    emptySessions: 0,
    jsonlFiles: 0,
    jsonFiles: 0,
  };

  let entries;
  try { entries = fs.readdirSync(storageDir, { withFileTypes: true }); } catch { entries = []; }

  const buckets = [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const chatDir = path.join(storageDir, e.name, CHAT_SESSIONS_DIR);
    if (!fs.existsSync(chatDir)) continue;
    buckets.push({ chatDir, workspace: wsMap.get(e.name) || e.name });
  }

  const globalDir = path.join(path.dirname(storageDir), GLOBAL_EMPTY_SESSIONS);
  if (fs.existsSync(globalDir)) {
    buckets.push({ chatDir: globalDir, workspace: "(no workspace — empty window)" });
  }

  const { emit, streamedKeys, getMsgCount } = makeRowEmitter(rows, options.onExtractedRows);
  let fileIndex = 0;
  const totalFiles = buckets.reduce((n, b) => n + listSessionFilesInDir(b.chatDir).length, 0);

  for (const { chatDir, workspace } of buckets) {
    const files = pickSessionFiles(listSessionFilesInDir(chatDir));
    for (const filePath of files) {
      fileIndex += 1;
      tickFileProgress(options.onFileProgress, fileIndex, Math.max(totalFiles, 1), filePath);
      try {
        emit(await extractSessionFile(filePath, workspace, attribution, combinedStats));
      } catch (e) {
        dbg("AIHIST", "copilot session failed", { path: filePath, err: e.message });
      }
    }
  }

  const msgCount = getMsgCount();
  const sparseSessions = combinedStats.sessionsScanned > 0
    && combinedStats.sessionsWithMessages < combinedStats.sessionsScanned;
  const needsVscdbSupplement = msgCount < 8
    || combinedStats.emptySessions > 0
    || sparseSessions;
  if (needsVscdbSupplement) {
    try {
      const userDir = path.dirname(storageDir);
      const { extractVsCodeUserChatDir, COPILOT_PROVIDER_RE } = require("./vscode-chat-db");
      // extractVsCodeUserChatDir RETURNS its rows (never streams) — pass onExtractedRows:undefined so
      // we always get the array to dedupe the supplement against the session rows.
      const { rows: vscRows, stats: vscStats } = await extractVsCodeUserChatDir(
        userDir,
        TOOL_COPILOT,
        attribution,
        {
          ...options,
          onExtractedRows: undefined,
          providerFilter: (entry) => COPILOT_PROVIDER_RE.test(`${entry?.providerType || ""} ${entry?.providerLabel || ""}`),
        },
      );
      if (vscStats?.alternateAgentSessions) {
        combinedStats.alternateAgentSessions = (combinedStats.alternateAgentSessions || 0)
          + vscStats.alternateAgentSessions;
      }
      if (vscRows.length) {
        if (options.onExtractedRows) {
          // Streamed: session rows already went to the sink. Dedupe the supplement against their keys
          // (and within itself) and stream the survivors — only the key Set was held, not the rows.
          const fresh = dedupeAiHistoryRows(vscRows.filter((r) => !streamedKeys.has(aiHistoryDedupeKey(r))));
          combinedStats.vscdbSupplement = fresh.filter(isMsgRow).length;
          if (fresh.length) options.onExtractedRows(fresh);
        } else {
          const beforeMsg = msgCount;
          const merged = dedupeAiHistoryRows([...rows, ...vscRows]);
          rows.length = 0;
          rows.push(...merged);
          const afterMsg = rows.filter(isMsgRow).length;
          combinedStats.vscdbSupplement = Math.max(0, afterMsg - beforeMsg);
        }
      }
    } catch (e) {
      dbg("AIHIST", "copilot vscdb supplement failed", { err: e.message });
    }
  }

  // Streamed: `rows` is empty (everything went to the sink); return carries only _copilotStats.
  rows._copilotStats = combinedStats;
  return rows;
}

async function extractCopilotPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  const cliRoot = copilotCli.resolveCopilotCliRoot(target);
  if (cliRoot) return copilotCli.extractCopilotCliPath(cliRoot, attribution, options);

  let stat;
  try { stat = fs.statSync(target); } catch (e) {
    throw new Error(`Cannot read path: ${e.message}`);
  }

  let rows;
  if (stat.isDirectory()) {
    const base = path.basename(target);
    if (base === CHAT_SESSIONS_DIR) {
      const wsHash = path.basename(path.dirname(target));
      const storageDir = path.dirname(path.dirname(target));
      const wsMap = loadWorkspaceMap(storageDir);
      rows = await extractChatSessionsDir(target, wsMap.get(wsHash) || "", attribution, options);
    } else if (base === "emptyWindowChatSessions") {
      rows = await extractChatSessionsDir(target, "(no workspace — empty window)", attribution, options);
    } else if (base === WORKSPACE_STORAGE) {
      rows = await extractWorkspaceStorageDir(target, attribution, options);
    } else if (isCopilotWorkspaceStorageDir(target)) {
      const storageDir = path.dirname(target);
      const wsMap = loadWorkspaceMap(storageDir);
      const hash = path.basename(target);
      rows = await extractChatSessionsDir(
        path.join(target, CHAT_SESSIONS_DIR),
        wsMap.get(hash) || "",
        attribution,
        options,
      );
    } else if (path.basename(target) === "User") {
      const ws = path.join(target, WORKSPACE_STORAGE);
      if (fs.existsSync(ws)) return extractCopilotPath(ws, attribution, options);
      throw new Error("Not a Copilot workspaceStorage, chatSessions, or emptyWindowChatSessions folder.");
    } else {
      const root = resolveCopilotRoot(target);
      if (root) return extractCopilotPath(root, attribution, options);
      throw new Error("Not a Copilot workspaceStorage, chatSessions, or emptyWindowChatSessions folder.");
    }
  } else {
    const chatDir = path.dirname(target);
    let workspace = "";
    if (path.basename(path.dirname(chatDir)) === WORKSPACE_STORAGE) {
      const storageDir = path.dirname(path.dirname(chatDir));
      const wsMap = loadWorkspaceMap(storageDir);
      workspace = wsMap.get(path.basename(path.dirname(chatDir))) || "";
    } else if (path.basename(chatDir) === "emptyWindowChatSessions") {
      workspace = "(no workspace — empty window)";
    }
    const stats = {
      sessionsScanned: 0,
      sessionsWithMessages: 0,
      emptySessions: 0,
      jsonlFiles: 0,
      jsonFiles: 0,
    };
    rows = await extractSessionFile(target, workspace, attribution, stats);
    rows._copilotStats = stats;
  }

  const sorted = finalizeAiHistoryRows(rows, options);
  sorted._copilotStats = rows._copilotStats;
  return sorted;
}

function getCopilotExtractionStats(rows) {
  return rows._copilotStats || buildCopilotExtractionStats(rows, {});
}

module.exports = {
  CHAT_SESSIONS_DIR,
  WORKSPACE_STORAGE,
  GLOBAL_EMPTY_SESSIONS,
  defaultCopilotWorkspaceStorage,
  listCopilotProductDirs,
  decodeWorkspaceUri,
  loadWorkspaceMap,
  formatWorkspaceDisplay,
  isChatSessionsDir,
  isCopilotWorkspaceStorageDir,
  resolveCopilotRoot,
  listSessionFilesInDir,
  collectCopilotSessionFiles,
  countCopilotExtractFiles,
  extractCopilotPath,
  extractChatSessionsDir,
  extractWorkspaceStorageDir,
  sessionRowsFromSnapshot,
  buildSnapshotFromJsonlLines,
  extractMessageText,
  extractResponseText,
  getCopilotExtractionStats,
  buildCopilotExtractionStats,
  ...copilotCli,
};
