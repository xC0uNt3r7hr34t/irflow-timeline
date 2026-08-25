/**
 * parsers/ai-history/gemini-cli.js — Google Gemini CLI session extraction.
 *
 * Artifacts:
 * - ~/.gemini/tmp/<hash>/chats/session-*.jsonl — current append-only session records
 * - ~/.gemini/tmp/<hash>/chats/session-*.json — legacy { messages: [...] } sessions
 * - ~/.gemini/tmp/<hash>/logs.json — legacy CLI log array [{ type, message, timestamp, sessionId, messageId }]
 * - ~/.gemini/tmp/<hash>/shell_history — project-scoped shell command history
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { tickFileProgress } = require("./extract-plan");
const { TOOL_GEMINI_CLI } = require("./schema");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, finalizeAiHistoryRows } = require("./row-utils");
const { parseChatgptTimestamp } = require("./chatgpt");
const { readJsonlBounded } = require("./jsonl-reader");
const { buildToolEvidence, serializeEvidenceValue } = require("./tool-evidence");

const GEMINI_DIR_NAME = ".gemini";
const LOGS_FILE_NAME = "logs.json";
const SHELL_HISTORY_FILE_NAME = "shell_history";
const SESSION_FILE_RE = /^session-.+\.(?:json|jsonl)$/i;
const CHECKPOINT_FILE_RE = /^checkpoint-.+\.json$/i;
const MAX_LEGACY_SESSION_BYTES = 32 * 1024 * 1024;
const MAX_SHELL_HISTORY_BYTES = 4 * 1024 * 1024;

const ROLE_BY_TYPE = {
  user: "user",
  gemini: "assistant",
  assistant: "assistant",
  model: "assistant",
  system: "system",
  error: "system",
  info: "system",
  tool: "tool",
  function: "tool",
};

function parseMessageTimestamp(value, fallbackMs) {
  if (value == null || value === "") {
    return fallbackMs != null ? fallbackMs : null;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1e12 ? value : value * 1000;
  }
  return parseChatgptTimestamp(value) ?? parseIsoTimestamp(String(value));
}

function parseTokenCounts(tokens) {
  if (!tokens || typeof tokens !== "object") return { input: 0, output: 0 };
  const input = tokens.input ?? tokens.inputTokens ?? tokens.prompt ?? tokens.promptTokenCount ?? 0;
  const output = tokens.output ?? tokens.outputTokens ?? tokens.completion ?? tokens.candidatesTokenCount ?? 0;
  return {
    input: Number(input) || 0,
    output: Number(output) || 0,
  };
}

function normalizeThoughts(thoughts) {
  if (!thoughts) return "";
  const values = Array.isArray(thoughts) ? thoughts : [thoughts];
  return values.map((thought) => {
    if (typeof thought === "string") return thought;
    if (!thought || typeof thought !== "object") return "";
    const subject = thought.subject != null ? String(thought.subject).trim() : "";
    const description = thought.description != null ? String(thought.description).trim() : "";
    const text = thought.text ?? thought.summary?.text ?? thought.summary ?? "";
    return [subject, description, typeof text === "string" ? text.trim() : ""]
      .filter(Boolean)
      .join(": ");
  }).filter(Boolean).join("\n");
}

function contentText(content) {
  let text = "";
  if (typeof content === "string") text = content.trim();
  else if (Array.isArray(content)) {
    text = content.map((p) => {
      if (typeof p === "string") return p;
      if (p && typeof p === "object") return p.text || p.content || "";
      return "";
    }).filter(Boolean).join(" ");
  } else if (content && typeof content === "object") {
    text = String(content.text || content.content || "").trim();
  }
  return text;
}

function normalizeContent(content, thoughts) {
  let text = contentText(content);
  const thoughtText = normalizeThoughts(thoughts);
  if (!text && thoughtText) text = "[Reasoning only]";
  else if (thoughtText) text = `${text} [Reasoning present]`.trim();
  return text;
}

function geminiRow(fields) {
  return makeRow({ ...fields, tool: fields.tool || TOOL_GEMINI_CLI }, TOOL_GEMINI_CLI);
}

function isNestedSubagentSession(sessionPath) {
  const norm = String(sessionPath || "").replace(/\\/g, "/");
  const afterChats = norm.split(/\/chats\//i)[1];
  return !!afterChats && afterChats.split("/").filter(Boolean).length > 1;
}

function parentSessionIdFromPath(sessionPath) {
  if (!isNestedSubagentSession(sessionPath)) return "";
  return path.basename(path.dirname(sessionPath));
}

function geminiWorkspace(data) {
  const directories = Array.isArray(data?.directories)
    ? data.directories.filter((p) => typeof p === "string" && p.trim())
    : [];
  if (directories.length) return directories.join(", ");
  return data?.projectHash != null ? String(data.projectHash) : "";
}

function rowsFromGeminiConversation(data, sessionPath, attribution = {}) {
  if (!data || typeof data !== "object") return [];
  const messages = Array.isArray(data.messages) ? data.messages : [];
  if (!messages.length) return [];

  const sessionId = data.sessionId != null ? String(data.sessionId) : "";
  const workspace = geminiWorkspace(data);
  const sessionFallback = parseMessageTimestamp(data.startTime)
    ?? parseMessageTimestamp(data.lastUpdated);
  const isSidechain = data.kind === "subagent" || isNestedSubagentSession(sessionPath);
  const parentSessionId = parentSessionIdFromPath(sessionPath);
  const rows = [];
  let idx = 0;

  for (let msgIdx = 0; msgIdx < messages.length; msgIdx++) {
    const msg = messages[msgIdx];
    if (!msg || typeof msg !== "object") continue;
    const lineNumber = msg.__irflowLineNumber ?? (msgIdx + 1);
    const msgType = msg.type != null ? String(msg.type).toLowerCase() : "";
    const role = ROLE_BY_TYPE[msgType] || (msgType ? "system" : "");
    const messageId = msg.id != null
      ? String(msg.id)
      : `${sessionId || path.basename(sessionPath)}-${idx + 1}`;
    const tsMs = parseMessageTimestamp(msg.timestamp, sessionFallback);
    const thoughtText = normalizeThoughts(msg.thoughts);

    let summary = normalizeContent(msg.content, msg.thoughts);
    if (!summary && msg.message != null) summary = String(msg.message).trim();
    if (!summary && msg.error) summary = String(msg.error).trim();
    if (!summary && msgType === "error") summary = "[Error event]";
    if (!summary && role && !Array.isArray(msg.toolCalls)) summary = `[${msgType || role} event]`;

    if (summary) {
      const tokens = parseTokenCounts(msg.tokens);
      const bodyText = contentText(msg.content);
      const fullText = thoughtText
        ? `${bodyText ? `${bodyText}\n\n` : ""}Reasoning:\n${thoughtText}`
        : (bodyText || summary);
      idx += 1;
      rows.push(geminiRow({
        timestamp: formatTimestampUtc(tsMs),
        role: role || "system",
        recordType: msgType || role || "event",
        summary,
        fullText,
        toolName: "",
        sessionId,
        messageId,
        parentId: parentSessionId,
        workspace,
        isSidechain,
        gitBranch: "",
        model: msg.model != null ? String(msg.model) : "",
        inputTokens: tokens.input,
        outputTokens: tokens.output,
        sourceFile: sessionPath,
        lineNumber,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }

    const toolCalls = Array.isArray(msg.toolCalls) ? msg.toolCalls : [];
    for (let toolIdx = 0; toolIdx < toolCalls.length; toolIdx++) {
      const call = toolCalls[toolIdx];
      if (!call || typeof call !== "object" || !call.name) continue;
      const callId = call.id != null ? String(call.id) : `${messageId}-tool-${toolIdx + 1}`;
      const callTs = parseMessageTimestamp(call.timestamp, tsMs);
      const status = call.status != null ? String(call.status) : "";
      const evidence = buildToolEvidence([{ name: call.name, input: call.args }]);
      rows.push(geminiRow({
        timestamp: formatTimestampUtc(callTs),
        role: "tool",
        recordType: "tool_call",
        summary: `${call.name}${status ? ` (${status})` : ""}`,
        fullText: serializeEvidenceValue(call.args),
        ...evidence,
        sessionId,
        messageId: callId,
        parentId: messageId,
        workspace,
        isSidechain,
        model: msg.model != null ? String(msg.model) : "",
        sourceFile: sessionPath,
        lineNumber,
        user: attribution.user || "",
        host: attribution.host || "",
      }));

      if (call.result != null || call.resultDisplay != null) {
        const result = call.result ?? call.resultDisplay;
        rows.push(geminiRow({
          timestamp: formatTimestampUtc(callTs),
          role: "tool",
          recordType: "tool_result",
          summary: `${call.name} result${status ? ` (${status})` : ""}`,
          fullText: serializeEvidenceValue(result),
          ...evidence,
          sessionId,
          messageId: `${callId}-result`,
          parentId: callId,
          workspace,
          isSidechain,
          model: msg.model != null ? String(msg.model) : "",
          sourceFile: sessionPath,
          lineNumber,
          user: attribution.user || "",
          host: attribution.host || "",
        }));
      }
    }
  }

  return rows;
}

/**
 * Parse one Gemini CLI session JSON file into timeline rows.
 */
function extractGeminiSessionFile(sessionPath, attribution = {}) {
  let data;
  try {
    if (fs.statSync(sessionPath).size > MAX_LEGACY_SESSION_BYTES) {
      dbg("AIHIST", "skip large gemini legacy session", { sessionPath });
      return [];
    }
    data = JSON.parse(fs.readFileSync(sessionPath, "utf8"));
  } catch (e) {
    dbg("AIHIST", "gemini session parse failed", { sessionPath, err: e.message });
    return [];
  }

  // JSON.parse("null") (and primitives/arrays) survive the try/catch above; guard before deref.
  if (!data || typeof data !== "object") return [];
  return rowsFromGeminiConversation(data, sessionPath, attribution);
}

function setGeminiMessageLineNumber(msg, lineNumber) {
  if (!msg || typeof msg !== "object") return null;
  return { ...msg, __irflowLineNumber: lineNumber };
}

async function extractGeminiSessionJsonlFile(sessionPath, attribution = {}, options = {}) {
  const metadata = {};
  const messages = new Map();
  const parseStats = options.parseStats || { errors: 0 };

  await readJsonlBounded(sessionPath, (record, lineNumber) => {
    if (!record || typeof record !== "object" || Array.isArray(record)) return;

    if (typeof record.$rewindTo === "string") {
      let found = false;
      for (const id of [...messages.keys()]) {
        if (id === record.$rewindTo) found = true;
        if (found) messages.delete(id);
      }
      if (!found) messages.clear();
      return;
    }

    if (record.$set && typeof record.$set === "object" && !Array.isArray(record.$set)) {
      if (Array.isArray(record.$set.messages)) {
        messages.clear();
        for (const msg of record.$set.messages) {
          if (!msg || typeof msg !== "object" || msg.id == null) continue;
          messages.set(String(msg.id), setGeminiMessageLineNumber(msg, lineNumber));
        }
      }
      Object.assign(metadata, record.$set);
      return;
    }

    if (record.id != null && record.type != null && record.content != null) {
      messages.set(String(record.id), setGeminiMessageLineNumber(record, lineNumber));
      return;
    }

    if (record.sessionId != null || record.projectHash != null) {
      Object.assign(metadata, record);
      if (Array.isArray(record.messages)) {
        for (const msg of record.messages) {
          if (!msg || typeof msg !== "object" || msg.id == null) continue;
          messages.set(String(msg.id), setGeminiMessageLineNumber(msg, lineNumber));
        }
      }
    }
  }, { parseStats });

  return rowsFromGeminiConversation(
    { ...metadata, messages: [...messages.values()] },
    sessionPath,
    attribution,
  );
}

function extractGeminiShellHistoryFile(historyPath, attribution = {}) {
  let raw;
  try {
    if (fs.statSync(historyPath).size > MAX_SHELL_HISTORY_BYTES) {
      dbg("AIHIST", "skip large gemini shell history", { historyPath });
      return [];
    }
    raw = fs.readFileSync(historyPath, "utf8");
  } catch {
    return [];
  }

  const workspace = path.basename(path.dirname(historyPath));
  const commands = [];
  let current = "";
  let startLine = 0;
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const line = lines[i];
    if (!line.trim()) continue;
    const trailingSlashes = current.match(/(\\+)$/);
    if (current && trailingSlashes && trailingSlashes[1].length % 2 === 1) {
      current = `${current.slice(0, -1)} ${line}`;
      continue;
    }
    if (current) commands.push({ command: current, lineNumber: startLine });
    current = line;
    startLine = lineNumber;
  }
  if (current) commands.push({ command: current, lineNumber: startLine });

  return commands.map(({ command, lineNumber }, index) => {
    const evidence = buildToolEvidence([{
      name: "run_shell_command",
      input: { command },
    }]);
    return geminiRow({
      timestamp: "",
      role: "user",
      recordType: "shell_history",
      summary: command,
      fullText: command,
      ...evidence,
      sessionId: "",
      messageId: `shell-history-${index + 1}`,
      workspace,
      isSidechain: false,
      sourceFile: historyPath,
      lineNumber,
      user: attribution.user || "",
      host: attribution.host || "",
    });
  });
}

/**
 * Parse legacy tmp/<hash>/logs.json (array of { type, message, timestamp, sessionId, messageId }).
 */
function extractGeminiLogsFile(logsPath, attribution = {}) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(logsPath, "utf8"));
  } catch (e) {
    dbg("AIHIST", "gemini logs parse failed", { logsPath, err: e.message });
    return [];
  }

  const entries = Array.isArray(data)
    ? data
    : (Array.isArray(data?.messages) ? data.messages : (Array.isArray(data?.logs) ? data.logs : []));
  if (!entries.length) return [];

  const workspace = path.basename(path.dirname(logsPath));
  const rows = [];

  for (let msgIdx = 0; msgIdx < entries.length; msgIdx++) {
    const msg = entries[msgIdx];
    if (!msg || typeof msg !== "object") continue;

    const msgType = msg.type != null ? String(msg.type).toLowerCase() : "";
    const role = ROLE_BY_TYPE[msgType] || (msgType ? "system" : "user");

    let summary = normalizeContent(msg.content ?? msg.message, msg.thoughts);
    if (!summary && msg.error) summary = String(msg.error).trim();
    if (!summary && msgType === "error") summary = "[Error event]";
    if (!summary && role) summary = `[${msgType || role} event]`;
    if (!summary) continue;

    const tsMs = parseMessageTimestamp(msg.timestamp);
    if (tsMs == null) continue;

    const sessionId = msg.sessionId != null ? String(msg.sessionId) : "";
    const msgKey = msg.messageId != null ? String(msg.messageId) : String(msgIdx + 1);
    const tokens = parseTokenCounts(msg.tokens);

    rows.push(geminiRow({
      timestamp: formatTimestampUtc(tsMs),
      role: role || "user",
      recordType: msgType || role || "event",
      summary,
      toolName: "",
      sessionId,
      messageId: sessionId ? `${sessionId}-${msgKey}` : `${path.basename(logsPath)}-${msgKey}`,
      parentId: "",
      workspace,
      isSidechain: false,
      gitBranch: "",
      model: msg.model != null ? String(msg.model) : "",
      inputTokens: tokens.input,
      outputTokens: tokens.output,
      sourceFile: logsPath,
      lineNumber: msgIdx + 1,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  return rows;
}

function isGeminiLogsFile(filePath) {
  if (!filePath || path.basename(filePath) !== LOGS_FILE_NAME) return false;
  const norm = filePath.replace(/\\/g, "/").toLowerCase();
  return norm.includes(`/${GEMINI_DIR_NAME}/tmp/`);
}

function isGeminiSessionFile(filePath) {
  const base = path.basename(filePath);
  const norm = filePath.replace(/\\/g, "/").toLowerCase();
  if (!norm.includes(`/${GEMINI_DIR_NAME}/`)) return false;
  if (SESSION_FILE_RE.test(base)) return norm.includes("/chats/");
  if (base.toLowerCase().endsWith(".jsonl") && norm.includes("/chats/")) return true;
  if (CHECKPOINT_FILE_RE.test(base)) return norm.includes("/tmp/");
  return false;
}

function isGeminiShellHistoryFile(filePath) {
  if (!filePath || path.basename(filePath) !== SHELL_HISTORY_FILE_NAME) return false;
  const norm = filePath.replace(/\\/g, "/").toLowerCase();
  return norm.includes(`/${GEMINI_DIR_NAME}/tmp/`);
}

function isGeminiDataFile(filePath) {
  return isGeminiSessionFile(filePath)
    || isGeminiLogsFile(filePath)
    || isGeminiShellHistoryFile(filePath);
}

function walkGeminiTmp(geminiRoot, onFile, limits = { maxDirs: 96, maxDepth: 6 }) {
  const tmpDir = path.join(geminiRoot, "tmp");
  if (!fs.existsSync(tmpDir)) return;
  let dirsVisited = 0;
  const stack = [{ d: tmpDir, depth: 0 }];
  while (stack.length && dirsVisited < limits.maxDirs) {
    const { d, depth } = stack.pop();
    dirsVisited += 1;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isFile()) onFile(full);
      if (e.isDirectory() && depth < limits.maxDepth && !e.isSymbolicLink()) {
        stack.push({ d: full, depth: depth + 1 });
      }
    }
  }
}

/** Fast existence check for discovery (bounded walk — avoids hanging on huge ~/.gemini/tmp). */
function hasGeminiSessionsQuick(geminiRoot, limits = { maxDirs: 96, maxDepth: 6 }) {
  const tmpDir = path.join(geminiRoot, "tmp");
  if (!fs.existsSync(tmpDir)) return false;
  let found = false;
  walkGeminiTmp(geminiRoot, (full) => {
    if (!found && isGeminiDataFile(full)) found = true;
  }, limits);
  return found;
}

/** List current JSONL and legacy JSON session files under geminiRoot/tmp/.../chats/. */
function listSessionJsonFiles(geminiRoot) {
  const out = [];
  walkGeminiTmp(geminiRoot, (full) => {
    if (isGeminiSessionFile(full)) out.push(full);
  }, { maxDirs: 10_000, maxDepth: 12 });
  return out;
}

function listShellHistoryFiles(geminiRoot) {
  const out = [];
  walkGeminiTmp(geminiRoot, (full) => {
    if (isGeminiShellHistoryFile(full)) out.push(full);
  }, { maxDirs: 10_000, maxDepth: 12 });
  return out;
}

/** List tmp/<hash>/logs.json files (legacy Gemini CLI conversation log). */
function listLogsJsonFiles(geminiRoot) {
  const out = [];
  walkGeminiTmp(geminiRoot, (full) => {
    if (isGeminiLogsFile(full)) out.push(full);
  }, { maxDirs: 10_000, maxDepth: 12 });
  return out;
}

/** All parseable Gemini CLI JSON artifacts under a .gemini root. */
function listGeminiDataFiles(geminiRoot) {
  return [
    ...listSessionJsonFiles(geminiRoot),
    ...listLogsJsonFiles(geminiRoot),
    ...listShellHistoryFiles(geminiRoot),
  ];
}

function isGeminiCliRoot(dirPath, { quick = false } = {}) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  if (quick) return hasGeminiSessionsQuick(dirPath);
  return listGeminiDataFiles(dirPath).length > 0;
}

async function extractGeminiDataFile(filePath, attribution, options = {}) {
  if (isGeminiLogsFile(filePath)) return extractGeminiLogsFile(filePath, attribution);
  if (isGeminiShellHistoryFile(filePath)) return extractGeminiShellHistoryFile(filePath, attribution);
  if (path.extname(filePath).toLowerCase() === ".jsonl") {
    return extractGeminiSessionJsonlFile(filePath, attribution, options);
  }
  return extractGeminiSessionFile(filePath, attribution);
}

async function extractGeminiCliDir(geminiRoot, attribution = {}, options = {}) {
  const rows = [];
  const parseStats = { errors: 0 };
  const dataPaths = listGeminiDataFiles(geminiRoot);
  const fileCount = dataPaths.length;
  const { onFileProgress, onExtractedRows, checkAbort } = options;

  for (let i = 0; i < dataPaths.length; i++) {
    const dataPath = dataPaths[i];
    if (typeof checkAbort === "function") checkAbort();
    tickFileProgress(onFileProgress, i + 1, fileCount, dataPath);
    try {
      const fileRows = await extractGeminiDataFile(
        dataPath,
        attribution,
        { ...options, parseStats },
      );
      if (onExtractedRows && fileRows.length) onExtractedRows(fileRows);
      else rows.push(...fileRows);
    } catch (e) {
      dbg("AIHIST", "gemini extract failed", { dataPath, err: e.message });
    }
    if ((i + 1) % 16 === 0) await new Promise((r) => setImmediate(r));
  }
  if (onExtractedRows) {
    const out = [];
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }
  const finalized = finalizeAiHistoryRows(rows, options);
  if (parseStats.errors) finalized._parseErrors = parseStats.errors;
  return finalized;
}

function resolveGeminiCliRoot(target) {
  if (!target) return null;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  for (let i = 0; i < 12; i++) {
    if (path.basename(p) === GEMINI_DIR_NAME && listGeminiDataFiles(p).length > 0) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  if (isGeminiCliRoot(target)) return target;
  return null;
}

async function extractGeminiCliPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (!isGeminiDataFile(target)) {
      throw new Error("Expected a Gemini CLI session JSON/JSONL, logs.json, or shell_history file.");
    }
    return finalizeAiHistoryRows(await extractGeminiDataFile(target, attribution, options), options);
  }

  const root = resolveGeminiCliRoot(target);
  if (!root || !isGeminiCliRoot(root)) {
    throw new Error("Not a Gemini CLI .gemini directory (expected chats/*.jsonl, legacy JSON/logs, or shell_history).");
  }
  return extractGeminiCliDir(root, attribution, options);
}

/** Count parseable data files (for triage manifest sizing). */
function countGeminiSessions(geminiRoot) {
  return listGeminiDataFiles(geminiRoot).length;
}

module.exports = {
  GEMINI_DIR_NAME,
  extractGeminiSessionFile,
  extractGeminiSessionJsonlFile,
  extractGeminiShellHistoryFile,
  extractGeminiLogsFile,
  extractGeminiCliDir,
  extractGeminiCliPath,
  isGeminiCliRoot,
  isGeminiSessionFile,
  isGeminiShellHistoryFile,
  isGeminiLogsFile,
  isGeminiDataFile,
  resolveGeminiCliRoot,
  hasGeminiSessionsQuick,
  listSessionJsonFiles,
  listShellHistoryFiles,
  listLogsJsonFiles,
  listGeminiDataFiles,
  countGeminiSessions,
};
