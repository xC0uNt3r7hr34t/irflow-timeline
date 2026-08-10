/**
 * copilot-cli.js — GitHub Copilot CLI artifact extraction.
 *
 * The CLI store is separate from VS Code Copilot Chat:
 *   $COPILOT_HOME or ~/.copilot/
 *     session-state/<session-id>/{events.jsonl,workspace.yaml,plan.md,checkpoints/,files/}
 *     command-history-state/
 *     session-store.db (+ WAL/SHM)
 *     logs/
 *
 * Authentication/configuration and MCP secret stores are deliberately excluded.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const yaml = require("js-yaml");

const { dbg } = require("../../logger");
const { TOOL_COPILOT } = require("./schema");
const { readJsonlBounded } = require("./jsonl-reader");
const { buildToolEvidence, serializeEvidenceValue } = require("./tool-evidence");
const {
  formatTimestampUtc,
  parseIsoTimestamp,
  makeRow,
  finalizeAiHistoryRows,
  assignLineNumber,
} = require("./row-utils");
const { openVscdbReadOnly, listTables, safeCloseDb } = require("./vscdb-kv");
const { copySqliteFamilyToTemp } = require("./codex-state-sqlite");
const { tickFileProgress } = require("./extract-plan");

const COPILOT_CLI_DIR_NAME = ".copilot";
const SESSION_STATE_DIR = "session-state";
const COMMAND_HISTORY_DIR = "command-history-state";
const SESSION_STORE_DB = "session-store.db";
const MAX_AUX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_AUX_FILES = 4000;
const MAX_COMMAND_ROWS = 5000;
const MAX_SESSION_STORE_TABLE_ROWS = 500;

const SENSITIVE_TOP_LEVEL = new Set([
  "config.json",
  "mcp-config.json",
  "mcp-oauth-config",
  "mcp-secrets",
  "permissions-config",
  "permissions-config.json",
]);

function copilotCliRow(fields) {
  return makeRow({ ...fields, tool: TOOL_COPILOT }, TOOL_COPILOT);
}

function defaultCopilotCliHome() {
  const configured = process.env.COPILOT_HOME;
  return configured ? path.resolve(configured) : path.join(os.homedir(), COPILOT_CLI_DIR_NAME);
}

function isDirectory(dirPath) {
  try { return fs.statSync(dirPath).isDirectory(); } catch { return false; }
}

function isCopilotCliRoot(dirPath, { quick = false } = {}) {
  if (!dirPath || !isDirectory(dirPath)) return false;
  const markers = [
    path.join(dirPath, SESSION_STATE_DIR),
    path.join(dirPath, COMMAND_HISTORY_DIR),
    path.join(dirPath, SESSION_STORE_DB),
  ];
  if (markers.some((p) => fs.existsSync(p))) return true;
  if (quick) return false;
  return path.basename(dirPath) === COPILOT_CLI_DIR_NAME
    && fs.existsSync(path.join(dirPath, "logs"));
}

function resolveCopilotCliRoot(target) {
  if (!target) return null;
  let current = path.resolve(target);
  try {
    if (fs.statSync(current).isFile()) current = path.dirname(current);
  } catch { return null; }

  for (let i = 0; i < 24; i++) {
    if (isCopilotCliRoot(current)) return current;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function isCopilotCliArtifactPath(filePath) {
  const root = resolveCopilotCliRoot(filePath);
  if (!root) return false;
  const relative = path.relative(root, filePath);
  if (!relative || relative === ".") return true;
  const first = relative.split(path.sep)[0];
  if (SENSITIVE_TOP_LEVEL.has(first)) return false;
  return first === SESSION_STATE_DIR
    || first === COMMAND_HISTORY_DIR
    || first === "logs"
    || relative === SESSION_STORE_DB
    || relative.startsWith(`${SESSION_STORE_DB}-`);
}

function listFilesBounded(rootDir, options = {}) {
  const out = [];
  if (!isDirectory(rootDir)) return out;
  const maxDepth = options.maxDepth ?? 12;
  const maxFiles = options.maxFiles ?? MAX_AUX_FILES;
  const stack = [{ dir: rootDir, depth: 0 }];
  while (stack.length && out.length < maxFiles) {
    const { dir, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!entry.isSymbolicLink() && depth < maxDepth) {
          stack.push({ dir: full, depth: depth + 1 });
        }
      } else if (entry.isFile()) {
        out.push(full);
        if (out.length >= maxFiles) break;
      }
    }
  }
  return out.sort();
}

function listCopilotCliSessionDirs(root) {
  const stateDir = path.join(root, SESSION_STATE_DIR);
  if (!isDirectory(stateDir)) return [];
  let entries;
  try { entries = fs.readdirSync(stateDir, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((entry) => entry.isDirectory() && !entry.isSymbolicLink())
    .map((entry) => path.join(stateDir, entry.name))
    .sort();
}

function listCopilotCliArtifactFiles(root) {
  if (!isCopilotCliRoot(root)) return [];
  const files = [];
  for (const sessionDir of listCopilotCliSessionDirs(root)) {
    for (const name of ["workspace.yaml", "workspace.yml", "events.jsonl", "plan.md"]) {
      const candidate = path.join(sessionDir, name);
      if (fs.existsSync(candidate)) files.push(candidate);
    }
    files.push(...listFilesBounded(path.join(sessionDir, "checkpoints")));
    files.push(...listFilesBounded(path.join(sessionDir, "files")));
  }
  files.push(...listFilesBounded(path.join(root, COMMAND_HISTORY_DIR)));
  const sessionStore = path.join(root, SESSION_STORE_DB);
  if (fs.existsSync(sessionStore)) files.push(sessionStore);
  files.push(...listFilesBounded(path.join(root, "logs"), { maxDepth: 8 }));
  return [...new Set(files)];
}

function countCopilotCliExtractFiles(root) {
  const resolved = resolveCopilotCliRoot(root) || root;
  return listCopilotCliArtifactFiles(resolved).length;
}

function readBoundedText(filePath, maxBytes = MAX_AUX_FILE_BYTES) {
  const stat = fs.statSync(filePath);
  if (stat.size > maxBytes) {
    throw new Error(`File exceeds ${maxBytes}-byte safety limit`);
  }
  return fs.readFileSync(filePath, "utf8").replace(/^\uFEFF/, "");
}

function valueAt(obj, paths) {
  for (const keys of paths) {
    let value = obj;
    for (const key of keys) {
      if (!value || typeof value !== "object") { value = undefined; break; }
      value = value[key];
    }
    if (value != null && value !== "") return value;
  }
  return undefined;
}

function firstString(obj, paths) {
  const value = valueAt(obj, paths);
  return value == null ? "" : String(value);
}

function parseFlexibleTimestamp(value) {
  if (value == null || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value > 1e12) return value;
    if (value > 1e9) return value * 1000;
  }
  return parseIsoTimestamp(value);
}

function contentText(value, depth = 0) {
  if (value == null || depth > 6) return "";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    return value.map((item) => contentText(item, depth + 1)).filter(Boolean).join("\n").trim();
  }
  if (typeof value !== "object") return "";

  const chunks = [];
  for (const key of ["text", "content", "message", "summary", "value", "output", "result"]) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    const text = contentText(value[key], depth + 1);
    if (text) chunks.push(text);
  }
  return [...new Set(chunks)].join("\n").trim();
}

function boundedJson(value, maxChars = 1024 * 1024) {
  let text;
  try { text = JSON.stringify(value, null, 2); } catch { text = String(value ?? ""); }
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n…[truncated ${text.length - maxChars} chars]`;
}

function sessionIdFromDir(sessionDir) {
  return path.basename(sessionDir);
}

function loadWorkspaceMetadata(sessionDir) {
  const sourceFile = ["workspace.yaml", "workspace.yml"]
    .map((name) => path.join(sessionDir, name))
    .find((candidate) => fs.existsSync(candidate));
  if (!sourceFile) return { sourceFile: "", data: {} };
  try {
    const data = yaml.load(readBoundedText(sourceFile));
    return { sourceFile, data: data && typeof data === "object" ? data : {} };
  } catch (e) {
    dbg("AIHIST", "copilot cli workspace metadata failed", { sourceFile, err: e.message });
    return { sourceFile, data: {} };
  }
}

function workspaceContext(sessionDir, workspaceData = {}) {
  return {
    sessionId: firstString(workspaceData, [
      ["sessionId"], ["session_id"], ["id"],
    ]) || sessionIdFromDir(sessionDir),
    workspace: firstString(workspaceData, [
      ["cwd"], ["workingDirectory"], ["working_directory"], ["workspace"],
      ["context", "cwd"], ["context", "workingDirectory"],
    ]),
    model: firstString(workspaceData, [["model"], ["modelId"], ["model_id"]]),
    title: firstString(workspaceData, [["name"], ["title"], ["summary"]]),
    toolCalls: new Map(),
  };
}

function eventTimestamp(event, data) {
  return parseFlexibleTimestamp(valueAt(event, [
    ["timestamp"], ["createdAt"], ["created_at"], ["time"],
  ]) ?? valueAt(data, [
    ["timestamp"], ["startTime"], ["start_time"], ["endTime"], ["end_time"],
  ]));
}

function eventRole(type) {
  if (type === "user.message") return "user";
  if (type === "assistant.message" || type === "session.task_complete") return "assistant";
  if (type === "tool.execution_complete") return "tool";
  if (type === "tool.execution_start") return "assistant";
  return "system";
}

function eventToRow(event, sourceFile, lineNumber, attribution, context) {
  if (!event || typeof event !== "object") return null;
  const type = String(event.type || event.event || "event");
  const data = event.data && typeof event.data === "object" ? event.data : {};

  if (type === "session.start") {
    context.sessionId = firstString(data, [["sessionId"], ["session_id"]]) || context.sessionId;
    context.workspace = firstString(data, [
      ["context", "cwd"], ["cwd"], ["workingDirectory"], ["working_directory"],
    ]) || context.workspace;
    context.model = firstString(data, [["model"], ["modelId"], ["model_id"]]) || context.model;
  } else if (type === "session.model_change") {
    context.model = firstString(data, [["model"], ["modelId"], ["model_id"], ["to"]]) || context.model;
  }

  const toolCallId = firstString(data, [["toolCallId"], ["tool_call_id"], ["callId"], ["id"]]);
  const toolName = firstString(data, [["toolName"], ["tool_name"], ["name"]]);
  const args = valueAt(data, [["arguments"], ["args"], ["input"], ["parameters"]]);
  if (type === "tool.execution_start" && toolCallId) {
    context.toolCalls.set(toolCallId, { toolName, args });
  }
  const priorCall = toolCallId ? context.toolCalls.get(toolCallId) : null;

  let summary = "";
  let fullText = "";
  let evidence = { toolName: "", toolCommand: "", toolInput: "", toolDescription: "" };
  if (type === "user.message") {
    summary = contentText(valueAt(data, [["content"], ["message"], ["text"]]));
    fullText = summary;
  } else if (type === "assistant.message") {
    summary = contentText(valueAt(data, [["content"], ["message"], ["text"], ["summary"]]));
    fullText = summary;
  } else if (type === "tool.execution_start") {
    evidence = buildToolEvidence([{ name: toolName || "tool", input: args }]);
    const command = evidence.toolCommand || evidence.toolDescription;
    summary = `${toolName || "Tool"} call${command ? `: ${command}` : ""}`;
    fullText = boundedJson(data);
  } else if (type === "tool.execution_complete") {
    const callName = toolName || priorCall?.toolName || "tool";
    evidence = buildToolEvidence([{ name: callName, input: priorCall?.args ?? args }]);
    fullText = contentText(valueAt(data, [["result"], ["output"], ["content"], ["error"]]))
      || boundedJson(data);
    summary = `${callName} ${data.success === false ? "failed" : "completed"}${fullText ? `: ${fullText}` : ""}`;
  } else if (type === "session.task_complete") {
    summary = contentText(valueAt(data, [["summary"], ["content"], ["message"]]));
    fullText = summary || boundedJson(data);
  } else {
    summary = contentText(valueAt(data, [["summary"], ["message"], ["content"], ["reason"], ["status"]]));
    if (!summary && type === "session.start" && context.workspace) {
      summary = `Session started in ${context.workspace}`;
    }
    fullText = summary || boundedJson(data);
  }

  if (!summary && !fullText && type === "event") return null;
  const usage = data.usage || data.tokenUsage || data.compactionTokensUsed || {};
  const model = firstString(data, [["model"], ["modelId"], ["model_id"]])
    || firstString(usage, [["model"]])
    || context.model;
  const sessionId = firstString(data, [["sessionId"], ["session_id"]]) || context.sessionId;
  const workspace = firstString(data, [
    ["cwd"], ["workingDirectory"], ["working_directory"], ["context", "cwd"],
  ]) || context.workspace;

  return assignLineNumber(copilotCliRow({
    timestamp: formatTimestampUtc(parseFlexibleTimestamp(eventTimestamp(event, data))),
    role: eventRole(type),
    recordType: type === "tool.execution_complete" && data.success === false ? "tool_result_failed" : type,
    summary: summary || type,
    fullText: fullText || summary || type,
    ...evidence,
    sessionId,
    messageId: event.id != null ? String(event.id) : "",
    parentId: event.parentId != null ? String(event.parentId) : "",
    workspace,
    isSidechain: type.startsWith("subagent.")
      || data.isSubagent === true
      || data.isSidechain === true,
    model,
    inputTokens: usage.inputTokens ?? usage.input_tokens ?? data.inputTokens ?? "",
    outputTokens: usage.outputTokens ?? usage.output_tokens ?? data.outputTokens ?? "",
    sourceFile,
    lineNumber,
    user: attribution.user || "",
    host: attribution.host || "",
  }), lineNumber);
}

async function extractEventsFile(filePath, attribution, context, stats) {
  const rows = [];
  await readJsonlBounded(filePath, (event, lineNumber) => {
    const row = eventToRow(event, filePath, lineNumber, attribution, context);
    if (row) rows.push(row);
  }, { parseStats: stats.parseStats });
  stats.eventFiles += 1;
  stats.eventRows += rows.length;
  stats.messageRows += rows.filter((row) => row.Role === "user" || row.Role === "assistant").length;
  if (rows.some((row) => row.Role === "user" || row.Role === "assistant")) {
    stats.sessionsWithMessages += 1;
  }
  return rows;
}

function workspaceMetadataRow(meta, context, attribution) {
  if (!meta.sourceFile || !Object.keys(meta.data).length) return null;
  const ts = parseFlexibleTimestamp(valueAt(meta.data, [
    ["updatedAt"], ["updated_at"], ["createdAt"], ["created_at"], ["startTime"],
  ]));
  return copilotCliRow({
    timestamp: formatTimestampUtc(ts),
    role: "system",
    recordType: "workspace_metadata",
    summary: context.title || `Copilot CLI workspace: ${context.workspace || "(unknown)"}`,
    fullText: boundedJson(meta.data),
    sessionId: context.sessionId,
    workspace: context.workspace,
    model: context.model,
    sourceFile: meta.sourceFile,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function textArtifactRow(filePath, recordType, context, attribution) {
  const text = readBoundedText(filePath).trim();
  if (!text) return null;
  const stat = fs.statSync(filePath);
  return copilotCliRow({
    timestamp: formatTimestampUtc(stat.mtimeMs),
    role: "system",
    recordType,
    summary: `${recordType.replace(/_/g, " ")}: ${text}`,
    fullText: text,
    sessionId: context.sessionId,
    workspace: context.workspace,
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function checkpointRow(filePath, context, attribution) {
  const raw = readBoundedText(filePath).trim();
  if (!raw) return null;
  let fullText = raw;
  try { fullText = boundedJson(JSON.parse(raw)); } catch { /* markdown/yaml/plaintext checkpoint */ }
  const stat = fs.statSync(filePath);
  return copilotCliRow({
    timestamp: formatTimestampUtc(stat.mtimeMs),
    role: "system",
    recordType: "checkpoint",
    summary: `Copilot CLI checkpoint ${path.basename(filePath)}`,
    fullText,
    sessionId: context.sessionId,
    workspace: context.workspace,
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function inventoryRow(filePath, recordType, root, context, attribution) {
  const stat = fs.statSync(filePath);
  const relative = path.relative(root, filePath);
  const detail = {
    relativePath: relative,
    sizeBytes: stat.size,
    modifiedUtc: new Date(stat.mtimeMs).toISOString(),
    contentParsed: false,
  };
  return copilotCliRow({
    timestamp: formatTimestampUtc(stat.mtimeMs),
    role: "system",
    recordType,
    summary: `${recordType.replace(/_/g, " ")}: ${relative} (${stat.size} bytes)`,
    fullText: boundedJson(detail),
    sessionId: context?.sessionId || "",
    workspace: context?.workspace || "",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

function commandEntryRows(value, filePath, attribution, stats, fallbackTimestamp = null) {
  const rows = [];
  const visit = (entry, inheritedTs, depth = 0) => {
    if (rows.length >= MAX_COMMAND_ROWS || entry == null || depth > 6) return;
    if (typeof entry === "string") {
      const command = entry.trim();
      if (!command) return;
      rows.push(copilotCliRow({
        timestamp: formatTimestampUtc(parseFlexibleTimestamp(inheritedTs)),
        role: "user",
        recordType: "command_history",
        summary: command,
        fullText: command,
        toolName: "shell",
        toolCommand: command,
        toolInput: serializeEvidenceValue({ command }),
        workspace: "Copilot CLI command history",
        sourceFile: filePath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
      return;
    }
    if (Array.isArray(entry)) {
      for (const item of entry) visit(item, inheritedTs, depth + 1);
      return;
    }
    if (typeof entry !== "object") return;
    const ts = valueAt(entry, [
      ["timestamp"], ["createdAt"], ["created_at"], ["time"], ["updatedAt"],
    ]) ?? inheritedTs;
    const command = firstString(entry, [
      ["command"], ["cmd"], ["shellCommand"], ["shell_command"], ["text"], ["value"], ["input"],
    ]);
    if (command) {
      visit(command, ts, depth + 1);
      return;
    }
    for (const key of ["commands", "history", "entries", "items", "records"]) {
      if (entry[key] != null) visit(entry[key], ts, depth + 1);
    }
  };
  visit(value, fallbackTimestamp);
  stats.commandHistoryRows += rows.length;
  return rows;
}

async function extractCommandHistoryFile(filePath, attribution, stats) {
  if (path.extname(filePath).toLowerCase() === ".jsonl") {
    const rows = [];
    await readJsonlBounded(filePath, (entry) => {
      if (rows.length >= MAX_COMMAND_ROWS) return;
      rows.push(...commandEntryRows(entry, filePath, attribution, stats));
    }, { parseStats: stats.parseStats });
    return rows.slice(0, MAX_COMMAND_ROWS);
  }

  const raw = readBoundedText(filePath);
  try {
    return commandEntryRows(JSON.parse(raw), filePath, attribution, stats);
  } catch {
    const stat = fs.statSync(filePath);
    return commandEntryRows(
      raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
      filePath,
      attribution,
      stats,
      stat.mtimeMs,
    );
  }
}

function quoteIdentifier(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

function safeStoreColumn(name) {
  const lower = String(name).toLowerCase();
  if (/token|secret|auth|credential|cookie|password|api.?key/.test(lower)) return false;
  return /(id|session|title|summary|content|text|message|cwd|workspace|path|model|created|updated|timestamp|time|role|status|type|name)/.test(lower);
}

function rowValue(record, names) {
  const map = new Map(Object.keys(record).map((key) => [key.toLowerCase(), record[key]]));
  for (const name of names) {
    if (map.has(name)) return map.get(name);
  }
  return undefined;
}

function extractSessionStoreRows(dbPath, attribution, stats) {
  const rows = [];
  let snapshot;
  let db;
  try {
    snapshot = copySqliteFamilyToTemp(dbPath);
    db = openVscdbReadOnly(snapshot.dbPath);
    const tables = listTables(db)
      .filter((name) => !/^conversation_fts_(data|idx|content|docsize|config)$/i.test(name));
    stats.sessionStoreTables = tables.length;

    for (const table of tables) {
      const quotedTable = quoteIdentifier(table);
      let count = 0;
      try { count = Number(db.prepare(`SELECT COUNT(*) AS n FROM ${quotedTable}`).get()?.n || 0); } catch { /* ignore */ }
      rows.push(copilotCliRow({
        timestamp: formatTimestampUtc(fs.statSync(dbPath).mtimeMs),
        role: "system",
        recordType: "session_store_table",
        summary: `Copilot CLI session store table ${table}: ${count} row(s)`,
        fullText: boundedJson({ table, rowCount: count, contentParsed: false }),
        workspace: "Copilot CLI session store",
        sourceFile: dbPath,
        user: attribution.user || "",
        host: attribution.host || "",
      }));

      if (!/(session|turn|checkpoint|conversation|message)/i.test(table) || count === 0) continue;
      let columns;
      try { columns = db.prepare(`PRAGMA table_info(${quotedTable})`).all(); } catch { continue; }
      const selected = columns.map((column) => String(column.name)).filter(safeStoreColumn).slice(0, 16);
      if (!selected.length) continue;
      const selectSql = selected.map((name, index) => (
        `CASE WHEN typeof(${quoteIdentifier(name)}) IN ('text','integer','real') `
        + `THEN ${quoteIdentifier(name)} ELSE NULL END AS ${quoteIdentifier(`c${index}`)}`
      )).join(", ");
      let records;
      try {
        records = db.prepare(
          `SELECT ${selectSql} FROM ${quotedTable} LIMIT ${MAX_SESSION_STORE_TABLE_ROWS}`,
        ).all();
      } catch { continue; }

      for (const rawRecord of records) {
        const record = {};
        for (let i = 0; i < selected.length; i++) record[selected[i]] = rawRecord[`c${i}`];
        const fullText = contentText(rowValue(record, [
          "content", "text", "message", "summary", "title", "name",
        ]));
        const sessionId = rowValue(record, ["session_id", "sessionid", "session", "id"]);
        const timestamp = rowValue(record, [
          "updated_at", "updatedat", "created_at", "createdat", "timestamp", "time",
        ]);
        if (!fullText && !sessionId) continue;
        rows.push(copilotCliRow({
          timestamp: formatTimestampUtc(parseFlexibleTimestamp(timestamp)),
          role: String(rowValue(record, ["role"]) || "system"),
          recordType: `session_store_${table}`,
          summary: fullText || `Session-store record ${sessionId}`,
          fullText: fullText || boundedJson(record),
          sessionId: sessionId != null ? String(sessionId) : "",
          workspace: String(rowValue(record, ["cwd", "workspace", "path"]) || "Copilot CLI session store"),
          model: String(rowValue(record, ["model", "model_id", "modelid"]) || ""),
          sourceFile: dbPath,
          user: attribution.user || "",
          host: attribution.host || "",
        }));
      }
    }
    stats.sessionStoreRows += rows.length;
  } catch (e) {
    stats.failed += 1;
    dbg("AIHIST", "copilot cli session-store failed", { dbPath, err: e.message });
  } finally {
    safeCloseDb(db);
    if (snapshot) snapshot.cleanup();
  }
  return rows;
}

async function extractCopilotCliPath(target, attribution = {}, options = {}) {
  const root = resolveCopilotCliRoot(target);
  if (!root) throw new Error("Not a GitHub Copilot CLI data root (expected session-state, command-history-state, or session-store.db).");

  const rows = [];
  const stats = {
    cli: true,
    sessionsScanned: 0,
    sessionsWithMessages: 0,
    eventFiles: 0,
    eventRows: 0,
    messageRows: 0,
    planRows: 0,
    checkpointRows: 0,
    trackedFileRows: 0,
    commandHistoryRows: 0,
    sessionStoreTables: 0,
    sessionStoreRows: 0,
    logInventoryRows: 0,
    failed: 0,
    parseStats: { errors: 0 },
    excludedSensitiveStores: [...SENSITIVE_TOP_LEVEL],
  };
  const files = listCopilotCliArtifactFiles(root);
  const { onExtractedRows, onFileProgress, checkAbort } = options;
  let fileIndex = 0;
  const emit = (chunk) => {
    if (!chunk?.length) return;
    if (onExtractedRows) onExtractedRows(chunk);
    else rows.push(...chunk);
  };
  const progress = (filePath) => {
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, Math.max(files.length, 1), filePath);
  };

  for (const sessionDir of listCopilotCliSessionDirs(root)) {
    if (typeof checkAbort === "function") checkAbort();
    stats.sessionsScanned += 1;
    const metadata = loadWorkspaceMetadata(sessionDir);
    const context = workspaceContext(sessionDir, metadata.data);
    if (metadata.sourceFile) {
      progress(metadata.sourceFile);
      const row = workspaceMetadataRow(metadata, context, attribution);
      if (row) emit([row]);
    }

    const eventsFile = path.join(sessionDir, "events.jsonl");
    if (fs.existsSync(eventsFile)) {
      progress(eventsFile);
      try { emit(await extractEventsFile(eventsFile, attribution, context, stats)); } catch (e) {
        stats.failed += 1;
        dbg("AIHIST", "copilot cli events failed", { eventsFile, err: e.message });
      }
    }

    const planFile = path.join(sessionDir, "plan.md");
    if (fs.existsSync(planFile)) {
      progress(planFile);
      try {
        const row = textArtifactRow(planFile, "plan", context, attribution);
        if (row) { stats.planRows += 1; emit([row]); }
      } catch (e) {
        stats.failed += 1;
        dbg("AIHIST", "copilot cli plan failed", { planFile, err: e.message });
      }
    }

    for (const checkpointFile of listFilesBounded(path.join(sessionDir, "checkpoints"))) {
      progress(checkpointFile);
      try {
        const row = checkpointRow(checkpointFile, context, attribution);
        if (row) { stats.checkpointRows += 1; emit([row]); }
      } catch (e) {
        stats.failed += 1;
        dbg("AIHIST", "copilot cli checkpoint failed", { checkpointFile, err: e.message });
      }
    }

    for (const trackedFile of listFilesBounded(path.join(sessionDir, "files"))) {
      progress(trackedFile);
      try {
        stats.trackedFileRows += 1;
        emit([inventoryRow(trackedFile, "tracked_file_inventory", root, context, attribution)]);
      } catch { stats.failed += 1; }
    }
  }

  for (const historyFile of listFilesBounded(path.join(root, COMMAND_HISTORY_DIR))) {
    progress(historyFile);
    try { emit(await extractCommandHistoryFile(historyFile, attribution, stats)); } catch (e) {
      stats.failed += 1;
      dbg("AIHIST", "copilot cli command history failed", { historyFile, err: e.message });
    }
  }

  const sessionStore = path.join(root, SESSION_STORE_DB);
  if (fs.existsSync(sessionStore)) {
    progress(sessionStore);
    emit(extractSessionStoreRows(sessionStore, attribution, stats));
  }

  for (const logFile of listFilesBounded(path.join(root, "logs"), { maxDepth: 8 })) {
    progress(logFile);
    try {
      stats.logInventoryRows += 1;
      emit([inventoryRow(logFile, "log_inventory", root, null, attribution)]);
    } catch { stats.failed += 1; }
  }

  stats.parseErrors = stats.parseStats.errors;
  delete stats.parseStats;
  if (onExtractedRows) {
    const out = [];
    out._copilotStats = stats;
    if (stats.parseErrors) out._parseErrors = stats.parseErrors;
    return out;
  }

  const sorted = finalizeAiHistoryRows(rows, options);
  sorted._copilotStats = stats;
  if (stats.parseErrors) sorted._parseErrors = stats.parseErrors;
  return sorted;
}

module.exports = {
  COPILOT_CLI_DIR_NAME,
  SESSION_STATE_DIR,
  COMMAND_HISTORY_DIR,
  SESSION_STORE_DB,
  SENSITIVE_TOP_LEVEL,
  defaultCopilotCliHome,
  isCopilotCliRoot,
  resolveCopilotCliRoot,
  isCopilotCliArtifactPath,
  listCopilotCliSessionDirs,
  listCopilotCliArtifactFiles,
  countCopilotCliExtractFiles,
  eventToRow,
  extractEventsFile,
  extractCommandHistoryFile,
  extractSessionStoreRows,
  extractCopilotCliPath,
};
