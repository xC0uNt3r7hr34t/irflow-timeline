/**
 * vscode-chat-db.js — VS Code / Windsurf / Copilot workspace state.vscdb chat extraction.
 *
 * Reads legacy ItemTable keys (aiService.prompts, aichat.chatdata) and modern VS Code chat keys
 * (agentSessions.model.cache, chat.ChatSessionStore.index) when chatSessions JSON is empty.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { tickFileProgress } = require("./extract-plan");
const {
  openVscdbReadOnly,
  kvTableNames,
  parseKvValue,
  queryKvByKey,
  findVscdbFilesUnder,
  safeCloseDb,
} = require("./vscdb-kv");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, sortAndNumberRows } = require("./row-utils");

function messageTimestampMs(msg) {
  // Return null (-> blank Timestamp) when there is no real timestamp. Fabricating one from
  // Date.now() injected the import-time wall clock into the forensic timeline as if it were the
  // event time, with no synthetic marker — mis-ordering the incident timeline. Blank = unknown,
  // matching the app's naive=UTC / blank=unknown convention.
  const raw = msg?.timestamp ?? msg?.createdAt;
  if (raw == null) return null;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return raw > 1e12 ? raw : raw * 1000;
  }
  return parseIsoTimestamp(raw);
}

const ITEM_CHAT_KEYS = [
  "aiService.prompts",
  "aiService.generations",
  "workbench.panel.aichat.view.aichat.chatdata",
  "workbench.panel.chat.view.chat.response",
  "workbench.panel.chat.view.copilot.chatdata",
];

const AGENT_SESSIONS_KEY = "agentSessions.model.cache";
const CHAT_SESSION_INDEX_KEY = "chat.ChatSessionStore.index";

const COPILOT_PROVIDER_RE = /copilot|github/i;
const CODEX_PROVIDER_RE = /codex|openai-codex/i;

function matchesProviderFilter(entry, filter) {
  if (!filter) return true;
  if (typeof filter === "function") return filter(entry);
  if (filter instanceof RegExp) {
    const hay = `${entry?.providerType || ""} ${entry?.providerLabel || ""}`;
    return filter.test(hay);
  }
  return true;
}

function sessionIdFromAgentResource(resource) {
  if (resource == null || resource === "") return "";
  const s = String(resource);
  const tail = s.match(/([0-9a-f-]{36})$/i);
  return tail ? tail[1] : s;
}

function agentSessionTimestampMs(entry) {
  const raw = entry?.timing?.created
    ?? entry?.timing?.lastRequestStarted
    ?? entry?.timing?.lastRequestEnded;
  if (raw == null) return null;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return raw > 1e12 ? raw : raw * 1000;
  }
  return parseIsoTimestamp(raw);
}

function rowsFromAgentSessionsCache(data, sourceFile, toolLabel, attribution, workspace, options = {}) {
  const rows = [];
  let alternateAgentSessions = 0;
  if (!Array.isArray(data)) return { rows, alternateAgentSessions };

  let idx = 0;
  for (const entry of data) {
    if (!entry || typeof entry !== "object") continue;
    if (!matchesProviderFilter(entry, options.providerFilter)) {
      alternateAgentSessions += 1;
      continue;
    }
    const label = String(entry.label || entry.title || "").trim();
    if (!label) continue;
    idx += 1;
    const sessionId = sessionIdFromAgentResource(entry.resource)
      || String(entry.sessionId || idx);
    rows.push(makeRow({
      timestamp: formatTimestampUtc(agentSessionTimestampMs(entry)),
      role: "user",
      recordType: "agent_session",
      summary: label,
      sessionId,
      messageId: String(idx),
      workspace,
      model: entry.providerLabel || entry.providerType || "",
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
      tool: toolLabel,
      description: "VS Code agent session index (first prompt label; full transcript may not be on disk)",
    }, toolLabel));
  }
  return { rows, alternateAgentSessions };
}

function rowsFromChatSessionStoreIndex(data, sourceFile, toolLabel, attribution, workspace) {
  const rows = [];
  if (!data || typeof data !== "object") return rows;
  const entries = data.entries && typeof data.entries === "object" ? data.entries : data;
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) return rows;

  let idx = 0;
  for (const [key, entry] of Object.entries(entries)) {
    if (!entry || typeof entry !== "object") continue;
    const title = String(entry.title || "").trim();
    if (!title || title === "New Chat") continue;
    if (entry.isEmpty === true && !title) continue;
    idx += 1;
    const sessionId = String(entry.sessionId || key);
    const tsMs = entry.lastMessageDate ?? entry.timing?.created ?? entry.timing?.lastRequestEnded;
    rows.push(makeRow({
      timestamp: formatTimestampUtc(tsMs != null && typeof tsMs === "number"
        ? (tsMs > 1e12 ? tsMs : tsMs * 1000)
        : parseIsoTimestamp(tsMs)),
      role: "system",
      recordType: "session_index",
      summary: title,
      sessionId,
      messageId: String(idx),
      workspace,
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
      tool: toolLabel,
      description: "VS Code chat session index title (chatSessions file may be an empty shell)",
    }, toolLabel));
  }
  return rows;
}

function textFromPromptEntry(entry) {
  if (entry == null) return "";
  if (typeof entry === "string") return entry.trim();
  if (typeof entry === "object") {
    const t = entry.text ?? entry.message ?? entry.content ?? entry.query ?? entry.response;
    if (typeof t === "string") return t.trim();
    if (Array.isArray(t)) return t.map((p) => textFromPromptEntry(p)).filter(Boolean).join(" ");
  }
  return "";
}

function rowsFromPromptArray(data, sessionId, sourceFile, toolLabel, attribution, workspace) {
  const rows = [];
  if (!Array.isArray(data)) return rows;
  let idx = 0;
  for (const entry of data) {
    idx += 1;
    const text = textFromPromptEntry(entry);
    if (!text) continue;
    const role = typeof entry === "object" && entry.role
      ? String(entry.role).toLowerCase()
      : (idx % 2 === 1 ? "user" : "assistant");
    if (role !== "user" && role !== "assistant") continue;
    rows.push(makeRow({
      // Use the entry's own timestamp if present; never fabricate a Date.now()-derived series.
      timestamp: formatTimestampUtc(messageTimestampMs(entry)),
      role,
      recordType: role,
      summary: text,
      sessionId: sessionId || "vscdb-prompts",
      messageId: String(idx),
      workspace,
      sourceFile,
      user: attribution.user || "",
      host: attribution.host || "",
      tool: toolLabel,
    }, toolLabel));
  }
  return rows;
}

function rowsFromChatData(data, sessionId, sourceFile, toolLabel, attribution, workspace) {
  const rows = [];
  if (!data || typeof data !== "object") return rows;

  const tabs = data.tabs || data.sessions || data.chats;
  if (Array.isArray(tabs)) {
    for (const tab of tabs) {
      if (!tab || typeof tab !== "object") continue; // null/primitive tab — skip, don't deref
      const tabId = tab.id || tab.sessionId || tab.chatId || sessionId;
      const messages = tab.messages || tab.bubbles || tab.history;
      if (!Array.isArray(messages)) continue;
      let idx = 0;
      for (const msg of messages) {
        idx += 1;
        if (!msg || typeof msg !== "object") continue; // null/primitive message — skip
        const role = String(msg.role || msg.type || "").toLowerCase();
        const text = textFromPromptEntry(msg.message || msg) || textFromPromptEntry(msg);
        if (!text || (role !== "user" && role !== "assistant" && role !== "1" && role !== "2")) {
          if (text) {
            rows.push(makeRow({
              timestamp: "",
              role: "user",
              recordType: "message",
              summary: text,
              sessionId: String(tabId),
              messageId: String(idx),
              workspace,
              sourceFile,
              user: attribution.user || "",
              host: attribution.host || "",
              tool: toolLabel,
            }, toolLabel));
          }
          continue;
        }
        const normRole = role === "1" || role === "user" ? "user" : "assistant";
        rows.push(makeRow({
          timestamp: formatTimestampUtc(messageTimestampMs(msg)),
          role: normRole,
          recordType: normRole,
          summary: text,
          sessionId: String(tabId),
          messageId: String(idx),
          workspace,
          sourceFile,
          user: attribution.user || "",
          host: attribution.host || "",
          tool: toolLabel,
        }, toolLabel));
      }
    }
  }
  return rows;
}

function extractChatFromVscdb(dbPath, toolLabel, attribution, workspaceLabel, options = {}) {
  const rows = [];
  let alternateAgentSessions = 0;
  let db;
  try {
    db = openVscdbReadOnly(dbPath);
    const tables = kvTableNames(db);
    if (!tables.includes("ItemTable")) return { rows, alternateAgentSessions };

    if (!options.agentSessionsOnly) {
      for (const key of ITEM_CHAT_KEYS) {
        const row = queryKvByKey(db, "ItemTable", key);
        if (!row) continue;
        const data = parseKvValue(row.value);
        const sid = `${path.basename(path.dirname(dbPath))}:${key}`;
        if (key.includes("prompts") || key.includes("generations")) {
          rows.push(...rowsFromPromptArray(data, sid, dbPath, toolLabel, attribution, workspaceLabel));
        } else {
          rows.push(...rowsFromChatData(data, sid, dbPath, toolLabel, attribution, workspaceLabel));
        }
      }
    }

    const agentRow = queryKvByKey(db, "ItemTable", AGENT_SESSIONS_KEY);
    if (agentRow) {
      const agentData = parseKvValue(agentRow.value);
      const { rows: agentRows, alternateAgentSessions: alternates } = rowsFromAgentSessionsCache(
        agentData,
        dbPath,
        toolLabel,
        attribution,
        workspaceLabel,
        options,
      );
      rows.push(...agentRows);
      alternateAgentSessions += alternates;
    }

    if (!options.agentSessionsOnly) {
      const indexRow = queryKvByKey(db, "ItemTable", CHAT_SESSION_INDEX_KEY);
      if (indexRow) {
        const indexData = parseKvValue(indexRow.value);
        rows.push(...rowsFromChatSessionStoreIndex(
          indexData,
          dbPath,
          toolLabel,
          attribution,
          workspaceLabel,
        ));
      }
    }
  } catch (e) {
    dbg("AIHIST", "vscode-chat-db extract failed", { dbPath, err: e.message });
  } finally {
    safeCloseDb(db);
  }
  return { rows, alternateAgentSessions };
}

/**
 * Scan a VS Code–family User directory (workspaceStorage + globalStorage).
 */
async function extractVsCodeUserChatDir(userDir, toolLabel, attribution = {}, options = {}) {
  const rows = [];
  if (!userDir || !fs.existsSync(userDir)) {
    return { rows, stats: { databases: 0, messageRows: 0, alternateAgentSessions: 0 } };
  }

  const dbs = new Set();
  const globalDb = path.join(userDir, "globalStorage", "state.vscdb");
  if (fs.existsSync(globalDb)) dbs.add(globalDb);
  const wsRoot = path.join(userDir, "workspaceStorage");
  if (fs.existsSync(wsRoot)) {
    for (const p of findVscdbFilesUnder(wsRoot, { maxDepth: 3, maxFiles: 24 })) {
      dbs.add(p);
    }
  }

  const dbList = [...dbs];
  let fileIndex = 0;
  let alternateAgentSessions = 0;
  const { onFileProgress, checkAbort } = options;

  for (const dbPath of dbList) {
    if (typeof checkAbort === "function") checkAbort();
    fileIndex += 1;
    tickFileProgress(onFileProgress, fileIndex, dbList.length, dbPath);
    const wsLabel = dbPath.includes("workspaceStorage")
      ? path.basename(path.dirname(dbPath))
      : "global";
    const chunk = extractChatFromVscdb(dbPath, toolLabel, attribution, wsLabel, options);
    rows.push(...chunk.rows);
    alternateAgentSessions += chunk.alternateAgentSessions || 0;
    if (fileIndex % 3 === 0) await new Promise((r) => setImmediate(r));
  }

  return {
    rows,
    stats: {
      databases: dbList.length,
      messageRows: rows.length,
      alternateAgentSessions,
    },
  };
}

function buildVsCodeChatImportNotice(toolLabel, stats) {
  if (!stats?.messageRows) return "";
  let msg = `${toolLabel} workspace DB: ${stats.messageRows} message(s) from ${stats.databases} state.vscdb file(s).`;
  if (stats.agentSessionRows) {
    msg += ` ${stats.agentSessionRows} from VS Code agent session index.`;
  }
  return msg;
}

/**
 * Read VS Code agentSessions.model.cache rows for Codex (embedded in VS Code, not ~/.codex).
 */
async function supplementCodexFromVsCodeAgentSessions(attribution = {}, options = {}) {
  const { dedupeAiHistoryRows } = require("./row-utils");
  const { TOOL_CODEX } = require("./schema");
  const merged = [];
  let databases = 0;
  let agentSessionRows = 0;
  const userDataDirs = Array.isArray(options.userDataDirs)
    ? options.userDataDirs.filter((p) => typeof p === "string" && p.trim())
    : [];

  for (const userDir of userDataDirs) {
    if (!fs.existsSync(userDir)) continue;
    const { rows, stats } = await extractVsCodeUserChatDir(userDir, TOOL_CODEX, attribution, {
      ...options,
      agentSessionsOnly: true,
      providerFilter: (entry) => CODEX_PROVIDER_RE.test(`${entry?.providerType || ""} ${entry?.providerLabel || ""}`),
    });
    if (stats?.databases) databases += stats.databases;
    if (rows.length) {
      merged.push(...rows);
      agentSessionRows += rows.length;
    }
  }

  return {
    rows: dedupeAiHistoryRows(merged),
    stats: {
      databases,
      messageRows: merged.length,
      agentSessionRows,
    },
  };
}

module.exports = {
  extractVsCodeUserChatDir,
  extractChatFromVscdb,
  buildVsCodeChatImportNotice,
  supplementCodexFromVsCodeAgentSessions,
  messageTimestampMs,
  rowsFromAgentSessionsCache,
  rowsFromChatSessionStoreIndex,
  matchesProviderFilter,
  COPILOT_PROVIDER_RE,
  CODEX_PROVIDER_RE,
  AGENT_SESSIONS_KEY,
  CHAT_SESSION_INDEX_KEY,
};
