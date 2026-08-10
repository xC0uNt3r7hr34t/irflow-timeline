/**
 * ai-history/row-utils.js — shared timeline row builders for AI history parsers.
 */

const { SUMMARY_MAX_LEN } = require("./schema");

// Bound a single message body held in heap. FullText is the only uncapped field (Summary is
// truncated to 500); without this a single adversarial JSONL line / SQLite value carrying a
// multi-hundred-MB string would be materialized in full per row. 1MB is far above any real
// prompt/response; truncation is marked so it is auditable rather than silent.
const MAX_FULLTEXT_CHARS = 1024 * 1024;
// Tool inputs may contain file bodies or other large arguments. Keep enough source evidence for
// normal invocations while bounding a malicious/pathological single value. The marker makes the
// exceptional truncation visible; ordinary shell commands remain byte-for-byte unchanged.
const MAX_TOOL_EVIDENCE_CHARS = 1024 * 1024;

function capEvidenceText(text, maxChars) {
  const value = String(text ?? "");
  if (value.length <= maxChars) return value;
  const dropped = value.length - maxChars;
  return `${value.slice(0, maxChars)}\n…[truncated ${dropped} chars over ${maxChars}-char cap]`;
}

function capFullText(text) {
  return capEvidenceText(text, MAX_FULLTEXT_CHARS);
}

function formatTimestampUtc(ms) {
  if (ms == null || !Number.isFinite(ms)) return "";
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} `
    + `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function parseIsoTimestamp(s) {
  if (s == null) return null;
  if (typeof s === "number" && Number.isFinite(s)) {
    return s > 1e12 ? s : (s > 1e9 ? s * 1000 : null);
  }
  const raw = String(s).trim();
  if (!raw) return null;
  const iso = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(raw) ? raw : `${raw.replace(" ", "T")}Z`;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

function truncateSummary(text) {
  const s = String(text || "").replace(/\r?\n/g, " ").trim();
  if (s.length <= SUMMARY_MAX_LEN) return s;
  return `${s.slice(0, SUMMARY_MAX_LEN - 1)}…`;
}

function detectActivity(role, content, recordType) {
  const rt = String(recordType || "").toLowerCase();
  if (rt && rt !== "user" && rt !== "assistant" && rt !== "history") {
    return rt.split("-").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
  }
  const lower = String(content || "").toLowerCase();
  if (role === "conversation") return "Conversation";
  if (role === "assistant") return "AI Response";
  if (role !== "user") return "System Message";
  if (/\b(fix|bug|error)\b/.test(lower)) return "Bug Fix Request";
  if (/\b(create|build|implement|add)\b/.test(lower)) return "Feature Request";
  if (/\b(explain|what|how|why)\b/.test(lower)) return "Question";
  if (/\b(refactor|clean|optimize)\b/.test(lower)) return "Refactor Request";
  if (/\btest\b/.test(lower)) return "Test Request";
  return "User Query";
}

function buildDescription(entry) {
  const activity = detectActivity(entry.role, entry.summary, entry.recordType);
  const preview = truncateSummary(entry.summary).slice(0, 150);
  const sessionShort = entry.sessionId && entry.sessionId.length > 8
    ? entry.sessionId.slice(0, 8)
    : (entry.sessionId || "—");
  const tokenInfo = (entry.inputTokens > 0 || entry.outputTokens > 0)
    ? ` | Tokens: ${entry.inputTokens}/${entry.outputTokens}`
    : "";
  const modelInfo = entry.model ? ` | Model: ${entry.model}` : "";
  const workspaceInfo = entry.workspace ? ` | Workspace: ${entry.workspace}` : "";
  const toolInfo = entry.toolName && entry.toolName !== entry.tool ? ` | InvokedTool: ${entry.toolName}` : "";
  const branchInfo = entry.gitBranch ? ` | Branch: ${entry.gitBranch}` : "";
  const typeInfo = entry.recordType && !["user", "assistant", "history"].includes(entry.recordType)
    ? ` | Type: ${entry.recordType}`
    : "";
  return `[${entry.timestamp}] ${activity} in ${entry.tool} - "${preview}" (Session: ${sessionShort})${typeInfo}${modelInfo}${workspaceInfo}${toolInfo}${branchInfo}${tokenInfo}`;
}

function makeRow(fields, defaultTool) {
  const fullText = capFullText(String(fields.fullText ?? fields.summary ?? "")
    .replace(/\r\n/g, "\n")
    .trim());
  // Callers may provide an analyst-friendly event summary plus a much larger evidence body.
  // Preserve that explicit summary; use FullText as the fallback only when no summary exists.
  const summarySource = fields.summary != null && String(fields.summary).trim()
    ? fields.summary
    : fullText;
  const summary = truncateSummary(summarySource);
  const tool = fields.tool || defaultTool || "";
  const row = {
    Timestamp: fields.timestamp || "",
    Role: fields.role || "",
    RecordType: fields.recordType || "",
    Summary: summary,
    FullText: fullText,
    InvokedTool: fields.toolName || "",
    ToolCommand: capEvidenceText(fields.toolCommand, MAX_TOOL_EVIDENCE_CHARS),
    ToolInput: capEvidenceText(fields.toolInput, MAX_TOOL_EVIDENCE_CHARS),
    ToolDescription: capEvidenceText(fields.toolDescription, MAX_TOOL_EVIDENCE_CHARS),
    SessionId: fields.sessionId || "",
    MessageId: fields.messageId || "",
    ParentId: fields.parentId || "",
    Workspace: fields.workspace || "",
    IsSidechain: fields.isSidechain === true ? "true" : (fields.isSidechain === false ? "false" : ""),
    GitBranch: fields.gitBranch || "",
    Tool: tool,
    Model: fields.model || "",
    InputTokens: fields.inputTokens != null ? String(fields.inputTokens) : "",
    OutputTokens: fields.outputTokens != null ? String(fields.outputTokens) : "",
    SourceFile: fields.sourceFile || "",
    LineNumber: fields.lineNumber != null && fields.lineNumber !== "" ? String(fields.lineNumber) : "",
    User: fields.user || "",
    Host: fields.host || "",
    AlsoInTools: fields.alsoInTools || "",
    RecordId: "",
    Description: "",
  };
  row.Description = buildDescription({
    timestamp: row.Timestamp,
    role: row.Role,
    summary: fullText || row.Summary,
    sessionId: row.SessionId,
    tool: row.Tool,
    model: row.Model,
    workspace: row.Workspace,
    recordType: row.RecordType,
    toolName: row.InvokedTool,
    gitBranch: row.GitBranch,
    inputTokens: Number(row.InputTokens) || 0,
    outputTokens: Number(row.OutputTokens) || 0,
  });
  return row;
}

function summaryDedupeSlice(row) {
  return String(row.Summary || "").toLowerCase().replace(/\s+/g, " ").trim().slice(0, 120);
}

function crossToolPromptKey(row) {
  const slice = summaryDedupeSlice(row);
  if (!slice || slice.length < 20) return "";
  const role = String(row.Role || "").toLowerCase();
  if (role !== "user" && role !== "assistant") return "";
  return `${role}\x1f${slice}`;
}

function pickRicherAiHistoryRow(a, b) {
  const lenA = String(a.FullText || a.Summary || "").length;
  const lenB = String(b.FullText || b.Summary || "").length;
  if (a.Timestamp && !b.Timestamp) return a;
  if (b.Timestamp && !a.Timestamp) return b;
  if (lenA !== lenB) return lenA > lenB ? a : b;
  if (a.Tool && b.Tool && a.Tool !== b.Tool) return a;
  return a;
}

/**
 * Collapse the SAME prompt seen across DIFFERENT tools into the richest single row, recording the
 * tools it appeared in via `AlsoInTools`. The key guard (the finding's recommended fix): only merge
 * across DISTINCT Tool values. Two rows from the SAME tool that merely share a 120-char opening
 * (e.g. a repeated "fix the bug in…" template at different times) are DISTINCT prompts — the exact
 * dedupe (aiHistoryDedupeKey, incl. Timestamp+SessionId) already ran, so anything left here is
 * genuinely different and must be kept, not silently dropped. Cross-tool merges remain VISIBLE
 * (AlsoInTools is set), unlike the previous silent same-tool collapse.
 */
function dedupeCrossToolPrompts(rows) {
  const bucketsByKey = new Map(); // key -> [{ idx, tools:Set }]
  const out = [];
  for (const r of rows) {
    const key = crossToolPromptKey(r);
    if (!key) { out.push(r); continue; }
    const tool = String(r.Tool || "").trim();
    const buckets = bucketsByKey.get(key);
    if (buckets && tool) {
      // Merge into an existing occurrence whose tool set does NOT already include this tool.
      const match = buckets.find((b) => !b.tools.has(tool));
      if (match) {
        out[match.idx] = pickRicherAiHistoryRow(out[match.idx], r);
        match.tools.add(tool);
        continue;
      }
    }
    const entry = { idx: out.length, tools: new Set(tool ? [tool] : []) };
    if (buckets) buckets.push(entry);
    else bucketsByKey.set(key, [entry]);
    out.push(r);
  }
  for (const buckets of bucketsByKey.values()) {
    for (const b of buckets) {
      if (b.tools.size > 1) out[b.idx].AlsoInTools = [...b.tools].sort().join(", ");
    }
  }
  return out;
}

function aiHistoryDedupeKey(row) {
  return [
    row.SessionId || "",
    row.Timestamp || "",
    row.Role || "",
    summaryDedupeSlice(row),
  ].join("\x1e");
}

/** Match history.jsonl prompts to session rows when timestamps differ. */
function aiHistoryLooseKey(row) {
  return [
    row.SessionId || "",
    row.Role || "",
    summaryDedupeSlice(row),
  ].join("\x1e");
}

function isHistoryRow(row) {
  const src = row.SourceFile || "";
  return src.endsWith("history.jsonl") || row.RecordType === "history";
}

function isSessionRow(row) {
  if (isHistoryRow(row)) return false;
  const src = row.SourceFile || "";
  return !!(row.MessageId || /\.jsonl$/i.test(src));
}

/**
 * Drop history.jsonl rows when an equivalent session JSONL row exists (same session + summary).
 */
function dedupeAiHistoryRows(rows, options = {}) {
  const sessionLoose = new Set();
  for (const r of rows) {
    if (isSessionRow(r)) sessionLoose.add(aiHistoryLooseKey(r));
  }

  const seen = new Set();
  const out = [];
  for (const r of rows) {
    const key = aiHistoryDedupeKey(r);
    if (isHistoryRow(r) && sessionLoose.has(aiHistoryLooseKey(r))) continue;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  if (options.crossTool) return dedupeCrossToolPrompts(out);
  return out;
}

function assignLineNumber(row, lineNumber) {
  if (row && lineNumber != null && lineNumber !== "") row.LineNumber = String(lineNumber);
  return row;
}

function sortAndNumberRows(rows) {
  rows.sort((a, b) => (a.Timestamp < b.Timestamp ? -1 : a.Timestamp > b.Timestamp ? 1 : 0));
  for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
  return rows;
}

/**
 * Per-tool sort + dedupe. Pass `skipFinalize: true` when rows feed `extractMergedAiHistoryRoots`
 * so merge performs a single dedupe/sort pass (P2).
 */
function finalizeAiHistoryRows(rows, options = {}) {
  if (options.skipFinalize) return rows;
  return sortAndNumberRows(dedupeAiHistoryRows(rows, options));
}

module.exports = {
  formatTimestampUtc,
  parseIsoTimestamp,
  truncateSummary,
  detectActivity,
  buildDescription,
  makeRow,
  aiHistoryDedupeKey,
  aiHistoryLooseKey,
  crossToolPromptKey,
  dedupeCrossToolPrompts,
  dedupeAiHistoryRows,
  assignLineNumber,
  sortAndNumberRows,
  finalizeAiHistoryRows,
};
