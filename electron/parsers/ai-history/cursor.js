/**
 * parsers/ai-history/cursor.js — Cursor IDE agent transcript extraction.
 *
 * Artifacts:
 *   ~/.cursor/projects/<project-slug>/agent-transcripts/<session-id>/<session-id>.jsonl
 *   Each line: { role, message: { content: [{ type: "text"|"tool_use", ... }] } }
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");

const { dbg } = require("../../logger");
const { TOOL_CURSOR } = require("./schema");
const { shouldSkipSubagentPath, filterSidechainRows, tickFileProgress } = require("./extract-plan");
const { processFilesConcurrently } = require("./file-batch");
const { extractContentText, extractToolEvidence } = require("./claude-code");
const {
  formatWorkspaceDisplay,
  workspaceFromCursorTranscriptPath,
} = require("./workspace-utils");
const { defaultCursorHome } = require("./artifact-paths");
const {
  formatTimestampUtc,
  parseIsoTimestamp,
  makeRow,
  finalizeAiHistoryRows,
  assignLineNumber,
} = require("./row-utils");
const {
  isCursorUserDataDir,
  listCursorComposerDbs,
} = require("./cursor-composer");

const CURSOR_DIR_NAME = ".cursor";
const AGENT_TRANSCRIPTS = "agent-transcripts";

function cursorRow(fields) {
  return makeRow({ ...fields, tool: fields.tool || TOOL_CURSOR }, TOOL_CURSOR);
}

function resolveCursorHome(target, options = {}) {
  if (options.cursorHome) return options.cursorHome;
  const root = resolveCursorRoot(target);
  return root || defaultCursorHome();
}

function workspaceFromTranscriptPath(filePath, cursorHome) {
  const raw = workspaceFromCursorTranscriptPath(filePath, cursorHome);
  return formatWorkspaceDisplay(raw, raw);
}

function sessionIdFromTranscriptPath(filePath) {
  const base = path.basename(filePath, path.extname(filePath));
  if (/^[0-9a-f-]{36}$/i.test(base)) return base;
  const parent = path.basename(path.dirname(filePath));
  if (/^[0-9a-f-]{36}$/i.test(parent)) return parent;
  return base;
}

function isSidechainPath(filePath) {
  return shouldSkipSubagentPath(filePath, { includeSubagents: false });
}

/** Sub-agent turn: either a subagents/ path or a per-line isSidechain flag in the transcript. */
function isSidechainTranscriptLine(obj, filePath) {
  if (obj && (obj.isSidechain === true || obj.message?.isSidechain === true)) return true;
  return isSidechainPath(filePath);
}

function fileTimestampSpread(filePath, messageCount) {
  let endMs = null;
  let startMs = null;
  try {
    const st = fs.statSync(filePath);
    endMs = st.mtimeMs;
    const birth = st.birthtimeMs;
    if (birth > 0 && birth <= endMs) {
      startMs = birth;
    } else {
      startMs = endMs - Math.min(Math.max(messageCount, 1) * 2000, 3600000);
    }
  } catch { /* ignore */ }
  if (startMs != null && endMs != null && startMs > endMs) {
    const t = startMs;
    startMs = endMs;
    endMs = t;
  }
  return { startMs, endMs };
}

function timestampForMessageIndex(index, total, startMs, endMs) {
  if (endMs == null) return null;
  if (total <= 1 || startMs == null) return endMs;
  const span = Math.max(endMs - startMs, 1000);
  const ratio = (index - 1) / Math.max(total - 1, 1);
  return Math.round(startMs + ratio * span);
}

function transcriptTimestampMs(obj, fallbackMs) {
  const candidates = [
    obj.timestamp,
    obj.createdAt,
    obj.message?.timestamp,
    obj.message?.createdAt,
  ];
  for (const c of candidates) {
    if (c == null) continue;
    if (typeof c === "number" && Number.isFinite(c)) {
      return c > 1e12 ? c : c * 1000;
    }
    const parsed = parseIsoTimestamp(c);
    if (parsed != null) return parsed;
  }
  return fallbackMs;
}

function parseTranscriptLine(obj, filePath, attribution, lineNumber, fallbackTsMs, workspace) {
  const role = obj.role != null ? String(obj.role).toLowerCase() : "";
  if (role !== "user" && role !== "assistant") return null;

  const message = obj.message && typeof obj.message === "object" ? obj.message : {};
  const summary = extractContentText(message.content);
  if (!summary) return null;
  const toolEvidence = extractToolEvidence(message.content);

  const tsMs = transcriptTimestampMs(obj, fallbackTsMs);

  return cursorRow({
    timestamp: formatTimestampUtc(tsMs),
    role,
    recordType: role,
    summary,
    ...toolEvidence,
    sessionId: sessionIdFromTranscriptPath(filePath),
    messageId: obj.id != null ? String(obj.id) : "",
    workspace,
    isSidechain: isSidechainTranscriptLine(obj, filePath),
    sourceFile: filePath,
    lineNumber,
    user: attribution.user || "",
    host: attribution.host || "",
  });
}

async function readTranscriptFile(filePath, attribution = {}, options = {}) {
  const cursorHome = resolveCursorHome(filePath, options);
  const workspace = workspaceFromTranscriptPath(filePath, cursorHome);

  // Single pass over the file (was two: count messages, then build rows). Under concurrent
  // transcript reads that doubled parse work and heap churn in the worker.
  const pending = [];
  const stream = fs.createReadStream(filePath, { encoding: "utf8" });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  let lineNumber = 0;
  for await (const line of rl) {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed) continue;
    let obj;
    try { obj = JSON.parse(trimmed); } catch { if (options.parseStats) options.parseStats.errors += 1; continue; }
    const role = obj.role != null ? String(obj.role).toLowerCase() : "";
    if (role !== "user" && role !== "assistant") continue;
    const message = obj.message && typeof obj.message === "object" ? obj.message : {};
    if (!extractContentText(message.content)) continue;
    pending.push({ obj, lineNumber });
  }

  const messageCount = options._messageCount != null ? options._messageCount : pending.length;
  const { startMs, endMs } = fileTimestampSpread(filePath, messageCount);

  const rows = [];
  let msgIndex = 0;
  let syntheticCount = 0;
  for (const { obj, lineNumber: ln } of pending) {
    msgIndex += 1;
    const spreadMs = timestampForMessageIndex(msgIndex, messageCount, startMs, endMs);
    const before = transcriptTimestampMs(obj, null);
    const row = parseTranscriptLine(obj, filePath, attribution, ln, spreadMs, workspace);
    if (!row) continue;
    if (before == null) syntheticCount += 1;
    rows.push(assignLineNumber(row, ln));
  }

  if (syntheticCount > 0 && syntheticCount < rows.length) {
    rows._cursorPartialSyntheticTimestamps = true;
  } else if (syntheticCount === rows.length && rows.length > 0) {
    rows._cursorSyntheticTimestamps = true;
  }
  return rows;
}

function listTranscriptJsonlFiles(rootDir, options = {}) {
  const out = [];
  if (!rootDir || !fs.existsSync(rootDir)) return out;

  const stack = [rootDir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (shouldSkipSubagentPath(full, options)) continue;
        if (!e.isSymbolicLink()) stack.push(full);
      } else if (e.isFile()) {
        const ext = path.extname(e.name).toLowerCase();
        if ((ext === ".jsonl" || ext === ".txt")
          && full.includes(`${path.sep}${AGENT_TRANSCRIPTS}${path.sep}`)
          && !shouldSkipSubagentPath(full, options)) {
          out.push(full);
        }
      }
    }
  }
  return out;
}

function isCursorTranscriptFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (!filePath || (ext !== ".jsonl" && ext !== ".txt")) return false;
  const norm = filePath.replace(/\\/g, "/");
  return norm.includes(`/${AGENT_TRANSCRIPTS}/`);
}

function isCursorHome(dirPath) {
  if (!dirPath || path.basename(dirPath) !== CURSOR_DIR_NAME) return false;
  try {
    if (!fs.statSync(dirPath).isDirectory()) return false;
  } catch { return false; }
  return fs.existsSync(path.join(dirPath, "projects"));
}

function isCursorDataRoot(dirPath) {
  return isCursorHome(dirPath) || isCursorUserDataDir(dirPath);
}

function resolveCursorRoot(target) {
  if (!target) return null;
  let p = target;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }
  for (let i = 0; i < 16; i++) {
    if (path.basename(p) === CURSOR_DIR_NAME && isCursorHome(p)) return p;
    if (isCursorUserDataDir(p)) return p;
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  if (isCursorDataRoot(target)) return target;
  return null;
}

function countCursorExtractFiles(cursorRoot, options = {}) {
  const projects = path.join(cursorRoot, "projects");
  return listTranscriptJsonlFiles(projects, options).length
    + listCursorComposerDbs(cursorRoot, options.userDataDirs || []).length;
}

async function extractCursorDir(cursorRoot, attribution = {}, options = {}) {
  const parseStats = { errors: 0 };
  const extractOpts = { ...options, cursorHome: cursorRoot, parseStats };
  const projects = path.join(cursorRoot, "projects");
  const files = listTranscriptJsonlFiles(projects, options);
  const rows = [];
  let fileIndex = 0;
  const { onFileProgress, checkAbort, onExtractedRows } = options;
  let streamTimed = 0;
  let streamTotal = 0;
  const flushExtracted = onExtractedRows
    ? (batch) => {
      if (!batch?.length) return;
      for (const r of batch) {
        streamTotal += 1;
        if (String(r.Timestamp || "").trim()) streamTimed += 1;
      }
      onExtractedRows(batch);
    }
    : null;

  // Read transcripts in bounded-concurrency batches (order-independent: streamed rows dedupe at the
  // sink, in-memory rows are finalize-sorted). Per-file error isolation + progress + abort preserved.
  await processFilesConcurrently(files, {
    process: async (filePath) => filterSidechainRows(await readTranscriptFile(filePath, attribution, extractOpts), options),
    onProgress: (filePath) => { fileIndex += 1; tickFileProgress(onFileProgress, fileIndex, files.length, filePath); },
    onRows: (fileRows) => { if (flushExtracted && fileRows.length) flushExtracted(fileRows); else rows.push(...fileRows); },
    onError: (e, filePath) => dbg("AIHIST", "cursor transcript failed", { path: filePath, err: e.message }),
    checkAbort,
  });

  const { extractCursorComposerStores } = require("./cursor-composer");
  const { rows: composerRows, stats: composerStats } = await extractCursorComposerStores(
    cursorRoot,
    attribution,
    { ...options, onExtractedRows: flushExtracted },
  );
  if (!flushExtracted && composerRows.length) {
    rows.push(...composerRows);
  }

  if (onExtractedRows) {
    const out = [];
    if (streamTimed === 0 && streamTotal > 0) out._cursorSyntheticTimestamps = true;
    else if (streamTimed > 0 && streamTimed < streamTotal) out._cursorPartialSyntheticTimestamps = true;
    out._cursorComposerStats = composerStats;
    if (parseStats.errors) out._parseErrors = parseStats.errors;
    return out;
  }

  const sorted = finalizeAiHistoryRows(filterSidechainRows(rows, options), options);
  const timed = sorted.filter((r) => String(r.Timestamp || "").trim()).length;
  if (timed === 0 && sorted.length > 0) {
    sorted._cursorSyntheticTimestamps = true;
  } else if (timed > 0 && timed < sorted.length) {
    sorted._cursorPartialSyntheticTimestamps = true;
  }
  sorted._cursorComposerStats = composerStats;
  if (parseStats.errors) sorted._parseErrors = parseStats.errors;
  return sorted;
}

async function extractCursorPath(target, attribution = {}, options = {}) {
  if (!target || !fs.existsSync(target)) {
    throw new Error(`Path does not exist: ${target}`);
  }

  let stat;
  try { stat = fs.statSync(target); } catch (e) {
    throw new Error(`Cannot read path: ${e.message}`);
  }

  if (stat.isDirectory()) {
    const base = path.basename(target);
    if (isCursorDataRoot(target)) {
      return extractCursorDir(target, attribution, options);
    }
    if (base === AGENT_TRANSCRIPTS || target.includes(`${path.sep}${AGENT_TRANSCRIPTS}${path.sep}`)) {
      const cursorHome = resolveCursorRoot(target) || path.dirname(path.dirname(path.dirname(target)));
      const files = listTranscriptJsonlFiles(target, options);
      const rows = [];
      let fileIndex = 0;
      for (const filePath of files) {
        fileIndex += 1;
        tickFileProgress(options.onFileProgress, fileIndex, files.length, filePath);
        rows.push(...await readTranscriptFile(filePath, attribution, { ...options, cursorHome }));
      }
      const sorted = finalizeAiHistoryRows(filterSidechainRows(rows, options), options);
      sorted._cursorSyntheticTimestamps = true;
      return sorted;
    }
    if (base === "projects") {
      return extractCursorDir(path.dirname(target), attribution, options);
    }
    const root = resolveCursorRoot(target);
    if (root) return extractCursorDir(root, attribution, options);
    throw new Error("Not a Cursor .cursor agent root or Cursor User data directory.");
  }

  if (path.basename(target) === "conversation-search.db") {
    const root = resolveCursorRoot(target);
    if (root) return extractCursorDir(root, attribution, options);
  }
  if (!isCursorTranscriptFile(target)) {
    throw new Error("Expected a Cursor transcript, conversation-search.db, .cursor root, or Cursor User directory.");
  }

  const cursorHome = resolveCursorRoot(target);
  const rows = filterSidechainRows(
    await readTranscriptFile(target, attribution, { ...options, cursorHome }),
    options,
  );
  for (let i = 0; i < rows.length; i++) rows[i].RecordId = String(i + 1);
  return rows;
}

module.exports = {
  CURSOR_DIR_NAME,
  AGENT_TRANSCRIPTS,
  isCursorHome,
  isCursorUserDataDir,
  isCursorDataRoot,
  isCursorTranscriptFile,
  resolveCursorRoot,
  listTranscriptJsonlFiles,
  countCursorExtractFiles,
  extractCursorDir,
  extractCursorPath,
  readTranscriptFile,
  workspaceFromTranscriptPath,
  sessionIdFromTranscriptPath,
  fileTimestampSpread,
  timestampForMessageIndex,
};
