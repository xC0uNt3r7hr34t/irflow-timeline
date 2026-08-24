/**
 * parser.js — Streaming file parser for IRFlow Timeline
 *
 * Handles:
 *   - CSV (comma, tab, pipe delimited) via raw chunk processing
 *   - XLSX via ExcelJS streaming reader
 *   - Plaso (.plaso) SQLite databases via native reading
 *   - Generic SQLite (.sqlite, .db) databases with table selection
 *   - Progress callbacks for UI feedback
 *   - Batch insertion into SQLite (array-based, zero object allocation)
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const unzipper = require("unzipper");

const BATCH_SIZE_DEFAULT = 100000;
const BATCH_SIZE_MAX_BYTES = 100 * 1024 * 1024; // ~100MB target max per batch
const XLSX_SHARED_STRING_FLUSH_BATCH = 2000;
const XLSX_SHARED_STRING_CACHE_LIMIT = 16384;

// ── Cached EVTX message provider (created once, reused across all EVTX imports) ──
let _cachedMsgProvider = null;
let _msgProviderPromise = null;

async function getEvtxMessageProvider() {
  if (_cachedMsgProvider) return _cachedMsgProvider;
  if (_msgProviderPromise) return _msgProviderPromise;
  _msgProviderPromise = (async () => {
    try {
      const { SmartManagedMessageProvider } = await import("@ts-evtx/messages");
      const managed = new SmartManagedMessageProvider({ preload: true });
      await managed.ensure();
      _cachedMsgProvider = managed.provider; // SqliteMessageProvider with sync lookup
      dbg("EVTX", "Message provider cached globally");
      return _cachedMsgProvider;
    } catch {
      dbg("EVTX", "Message provider not available, skipping");
      return null;
    }
  })();
  return _msgProviderPromise;
}

// ── Debug trace logger (shared singleton — see logger.js) ─────────
const { dbg } = require("./logger");

// ── CSV line parser (RFC 4180 compliant) ───────────────────────────
function parseCSVLine(line, delimiter = ",") {
  const fields = [];
  let inQuotes = false;
  let fieldStart = 0;
  // Fast path: accumulate character ranges instead of per-char string concat
  const parts = []; // array of substrings for the current field (used in quoted fields)
  let useParts = false; // only use parts array when we encounter quotes
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          // Escaped quote — flush range up to here (including first quote), skip second
          parts.push(line.substring(fieldStart, i + 1));
          i++;
          fieldStart = i + 1;
        } else {
          // End of quoted section — flush range before closing quote
          parts.push(line.substring(fieldStart, i));
          fieldStart = i + 1;
          inQuotes = false;
        }
      }
    } else {
      if (ch === '"') {
        // Start quoted section — flush any unquoted prefix
        if (i > fieldStart) parts.push(line.substring(fieldStart, i));
        useParts = true;
        inQuotes = true;
        fieldStart = i + 1;
      } else if (ch === delimiter) {
        if (useParts) {
          if (i > fieldStart) parts.push(line.substring(fieldStart, i));
          fields.push(parts.join(""));
          parts.length = 0;
          useParts = false;
        } else {
          fields.push(line.substring(fieldStart, i));
        }
        fieldStart = i + 1;
      }
    }
  }
  // Final field
  if (useParts) {
    if (line.length > fieldStart) parts.push(line.substring(fieldStart));
    fields.push(parts.join(""));
  } else {
    fields.push(line.substring(fieldStart));
  }
  return fields;
}

// ── Fast CSV field parser (returns array, no allocations beyond the fields array)
// For comma-delimited files that may use quoting.
function parseCSVLineToArray(line, delimiter, colCount) {
  const fields = new Array(colCount);
  let fi = 0;
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === delimiter) {
        fields[fi++] = current;
        current = "";
        if (fi >= colCount) return fields;
      } else {
        current += ch;
      }
    }
  }
  if (fi < colCount) fields[fi++] = current;
  // Fill remaining with empty strings
  while (fi < colCount) fields[fi++] = "";
  return fields;
}

function detectDelimiter(firstLine) {
  const tabCount = (firstLine.match(/\t/g) || []).length;
  const commaCount = (firstLine.match(/,/g) || []).length;
  const pipeCount = (firstLine.match(/\|/g) || []).length;
  if (tabCount > commaCount && tabCount > pipeCount) return "\t";
  if (pipeCount > commaCount) return "|";
  return ",";
}

/**
 * Fast split to pre-sized array (avoids String.split() allocating unknown-length array)
 */
function splitToArray(line, delimiter, colCount) {
  const result = new Array(colCount);
  let fi = 0;
  let start = 0;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === delimiter) {
      result[fi++] = line.substring(start, i);
      start = i + 1;
      if (fi >= colCount - 1) break;
    }
  }
  result[fi++] = line.substring(start);
  while (fi < colCount) result[fi++] = "";
  return result;
}

function stripTrailingCR(line) {
  return line.length > 0 && line.charCodeAt(line.length - 1) === 13
    ? line.substring(0, line.length - 1)
    : line;
}

function getWrappedFieldMode(headerName) {
  const h = String(headerName || "").trim().toLowerCase();
  if (!h) return "text";
  if (/^(?:detection_rules|ruletitle|rule_title|description|message)$/i.test(h)) return "text";
  if (/^(?:computer_name|workstation_name|source_ip|target_username|process_name|image|target_object|targetfilename|target_filename|hostname|computer|keypath|hivepath|relativetargetname|event\.eventdata\.(?:image|targetobject|targetfilename))$/i.test(h)) {
    return "join";
  }
  if (/^(?:command_line|commandline|processcommandline|executableinfo|event\.eventdata\.commandline)$/i.test(h)) {
    return "smart";
  }
  return "text";
}

function shouldJoinWrappedField(prevChar, nextChar) {
  if (!prevChar || !nextChar) return true;
  if (/\s/.test(prevChar) || /\s/.test(nextChar)) return false;
  if (/[\\/:._-]/.test(prevChar) || /[\\/:._-]/.test(nextChar)) return true;
  return /[A-Za-z0-9]/.test(prevChar) && /[A-Za-z0-9]/.test(nextChar);
}

function normalizeWrappedFieldValue(value, headerName) {
  const raw = String(value || "");
  if (!/[\r\n]/.test(raw)) return raw;

  const mode = getWrappedFieldMode(headerName);
  if (mode === "text") return raw.replace(/[\r\n]+/g, " ");

  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch !== "\r" && ch !== "\n") {
      out += ch;
      continue;
    }

    let j = i;
    while (j < raw.length && (raw[j] === "\r" || raw[j] === "\n")) j++;
    const prevChar = out.length > 0 ? out[out.length - 1] : "";
    const nextChar = j < raw.length ? raw[j] : "";
    const shouldJoin = mode === "join" || shouldJoinWrappedField(prevChar, nextChar);
    if (!shouldJoin && out.length > 0 && out[out.length - 1] !== " ") out += " ";
    i = j - 1;
  }

  return out;
}

/**
 * Quote-aware CSV record scanner (RFC 4180 compliant).
 * Processes complete records immediately instead of building a giant `records[]`
 * array for the whole chunk, which keeps heap usage bounded on 10GB+ CSV imports.
 */
function scanCSVRecords(str, onRecord) {
  let start = 0;
  let inQuotes = false;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    if (inQuotes) {
      if (ch === 34) { // '"'
        if (i + 1 < str.length && str.charCodeAt(i + 1) === 34) {
          i++; // Skip escaped quote ""
        } else {
          inQuotes = false;
        }
      }
    } else if (ch === 34) {
      inQuotes = true;
    } else if (ch === 10) { // '\n'
      const record = stripTrailingCR(str.substring(start, i));
      if (record.length > 0) onRecord(record);
      start = i + 1;
    }
  }
  return start < str.length ? str.substring(start) : "";
}

/**
 * Stream-parse a CSV/TSV file and insert into TimelineDB
 * Uses raw chunk processing instead of readline for maximum throughput.
 *
 * @param {string} filePath - Path to the file
 * @param {string} tabId - Tab identifier
 * @param {TimelineDB} db - Database instance
 * @param {Function} onProgress - Progress callback(rowsImported, fileBytes, totalBytes)
 * @returns {Promise<{headers, rowCount, tsColumns}>}
 */
async function parseCSVStream(filePath, tabId, db, onProgress) {
  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    try { totalBytes = fs.statSync(filePath).size; } catch { /* proceed with 0 */ }
    let bytesRead = 0;
    let lineCount = 0;
    let headers = null;
    // Guard against double resolve/reject — stream end can fire after destroy
    let settled = false;
    const safeReject = (err) => { if (!settled) { settled = true; reject(err); } };
    const safeResolve = (val) => { if (!settled) { settled = true; resolve(val); } };
    let colCount = 0;
    let delimiter = null;
    let batch = new Array(BATCH_SIZE_DEFAULT);
    let batchLen = 0;
    let batchSize = BATCH_SIZE_DEFAULT;
    let lastProgressTime = Date.now();

    // Buffer-level leftover — avoids string concatenation between chunks
    let leftoverBuf = null;

    // Fast-path flag for tab/pipe delimiters (no quoting needed)
    let fastSplit = false;

    // Quote-aware partial record buffer (string) — for comma-delimited RFC 4180 multiline fields
    let partialRecord = "";

    // Helper: process a single parsed record (shared by both paths)
    const processRecord = (line) => {
      // Preserve wrapped structured values (paths, hosts, command lines) while still
      // flattening narrative text fields for display.
      const values = parseCSVLineToArray(line, delimiter, colCount);
      for (let vi = 0; vi < colCount; vi++) {
        const v = values[vi];
        if (v && (v.indexOf("\n") !== -1 || v.indexOf("\r") !== -1)) {
          values[vi] = normalizeWrappedFieldValue(v, headers?.[vi]);
        }
      }
      batch[batchLen++] = values;
      lineCount++;

      if (batchLen >= batchSize) {
        db.insertBatchArrays(tabId, batchLen === batch.length ? batch : batch.slice(0, batchLen));
        batchLen = 0;
        const now = Date.now();
        if (now - lastProgressTime >= 200) {
          lastProgressTime = now;
          if (onProgress) onProgress(lineCount, bytesRead, totalBytes);
        }
      }
    };

    const ensurePartialRecordSafe = () => {
      // Large carry-over records are almost always malformed CSV or binary input.
      if (partialRecord.length > 128 * 1024 * 1024) {
        stream.destroy();
        safeReject(new Error("Quoted field exceeds 128MB — file may be corrupted or contain binary data"));
        return false;
      }
      return true;
    };

    // Early binary detection flag — checked on first chunk only
    let firstChunk = true;

    // Adaptive buffer: 128MB for large files (fewer syscalls), 4MB for small files (less memory)
    const hwm = totalBytes > 500 * 1024 * 1024 ? 128 * 1024 * 1024 : 4 * 1024 * 1024;
    const stream = fs.createReadStream(filePath, { highWaterMark: hwm });

    stream.on("data", (chunk) => {
      bytesRead += chunk.length;

      // Binary detection: check first 8KB of first chunk for null bytes
      if (firstChunk) {
        firstChunk = false;
        const checkLen = Math.min(chunk.length, 8192);
        for (let i = 0; i < checkLen; i++) {
          if (chunk[i] === 0) {
            stream.destroy();
            safeReject(new Error("File appears to be binary (null bytes in first 8KB) — not a valid CSV/TSV"));
            return;
          }
        }
      }

      // ── Path A: Quote-aware streaming for comma-delimited (RFC 4180 multiline) ──
      // Used after headers are parsed and delimiter is comma (not tab/pipe).
      // Cannot use binary lastNL optimization here because \n may be inside quoted fields.
      if (headers && !fastSplit) {
        const decoded = chunk.toString("utf-8");
        const fullStr = partialRecord ? partialRecord + decoded : decoded;
        partialRecord = scanCSVRecords(fullStr, processRecord);
        if (!ensurePartialRecordSafe()) return;
        return;
      }

      // ── Path B: Binary approach for header detection or fastSplit mode ──
      // Safe for tab/pipe (no RFC 4180 quoting) and for the header line (never multiline).
      const buf = leftoverBuf ? Buffer.concat([leftoverBuf, chunk]) : chunk;
      leftoverBuf = null;

      // Find last newline in buffer — only decode complete lines
      const lastNL = buf.lastIndexOf(10); // 10 = '\n'
      if (lastNL === -1) {
        // No complete line yet — save entire buffer
        leftoverBuf = buf;
        // Safety cap: if no newline found in 256MB, likely binary — abort
        if (leftoverBuf.length > 256 * 1024 * 1024) {
          stream.destroy();
          safeReject(new Error("No line breaks found in 256MB of data — file may be binary or corrupted"));
          return;
        }
        return;
      }

      // Save bytes after last newline as leftover (Buffer view, no copy)
      if (lastNL < buf.length - 1) {
        leftoverBuf = buf.subarray(lastNL + 1);
      }

      // Decode only the complete-lines portion
      const str = buf.toString("utf-8", 0, lastNL);
      let lineStart = 0;

      for (let i = 0; i <= str.length; i++) {
        if (i < str.length && str.charCodeAt(i) !== 10) continue;
        let line = stripTrailingCR(str.substring(lineStart, i));
        const nextStart = i + 1;
        lineStart = nextStart;
        if (line.length === 0) continue;

        if (!headers) {
          // First line = headers — strip UTF-8 BOM if present
          if (line.charCodeAt(0) === 0xFEFF) line = line.slice(1);
          delimiter = detectDelimiter(line);
          fastSplit = delimiter === "\t" || delimiter === "|";
          const rawFields = fastSplit ? line.split(delimiter) : parseCSVLine(line, delimiter);
          headers = rawFields.map((h) => h.trim());

          // Deduplicate headers
          const seen = new Map();
          headers = headers.map((h) => {
            if (!h) h = "Column";
            if (seen.has(h)) {
              const count = seen.get(h) + 1;
              seen.set(h, count);
              return `${h}_${count}`;
            }
            seen.set(h, 0);
            return h;
          });

          colCount = headers.length;
          // Adaptive batch size: ~100MB target / estimated row size, clamped to [5k, 100k]
          batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
          batch = new Array(batchSize); // re-allocate to actual batch size
          db.createTab(tabId, headers);

          // For comma-delimited: transition remaining data to quote-aware mode
          if (!fastSplit) {
            // Remaining text after the header line is complete, but it may contain
            // quoted multiline records, so switch to the quote-aware scanner now.
            let remainingStr = nextStart < str.length ? str.substring(nextStart) : "";
            if (leftoverBuf) {
              const leftoverStr = leftoverBuf.toString("utf-8");
              remainingStr = remainingStr ? `${remainingStr}\n${leftoverStr}` : leftoverStr;
              leftoverBuf = null;
            }
            if (remainingStr.length > 0) {
              partialRecord = scanCSVRecords(remainingStr, processRecord);
              if (!ensurePartialRecordSafe()) return;
            }
            return;
          }
          continue;
        }

        // fastSplit data row processing (tab/pipe — no quoting)
        const values = splitToArray(line, delimiter, colCount);
        batch[batchLen++] = values;
        lineCount++;

        if (batchLen >= batchSize) {
          db.insertBatchArrays(tabId, batchLen === batch.length ? batch : batch.slice(0, batchLen));
          batchLen = 0;
          const now = Date.now();
          if (now - lastProgressTime >= 200) {
            lastProgressTime = now;
            if (onProgress) onProgress(lineCount, bytesRead, totalBytes);
          }
        }
      }
    });

    stream.on("end", () => {
      // Process remaining partial record (comma-delimited quote-aware mode)
      if (partialRecord.length > 0 && headers) {
        let line = stripTrailingCR(partialRecord);
        if (line.length > 0) {
          if (fastSplit) {
            const values = splitToArray(line, delimiter, colCount);
            batch[batchLen++] = values;
            lineCount++;
          } else {
            processRecord(line);
          }
        }
        partialRecord = "";
      }

      // Process any leftover partial line (fastSplit mode — last line without trailing newline)
      if (leftoverBuf && leftoverBuf.length > 0 && headers) {
        let line = stripTrailingCR(leftoverBuf.toString("utf-8"));
        if (line.length > 0) {
          const values = fastSplit
            ? splitToArray(line, delimiter, colCount)
            : parseCSVLineToArray(line, delimiter, colCount);
          batch[batchLen++] = values;
          lineCount++;
        }
      }

      // Empty file or no parseable headers — reject cleanly
      if (!headers) {
        safeReject(new Error("No data found — file is empty or contains no parseable headers"));
        return;
      }

      // Insert remaining batch
      if (batchLen > 0) {
        db.insertBatchArrays(tabId, batch.slice(0, batchLen));
      }

      // Finalize
      if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
      const result = db.finalizeImport(tabId);

      safeResolve({
        headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns,
      });
    });

    stream.on("error", safeReject);
  });
}

function decodeXmlAttribute(value) {
  return String(value || "")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function flattenRichText(richText) {
  if (!Array.isArray(richText) || richText.length === 0) return "";
  let out = "";
  for (const part of richText) {
    if (!part) continue;
    out += String(part.text || "");
  }
  return out;
}

function normalizeXlsxTextValue(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "object") {
    if (Array.isArray(value.richText)) return flattenRichText(value.richText);
    if (value.text != null) return String(value.text);
  }
  return String(value);
}

function normalizeXlsxCellValue(value, resolveSharedString) {
  if (value == null) return "";
  if (value instanceof Date) {
    return value.toISOString().replace("T", " ").replace("Z", "");
  }
  if (typeof value === "object") {
    if (value.sharedString != null && resolveSharedString) {
      return resolveSharedString(value.sharedString);
    }
    if (Array.isArray(value.richText)) {
      return flattenRichText(value.richText);
    }
    if (value.text != null) {
      return String(value.text);
    }
    if (value.result !== undefined) {
      return String(value.result);
    }
  }
  return String(value);
}

async function readZipEntryText(filePath, entryPath) {
  const directory = await unzipper.Open.file(filePath);
  const entry = directory.files.find((file) => file.path === entryPath);
  if (!entry) return null;
  const content = await entry.buffer();
  return content.toString("utf-8");
}

function createXlsxSharedStringStore() {
  const Database = require("better-sqlite3");
  const dbPath = path.join(
    os.tmpdir(),
    `tle_xlsx_shared_${crypto.randomBytes(4).toString("hex")}.db`
  );
  const db = new Database(dbPath);
  db.pragma("journal_mode = MEMORY");
  db.pragma("synchronous = OFF");
  db.pragma("temp_store = MEMORY");
  db.pragma("cache_size = -32768"); // 32MB
  db.exec("CREATE TABLE shared_strings (idx INTEGER PRIMARY KEY, value TEXT NOT NULL)");

  const insertStmt = db.prepare("INSERT INTO shared_strings (idx, value) VALUES (?, ?)");
  const lookupStmt = db.prepare("SELECT value FROM shared_strings WHERE idx = ?");
  const insertBatchTx = db.transaction((rows) => {
    for (const [idx, value] of rows) insertStmt.run(idx, value);
  });

  let pending = [];
  let count = 0;
  const cache = new Map();

  const remember = (idx, value) => {
    if (cache.has(idx)) cache.delete(idx);
    cache.set(idx, value);
    if (cache.size > XLSX_SHARED_STRING_CACHE_LIMIT) {
      cache.delete(cache.keys().next().value);
    }
  };

  const flush = () => {
    if (pending.length === 0) return;
    insertBatchTx(pending);
    pending = [];
  };

  return {
    add(index, value) {
      const normalized = normalizeXlsxTextValue(value);
      pending.push([index, normalized]);
      remember(index, normalized);
      if (index >= count) count = index + 1;
      if (pending.length >= XLSX_SHARED_STRING_FLUSH_BATCH) flush();
    },
    get(index) {
      const idx = Number(index);
      if (!Number.isInteger(idx) || idx < 0) return "";
      const cached = cache.get(idx);
      if (cached !== undefined) return cached;
      flush();
      const row = lookupStmt.get(idx);
      const value = row ? row.value : "";
      remember(idx, value);
      return value;
    },
    flush,
    size() {
      return count;
    },
    close() {
      try { flush(); } catch {}
      try { db.close(); } catch {}
      try { fs.unlinkSync(dbPath); } catch {}
    },
  };
}

async function populateXlsxSharedStringStore(filePath, sharedStringStore) {
  const directory = await unzipper.Open.file(filePath);
  const entry = directory.files.find((file) => file.path === "xl/sharedStrings.xml");
  if (!entry) return 0;

  const parseSax = require("exceljs/lib/utils/parse-sax");
  const iterateStream = require("exceljs/lib/utils/iterate-stream");

  let currentText = "";
  let inSharedString = false;
  let inTextNode = false;
  let index = 0;

  for await (const events of parseSax(iterateStream(entry.stream()))) {
    for (const { eventType, value } of events) {
      if (eventType === "opentag") {
        if (value.name === "si") {
          inSharedString = true;
          currentText = "";
        } else if (inSharedString && value.name === "t") {
          inTextNode = true;
        }
      } else if (eventType === "text") {
        if (inSharedString && inTextNode) currentText += value;
      } else if (eventType === "closetag") {
        if (value.name === "t") {
          inTextNode = false;
        } else if (value.name === "si") {
          sharedStringStore.add(index++, currentText);
          currentText = "";
          inSharedString = false;
          inTextNode = false;
        }
      }
    }
  }

  sharedStringStore.flush();
  return index;
}

/**
 * Stream-parse an XLSX file and insert into TimelineDB
 *
 * Uses ExcelJS streaming reader to avoid loading entire file into memory.
 *
 * @param {string} filePath - Path to the .xlsx file
 * @param {string} tabId - Tab identifier
 * @param {TimelineDB} db - Database instance
 * @param {Function} onProgress - Progress callback
 * @param {string|number} sheetName - Sheet name or 1-based index (default: 1)
 * @returns {Promise<{headers, rowCount, tsColumns}>}
 */
async function parseXLSXStream(filePath, tabId, db, onProgress, sheetName) {
  const ExcelJS = require("exceljs");
  dbg("XLSX", `parseXLSXStream start`, { filePath, tabId, sheetName });

  const sharedStringStore = createXlsxSharedStringStore();
  try {
    const sharedCount = await populateXlsxSharedStringStore(filePath, sharedStringStore);
    dbg("XLSX", `shared strings indexed`, { sharedCount });
  } catch (err) {
    sharedStringStore.close();
    throw err;
  }

  return new Promise((resolve, reject) => {
    let totalBytes = 0;
    try { totalBytes = fs.statSync(filePath).size; } catch { /* proceed with 0 */ }
    dbg("XLSX", `file size`, { totalBytes });
    let headers = null;
    let colCount = 0;
    let lineCount = 0;
    let batch = [];
    let batchSize = BATCH_SIZE_DEFAULT;
    let lastProgressTime = 0;
    let targetSheet = sheetName || 1;
    let sheetFound = false;
    let cleanedUp = false;
    const cleanup = () => {
      if (cleanedUp) return;
      cleanedUp = true;
      sharedStringStore.close();
    };

    const workbookReader = new ExcelJS.stream.xlsx.WorkbookReader(filePath, {
      sharedStrings: "ignore",
      hyperlinks: "ignore",
      styles: "cache",
      worksheets: "emit",
    });
    workbookReader.model = { sheets: [] };

    workbookReader.on("worksheet", (worksheet) => {
      dbg("XLSX", `worksheet event`, { name: worksheet.name, id: worksheet.id, targetSheet });
      // Match by name or index
      if (typeof targetSheet === "string" && !/^\d+$/.test(targetSheet)) {
        if (worksheet.name !== targetSheet) return;
      } else {
        if (String(worksheet.id) !== String(targetSheet)) return;
      }

      dbg("XLSX", `matched target sheet`, { name: worksheet.name });
      sheetFound = true;

      worksheet.on("error", (err) => {
        dbg("XLSX", `worksheet ERROR`, { sheet: worksheet.name, message: err.message });
        cleanup();
        reject(err);
      });

      worksheet.on("row", (row) => {
        try {
          const values = [];
          row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
            const val = normalizeXlsxCellValue(cell.value, (index) => sharedStringStore.get(index));
            // Ensure array is large enough
            while (values.length < colNumber) values.push("");
            values[colNumber - 1] = val;
          });

          if (!headers) {
            headers = values.map((v, i) => (v.trim() || `Column_${i + 1}`));
            // Deduplicate
            const seen = new Map();
            headers = headers.map((h) => {
              if (seen.has(h)) {
                const c = seen.get(h) + 1;
                seen.set(h, c);
                return `${h}_${c}`;
              }
              seen.set(h, 0);
              return h;
            });
            colCount = headers.length;
            batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
            dbg("XLSX", `headers parsed, calling db.createTab`, { colCount, headers: headers.slice(0, 10) });
            db.createTab(tabId, headers);
            dbg("XLSX", `db.createTab OK`);
            return;
          }

          // Pad or truncate to colCount
          while (values.length < colCount) values.push("");
          if (values.length > colCount) values.length = colCount;
          batch.push(values);
          lineCount++;

          if (batch.length >= batchSize) {
            db.insertBatchArrays(tabId, batch);
            batch = [];
            const now = Date.now();
            if (now - lastProgressTime >= 200) {
              lastProgressTime = now;
              // XLSX streaming doesn't expose byte position — estimate progress
              // using an assumed ~200 bytes/row average for compressed XLSX
              const estimatedBytes = Math.min(lineCount * 200, totalBytes - 1);
              if (onProgress) onProgress(lineCount, estimatedBytes, totalBytes);
            }
          }
        } catch (e) {
          dbg("XLSX", `row processing error`, { row: lineCount, message: e.message });
          cleanup();
          reject(e);
        }
      });
    });

    workbookReader.on("end", () => {
      dbg("XLSX", `workbookReader end event`, { lineCount, batchRemaining: batch.length, hasHeaders: !!headers });
      if (!sheetFound) {
        cleanup();
        reject(new Error(`Sheet "${targetSheet}" not found`));
        return;
      }
      if (batch.length > 0 && headers) {
        db.insertBatchArrays(tabId, batch);
      }
      if (!headers) {
        dbg("XLSX", `no headers found — rejecting`);
        cleanup();
        reject(new Error("No data found in sheet"));
        return;
      }
      if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
      dbg("XLSX", `calling finalizeImport`);
      const result = db.finalizeImport(tabId);
      dbg("XLSX", `finalizeImport OK`, { rowCount: result.rowCount, tsColumns: result.tsColumns?.length });
      cleanup();
      resolve({
        headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns,
      });
    });

    workbookReader.on("error", (err) => {
      dbg("XLSX", `workbookReader ERROR`, { message: err.message, stack: err.stack });
      cleanup();
      reject(err);
    });

    // Start reading
    workbookReader.read();
  });
}

// ── Legacy .xls (OLE2/BIFF) parser using SheetJS ────────────────────
/**
 * Parse a legacy .xls file (binary Excel format).
 * SheetJS reads the entire file into memory — fine for .xls (max ~65k rows).
 */
function parseXLSFile(filePath, tabId, db, onProgress, sheetName) {
  const XLSX = require("xlsx");
  dbg("XLS", `parseXLSFile start`, { filePath, tabId, sheetName });

  const workbook = XLSX.readFile(filePath, { dateNF: "yyyy-mm-dd hh:mm:ss" });
  const targetSheet = sheetName || workbook.SheetNames[0];
  const worksheet = workbook.Sheets[targetSheet];
  if (!worksheet) throw new Error(`Sheet "${targetSheet}" not found`);

  // Convert to array-of-arrays; raw:false converts dates to formatted strings
  const data = XLSX.utils.sheet_to_json(worksheet, { header: 1, raw: false, dateNF: "yyyy-mm-dd hh:mm:ss" });
  dbg("XLS", `sheet_to_json done`, { rows: data.length, sheet: targetSheet });
  if (data.length === 0) throw new Error("No data found in sheet");

  // First row = headers
  let headers = data[0].map((v, i) => (v ? String(v).trim() : `Column_${i + 1}`));
  // Deduplicate
  const seen = new Map();
  headers = headers.map((h) => {
    if (seen.has(h)) {
      const c = seen.get(h) + 1;
      seen.set(h, c);
      return `${h}_${c}`;
    }
    seen.set(h, 0);
    return h;
  });

  const colCount = headers.length;
  const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
  db.createTab(tabId, headers);

  let totalBytes = 0;
  try { totalBytes = fs.statSync(filePath).size; } catch {}

  let batch = [];
  let lineCount = 0;

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    const values = [];
    for (let j = 0; j < colCount; j++) {
      values.push(row[j] != null ? String(row[j]) : "");
    }
    batch.push(values);
    lineCount++;

    if (batch.length >= batchSize) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      if (onProgress) onProgress(lineCount, Math.round((i / data.length) * totalBytes), totalBytes);
    }
  }

  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
  }

  if (onProgress) onProgress(lineCount, totalBytes, totalBytes);
  dbg("XLS", `parsing complete`, { lineCount });
  const result = db.finalizeImport(tabId);

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
  };
}

/**
 * Get list of sheet names from an Excel file (.xlsx or .xls)
 */
async function getXLSXSheets(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  dbg("XLSX", `getXLSXSheets start`, { filePath, ext });

  // Legacy .xls — use SheetJS
  if (ext === ".xls") {
    const XLSX = require("xlsx");
    const workbook = XLSX.readFile(filePath);
    const sheets = workbook.SheetNames.map((name, i) => {
      const sheet = workbook.Sheets[name];
      const range = sheet["!ref"] ? XLSX.utils.decode_range(sheet["!ref"]) : null;
      return { name, id: i + 1, rowCount: range ? range.e.r : 0 };
    });
    dbg("XLSX", `getXLSXSheets done (xls)`, { sheetCount: sheets.length });
    return sheets;
  }

  // .xlsx/.xlsm — read only workbook.xml from the ZIP central directory
  const workbookXml = await readZipEntryText(filePath, "xl/workbook.xml");
  if (!workbookXml) throw new Error("Workbook metadata not found");

  const sheets = [];
  const sheetTagRe = /<sheet\b([^>]*)\/?>/g;
  let match;
  while ((match = sheetTagRe.exec(workbookXml)) !== null) {
    const attrs = Object.create(null);
    const attrText = match[1];
    const attrRe = /\b([A-Za-z:]+)="([^"]*)"/g;
    let attrMatch;
    while ((attrMatch = attrRe.exec(attrText)) !== null) {
      attrs[attrMatch[1]] = decodeXmlAttribute(attrMatch[2]);
    }
    if (!attrs.name) continue;
    const id = Number(attrs.sheetId);
    sheets.push({
      name: attrs.name,
      id: Number.isFinite(id) ? id : sheets.length + 1,
      rowCount: "?",
    });
  }

  if (sheets.length === 0) throw new Error("No sheets found in workbook metadata");
  dbg("XLSX", `getXLSXSheets done`, { sheetCount: sheets.length });
  return sheets;
}

// ── Plaso (.plaso) SQLite parser ─────────────────────────────────────

/**
 * Validate that a file is a genuine Plaso SQLite database.
 * @returns {{ valid: boolean, formatVersion?: string, compressionFormat?: string }}
 */
function validatePlasoFile(filePath) {
  const Database = require("better-sqlite3");
  let plasoDb;
  try {
    plasoDb = new Database(filePath, { readonly: true, fileMustExist: true });
    const hasMeta = plasoDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'"
    ).get();
    if (!hasMeta) return { valid: false };
    const fmtRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'format_version'"
    ).get();
    if (!fmtRow) return { valid: false };
    const compRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'compression_format'"
    ).get();
    return {
      valid: true,
      formatVersion: String(fmtRow.value),
      compressionFormat: compRow ? String(compRow.value) : "none",
    };
  } catch {
    return { valid: false };
  } finally {
    try { plasoDb?.close(); } catch {}
  }
}

/**
 * Decompress and parse a Plaso event_data blob.
 * Handles both zlib-compressed BLOBs and plain-text JSON.
 */
function parsePlasoBlob(data, useZlib) {
  if (data == null) return {};
  try {
    let jsonStr;
    if (useZlib && Buffer.isBuffer(data)) {
      // Guard against decompression bombs — cap at 64MB per blob
      const inflated = zlib.inflateSync(data, { maxOutputLength: 64 * 1024 * 1024 });
      jsonStr = inflated.toString("utf-8");
    } else {
      jsonStr = typeof data === "string" ? data : data.toString("utf-8");
    }
    return JSON.parse(jsonStr);
  } catch {
    return {};
  }
}

/**
 * Parse a Plaso (.plaso) SQLite file and insert events into TimelineDB.
 *
 * Plaso schema:
 *   metadata: key/value pairs (format_version, compression_format)
 *   event: _timestamp (int64 microseconds), _timestamp_desc, _event_data_row_identifier
 *   event_data: _identifier (PK), _data (JSON text or zlib-compressed blob)
 *
 * @param {string} filePath
 * @param {string} tabId
 * @param {TimelineDB} db
 * @param {Function} onProgress
 * @returns {Promise<{headers, rowCount, tsColumns, numericColumns}>}
 */
async function parsePlasoFile(filePath, tabId, db, onProgress) {
  const Database = require("better-sqlite3");
  let plasoDb;
  try {
    plasoDb = new Database(filePath, { readonly: true, fileMustExist: true });
  } catch (e) {
    throw new Error(`Cannot open Plaso file: ${e.message}`);
  }
  plasoDb.pragma("mmap_size = 268435456"); // 256MB mmap for read-only Plaso file
  plasoDb.pragma("cache_size = -65536");  // 64MB cache (read-only, sequential scan)

  try {
    // Read compression setting
    const compRow = plasoDb.prepare(
      "SELECT value FROM metadata WHERE key = 'compression_format'"
    ).get();
    const useZlib = compRow?.value?.toString().toUpperCase() === "ZLIB";

    // Detect schema — check which tables exist
    const tables = plasoDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table'"
    ).all().map((r) => r.name);
    const hasEventData = tables.includes("event_data");
    const hasEvent = tables.includes("event");
    if (!hasEvent) throw new Error("Plaso file missing 'event' table");

    // Detect event table column names (varies between Plaso format versions)
    // Old format: _timestamp, _timestamp_desc, _event_data_row_identifier
    // New format (20230327+): timestamp, timestamp_desc, _event_data_identifier
    const eventCols = plasoDb.pragma("table_info(event)").map((c) => c.name);
    const tsCol = eventCols.includes("_timestamp") ? "_timestamp" : "timestamp";
    const tsDescCol = eventCols.includes("_timestamp_desc") ? "_timestamp_desc" : "timestamp_desc";
    const edRefCol = eventCols.includes("_event_data_row_identifier")
      ? "_event_data_row_identifier"
      : eventCols.includes("_event_data_identifier")
        ? "_event_data_identifier"
        : null;

    // Detect if the reference column uses "event_data.N" format (new) vs plain integer (old)
    let joinIsTextRef = false;
    if (edRefCol && hasEventData) {
      const sample = plasoDb.prepare(`SELECT ${edRefCol} FROM event LIMIT 1`).get();
      if (sample) {
        const val = String(sample[edRefCol]);
        joinIsTextRef = val.startsWith("event_data.");
      }
    }

    // Count events for progress
    const totalEvents = plasoDb.prepare("SELECT COUNT(*) as cnt FROM event").get().cnt;

    // Phase 1: Column discovery — sample event_data entries to find all field keys
    const FIXED_FIELDS = ["datetime", "timestamp_desc", "data_type"];
    const fieldSet = new Set();

    if (hasEventData) {
      // Sample from start + middle + end in a single query to discover all field keys
      const edCount = plasoDb.prepare("SELECT COUNT(*) as cnt FROM event_data").get().cnt;
      const midOffset = Math.max(0, Math.floor(edCount / 2));
      const endOffset = Math.max(0, edCount - 200);
      const sampleSql = `SELECT _data FROM (SELECT _data FROM event_data LIMIT 300) UNION ALL SELECT _data FROM (SELECT _data FROM event_data LIMIT 200 OFFSET ${midOffset}) UNION ALL SELECT _data FROM (SELECT _data FROM event_data LIMIT 200 OFFSET ${endOffset})`;
      for (const row of plasoDb.prepare(sampleSql).iterate()) {
        const obj = parsePlasoBlob(row._data, useZlib);
        for (const key of Object.keys(obj)) {
          if (!key.startsWith("__") && !key.startsWith("_")) fieldSet.add(key);
        }
      }
    }

    // Remove fields handled in fixed positions
    fieldSet.delete("data_type");
    fieldSet.delete("timestamp_desc");
    const discoveredFields = [...fieldSet].sort();
    const headers = [...FIXED_FIELDS, ...discoveredFields];
    const colCount = headers.length;

    // Create the TLE tab with discovered headers
    db.createTab(tabId, headers);

    // Phase 2: Stream events in batches
    // For text-ref format ("event_data.N"), extract the integer and match against PK
    // to enable SEARCH USING INTEGER PRIMARY KEY instead of full table scan.
    // Skip ORDER BY — events are stored in chronological order; app sorts after import.
    let eventStmt;
    if (hasEventData && edRefCol) {
      // Text-ref: "event_data.N" → extract N via SUBSTR(col, 12) and match against integer PK
      const joinCondition = joinIsTextRef
        ? `ed._identifier = CAST(SUBSTR(e.${edRefCol}, 12) AS INTEGER)`
        : `e.${edRefCol} = ed._identifier`;
      eventStmt = plasoDb.prepare(`
        SELECT e.${tsCol} AS ts, e.${tsDescCol} AS ts_desc, ed._data
        FROM event e
        LEFT JOIN event_data ed ON ${joinCondition}
      `);
    } else {
      eventStmt = plasoDb.prepare(`
        SELECT ${tsCol} AS ts, ${tsDescCol} AS ts_desc, _data FROM event
      `);
    }

    let batch = [];
    let rowCount = 0;
    let lastProgress = 0;
    const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));

    for (const row of eventStmt.iterate()) {
      // Convert microseconds → ISO string "YYYY-MM-DD HH:MM:SS.ffffff"
      let datetime = "";
      if (row.ts != null && row.ts !== 0) {
        try {
          const tsNum = Number(row.ts);
          const ms = tsNum / 1000;
          const d = new Date(ms);
          if (!isNaN(d.getTime())) {
            const iso = d.toISOString(); // YYYY-MM-DDTHH:MM:SS.mmmZ
            const micros = String(Math.abs(tsNum % 1000000)).padStart(6, "0");
            datetime = iso.slice(0, 10) + " " + iso.slice(11, 19) + "." + micros;
          }
        } catch { /* leave empty */ }
      }

      // Parse event_data JSON
      const eventObj = parsePlasoBlob(row._data, useZlib);

      // Build row array in header order
      const values = new Array(colCount);
      values[0] = datetime;
      values[1] = row.ts_desc || eventObj.timestamp_desc || "";
      values[2] = eventObj.data_type || "";
      for (let i = 3; i < colCount; i++) {
        const val = eventObj[headers[i]];
        if (val == null) {
          values[i] = "";
        } else if (typeof val === "object") {
          values[i] = JSON.stringify(val);
        } else {
          values[i] = String(val);
        }
      }

      batch.push(values);
      rowCount++;

      if (batch.length >= batchSize) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
        if (rowCount - lastProgress >= 10000) {
          lastProgress = rowCount;
          if (onProgress) onProgress(rowCount, rowCount, totalEvents);
        }
      }
    }

    // Insert remaining batch
    if (batch.length > 0) {
      db.insertBatchArrays(tabId, batch);
    }

    if (onProgress) onProgress(rowCount, totalEvents, totalEvents);
    const result = db.finalizeImport(tabId);

    return {
      headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
    };
  } finally {
    try { plasoDb.close(); } catch {}
  }
}

// ── Generic SQLite database parser ───────────────────────────────────

const SQLITE_MAGIC = Buffer.from("SQLite format 3\0");

/**
 * Check if a file is a SQLite database by magic bytes.
 */
function isSQLiteFile(filePath) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    fs.closeSync(fd);
    return buf.equals(SQLITE_MAGIC);
  } catch {
    return false;
  }
}

/**
 * Open a SQLite file readonly with performance pragmas.
 */
function _openSQLiteReadonly(filePath) {
  const Database = require("better-sqlite3");
  const sqliteDb = new Database(filePath, { readonly: true, fileMustExist: true });
  sqliteDb.pragma("mmap_size = 268435456");
  sqliteDb.pragma("cache_size = -65536");
  return sqliteDb;
}

/**
 * Quote a SQLite identifier (table/column name).
 */
function _quoteSqliteIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

/**
 * Get list of importable tables from a SQLite database.
 * @returns {Promise<Array<{name: string, rowCount: number}>>}
 */
async function getSQLiteTables(filePath) {
  dbg("SQLITE", "getSQLiteTables start", { filePath });
  let sqliteDb;
  try {
    sqliteDb = _openSQLiteReadonly(filePath);
    const rows = sqliteDb.prepare(
      `SELECT name, sql FROM sqlite_master
       WHERE type = 'table'
         AND name NOT LIKE 'sqlite_%'
       ORDER BY name`
    ).all();
    const tables = [];
    for (const row of rows) {
      if (row.sql && /VIRTUAL/i.test(row.sql)) continue;
      const quoted = _quoteSqliteIdent(row.name);
      const countRow = sqliteDb.prepare(`SELECT COUNT(*) AS cnt FROM ${quoted}`).get();
      tables.push({ name: row.name, rowCount: countRow.cnt });
    }
    dbg("SQLITE", "getSQLiteTables done", { tableCount: tables.length });
    return tables;
  } finally {
    try { sqliteDb?.close(); } catch {}
  }
}

/**
 * Coerce a SQLite cell value to a display string.
 */
function _coerceSqliteValue(val) {
  if (val == null) return "";
  if (Buffer.isBuffer(val)) return "0x" + val.toString("hex");
  if (typeof val === "object") return JSON.stringify(val);
  return String(val);
}

/**
 * Parse a single table from a generic SQLite database into TimelineDB.
 */
async function parseSQLiteTable(filePath, tabId, db, onProgress, tableName) {
  dbg("SQLITE", "parseSQLiteTable start", { filePath, tabId, tableName });
  const tables = await getSQLiteTables(filePath);
  const tableInfo = tables.find((t) => t.name === tableName);
  if (!tableInfo) throw new Error(`Table not found: ${tableName}`);

  let sqliteDb;
  try {
    sqliteDb = _openSQLiteReadonly(filePath);
    const quoted = _quoteSqliteIdent(tableName);
    const colInfo = sqliteDb.pragma(`table_info(${quoted})`);
    if (colInfo.length === 0) throw new Error(`Table has no columns: ${tableName}`);

    const headers = colInfo.map((c) => c.name);
    const colCount = headers.length;
    const totalRows = tableInfo.rowCount;

    db.createTab(tabId, headers);

    const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
    let batch = [];
    let rowCount = 0;
    let lastProgress = 0;

    const stmt = sqliteDb.prepare(`SELECT * FROM ${quoted}`);
    for (const row of stmt.iterate()) {
      const values = new Array(colCount);
      for (let i = 0; i < colCount; i++) {
        values[i] = _coerceSqliteValue(row[headers[i]]);
      }
      batch.push(values);
      rowCount++;

      if (batch.length >= batchSize) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
        if (rowCount - lastProgress >= 10000) {
          lastProgress = rowCount;
          if (onProgress) onProgress(rowCount, rowCount, totalRows);
        }
      }
    }

    if (batch.length > 0) {
      db.insertBatchArrays(tabId, batch);
    }

    if (onProgress) onProgress(rowCount, totalRows, totalRows);
    const result = db.finalizeImport(tabId);

    dbg("SQLITE", "parseSQLiteTable done", { tableName, rowCount: result.rowCount });
    return {
      headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
    };
  } finally {
    try { sqliteDb?.close(); } catch {}
  }
}

// ── EVTX (.evtx) parser ─────────────────────────────────────────

const EVTX_FIXED_FIELDS = ["datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message"];
const EVTX_FIXED_COUNT = EVTX_FIXED_FIELDS.length;
const EVTX_LEVEL_MAP = { "0": "LogAlways", "1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose" };
const XML_ENTITIES = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" };
const decodeXmlEntities = (s) => s.replace(/&(?:amp|lt|gt|quot|apos|#(\d+)|#x([0-9a-fA-F]+));/g, (m, dec, hex) => {
  if (dec) return String.fromCharCode(parseInt(dec, 10));
  if (hex) return String.fromCharCode(parseInt(hex, 16));
  return XML_ENTITIES[m] || m;
});

// Module-level regex constants for EVTX XML parsing — avoids recompilation per record
const EVTX_NAMED_DATA_RE = /<Data\s+Name="([^"]*)"[^>]*?>([^<]*)<\/Data>/gi;
const EVTX_UNNAMED_DATA_RE = /<Data>([^<]+)<\/Data>/g;
const EVTX_USERDATA_LEAF_RE = /<(\w+)>([^<]+)<\/\1>/g;

/**
 * Format a Windows event message template by substituting %1, %2, ... with data values.
 * Also replaces %n (newline) and %t (tab) with spaces for compact display.
 */
const EVTX_MSG_PARAM_RE = /%(\d+)(?:![^!]*!)?|%n|%t|%%/gi;
const EVTX_MULTI_SPACE_RE = /\s{2,}/g;

function formatEvtxMessage(template, dataValues) {
  if (!template) return "";
  // Single-pass: replace all %N params, %n, %t, %% in one regex callback
  const result = template.replace(EVTX_MSG_PARAM_RE, (match, num) => {
    if (num) {
      const idx = parseInt(num) - 1;
      return idx < dataValues.length ? dataValues[idx] : "";
    }
    const lower = match.toLowerCase();
    if (lower === "%n" || lower === "%t") return " ";
    if (match === "%%") return "%";
    return "";
  });
  return result.replace(EVTX_MULTI_SPACE_RE, " ").trim();
}

/**
 * Parse a Windows EVTX file using @ts-evtx/core.
 * ESM-only library loaded via dynamic import() since app is CJS.
 *
 * Uses EvtxFile.open() + records() + renderXml() to extract system fields
 * and EventData from rendered XML. This bypasses the library's template
 * resolution which currently fails to extract EventID, Channel, Computer,
 * and Level from the structured API (returns 0/undefined for all files).
 *
 * Single-pass approach: buffer first 500 events for schema discovery,
 * finalize schema, flush buffer, then continue streaming.
 *
 * @param {string} filePath
 * @param {string} tabId
 * @param {TimelineDB} db
 * @param {Function} onProgress
 * @returns {Promise<{headers, rowCount, tsColumns, numericColumns}>}
 */
async function parseEvtxFile(filePath, tabId, db, onProgress) {
  const { EvtxFile } = await import("@ts-evtx/core");
  let totalBytes = 0;
  try { totalBytes = fs.statSync(filePath).size; } catch { /* proceed with 0 */ }
  const SAMPLE_LIMIT = 500;

  // Use cached global message provider (created once, reused across all EVTX imports)
  const msgProvider = await getEvtxMessageProvider();

  const parseXmlRecord = (xml, record) => {
    // Timestamp from the Record object (always reliable)
    let datetime = "";
    try {
      const d = record.timestampAsDate();
      if (!isNaN(d.getTime())) {
        datetime = d.toISOString().replace("T", " ").replace("Z", "");
      }
    } catch { /* leave empty */ }

    const recordId = String(record.recordNum());

    // System fields from XML
    const eventIdMatch = xml.match(/<EventID[^>]*>(\d+)<\/EventID>/i);
    const eventId = eventIdMatch ? eventIdMatch[1] : "";

    const providerMatch = xml.match(/<Provider\s[^>]*Name="([^"]*)"/i);
    const provider = providerMatch ? providerMatch[1] : "";

    const levelMatch = xml.match(/<Level>(\d+)<\/Level>/i);
    const levelNum = levelMatch ? levelMatch[1] : "";
    const level = EVTX_LEVEL_MAP[levelNum] || levelNum;

    const channelMatch = xml.match(/<Channel>([^<]*)<\/Channel>/i);
    const channel = channelMatch ? channelMatch[1] : "";

    const computerMatch = xml.match(/<Computer>([^<]*)<\/Computer>/i);
    const computer = computerMatch ? computerMatch[1] : "";

    // EventData fields — collect both map (for columns) and ordered values (for message substitution)
    const dataMap = {};
    const dataValues = [];
    let paramIdx = 0;

    // Named: <Data Name="key">value</Data>
    EVTX_NAMED_DATA_RE.lastIndex = 0;
    let m;
    while ((m = EVTX_NAMED_DATA_RE.exec(xml)) !== null) {
      const val = decodeXmlEntities(m[2]);
      dataMap[m[1]] = val;
      dataValues.push(val);
      paramIdx++;
    }

    // Unnamed: <Data>value</Data> (no Name attribute)
    EVTX_UNNAMED_DATA_RE.lastIndex = 0;
    while ((m = EVTX_UNNAMED_DATA_RE.exec(xml)) !== null) {
      const val = decodeXmlEntities(m[1]);
      dataMap[`param${paramIdx}`] = val;
      dataValues.push(val);
      paramIdx++;
    }

    // UserData: extract leaf elements (some EVTX files use UserData instead of EventData)
    const userDataMatch = xml.match(/<UserData>([\s\S]*?)<\/UserData>/i);
    if (userDataMatch && paramIdx === 0) {
      const udContent = userDataMatch[1];
      EVTX_USERDATA_LEAF_RE.lastIndex = 0;
      while ((m = EVTX_USERDATA_LEAF_RE.exec(udContent)) !== null) {
        if (!dataMap[m[1]]) {
          const val = decodeXmlEntities(m[2]);
          dataMap[m[1]] = val;
          dataValues.push(val);
        }
      }
    }

    // Look up and format message from catalog
    let message = "";
    if (msgProvider && eventId && provider) {
      const template = msgProvider.getMessageSync(provider, parseInt(eventId));
      if (template) message = formatEvtxMessage(template, dataValues);
    }

    return {
      fixed: [datetime, recordId, eventId, provider, level, channel, computer, message],
      dataMap,
    };
  };

  const fieldSet = new Set();
  let earlyBuffer = [];
  let schemaFinalized = false;
  let headers = null;
  let colCount = 0;
  let batch = [];
  let batchSize = BATCH_SIZE_DEFAULT;
  let rowCount = 0;
  let lastProgress = 0;

  const buildRow = (parsed) => {
    const values = new Array(colCount);
    for (let f = 0; f < EVTX_FIXED_COUNT; f++) values[f] = parsed.fixed[f];
    for (let i = EVTX_FIXED_COUNT; i < colCount; i++) {
      const val = parsed.dataMap[headers[i]];
      values[i] = val != null ? val : "";
    }
    return values;
  };

  const evtxFile = await EvtxFile.open(filePath);
  // Yield to event loop before starting to allow pending IPC to process
  await new Promise((r) => setImmediate(r));

  try {
    for (const record of evtxFile.records()) {
      let xml;
      try { xml = record.renderXml(); } catch { continue; }

      rowCount++;
      const parsed = parseXmlRecord(xml, record);

      if (!schemaFinalized) {
        for (const key of Object.keys(parsed.dataMap)) fieldSet.add(key);
        earlyBuffer.push(parsed);

        if (rowCount >= SAMPLE_LIMIT) {
          const discoveredFields = [...fieldSet].sort();
          headers = [...EVTX_FIXED_FIELDS, ...discoveredFields];
          colCount = headers.length;
          db.createTab(tabId, headers);
          batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
          schemaFinalized = true;

          for (const buf of earlyBuffer) batch.push(buildRow(buf));
          earlyBuffer = null;

          if (batch.length >= batchSize) {
            db.insertBatchArrays(tabId, batch);
            batch = [];
          }
          if (onProgress) { let eo = 0; try { eo = record.offset ? Number(record.offset) : 0; } catch {} onProgress(rowCount, eo, totalBytes); }
        }
        continue;
      }

      batch.push(buildRow(parsed));
      if (batch.length >= batchSize) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
        if (rowCount - lastProgress >= 10000) {
          lastProgress = rowCount;
          // Estimate bytes read from record offset when available
          let estBytes = 0;
          try { estBytes = record.offset ? Number(record.offset) : 0; } catch {}
          if (onProgress) onProgress(rowCount, estBytes, totalBytes);
          // Yield to event loop periodically so IPC remains responsive
          await new Promise((r) => setImmediate(r));
        }
      }
    }

    // Handle files with fewer than SAMPLE_LIMIT events
    if (!schemaFinalized) {
      if (rowCount === 0) {
        // No events at all
        headers = [...EVTX_FIXED_FIELDS];
        colCount = headers.length;
        db.createTab(tabId, headers);
      } else {
        const discoveredFields = [...fieldSet].sort();
        headers = [...EVTX_FIXED_FIELDS, ...discoveredFields];
        colCount = headers.length;
        db.createTab(tabId, headers);
        for (const buf of earlyBuffer) batch.push(buildRow(buf));
        earlyBuffer = null;
      }
    }

    if (batch.length > 0) {
      db.insertBatchArrays(tabId, batch);
    }
  } finally {
    // Always close the EVTX file handle to release memory
    try { if (evtxFile?.close) evtxFile.close(); } catch {}
  }
  // Null out large arrays to help GC before next import
  batch = null;
  earlyBuffer = null;

  if (onProgress) onProgress(rowCount, totalBytes, totalBytes);
  const result = db.finalizeImport(tabId);

  // Log memory usage after parsing
  const mem = process.memoryUsage();
  dbg("EVTX", `parseEvtxFile done`, { rowCount, heapUsedMB: Math.round(mem.heapUsed / 1048576), rssMB: Math.round(mem.rss / 1048576) });

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
  };
}

// ═══════════════════════════════════════════════════════════════════
// ── Raw $MFT (NTFS Master File Table) binary parser ─────────────
// ═══════════════════════════════════════════════════════════════════

const MFT_COLUMNS = [
  "EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber", "ParentSequenceNumber",
  "ParentPath", "FileName", "Extension", "FileSize", "ReferenceCount", "ReparseTarget",
  "IsDirectory", "HasAds", "IsAds", "SI<FN", "uSecZeros", "Copied", "SiFlags", "NameType",
  "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30",
  "LastRecordChange0x10", "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30",
  "UpdateSequenceNumber", "LogfileSequenceNumber", "SecurityId", "ObjectIdFileDroid",
  "LoggedUtilStream", "ZoneIdContents",
];

// FILETIME epoch: 100ns intervals between 1601-01-01 and 1970-01-01
const FT_EPOCH_DIFF = 116444736000000000n;

const SI_FLAG_NAMES = [
  [0x0001, "ReadOnly"], [0x0002, "Hidden"], [0x0004, "System"],
  [0x0010, "Directory"], [0x0020, "Archive"], [0x0040, "Device"], [0x0080, "Normal"],
  [0x0100, "Temporary"], [0x0200, "SparseFile"], [0x0400, "ReparsePoint"],
  [0x0800, "Compressed"], [0x1000, "Offline"], [0x2000, "NotContentIndexed"],
  [0x4000, "Encrypted"], [0x8000, "IntegrityStream"],
  [0x10000, "Virtual"], [0x20000, "NoScrubData"],
  [0x40000, "RecallOnOpen"], [0x400000, "RecallOnDataAccess"],
  [0x10000000, "IsIndexView"],
];

const FN_NAMESPACE_NAMES = ["Posix", "Windows", "Dos", "DosWindows"];

/**
 * Check if a file is a raw $MFT binary by reading the first 4 bytes
 */
function isMftFile(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(4);
    const bytesRead = fs.readSync(fd, buf, 0, 4, 0);
    if (bytesRead < 4) return false;
    // "FILE" = 0x46 0x49 0x4C 0x45
    return buf[0] === 0x46 && buf[1] === 0x49 && buf[2] === 0x4C && buf[3] === 0x45;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
}

/**
 * Convert Windows FILETIME (BigInt, 100ns since 1601) to ISO-like string
 * Output format: "2024-07-03 10:05:28.2583360" (matches MFTECmd)
 */
function filetimeToIso(ft) {
  if (ft === 0n || ft < FT_EPOCH_DIFF) return "";
  const ticks = ft - FT_EPOCH_DIFF;
  const ms = Number(ticks / 10000n);
  const d = new Date(ms);
  if (isNaN(d.getTime())) return "";
  // Build 7-digit fractional seconds (100ns precision)
  // Use slice instead of padStart to avoid per-call string allocations
  const frac = ("0000000" + Number(ticks % 10000000n)).slice(-7);
  const yyyy = d.getUTCFullYear();
  const mo = ("0" + (d.getUTCMonth() + 1)).slice(-2);
  const dd = ("0" + d.getUTCDate()).slice(-2);
  const hh = ("0" + d.getUTCHours()).slice(-2);
  const mi = ("0" + d.getUTCMinutes()).slice(-2);
  const ss = ("0" + d.getUTCSeconds()).slice(-2);
  return yyyy + "-" + mo + "-" + dd + " " + hh + ":" + mi + ":" + ss + "." + frac;
}

/** Check if FILETIME sub-second portion is exactly zero (timestomping indicator) */
function ftHasZeroUsec(ft) {
  return ft !== 0n && (ft % 10000000n === 0n);
}

/** Decode SiFlags bitmask to pipe-separated string */
function flagsToString(flags) {
  if (!flags) return "None";
  const parts = [];
  for (const [mask, name] of SI_FLAG_NAMES) {
    if (flags & mask) parts.push(name);
  }
  return parts.length > 0 ? parts.join("|") : "None";
}

/** Extract file extension from filename */
function mftGetExtension(filename) {
  if (!filename) return "";
  const dot = filename.lastIndexOf(".");
  if (dot <= 0 || dot === filename.length - 1) return "";
  return filename.substring(dot);
}

/**
 * Apply fixup array — restore last 2 bytes of each 512-byte sector
 * Critical for MFT record integrity
 */
function applyFixup(buf, fixupOffset, fixupCount) {
  if (fixupCount <= 1 || fixupOffset < 4 || fixupOffset + fixupCount * 2 > buf.length) return;
  for (let i = 1; i < fixupCount; i++) {
    const sectorEnd = i * 512 - 2;
    const srcOff = fixupOffset + i * 2;
    if (sectorEnd + 2 > buf.length || srcOff + 2 > buf.length) break;
    const replacement = buf.readUInt16LE(srcOff);
    buf.writeUInt16LE(replacement, sectorEnd);
  }
}

/**
 * Parse $STANDARD_INFORMATION attribute (type 0x10) — always resident
 */
function parseSI(buf, attrPos) {
  const contentSize = buf.readUInt32LE(attrPos + 16);
  const contentOffset = buf.readUInt16LE(attrPos + 20);
  const s = attrPos + contentOffset;
  if (contentSize < 48 || s + 48 > buf.length) return null;
  return {
    created:     buf.readBigUInt64LE(s),
    modified:    buf.readBigUInt64LE(s + 8),
    mftModified: buf.readBigUInt64LE(s + 16),
    accessed:    buf.readBigUInt64LE(s + 24),
    fileFlags:   buf.readUInt32LE(s + 32),
    securityId:  contentSize >= 56 && s + 56 <= buf.length ? buf.readUInt32LE(s + 52) : 0,
    usn:         contentSize >= 72 && s + 72 <= buf.length ? buf.readBigUInt64LE(s + 64) : 0n,
  };
}

/**
 * Parse $FILE_NAME attribute (type 0x30) — always resident
 */
function parseFN(buf, attrPos) {
  const contentSize = buf.readUInt32LE(attrPos + 16);
  const contentOffset = buf.readUInt16LE(attrPos + 20);
  const s = attrPos + contentOffset;
  if (contentSize < 66 || s + 66 > buf.length) return null;

  const parentRefLow = buf.readUInt32LE(s);
  const parentRefHigh = buf.readUInt16LE(s + 4);
  const parentEntry = parentRefLow + parentRefHigh * 0x100000000;
  const parentSeqNum = buf.readUInt16LE(s + 6);

  const nameLen = buf[s + 64];
  const namespace = buf[s + 65];
  const fnEnd = s + 66 + nameLen * 2;
  if (fnEnd > buf.length) return null;
  const filename = buf.toString("utf16le", s + 66, fnEnd);

  return {
    parentEntry,
    parentSeqNum,
    created:     buf.readBigUInt64LE(s + 8),
    modified:    buf.readBigUInt64LE(s + 16),
    mftModified: buf.readBigUInt64LE(s + 24),
    accessed:    buf.readBigUInt64LE(s + 32),
    realSize:    buf.readBigUInt64LE(s + 48),
    namespace,
    filename,
  };
}

/**
 * Parse $OBJECT_ID attribute (type 0x40) — extract file GUID
 */
function parseObjectId(buf, attrPos) {
  const contentSize = buf.readUInt32LE(attrPos + 16);
  const contentOffset = buf.readUInt16LE(attrPos + 20);
  const s = attrPos + contentOffset;
  if (contentSize < 16 || s + 16 > buf.length) return "";
  // Format as GUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
  const hex = buf.toString("hex", s, s + 16);
  return `${hex.slice(6,8)}${hex.slice(4,6)}${hex.slice(2,4)}${hex.slice(0,2)}-${hex.slice(10,12)}${hex.slice(8,10)}-${hex.slice(14,16)}${hex.slice(12,14)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
}

/**
 * Walk all attributes in an MFT record
 */
function parseAttributes(buf, offset, header) {
  const rec = {
    ...header,
    si: null,
    fn: null,
    hasAds: false,
    isAds: false,
    zoneId: "",
    objectId: "",
    loggedUtilStream: "",
    reparseTarget: "",
    refCount: 0,
    dataSize: -1n, // Real file size from $DATA attribute (-1 = not found)
  };

  let pos = offset;
  let dataAttrCount = 0;
  let fnBest = null;
  let fnDos = null;
  let fnLinkCount = 0; // Count distinct non-DOS names (hard links)

  while (pos + 8 <= buf.length) {
    const attrType = buf.readUInt32LE(pos);
    if (attrType === 0xFFFFFFFF || attrType === 0) break;
    const attrLen = buf.readUInt32LE(pos + 4);
    if (attrLen < 16 || pos + attrLen > buf.length) break;

    const nonResident = buf[pos + 8];
    const nameLen = buf[pos + 9];
    const nameOffset = buf.readUInt16LE(pos + 10);

    try {
      if (attrType === 0x10 && !nonResident) {
        rec.si = parseSI(buf, pos);
      } else if (attrType === 0x30 && !nonResident) {
        const fn = parseFN(buf, pos);
        if (fn) {
          // Count non-DOS names as hard link references (DOS is companion, not separate link)
          if (fn.namespace !== 2) fnLinkCount++;
          if (fn.namespace === 2) {
            // DOS (8.3 short name) — lowest priority
            fnDos = fn;
          } else if (fn.namespace === 3) {
            // DosWindows (combined) — highest priority
            fnBest = fn;
          } else if (fn.namespace === 1) {
            // Win32 (long name) — high priority, don't override DosWindows
            if (!fnBest || fnBest.namespace !== 3) fnBest = fn;
          } else {
            // POSIX (0) — fallback only
            if (!fnBest) fnBest = fn;
          }
        }
      } else if (attrType === 0x40 && !nonResident) {
        rec.objectId = parseObjectId(buf, pos);
      } else if (attrType === 0x80) {
        dataAttrCount++;
        if (nameLen === 0) {
          // Primary (unnamed) $DATA — extract real file size
          if (nonResident) {
            // Non-resident: real size at offset 48 from attribute start
            if (pos + 56 <= buf.length) rec.dataSize = buf.readBigUInt64LE(pos + 48);
          } else {
            // Resident: content size at offset 16 from attribute start
            rec.dataSize = BigInt(buf.readUInt32LE(pos + 16));
          }
        } else {
          rec.hasAds = true;
          if (!nonResident && pos + nameOffset + nameLen * 2 <= buf.length) {
            const attrName = buf.toString("utf16le", pos + nameOffset, pos + nameOffset + nameLen * 2);
            if (attrName === "Zone.Identifier") {
              const cSize = buf.readUInt32LE(pos + 16);
              const cOff = buf.readUInt16LE(pos + 20);
              if (cSize > 0 && cSize < 2048 && pos + cOff + cSize <= buf.length) {
                rec.zoneId = buf.toString("utf8", pos + cOff, pos + cOff + cSize).trim();
              }
            }
          }
        }
        if (dataAttrCount > 1) rec.hasAds = true;
      } else if (attrType === 0xC0 && !nonResident && nameLen > 0 && pos + nameOffset + nameLen * 2 <= buf.length) {
        // $LOGGED_UTILITY_STREAM
        rec.loggedUtilStream = buf.toString("utf16le", pos + nameOffset, pos + nameOffset + nameLen * 2);
      } else if (attrType === 0xC0 && !nonResident && nameLen === 0) {
        // Reparse point data is in 0xC0 in some cases, but typically from $REPARSE_POINT
      }
    } catch {
      // Skip corrupt attribute
    }

    pos += attrLen;
  }

  rec.fn = fnBest || fnDos || null;
  // Use non-DOS link count; fall back to 1 if only a DOS name exists
  rec.refCount = fnLinkCount > 0 ? fnLinkCount : (fnDos ? 1 : 0);
  return rec;
}

/**
 * Parse a single 1024-byte MFT record.
 * Returns { type: "base", rec } for base records, or
 * { type: "ext", baseEntry, fnAttrs } for extension records with $FILE_NAME attrs.
 */
function parseMftRecord(buf, recordIndex) {
  if (buf.length < 48) return null;
  if (buf[0] !== 0x46 || buf[1] !== 0x49 || buf[2] !== 0x4C || buf[3] !== 0x45) return null;

  const fixupOffset = buf.readUInt16LE(4);
  const fixupCount = buf.readUInt16LE(6);
  const attrOffset = buf.readUInt16LE(20);
  const baseRefLow = buf.readUInt32LE(32);
  const baseRefHigh = buf.readUInt16LE(36);

  applyFixup(buf, fixupOffset, fixupCount);
  if (attrOffset < 48 || attrOffset >= buf.length) return null;

  // Extension record — extract $FILE_NAME attrs for merging into base record
  if (baseRefLow !== 0 || baseRefHigh !== 0) {
    const baseEntry = baseRefLow + baseRefHigh * 0x100000000;
    const fnAttrs = [];
    let pos = attrOffset;
    while (pos + 8 <= buf.length) {
      const aType = buf.readUInt32LE(pos);
      if (aType === 0xFFFFFFFF || aType === 0) break;
      const aLen = buf.readUInt32LE(pos + 4);
      if (aLen < 16 || pos + aLen > buf.length) break;
      if (aType === 0x30 && !buf[pos + 8]) {
        try { const fn = parseFN(buf, pos); if (fn) fnAttrs.push(fn); } catch {}
      }
      pos += aLen;
    }
    return fnAttrs.length > 0 ? { type: "ext", baseEntry, fnAttrs } : null;
  }

  // Base record
  const lsn = buf.readBigUInt64LE(8);
  const seqNum = buf.readUInt16LE(16);
  const flags = buf.readUInt16LE(22);
  let entryNumber = buf.readUInt32LE(44);
  if (entryNumber === 0 && recordIndex > 0) entryNumber = recordIndex;

  return { type: "base", rec: parseAttributes(buf, attrOffset, {
    entryNumber, seqNum, lsn,
    inUse: (flags & 0x01) !== 0,
    isDirectory: (flags & 0x02) !== 0,
  }) };
}

/**
 * Resolve full parent path by walking the directory map
 */
function resolveParentPath(entryNumber, dirMap, pathCache) {
  if (pathCache.has(entryNumber)) return pathCache.get(entryNumber);

  const parts = [];
  let current = entryNumber;
  const visited = new Set();

  while (current !== undefined && current !== 5) { // Entry 5 = root "."
    if (visited.has(current)) { parts.unshift("[ORPHAN]"); break; }
    visited.add(current);
    const entry = dirMap.get(current);
    if (!entry) { parts.unshift("[ORPHAN]"); break; }
    parts.unshift(entry.name);
    current = entry.parentEntry;
  }

  const resolved = parts.length > 0 ? ".\\" + parts.join("\\") : ".";
  pathCache.set(entryNumber, resolved);
  return resolved;
}

/**
 * Build a row array matching MFT_COLUMNS order from a parsed record
 */
function buildMftRow(rec, dirMap, pathCache) {
  const fn = rec.fn;
  const si = rec.si;
  const parentPath = fn ? resolveParentPath(fn.parentEntry, dirMap, pathCache) : "";

  // SI<FN: True if any SI timestamp is earlier than corresponding FN timestamp
  let siFn = "False";
  if (si && fn) {
    if (si.created < fn.created || si.modified < fn.modified ||
        si.mftModified < fn.mftModified || si.accessed < fn.accessed) {
      siFn = "True";
    }
  }

  // uSecZeros: True if any SI timestamp has zero sub-second component
  let uSecZeros = "False";
  if (si) {
    if (ftHasZeroUsec(si.created) || ftHasZeroUsec(si.modified) ||
        ftHasZeroUsec(si.mftModified) || ftHasZeroUsec(si.accessed)) {
      uSecZeros = "True";
    }
  }

  // Copied: True if SI Created > SI Modified
  const copied = si && si.created > si.modified ? "True" : "False";

  // File size: prefer $DATA real size, fall back to $FILE_NAME realSize
  const fileSize = rec.dataSize >= 0n ? rec.dataSize : (fn ? fn.realSize : 0n);

  return [
    String(rec.entryNumber),                              // EntryNumber
    String(rec.seqNum),                                   // SequenceNumber
    rec.inUse ? "True" : "False",                         // InUse
    fn ? String(fn.parentEntry) : "",                     // ParentEntryNumber
    fn ? String(fn.parentSeqNum) : "",                    // ParentSequenceNumber
    parentPath,                                           // ParentPath
    fn ? fn.filename : "",                                // FileName
    fn ? mftGetExtension(fn.filename) : "",               // Extension
    String(fileSize),                                       // FileSize
    String(rec.refCount),                                 // ReferenceCount
    rec.reparseTarget,                                    // ReparseTarget
    rec.isDirectory ? "True" : "False",                   // IsDirectory
    rec.hasAds ? "True" : "False",                        // HasAds
    rec.isAds ? "True" : "False",                         // IsAds
    siFn,                                                 // SI<FN
    uSecZeros,                                            // uSecZeros
    copied,                                               // Copied
    si ? flagsToString(si.fileFlags) : "",                // SiFlags
    fn ? (FN_NAMESPACE_NAMES[fn.namespace] || String(fn.namespace)) : "", // NameType
    si ? filetimeToIso(si.created) : "",                  // Created0x10
    fn ? filetimeToIso(fn.created) : "",                  // Created0x30
    si ? filetimeToIso(si.modified) : "",                 // LastModified0x10
    fn ? filetimeToIso(fn.modified) : "",                 // LastModified0x30
    si ? filetimeToIso(si.mftModified) : "",              // LastRecordChange0x10
    fn ? filetimeToIso(fn.mftModified) : "",              // LastRecordChange0x30
    si ? filetimeToIso(si.accessed) : "",                 // LastAccess0x10
    fn ? filetimeToIso(fn.accessed) : "",                 // LastAccess0x30
    si ? String(si.usn) : "",                             // UpdateSequenceNumber
    String(rec.lsn),                                      // LogfileSequenceNumber
    si ? String(si.securityId) : "",                      // SecurityId
    rec.objectId,                                         // ObjectIdFileDroid
    rec.loggedUtilStream,                                 // LoggedUtilStream
    rec.zoneId,                                           // ZoneIdContents
  ];
}

/**
 * Parse raw $MFT binary file — memory-efficient two-pass architecture
 * Pass 1: Read file, build directory map + extension FN map (directories only ~5-10% of entries)
 * Pass 2: Re-read file from disk, parse each record, resolve paths, insert into SQLite
 *
 * Previous approach stored ALL parsed records in memory (~500 bytes each),
 * which for a 30GB MFT (29M records) = ~15GB heap → OOM crash.
 * New approach re-reads the file from disk in Pass 2 instead.
 */
async function parseMftFile(filePath, tabId, db, onProgress) {
  const RECORD_SIZE = 1024;
  const CHUNK_RECORDS = 4096; // Read 4MB at a time
  let fileSize, fd;
  try {
    fileSize = fs.statSync(filePath).size;
    fd = fs.openSync(filePath, "r");
  } catch (e) {
    throw new Error(`Cannot open MFT file: ${e.message}`);
  }
  const totalRecords = Math.floor(fileSize / RECORD_SIZE);

  dbg("MFT", `parseMftFile start`, { filePath, fileSize, totalRecords });

  // Fixed schema — no discovery phase needed
  const headers = [...MFT_COLUMNS];
  const colCount = headers.length;
  db.createTab(tabId, headers);

  const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
  const chunkBuf = Buffer.alloc(RECORD_SIZE * CHUNK_RECORDS);
  const dirMap = new Map();
  const extFnMap = new Map(); // extension record FN attrs keyed by base entry number
  // dosOnlyEntries: track base records that only have DOS-namespace FN (namespace=2)
  // so Pass 2 can apply extension FN merge without re-scanning all records
  const dosOnlyEntries = new Set();
  let recordsRead = 0;
  let lastYield = Date.now();

  // ── Pass 1: Build directory map + collect extension FN attrs ──
  // Only stores directory entries (~5-10% of all records) + extension FN attrs.
  // Does NOT store parsed base records — saves ~12-17GB on 30GB files.
  try {
    for (let offset = 0; offset < fileSize; offset += RECORD_SIZE * CHUNK_RECORDS) {
      const bytesToRead = Math.min(RECORD_SIZE * CHUNK_RECORDS, fileSize - offset);
      const bytesRead = fs.readSync(fd, chunkBuf, 0, bytesToRead, offset);
      const recordsInChunk = Math.floor(bytesRead / RECORD_SIZE);

      for (let i = 0; i < recordsInChunk; i++) {
        const recStart = i * RECORD_SIZE;
        const recBuf = chunkBuf.subarray(recStart, recStart + RECORD_SIZE);
        const recordIndex = Math.floor(offset / RECORD_SIZE) + i;

        try {
          const parsed = parseMftRecord(recBuf, recordIndex);
          if (!parsed) continue;
          if (parsed.type === "base") {
            const rec = parsed.rec;
            if (rec.isDirectory && rec.fn) {
              dirMap.set(rec.entryNumber, {
                parentEntry: rec.fn.parentEntry,
                name: rec.fn.filename,
              });
            }
            // Track entries with DOS-only FN for extension merge
            if (!rec.fn || rec.fn.namespace === 2) {
              dosOnlyEntries.add(rec.entryNumber);
            }
          } else if (parsed.type === "ext") {
            // Only keep extension attrs for entries that need them
            let arr = extFnMap.get(parsed.baseEntry);
            if (!arr) { arr = []; extFnMap.set(parsed.baseEntry, arr); }
            for (const fn of parsed.fnAttrs) arr.push(fn);
          }
        } catch {
          // Skip corrupt record
        }
        recordsRead++;
      }

      // Progress (Pass 1 = 0-40%) + event loop yield
      const now = Date.now();
      if (now - lastYield >= 200) {
        lastYield = now;
        if (onProgress) onProgress(recordsRead, Math.floor(offset * 0.4), fileSize);
        await new Promise((r) => setImmediate(r));
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  dbg("MFT", `Pass 1 complete`, { recordsRead, dirMapSize: dirMap.size, extEntries: extFnMap.size, dosOnly: dosOnlyEntries.size });

  // ── Pre-merge extension FN attrs into dirMap ──
  // Apply extension FN fixes to dirMap before Pass 2 so path resolution is correct
  let extMerged = 0;
  if (extFnMap.size > 0) {
    for (const [entryNum, extFns] of extFnMap) {
      if (!dosOnlyEntries.has(entryNum)) continue;
      let best = null;
      for (const fn of extFns) {
        if (fn.namespace === 3) { best = fn; break; }
        if (fn.namespace === 1 && (!best || best.namespace === 0)) best = fn;
        if (fn.namespace === 0 && !best) best = fn;
      }
      if (best) {
        // Update dirMap if this entry is a directory
        const existing = dirMap.get(entryNum);
        if (existing) {
          dirMap.set(entryNum, { parentEntry: best.parentEntry, name: best.filename });
        }
        extMerged++;
      }
    }
    dbg("MFT", `Extension FN pre-merge for dirMap`, { extEntries: extFnMap.size, merged: extMerged });
  }

  // ── Pass 2: Re-read file, parse records, resolve paths, insert into SQLite ──
  // Re-reads from disk instead of holding all records in memory.
  // Cost: ~30-60s extra parse time for 30GB. Savings: ~12-17GB heap.
  const pathCache = new Map();
  pathCache.set(5, "."); // Entry 5 = root directory

  let batch = [];
  let rowCount = 0;
  lastYield = Date.now();

  let fd2;
  try {
    fd2 = fs.openSync(filePath, "r");
  } catch (e) {
    throw new Error(`Cannot re-open MFT file for Pass 2: ${e.message}`);
  }

  try {
    for (let offset = 0; offset < fileSize; offset += RECORD_SIZE * CHUNK_RECORDS) {
      const bytesToRead = Math.min(RECORD_SIZE * CHUNK_RECORDS, fileSize - offset);
      const bytesRead = fs.readSync(fd2, chunkBuf, 0, bytesToRead, offset);
      const recordsInChunk = Math.floor(bytesRead / RECORD_SIZE);

      for (let i = 0; i < recordsInChunk; i++) {
        const recStart = i * RECORD_SIZE;
        const recBuf = chunkBuf.subarray(recStart, recStart + RECORD_SIZE);
        const recordIndex = Math.floor(offset / RECORD_SIZE) + i;

        try {
          const parsed = parseMftRecord(recBuf, recordIndex);
          if (!parsed || parsed.type !== "base") continue;
          const rec = parsed.rec;

          // Apply extension FN merge for DOS-only entries
          if (dosOnlyEntries.has(rec.entryNumber)) {
            const extFns = extFnMap.get(rec.entryNumber);
            if (extFns) {
              let best = null;
              for (const fn of extFns) {
                if (fn.namespace === 3) { best = fn; break; }
                if (fn.namespace === 1 && (!best || best.namespace === 0)) best = fn;
                if (fn.namespace === 0 && !best) best = fn;
              }
              if (best) {
                rec.fn = best;
                if (rec.refCount === 0 && best.namespace !== 2) rec.refCount = 1;
              }
            }
          }

          batch.push(buildMftRow(rec, dirMap, pathCache));
          rowCount++;

          if (batch.length >= batchSize) {
            db.insertBatchArrays(tabId, batch);
            batch = [];
            const now = Date.now();
            if (now - lastYield >= 200) {
              lastYield = now;
              // Pass 2 = 40-100%
              if (onProgress) onProgress(rowCount, Math.floor(fileSize * 0.4 + (offset / fileSize) * fileSize * 0.6), fileSize);
              await new Promise((r) => setImmediate(r));
            }
          }
        } catch {
          // Skip corrupt record
        }
      }
    }
  } finally {
    fs.closeSync(fd2);
  }

  // Final batch
  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
    batch = [];
  }

  // Cleanup
  dirMap.clear();
  extFnMap.clear();
  dosOnlyEntries.clear();
  pathCache.clear();
  batch = null;

  if (onProgress) onProgress(rowCount, fileSize, fileSize);
  const result = db.finalizeImport(tabId);

  const mem = process.memoryUsage();
  dbg("MFT", `parseMftFile done`, { rowCount, heapUsedMB: Math.round(mem.heapUsed / 1048576), rssMB: Math.round(mem.rss / 1048576) });

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    sourceFormat: "raw-mft",
  };
}

/**
 * Extract all resident $DATA content from a raw $MFT file.
 * Writes each resident file to outputDir/Resident/ using MFTECmd naming.
 */
async function extractResidentData(mftPath, outputDir, progressCb) {
  const RECORD_SIZE = 1024;
  const CHUNK_RECORDS = 1024;
  const fileSize = fs.statSync(mftPath).size;
  const totalRecords = Math.floor(fileSize / RECORD_SIZE);
  const residentDir = path.join(outputDir, "Resident");
  fs.mkdirSync(residentDir, { recursive: true });

  const fd = fs.openSync(mftPath, "r");
  const chunkBuf = Buffer.alloc(RECORD_SIZE * CHUNK_RECORDS);
  let extractedCount = 0;
  let skippedErrors = 0;
  let recordsProcessed = 0;
  let lastYield = Date.now();

  // Sanitize filename for filesystem safety
  const sanitize = (name) => name.replace(/[/\\:*?"<>|\x00]/g, "_");

  try {
    for (let offset = 0; offset < fileSize; offset += RECORD_SIZE * CHUNK_RECORDS) {
      const bytesToRead = Math.min(RECORD_SIZE * CHUNK_RECORDS, fileSize - offset);
      const bytesRead = fs.readSync(fd, chunkBuf, 0, bytesToRead, offset);
      const recordsInChunk = Math.floor(bytesRead / RECORD_SIZE);

      for (let i = 0; i < recordsInChunk; i++) {
        const recStart = i * RECORD_SIZE;
        const buf = chunkBuf.subarray(recStart, recStart + RECORD_SIZE);
        recordsProcessed++;

        try {
          // Validate FILE signature
          if (buf[0] !== 0x46 || buf[1] !== 0x49 || buf[2] !== 0x4C || buf[3] !== 0x45) continue;

          const fixupOffset = buf.readUInt16LE(4);
          const fixupCount = buf.readUInt16LE(6);
          const attrOffset = buf.readUInt16LE(20);
          applyFixup(buf, fixupOffset, fixupCount);
          if (attrOffset < 48 || attrOffset >= buf.length) continue;

          const recordIndex = Math.floor(offset / RECORD_SIZE) + i;
          let entryNumber = buf.readUInt32LE(44);
          if (entryNumber === 0 && recordIndex > 0) entryNumber = recordIndex;
          const seqNum = buf.readUInt16LE(16);

          // Check if extension record
          const baseRefLow = buf.readUInt32LE(32);
          const baseRefHigh = buf.readUInt16LE(36);
          const isExtension = baseRefLow !== 0 || baseRefHigh !== 0;
          const baseEntry = isExtension ? baseRefLow + baseRefHigh * 0x100000000 : entryNumber;

          // Walk attributes — collect best filename + resident $DATA content
          let fnBest = null, fnDos = null;
          const residentData = []; // { content: Buffer, streamName: string|null }

          let pos = attrOffset;
          while (pos + 8 <= buf.length) {
            const attrType = buf.readUInt32LE(pos);
            if (attrType === 0xFFFFFFFF || attrType === 0) break;
            const attrLen = buf.readUInt32LE(pos + 4);
            if (attrLen < 16 || pos + attrLen > buf.length) break;

            const nonResident = buf[pos + 8];
            const nameLen = buf[pos + 9];
            const nameOffset = buf.readUInt16LE(pos + 10);

            if (attrType === 0x30 && !nonResident) {
              // $FILE_NAME — use same namespace priority
              try {
                const fn = parseFN(buf, pos);
                if (fn) {
                  if (fn.namespace === 2) fnDos = fn;
                  else if (fn.namespace === 3) fnBest = fn;
                  else if (fn.namespace === 1) { if (!fnBest || fnBest.namespace !== 3) fnBest = fn; }
                  else { if (!fnBest) fnBest = fn; }
                }
              } catch {}
            } else if (attrType === 0x80 && !nonResident) {
              // Resident $DATA — extract content
              try {
                const contentSize = buf.readUInt32LE(pos + 16);
                const contentOffset = buf.readUInt16LE(pos + 20);
                const dataStart = pos + contentOffset;
                if (contentSize > 0 && dataStart + contentSize <= buf.length) {
                  let streamName = null;
                  if (nameLen > 0 && pos + nameOffset + nameLen * 2 <= buf.length) {
                    streamName = buf.toString("utf16le", pos + nameOffset, pos + nameOffset + nameLen * 2);
                  }
                  residentData.push({
                    content: Buffer.from(buf.subarray(dataStart, dataStart + contentSize)),
                    streamName,
                  });
                }
              } catch {}
            }

            pos += attrLen;
          }

          // Write extracted resident data files
          if (residentData.length > 0) {
            const fn = fnBest || fnDos;
            const baseName = sanitize(fn ? fn.filename : "unknown");
            const entry = isExtension ? baseEntry : entryNumber;

            for (const rd of residentData) {
              let outName;
              if (rd.streamName) {
                outName = `${entry}-${seqNum}_${baseName}_${sanitize(rd.streamName)}`;
              } else {
                outName = `${entry}-${seqNum}_${baseName}`;
              }
              // Use original extension if present, otherwise append .bin
              if (!path.extname(outName)) outName += ".bin";
              fs.writeFileSync(path.join(residentDir, outName), rd.content);
              extractedCount++;
            }
          }
        } catch {
          skippedErrors++;
        }

        // Progress + event loop yield
        const now = Date.now();
        if (now - lastYield >= 200) {
          lastYield = now;
          if (progressCb) progressCb(recordsProcessed, totalRecords);
          await new Promise((r) => setImmediate(r));
        }
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  return { extractedCount, totalRecords, outputDir: residentDir, skippedErrors };
}

// ═══════════════════════════════════════════════════════════════════
// ── Raw $J (USN Journal) binary parser ──────────────────────────
// ═══════════════════════════════════════════════════════════════════

const USN_COLUMNS = [
  "Name", "Extension", "EntryNumber", "SequenceNumber",
  "ParentEntryNumber", "ParentSequenceNumber", "ParentPath",
  "UpdateSequenceNumber", "UpdateTimestamp", "UpdateReasons",
  "FileAttributes", "OffsetToData", "SourceFile",
];

const USN_REASON_FLAGS = [
  [0x00000001, "DataOverwrite"],
  [0x00000002, "DataExtend"],
  [0x00000004, "DataTruncation"],
  [0x00000010, "NamedDataOverwrite"],
  [0x00000020, "NamedDataExtend"],
  [0x00000040, "NamedDataTruncation"],
  [0x00000100, "FileCreate"],
  [0x00000200, "FileDelete"],
  [0x00000400, "EaChange"],
  [0x00000800, "SecurityChange"],
  [0x00001000, "RenameOldName"],
  [0x00002000, "RenameNewName"],
  [0x00004000, "IndexableChange"],
  [0x00008000, "BasicInfoChange"],
  [0x00010000, "HardLinkChange"],
  [0x00020000, "CompressionChange"],
  [0x00040000, "EncryptionChange"],
  [0x00080000, "ObjectIdChange"],
  [0x00100000, "ReparsePointChange"],
  [0x00200000, "StreamChange"],
  [0x00400000, "TransactedChange"],
  [0x00800000, "IntegrityChange"],
  [0x01000000, "DesiredStorageClassChange"],
  [0x80000000, "Close"],
];

const USN_ATTR_FLAGS = [
  [0x0001, "ReadOnly"], [0x0002, "Hidden"], [0x0004, "System"],
  [0x0010, "Directory"], [0x0020, "Archive"], [0x0040, "Device"],
  [0x0080, "Normal"], [0x0100, "Temporary"], [0x0200, "SparseFile"],
  [0x0400, "ReparsePoint"], [0x0800, "Compressed"], [0x1000, "Offline"],
  [0x2000, "NotContentIndexed"], [0x4000, "Encrypted"],
];

/** Decode USN reason bitmask to pipe-separated string */
function usnReasonToString(reason) {
  const parts = [];
  for (const [mask, name] of USN_REASON_FLAGS) {
    if (reason & mask) parts.push(name);
  }
  return parts.join("|") || String(reason);
}

/** Decode file attributes bitmask to pipe-separated string */
function usnAttrsToString(attrs) {
  const parts = [];
  for (const [mask, name] of USN_ATTR_FLAGS) {
    if (attrs & mask) parts.push(name);
  }
  return parts.join("|") || "";
}

/**
 * Check if a file is a raw $J (USN Journal) by filename patterns
 */
function isUsnJrnlFile(filePath) {
  const base = path.basename(filePath).toUpperCase();
  // Common names: $UsnJrnl%3A$J, $UsnJrnl:$J, $J
  if (base.includes("USNJRNL") || base === "$J") return true;
  // Also check parent directory for $Extend
  const dir = path.basename(path.dirname(filePath)).toUpperCase();
  if (dir.includes("EXTEND") && base.startsWith("$")) return true;
  return false;
}

/**
 * Parse raw $J (USN Journal) binary file
 * USN_RECORD_V2: variable-length records, may start with null padding
 */
async function parseUsnJrnlFile(filePath, tabId, db, onProgress) {
  let fileSize, fd;
  try {
    fileSize = fs.statSync(filePath).size;
    fd = fs.openSync(filePath, "r");
  } catch (e) {
    throw new Error(`Cannot open USN Journal file: ${e.message}`);
  }
  dbg("USN", `parseUsnJrnlFile start`, { filePath, fileSize });

  const headers = [...USN_COLUMNS];
  const colCount = headers.length;
  db.createTab(tabId, headers);

  const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
  const sourceFile = filePath;

  const READ_CHUNK = 4 * 1024 * 1024; // Read 4MB at a time
  const chunkBuf = Buffer.alloc(READ_CHUNK + 4096); // Extra space for record spanning chunk boundary
  let batch = [];
  let rowCount = 0;
  let lastYield = Date.now();
  let fileReadPos = 0; // Next byte to read from the file
  let carryOver = 0;   // Bytes carried from previous chunk (already at chunkBuf[0..carryOver-1])
  let isFirstChunk = true;

  try {
    while (fileReadPos < fileSize || carryOver > 0) {
      const bytesToRead = Math.min(READ_CHUNK + 4096 - carryOver, fileSize - fileReadPos);
      if (bytesToRead <= 0 && carryOver === 0) break;

      // Read new data after carry-over bytes
      const bytesRead = fs.readSync(fd, chunkBuf, carryOver, Math.max(0, bytesToRead), fileReadPos);
      if (bytesRead === 0 && carryOver === 0) break; // EOF with no pending data
      fileReadPos += bytesRead;
      const available = carryOver + bytesRead;
      if (available < 60) break; // Minimum USN_RECORD_V2 size

      // chunkBuf[0] corresponds to this file position
      const chunkBase = fileReadPos - available;
      let pos = 0;

      if (isFirstChunk) {
        isFirstChunk = false;
        // Skip initial null padding (sparse file region)
        while (pos + 8 <= available) {
          if (chunkBuf.readBigUInt64LE(pos) !== 0n) break;
          pos += 8;
        }
        if (pos > 0) {
          dbg("USN", `Skipped sparse region`, { nullBytes: pos });
        }
      }

      // Parse records from this chunk
      while (pos + 60 <= available) {
        // Skip null padding between records
        if (chunkBuf.readUInt32LE(pos) === 0) {
          pos += 8; // Align to 8-byte boundary
          continue;
        }

        const recLen = chunkBuf.readUInt32LE(pos);
        // Sanity: USN_RECORD_V2 min=60, max reasonable ~4096
        if (recLen < 60 || recLen > 4096) {
          pos += 8;
          continue;
        }

        // Need full record in buffer
        if (pos + recLen > available) break; // Will carry over

        const majorVer = chunkBuf.readUInt16LE(pos + 4);

        if (majorVer === 2) {
          // USN_RECORD_V2
          const entryLo = chunkBuf.readUInt32LE(pos + 8);
          const entryHi = chunkBuf.readUInt16LE(pos + 12);
          const entryNum = entryLo + entryHi * 0x100000000;
          const seqNum = chunkBuf.readUInt16LE(pos + 14);

          const parentLo = chunkBuf.readUInt32LE(pos + 16);
          const parentHi = chunkBuf.readUInt16LE(pos + 20);
          const parentEntry = parentLo + parentHi * 0x100000000;
          const parentSeq = chunkBuf.readUInt16LE(pos + 22);

          const usn = chunkBuf.readBigUInt64LE(pos + 24);
          const timestamp = chunkBuf.readBigUInt64LE(pos + 32);
          const reason = chunkBuf.readUInt32LE(pos + 40);
          const fileAttrs = chunkBuf.readUInt32LE(pos + 52);
          const nameLen = chunkBuf.readUInt16LE(pos + 56);
          const nameOff = chunkBuf.readUInt16LE(pos + 58);

          let filename = "";
          if (nameLen > 0 && pos + nameOff + nameLen <= available) {
            filename = chunkBuf.toString("utf16le", pos + nameOff, pos + nameOff + nameLen);
          }

          const ext = mftGetExtension(filename);
          const dataOffset = chunkBase + pos;

          batch.push([
            filename,                                    // Name
            ext,                                         // Extension
            String(entryNum),                            // EntryNumber
            String(seqNum),                              // SequenceNumber
            String(parentEntry),                         // ParentEntryNumber
            String(parentSeq),                           // ParentSequenceNumber
            "",                                          // ParentPath (needs $MFT)
            String(usn),                                 // UpdateSequenceNumber
            filetimeToIso(timestamp),                    // UpdateTimestamp
            usnReasonToString(reason),                   // UpdateReasons
            usnAttrsToString(fileAttrs),                 // FileAttributes
            String(dataOffset),                          // OffsetToData
            sourceFile,                                  // SourceFile
          ]);
          rowCount++;
        } else if (majorVer === 3) {
          // USN_RECORD_V3 — 128-bit file references (16 bytes each)
          if (recLen < 76 || pos + 76 > available) { pos += Math.max(recLen, 8); continue; }
          const entryLo = chunkBuf.readUInt32LE(pos + 8);
          const seqNum = chunkBuf.readUInt16LE(pos + 14);
          const parentLo = chunkBuf.readUInt32LE(pos + 24);
          const parentSeq = chunkBuf.readUInt16LE(pos + 30);

          const usn = chunkBuf.readBigUInt64LE(pos + 40);
          const timestamp = chunkBuf.readBigUInt64LE(pos + 48);
          const reason = chunkBuf.readUInt32LE(pos + 56);
          const fileAttrs = chunkBuf.readUInt32LE(pos + 68);
          const nameLen = chunkBuf.readUInt16LE(pos + 72);
          const nameOff = chunkBuf.readUInt16LE(pos + 74);

          let filename = "";
          if (nameLen > 0 && pos + nameOff + nameLen <= available) {
            filename = chunkBuf.toString("utf16le", pos + nameOff, pos + nameOff + nameLen);
          }

          const ext = mftGetExtension(filename);
          const dataOffset = chunkBase + pos;

          batch.push([
            filename, ext, String(entryLo), String(seqNum),
            String(parentLo), String(parentSeq), "",
            String(usn), filetimeToIso(timestamp),
            usnReasonToString(reason), usnAttrsToString(fileAttrs),
            String(dataOffset), sourceFile,
          ]);
          rowCount++;
        }
        // else: unknown version, skip

        pos += recLen;
        // Align to 8-byte boundary
        if (pos % 8 !== 0) pos += 8 - (pos % 8);
      }

      // Flush batch
      if (batch.length >= batchSize) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
      }

      // Carry remaining bytes to next iteration
      if (pos < available) {
        const remaining = available - pos;
        chunkBuf.copy(chunkBuf, 0, pos, pos + remaining);
        carryOver = remaining;
      } else {
        carryOver = 0;
      }

      // EOF with unprocessable carry-over — break to avoid infinite loop
      if (bytesRead === 0) break;

      // Progress + yield
      const now = Date.now();
      if (now - lastYield >= 200) {
        lastYield = now;
        if (onProgress) onProgress(rowCount, fileReadPos, fileSize);
        await new Promise((r) => setImmediate(r));
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  // Final batch
  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
    batch = [];
  }

  if (onProgress) onProgress(rowCount, fileSize, fileSize);
  const result = db.finalizeImport(tabId);

  const mem = process.memoryUsage();
  dbg("USN", `parseUsnJrnlFile done`, { rowCount, heapUsedMB: Math.round(mem.heapUsed / 1048576), rssMB: Math.round(mem.rss / 1048576) });

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    sourceFormat: "raw-usnjrnl",
  };
}

/**
 * Auto-detect file type and parse accordingly
 */
async function parseFile(filePath, tabId, db, onProgress, sheetName, fileSize, tableName) {
  // Pass fileSize hint to db.createTab for pragma scaling on large files
  if (fileSize) db._fileSizeHint = fileSize;
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".xls") {
    return parseXLSFile(filePath, tabId, db, onProgress, sheetName);
  }
  if (ext === ".xlsx" || ext === ".xlsm") {
    return parseXLSXStream(filePath, tabId, db, onProgress, sheetName);
  }
  if (ext === ".evtx") {
    return parseEvtxFile(filePath, tabId, db, onProgress);
  }
  if (ext === ".plaso" || ext === ".timeline") {
    const check = validatePlasoFile(filePath);
    if (ext === ".plaso" && !check.valid) throw new Error("Not a valid Plaso database (missing metadata table or format_version)");
    // .timeline files: if valid Plaso SQLite, parse as Plaso; otherwise fall through to CSV
    if (check.valid) return parsePlasoFile(filePath, tabId, db, onProgress);
    if (ext === ".timeline") { /* not Plaso — fall through to CSV below */ }
  }
  if (ext === ".sqlite" || ext === ".db" || isSQLiteFile(filePath)) {
    const check = validatePlasoFile(filePath);
    if (check.valid) return parsePlasoFile(filePath, tabId, db, onProgress);
    if (!tableName) throw new Error("SQLite table name required");
    return parseSQLiteTable(filePath, tabId, db, onProgress, tableName);
  }
  if (ext === ".mft") {
    return parseMftFile(filePath, tabId, db, onProgress);
  }
  // Auto-detect raw forensic files by name/magic bytes
  const baseName = path.basename(filePath).toUpperCase();
  if (!ext || baseName.includes("MFT") || baseName.includes("USNJRNL") || baseName === "$J") {
    // Check $J (USN Journal) first — filename-based detection
    if (isUsnJrnlFile(filePath)) {
      return parseUsnJrnlFile(filePath, tabId, db, onProgress);
    }
    // Check $MFT — magic byte detection
    if (isMftFile(filePath)) {
      return parseMftFile(filePath, tabId, db, onProgress);
    }
  }
  // Default to CSV parsing (handles .csv, .tsv, .txt, .log, etc.)
  return parseCSVStream(filePath, tabId, db, onProgress);
}

module.exports = {
  parseCSVStream,
  parseXLSXStream,
  parseXLSFile,
  parsePlasoFile,
  parseEvtxFile,
  parseMftFile,
  isMftFile,
  extractResidentData,
  parseUsnJrnlFile,
  isUsnJrnlFile,
  validatePlasoFile,
  getXLSXSheets,
  isSQLiteFile,
  getSQLiteTables,
  parseSQLiteTable,
  parseFile,
  parseCSVLine,
  detectDelimiter,
};
