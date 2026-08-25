// ── Plaso (.plaso) SQLite parser ─────────────────────────────────────

const zlib = require("zlib");
const { dbg } = require("../logger");

const BATCH_SIZE_DEFAULT = 100000;
const BATCH_SIZE_MAX_BYTES = 100 * 1024 * 1024; // ~100MB target max per batch
const DISCOVERY_WINDOW_COUNT = 48;
const DISCOVERY_ROWS_PER_WINDOW = 32;

// Plaso stores heterogeneous artifact families in one event_data table. These
// fields must not depend on a small schema-discovery sample: otherwise a file
// whose early rows are file-system events can silently lose all EVTX columns.
const FIXED_FIELDS = [
  "datetime",
  "timestamp_desc",
  "data_type",
  "parser_chain",
  "message",
  "event_identifier",
  "record_number",
  "source_name",
  "computer_name",
  "channel",
  "creation_time",
  "written_time",
  "strings",
  "xml_string",
  "recovered",
  "extra_fields",
];

const FILETIME_UNIX_EPOCH_100NS = 116444736000000000n;
const WEBKIT_UNIX_EPOCH_MICROSECONDS = 11644473600000000n;
const UUID_UNIX_EPOCH_100NS = 122192928000000000n;
const DOTNET_UNIX_EPOCH_100NS = 621355968000000000n;
const HFS_UNIX_EPOCH_SECONDS = 2082844800n;
const FAT_UNIX_EPOCH_SECONDS = 315532800n;

/**
 * JSON.parse rounds integers larger than Number.MAX_SAFE_INTEGER. Plaso date
 * objects commonly contain 17-19 digit FILETIME/nanosecond timestamps, so
 * preserve those timestamp tokens as strings before parsing.
 */
function parsePlasoJson(jsonStr) {
  const safeJson = String(jsonStr).replace(
    /("timestamp"\s*:\s*)(-?\d{16,})(?=\s*[,}])/g,
    '$1"$2"'
  );
  return JSON.parse(safeJson);
}

function formatEpochMicroseconds(value) {
  try {
    let micros = typeof value === "bigint" ? value : BigInt(String(value));
    let seconds = micros / 1000000n;
    let fraction = micros % 1000000n;
    if (fraction < 0n) {
      seconds -= 1n;
      fraction += 1000000n;
    }
    const date = new Date(Number(seconds) * 1000);
    if (!Number.isFinite(date.getTime())) return "";
    const iso = date.toISOString();
    // IRFlow's timestamp parser and date-range UI use four-digit ISO years.
    if (!/^\d{4}-\d{2}-\d{2}T/.test(iso)) return "";
    return `${iso.slice(0, 10)} ${iso.slice(11, 19)}.${String(fraction).padStart(6, "0")}`;
  } catch {
    return "";
  }
}

function formatTimeElements(parts, fractionUnit = "none", timeZoneOffset = 0) {
  if (!Array.isArray(parts) || parts.length < 6) return "";
  const [year, month, day, hour, minute, second] = parts.map(Number);
  const offsetMinutes = Number(timeZoneOffset || 0);
  if (
    !Number.isInteger(year) || year < 1 || year > 9999 ||
    !Number.isInteger(month) || month < 1 || month > 12 ||
    !Number.isInteger(day) || day < 1 || day > 31 ||
    !Number.isInteger(hour) || hour < 0 || hour > 23 ||
    !Number.isInteger(minute) || minute < 0 || minute > 59 ||
    !Number.isInteger(second) || second < 0 || second > 60 ||
    !Number.isFinite(offsetMinutes)
  ) return "";

  // Date.UTC treats years 0-99 as 1900-1999. setUTCFullYear avoids that legacy
  // behavior and also gives us a strict rollover check for malformed values.
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, Math.min(second, 59), 0);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute
  ) return "";

  let fractionMicros = 0;
  if (parts.length > 6) {
    const rawFraction = Number(parts[6]);
    if (!Number.isFinite(rawFraction) || rawFraction < 0) return "";
    if (fractionUnit === "microseconds") fractionMicros = Math.trunc(rawFraction);
    else if (fractionUnit === "milliseconds") fractionMicros = Math.trunc(rawFraction * 1000);
  }
  if (fractionMicros < 0 || fractionMicros >= 1000000) return "";

  const utcMillis = date.getTime() - Math.trunc(offsetMinutes) * 60000;
  return formatEpochMicroseconds(BigInt(utcMillis) * 1000n + BigInt(fractionMicros));
}

function formatFatDateTime(value) {
  const packed = Number(value);
  if (!Number.isInteger(packed) || packed < 0 || packed > 0xffffffff) return "";
  const unsigned = packed >>> 0;
  // dfDateTime serializes the FAT time word in the upper 16 bits and the FAT
  // date word in the lower 16 bits (the inverse of some on-disk examples).
  const timePart = unsigned >>> 16;
  const datePart = unsigned & 0xffff;
  const parts = [
    1980 + ((datePart >>> 9) & 0x7f),
    (datePart >>> 5) & 0x0f,
    datePart & 0x1f,
    (timePart >>> 11) & 0x1f,
    (timePart >>> 5) & 0x3f,
    (timePart & 0x1f) * 2,
  ];
  return formatTimeElements(parts);
}

/**
 * Convert a serialized dfDateTime value to IRFlow's canonical UTC form.
 * Covers every date-time class observed in the supplied Plaso 20260512 files.
 */
function formatPlasoDateTime(value) {
  if (value == null) return "";
  let obj = value;
  if (typeof value === "string") {
    try {
      obj = parsePlasoJson(value);
    } catch {
      return "";
    }
  }
  if (!obj || typeof obj !== "object") return "";

  const className = String(obj.__class_name__ || "").toLowerCase();
  if (className === "notset") return "";

  try {
    const timestamp = obj.timestamp;
    switch (className) {
      case "filetime":
        return formatEpochMicroseconds((BigInt(String(timestamp)) - FILETIME_UNIX_EPOCH_100NS) / 10n);
      case "posixtime":
        return formatEpochMicroseconds(BigInt(String(timestamp)) * 1000000n);
      case "posixtimeinmilliseconds":
      case "javatime":
        return formatEpochMicroseconds(BigInt(String(timestamp)) * 1000n);
      case "posixtimeinmicroseconds":
        return formatEpochMicroseconds(timestamp);
      case "posixtimeinnanoseconds":
      case "apfstime":
        return formatEpochMicroseconds(BigInt(String(timestamp)) / 1000n);
      case "webkittime":
        return formatEpochMicroseconds(BigInt(String(timestamp)) - WEBKIT_UNIX_EPOCH_MICROSECONDS);
      case "uuidtime":
        return formatEpochMicroseconds((BigInt(String(timestamp)) - UUID_UNIX_EPOCH_100NS) / 10n);
      case "dotnetdatetime":
        return formatEpochMicroseconds((BigInt(String(timestamp)) - DOTNET_UNIX_EPOCH_100NS) / 10n);
      case "hfstime":
        return formatEpochMicroseconds((BigInt(String(timestamp)) - HFS_UNIX_EPOCH_SECONDS) * 1000000n);
      case "fatdatetime":
        return formatFatDateTime(obj.fat_date_time);
      case "timeelements":
        return formatTimeElements(obj.time_elements_tuple, "none", obj.time_zone_offset);
      case "timeelementsinmilliseconds":
        return formatTimeElements(obj.time_elements_tuple, "milliseconds", obj.time_zone_offset);
      case "timeelementsinmicroseconds":
        return formatTimeElements(obj.time_elements_tuple, "microseconds", obj.time_zone_offset);
      case "systemtime": {
        const p = obj.system_time_tuple;
        if (!Array.isArray(p) || p.length < 8) return "";
        // SYSTEMTIME: year, month, day-of-week, day, hour, minute, second, ms.
        return formatTimeElements([p[0], p[1], p[3], p[4], p[5], p[6], p[7]], "milliseconds");
      }
      case "cocoatime": {
        const seconds = Number(timestamp);
        if (!Number.isFinite(seconds)) return "";
        return formatEpochMicroseconds(BigInt(Math.round((seconds + 978307200) * 1000000)));
      }
      case "fattimestamp":
        return formatEpochMicroseconds(
          FAT_UNIX_EPOCH_SECONDS * 1000000n + BigInt(String(timestamp)) * 10000n
        );
      default:
        // Some dfDateTime subclasses serialize using the common tuple shape
        // even when IRFlow has not seen their class name before.
        if (Array.isArray(obj.time_elements_tuple)) {
          return formatTimeElements(obj.time_elements_tuple, "microseconds", obj.time_zone_offset);
        }
        return "";
    }
  } catch {
    return "";
  }
}

function normalizePlasoJsonValue(value) {
  if (value == null) return value;
  if (Array.isArray(value)) return value.map(normalizePlasoJsonValue);
  if (typeof value !== "object") return value;
  if (value.__type__ === "DateTimeValues" || value.__class_name__) {
    const formatted = formatPlasoDateTime(value);
    if (formatted || String(value.__class_name__ || "").toLowerCase() === "notset") return formatted;
  }
  const normalized = {};
  for (const [key, nestedValue] of Object.entries(value)) {
    if (key.startsWith("__")) continue;
    normalized[key] = normalizePlasoJsonValue(nestedValue);
  }
  return normalized;
}

function normalizePlasoValue(value) {
  if (value == null) return "";
  if (typeof value === "object") {
    const normalized = normalizePlasoJsonValue(value);
    return typeof normalized === "string" ? normalized : JSON.stringify(normalized);
  }
  return String(value);
}

function decodeXmlText(value) {
  return String(value || "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      try { return String.fromCodePoint(parseInt(hex, 16)); } catch { return ""; }
    })
    .replace(/&#(\d+);/g, (_, decimal) => {
      try { return String.fromCodePoint(parseInt(decimal, 10)); } catch { return ""; }
    })
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&")
    .trim();
}

function extractEvtxChannel(xmlString) {
  if (typeof xmlString !== "string") return "";
  const match = xmlString.match(/<Channel\b[^>]*>([\s\S]*?)<\/Channel>/i);
  return match ? decodeXmlText(match[1]) : "";
}

function extractEvtxDataMessage(xmlString) {
  if (typeof xmlString !== "string" || !xmlString) return "";
  const parts = [];
  const dataPattern = /<Data\b([^>]*?)(?:\/>|>([\s\S]*?)<\/Data>)/gi;
  let match;
  while ((match = dataPattern.exec(xmlString)) !== null) {
    const nameMatch = match[1].match(/\bName\s*=\s*["']([^"']*)["']/i);
    const name = nameMatch ? decodeXmlText(nameMatch[1]) : "";
    const text = decodeXmlText(match[2] || "");
    if (!text) continue;
    parts.push(name ? `${name}=${text}` : text);
  }
  return parts.join("\n");
}

function buildPlasoMessage(eventObj) {
  if (!eventObj || typeof eventObj !== "object") return "";
  if (typeof eventObj.message === "string" && eventObj.message.trim()) {
    return eventObj.message.trim();
  }

  const xmlMessage = extractEvtxDataMessage(eventObj.xml_string);
  if (xmlMessage) return xmlMessage;

  if (Array.isArray(eventObj.strings)) {
    const strings = eventObj.strings
      .filter((value) => value != null && String(value).trim())
      .map((value) => String(value).trim());
    if (strings.length) return strings.join("\n");
  }

  for (const key of ["body", "text", "description", "summary"]) {
    if (typeof eventObj[key] === "string" && eventObj[key].trim()) {
      return eventObj[key].trim();
    }
  }
  return "";
}

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
    return parsePlasoJson(jsonStr);
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
    const tsCol = eventCols.includes("_timestamp")
      ? "_timestamp"
      : eventCols.includes("timestamp")
        ? "timestamp"
        : null;
    if (!tsCol) throw new Error("Plaso event table missing timestamp column");
    const tsDescCol = eventCols.includes("_timestamp_desc")
      ? "_timestamp_desc"
      : eventCols.includes("timestamp_desc")
        ? "timestamp_desc"
        : null;
    const dateTimeCol = eventCols.includes("_date_time")
      ? "_date_time"
      : eventCols.includes("date_time")
        ? "date_time"
        : null;
    const edRefCol = eventCols.includes("_event_data_row_identifier")
      ? "_event_data_row_identifier"
      : eventCols.includes("_event_data_identifier")
        ? "_event_data_identifier"
        : null;

    // Detect if the reference column uses "event_data.N" format (new) vs plain integer (old)
    let joinIsTextRef = false;
    if (edRefCol && hasEventData) {
      const sample = plasoDb.prepare(
        `SELECT ${edRefCol} FROM event WHERE ${edRefCol} IS NOT NULL LIMIT 1`
      ).get();
      if (sample) {
        const val = String(sample[edRefCol]);
        joinIsTextRef = val.startsWith("event_data.");
      }
    }

    // Count events for progress
    const totalEvents = plasoDb.prepare("SELECT COUNT(*) as cnt FROM event").get().cnt;

    // Phase 1: Column discovery — sample event_data entries to find all field keys
    const fieldSet = new Set();

    if (hasEventData) {
      // Plaso commonly stores parser families in long contiguous regions. Sample
      // small windows across the whole INTEGER PRIMARY KEY range rather than only
      // start/middle/end, which missed winevtx in the supplied mixed-image files.
      const idRange = plasoDb.prepare(
        "SELECT MIN(_identifier) AS minId, MAX(_identifier) AS maxId FROM event_data"
      ).get();
      const minId = Number(idRange?.minId || 0);
      const maxId = Number(idRange?.maxId || 0);
      const sampleStmt = plasoDb.prepare(
        "SELECT _identifier, _data FROM event_data WHERE _identifier >= ? ORDER BY _identifier LIMIT ?"
      );
      const seenSampleIds = new Set();
      const windowCount = maxId > minId ? DISCOVERY_WINDOW_COUNT : 1;
      for (let windowIndex = 0; windowIndex < windowCount; windowIndex++) {
        const ratio = windowCount === 1 ? 0 : windowIndex / (windowCount - 1);
        const startId = Math.floor(minId + (maxId - minId) * ratio);
        for (const row of sampleStmt.iterate(startId, DISCOVERY_ROWS_PER_WINDOW)) {
          if (seenSampleIds.has(row._identifier)) continue;
          seenSampleIds.add(row._identifier);
          const obj = parsePlasoBlob(row._data, useZlib);
          for (const key of Object.keys(obj)) {
            if (!key.startsWith("__") && !key.startsWith("_")) fieldSet.add(key);
          }
        }
      }
    }

    // Remove fields handled in fixed positions
    for (const field of FIXED_FIELDS) fieldSet.delete(field);
    const discoveredFields = [...fieldSet].sort();
    const headers = [...FIXED_FIELDS, ...discoveredFields];
    const colCount = headers.length;
    const headerSet = new Set(headers);

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
        SELECT CAST(e.${tsCol} AS TEXT) AS ts,
               ${tsDescCol ? `e.${tsDescCol}` : "NULL"} AS ts_desc,
               ${dateTimeCol ? `e.${dateTimeCol}` : "NULL"} AS date_time,
               ed._data
        FROM event e
        LEFT JOIN event_data ed ON ${joinCondition}
      `);
    } else {
      eventStmt = plasoDb.prepare(`
        SELECT CAST(e.${tsCol} AS TEXT) AS ts,
               ${tsDescCol ? `e.${tsDescCol}` : "NULL"} AS ts_desc,
               ${dateTimeCol ? `e.${dateTimeCol}` : "NULL"} AS date_time,
               e._data
        FROM event e
      `);
    }

    let batch = [];
    let rowCount = 0;
    let lastProgress = 0;
    const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));

    for (const row of eventStmt.iterate()) {
      // Parse event_data JSON
      const eventObj = parsePlasoBlob(row._data, useZlib);
      let serializedDateTime = null;
      if (row.date_time) {
        try { serializedDateTime = parsePlasoJson(row.date_time); } catch { /* fall back below */ }
      }

      // The event.timestamp column is Plaso's normalized POSIX-microsecond value
      // and is authoritative for sorting/time zones. A NotSet value is stored as
      // integer 0 and must remain empty rather than becoming the Unix epoch.
      const isNotSet = String(serializedDateTime?.__class_name__ || "").toLowerCase() === "notset";
      const isLegacyUnset = !serializedDateTime && /^0+$/.test(String(row.ts || ""));
      let datetime = (isNotSet || isLegacyUnset) ? "" : formatEpochMicroseconds(row.ts);
      if (!datetime && !isNotSet) datetime = formatPlasoDateTime(serializedDateTime);

      // Build row array in header order
      const values = new Array(colCount);
      const extraFields = {};
      for (const [key, val] of Object.entries(eventObj)) {
        if (key.startsWith("__") || key.startsWith("_") || headerSet.has(key)) continue;
        extraFields[key] = normalizePlasoJsonValue(val);
      }
      const derived = {
        datetime,
        timestamp_desc: row.ts_desc || eventObj.timestamp_desc || "",
        data_type: eventObj.data_type || "",
        parser_chain: eventObj._parser_chain || "",
        message: buildPlasoMessage(eventObj),
        channel: eventObj.channel || extractEvtxChannel(eventObj.xml_string),
        extra_fields: Object.keys(extraFields).length ? JSON.stringify(extraFields) : "",
      };
      for (let i = 0; i < colCount; i++) {
        const header = headers[i];
        if (Object.prototype.hasOwnProperty.call(derived, header)) {
          values[i] = normalizePlasoValue(derived[header]);
        } else {
          values[i] = normalizePlasoValue(eventObj[header]);
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

module.exports = {
  FIXED_FIELDS,
  buildPlasoMessage,
  extractEvtxChannel,
  extractEvtxDataMessage,
  formatEpochMicroseconds,
  formatPlasoDateTime,
  normalizePlasoValue,
  parsePlasoBlob,
  parsePlasoFile,
  validatePlasoFile,
};
