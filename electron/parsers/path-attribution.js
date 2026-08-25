/**
 * parsers/path-attribution.js — derive User + Host from an artifact's source path.
 *
 * KAPE packages preserve original paths (…\Users\<name>\… on a per-host root), so the
 * "who / which machine" dimension is sitting in every SourceFile path — just not usable as a
 * column. These helpers extract it so AI and timeline rows become filterable + groupable per user
 * and per host.
 */

const path = require("path");

// A KAPE collection root's first segment is often a drive marker rather than a host folder.
const DRIVE_RE = /^(\[?[a-z]\]?|[a-z]%3a|[a-z]:|\[root\])$/i;
// Well-known artifact-root folder names — a host folder is never one of these.
const NON_HOST_RE = /^(users|windows|winnt|programdata|program files( \(x86\))?|\$extend|\$recycle\.bin|documents and settings|system volume information|appcompat|config)$/i;

/** Username from a `…\Users\<name>\…` (or `Documents and Settings\<name>`) path, else "". */
function deriveUser(filePath) {
  const segs = String(filePath || "").split(/[\\/]+/);
  for (let i = 0; i < segs.length - 1; i++) {
    const s = segs[i].toLowerCase();
    if (s === "users" || s === "documents and settings") return segs[i + 1] || "";
  }
  return "";
}

/**
 * Host for a file, relative to the collection root:
 *   <root>/<HOST>/C/Users/...  -> "HOST"     (first segment is not a drive marker)
 *   <root>/C/Users/...         -> basename(root)  (single host; the root folder names it)
 */
function deriveHost(filePath, root) {
  if (!root) return "";
  // No source path -> single-host fallback. Guard before path.relative(): path.relative(root, "")
  // resolves "" to cwd and returns a "../.." artifact, which would leak as a bogus host.
  if (!filePath) return path.basename(root) || "";
  let rel;
  try { rel = path.relative(root, filePath); } catch { return ""; }
  const segs = rel.split(/[\\/]+/).filter(Boolean);
  // A leading non-drive, non-artifact-root folder (with path beneath it) is the host.
  if (segs.length >= 2 && !DRIVE_RE.test(segs[0]) && !NON_HOST_RE.test(segs[0])) return segs[0];
  return path.basename(root) || ""; // single-host collection: the root folder names it
}

/** CSV-escape a single cell. */
function csvCell(v) {
  const s = String(v == null ? "" : v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Strip a leading UTF-8 BOM from a header cell (for column-name matching only). */
function deBom(s) {
  return s && s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

/**
 * Append `User` + `Host` columns to an EZ-Tools CSV, derived per-row from its SourceFile /
 * SourceFilename column. Records are preserved verbatim (BOM, quoting) — the two values are
 * appended — so the KAPE column profile still detects on import. Returns the input unchanged
 * if there is no source-path column.
 *
 * Operates on LOGICAL CSV records, not physical lines. An EZ-Tools field can legitimately carry
 * an embedded newline (LNK / Jump List `Arguments`, Shellbag `Value`); a naive `\n` split would
 * cut such a record in half and inject `,User,Host` mid-record — corrupting structure and
 * misattributing every column after it. A short row (fewer cells than the header) is padded to
 * header width first, so the appended User/Host always occupy their own two trailing columns for
 * the downstream by-header-name reader (worker `explodeCsvFileInto`, importer `parseCSVStream`).
 *
 * @param {string} csvText
 * @param {string} root  the triage collection root (for host derivation)
 * @param {(rec:string)=>string[]} parseLine  a single-record field splitter (parsers/csv parseCSVLine; quote-aware, tolerates embedded newlines)
 * @param {(str:string, onRecord:(rec:string)=>void)=>string} scanRecords  quote-aware record scanner (parsers/csv scanCSVRecords); returns any trailing partial record
 */
function annotateCsvUserHost(csvText, root, parseLine, scanRecords) {
  if (!csvText) return csvText;

  // Group physical lines into logical records (a record ends only at a newline OUTSIDE quotes).
  const records = [];
  const tail = scanRecords(String(csvText), (rec) => records.push(rec));
  if (tail) records.push(tail); // final record when the file lacks a trailing newline
  if (records.length === 0) return csvText;

  const header = parseLine(records[0]).map(deBom);
  const width = header.length; // original column count, before the two appended columns
  const srcIdx = header.findIndex((h) => /^(SourceFile|SourceFilename)$/i.test(h));
  if (srcIdx < 0) return csvText; // nothing to attribute from

  const out = [`${records[0]},User,Host`];
  for (let i = 1; i < records.length; i++) {
    const cells = parseLine(records[i]);
    const src = cells[srcIdx] || "";
    // Pad a short row up to header width (appends empty trailing cells, verbatim-safe) so the
    // appended User/Host stay in their own columns instead of shifting onto real data columns.
    const pad = cells.length < width ? ",".repeat(width - cells.length) : "";
    out.push(`${records[i]}${pad},${csvCell(deriveUser(src))},${csvCell(deriveHost(src, root))}`);
  }
  // Preserve the input's trailing-newline state (EZ-Tools CSVs end with one).
  return out.join("\n") + (/\n$/.test(csvText) ? "\n" : "");
}

module.exports = { deriveUser, deriveHost, annotateCsvUserHost };
