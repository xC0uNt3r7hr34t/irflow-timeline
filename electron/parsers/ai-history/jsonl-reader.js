/**
 * ai-history/jsonl-reader.js — bounded streaming reader for untrusted JSONL.
 *
 * readline.createInterface buffers an entire line into one string before emitting it, so a
 * subject-controlled session file with one multi-gigabyte (or newline-free) line buffers the
 * whole file into heap and can OOM the worker. This reader caps per-line size: lines over the
 * cap are skipped (counted in parseStats.errors) without ever being fully materialized, so peak
 * memory is bounded by maxLineBytes + one read chunk regardless of input.
 */

const fs = require("fs");

// Current Claude Cowork transcripts can contain legitimate detached/tool-result records above
// 16MB (18.8MB observed in the live 2026 schema). Keep ingestion bounded while allowing those
// records to reach makeRow(), which independently caps retained FullText/tool evidence to 1MB.
const DEFAULT_MAX_LINE_BYTES = 32 * 1024 * 1024;
const READ_CHUNK_BYTES = 1 << 20; // 1MB

/**
 * Stream a JSONL file line-by-line, JSON-parsing each line and invoking onLine(obj, lineNumber).
 * A JSON.parse failure or an onLine() throw skips only that line (counted), never the whole file.
 * @param {string} filePath
 * @param {(obj:any, lineNumber:number) => void} onLine
 * @param {{ parseStats?: {errors:number}, maxLineBytes?: number }} [options]
 */
async function readJsonlBounded(filePath, onLine, options = {}) {
  const parseStats = options.parseStats || null;
  const maxLineBytes = options.maxLineBytes || DEFAULT_MAX_LINE_BYTES;
  const stream = fs.createReadStream(filePath, { encoding: "utf8", highWaterMark: READ_CHUNK_BYTES });

  let buf = "";        // current partial line
  let lineNumber = 0;
  let dropping = false; // discarding an over-length line until its terminating newline

  const emit = (line) => {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed) return;
    let obj;
    try { obj = JSON.parse(trimmed); } catch { if (parseStats) parseStats.errors += 1; return; }
    try { onLine(obj, lineNumber); } catch { if (parseStats) parseStats.errors += 1; }
  };

  for await (const chunk of stream) {
    let rest = chunk;
    while (rest.length) {
      const nl = rest.indexOf("\n");
      if (nl === -1) {
        if (dropping) break; // still inside an over-length line — discard the whole chunk
        buf += rest;
        if (buf.length > maxLineBytes) { // partial line already too big — drop the rest of it
          if (parseStats) parseStats.errors += 1;
          dropping = true;
          buf = "";
        }
        break;
      }
      const segment = rest.slice(0, nl);
      rest = rest.slice(nl + 1);
      if (dropping) { dropping = false; buf = ""; continue; } // tail of the dropped line
      const line = buf + segment;
      buf = "";
      if (line.length > maxLineBytes) { if (parseStats) parseStats.errors += 1; continue; }
      emit(line);
    }
  }
  if (!dropping && buf.length) {
    if (buf.length > maxLineBytes) { if (parseStats) parseStats.errors += 1; }
    else emit(buf);
  }
}

module.exports = { readJsonlBounded, DEFAULT_MAX_LINE_BYTES };
