/**
 * EventID / Channel indexes for JS Sigma SQL pre-filters on large imported tabs.
 */

const { dbg } = require("../../logger");

const SIGMA_FILTER_HEADER = /^(EventID|EventId|event_id|eventid|id|Channel|SourceName|Provider)$/i;

function isSigmaFilterColumn(original) {
  return SIGMA_FILTER_HEADER.test(String(original || ""));
}

/**
 * Build missing indexes on columns used by Sigma logsource SQL pre-filters.
 * Safe to call repeatedly; skips columns already in meta.indexedCols.
 *
 * @param {object} meta - Tab DB metadata from TimelineDB
 * @returns {{ built: number, columns: string[] }}
 */
function ensureSigmaFilterIndexes(meta) {
  if (!meta?.db || meta.closed) return { built: 0, columns: [] };

  const numericSet = meta.numericColumns || new Set();
  const cols = (meta.safeCols || []).filter((c) => isSigmaFilterColumn(c.original));
  const builtCols = [];
  let built = 0;

  for (const col of cols) {
    if (meta.indexedCols?.has(col.safe)) continue;
    try {
      const useBinary = numericSet.has(col.original);
      if (useBinary) {
        meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${col.safe} ON data(${col.safe})`);
      } else {
        meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${col.safe} ON data(${col.safe} COLLATE NOCASE)`);
      }
      meta.indexedCols.add(col.safe);
      built++;
      builtCols.push(col.original);
    } catch (e) {
      dbg("SIGMA", `sigma filter index failed for ${col.original}`, { error: e.message });
    }
  }

  if (built > 0) {
    try {
      meta.db.pragma("analysis_limit = 1000");
      meta.db.exec("ANALYZE");
    } catch (e) {
      dbg("SIGMA", "ANALYZE after sigma filter indexes failed", { error: e.message });
    }
    dbg("SIGMA", `Built ${built} on-demand sigma filter indexes`, { columns: builtCols });
  }

  return { built, columns: builtCols };
}

module.exports = { ensureSigmaFilterIndexes, isSigmaFilterColumn };
