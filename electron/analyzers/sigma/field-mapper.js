/**
 * sigma/field-mapper.js — Format-Aware Sigma Field Resolution
 *
 * Maps Sigma field names (Image, CommandLine, TargetUserName, etc.) to the
 * actual column or extraction path for each data format.
 *
 * For raw EVTX: direct column match (Sigma field names = EventData field names)
 * For Chainsaw: static rename table
 * For EvtxECmd/Hayabusa: runtime KV extraction from packed fields
 */

const { _parseCompactKeyValues, _compactGet } = require("../evtx-utils");
const { SIGMA_FIELD_TO_CONCEPT, buildAliasMap } = require("../../utils/dfir-event-fields");

const SIGMA_FIELDS = Object.keys(SIGMA_FIELD_TO_CONCEPT);

// Chainsaw field name mapping: Sigma field -> Chainsaw column name(s).
const CHAINSAW_MAP = buildAliasMap(SIGMA_FIELDS, { source: "chainsaw", includeLabel: false });

// EvtxECmd/Hayabusa KV alias resolution: Sigma field -> compact key aliases.
const KV_ALIASES = buildAliasMap(SIGMA_FIELDS, { source: "kv", includeLabel: false });

/**
 * Create a field resolver for a specific dataset format.
 *
 * @param {object} meta - { headers, colMap }
 * @param {object} formatFlags - { isEvtxECmd, isHayabusa, isChainsaw, isRawEvtx }
 * @returns {Function} resolve(sigmaFieldName, row) => field value or undefined
 */
function createFieldResolver(meta, formatFlags) {
  const { headers, colMap } = meta;
  const { isEvtxECmd, isHayabusa, isChainsaw } = formatFlags;
  const kvCache = new WeakMap();

  // Build column lookup: normalized header name -> colMap safe name
  const headerLower = {};
  for (const h of headers) {
    headerLower[h.toLowerCase()] = h;
  }

  // For EvtxECmd: identify all content columns for KV parsing and field extraction
  const kvCols = [];
  if (isEvtxECmd) {
    for (const h of headers) {
      if (/^PayloadData\d$/i.test(h) || /^Details$/i.test(h) || /^MapDescription$/i.test(h) || /^ExecutableInfo$/i.test(h) || /^Payload$/i.test(h)) {
        kvCols.push(h);
      }
    }
  }
  if (isHayabusa) {
    for (const h of headers) {
      if (/^Details$/i.test(h) || /^ExtraFieldInfo$/i.test(h)) {
        kvCols.push(h);
      }
    }
  }

  const getKvMap = (row) => {
    let cached = kvCache.get(row);
    if (cached) return cached;
    const texts = [];
    for (const kvCol of kvCols) {
      if (row[kvCol]) texts.push(String(row[kvCol]));
    }
    cached = _parseCompactKeyValues(...texts);
    kvCache.set(row, cached);
    return cached;
  };

  /**
   * Resolve a Sigma field name to a value from a row.
   * @param {string} field - Sigma field name (e.g., "Image", "CommandLine")
   * @param {object} row - Data row object (column names as keys)
   * @returns {string|undefined}
   */
  return function resolve(field, row) {
    // 1. Direct column match (works for raw EVTX and sometimes EvtxECmd)
    if (row[field] !== undefined && row[field] !== null && row[field] !== "") {
      return String(row[field]);
    }

    // 2. Case-insensitive direct match
    const lf = field.toLowerCase();
    const matchedHeader = headerLower[lf];
    if (matchedHeader && row[matchedHeader] !== undefined && row[matchedHeader] !== null && row[matchedHeader] !== "") {
      return String(row[matchedHeader]);
    }

    // 3. Chainsaw rename table
    if (isChainsaw && CHAINSAW_MAP[field]) {
      for (const alias of CHAINSAW_MAP[field]) {
        const v = row[alias];
        if (v !== undefined && v !== null && v !== "") return String(v);
        // Case-insensitive fallback
        const aliasMatch = headerLower[alias.toLowerCase()];
        if (aliasMatch && row[aliasMatch] !== undefined && row[aliasMatch] !== null && row[aliasMatch] !== "") {
          return String(row[aliasMatch]);
        }
      }
    }

    // 4. EvtxECmd/Hayabusa: KV extraction from packed fields
    if ((isEvtxECmd || isHayabusa) && KV_ALIASES[field]) {
      const val = _compactGet(getKvMap(row), ...KV_ALIASES[field]);
      if (val) return val;
    }

    // 5. EvtxECmd: check if field value is embedded in blob text (fallback)
    if (isEvtxECmd) {
      for (const kvCol of kvCols) {
        const rawVal = row[kvCol];
        if (!rawVal) continue;
        // Pattern: "FieldName: Value" inside the blob
        const re = new RegExp(`(?:^|\\b)${field}:\\s*(.+?)(?:\\s*$|\\s*[,|¦])`, "i");
        const m = String(rawVal).match(re);
        if (m) return m[1].trim();
      }
    }

    return undefined;
  };
}

module.exports = { createFieldResolver, CHAINSAW_MAP, KV_ALIASES };
