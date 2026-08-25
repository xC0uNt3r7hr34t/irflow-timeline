/**
 * Build a narrowed SELECT list for a logsource rule group (less SQLite I/O on large CSVs).
 */

const { CHAINSAW_MAP, KV_ALIASES } = require("./field-mapper");
const { collectDetectionFields } = require("./detection-fields");

const MATCH_DETAIL_FIELDS = [
  "Image", "CommandLine", "ParentImage", "TargetUserName", "SubjectUserName", "User",
  "ServiceName", "TargetObject", "Details", "LogonType", "IpAddress", "WorkstationName",
  "ShareName", "ScriptBlockText", "Hashes", "DestinationIp", "DestinationPort", "SourcePort",
  "EventID", "EventId", "Channel", "Provider", "Computer", "ComputerName",
];

const EVTXECMD_KV_HEADER = /^(PayloadData\d+|Details|MapDescription|ExecutableInfo|Payload)$/i;
const HAYABUSA_KV_HEADER = /^(Details|ExtraFieldInfo)$/i;

function addSigmaFieldHeaders(headers, sigmaField, headerLower, out) {
  const lf = sigmaField.toLowerCase();
  if (headerLower[lf]) out.add(headerLower[lf]);
  const aliases = CHAINSAW_MAP[sigmaField];
  if (aliases) {
    for (const alias of aliases) {
      const match = headerLower[alias.toLowerCase()];
      if (match) out.add(match);
    }
  }
  if (KV_ALIASES[sigmaField]) {
    for (const alias of KV_ALIASES[sigmaField]) {
      const match = headerLower[alias.toLowerCase()];
      if (match) out.add(match);
    }
  }
}

/**
 * @param {object} meta - { headers, colMap }
 * @param {object} formatFlags
 * @param {object[]} rules - Rules in this logsource group
 * @param {{ tsCol: string|null, computerCol: string|null, eidCol: string|null, channelCol: string|null }} cols
 * @returns {string} SQL SELECT clause (comma-separated expressions)
 */
function buildGroupSelectClause(meta, formatFlags, rules, cols) {
  const { headers, colMap } = meta;
  const { isEvtxECmd, isHayabusa, isChainsaw, isRawEvtx } = formatFlags;

  const headerLower = {};
  for (const h of headers) headerLower[h.toLowerCase()] = h;

  const neededHeaders = new Set();
  const sigmaFields = new Set(MATCH_DETAIL_FIELDS);
  for (const rule of rules) {
    for (const f of collectDetectionFields(rule.detection)) sigmaFields.add(f);
  }
  for (const f of sigmaFields) addSigmaFieldHeaders(headers, f, headerLower, neededHeaders);

  for (const h of headers) {
    if (!colMap[h]) continue;
    if (neededHeaders.has(h)) continue;
    if (isEvtxECmd && EVTXECMD_KV_HEADER.test(h)) neededHeaders.add(h);
    if (isHayabusa && HAYABUSA_KV_HEADER.test(h)) neededHeaders.add(h);
    if (isRawEvtx && !["datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message"].includes(h)) {
      // Raw EVTX rules may reference any EventData column — keep full width only for raw EVTX
      neededHeaders.add(h);
    }
  }

  for (const h of headers) {
    if (!colMap[h]) continue;
    const safe = colMap[h];
    if (safe === cols.tsCol || safe === cols.computerCol || safe === cols.eidCol || safe === cols.channelCol) {
      neededHeaders.add(h);
    }
  }

  const selectCols = new Set();
  selectCols.add("data.rowid as _rid");
  if (cols.tsCol) selectCols.add(`${cols.tsCol} as _ts`);
  if (cols.computerCol) selectCols.add(`${cols.computerCol} as _host`);
  for (const h of neededHeaders) {
    if (colMap[h]) selectCols.add(`${colMap[h]} as [${h}]`);
  }

  // Chainsaw without explicit field list: keep moderate width
  if (isChainsaw && neededHeaders.size < 4) {
    for (const h of headers) {
      if (colMap[h]) selectCols.add(`${colMap[h]} as [${h}]`);
    }
  }

  return [...selectCols].join(", ");
}

module.exports = { buildGroupSelectClause, MATCH_DETAIL_FIELDS };
