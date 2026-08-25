/**
 * sigma/format-detect.js — dataset format detection for the JS Sigma engine.
 *
 * The JS engine resolves Sigma fields differently per source format (raw EVTX
 * direct columns vs EvtxECmd/Hayabusa KV blobs vs Chainsaw renames). Detection
 * is header-based and can misfire on unusual exports, silently mis-mapping every
 * field. Centralizing it here lets the UI preview the detected format and lets an
 * analyst override it before scanning.
 *
 * Pure (no native deps) — unit-testable under plain `node --test`.
 */

const { isHayabusaDataset, isChainsawDataset } = require("../evtx-utils");

// Canonical format ids and their display labels.
const FORMAT_LABELS = {
  evtxecmd: "EvtxECmd",
  hayabusa: "Hayabusa",
  chainsaw: "Chainsaw",
  rawevtx: "Raw EVTX",
  unknown: "Unknown",
};
const FORMATS = ["evtxecmd", "hayabusa", "chainsaw", "rawevtx"];

// Map a format id to the boolean flags the field resolver / scanner expect.
function flagsForFormat(format) {
  return {
    isEvtxECmd: format === "evtxecmd",
    isHayabusa: format === "hayabusa",
    isChainsaw: format === "chainsaw",
    isRawEvtx: format === "rawevtx",
  };
}

// Normalize a user-supplied override to a canonical id, or null if unrecognized
// (an unrecognized override falls back to auto-detection rather than breaking).
function normalizeFormatId(value) {
  if (!value) return null;
  const v = String(value).trim().toLowerCase().replace(/[\s_-]+/g, "");
  if (v === "evtxecmd" || v === "kape") return "evtxecmd";
  if (v === "hayabusa") return "hayabusa";
  if (v === "chainsaw") return "chainsaw";
  if (v === "rawevtx" || v === "raw" || v === "evtx") return "rawevtx";
  return null;
}

// Auto-detect a tab's format from its headers. Mirrors the original inline
// detection in index.js exactly.
function detectDatasetFormat(meta) {
  const headers = (meta && meta.headers) || [];
  const isEvtxECmd = headers.some((h) => /^RemoteHost$/i.test(h)) && headers.some((h) => /^PayloadData1$/i.test(h));
  const isHayabusa = isHayabusaDataset(meta);
  const isChainsaw = isChainsawDataset(meta);
  const isRawEvtx = !isEvtxECmd && !isHayabusa && !isChainsaw
    && headers.some((h) => /^datetime$/i.test(h)) && headers.some((h) => /^Provider$/i.test(h));
  if (isEvtxECmd) return "evtxecmd";
  if (isHayabusa) return "hayabusa";
  if (isChainsaw) return "chainsaw";
  if (isRawEvtx) return "rawevtx";
  return "unknown";
}

/**
 * Resolve the format to scan with: an explicit (recognized) override wins over
 * auto-detection; an unknown/empty override falls back to detection.
 *
 * @returns {{ format, label, flags, detected, detectedLabel, overridden }}
 */
function resolveDatasetFormat(meta, override) {
  const detected = detectDatasetFormat(meta);
  const overrideId = normalizeFormatId(override);
  const format = overrideId || detected;
  return {
    format,
    label: FORMAT_LABELS[format] || "Unknown",
    flags: flagsForFormat(format),
    detected,
    detectedLabel: FORMAT_LABELS[detected] || "Unknown",
    overridden: !!overrideId && overrideId !== detected,
  };
}

module.exports = {
  FORMATS,
  FORMAT_LABELS,
  flagsForFormat,
  normalizeFormatId,
  detectDatasetFormat,
  resolveDatasetFormat,
};
