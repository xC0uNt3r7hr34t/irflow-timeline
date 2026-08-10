// Shared process identity helpers for Process Inspector, Lateral Movement, and Sigma.
// Single place to normalize GUID / PID / host / logon and build stable entity keys
// so cross-feature handoffs and grid pivots agree on "same process".

import {
  normalizeGuid,
  normalizePid,
  normalizeHost,
  normalizeLogonId,
  normalizeUser,
  normalizeTimestamp,
} from "./forensic-normalize.js";

export {
  normalizeGuid,
  normalizePid,
  normalizeHost,
  normalizeLogonId,
  normalizeUser,
  normalizeTimestamp,
};

/** Basename of an image path without .exe (lowercase). */
export function processBasename(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^.*[/\\]/, "")
    .replace(/\.exe$/i, "");
}

/**
 * Canonical process entity key for correlation across features.
 * Prefer GUID; fall back to host|pid|createMs bucket.
 */
export function processEntityKey({ guid, pid, hostname, ts, tsMs, rowid } = {}) {
  const g = normalizeGuid(guid);
  if (g) return `guid:${g}`;
  const p = normalizePid(pid);
  const h = normalizeHost(hostname) || "__nohost__";
  const t = Number.isFinite(tsMs) ? tsMs : normalizeTimestamp(ts || "");
  if (p && Number.isFinite(t)) return `pid:${h}|${p}|${t}`;
  if (p) return `pid:${h}|${p}`;
  if (rowid != null) return `row:${rowid}`;
  return "";
}

/** Session scope key: logon preferred, then session id. */
export function processSessionScope({ logonId, sessionId } = {}) {
  const lid = normalizeLogonId(logonId);
  if (lid) return `logon:${lid}`;
  const sid = normalizeLogonId(sessionId);
  if (sid) return `session:${sid}`;
  return "";
}

/**
 * Build a lightweight identity snapshot from a PI node (or similar).
 * Used by handoffs and pivot builders so field access stays consistent.
 */
export function processIdentityFromNode(node = {}) {
  const guid = normalizeGuid(node.guid);
  const pid = normalizePid(node.pid);
  const hostname = normalizeHost(node.hostname || node.normHost);
  const user = normalizeUser(node.user);
  const tsMs = Number.isFinite(node.tsMs) ? node.tsMs : normalizeTimestamp(node.ts || "");
  return {
    guid,
    pid,
    ppid: normalizePid(node.ppid),
    parentGuid: normalizeGuid(node.parentGuid),
    hostname,
    user,
    processName: processBasename(node.processName || node.image),
    image: String(node.image || "").trim(),
    cmdLine: String(node.cmdLine || "").trim(),
    ts: node.ts || "",
    tsMs: Number.isFinite(tsMs) ? tsMs : NaN,
    logonId: normalizeLogonId(node.logonId),
    sessionId: normalizeLogonId(node.sessionId),
    sessionScope: processSessionScope(node),
    entityKey: processEntityKey({
      guid,
      pid,
      hostname: node.hostname || node.normHost,
      ts: node.ts,
      tsMs,
      rowid: node.rowid,
    }),
    rowid: node.rowid ?? null,
  };
}

/** True when two identity snapshots refer to the same process entity. */
export function sameProcessEntity(a, b) {
  if (!a || !b) return false;
  if (a.entityKey && b.entityKey && a.entityKey === b.entityKey) return true;
  const ga = normalizeGuid(a.guid);
  const gb = normalizeGuid(b.guid);
  if (ga && gb) return ga === gb;
  const pa = normalizePid(a.pid);
  const pb = normalizePid(b.pid);
  if (!pa || pa !== pb) return false;
  const ha = normalizeHost(a.hostname);
  const hb = normalizeHost(b.hostname);
  if (ha && hb && ha !== hb) return false;
  return true;
}
