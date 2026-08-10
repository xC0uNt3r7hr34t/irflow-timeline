// Child-process runner for lateral-movement-timezone.test.js.
//
// TZ must be set before the process starts for Node to honour it, so the analysis is
// executed here and the scoring-relevant output is emitted as JSON on stdout.

const { getLateralMovement } = require("../../electron/analyzers/lateral-movement");

const HEADERS = [
  "datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message",
  "User", "SessionID", "Address",
];

const LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

// 02:00 UTC on Tuesday 2026-03-10 — off-hours in UTC, business hours in UTC+8,
// and the previous evening in UTC-5.
function lsm(eid, ts, sessionId = "3") {
  return {
    datetime: ts,
    RecordId: "1",
    EventID: eid,
    Provider: "Microsoft-Windows-TerminalServices-LocalSessionManager",
    Level: "Information",
    Channel: LSM_CHANNEL,
    Computer: "WKS-TARGET",
    Message: "",
    User: "SEVENKINGDOMS\\cersei.lannister",
    SessionID: sessionId,
    Address: "10.10.10.55",
  };
}

// Timestamp style comes from argv so the test can prove that the SAME INSTANT written
// naively vs with an explicit Z scores identically. This matters because the two old
// bugs (parse-as-local + read-as-local) cancel each other for naive input and only
// diverge once the string carries a zone — so a naive-only fixture cannot catch it.
const style = process.argv[2] === "zulu" ? "zulu" : "naive";
const T = (naive, zulu) => (style === "zulu" ? zulu : naive);

const rows = [
  lsm("21", T("2026-03-10 02:00:00.000", "2026-03-10T02:00:00.000Z")),
  lsm("22", T("2026-03-10 02:00:02.000", "2026-03-10T02:00:02.000Z")),
  lsm("24", T("2026-03-10 02:45:00.000", "2026-03-10T02:45:00.000Z")),
];

const colMap = {};
HEADERS.forEach((h, i) => { colMap[h] = `c${i}`; });
const rowsByCN = rows.map((r, i) => {
  const out = { _rowid: i + 1 };
  HEADERS.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
  return out;
});

const db = {
  prepare(sql) {
    return {
      get() { if (/COUNT\(\*\)/i.test(sql)) return { cnt: rowsByCN.length || 1 }; return null; },
      all() {
        if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) {
          const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
          return rowsByCN.map((r) => {
            const out = { _rowid: r._rowid };
            for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
            return out;
          });
        }
        return [];
      },
    };
  },
};

const res = getLateralMovement(
  { db, headers: HEADERS, colMap, tabId: "lm-tz-test" },
  { excludeLocalLogons: true, excludeServiceAccounts: true },
  {
    applyStandardFilters() {},
    ensureIndex() {},
    isChainsawLogonDataset: () => false,
    isHayabusaDataset: () => false,
  },
);

process.stdout.write(JSON.stringify({
  tz: process.env.TZ || null,
  style,
  error: res.error || null,
  sessions: (res.rdpSessions || []).map((s) => ({
    source: s.source,
    target: s.target,
    suspicionScore: s.suspicionScore ?? null,
    flags: s.flags || [],
  })),
}));
