// Regression test for multi-source Lateral Movement mixed-format parsing (release review M1).
//
// Bug: getMultiSourceLateralMovement merged rows from every tab and parsed ALL of them
// with a single global format derived from the FIRST tab (isEvtxECmd/isHayabusa from
// primaryColumns). Mixing formats (e.g. a KAPE EvtxECmd tab + a raw Security.evtx tab)
// mis-parsed the non-primary tab: when EvtxECmd is primary, a Standard row's plain
// TargetUserName has no "Target:" prefix, so the EvtxECmd parser wiped the username to ""
// (and the _userNameFallback column doesn't exist on a Standard tab) — silently dropping
// those accounts from the merged result.
//
// Fix: each merged row carries row._sourceFormat (set by multi-source.js); index.js now
// parses each row by its OWN format. Single-tab behavior is unchanged (no _sourceFormat
// => falls back to the global flags).

const test = require("node:test");
const assert = require("node:assert/strict");
const { getMultiSourceLateralMovement } = require("../electron/analyzers/lateral-movement/multi-source");

// Stub tab whose db answers the analyzer's aliased SELECTs (cN as [alias]) with rows,
// COUNT(*) with a count, and everything else with []. Enough to exercise the merged
// logon-parsing path without a real SQLite binding.
function tab(tabId, headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });
  const aliasRows = (sql) => {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
      return out;
    });
  };
  const db = {
    prepare(sql) {
      return {
        get() { return /COUNT\(\*\)/i.test(sql) ? { cnt: rowsByCN.length || 1 } : null; },
        all() {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) return aliasRows(sql);
          return [];
        },
      };
    },
  };
  return { meta: { db, headers, colMap, tabId }, tabId, label: tabId };
}

// Exact detector-less ctx db.js builds for getMultiSourceLateralMovement.
const realCtx = () => ({ applyStandardFilters() {}, ensureIndex() {}, lmPreviewCache: new Map() });

const EVTXECMD = ["TimeCreated", "EventId", "Computer", "RemoteHost", "UserName", "PayloadData1", "PayloadData2", "Channel"];
const STANDARD = ["datetime", "EventID", "Computer", "IpAddress", "WorkstationName", "TargetUserName", "LogonType", "Provider", "Channel"];

const evtxRow = (o) => ({
  TimeCreated: o.ts || "2026-02-14T10:00:00Z", EventId: o.eid || "4624", Computer: o.computer || "DC01",
  RemoteHost: o.remoteHost || "WKSA (10.0.0.1)", UserName: o.userName || "-\\-",
  PayloadData1: o.pd1 || "", PayloadData2: o.pd2 || "LogonType 3", Channel: "Security",
});
const stdRow = (o) => ({
  datetime: o.ts || "2026-02-14T11:00:00Z", EventID: o.eid || "4624", Computer: o.computer || "DC02",
  IpAddress: o.ip || "10.0.0.2", WorkstationName: o.wks || "WKSB", TargetUserName: o.user || "bob",
  LogonType: o.lt || "3", Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security",
});

function accountUsers(result) {
  return new Set((result.accounts || []).map((a) => String(a.user).toLowerCase()));
}

test("multi-source LM attributes usernames per-tab format (EvtxECmd primary + Standard secondary)", () => {
  const metas = [
    tab("evtxecmd-tab", EVTXECMD, [evtxRow({ pd1: "Target: CORP\\alice", remoteHost: "WKSA (10.0.0.1)", computer: "DC01" })]),
    tab("standard-tab", STANDARD, [stdRow({ user: "bob", ip: "10.0.0.2", wks: "WKSB", computer: "DC02" })]),
  ];
  const result = getMultiSourceLateralMovement(metas, { excludeServiceAccounts: false, excludeLocalLogons: false }, realCtx());
  const users = accountUsers(result);
  assert.ok(users.has("alice"), `expected alice from the EvtxECmd tab, got ${[...users].join(",")}`);
  // bob is the cross-format regression: a Standard TargetUserName parsed under the global
  // EvtxECmd format used to resolve to "" (no "Target:" prefix, no _userNameFallback column).
  assert.ok(users.has("bob"), `expected bob from the Standard tab (cross-format attribution), got ${[...users].join(",")}`);
});

test("multi-source LM attributes usernames per-tab format with the order reversed (Standard primary + EvtxECmd secondary)", () => {
  const metas = [
    tab("standard-tab", STANDARD, [stdRow({ user: "carol", ip: "10.0.0.3", wks: "WKSC", computer: "DC03" })]),
    tab("evtxecmd-tab", EVTXECMD, [evtxRow({ pd1: "Target: dave", remoteHost: "WKSD (10.0.0.4)", computer: "DC04" })]),
  ];
  const result = getMultiSourceLateralMovement(metas, { excludeServiceAccounts: false, excludeLocalLogons: false }, realCtx());
  const users = accountUsers(result);
  assert.ok(users.has("carol"), `expected carol from the Standard tab, got ${[...users].join(",")}`);
  // dave is the cross-format regression in this direction: an EvtxECmd PayloadData1
  // "Target: dave" parsed under the global Standard format keeps the literal "Target: "
  // prefix (no domain backslash to coincidentally split on), so only the per-row EvtxECmd
  // path correctly extracts "dave".
  assert.ok(users.has("dave"), `expected dave from the EvtxECmd tab (cross-format attribution), got ${[...users].join(",")}`);
});
