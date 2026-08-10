// Tests for getProcessInspectorContext — locks in that timestamp parsing for
// the selected event uses the canonical normalizer rather than `new Date(s)`.
//
// Background: the inspector context API was the last site still parsing
// timestamps with raw `new Date(timestamp)` (electron/analyzers/process-tree/
// index.js:1058 prior to fix). On non-ISO datasets that meant the side panel
// host/user-window queries were dispatched with `fromIso = "Invalid Date".toISOString()`
// — they silently returned no related events. These tests would have caught it.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getProcessInspectorContext } = require("../electron/analyzers/process-tree");

// Minimal stub: db.prepare returns objects whose .get() / .all() respond to the
// SELECT shape getProcessInspectorContext uses. We capture every prepared SQL
// + bind params so the test can assert *what* was queried, not just the result.
function makeContextStub(headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });

  // Translate fixture rows to cN-keyed shape with synthetic rowid
  const cnRows = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });

  function aliasRow(row, sql) {
    const out = { _rowid: row._rowid };
    for (const [, idx, alias] of sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)) {
      out[alias] = row[`c${idx}`];
    }
    return out;
  }

  const captured = [];
  const db = {
    prepare(sql) {
      return {
        get(...params) {
          captured.push({ kind: "get", sql, params });
          // The selected-event lookup is `WHERE data.rowid = ?`
          const rowidMatch = sql.match(/data\.rowid\s*=\s*\?/);
          if (rowidMatch) {
            const wanted = Number(params[0]);
            const row = cnRows.find((r) => r._rowid === wanted);
            return row ? aliasRow(row, sql) : null;
          }
          return null;
        },
        all(...params) {
          captured.push({ kind: "all", sql, params });
          // Respond with every row — the analyzer filters/groups in JS based on
          // the selected event so we don't need real WHERE evaluation here.
          return cnRows.map((r) => aliasRow(r, sql));
        },
      };
    },
    // norm_host / norm_guid / norm_logon_id / norm_pid / sort_datetime — we register
    // them as no-ops because the stub `all()` ignores filters anyway.
    function() {},
  };

  return {
    meta: { db, headers, colMap, tabId: "ctx-test" },
    captured,
  };
}

const HDRS = [
  "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid",
  "Image", "ParentImage", "CommandLine", "User", "UtcTime",
  "EventID", "Provider", "Computer",
];
const PIVOT_HDRS = [
  ...HDRS,
  "DestinationIp", "DestinationPort", "QueryName", "RuleTitle", "RuleID", "Level",
];

test("inspector context parses US-style timestamps into a finite tsMs", () => {
  const rows = [
    {
      ProcessId: "1234", ParentProcessId: "1000", ProcessGuid: "", ParentProcessGuid: "",
      Image: "C:\\Windows\\System32\\cmd.exe", ParentImage: "C:\\Windows\\System32\\svchost.exe",
      CommandLine: "cmd.exe /c whoami", User: "SYSTEM",
      UtcTime: "3/15/2026 10:00:00 AM",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
    },
  ];
  const { meta } = makeContextStub(HDRS, rows);
  const ctx = getProcessInspectorContext(meta, { rowId: 1 });
  assert.ok(ctx.selected, "selected event must resolve");
  assert.ok(Number.isFinite(ctx.selected.tsMs), "tsMs must be a finite number for a US-style timestamp");
  assert.ok(ctx.selected.tsMs > 0, "tsMs must be a real epoch");
  // Sanity: parsed value should be 2026-03-15 10:00 UTC
  const expected = Date.UTC(2026, 2, 15, 10, 0, 0);
  assert.equal(ctx.selected.tsMs, expected);
});

test("inspector context dispatches host-window query with ISO bounds for non-ISO source ts", () => {
  const rows = [
    {
      ProcessId: "1234", ParentProcessId: "1000", ProcessGuid: "", ParentProcessGuid: "",
      Image: "C:\\Foo.exe", ParentImage: "C:\\Bar.exe",
      CommandLine: "foo.exe", User: "Alice",
      UtcTime: "3/15/2026 10:00:00 AM",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
    },
  ];
  const { meta, captured } = makeContextStub(HDRS, rows);
  getProcessInspectorContext(meta, { rowId: 1, windowMinutes: 5 });
  // The host-window query binds [normHost, fromIso, toIso].
  const hostWindow = captured.find((c) =>
    c.kind === "all" && /norm_host\(/.test(c.sql) && /sort_datetime\(/.test(c.sql)
  );
  assert.ok(hostWindow, "host-window query must be dispatched");
  // Bounds 2 + 3 are the ISO date strings — the bug we're guarding against
  // is `Invalid Date`.toISOString() throwing or producing the wrong instant.
  const [, fromIso, toIso] = hostWindow.params;
  assert.match(fromIso, /^2026-03-15T0[09]:5\d:/, `fromIso (${fromIso}) must be a real ISO around 2026-03-15 09:55Z`);
  assert.match(toIso,   /^2026-03-15T10:0\d:/,    `toIso (${toIso}) must be a real ISO around 2026-03-15 10:05Z`);
});

test("inspector context: ISO timestamps still parse correctly (regression guard)", () => {
  const rows = [
    {
      ProcessId: "1234", ParentProcessId: "1000", ProcessGuid: "", ParentProcessGuid: "",
      Image: "C:\\Foo.exe", ParentImage: "C:\\Bar.exe",
      CommandLine: "foo.exe", User: "SYSTEM",
      UtcTime: "2026-03-15T10:00:00Z",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
  ];
  const { meta } = makeContextStub(HDRS, rows);
  const ctx = getProcessInspectorContext(meta, { rowId: 1 });
  assert.equal(ctx.selected.tsMs, Date.UTC(2026, 2, 15, 10, 0, 0));
});

test("inspector context returns cross-telemetry pivots with exact source refs", () => {
  const rows = [
    {
      ProcessId: "4444", ParentProcessId: "1000", ProcessGuid: "{aaaaaaaa-1111-2222-3333-444444444444}", ParentProcessGuid: "",
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "powershell.exe -nop -w hidden", User: "ACME\\Alice",
      UtcTime: "2026-03-15T10:00:00Z",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
    {
      ProcessId: "4444", ParentProcessId: "", ProcessGuid: "{aaaaaaaa-1111-2222-3333-444444444444}", ParentProcessGuid: "",
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ParentImage: "",
      CommandLine: "", User: "ACME\\Alice",
      UtcTime: "2026-03-15T10:00:04Z",
      EventID: "22", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      QueryName: "weird-domain.example",
    },
    {
      ProcessId: "4444", ParentProcessId: "", ProcessGuid: "{aaaaaaaa-1111-2222-3333-444444444444}", ParentProcessGuid: "",
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ParentImage: "",
      CommandLine: "", User: "ACME\\Alice",
      UtcTime: "2026-03-15T10:00:08Z",
      EventID: "3", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      DestinationIp: "45.77.1.2", DestinationPort: "443",
    },
    {
      ProcessId: "4444", ParentProcessId: "", ProcessGuid: "{aaaaaaaa-1111-2222-3333-444444444444}", ParentProcessGuid: "",
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ParentImage: "",
      CommandLine: "", User: "ACME\\Alice",
      UtcTime: "2026-03-15T10:00:10Z",
      EventID: "1", Provider: "Hayabusa", Computer: "HOST-A",
      RuleTitle: "Suspicious PowerShell Network Activity", RuleID: "rule-ps-net", Level: "high",
    },
  ];
  const { meta } = makeContextStub(PIVOT_HDRS, rows);
  meta.tabId = "process-pivot-tab";
  const ctx = getProcessInspectorContext(meta, { rowId: 1, windowMinutes: 1, contextMinutes: 1 });

  assert.equal(ctx.crossTelemetry.stats.total, 3);
  assert.deepEqual(ctx.crossTelemetry.counts, { dns: 1, network: 1, detection: 1 });
  assert.deepEqual(
    ctx.crossTelemetry.evidenceRefs,
    [
      { tabId: "process-pivot-tab", rowId: 1 },
      { tabId: "process-pivot-tab", rowId: 2 },
      { tabId: "process-pivot-tab", rowId: 3 },
      { tabId: "process-pivot-tab", rowId: 4 },
    ]
  );
  const networkPivot = ctx.crossTelemetry.pivots.find((pivot) => pivot.type === "network");
  assert.ok(networkPivot, "network pivot must be present");
  assert.equal(networkPivot.entities.destIp, "45.77.1.2");
  assert.equal(networkPivot.entities.destPort, "443");
  assert.equal(networkPivot.confidence, "high");

  const detectionPivot = ctx.crossTelemetry.pivots.find((pivot) => pivot.type === "detection");
  assert.ok(detectionPivot, "detection pivot must be present");
  assert.equal(detectionPivot.entities.ruleId, "rule-ps-net");
  assert.equal(detectionPivot.entities.ruleTitle, "Suspicious PowerShell Network Activity");
});
