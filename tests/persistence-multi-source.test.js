// Multi-source persistence — the structural fix.
//
// The analyzer was single-tab/single-file, but the evidence for ONE persistence artifact is
// spread across a KAPE package:
//
//   System.evtx                    7045 Service Installed   ← the finding
//   Security.evtx                  4688 process creation    ← the corroboration
//   PowerShell%4Operational.evtx   4104 script block        ← how it was created
//   SOFTWARE hive export           Run value                ← the same artifact again
//
// Each import is its own tab with its own database, and the engine's correlation queries ran
// against one of them, so a service install could never be corroborated: it stayed at
// confidence "present" no matter how much evidence the package actually held.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getPersistenceAnalysis } = require("../electron/analyzers/persistence");
const {
  getMultiSourcePersistence, previewMultiSourcePersistence, detectTabShape, MERGED_EIDS,
} = require("../electron/analyzers/persistence/multi-source");

// Stub tab: prepare().all() aliases "c<idx> as [alias]" out of the SELECT and honours an
// `IN (...)` event-id predicate, so per-tab pre-filtering behaves like real SQL.
function makeTab(label, headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const byCN = rows.map((r, i) => {
    const o = { _rowid: i + 1 };
    headers.forEach((h) => { o[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return o;
  });
  const db = {
    prepare: (sql) => ({
      get: (...params) => (/COUNT\(\*\)/i.test(sql) ? { cnt: byCN.length } : null),
      all: (...params) => {
        if (/SELECT DISTINCT/i.test(sql)) {
          const idx = Number(/c(\d+) as eid/i.exec(sql)?.[1] ?? -1);
          const want = new Set(params.map(String));
          return [...new Set(byCN.map((r) => r[`c${idx}`]).filter((v) => want.has(String(v))))].map((eid) => ({ eid }));
        }
        if (!/^SELECT\s/i.test(sql) || !/FROM\s+data/i.test(sql) || !/\bas\s+\[/.test(sql)) return [];
        const aliases = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
        let out = byCN.map((r) => {
          const o = { _rowid: r._rowid };
          for (const [, i, a] of aliases) o[a] = r[`c${i}`];
          return o;
        });
        const inPred = /c(\d+) IN \(/.exec(sql);
        if (inPred) {
          const aliasKey = aliases.find((x) => x[1] === inPred[1])?.[2];
          const want = new Set(params.map(String));
          if (aliasKey) out = out.filter((r) => want.has(String(r[aliasKey])));
        }
        return out;
      },
    }),
  };
  return { meta: { db, headers, colMap, tabId: label }, tabId: label, label };
}

const ctx = { applyStandardFilters() {}, ensureIndex() {} };

const EVTX_H = ["EventID", "Channel", "datetime", "Computer", "ServiceName", "ImagePath", "StartType", "AccountName",
  "NewProcessName", "ParentProcessName", "ScriptBlockText", "ScriptBlockId", "MessageNumber", "MessageTotal", "TaskName", "param1", "param2"];
const ev = (o) => ({ Channel: "", datetime: "2026-03-15T10:00:00Z", Computer: "U42-TECH", ...o });

const systemTab = () => makeTab("System.evtx", EVTX_H, [
  ev({ EventID: "7045", Channel: "System", datetime: "2026-03-15T10:05:00Z",
    ServiceName: "PSEXESVC", ImagePath: "C:\\Windows\\PSEXESVC.exe", StartType: "demand start", AccountName: "LocalSystem" }),
  ev({ EventID: "7045", Channel: "System", datetime: "2026-03-15T10:00:00Z",
    ServiceName: "BreadSvc", ImagePath: "powershell -File C:\\Users\\Public\\breadService.ps1", StartType: "auto start", AccountName: "LocalSystem" }),
]);
const securityTab = () => makeTab("Security.evtx", EVTX_H, [
  ev({ EventID: "4688", Channel: "Security", datetime: "2026-03-15T10:05:20Z",
    NewProcessName: "C:\\Windows\\PSEXESVC.exe", ParentProcessName: "C:\\Windows\\System32\\services.exe" }),
]);
const psTab = () => makeTab("PowerShell.evtx", EVTX_H, [
  ev({ EventID: "4104", Channel: "Microsoft-Windows-PowerShell/Operational", datetime: "2026-03-15T09:59:00Z",
    ScriptBlockText: "New-Service -Name BreadSvc -BinaryPathName 'C:\\Users\\Public\\breadService.ps1'",
    ScriptBlockId: "aaaaaaaa-1111-2222-3333-444444444444", MessageNumber: "1", MessageTotal: "1" }),
]);

const REG_H = ["HivePath", "HiveType", "KeyPath", "ValueName", "ValueData", "LastWriteTimestamp"];
const hiveTab = () => makeTab("SOFTWARE hive", REG_H, [
  { HivePath: "E:\\tout\\U42-TECH\\C\\Windows\\System32\\config\\SOFTWARE", HiveType: "SOFTWARE",
    KeyPath: "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", ValueName: "Updater",
    ValueData: "C:\\Users\\Public\\evil.exe", LastWriteTimestamp: "2026-03-15 10:02:00" },
]);
const SYSMON_H = ["EventID", "Channel", "datetime", "Computer", "TargetObject", "Details", "Image"];
const sysmonTab = () => makeTab("Sysmon.evtx", SYSMON_H, [
  { EventID: "13", Channel: "Microsoft-Windows-Sysmon/Operational", datetime: "2026-03-15T10:02:00Z", Computer: "U42-TECH",
    TargetObject: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    Details: "C:\\Users\\Public\\evil.exe", Image: "C:\\Windows\\System32\\reg.exe" },
]);

const findItem = (res, name, artifact) => res.items.find((i) => i.name === name && i.artifact === artifact);

// ── the headline: cross-file correlation ───────────────────────────────────

test("a service install alone can only ever be 'present'", () => {
  const res = getPersistenceAnalysis(systemTab().meta, { mode: "evtx" }, ctx);
  const psexec = findItem(res, "Service Installed", "PSEXESVC");
  assert.ok(psexec);
  assert.equal(psexec.confidence, "present", "System.evtx holds no 4688 to corroborate with");
});

test("merging Security.evtx promotes the same install to 'confirmed'", () => {
  const res = getMultiSourcePersistence([systemTab(), securityTab()], {}, ctx);
  const psexec = findItem(res, "Service Installed", "PSEXESVC");
  assert.ok(psexec, "the finding still comes from System.evtx");
  assert.equal(psexec.confidence, "confirmed");
  assert.equal(psexec.details._serviceProcessStarted, true);
  assert.match(psexec.details._serviceProcessParent || "", /services\.exe/);
  assert.ok(psexec.suspiciousReasons.some((r) => /corroborated by process creation/i.test(r)));
  assert.ok(psexec.riskScore > 7, "corroboration must raise the triage score");
});

test("merging PowerShell%4Operational attaches the script block that created the service", () => {
  const alone = getPersistenceAnalysis(systemTab().meta, { mode: "evtx" }, ctx);
  assert.ok((alone.warnings || []).some((w) => /No PowerShell 4104/i.test(w)),
    "single-tab correctly reports it cannot see 4104");

  const res = getMultiSourcePersistence([systemTab(), psTab()], {}, ctx);
  const bread = findItem(res, "Service Installed", "BreadSvc");
  assert.ok(bread);
  assert.equal(bread.details._ps4104Seen, true, "the 4104 that created the service must attach to it");
  assert.notEqual(bread.confidence, "present");
  assert.ok(res.stats.ps4104Scripts >= 1);
});

test("provenance survives the merge", () => {
  const res = getMultiSourcePersistence([systemTab(), securityTab(), psTab()], {}, ctx);
  const psexec = findItem(res, "Service Installed", "PSEXESVC");
  assert.equal(psexec._sourceTab, "System.evtx", "a merged finding must say which tab produced it");
  assert.equal(psexec._sourceTabId, "System.evtx");
  assert.equal(typeof psexec._sourceRowId, "number", "rowids collide across tabs — the source row must be kept");
  assert.equal(res.multiSource, true);
  assert.deepEqual(res.tabSummaries.map((t) => t.label), ["System.evtx", "Security.evtx", "PowerShell.evtx"]);
  assert.equal(res.stats.totalMergedRows, 4);
});

// ── EVTX + registry in one analysis ────────────────────────────────────────

test("EVTX and registry tabs analyze together", () => {
  const res = getMultiSourcePersistence([systemTab(), hiveTab()], {}, ctx);
  assert.equal(res.detectedMode, "mixed");
  assert.ok(res.items.some((i) => i.mode === "evtx"), "EVTX findings must survive");
  assert.ok(res.items.some((i) => i.mode === "registry"), "registry findings must survive");
});

test("the same Run value seen in a hive export and in Sysmon 13 is ONE incident", () => {
  const res = getMultiSourcePersistence([hiveTab(), sysmonTab()], {}, ctx);
  assert.equal(res.items.length, 2, "both sources still produce their own item");

  const runIncidents = res.incidents.filter((i) => /\\Run/i.test(i.artifact || ""));
  assert.equal(runIncidents.length, 1, "one registry write must not become two alerts");
  assert.equal(runIncidents[0].occurrenceCount, 2);
  assert.deepEqual([...(runIncidents[0].sourceTabs || [])].sort(), ["SOFTWARE hive", "Sysmon.evtx"]);
  assert.ok((runIncidents[0].observedBy || []).length > 1, "the incident should record both observing artifacts");
  assert.equal(res.stats.crossSourceIncidents, 1);
});

test("different Run values stay separate incidents", () => {
  const other = makeTab("Sysmon2.evtx", SYSMON_H, [
    { EventID: "13", Channel: "Microsoft-Windows-Sysmon/Operational", datetime: "2026-03-15T10:02:00Z", Computer: "U42-TECH",
      TargetObject: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SomethingElse",
      Details: "C:\\Users\\Public\\other.exe", Image: "C:\\Windows\\System32\\reg.exe" },
  ]);
  const res = getMultiSourcePersistence([hiveTab(), other], {}, ctx);
  const runIncidents = res.incidents.filter((i) => /\\Run/i.test(i.artifact || ""));
  assert.equal(runIncidents.length, 2, "two distinct autoruns are two findings");
});

// ── behaviour, guards and reporting ────────────────────────────────────────

test("one tab is just the single-tab analysis", () => {
  const multi = getMultiSourcePersistence([systemTab()], { mode: "evtx" }, ctx);
  const single = getPersistenceAnalysis(systemTab().meta, { mode: "evtx" }, ctx);
  assert.equal(multi.items.length, single.items.length);
  assert.ok(!multi.multiSource, "no merge happened, so nothing should claim one did");
});

test("a tab that holds neither shape is skipped, loudly", () => {
  const junk = makeTab("notes.csv", ["Title", "Body"], [{ Title: "a", Body: "b" }]);
  const res = getMultiSourcePersistence([systemTab(), junk], {}, ctx);
  assert.ok(res.items.length > 0, "the usable tab must still be analyzed");
  assert.ok(res.warnings.some((w) => /notes\.csv/.test(w) && /skipped/i.test(w)));
  assert.equal(res.tabSummaries.find((t) => t.label === "notes.csv").skipped, true);
});

test("execution-evidence plugin tabs are named, not silently dropped", () => {
  const ua = makeTab("UserAssist.csv", ["ProgramName", "RunCounter", "LastExecuted", "HivePath"],
    [{ ProgramName: "C:\\Temp\\evil.exe", RunCounter: "3", LastExecuted: "2026-03-15 10:00:00", HivePath: "x\\NTUSER.DAT" }]);
  const res = getMultiSourcePersistence([systemTab(), ua], {}, ctx);
  assert.ok(res.warnings.some((w) => /UserAssist/.test(w)));
  assert.ok(res.items.length > 0);
});

test("no usable rows anywhere reports why", () => {
  const junk = makeTab("a.csv", ["Title"], [{ Title: "x" }]);
  const junk2 = makeTab("b.csv", ["Body"], [{ Body: "y" }]);
  const res = getMultiSourcePersistence([junk, junk2], {}, ctx);
  assert.match(res.error, /No persistence-relevant rows/i);
  assert.equal(res.items.length, 0);
});

test("the merged query pulls correlation events, not just rule events", () => {
  // 4688/4104/7036/1 are never reported — they exist to corroborate. If the per-tab query
  // filtered them out, merging would achieve nothing.
  for (const eid of ["7036", "7035", "1", "4688", "4104"]) {
    assert.ok(MERGED_EIDS.includes(eid), `${eid} must be pulled into the merged set`);
  }
  assert.ok(MERGED_EIDS.includes("7045"), "rule event ids must still be included");
});

test("tab shape detection identifies each source", () => {
  assert.equal(detectTabShape(systemTab().meta).mode, "evtx");
  assert.equal(detectTabShape(hiveTab().meta).mode, "registry");
  assert.equal(detectTabShape(makeTab("x", ["Title"], []).meta), null);
});

test("preview says what each tab contributes", () => {
  const prev = previewMultiSourcePersistence([systemTab(), securityTab(), psTab(), hiveTab()], {}, ctx);
  const by = Object.fromEntries(prev.tabs.map((t) => [t.label, t]));
  assert.equal(by["System.evtx"].mode, "evtx");
  assert.equal(by["SOFTWARE hive"].mode, "registry");
  // The reason to tick a tab: it is the only source of a correlation event.
  assert.deepEqual(by["Security.evtx"].correlationEids, ["4688"]);
  assert.deepEqual(by["PowerShell.evtx"].correlationEids, ["4104"]);
  assert.equal(by["System.evtx"].correlationEids.length, 0);
  assert.ok(prev.totalEvents >= 4);
});

test("merged stats report per-tab contribution and confidence spread", () => {
  const res = getMultiSourcePersistence([systemTab(), securityTab(), psTab(), hiveTab(), sysmonTab()], {}, ctx);
  assert.equal(res.stats.tabCount, 5);
  assert.equal(res.stats.perTabRows.length, 5);
  assert.ok(res.stats.byConfidence.confirmed >= 1, "the whole point is findings that reach 'confirmed'");
  assert.ok(res.stats.incidentCount <= res.stats.total, "incidents collapse items, never multiply them");
});
