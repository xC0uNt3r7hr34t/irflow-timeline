// Registry input normalization — the parsed-KAPE path.
//
// Registry evidence arrives in mutually incompatible shapes and the detection rules are
// written against exactly one of them. On a real RECmd batch export of a triage package:
//
//   rows with "Services" in KeyPath : 1485
//   Services rule matches           :    0
//
// ...because RECmd emits hive-relative paths ("ROOT\ControlSet001\Services\X") while the
// rule requires a literal \SYSTEM\ segment. The per-plugin CSVs were worse: no
// KeyPath/ValueName pair at all, so mode auto-detect returned null and the richest
// registry artifact in the package was simply unreadable.
//
// These tests cover canonicalization, plugin projection, host attribution and the
// registry false-positive pack.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getPersistenceAnalysis, previewPersistenceAnalysis } = require("../electron/analyzers/persistence");
const {
  canonicalizeKeyPath, hiveContext, deriveCollectionHost, hiveNameFor,
} = require("../electron/analyzers/persistence/registry-shapes");

// Same stub pattern as the other persistence suites: prepare().all() aliases
// "c<idx> as [alias]" out of the SELECT; WHERE/params are ignored.
function analyze(headers, rows, options = {}) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const byCN = rows.map((r, i) => {
    const o = { _rowid: i + 1 };
    headers.forEach((h) => { o[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return o;
  });
  const alias = (sql) => {
    const m = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return byCN.map((r) => {
      const o = { _rowid: r._rowid };
      for (const [, i, a] of m) o[a] = r[`c${i}`];
      return o;
    });
  };
  const db = {
    prepare: (sql) => ({
      get: () => (/COUNT\(\*\)/i.test(sql) ? { cnt: byCN.length } : null),
      all: () => (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql) ? alias(sql) : []),
    }),
  };
  return getPersistenceAnalysis({ db, headers, colMap, tabId: "reg" }, options, { applyStandardFilters() {} });
}

// ── 1.1 canonicalization ───────────────────────────────────────────────────

test("canonicalizeKeyPath resolves hive-relative paths through HiveType", () => {
  assert.equal(
    canonicalizeKeyPath("ROOT\\ControlSet001\\Services\\EvilSvc", { hiveType: "SYSTEM" }),
    "HKLM\\SYSTEM\\ControlSet001\\Services\\EvilSvc",
  );
  assert.equal(
    canonicalizeKeyPath("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", { hiveType: "NtUser" }),
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  );
  assert.equal(
    canonicalizeKeyPath("ROOT\\.txt\\shell\\open\\command", { hiveType: "UsrClass" }),
    "HKCU\\Software\\Classes\\.txt\\shell\\open\\command",
  );
});

test("canonicalizeKeyPath falls back to the hive file name when HiveType is absent", () => {
  assert.equal(
    canonicalizeKeyPath("ROOT\\ControlSet001\\Services\\X", { hivePath: "E:\\t\\C\\Windows\\System32\\config\\SYSTEM" }),
    "HKLM\\SYSTEM\\ControlSet001\\Services\\X",
  );
  assert.equal(
    canonicalizeKeyPath("Software\\Microsoft\\Windows\\CurrentVersion\\Run", { hivePath: "C:\\Users\\bob\\NTUSER.DAT" }),
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  );
  assert.equal(hiveNameFor({ hivePath: "X\\Amcache.hve" }), "AMCACHE");
});

test("canonicalizeKeyPath does not duplicate a hive name the path already carries", () => {
  assert.equal(
    canonicalizeKeyPath("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", { hiveType: "SOFTWARE" }),
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
  );
});

test("canonicalizeKeyPath normalizes already-rooted and NT object paths", () => {
  assert.equal(canonicalizeKeyPath("HKEY_LOCAL_MACHINE\\SOFTWARE\\X"), "HKLM\\SOFTWARE\\X");
  assert.equal(canonicalizeKeyPath("\\REGISTRY\\MACHINE\\SOFTWARE\\X"), "HKLM\\SOFTWARE\\X");
  assert.equal(canonicalizeKeyPath("\\REGISTRY\\USER\\S-1-5-21-1\\Software\\X"), "HKU\\S-1-5-21-1\\Software\\X");
  assert.equal(canonicalizeKeyPath("CMI-CreateHive{2A7FB991-7BBE-4F9D-B91E-7CB51D4737F5}\\Microsoft\\X", { hiveType: "SOFTWARE" }),
    "HKLM\\SOFTWARE\\Microsoft\\X");
  // An explicit root wins over a contradictory hive hint.
  assert.equal(canonicalizeKeyPath("HKLM\\SOFTWARE\\X", { hiveType: "NtUser" }), "HKLM\\SOFTWARE\\X");
});

test("canonicalizeKeyPath preserves slashes and spaces inside key names", () => {
  // Registry key names may legitimately contain "/" and spaces.
  assert.equal(
    canonicalizeKeyPath("ROOT\\ControlSet001\\Services\\TCP/IP NetBIOS Helper", { hiveType: "SYSTEM" }),
    "HKLM\\SYSTEM\\ControlSet001\\Services\\TCP/IP NetBIOS Helper",
  );
});

test("canonicalizeKeyPath leaves the path alone when the hive is unknowable", () => {
  assert.equal(canonicalizeKeyPath("ControlSet001\\Services\\X", {}), "ControlSet001\\Services\\X");
  assert.equal(canonicalizeKeyPath("", { hiveType: "SYSTEM" }), "");
});

test("hiveContext derives the owning user and scope", () => {
  assert.deepEqual(hiveContext("E:\\t\\HOST\\C\\Users\\victim\\NTUSER.DAT", "NtUser"), { user: "victim", hiveScope: "HKCU" });
  assert.deepEqual(hiveContext("E:\\t\\HOST\\C\\Windows\\System32\\config\\SYSTEM", "SYSTEM"), { user: "", hiveScope: "HKLM\\SYSTEM" });
});

// ── RECmd batch export end-to-end ──────────────────────────────────────────

const BATCH = ["HivePath", "HiveType", "KeyPath", "ValueName", "ValueData", "LastWriteTimestamp"];
const hp = (h) => `E:\\tout\\U42-TECH\\C\\Windows\\System32\\config\\${h}`;
const brow = (hive, KeyPath, ValueName, ValueData, ts = "2026-03-15 10:00:00") =>
  ({ HivePath: hp(hive), HiveType: hive, KeyPath, ValueName, ValueData, LastWriteTimestamp: ts });
const ntrow = (KeyPath, ValueName, ValueData, ts = "2026-03-15 10:00:00") =>
  ({ HivePath: "E:\\tout\\AZEROTH\\C\\Users\\jdoe\\NTUSER.DAT", HiveType: "NtUser", KeyPath, ValueName, ValueData, LastWriteTimestamp: ts });

test("RECmd batch: the Services rule fires on hive-relative key paths", () => {
  const res = analyze(BATCH, [
    brow("SYSTEM", "ROOT\\ControlSet001\\Services\\EvilSvc", "ImagePath", "C:\\Users\\Public\\beacon.exe"),
    brow("SOFTWARE", "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", "C:\\Temp\\evil.exe"),
    brow("SOFTWARE", "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Userinit", "C:\\Windows\\system32\\userinit.exe,evil.exe"),
  ]);
  assert.equal(res.error, null);
  const svc = res.items.find((i) => i.category === "Services");
  assert.ok(svc, "ROOT\\ControlSet001\\Services\\... must match the Services rule");
  assert.equal(svc.artifact, "HKLM\\SYSTEM\\ControlSet001\\Services\\EvilSvc");
  assert.equal(svc.details.keyPathRaw, "ROOT\\ControlSet001\\Services\\EvilSvc", "the raw path stays available");
  assert.ok(res.items.some((i) => i.category === "Run Keys"));
  assert.ok(res.items.some((i) => i.category === "Winlogon"));
});

// ── 1.3 host attribution ───────────────────────────────────────────────────

test("registry host comes from the SYSTEM hive's own ComputerName value", () => {
  const res = analyze(BATCH, [
    brow("SYSTEM", "ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "U42-TECH", "2018-09-15 08:00:00"),
    brow("SYSTEM", "ROOT\\ControlSet001\\Services\\EvilSvc", "ImagePath", "C:\\Users\\Public\\beacon.exe"),
  ]);
  assert.equal(res.stats.registryHost, "U42-TECH");
  assert.equal(res.stats.registryHostSource, "system-hive");
  assert.equal(res.stats.uniqueComputers, 1, "registry findings used to have no host at all");
  const svc = res.items.find((i) => i.category === "Services");
  assert.equal(svc.computer, "U42-TECH");
  assert.ok(!svc.details._hostInferred, "a hive-read host is not an inference");
});

test("registry host falls back to the KAPE collection path, flagged as inferred", () => {
  const res = analyze(BATCH, [brow("SYSTEM", "ROOT\\ControlSet001\\Services\\EvilSvc", "ImagePath", "C:\\Users\\Public\\beacon.exe")]);
  assert.equal(res.stats.registryHost, "U42-TECH");
  assert.equal(res.stats.registryHostSource, "collection-path");
  assert.equal(res.items[0].details._hostInferred, true);
});

test("collection-path host extraction rejects generic output folders", () => {
  assert.equal(deriveCollectionHost("E:\\tout\\WKSTA-7\\C\\Windows\\System32\\config\\SYSTEM"), "WKSTA-7");
  assert.equal(deriveCollectionHost("E:\\tout\\C\\Windows\\System32\\config\\SYSTEM"), "",
    "\"tout\" is the KAPE destination folder, not a machine");
  assert.equal(deriveCollectionHost("C:\\Windows\\System32\\config\\SYSTEM"), "",
    "a live-system path names no machine");
  assert.equal(deriveCollectionHost("\\\\fileserver\\share\\C\\Windows\\System32\\config\\SYSTEM"), "",
    "a UNC share name is not a machine name");
  assert.equal(deriveCollectionHost("E:\\tout\\HOST-9\\C%3A\\Windows\\System32\\config\\SYSTEM"), "HOST-9",
    "KAPE sometimes URL-escapes the drive letter");
  assert.equal(deriveCollectionHost(""), "");
});

test("an explicit computer column and a caller override outrank the heuristics", () => {
  const headers = [...BATCH, "ComputerName"];
  const withCol = analyze(headers, [{ ...brow("SYSTEM", "ROOT\\ControlSet001\\Services\\X", "ImagePath", "C:\\Temp\\a.exe"), ComputerName: "REAL-HOST" }]);
  assert.equal(withCol.stats.registryHost, "REAL-HOST");
  assert.equal(withCol.stats.registryHostSource, "column");

  const overridden = analyze(BATCH, [brow("SYSTEM", "ROOT\\ControlSet001\\Services\\X", "ImagePath", "C:\\Temp\\a.exe")], { computerName: "ANALYST-SET" });
  assert.equal(overridden.stats.registryHost, "ANALYST-SET");
  assert.equal(overridden.stats.registryHostSource, "user");
});

// ── 1.4 false-positive pack ────────────────────────────────────────────────

test("the default Startup shell-folder value is not a redirection", () => {
  const DEFAULT = "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
  const res = analyze(BATCH, [
    ntrow("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", "Startup", DEFAULT, "2018-09-15 08:00:00"),
  ]);
  assert.equal(res.items.length, 0, "the shipped Startup path dominated the top of triage as a fake redirection");

  const redirected = analyze(BATCH, [
    ntrow("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", "Startup", "C:\\Users\\Public\\Evil"),
  ]);
  assert.equal(redirected.items.length, 1, "an actual redirection must still fire");
  assert.equal(redirected.items[0].category, "Startup Folder");
});

test("a Defender Exclusions key with no value is not an exclusion", () => {
  const empty = analyze(BATCH, [brow("SOFTWARE", "ROOT\\Microsoft\\Windows Defender\\Exclusions\\Paths", "", "")]);
  assert.equal(empty.items.length, 0, "the key existing is not evidence an exclusion was set");

  const real = analyze(BATCH, [brow("SOFTWARE", "ROOT\\Microsoft\\Windows Defender\\Exclusions\\Paths", "C:\\Users\\Public", "0")]);
  assert.equal(real.items.length, 1, "the excluded path is the VALUE NAME — that row is real evidence");
  assert.equal(real.items[0].category, "Defender Tampering");
});

test("Defender Disable* = 0 means protection is on", () => {
  const off = analyze(BATCH, [brow("SOFTWARE", "ROOT\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", "0")]);
  assert.equal(off.items.length, 0);
  const on = analyze(BATCH, [brow("SOFTWARE", "ROOT\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", "1")]);
  assert.equal(on.items.length, 1, "actually disabling real-time protection must fire");
});

test("a default file-association verb is not a hijack", () => {
  const dflt = analyze(BATCH, [ntrow("ROOT\\Software\\Classes\\exefile\\shell\\open\\command", "", '"%1" %*')]);
  assert.equal(dflt.items.length, 0, '`"%1" %*` names no image — nothing is hijacked');

  const hijacked = analyze(BATCH, [ntrow("ROOT\\Software\\Classes\\exefile\\shell\\open\\command", "", 'C:\\Users\\Public\\evil.exe "%1" %*')]);
  assert.equal(hijacked.items.length, 1);
  assert.equal(hijacked.items[0].category, "File Association");
});

test("built-in TaskCache\\Tree inventory rows are dropped, non-Microsoft ones kept", () => {
  const builtIn = analyze(BATCH, [
    brow("SOFTWARE", "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "Id", "{2f0a1b3c-0000-0000-0000-000000000000}"),
  ]);
  assert.equal(builtIn.items.length, 0, "an Id with no action blob on a built-in task says nothing");

  const attacker = analyze(BATCH, [
    brow("SOFTWARE", "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\mcollective_facts_yaml_refresh", "Id", "{2f0a1b3c-0000-0000-0000-000000000000}"),
  ]);
  assert.equal(attacker.items.length, 1, "a non-Microsoft task at the Tasks root is exactly what to look at");
});

// ── 1.2 RECmd per-plugin CSVs ──────────────────────────────────────────────

const SVC_PLUGIN = ["HivePath", "HiveType", "ControlSet", "Name", "DisplayName", "StartMode", "ServiceType", "ImagePath", "ServiceDll", "ObjectName", "LastWriteTimestamp"];
const svc = (Name, ImagePath, opts = {}) => ({
  HivePath: hp("SYSTEM"), HiveType: "SYSTEM", ControlSet: "1", Name, DisplayName: opts.display || Name,
  StartMode: opts.start || "Auto", ServiceType: "Win32OwnProcess", ImagePath, ServiceDll: opts.dll || "",
  ObjectName: "LocalSystem", LastWriteTimestamp: "2026-03-15 10:00:00",
});
const CLEAN_INVENTORY = [
  svc("Dnscache", "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p", { dll: "%SystemRoot%\\System32\\dnsrslvr.dll" }),
  svc("Tcpip", "System32\\drivers\\tcpip.sys"),
  svc("afd", "\\SystemRoot\\System32\\drivers\\afd.sys"),
  svc("WSearch", "%SystemRoot%\\system32\\SearchIndexer.exe /Embedding"),
  svc("Spooler", "C:\\Windows\\System32\\spoolsv.exe"),
  svc("gupdate", '"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /svc'),
];

test("a Services plugin CSV is ingestible at all", () => {
  const res = analyze(SVC_PLUGIN, CLEAN_INVENTORY);
  assert.equal(res.error, null, 'this used to fail mode detection with "Cannot detect data type"');
  assert.equal(res.stats.registryPlugin?.id, "services");
});

test("a clean service inventory produces no findings but reports what it dropped", () => {
  const res = analyze(SVC_PLUGIN, CLEAN_INVENTORY);
  assert.equal(res.items.length, 0, "300 signed system services must not all be 'high' findings");
  assert.equal(res.stats.registryInventorySuppressed, 7, "coverage reduction is reported, not silent");
});

test("the Services plugin surfaces the intrusion inside the inventory", () => {
  const res = analyze(SVC_PLUGIN, [
    ...CLEAN_INVENTORY,
    svc("PSEXESVC", "C:\\Windows\\PSEXESVC.exe"),
    svc("BreadSvc", "powershell -File C:\\Users\\Public\\breadService.ps1"),
    svc("UpdaterDll", "%SystemRoot%\\system32\\svchost.exe -k netsvcs", { dll: "C:\\Users\\Public\\evil.dll" }),
  ]);
  const byName = Object.fromEntries(res.items.map((i) => [i.artifact.split("\\").pop(), i]));

  // PsExec sits directly in C:\Windows and is otherwise unremarkable — it is caught on
  // the service NAME, which in registry mode has to be resolved out of the key path.
  assert.ok(byName.PSEXESVC, "PSEXESVC must survive the inventory gate");
  assert.equal(byName.PSEXESVC.severity, "critical");
  assert.ok((byName.PSEXESVC.suspiciousReasons || []).some((r) => /PsExec/i.test(r)));

  assert.ok(byName.BreadSvc, "a LOLBin ImagePath must survive");
  assert.ok(byName.BreadSvc.riskScore >= 9);

  // ServiceDll is projected onto the Parameters subkey, where the rule expects it.
  assert.ok(byName.Parameters, "a user-writable ServiceDll must survive");
  assert.match(byName.Parameters.artifact, /\\Services\\UpdaterDll\\Parameters$/);
  assert.equal(byName.Parameters.details.valueName, "ServiceDll");
});

test("a known AV service in the inventory is recognized, not ranked as an intrusion", () => {
  const res = analyze(SVC_PLUGIN, [
    svc("CSFalconService", "C:\\Program Files\\CrowdStrike\\CSFalconService.exe"),
    svc("csagent", "C:\\Windows\\System32\\drivers\\CrowdStrike\\csagent.sys"),
  ]);
  for (const item of res.items) {
    assert.equal(item.severity, "low", `${item.artifact} should be recognized as an AV/EDR component`);
  }
});

test("execution-evidence plugins report what they are instead of dead-ending", () => {
  const res = analyze(
    ["ProgramName", "RunCounter", "LastExecuted", "HivePath"],
    [{ ProgramName: "C:\\Temp\\evil.exe", RunCounter: "3", LastExecuted: "2026-03-15 10:00:00", HivePath: "x\\NTUSER.DAT" }],
  );
  assert.match(res.error, /UserAssist/, "the analyst should be told which artifact this is");
  assert.match(res.error, /batch output|Services/, "...and what to load instead");
  assert.equal(res.items.length, 0);
});

test("plugin detection never claims an ordinary KeyPath/ValueName export", () => {
  const res = analyze(BATCH, [brow("SYSTEM", "ROOT\\ControlSet001\\Services\\X", "ImagePath", "C:\\Temp\\a.exe")]);
  assert.equal(res.stats.registryPlugin, null);
});

test("preview reports the plugin shape and its row count", () => {
  const headers = SVC_PLUGIN;
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const db = { prepare: () => ({ get: () => ({ cnt: CLEAN_INVENTORY.length, total: CLEAN_INVENTORY.length }), all: () => [] }) };
  const res = previewPersistenceAnalysis({ db, headers, colMap }, { mode: "auto" }, { applyStandardFilters() {} });
  assert.equal(res.detectedMode, "registry");
  assert.equal(res.registryPlugin.id, "services");
  assert.equal(res.trackedEvents, CLEAN_INVENTORY.length);
});
