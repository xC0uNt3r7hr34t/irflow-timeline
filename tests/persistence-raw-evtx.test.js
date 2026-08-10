// Raw-EVTX persistence coverage (Tier-3 false-negative fix).
//
// For the app's own raw .evtx parser, each EventData field is a separate column. The
// persistence rule engine matches against buildEvtxHaystack(row); previously raw-EVTX
// EventData fields (Signed, ImageLoaded, ObjectDN, MemberName, ObjectName, …) were never
// selected into the row, so payloadFilter-gated rules (Sysmon 6/7, AD 5136/5137/5141,
// Security 4657) silently never fired. These tests lock in that they now do.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getPersistenceAnalysis } = require("../electron/analyzers/persistence");

// Stub db: prepare().all() aliases "c<idx> as [alias]" from the SELECT into row props
// (same pattern as persistence.test.js); WHERE/params are ignored.
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
  const meta = { db, headers, colMap, tabId: "persist-raw-evtx" };
  const ctx = { applyStandardFilters() {}, ensureIndex() {} };
  return { meta, ctx };
}

function analyzeRaw(headers, rows) {
  const { meta, ctx } = makeStub(headers, rows);
  return getPersistenceAnalysis(meta, { mode: "evtx" }, ctx);
}

const COMMON = { Channel: "", datetime: "2026-03-15T10:00:00Z", Computer: "HOST-A" };
const row = (extra) => ({ ...COMMON, ...extra });

test("raw EVTX: Sysmon EID 6 unsigned driver (BYOVD) now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ImageLoaded", "Signed", "SignatureStatus", "Signer"];
  const result = analyzeRaw(headers, [row({
    EventID: "6", Channel: "Microsoft-Windows-Sysmon/Operational",
    ImageLoaded: "C:\\Windows\\Temp\\evil.sys", Signed: "false", SignatureStatus: "Unavailable", Signer: "",
  })]);
  const item = result.items.find((i) => i.name === "Suspicious Driver Loaded");
  assert.ok(item, "EID 6 unsigned-driver rule must fire on raw EVTX");
  assert.equal(item.category, "Driver Loading");
  assert.equal(item.severity, "critical");
  assert.match(item.details.imageLoaded || "", /evil\.sys/);
  assert.equal(item.details.signed, "false");
});

test("raw EVTX: Sysmon EID 6 signed driver does NOT fire (negative control)", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ImageLoaded", "Signed", "SignatureStatus", "Signer"];
  const result = analyzeRaw(headers, [row({
    EventID: "6", Channel: "Microsoft-Windows-Sysmon/Operational",
    ImageLoaded: "C:\\Windows\\System32\\drivers\\good.sys", Signed: "true", SignatureStatus: "Valid", Signer: "Microsoft Windows",
  })]);
  assert.equal(result.items.find((i) => i.name === "Suspicious Driver Loaded"), undefined,
    "a validly-signed driver must not be flagged");
});

test("raw EVTX: Sysmon EID 7 unsigned DLL load now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ImageLoaded", "Signed", "SignatureStatus", "Image"];
  const result = analyzeRaw(headers, [row({
    EventID: "7", Channel: "Microsoft-Windows-Sysmon/Operational",
    ImageLoaded: "C:\\Users\\v\\AppData\\Local\\Temp\\evil.dll", Signed: "false", SignatureStatus: "Unavailable",
    Image: "C:\\Windows\\System32\\svchost.exe",
  })]);
  const item = result.items.find((i) => i.name === "Unsigned DLL Loaded");
  assert.ok(item, "EID 7 unsigned-DLL rule must fire on raw EVTX");
  assert.match(item.details.imageLoaded || "", /evil\.dll/);
});

test("raw EVTX: Security 5136 AD object modification (SPN / shadow creds) now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ObjectDN", "ObjectClass", "AttributeLDAPDisplayName", "AttributeValue", "OperationType", "SubjectUserName"];
  const result = analyzeRaw(headers, [row({
    EventID: "5136", Channel: "Security",
    ObjectDN: "CN=svc-sql,CN=Users,DC=corp,DC=local", ObjectClass: "user",
    AttributeLDAPDisplayName: "servicePrincipalName", AttributeValue: "HTTP/evil.corp.local",
    OperationType: "%%14674", SubjectUserName: "attacker",
  })]);
  const item = result.items.find((i) => i.name === "AD Object Modified");
  assert.ok(item, "5136 AD persistence rule must fire on raw EVTX");
  assert.equal(item.category, "Domain Persistence");
  assert.match(item.details.attributeName || "", /servicePrincipalName/);
  assert.match(item.details.objectDN || "", /svc-sql/);
});

test("raw EVTX: Security 4657 registry Run-key modification now fires", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ObjectName", "ObjectValueName", "NewValue", "OldValue", "ProcessName", "SubjectUserName"];
  const result = analyzeRaw(headers, [row({
    EventID: "4657", Channel: "Security",
    ObjectName: "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ObjectValueName: "Updater", NewValue: "C:\\Temp\\evil.exe", OldValue: "(NONE)",
    ProcessName: "C:\\Windows\\System32\\reg.exe", SubjectUserName: "attacker",
  })]);
  const item = result.items.find((i) => i.name === "Registry Value Modified (4657)");
  assert.ok(item, "4657 registry-autorun rule must fire on raw EVTX");
  assert.match(item.details.targetObject || "", /\\Run/);
  assert.match(item.details.newValue || "", /evil\.exe/);
});

test("raw EVTX: Security 4728 group membership extracts MemberName", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "TargetUserName", "MemberName", "SubjectUserName"];
  const result = analyzeRaw(headers, [row({
    EventID: "4728", Channel: "Security",
    TargetUserName: "Domain Admins", MemberName: "CN=attacker,CN=Users,DC=corp,DC=local", SubjectUserName: "admin",
  })]);
  const item = result.items.find((i) => i.name === "Member Added to Global Security Group");
  assert.ok(item, "4728 group-membership rule must fire on raw EVTX");
  assert.match(item.details.memberName || "", /attacker/);
  assert.match(item.details.groupName || "", /Domain Admins/);
});

// ── Raw-EVTX Task Scheduler + Service Control Manager ──────────────────────
// Regression pack for the KAPE raw-triage audit. On U42-TECH's real
// TaskScheduler%4Operational.evtx the analyzer produced 7,277 findings with an
// EMPTY artifact and command: TaskName/Path/ActionName/param1..4 were in neither
// RAW_EVTX_HAYSTACK_FIELDS nor the Chainsaw alias blob, so P("Task")/P("TaskName")/
// P("Name") matched nothing. An empty artifact also cannot match
// LEGIT_WINDOWS_TASK_PREFIX (^\Microsoft\Windows\), so 3,437 benign taskhostw
// executions could not be suppressed and collapsed into one x3437 incident.

test("raw EVTX: TaskScheduler 200 names the task and its action", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "TaskName", "ActionName", "TaskInstanceId"];
  const result = analyzeRaw(headers, [row({
    EventID: "200", Channel: "Microsoft-Windows-TaskScheduler/Operational",
    TaskName: "\\Contoso\\UpdaterTask", ActionName: "C:\\Users\\Public\\beacon.exe",
    TaskInstanceId: "{2c1b8a1e-0000-0000-0000-000000000000}",
  })]);
  const item = result.items.find((i) => i.name === "Task Action Started");
  assert.ok(item, "EID 200 rule must fire on raw EVTX");
  assert.equal(item.details.taskName, "\\Contoso\\UpdaterTask", "TaskName must reach the extractor");
  assert.equal(item.details.executable, "C:\\Users\\Public\\beacon.exe", "ActionName must populate the executable");
  assert.equal(item.artifact, "\\Contoso\\UpdaterTask", "the finding must not be anonymous");
});

test("raw EVTX: TaskScheduler 129 names the task and the launched image", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "TaskName", "Path", "ProcessID"];
  const result = analyzeRaw(headers, [row({
    EventID: "129", Channel: "Microsoft-Windows-TaskScheduler/Operational",
    TaskName: "\\Contoso\\UpdaterTask", Path: "C:\\Users\\Public\\beacon.exe", ProcessID: "4242",
  })]);
  const item = result.items.find((i) => i.name === "Task Process Created");
  assert.ok(item, "EID 129 rule must fire on raw EVTX");
  assert.equal(item.details.taskName, "\\Contoso\\UpdaterTask");
  assert.equal(item.details.executable, "C:\\Users\\Public\\beacon.exe");
  assert.equal(item.details.processId, "4242");
});

test("raw EVTX: built-in Windows tasks are suppressed now that TaskName resolves", () => {
  // \Microsoft\Windows\... via taskhostw.exe is the single loudest benign pattern in a
  // real TaskScheduler log — 3,437 of them in the U42-TECH package alone. With an empty
  // artifact none could match LEGIT_WINDOWS_TASK_PREFIX, so every one surfaced at high
  // severity and they collapsed into a single x3437 incident that could hide a real
  // malicious task inside it.
  const headers = ["EventID", "Channel", "datetime", "Computer", "TaskName", "Path"];
  const benign = analyzeRaw(headers, [row({
    EventID: "129", Channel: "Microsoft-Windows-TaskScheduler/Operational",
    TaskName: "\\Microsoft\\Windows\\Input\\LocalUserSyncDataAvailable",
    Path: "C:\\Windows\\system32\\taskhostw.exe",
  })]);
  const evil = analyzeRaw(headers, [row({
    EventID: "129", Channel: "Microsoft-Windows-TaskScheduler/Operational",
    TaskName: "\\mcollective_facts_yaml_refresh", Path: "C:\\Users\\Public\\beacon.exe",
  })]);
  assert.equal(benign.items.length, 0, "a built-in Windows task running taskhostw.exe must be allowlisted away");
  const eItem = evil.items.find((i) => i.name === "Task Process Created");
  assert.ok(eItem, "a non-Microsoft task at the Tasks root must still surface");
  assert.equal(eItem.artifact, "\\mcollective_facts_yaml_refresh");
  assert.equal(eItem.command, "C:\\Users\\Public\\beacon.exe");
  assert.ok((eItem.riskScore || 0) >= 8, `expected a high risk score, got ${eItem.riskScore}`);
});

test("raw EVTX: 7040 binds serviceName to param4, not the display name in param1", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "param1", "param2", "param3", "param4"];
  const result = analyzeRaw(headers, [row({
    EventID: "7040", Channel: "System",
    param1: "Windows Search", param2: "auto start", param3: "demand start", param4: "WSearch",
  })]);
  const item = result.items.find((i) => i.name === "Service StartType Changed");
  assert.ok(item, "7040 rule must fire on raw EVTX");
  assert.equal(item.details.serviceName, "WSearch", "param4 is the service name 7045/7036 correlation keys on");
  assert.equal(item.details.displayName, "Windows Search", "param1 is kept as the display name");
  assert.equal(item.details.oldStartType, "auto start");
  assert.equal(item.details.newStartType, "demand start");
  assert.equal(item.artifact, "WSearch", "the finding must not be anonymous");
});

test("EvtxECmd 7040 without param4 still falls back to param1", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "PayloadData1"];
  const result = analyzeRaw(headers, [row({
    EventID: "7040", Channel: "System",
    PayloadData1: "param1: ScoreSvc | param2: demand start | param3: auto start",
  })]);
  const item = result.items.find((i) => i.name === "Service StartType Changed");
  assert.ok(item);
  assert.equal(item.details.serviceName, "ScoreSvc");
});

test("raw EVTX: 7045 correlates with its own 7036 start across FQDN/short hostnames", () => {
  // Live in the U42-TECH triage package: PSEXESVC's install is logged on "U42-TECH"
  // while the service-start event carries "U42-TECH.sevenkingdoms.local". An exact
  // host compare treated them as two machines and dropped the corroboration.
  const headers = ["EventID", "Channel", "datetime", "Computer", "ServiceName", "ImagePath", "StartType", "AccountName", "param1", "param2"];
  const rows = [
    { ...COMMON, EventID: "7045", Channel: "System", Computer: "U42-TECH",
      ServiceName: "PSEXESVC", ImagePath: "C:\\Windows\\PSEXESVC.exe", StartType: "demand start", AccountName: "LocalSystem",
      datetime: "2026-03-15T10:00:00Z" },
    { ...COMMON, EventID: "7036", Channel: "System", Computer: "U42-TECH.sevenkingdoms.local",
      param1: "PSEXESVC", param2: "running", datetime: "2026-03-15T10:00:30Z" },
  ];
  const result = analyzeRaw(headers, rows);
  const item = result.items.find((i) => i.name === "Service Installed");
  assert.ok(item, "7045 rule must fire on raw EVTX");
  assert.equal(item.details._serviceStarted, true, "the 7036 start must corroborate the install");
  assert.equal(item.confidence, "confirmed");
  assert.equal(result.stats.uniqueComputers, 1, "short name and FQDN are one host");
});

test("a computer-account trailing $ does not fork the host key", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ServiceName", "ImagePath", "param1", "param2"];
  const rows = [
    { ...COMMON, EventID: "7045", Channel: "System", Computer: "WKSTA-01$",
      ServiceName: "EvilSvc", ImagePath: "C:\\Temp\\evil.exe", datetime: "2026-03-15T10:00:00Z" },
    { ...COMMON, EventID: "7036", Channel: "System", Computer: "wksta-01.corp.local",
      param1: "EvilSvc", param2: "running", datetime: "2026-03-15T10:01:00Z" },
  ];
  const result = analyzeRaw(headers, rows);
  const item = result.items.find((i) => i.name === "Service Installed");
  assert.ok(item);
  assert.equal(item.details._serviceStarted, true);
});

test("distinct hosts still do NOT cross-correlate", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "ServiceName", "ImagePath", "param1", "param2"];
  const rows = [
    { ...COMMON, EventID: "7045", Channel: "System", Computer: "HOST-A.corp.local",
      ServiceName: "EvilSvc", ImagePath: "C:\\Temp\\evil.exe", datetime: "2026-03-15T10:00:00Z" },
    { ...COMMON, EventID: "7036", Channel: "System", Computer: "HOST-B.corp.local",
      param1: "EvilSvc", param2: "running", datetime: "2026-03-15T10:01:00Z" },
  ];
  const result = analyzeRaw(headers, rows);
  const item = result.items.find((i) => i.name === "Service Installed");
  assert.ok(item);
  assert.ok(!item.details._serviceStarted, "a start on a different host must not corroborate");
  assert.equal(result.stats.uniqueComputers, 1, "only the 7045 row becomes an item");
});

test("raw EVTX: WMI-Activity 5861 subscription resolves its consumer and query", () => {
  const headers = ["EventID", "Channel", "datetime", "Computer", "Operation", "Consumer", "Query", "Namespace"];
  const result = analyzeRaw(headers, [row({
    EventID: "5861", Channel: "Microsoft-Windows-WMI-Activity/Operational",
    Operation: "ESS started a consumer",
    Consumer: 'instance of CommandLineEventConsumer { Name = "EvilConsumer"; CommandLineTemplate = "powershell.exe -enc SQBFAFgA"; }',
    Query: "SELECT * FROM __InstanceModificationEvent",
    Namespace: "root\\subscription",
  })]);
  const item = result.items.find((i) => i.name === "WMI Event Subscription");
  assert.ok(item, "5861 rule must fire on raw EVTX");
  assert.equal(item.details._wmiName, "EvilConsumer");
  assert.match(item.details._wmiCommand || "", /powershell\.exe/);
});
