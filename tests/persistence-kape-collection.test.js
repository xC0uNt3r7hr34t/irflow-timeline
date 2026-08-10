// Folder-level KAPE ingestion.
//
// The analyzer worked on one imported file at a time; a KAPE package is a folder of
// hundreds of artifacts. The most valuable one was entirely unreachable: the ~200
// scheduled-task DEFINITIONS under Windows\System32\Tasks. The analyzer inferred
// Hidden/RunLevel/ComHandler/triggers by scraping fragments out of event payloads (hence
// `_taskXmlPartial`), and could only ever see tasks that FIRED inside the log window — a
// task registered for persistence and waiting on its trigger left no event at all.
//
// Fixtures are written to a temp directory in the layout KAPE actually produces
// (<root>\<Drive>\Windows\System32\Tasks\...), including UTF-16LE encoding.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { parseTaskXml, decodeTaskXml, taskNameFromPath } = require("../electron/analyzers/persistence/task-xml");
const { scanCollection, classifyHive, classifyModuleCsv, deriveCollectionName } = require("../electron/analyzers/persistence/kape-collection");
const { analyzeCollection, parseCsv } = require("../electron/analyzers/persistence/collection-analysis");

// ── fixture helpers ────────────────────────────────────────────────────────

const TASK_XML = ({ uri, command = "", args = "", hidden = false, runLevel = "LeastPrivilege", com = "", triggers = ["<CalendarTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary></CalendarTrigger>"], author = "" }) => `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-03-15T10:00:00</Date>
    <Author>${author}</Author>
    <URI>${uri}</URI>
  </RegistrationInfo>
  <Triggers>${triggers.join("")}</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>${runLevel}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>${hidden ? "true" : "false"}</Hidden>
  </Settings>
  <Actions Context="Author">
${com ? `    <ComHandler><ClassId>${com}</ClassId></ComHandler>` : `    <Exec><Command>${command}</Command>${args ? `<Arguments>${args}</Arguments>` : ""}</Exec>`}
  </Actions>
</Task>`;

// Windows writes task definitions UTF-16LE with a BOM; KAPE copies them byte-for-byte.
const utf16 = (s) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(s, "utf16le")]);

function makeCollection(spec = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kape-fixture-"));
  const write = (rel, buf) => {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, buf);
    return full;
  };
  for (const [rel, buf] of Object.entries(spec.files || {})) write(rel, buf);
  return { root, write, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

const TASKS = "C/Windows/System32/Tasks";
const CONFIG = "C/Windows/System32/config";

// ── task XML parsing ───────────────────────────────────────────────────────

test("a UTF-16LE task definition decodes and parses", () => {
  const xml = TASK_XML({ uri: "\\EvilTask", command: "powershell.exe", args: "-enc SQBFAFgA", hidden: true, runLevel: "HighestAvailable" });
  const task = parseTaskXml(utf16(xml), { taskName: "\\EvilTask" });
  assert.ok(task);
  assert.equal(task.taskName, "\\EvilTask");
  assert.equal(task.command, "powershell.exe");
  assert.equal(task.arguments, "-enc SQBFAFgA");
  assert.equal(task.hidden, true, "Hidden is READ here, not inferred from event text");
  assert.equal(task.elevated, true);
  assert.equal(task.runLevel, "HighestAvailable");
  assert.equal(task.principal, "S-1-5-18");
  assert.deepEqual(task.triggers, ["calendar"]);
  assert.equal(task.enabled, true);
});

test("UTF-8, UTF-16BE and BOM-less input all decode", () => {
  const xml = TASK_XML({ uri: "\\T", command: "a.exe" });
  assert.match(decodeTaskXml(Buffer.from(xml, "utf8")), /<Task/);
  assert.match(decodeTaskXml(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(xml, "utf8")])), /<Task/);
  assert.match(decodeTaskXml(Buffer.from(xml, "utf16le")), /<Task/, "no BOM, UTF-16LE");
  const be = Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(xml, "utf16le").swap16()]);
  assert.match(decodeTaskXml(be), /<Task/, "UTF-16BE");
});

test("a COM-handler action is identified and carries its CLSID", () => {
  const task = parseTaskXml(utf16(TASK_XML({ uri: "\\ComTask", com: "{8E7C2AFB-72B9-415C-9AC2-5037693309B7}" })), { taskName: "\\ComTask" });
  assert.equal(task.hasComHandler, true);
  assert.deepEqual(task.comHandlers, ["{8E7C2AFB-72B9-415C-9AC2-5037693309B7}"]);
  assert.equal(task.command, "", "a COM handler has no image path — that is the point of using one");
});

test("every trigger kind the scorer understands is recognized", () => {
  const task = parseTaskXml(utf16(TASK_XML({
    uri: "\\Multi", command: "a.exe",
    triggers: ["<BootTrigger/>", "<LogonTrigger/>", "<RegistrationTrigger/>", "<IdleTrigger/>"],
  })), { taskName: "\\Multi" });
  assert.deepEqual(task.triggers.sort(), ["boot", "idle", "logon", "registration"]);
});

test("XML entities are unescaped and a longer tag is not mistaken for a shorter one", () => {
  const xml = `<?xml version="1.0"?><Task><Actions><Exec>` +
    `<Command>C:\\a &amp; b\\x.exe</Command><CommandLine>NOT THIS</CommandLine>` +
    `</Exec></Actions></Task>`;
  const task = parseTaskXml(Buffer.from(xml, "utf8"), { taskName: "\\T" });
  assert.equal(task.command, "C:\\a & b\\x.exe");
});

test("the task path comes from the file's location under Tasks\\", () => {
  assert.equal(taskNameFromPath("C/Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag"),
    "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag");
  assert.equal(taskNameFromPath("F\\Windows\\System32\\Tasks\\EvilTask"), "\\EvilTask");
  assert.equal(taskNameFromPath("/some/other/file"), "");
});

test("a non-task file is rejected rather than half-parsed", () => {
  assert.equal(parseTaskXml(Buffer.from("just some text", "utf8")), null);
  assert.equal(parseTaskXml(Buffer.alloc(0)), null);
});

// ── collection scanning ────────────────────────────────────────────────────

test("a raw triage layout is classified and bucketed", () => {
  const c = makeCollection({ files: {
    [`${TASKS}/EvilTask`]: utf16(TASK_XML({ uri: "\\EvilTask", command: "C:\\Users\\Public\\evil.exe" })),
    [`${TASKS}/Microsoft/Windows/Defrag/ScheduledDefrag`]: utf16(TASK_XML({ uri: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", command: "%windir%\\system32\\defrag.exe" })),
    [`${CONFIG}/SYSTEM`]: Buffer.from("regf-ish"),
    [`${CONFIG}/SOFTWARE`]: Buffer.from("regf-ish"),
    [`${CONFIG}/SYSTEM.LOG1`]: Buffer.from("transaction log"),
    "C/Users/victim/NTUSER.DAT": Buffer.from("regf-ish"),
    "C/Windows/System32/winevt/Logs/System.evtx": Buffer.from("ElfFile"),
    "2026-03-03T05_40_38_CopyLog.csv": Buffer.from("CopiedTimestamp,SourceFile\n"),
  } });
  try {
    const scan = scanCollection(c.root);
    assert.equal(scan.error, null);
    assert.equal(scan.layout, "raw");
    assert.equal(scan.artifacts.taskXml.length, 2);
    assert.equal(scan.artifacts.evtx.length, 1);
    assert.equal(scan.artifacts.hives.length, 3, "SYSTEM, SOFTWARE and NTUSER.DAT — not the .LOG1 sidecar");
    assert.equal(scan.artifacts.moduleCsv.length, 0, "KAPE's own run log is not evidence");
    const user = scan.artifacts.hives.find((h) => h.hive === "NTUSER");
    assert.equal(user.user, "victim", "an NTUSER hive names the user it belongs to");
  } finally { c.cleanup(); }
});

test("hive classification rejects sidecars and bare same-named folders", () => {
  assert.equal(classifyHive("/x/config/SYSTEM", "C/Windows/System32/config/SYSTEM").hive, "SYSTEM");
  assert.equal(classifyHive("/x/config/SYSTEM.LOG2", "C/Windows/System32/config/SYSTEM.LOG2"), null);
  assert.equal(classifyHive("/x/SOFTWARE", "SomeFolder/SOFTWARE"), null, "only meaningful under config\\");
  assert.equal(classifyHive("/x/UsrClass.dat", "C/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat").hive, "USRCLASS");
});

test("the scan refuses to follow a symlink out of the selected folder", { skip: process.platform === "win32" ? "symlinks need privilege on Windows" : false }, () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "kape-outside-"));
  fs.mkdirSync(path.join(outside, "Windows", "System32", "Tasks"), { recursive: true });
  fs.writeFileSync(path.join(outside, "Windows", "System32", "Tasks", "Escaped"), utf16(TASK_XML({ uri: "\\Escaped", command: "x.exe" })));
  const c = makeCollection({ files: { [`${TASKS}/Local`]: utf16(TASK_XML({ uri: "\\Local", command: "y.exe" })) } });
  try {
    fs.symlinkSync(outside, path.join(c.root, "C", "escape"));
    const scan = scanCollection(c.root);
    assert.equal(scan.artifacts.taskXml.length, 1, "only the task inside the chosen folder");
    assert.equal(scan.artifacts.taskXml[0].relPath.replace(/\\/g, "/"), `${TASKS}/Local`);
    assert.ok(scan.warnings.some((w) => /outside the selected folder/i.test(w)), "the refusal must be reported");
  } finally { c.cleanup(); fs.rmSync(outside, { recursive: true, force: true }); }
});

test("host name is derived from the collection folder, never from KAPE's ConsoleLog", () => {
  // KAPE's ConsoleLog "Machine name:" is the machine that RAN KAPE. On a mounted-image
  // collection that is the examiner's own workstation.
  assert.deepEqual(deriveCollectionName("/e/U42-TECH-TOut", []), { host: "U42-TECH", source: "collection-folder" });
  assert.deepEqual(deriveCollectionName("/e/GFUA-DC01_M_Out", []), { host: "GFUA-DC01", source: "collection-folder" });
  // "<Host>/T_Out" — the marker is the folder itself, so the host is its parent.
  assert.deepEqual(deriveCollectionName("/e/Azeroth-File/T_Out", []), { host: "Azeroth", source: "collection-folder" });
});

test("module-output CSVs are classified by header, and plugin CSVs by the analyzer's own detector", () => {
  const c = makeCollection({ files: {
    "Registry/batch.csv": Buffer.from("HivePath,HiveType,KeyPath,ValueName,ValueData,LastWriteTimestamp\n"),
    "Registry/20260305152349_Services__C_Windows_System32_config_SYSTEM.csv":
      Buffer.from("Name,BatchKeyPath,Description,BatchValueName,DisplayName,StartMode,ServiceType,NameKeyLastWrite,ParametersKeyLastWrite,Group,ImagePath,ServiceDLL,RequiredPrivileges\n"),
    "EventLogs/evtxecmd.csv": Buffer.from("RecordNumber,EventRecordId,TimeCreated,EventId,MapDescription,PayloadData1\n"),
  } });
  try {
    const scan = scanCollection(c.root);
    assert.equal(scan.layout, "module");
    const byKind = Object.fromEntries(scan.artifacts.moduleCsv.map((x) => [x.plugin || x.kind, x]));
    assert.ok(byKind["recmd-batch"]);
    assert.ok(byKind.evtxecmd);
    assert.equal(byKind.services.projects, true, "the Services plugin is projectable into registry rows");
  } finally { c.cleanup(); }
});

test("classifyModuleCsv identifies a Hayabusa export", () => {
  const c = makeCollection({ files: { "h.csv": Buffer.from("Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details\n") } });
  try {
    assert.equal(classifyModuleCsv(path.join(c.root, "h.csv")).kind, "hayabusa");
  } finally { c.cleanup(); }
});

test("a folder with nothing recognizable says so", () => {
  const c = makeCollection({ files: { "readme.txt": Buffer.from("hello") } });
  try {
    const scan = scanCollection(c.root);
    assert.equal(scan.layout, null);
    assert.ok(scan.warnings.some((w) => /No EVTX, registry hives/i.test(w)));
  } finally { c.cleanup(); }
});

test("a path that is not a directory is rejected", () => {
  const c = makeCollection({ files: { "f.txt": Buffer.from("x") } });
  try {
    const scan = scanCollection(path.join(c.root, "f.txt"));
    assert.match(scan.error, /Not a folder/i);
  } finally { c.cleanup(); }
});

// ── end-to-end collection analysis ─────────────────────────────────────────

test("a collection scan finds the attacker task and suppresses the OS's own", () => {
  const c = makeCollection({ files: {
    // The intrusion: non-Microsoft name, user-writable action.
    [`${TASKS}/mcollective_facts_yaml_refresh`]: utf16(TASK_XML({
      uri: "\\mcollective_facts_yaml_refresh", command: "C:\\Users\\Public\\beacon.exe", hidden: true, runLevel: "HighestAvailable",
    })),
    // Built-in Windows tasks: elevated, hidden, rundll32, COM handlers — all of which are
    // the NORM for this population and none of which should raise a finding on their own.
    [`${TASKS}/Microsoft/Windows/Defrag/ScheduledDefrag`]: utf16(TASK_XML({
      uri: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", command: "%windir%\\system32\\defrag.exe", runLevel: "HighestAvailable",
    })),
    [`${TASKS}/Microsoft/Windows/Input/LocalUserSyncDataAvailable`]: utf16(TASK_XML({
      uri: "\\Microsoft\\Windows\\Input\\LocalUserSyncDataAvailable", com: "{8E7C2AFB-72B9-415C-9AC2-5037693309B7}", runLevel: "HighestAvailable", hidden: true,
    })),
    [`${TASKS}/Microsoft/Windows/AppID/SmartScreenSpecific`]: utf16(TASK_XML({
      uri: "\\Microsoft\\Windows\\AppID\\SmartScreenSpecific", command: "%windir%\\system32\\rundll32.exe", args: "appidsvc.dll", hidden: true,
    })),
    "C/Windows/System32/winevt/Logs/System.evtx": Buffer.from("ElfFile"),
    [`${CONFIG}/SOFTWARE`]: Buffer.from("regf-ish"),
  } });
  try {
    const res = analyzeCollection(c.root);
    assert.equal(res.error, null);
    assert.equal(res.collection.counts.taskXml, 4);
    assert.equal(res.stats.taskDefinitionsRead, 4);

    const names = res.items.map((i) => i.artifact);
    assert.ok(names.includes("\\mcollective_facts_yaml_refresh"), "the non-Microsoft task must surface");
    assert.ok(!names.some((n) => /^\\Microsoft\\Windows\\/.test(n)),
      `built-in Windows tasks must not flood triage — got ${JSON.stringify(names)}`);

    const evil = res.items.find((i) => i.artifact === "\\mcollective_facts_yaml_refresh");
    assert.equal(evil.details._taskHidden, true, "flags are read from the definition");
    assert.equal(evil.details._taskElevated, true);
    assert.ok(!evil.details._taskXmlPartial, "a full definition is never a partial parse");
    assert.equal(evil.command, "C:\\Users\\Public\\beacon.exe");
  } finally { c.cleanup(); }
});

test("a built-in-looking task pointing somewhere user-writable still surfaces", () => {
  const c = makeCollection({ files: {
    [`${TASKS}/Microsoft/Windows/UpdateOrchestrator/Backdoor`]: utf16(TASK_XML({
      uri: "\\Microsoft\\Windows\\UpdateOrchestrator\\Backdoor",
      command: "%windir%\\system32\\rundll32.exe", args: "C:\\Users\\Public\\evil.dll,Start", hidden: true, runLevel: "HighestAvailable",
    })),
  } });
  try {
    const res = analyzeCollection(c.root);
    assert.equal(res.items.length, 1,
      "hiding behind a Microsoft-looking name must not buy an allowlist pass when the action is user-writable");
    assert.match(res.items[0].artifact, /UpdateOrchestrator\\Backdoor/);
  } finally { c.cleanup(); }
});

test("coverage that was NOT read is reported, not implied", () => {
  const c = makeCollection({ files: {
    [`${TASKS}/T`]: utf16(TASK_XML({ uri: "\\T", command: "C:\\Users\\Public\\x.exe" })),
    "C/Windows/System32/winevt/Logs/System.evtx": Buffer.from("ElfFile"),
    "C/Windows/System32/winevt/Logs/Security.evtx": Buffer.from("ElfFile"),
    [`${CONFIG}/SYSTEM`]: Buffer.from("regf-ish"),
  } });
  try {
    const res = analyzeCollection(c.root);
    assert.equal(res.collection.unread.evtx, 2);
    assert.equal(res.collection.unread.hives, 1);
    assert.ok(res.warnings.some((w) => /2 EVTX files .* not read/i.test(w)),
      "an analyst must be able to see the EVTX were not covered");
    assert.ok(res.warnings.some((w) => /registry hive.* not parsed/i.test(w)));
  } finally { c.cleanup(); }
});

test("a collection with a Services plugin CSV yields registry findings too", () => {
  const csv = [
    "Name,BatchKeyPath,Description,BatchValueName,DisplayName,StartMode,ServiceType,NameKeyLastWrite,ParametersKeyLastWrite,Group,ImagePath,ServiceDLL,RequiredPrivileges",
    "Dnscache,ROOT\\ControlSet001\\Services,,None,DNS Client,Auto,Win32ShareProcess,2021-06-17 02:05:42,,,%SystemRoot%\\system32\\svchost.exe -k NetworkService,%SystemRoot%\\System32\\dnsrslvr.dll,",
    "EvilSvc,ROOT\\ControlSet001\\Services,,None,Evil,Auto,Win32OwnProcess,2026-03-15 10:00:00,,,C:\\Users\\Public\\beacon.exe,,",
  ].join("\n");
  const c = makeCollection({ files: { "Registry/20260305_Services__C_Windows_System32_config_SYSTEM.csv": Buffer.from(csv) } });
  try {
    const res = analyzeCollection(c.root);
    assert.equal(res.error, null);
    assert.ok(res.stats.registryRowsRead >= 2, "the plugin CSV is read in place, no import needed");
    const svc = res.items.find((i) => /EvilSvc/.test(i.artifact || ""));
    assert.ok(svc, "a service imaged from a user-writable path must surface");
    assert.match(svc.artifact, /ControlSet001\\Services\\EvilSvc/, "the real control set from BatchKeyPath is kept");
    assert.ok(!res.items.some((i) => /Dnscache/.test(i.artifact || "")), "signed system services stay inventory");
  } finally { c.cleanup(); }
});

test("csv parsing handles quoting, embedded commas and CRLF", () => {
  const rows = parseCsv('a,b,c\r\n1,"x,y","he said ""hi"""\r\n');
  assert.deepEqual(rows[0], ["a", "b", "c"]);
  assert.deepEqual(rows[1], ["1", "x,y", 'he said "hi"']);
});

test("an unreadable folder reports the error instead of throwing", () => {
  const res = analyzeCollection(path.join(os.tmpdir(), "definitely-not-here-" + Date.now()));
  assert.ok(res.error);
  assert.equal(res.items.length, 0);
});
