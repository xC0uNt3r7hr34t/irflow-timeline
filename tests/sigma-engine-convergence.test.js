// JS-Sigma ↔ Hayabusa convergence.
//
// The two detection engines must agree on WHAT matched and HOW it's tallied.
// Nothing else catches them silently diverging (e.g. "info" vs "informational",
// per-event vs per-rule counts, host casing). This test drives BOTH real
// pipelines over one shared scenario with an authored ground truth:
//
//   JS side       : compileDetection + createFieldResolver (the real matcher)
//   Hayabusa side : parseHayabusaCsv over a CSV reflecting the same detections
//   both          : severityHistogram (the shared aggregation helper)
//
// Each engine must independently reproduce the ground truth — so they converge
// with each other AND neither is "wrong the same way". All real code paths,
// runs under plain `node --test` (no better-sqlite3, no Hayabusa binary).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { compileDetection } = require("../electron/analyzers/sigma/condition-compiler");
const { createFieldResolver } = require("../electron/analyzers/sigma/field-mapper");
const { parseHayabusaCsv } = require("../electron/analyzers/sigma/evtx-scanner/output-parser");
const { severityHistogram } = require("../electron/analyzers/sigma/match-utils");
const { flagsForFormat } = require("../electron/analyzers/sigma/format-detect");

// ── Shared scenario ──────────────────────────────────────────────────────────
const RULES = [
  { id: "r-mimikatz", title: "Mimikatz Credential Dumping", level: "critical", detection: { sel: { "Image|endswith": "\\mimikatz.exe" }, condition: "sel" } },
  { id: "r-psexec", title: "PsExec Service Install", level: "high", detection: { sel: { "ServiceName|contains": "PSEXESVC" }, condition: "sel" } },
  { id: "r-whoami", title: "Whoami Recon", level: "low", detection: { sel: { "CommandLine|contains": "whoami" }, condition: "sel" } },
  { id: "r-netview", title: "Net View Discovery", level: "informational", detection: { sel: { "CommandLine|contains": "net view" }, condition: "sel" } },
];

const EVENTS = [
  /* 0 */ { Computer: "HOST1", Image: "C:\\tools\\mimikatz.exe", CommandLine: "mimikatz.exe sekurlsa::logonpasswords" },
  /* 1 */ { Computer: "HOST1", Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd /c whoami /all" },
  /* 2 */ { Computer: "HOST2", Image: "D:\\m\\mimikatz.exe", CommandLine: "mimikatz" },
  /* 3 */ { Computer: "HOST3", ServiceName: "PSEXESVC", Image: "C:\\Windows\\PSEXESVC.exe" },
  /* 4 */ { Computer: "HOST1", Image: "C:\\Windows\\notepad.exe", CommandLine: "notepad" }, // matches nothing
  /* 5 */ { Computer: "HOST2", CommandLine: "net view" },
  /* 6 */ { Computer: "HOST4", CommandLine: "whoami && net view" }, // matches TWO rules
];

// Authoritative (eventIndex, ruleId) pairs — authored from rule semantics, NOT
// derived from either engine, so the test pins correctness rather than mutual agreement.
const GROUND_TRUTH = [
  [0, "r-mimikatz"], [2, "r-mimikatz"],
  [3, "r-psexec"],
  [1, "r-whoami"], [6, "r-whoami"],
  [5, "r-netview"], [6, "r-netview"],
];

const HEADERS = ["datetime", "Provider", "EventID", "Channel", "Computer", "Image", "CommandLine", "ServiceName"];
const CSV_HEADER = "Timestamp,RuleTitle,Level,Computer,Channel,EventID,MitreTactics,MitreTags,OtherTags,RecordID,Details,ExtraFieldInfo,RuleFile,RuleID,EvtxFile";
const CSV_COLS = CSV_HEADER.split(",");

// ── Helpers ──────────────────────────────────────────────────────────────────
const ruleById = new Map(RULES.map((r) => [r.id, r]));

// Normalize a set of (ruleId -> {level, count, hosts}) into a stable, comparable shape.
function summarize(byRule) {
  return [...byRule.values()]
    .map((m) => ({ ruleId: m.ruleId, level: m.level, count: m.count, hosts: [...m.hosts].sort() }))
    .sort((a, b) => a.ruleId.localeCompare(b.ruleId));
}

function aggregateFromPairs(pairs) {
  const byRule = new Map();
  for (const [ei, rid] of pairs) {
    if (!byRule.has(rid)) byRule.set(rid, { ruleId: rid, level: ruleById.get(rid).level, count: 0, hosts: new Set() });
    const m = byRule.get(rid);
    m.count++;
    const host = EVENTS[ei].Computer;
    if (host) m.hosts.add(String(host).toUpperCase());
  }
  return byRule;
}

// JS engine: the REAL compiler + resolver decide matches.
function runJsEngine() {
  const resolve = createFieldResolver(
    { headers: HEADERS, colMap: Object.fromEntries(HEADERS.map((h) => [h, h])) },
    flagsForFormat("rawevtx"),
  );
  const byRule = new Map();
  for (const rule of RULES) {
    const predicate = compileDetection(rule.detection);
    EVENTS.forEach((ev) => {
      if (predicate(resolve, ev)) {
        if (!byRule.has(rule.id)) byRule.set(rule.id, { ruleId: rule.id, level: rule.level, count: 0, hosts: new Set() });
        const m = byRule.get(rule.id);
        m.count++;
        if (ev.Computer) m.hosts.add(String(ev.Computer).toUpperCase());
      }
    });
  }
  return byRule;
}

function csvEsc(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
// Hayabusa emits "info" for the lowest level; the parser must normalize it back.
const hayaLevel = (level) => (level === "informational" ? "info" : level);

// Hayabusa engine: write the CSV Hayabusa would emit for the ground-truth matches,
// then parse it with the REAL output parser.
async function runHayabusaEngine(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-converge-"));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const lines = [CSV_HEADER];
  GROUND_TRUTH.forEach(([ei, rid], i) => {
    const r = ruleById.get(rid);
    const ev = EVENTS[ei];
    const values = {
      Timestamp: `2026-01-01T00:00:${String(i).padStart(2, "0")}Z`,
      RuleTitle: r.title, Level: hayaLevel(r.level), Computer: ev.Computer, RuleID: r.id,
    };
    lines.push(CSV_COLS.map((c) => csvEsc(values[c])).join(","));
  });
  const csvPath = path.join(dir, "haya.csv");
  fs.writeFileSync(csvPath, lines.join("\n") + "\n");

  const parsed = await parseHayabusaCsv(csvPath, null, null, { resultStore: null, previewLimit: 2000 });
  const byRule = new Map();
  for (const [, rm] of parsed.ruleMatches) {
    byRule.set(rm.ruleId, { ruleId: rm.ruleId, level: rm.level, count: rm.count, hosts: rm.hosts });
  }
  return byRule;
}

// ── Tests ────────────────────────────────────────────────────────────────────
test("both engines reproduce the authored ground truth (rules, counts, hosts)", async (t) => {
  const expected = summarize(aggregateFromPairs(GROUND_TRUTH));
  const js = summarize(runJsEngine());
  const haya = summarize(await runHayabusaEngine(t));

  assert.deepEqual(js, expected, "JS engine diverged from ground truth");
  assert.deepEqual(haya, expected, "Hayabusa parse diverged from ground truth");
  assert.deepEqual(js, haya, "JS and Hayabusa engines disagree");

  // Spot-check the interesting cases survived end-to-end:
  const byId = Object.fromEntries(js.map((m) => [m.ruleId, m]));
  assert.equal(byId["r-mimikatz"].count, 2, "endswith matched both mimikatz paths");
  assert.deepEqual(byId["r-mimikatz"].hosts, ["HOST1", "HOST2"]);
  assert.equal(byId["r-whoami"].count, 2, "an event matching two rules counts under each");
  assert.equal(byId["r-netview"].count, 2);
});

test("severity histograms converge (incl. info→informational normalization)", async (t) => {
  const js = summarize(runJsEngine());
  const haya = summarize(await runHayabusaEngine(t));

  const jsHist = severityHistogram(js);
  const hayaHist = severityHistogram(haya);

  assert.deepEqual(jsHist, hayaHist, "severity histograms diverge between engines");
  assert.deepEqual(jsHist, { critical: 1, high: 1, medium: 0, low: 1, informational: 1 });
});
