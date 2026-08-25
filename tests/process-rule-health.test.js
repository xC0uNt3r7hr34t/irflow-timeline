const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function strip(src) {
  return src
    .replace(/import\s+[\s\S]*?from\s+["'][^"']+["']\s*;?/g, "")
    .replace(/export\s+(const|function|async function|class|let|var)\s+/g, "$1 ")
    .replace(/export\s*\{[^}]+\}\s*;?/g, "")
    .replace(/export\s+default\s+/g, "");
}

function load() {
  const root = path.join(__dirname, "..");
  // Minimal stubs for rule catalog / sequences so the health util can load alone.
  const stubs = `
    const PI_ALL_RULES = [
      { id: "pi-0", name: "Office → Shell", group: "execution", sev: "critical", technique: "T1059" },
      { id: "pi-1", name: "Encoded PowerShell", group: "execution", sev: "high", technique: "T1059.001" },
      { id: "pi-8", name: "whoami", group: "discovery", sev: "low", technique: "T1033" },
      { id: "pi-46", name: "Path masquerade", group: "defense-evasion", sev: "high", technique: "T1036" },
    ];
    const PI_RULE_GROUPS = [
      { id: "execution", label: "Execution" },
      { id: "discovery", label: "Discovery" },
      { id: "defense-evasion", label: "Defense Evasion" },
    ];
    const SEQ_DEFS = [
      { id: "seq-lolbin-download", name: "LOLBin download cradle", tid: ["T1105"] },
      { id: "seq-lsass-dump", name: "LSASS dump sequence", tid: ["T1003.001"] },
    ];
  `;
  const utilSrc = strip(fs.readFileSync(path.join(root, "src/utils/process-rule-health.js"), "utf8"));
  const sandbox = {
    module: { exports: {} },
    exports: {},
    console,
    Math,
    Number,
    String,
    Array,
    Object,
    Map,
    Set,
    JSON,
  };
  vm.createContext(sandbox);
  vm.runInContext(
    stubs +
      "\n" +
      utilSrc +
      `
    module.exports = { buildRuleHealthReport, formatRuleHealthReportText };
  `,
    sandbox,
  );
  return sandbox.module.exports;
}

const { buildRuleHealthReport, formatRuleHealthReportText } = load();

function det(evidence, extra = {}) {
  const level = Math.max(0, ...evidence.map((e) => e.level || 0));
  return {
    level,
    evidence,
    behaviors: evidence.map((e) => e.beh).filter(Boolean),
    techniques: evidence.flatMap((e) => e.tid || []),
    ...extra,
  };
}

describe("process-rule-health", () => {
  it("aggregates fired / silent / disabled built-in rules", () => {
    const detMap = new Map([
      [
        "a",
        det([
          { ruleId: "pi-0", level: 3, reason: "Office → cmd", tid: ["T1059"], beh: "shell-exec" },
          { ruleId: "pi-1", level: 2, reason: "Encoded PS", tid: ["T1059.001"], beh: "script-exec" },
        ]),
      ],
      ["b", det([{ ruleId: "pi-0", level: 3, reason: "Office → ps", tid: ["T1059"], beh: "shell-exec" }])],
      ["c", det([])],
    ]);
    const report = buildRuleHealthReport(detMap, {
      disabledRules: new Set(["pi-8"]),
      customRules: [],
      seqMap: null,
    });

    assert.equal(report.processesScored, 3);
    assert.equal(report.processesDetected, 2);
    assert.equal(report.summary.fired, 2); // pi-0, pi-1
    assert.equal(report.summary.silent, 1); // pi-46
    assert.equal(report.summary.disabled, 1); // pi-8
    assert.equal(report.summary.catalogSize, 4);
    assert.ok(report.summary.coveragePct > 0);

    const pi0 = report.builtIn.find((r) => r.id === "pi-0");
    assert.equal(pi0.hits, 2);
    assert.equal(pi0.status, "fired");
    assert.equal(pi0.maxLevelSeen, 3);

    const pi8 = report.builtIn.find((r) => r.id === "pi-8");
    assert.equal(pi8.status, "disabled");
    assert.equal(pi8.hits, 0);

    const silentHigh = report.silentHighValue.map((r) => r.id);
    assert.ok(silentHigh.includes("pi-46"));
    assert.ok(!silentHigh.includes("pi-8"), "disabled rules are not silent-high");
  });

  it("tracks custom rules and sequence hits", () => {
    const detMap = new Map([
      [
        "x",
        det([
          {
            ruleId: "custom-0",
            level: 2,
            reason: "Analyst rule",
            tid: ["T1059"],
            beh: "custom",
          },
        ]),
      ],
    ]);
    const seqMap = new Map([
      ["x", [{ seqId: "seq-lolbin-download" }, { seqId: "seq-lolbin-download" }]],
      ["y", [{ seqId: "seq-lsass-dump" }]],
    ]);
    const report = buildRuleHealthReport(detMap, {
      customRules: [{ name: "My Cradle", pattern: "iwr", severity: "high", technique: "T1105" }],
      seqMap,
    });

    assert.equal(report.summary.customTotal, 1);
    assert.equal(report.summary.customFired, 1);
    assert.equal(report.custom[0].hits, 1);
    assert.equal(report.custom[0].name, "My Cradle");

    const seqDl = report.sequences.find((s) => s.id === "seq-lolbin-download");
    assert.equal(seqDl.hits, 2);
    assert.equal(seqDl.status, "fired");
    assert.equal(report.summary.sequencesFired, 2);
  });

  it("surfaces orphan rule ids and topFired ordering", () => {
    const detMap = new Map([
      ["a", det([{ ruleId: "pi-0", level: 3, tid: ["T1059"] }])],
      ["b", det([{ ruleId: "unknown-legacy", level: 1, reason: "legacy" }])],
      ["c", det([{ ruleId: "pi-1", level: 2, tid: ["T1059.001"] }, { ruleId: "pi-0", level: 3 }])],
    ]);
    const report = buildRuleHealthReport(detMap, {});
    assert.ok(report.orphans.some((o) => o.id === "unknown-legacy" && o.hits === 1));
    assert.equal(report.topFired[0].id, "pi-0");
    assert.equal(report.topFired[0].hits, 2);
    assert.ok(report.techniques.some((t) => t.tid === "T1059" && t.count >= 1));
  });

  it("orders fired and silent rules by severity before hit count", () => {
    const detMap = new Map([
      ["critical", det([{ ruleId: "pi-0", level: 3 }])],
      ["high", det([{ ruleId: "pi-1", level: 2 }])],
      ["medium-1", det([{ ruleId: "unknown-legacy", level: 1 }])],
      ["medium-2", det([{ ruleId: "unknown-legacy", level: 1 }])],
      ["medium-3", det([{ ruleId: "unknown-legacy", level: 1 }])],
    ]);
    const report = buildRuleHealthReport(detMap, {});

    assert.deepEqual(
      Array.from(report.topFired.slice(0, 3), (r) => r.id),
      ["pi-0", "pi-1", "unknown-legacy"],
      "critical and high rules must stay above noisier medium rules",
    );

    const silent = buildRuleHealthReport(new Map(), {});
    assert.deepEqual(
      Array.from(silent.silentHighValue, (r) => r.id),
      ["pi-0", "pi-1", "pi-46"],
      "silent coverage gaps must also be severity-first",
    );
  });

  it("formats a plain-text export", () => {
    const detMap = new Map([
      ["a", det([{ ruleId: "pi-0", level: 3, reason: "Office", tid: ["T1059"], beh: "shell-exec" }])],
    ]);
    const report = buildRuleHealthReport(detMap, { disabledRules: new Set(["pi-8"]) });
    const text = formatRuleHealthReportText(report);
    assert.match(text, /Process Inspector — Rule Health Report/);
    assert.match(text, /Coverage/);
    assert.match(text, /pi-0/);
    assert.match(text, /Silent high-value/);
    assert.match(text, /Sequences:/);
  });

  it("handles empty detMap without throwing", () => {
    const report = buildRuleHealthReport(new Map(), {});
    assert.equal(report.processesScored, 0);
    assert.equal(report.summary.fired, 0);
    assert.equal(report.topFired.length, 0);
    assert.ok(typeof formatRuleHealthReportText(report) === "string");
  });
});

describe("process-rule-health UI wiring", () => {
  it("ResultsView imports and gates Rule Health panel", () => {
    const root = path.join(__dirname, "..");
    const results = fs.readFileSync(
      path.join(root, "src/components/process-analyzer/internals/ProcessTreeResultsView.jsx"),
      "utf8",
    );
    assert.match(results, /ProcessTreeRuleHealthPanel/);
    assert.match(results, /isHealthMode/);
    assert.match(results, /ptViewMode:\s*"health"|ptViewMode === "health"/);
    assert.match(results, /Rule Health|Rules/);
    assert.match(results, /process-rule-health\.txt/);
    // Split regressions: modal fields must be rebound, not left free.
    assert.match(results, /const expandedNodes\s*=\s*modal\.expandedNodes/);
    assert.match(results, /const searchText\s*=\s*modal\.searchText/);
  });

  it("modal split keeps phase components and passes pw / updateActiveTab", () => {
    const root = path.join(__dirname, "..");
    const modal = fs.readFileSync(
      path.join(root, "src/components/process-analyzer/internals/ProcessTreeModal.jsx"),
      "utf8",
    );
    assert.match(modal, /ProcessTreeConfigPhase/);
    assert.match(modal, /ProcessTreeLoadingPhase/);
    assert.match(modal, /ProcessTreeResultsView/);
    assert.match(modal, /pw=\{pw\}/);
    assert.match(modal, /updateActiveTab=\{updateActiveTab\}/);
    // Orchestrator should stay lean relative to pre-split monolith.
    const lines = modal.split("\n").length;
    assert.ok(lines < 1600, `orchestrator grew to ${lines} lines`);
  });

  it("ConfigPhase defines piDisabledSet, PI_TELEMETRY, and accepts pw", () => {
    const root = path.join(__dirname, "..");
    const cfg = fs.readFileSync(
      path.join(root, "src/components/process-analyzer/internals/ProcessTreeConfigPhase.jsx"),
      "utf8",
    );
    assert.match(cfg, /piDisabledSet\s*=\s*modal\.ptDisabledRules/);
    assert.match(cfg, /pw\s*=\s*1200/);
    // Split left these only in the orchestrator once; config must define them locally.
    assert.match(cfg, /const PI_TELEMETRY\s*=/);
    assert.match(cfg, /const toggleTelemetry\s*=/);
    assert.match(cfg, /PI_TELEMETRY\.map/);
    assert.match(cfg, /const eventIdValue\s*=\s*modal\.eventIdValue/);
  });
});
