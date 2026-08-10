const test = require("node:test");
const assert = require("node:assert/strict");

test("Sigma triage summary ranks critical/high findings first and extracts entities", async () => {
  const { buildSigmaTriageSummary } = await import("../src/components/modals/sigma/triageSummary.mjs");
  const summary = buildSigmaTriageSummary({
    matches: [
      { ruleId: "low-1", title: "Low Signal", level: "low", matchCount: 50, hosts: ["HOST-A"], mitre: ["attack.t1059"] },
      { ruleId: "crit-1", title: "Critical Signal", level: "critical", matchCount: 2, hosts: ["HOST-B"], mitre: ["T1003"], tactics: ["credential_access"] },
      { ruleId: "high-1", title: "High Signal", level: "high", matchCount: 7, hosts: ["HOST-C"], mitre: ["T1021"] },
    ],
    eventRows: [
      { Timestamp: "2026-01-01T00:00:00Z", Computer: "HOST-B", User: "alice", Image: "C:\\Temp\\rare.exe", MITRE: "T1003" },
      { Timestamp: "2026-01-01T00:05:00Z", Computer: "HOST-C", User: "bob", Image: "C:\\Windows\\cmd.exe", MITRE: "T1021" },
    ],
  });

  assert.equal(summary.priorityFindings[0].ruleId, "crit-1");
  assert.equal(summary.priorityFindings[1].ruleId, "high-1");
  assert.equal(summary.priorityFindings[2].ruleId, "low-1");
  assert.equal(summary.criticalHigh.length, 2);
  assert.equal(summary.firstSeen, "2026-01-01T00:00:00Z");
  assert.equal(summary.lastSeen, "2026-01-01T00:05:00Z");
  assert.ok(summary.affectedHosts.some((item) => item.value === "HOST-B"));
  assert.ok(summary.mitreTechniques.some((item) => item.value === "T1003"));
  assert.ok(summary.rareUsers.some((item) => item.value === "alice"));
  assert.ok(summary.rareProcesses.some((item) => item.value.includes("rare.exe")));
});

test("Sigma triage summary pushes reviewed and false-positive findings down", async () => {
  const { buildSigmaTriageSummary } = await import("../src/components/modals/sigma/triageSummary.mjs");
  const summary = buildSigmaTriageSummary({
    matches: [
      { ruleId: "crit-reviewed", title: "Reviewed Critical", level: "critical", matchCount: 20 },
      { ruleId: "crit-open", title: "Open Critical", level: "critical", matchCount: 1 },
      { ruleId: "high-fp", title: "False Positive High", level: "high", matchCount: 100 },
    ],
    reviewed: { "crit-reviewed": true },
    falsePositives: { "high-fp": true },
  });

  assert.equal(summary.priorityFindings[0].ruleId, "crit-open");
  assert.equal(summary.priorityFindings.at(-1).ruleId, "high-fp");
});

test("Sigma triage summary prefers full-result aggregates over preview-only entities", async () => {
  const { buildSigmaTriageSummary } = await import("../src/components/modals/sigma/triageSummary.mjs");
  const summary = buildSigmaTriageSummary({
    matches: [{ ruleId: "high-1", title: "High Signal", level: "high", matchCount: 3 }],
    eventRows: [{ Timestamp: "2026-01-01T00:00:00Z", Computer: "PREVIEW-HOST", User: "preview" }],
    aggregates: {
      firstSeen: "2026-01-01T00:00:00Z",
      lastSeen: "2026-01-02T00:00:00Z",
      affectedHosts: [{ value: "FULL-HOST", count: 20 }],
      rareUsers: [{ value: "rare-user", count: 1 }],
      rareProcesses: [{ value: "rare.exe", count: 1 }],
      mitreTechniques: [{ value: "T1059", count: 3 }],
    },
  });

  assert.deepEqual(summary.affectedHosts, [{ value: "FULL-HOST", count: 20 }]);
  assert.deepEqual(summary.rareUsers, [{ value: "rare-user", count: 1 }]);
  assert.equal(summary.lastSeen, "2026-01-02T00:00:00Z");
  assert.ok(summary.mitreTechniques.some((item) => item.value === "T1059"));
});
