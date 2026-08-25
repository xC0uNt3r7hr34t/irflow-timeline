// Characterization tests for the triage-scoring + execution-session/incident
// clustering unit extracted from getLateralMovement() into
// processing/triage-and-clustering.js. This logic previously had no direct
// coverage; these tests pin its observable behavior (triage scoring, pair
// indexing, related-finding links, session + incident clustering).

const test = require("node:test");
const assert = require("node:assert/strict");
const { correlateTriageAndCluster } = require("../electron/analyzers/lateral-movement/processing/triage-and-clustering");
const { createEvidenceHelpers } = require("../electron/analyzers/lateral-movement/evidence");

const { _dedupeEvidenceRefs, _rowidsFromRefs } = createEvidenceHelpers({ tabId: "t" });

function finding(id, over = {}) {
  return {
    id, severity: "high", category: "PsExec Native", mitre: "T1569.002",
    source: "10.0.0.5", target: "HOST01", users: ["CORP\\attacker"],
    evidencePills: [{ text: "PSEXESVC", type: "execution" }],
    evidenceRefs: [{ tabId: "t", rowId: id }],
    filterEids: ["7045"], filterHosts: ["HOST01"], eventCount: 1,
    timeRange: { from: "2026-03-10T08:00:00", to: "2026-03-10T08:00:30" },
    ...over,
  };
}

function run(findings, over = {}) {
  return correlateTriageAndCluster({
    findings,
    chains: over.chains || [],
    timeOrdered: over.timeOrdered || [],
    _outlierHosts: over._outlierHosts || new Set(),
    _dedupeEvidenceRefs, _rowidsFromRefs,
  });
}

test("triage scoring: assigns numeric triageScore and sorts findings by it (desc)", () => {
  const findings = [
    finding(1, { severity: "medium", category: "Admin Share Access" }),
    finding(2, { severity: "critical" }),
  ];
  run(findings);
  assert.ok(findings.every((f) => typeof f.triageScore === "number"), "every finding has a numeric triageScore");
  // critical scores higher than medium → finding 2 sorts before finding 1
  assert.equal(findings[0].id, 2);
  assert.ok(findings[0].triageScore > findings[1].triageScore);
});

test("related findings: findings on the same source->target pair cross-link", () => {
  const findings = [finding(1, { category: "Admin Share Access" }), finding(2)];
  run(findings);
  const f1 = findings.find((f) => f.id === 1);
  const f2 = findings.find((f) => f.id === 2);
  assert.deepEqual(f1.relatedFindingIds, [2]);
  assert.deepEqual(f2.relatedFindingIds, [1]);
});

test("_findingPairs indexes finding ids by uppercased source->target pair", () => {
  const findings = [finding(1), finding(2)];
  const { _findingPairs, _chainEdges } = run(findings);
  assert.ok(_findingPairs instanceof Map);
  assert.deepEqual(_findingPairs.get("10.0.0.5->HOST01"), [1, 2]);
  assert.ok(_chainEdges instanceof Set);
});

test("incident clustering: 2+ pair findings within 30 min form one incident", () => {
  const findings = [
    finding(1, { category: "Admin Share Access", timeRange: { from: "2026-03-10T08:00:00", to: "2026-03-10T08:00:30" } }),
    finding(2, { timeRange: { from: "2026-03-10T08:05:00", to: "2026-03-10T08:05:10" } }),
  ];
  const { incidents } = run(findings);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].source, "10.0.0.5");
  assert.equal(incidents[0].target, "HOST01");
  assert.deepEqual([...incidents[0].findings].sort(), [1, 2]);
  assert.ok(incidents[0].narrative.includes("10.0.0.5"));
});

test("execution sessions: execution-category findings cluster into sessions", () => {
  const findings = [
    finding(1, { timeRange: { from: "2026-03-10T08:00:00", to: "2026-03-10T08:00:30" } }),
    finding(2, { timeRange: { from: "2026-03-10T08:01:00", to: "2026-03-10T08:01:10" } }),
  ];
  const { executionSessions } = run(findings);
  assert.ok(executionSessions.length >= 1);
  const ids = new Set(executionSessions.flatMap((s) => s.findingIds));
  assert.ok(ids.has(1) && ids.has(2), "both findings represented across sessions");
  for (const s of executionSessions) {
    assert.equal(typeof s.technique, "string");
    assert.equal(s.source, "10.0.0.5");
    assert.equal(s.target, "HOST01");
  }
});

test("execution sessions preserve service-install evidence context", () => {
  const details = [{
    eventId: "7045",
    timestamp: "2026-03-10T08:00:00",
    target: "HOST01",
    serviceName: "evilsvc",
    imagePath: "C:\\Windows\\Temp\\evil.exe",
    commandLine: "cmd /c whoami",
    eventActor: "NT AUTHORITY\\SYSTEM",
    serviceAccount: "LocalSystem",
    attributedUser: "CORP\\attacker",
    sourceHost: "10.0.0.5",
    reason: "Service binary from user-writable path",
    rowId: 1,
  }];
  const { executionSessions } = run([finding(1, {
    category: "Remote Service Execution",
    serviceNames: ["evilsvc"],
    imagePaths: ["C:\\Windows\\Temp\\evil.exe"],
    commandLines: ["cmd /c whoami"],
    eventActors: ["NT AUTHORITY\\SYSTEM"],
    serviceAccounts: ["LocalSystem"],
    executors: ["NT AUTHORITY\\SYSTEM", "CORP\\attacker"],
    executionDetails: details,
  })]);
  assert.equal(executionSessions.length, 1);
  assert.deepEqual(executionSessions[0].serviceNames, ["evilsvc"]);
  assert.deepEqual(executionSessions[0].imagePaths, ["C:\\Windows\\Temp\\evil.exe"]);
  assert.deepEqual(executionSessions[0].commandLines, ["cmd /c whoami"]);
  assert.deepEqual(executionSessions[0].eventActors, ["NT AUTHORITY\\SYSTEM"]);
  assert.deepEqual(executionSessions[0].serviceAccounts, ["LocalSystem"]);
  assert.deepEqual(executionSessions[0].executionDetails, details);
});

test("single finding on a pair does NOT form an incident", () => {
  const { incidents } = run([finding(1)]);
  assert.equal(incidents.length, 0);
});
