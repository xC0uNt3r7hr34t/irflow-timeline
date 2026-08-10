// Characterization tests for the RDP-scoring stage extracted from
// getLateralMovement() into processing/rdp-scoring.js: RDP session suspicion
// scoring, concurrent-RDP detection (+ fid threading), and per-edge episode
// clustering. Previously had no direct coverage.

const test = require("node:test");
const assert = require("node:assert/strict");
const { scoreRdpSessions } = require("../electron/analyzers/lateral-movement/processing/rdp-scoring");

function baseState(over = {}) {
  return {
    timeOrdered: [], edgeMap: new Map(), rdpSessions: [],
    _findingPairs: new Map(), _outlierHosts: new Set(), findings: [], fid: 200,
    ...over,
  };
}
function session(id, over = {}) {
  return {
    id, user: "CORP\\A", source: "10.0.0.5", target: "HOST01",
    startTime: "2026-03-10T08:00:00Z", endTime: "2026-03-10T08:30:00Z",
    status: "connected", events: [], confidence: "high", hasAdmin: false, technique: "RDP",
    ...over,
  };
}

test("suspicion scoring: outlier source + DC target + admin sets score + flags, upgrades technique", () => {
  const s = session(0, { source: "10.0.0.5", target: "DC01", hasAdmin: true });
  scoreRdpSessions(baseState({ rdpSessions: [s], _outlierHosts: new Set(["10.0.0.5"]) }));
  assert.equal(typeof s.suspicionScore, "number");
  assert.ok(s.suspicionScore >= 50, "outlier(20)+DC(15)+admin(15) at minimum");
  assert.ok(s.flags.includes("Source is outlier"));
  assert.ok(s.flags.includes("Target is DC"));
  assert.ok(s.flags.includes("Admin privileges (4672)"));
  assert.equal(s.technique, "Suspicious RDP", "technique upgraded when score >= 25");
});

test("concurrent RDP: same user overlapping on different targets → finding + fid advance + isConcurrent", () => {
  const s1 = session(0, { target: "HOST01", startTime: "2026-03-10T08:00:00Z", endTime: "2026-03-10T08:30:00Z" });
  const s2 = session(1, { target: "HOST02", startTime: "2026-03-10T08:10:00Z", endTime: "2026-03-10T08:40:00Z" });
  const state = baseState({ rdpSessions: [s1, s2], fid: 200 });
  const { fid } = scoreRdpSessions(state);
  const conc = state.findings.filter((f) => f.category === "Concurrent RDP Sessions");
  assert.equal(conc.length, 1);
  assert.equal(conc[0].mitre, "T1021.001");
  assert.ok(fid > 200, "fid advanced for the pushed finding");
  assert.ok(conc[0].id >= 200);
  assert.ok(s1.isConcurrent && s2.isConcurrent, "both sessions flagged concurrent");
});

test("episode clustering: every edge gets an episodes array (empty when no events)", () => {
  const edgeMap = new Map([["10.0.0.5->HOST01", { source: "10.0.0.5", target: "HOST01" }]]);
  scoreRdpSessions(baseState({ edgeMap }));
  assert.deepEqual(edgeMap.get("10.0.0.5->HOST01").episodes, []);
});

test("single RDP session does not produce a concurrent finding; fid unchanged", () => {
  const state = baseState({ rdpSessions: [session(0)], fid: 200 });
  const { fid } = scoreRdpSessions(state);
  assert.equal(state.findings.filter((f) => f.category === "Concurrent RDP Sessions").length, 0);
  assert.equal(fid, 200);
});

test("concurrent RDP: same user on the SAME target (no distinct targets) → no finding", () => {
  const s1 = session(0, { target: "HOST01", startTime: "2026-03-10T08:00:00Z", endTime: "2026-03-10T08:30:00Z" });
  const s2 = session(1, { target: "HOST01", startTime: "2026-03-10T08:10:00Z", endTime: "2026-03-10T08:40:00Z" });
  const state = baseState({ rdpSessions: [s1, s2], fid: 200 });
  const { fid } = scoreRdpSessions(state);
  assert.equal(state.findings.filter((f) => f.category === "Concurrent RDP Sessions").length, 0);
  assert.equal(fid, 200);
});

test("telemetry gaps and low reconstruction confidence are caveats, not score boosts", () => {
  const complete = session(0);
  scoreRdpSessions(baseState({ rdpSessions: [complete] }));

  const incomplete = session(0, {
    confidence: "low",
    missingExpected: ["1149", "21/22"],
    evidenceLevel: "correlated",
  });
  scoreRdpSessions(baseState({ rdpSessions: [incomplete] }));

  assert.equal(incomplete.suspicionScore, complete.suspicionScore);
  assert.ok(incomplete.flags.some((flag) => flag.startsWith("Telemetry gap:")));
  assert.ok(incomplete.flags.includes("Low reconstruction confidence"));
  assert.ok(incomplete.flags.includes("RDP classification is correlated, not direct"));
});

test("finding overlap raises an RDP score only when the pair also overlaps in time", () => {
  const finding = (id, from, to = from) => ({
    id,
    category: "Brute Force",
    severity: "high",
    source: "10.0.0.5",
    target: "HOST01",
    timeRange: { from, to },
  });

  const farSession = session(0);
  scoreRdpSessions(baseState({
    rdpSessions: [farSession],
    findings: [finding(10, "2026-03-11T08:00:00Z")],
    _findingPairs: undefined,
  }));
  assert.equal(farSession.findingIds.length, 0);
  assert.ok(!farSession.flags.some((flag) => flag.startsWith("Finding:")));

  const nearSession = session(0);
  scoreRdpSessions(baseState({
    rdpSessions: [nearSession],
    findings: [finding(11, "2026-03-10T08:05:00Z")],
    _findingPairs: undefined,
  }));
  assert.deepEqual(nearSession.findingIds, [11]);
  assert.equal(nearSession.suspicionScore, farSession.suspicionScore + 12);
  assert.ok(nearSession.flags.includes("Finding: Brute Force"));
});
