// Characterization tests for the Sysmon-EID13/session-grouping/coverage stage
// extracted into processing/sysmon-rdp-coverage.js. Previously untested.

const test = require("node:test");
const assert = require("node:assert/strict");
const { computeSysmonRdpAndCoverage } = require("../electron/analyzers/lateral-movement/processing/sysmon-rdp-coverage");
const { createEvidenceHelpers } = require("../electron/analyzers/lateral-movement/evidence");

const ev = createEvidenceHelpers({ tabId: "t" });

function baseState(over = {}) {
  return {
    db: { prepare: () => ({ all: () => [] }) },
    meta: { headers: [], colMap: {} },
    columns: { ts: null, target: null },
    options: {},
    hostSet: new Map(),
    _outlierHosts: new Set(),
    findings: [],
    warnings: [],
    isHayabusa: false,
    _scanEidCol: null, // skips the db-query Sysmon path
    _dedupeEvidenceRefs: ev._dedupeEvidenceRefs,
    _rowEvidenceRef: ev._rowEvidenceRef,
    _rowidsFromRefs: ev._rowidsFromRefs,
    _normalizeFindingEvidenceRefs: () => {},
    rdpSessions: [],
    hostTelemetry: new Map(),
    datasetEventCounts: new Map(),
    _conventionOutliers: new Map(),
    fid: 300,
    ...over,
  };
}

test("multi-source Sysmon CLIENTNAME → RDP Client Hostname finding + isolated node + fid advance", () => {
  const state = baseState({
    db: null,
    options: { _multiSourceSysmonClients: [{ clientHost: "ATTACKER-PC", target: "HOST01", ts: "2026-03-10T08:00:00Z", evidenceRefs: [{ tabId: "t", rowId: 1 }] }] },
    fid: 300,
  });
  const { fid } = computeSysmonRdpAndCoverage(state);
  const f = state.findings.filter((x) => x.category === "RDP Client Hostname");
  assert.equal(f.length, 1);
  assert.equal(f[0].mitre, "T1021.001");
  assert.equal(f[0].source, "ATTACKER-PC");
  assert.ok(fid > 300, "fid advanced");
  assert.ok(state.hostSet.has("ATTACKER-PC"), "isolated node added to hostSet");
  assert.ok(state._outlierHosts.has("ATTACKER-PC"));
});

test("session grouping: sessions with same source|target|user|technique collapse to one group", () => {
  const s = (start, end) => ({ source: "10.0.0.5", target: "HOST01", user: "CORP\\a", technique: "RDP", status: "connected", startTime: start, endTime: end, evidenceRefs: [] });
  const { groupedSessions } = computeSysmonRdpAndCoverage(baseState({
    rdpSessions: [s("2026-03-10T08:00:00Z", "2026-03-10T08:30:00Z"), s("2026-03-10T09:00:00Z", "2026-03-10T09:30:00Z")],
  }));
  assert.equal(groupedSessions.length, 1);
  assert.equal(groupedSessions[0].count, 2);
  assert.equal(groupedSessions[0].timeRange.from, "2026-03-10T08:00:00Z");
  assert.equal(groupedSessions[0].timeRange.to, "2026-03-10T09:30:00Z");
});

test("coverage computation: present categories scored, missing ones warned", () => {
  const { hostCoverage, datasetCoverage, datasetEventCountsObj, coverageWarnings } = computeSysmonRdpAndCoverage(baseState({
    hostTelemetry: new Map([["HOST01", new Map([["4624", 5], ["4625", 2]])]]),
    datasetEventCounts: new Map([["4624", 5], ["4625", 2]]),
  }));
  assert.ok(hostCoverage.has("HOST01"));
  assert.equal(typeof datasetCoverage.score, "number");
  assert.equal(datasetEventCountsObj["4624"], 5);
  assert.ok(!coverageWarnings.some((w) => w.category === "auth"), "auth present → no auth warning");
  assert.ok(coverageWarnings.some((w) => w.category === "rdp"), "rdp missing → rdp warning");
});

test("no Sysmon clients + no sessions → no findings, fid unchanged, empty coverage warnings list is fine", () => {
  const state = baseState({ fid: 300 });
  const { fid, groupedSessions } = computeSysmonRdpAndCoverage(state);
  assert.equal(state.findings.length, 0);
  assert.equal(fid, 300);
  assert.deepEqual(groupedSessions, []);
});
