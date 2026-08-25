// Unit tests for the LSASS / credential-theft emission paths of the
// admin-share-and-execution detector module (the admin-share + remote-exec
// sequence paths are already covered by lateral-movement-detections.test.js).

const test = require("node:test");
const assert = require("node:assert/strict");
const { detectAdminShareAndExecution } = require("../electron/analyzers/lateral-movement/detectors/admin-share-and-execution");
const { createEvidenceHelpers } = require("../electron/analyzers/lateral-movement/evidence");

const ev = createEvidenceHelpers({ tabId: "t" });

function baseState(over = {}) {
  return {
    timeOrdered: [], findings: [], edgeMap: new Map(), columns: {}, warnings: [], chains: [],
    meta: { tabId: "t" }, _outlierHosts: new Set(),
    _dedupeEvidenceRefs: ev._dedupeEvidenceRefs, _refsFromHits: ev._refsFromHits,
    _rowidsFromRefs: ev._rowidsFromRefs, _attachEvidenceRefs: ev._attachEvidenceRefs,
    _usersFromCorrelation: () => [], _sourcesFromCorrelation: () => [],
    _disabledSet: new Set(), _lsassAccessHits: [], _credTheftCmdHits: [],
    fid: 400,
    ...over,
  };
}

test("LSASS direct access hits → critical T1003.001 finding + fid advance", () => {
  const state = baseState({ _lsassAccessHits: [{ host: "HOST01", caller: "mimikatz.exe", ts: "2026-03-10T08:00:00Z", rid: 1 }], fid: 400 });
  const { fid } = detectAdminShareAndExecution(state);
  const f = state.findings.filter((x) => x.category === "LSASS Access");
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "critical");
  assert.equal(f[0].mitre, "T1003.001");
  assert.equal(f[0].target, "HOST01");
  assert.ok(fid > 400);
});

test("reg save SAM/SECURITY → critical SAM/LSA Registry Dump (T1003.002)", () => {
  const state = baseState({ _credTheftCmdHits: [{ category: "reg_save", host: "HOST01", target: "SAM", ts: "2026-03-10T08:00:00Z", rid: 1 }] });
  detectAdminShareAndExecution(state);
  const f = state.findings.filter((x) => x.category === "SAM/LSA Registry Dump");
  assert.equal(f.length, 1);
  assert.equal(f[0].mitre, "T1003.002");
  assert.equal(f[0].severity, "critical");
});

test("netsh portproxy → high Port Forwarding (T1090.001)", () => {
  const state = baseState({ _credTheftCmdHits: [{ category: "portproxy", host: "HOST01", ts: "2026-03-10T08:00:00Z", rid: 1 }] });
  detectAdminShareAndExecution(state);
  const f = state.findings.filter((x) => x.category === "Port Forwarding");
  assert.equal(f.length, 1);
  assert.equal(f[0].mitre, "T1090.001");
  assert.equal(f[0].severity, "high");
});

test("disabledDetectors suppresses the LSASS detector", () => {
  const state = baseState({ _lsassAccessHits: [{ host: "HOST01", caller: "x.exe", ts: "2026-03-10T08:00:00Z", rid: 1 }], _disabledSet: new Set(["lsass"]), fid: 400 });
  const { fid } = detectAdminShareAndExecution(state);
  assert.equal(state.findings.filter((x) => x.category === "LSASS Access").length, 0);
  assert.equal(fid, 400);
});

test("no accumulator hits → no findings, fid unchanged", () => {
  const state = baseState({ fid: 400 });
  const { fid } = detectAdminShareAndExecution(state);
  assert.equal(state.findings.length, 0);
  assert.equal(fid, 400);
});
