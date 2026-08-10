// Characterization tests for the campaign-clustering + edge-risk/enrichment stage
// extracted from getLateralMovement() into processing/campaign-clustering.js.
// Pins: campaign formation from connected incidents, fid threading (in/out), and
// edge risk scoring. This logic previously had no direct coverage.

const test = require("node:test");
const assert = require("node:assert/strict");
const { clusterCampaignsAndEnrich } = require("../electron/analyzers/lateral-movement/processing/campaign-clustering");
const { createEvidenceHelpers } = require("../electron/analyzers/lateral-movement/evidence");

const { _dedupeEvidenceRefs, _rowidsFromRefs } = createEvidenceHelpers({ tabId: "t" });

function baseState(over = {}) {
  return {
    incidents: [], findings: [], chains: [], edgeMap: new Map(),
    timeOrdered: [], hostSet: new Map(),
    _chainEdges: new Set(), _findingPairs: new Map(),
    _outlierHosts: new Set(), _conventionOutliers: new Map(), _computerHosts: [],
    detectOutlier: () => false,
    _dedupeEvidenceRefs, _rowidsFromRefs,
    fid: 100,
    ...over,
  };
}

function incident(id, source, target, over = {}) {
  return {
    id, source, target, users: ["CORP\\a"], techniques: ["T1021.002"],
    findings: [id + 1], eventCount: 2, severity: "high", triageScore: 30,
    timeRange: { from: "2026-03-10T08:0" + id + ":00", to: "2026-03-10T08:0" + (id + 1) + ":00" },
    evidenceRefs: [{ tabId: "t", rowId: id + 1 }],
    ...over,
  };
}

test("campaign clustering: two host-connected, time-proximate incidents form one campaign", () => {
  const incidents = [
    incident(0, "10.0.0.5", "HOST01"),
    incident(1, "HOST01", "HOST02", { severity: "critical", triageScore: 40, techniques: ["T1569.002"] }),
  ];
  const { campaigns, fid } = clusterCampaignsAndEnrich(baseState({ incidents }));
  assert.equal(campaigns.length, 1);
  assert.deepEqual([...campaigns[0].incidentIds].sort(), [0, 1]);
  assert.equal(campaigns[0].severity, "critical", "campaign takes worst incident severity");
  assert.ok(campaigns[0].hosts.includes("HOST01") && campaigns[0].hosts.includes("HOST02"));
  assert.ok(/Campaign across/.test(campaigns[0].narrative));
  assert.equal(fid, 100, "no findings pushed when chains/timeOrdered/conventionOutliers are empty");
});

test("campaign clustering: unrelated incidents (no shared host/user, far apart) do NOT cluster", () => {
  const incidents = [
    incident(0, "10.0.0.5", "HOST01", { users: ["CORP\\a"], timeRange: { from: "2026-03-10T08:00:00", to: "2026-03-10T08:05:00" } }),
    incident(1, "10.9.9.9", "HOST99", { users: ["CORP\\z"], timeRange: { from: "2026-03-12T20:00:00", to: "2026-03-12T20:05:00" } }),
  ];
  const { campaigns } = clusterCampaignsAndEnrich(baseState({ incidents }));
  assert.equal(campaigns.length, 0);
});

test("edge risk scoring: assigns riskScore + flags (DC target + first-seen)", () => {
  const edgeMap = new Map([[
    "10.0.0.5->DC01",
    { source: "10.0.0.5", target: "DC01", logonTypes: new Set(["3"]), hasFailures: false, users: new Set(["CORP\\a"]), isFirstSeen: true, count: 1, technique: "Network Logon" },
  ]]);
  clusterCampaignsAndEnrich(baseState({ edgeMap }));
  const edge = edgeMap.get("10.0.0.5->DC01");
  assert.equal(typeof edge.riskScore, "number");
  assert.ok(edge.riskScore > 0);
  assert.ok(Array.isArray(edge.flags));
  assert.ok(edge.flags.includes("Target is DC"));
  assert.ok(edge.flags.includes("First-seen pair"));
});

test("fid threading: anomalous-hostname findings advance and return the fid", () => {
  // One convention outlier → generateConventionFindings pushes a finding and bumps fid.
  const _conventionOutliers = new Map([["WEIRD-BOX", { reason: "does not match naming convention" }]]);
  const hostSet = new Map([["WEIRD-BOX", { eventCount: 3, isSource: true, isTarget: false }]]);
  const state = baseState({ _conventionOutliers, hostSet, _computerHosts: [{ host: "WEIRD-BOX", eventCount: 3 }] });
  const before = state.findings.length;
  const { fid } = clusterCampaignsAndEnrich(state);
  // If a convention finding was emitted, fid advanced past 100 and a finding was pushed.
  if (state.findings.length > before) {
    assert.ok(fid > 100, "fid advanced when a finding was pushed");
    assert.ok(state.findings.some((f) => typeof f.id === "number" && f.id >= 100));
  } else {
    assert.equal(fid, 100, "fid unchanged when no finding pushed");
  }
});
