const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function load() {
  const source = fs.readFileSync(path.join(__dirname, "../src/utils/lateral-movement-graph-layout.js"), "utf8")
    .replace(/export\s+(const|function|let|var|class)\s+/g, "$1 ")
    .replace(/export\s*\{[^}]+\}\s*;?/g, "");
  const sandbox = {
    module: { exports: {} }, exports: {}, Math, Number, String, Array, Object, Map, Set,
  };
  vm.createContext(sandbox);
  vm.runInContext(`${source}
    module.exports = {
      LATERAL_GRAPH_DEFAULTS,
      LATERAL_IDENTITY_NODE_PREFIX,
      buildLateralIdentityGraph,
      isLateralIdentityNodeId,
      selectLateralGraphNodes,
      selectLateralGraphEdges,
      layoutLateralMovementGraph,
    };`, sandbox);
  return sandbox.module.exports;
}

const api = load();

test("directed star layout separates sources from the target and spaces labels vertically", () => {
  const nodes = [
    { id: "SRC-A", eventCount: 2 },
    { id: "SRC-B-WITH-A-LONG-HOSTNAME", eventCount: 4 },
    { id: "SRC-C", eventCount: 1 },
    { id: "TARGET", eventCount: 20 },
  ];
  const edges = nodes.slice(0, 3).map((n) => ({ source: n.id, target: "TARGET", count: 1 }));
  const layout = api.layoutLateralMovementGraph(nodes, edges);

  assert.ok(layout.positions["SRC-A"].x < layout.positions.TARGET.x);
  assert.ok(layout.positions["SRC-B-WITH-A-LONG-HOSTNAME"].x < layout.positions.TARGET.x);
  const sourceYs = nodes.slice(0, 3).map((n) => layout.positions[n.id].y).sort((a, b) => a - b);
  assert.ok(sourceYs[1] - sourceYs[0] >= 60);
  assert.ok(sourceYs[2] - sourceYs[1] >= 60);
});

test("layout is deterministic and does not mutate node order", () => {
  const nodes = [
    { id: "B", eventCount: 1 },
    { id: "A", eventCount: 10 },
    { id: "C", eventCount: 2 },
  ];
  const before = nodes.map((n) => n.id);
  const edges = [{ source: "A", target: "C" }, { source: "B", target: "C" }];
  const first = api.layoutLateralMovementGraph(nodes, edges);
  const second = api.layoutLateralMovementGraph(nodes, edges);

  assert.deepEqual(nodes.map((n) => n.id), before);
  assert.deepEqual(first.positions, second.positions);
});

test("node cap prioritizes outliers and high-activity nodes without mutating input", () => {
  const nodes = [
    { id: "LOW", eventCount: 1 },
    { id: "HIGH", eventCount: 100 },
    { id: "OUTLIER", eventCount: 0, isOutlier: true },
  ];
  const selected = api.selectLateralGraphNodes(nodes, 2);
  assert.deepEqual(Array.from(selected, (n) => n.id), ["OUTLIER", "HIGH"]);
  assert.deepEqual(nodes.map((n) => n.id), ["LOW", "HIGH", "OUTLIER"]);
});

test("edge cap prioritizes risk, evidence signals, and activity without mutating input", () => {
  const edges = [
    { source: "A", target: "B", riskScore: 1, count: 1000 },
    { source: "B", target: "C", riskScore: 50, count: 1 },
    { source: "C", target: "D", riskScore: 50, count: 1, flags: ["finding"] },
  ];
  const before = edges.map((edge) => `${edge.source}->${edge.target}`);
  const selected = api.selectLateralGraphEdges(edges, 2);

  assert.deepEqual(
    Array.from(selected, (edge) => `${edge.source}->${edge.target}`),
    ["C->D", "B->C"],
  );
  assert.deepEqual(edges.map((edge) => `${edge.source}->${edge.target}`), before);
});

test("many disconnected components remain inside the visible graph bounds", () => {
  const nodes = Array.from({ length: 24 }, (_, index) => ({ id: `HOST-${index}` }));
  const layout = api.layoutLateralMovementGraph(nodes, []);
  const points = Object.values(layout.positions);

  assert.equal(points.length, nodes.length);
  assert.ok(points.every((point) => point.x >= 0 && point.x <= layout.width));
  assert.ok(points.every((point) => point.y >= 0 && point.y <= layout.height));
});

test("identity graph links one account across multiple machine hops with exact evidence", () => {
  const nodes = ["WKS01", "DC01", "FS01"].map((id) => ({ id, label: id, eventCount: 1 }));
  const edges = [
    {
      source: "WKS01", target: "DC01", users: ["CORP\\alice"], count: 3,
      riskScore: 40, technique: "RDP", firstSeen: "2026-01-01T01:00:00Z",
      lastSeen: "2026-01-01T01:02:00Z", evidenceRefs: [{ tabId: "security", rowId: 10 }],
      episodes: [{ user: "corp\\ALICE", count: 3 }],
    },
    {
      source: "DC01", target: "FS01", users: ["corp\\ALICE"], count: 2,
      riskScore: 25, technique: "Service Exec", firstSeen: "2026-01-01T01:05:00Z",
      lastSeen: "2026-01-01T01:06:00Z", evidenceRefs: [{ tabId: "system", rowId: 20 }],
      episodes: [{ user: "CORP\\alice", count: 2 }],
    },
  ];

  const graph = api.buildLateralIdentityGraph(nodes, edges);
  assert.equal(graph.identityNodes.length, 1);
  const identity = graph.identityNodes[0];
  assert.equal(api.isLateralIdentityNodeId(identity.id), true);
  assert.equal(identity.id, `${api.LATERAL_IDENTITY_NODE_PREFIX}corp\\alice`);
  assert.deepEqual(Array.from(identity.sourceHosts), ["DC01", "WKS01"]);
  assert.deepEqual(Array.from(identity.targetHosts), ["DC01", "FS01"]);
  assert.equal(identity.eventCount, 5);
  assert.equal(identity.riskScore, 40);
  assert.deepEqual(
    Array.from(identity.evidenceRefs, (ref) => `${ref.tabId}:${ref.rowId}`),
    ["security:10", "system:20"],
  );
  assert.ok(graph.edges.some((edge) => edge.source === "WKS01" && edge.target === identity.id));
  assert.ok(graph.edges.some((edge) => edge.source === identity.id && edge.target === "DC01"));
  assert.ok(graph.edges.some((edge) => edge.source === "DC01" && edge.target === identity.id));
  assert.ok(graph.edges.some((edge) => edge.source === identity.id && edge.target === "FS01"));
});

test("unattributed host pairs receive separate unresolved identity nodes", () => {
  const nodes = ["A", "B", "C"].map((id) => ({ id, label: id, eventCount: 1 }));
  const edges = [
    { source: "A", target: "B", users: [], count: 1, evidenceRefs: [{ tabId: "x", rowId: 1 }] },
    { source: "A", target: "C", users: ["(unknown)"], count: 1, evidenceRefs: [{ tabId: "x", rowId: 2 }] },
  ];
  const graph = api.buildLateralIdentityGraph(nodes, edges);
  assert.equal(graph.identityNodes.length, 2);
  assert.ok(graph.identityNodes.every((node) => node.unresolved));
  assert.equal(graph.unattributedEdges.length, 2);
});

test("multi-user edges without episode attribution are marked approximate, not proportionally fabricated", () => {
  const nodes = ["A", "B"].map((id) => ({ id, label: id }));
  const graph = api.buildLateralIdentityGraph(nodes, [
    { source: "A", target: "B", users: ["CORP\\alice", "CORP\\bob"], count: 9 },
  ]);

  assert.equal(graph.identityNodes.length, 2);
  assert.ok(graph.identityNodes.every((node) => node.eventCount === 1));
  assert.ok(graph.identityNodes.every((node) => node.attributionApproximate));
  assert.ok(graph.edges.every((edge) => edge.attributionApproximate));
});
