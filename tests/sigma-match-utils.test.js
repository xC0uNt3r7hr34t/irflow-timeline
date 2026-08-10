// Shared rule-match aggregation helpers (electron/analyzers/sigma/match-utils.js).
// Both the JS Sigma engine and the Hayabusa engine build severity histograms and
// sort matches through these, so they're the single source of truth the
// convergence test relies on.

const test = require("node:test");
const assert = require("node:assert/strict");

const { severityHistogram, sortMatchesBySeverity, SEVERITIES } = require("../electron/analyzers/sigma/match-utils");

test("severityHistogram counts each bucket and ignores unknown levels", () => {
  const matches = [
    { level: "critical" }, { level: "critical" },
    { level: "high" },
    { level: "low" },
    { level: "informational" },
    { level: "bogus" }, // unknown — must not crash or leak a key
  ];
  assert.deepEqual(severityHistogram(matches), {
    critical: 2, high: 1, medium: 0, low: 1, informational: 1,
  });
  assert.deepEqual(severityHistogram([]), { critical: 0, high: 0, medium: 0, low: 0, informational: 0 });
  assert.deepEqual(severityHistogram(undefined), { critical: 0, high: 0, medium: 0, low: 0, informational: 0 });
  assert.deepEqual(Object.keys(severityHistogram([])), SEVERITIES);
});

test("sortMatchesBySeverity orders by severity then match count desc", () => {
  const matches = [
    { level: "low", matchCount: 5 },
    { level: "critical", matchCount: 1 },
    { level: "high", matchCount: 2 },
    { level: "critical", matchCount: 9 },
    { level: "informational", matchCount: 100 },
  ];
  sortMatchesBySeverity(matches);
  assert.deepEqual(matches.map((m) => `${m.level}:${m.matchCount}`), [
    "critical:9", "critical:1", "high:2", "low:5", "informational:100",
  ]);
});
