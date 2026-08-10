// Tests for _buildActivityVerdict (electron/analyzers/file-activity.js).
// Pure logic — runs under plain `node --test` (no SQLite binding needed).
//
// The verdict's defining property: severity = impact, but CONFIDENCE is gated on forgery-resistant
// evidence so a $SI-only or timestomped burst is never presented as authoritative.

const test = require("node:test");
const assert = require("node:assert/strict");
const { _buildActivityVerdict } = require("../electron/analyzers/file-activity");

const win = (o = {}) => ({ mode: "created", bucket: "2024-01-06 03", count: 100, score: 10, weekend: true, offHours: true, riskyExtensionCount: 0, deletedCount: 0, ...o });

test("verdict: no activity → info / none, with the $SI caveat", () => {
  const v = _buildActivityVerdict({ suspiciousWindows: [], usnDeletionWindows: [], correlation: {} });
  assert.equal(v.severity, "info");
  assert.equal(v.confidence, "none");
  assert.match(v.headline, /No anomalous/i);
  assert.match(v.narrative, /\$SI|STANDARD_INFORMATION/);
  assert.deepEqual(v.mitre, []);
});

test("verdict: $SI-only burst, no companions → confidence 'observed'", () => {
  const v = _buildActivityVerdict({ suspiciousWindows: [win({ count: 320 })], usnDeletionWindows: [], correlation: { usnAvailable: false, evtxAvailable: false } });
  assert.equal(v.confidence, "observed");
  assert.match(v.narrative, /single-source \$SI|corroborate/i);
  assert.ok(["low", "medium"].includes(v.severity));
});

test("verdict: companions loaded but window not corroborated → 'weak'", () => {
  const v = _buildActivityVerdict({ suspiciousWindows: [win({ corroboration: { level: "uncorroborated", usn: { total: 0 }, evtx: { processCreations: 0 } } })], usnDeletionWindows: [], correlation: { usnAvailable: true, evtxAvailable: true } });
  assert.equal(v.confidence, "weak");
});

test("verdict: USN/EVTX-corroborated window → confidence 'corroborated'", () => {
  const v = _buildActivityVerdict({
    suspiciousWindows: [win({ count: 2140, riskyExtensionCount: 813, corroboration: { level: "strong", usn: { total: 1204, fileDelete: 12, contentWrite: 8, fileCreate: 5 }, evtx: { processCreations: 6 } } })],
    usnDeletionWindows: [], correlation: { usnAvailable: true, evtxAvailable: true },
  });
  assert.equal(v.confidence, "corroborated");
  assert.ok(["high", "critical"].includes(v.severity), "executable burst → high+");
  assert.ok(v.mitre.some((m) => m.technique === "T1105"));
  assert.ok(v.mitre.some((m) => m.technique === "T1074"), "large creation burst → Data Staged");
  assert.match(v.narrative, /USN corroborates/);
});

test("verdict: timestomping suspected caps confidence at 'low' even if corroborated, emits T1070.006", () => {
  const v = _buildActivityVerdict({
    suspiciousWindows: [win({ count: 600, riskyExtensionCount: 600, timestompSuspected: true, corroboration: { level: "corroborated", usn: { total: 50 } } })],
    usnDeletionWindows: [], correlation: { usnAvailable: true, evtxAvailable: false },
  });
  assert.equal(v.confidence, "low", "forgeable $SI must not read as corroborated");
  assert.ok(v.mitre.some((m) => m.technique === "T1070.006"));
  assert.ok(v.factors.some((f) => /timestomp/i.test(f.label)));
});

test("verdict: USN deletions → T1070.004 (corroborated); mass deletions → T1485", () => {
  const v = _buildActivityVerdict({
    suspiciousWindows: [win()],
    usnDeletionWindows: [{ bucket: "2024-01-06 03", count: 1500 }],
    correlation: { usnAvailable: true, evtxAvailable: false },
  });
  const del = v.mitre.find((m) => m.technique === "T1070.004");
  assert.ok(del && del.confidence === "corroborated", "USN-sourced deletion is corroborated, not just observed");
  assert.ok(v.mitre.some((m) => m.technique === "T1485"), "mass deletion → Data Destruction");
});

test("verdict: freed records are described as NOT confirmed deletions", () => {
  const v = _buildActivityVerdict({ suspiciousWindows: [win({ deletedCount: 40 })], usnDeletionWindows: [], correlation: {} });
  const f = v.factors.find((x) => /freed/i.test(x.label));
  assert.ok(f, "freed-records factor present");
  assert.match(f.detail, /NOT confirmed|true deletion time/i);
});

test("verdict: severity escalates with content signals, not pure volume", () => {
  // pure volume + off-hours alone stays at/below medium
  const volOnly = _buildActivityVerdict({ suspiciousWindows: [win({ count: 1500 })], usnDeletionWindows: [], correlation: {} });
  assert.ok(SEVLE(volOnly.severity, "medium"), "volume+timing alone ≤ medium");
  // add executable concentration + timestomp + USN deletes → high/critical
  const loaded = _buildActivityVerdict({
    suspiciousWindows: [win({ count: 1500, riskyExtensionCount: 1200, timestompSuspected: true })],
    usnDeletionWindows: [{ bucket: "2024-01-06 03", count: 800 }], correlation: { usnAvailable: true },
  });
  assert.ok(["high", "critical"].includes(loaded.severity));
  assert.ok(loaded.severityScore > volOnly.severityScore);
});

test("verdict: corroboration on a LOWER-ranked window does NOT lift the top window's confidence (no laundering)", () => {
  const v = _buildActivityVerdict({
    suspiciousWindows: [
      win({ bucket: "2024-01-06 03", count: 2000, score: 30, riskyExtensionCount: 1400 }), // top, uncorroborated
      win({ bucket: "2024-01-07 04", count: 15, score: 2, corroboration: { level: "corroborated", usn: { total: 9 } } }), // lower, corroborated
    ],
    usnDeletionWindows: [], correlation: { usnAvailable: true, evtxAvailable: true },
  });
  assert.notEqual(v.confidence, "corroborated", "a corroborated LOWER window must not launder the top");
  assert.equal(v.confidence, "weak");
  assert.ok(v.factors.some((f) => /lower-ranked/i.test(f.label)), "lower-corroborated window surfaced separately");
  assert.match(v.narrative, /top window above is not|single-source \$SI/i);
});

test("verdict: USN-only mass deletion drives high/critical severity (forgery-resistant impact, not capped at low)", () => {
  const mk = (n) => _buildActivityVerdict({ suspiciousWindows: [], usnDeletionWindows: [{ bucket: "2024-01-06 03", count: n }], correlation: { usnAvailable: true } });
  const v1k = mk(1000), v100k = mk(100000);
  assert.ok(["high", "critical"].includes(v1k.severity), `1k USN deletes → ${v1k.severity}, not low`);
  assert.equal(v100k.severity, "critical", "100k deletes → critical");
  assert.equal(v1k.confidence, "corroborated", "USN-only verdict rests on forgery-resistant evidence");
  assert.ok(v1k.mitre.some((m) => m.technique === "T1485" && m.confidence === "corroborated"));
});

test("verdict: T1105/T1074 (ingress/staging) only for a CREATED-axis window, not modified", () => {
  const created = _buildActivityVerdict({ suspiciousWindows: [win({ mode: "created", count: 400, riskyExtensionCount: 400 })], usnDeletionWindows: [], correlation: {} });
  const modified = _buildActivityVerdict({ suspiciousWindows: [win({ mode: "modified", count: 400, riskyExtensionCount: 400 })], usnDeletionWindows: [], correlation: {} });
  assert.ok(created.mitre.some((m) => m.technique === "T1105"), "created burst → ingress candidate");
  assert.ok(created.mitre.some((m) => m.technique === "T1074"));
  assert.ok(!modified.mitre.some((m) => m.technique === "T1105"), "modified executables are not ingress");
});

// severity-rank helper: is `a` no more severe than `b`?
function SEVLE(a, b) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return rank[a] >= rank[b];
}
