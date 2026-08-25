// Unit tests for the ransomware engine's pure synthesis helpers (encryption-method
// inference, recovery-prospects scoring, incident verdict). These are DB-free pure
// functions, so we require the analyzer directly — no MFT fixture needed.

const test = require("node:test");
const assert = require("node:assert/strict");
const rw = require("../electron/analyzers/ransomware");

const { _inferEncryptionMethod, _buildRecoveryProspects, _buildIncidentSummary, _rwIsResidentSize, _fmtBytes, _fmtDurationShort, _identifyFamily, _buildMitreMapping, _buildIncidentTimeline, _rwBucketMs, _familyForExtension, _buildBlastTreemap, _buildScoping, _rwResolveEvtxCols, _rwLooksLikeEvtx, _rwCategorizeEvasion, _rwExtractProcFields, _rwBasename, _rwProcMatchesFile, _rwFindBurst, _buildInPlaceAssessment, _rwInPlaceCategory } = rw;

const mkEvtxMeta = (headers, sourceFormat) => ({ headers, sourceFormat: sourceFormat || null, colMap: Object.fromEntries(headers.map((h, i) => [h, "c" + i])) });

// Build an originalPairs object shaped like what analyzeRansomware produces.
function mkPairs(over = {}) {
  const confirmed = over.confirmedSampleCount ?? 0;
  const likely = over.likelySampleCount ?? 0;
  return {
    confirmedPairs: over.confirmedPairs ?? confirmed,
    likelyPairs: over.likelyPairs ?? likely,
    confirmedSampleCount: confirmed,
    likelySampleCount: likely,
    residentSampleCount: over.residentSampleCount ?? 0,
    sampleSize: over.sampleSize ?? (confirmed + likely),
    samplePopulation: over.samplePopulation ?? (confirmed + likely),
    pairRate: over.pairRate ?? 0,
    sampled: over.sampled ?? false,
    ...over,
  };
}

// ---------- _rwIsResidentSize ----------

test("_rwIsResidentSize: small files are resident, large/empty are not", () => {
  assert.equal(_rwIsResidentSize(120), true);
  assert.equal(_rwIsResidentSize(700), true);
  assert.equal(_rwIsResidentSize(701), false);
  assert.equal(_rwIsResidentSize(0), false);
  assert.equal(_rwIsResidentSize(""), false);
  assert.equal(_rwIsResidentSize("512"), true);     // string sizes from SQLite
  assert.equal(_rwIsResidentSize("1,048,576"), false);
});

// ---------- _inferEncryptionMethod ----------

test("encryption method: deleted originals dominate → copy-delete", () => {
  const m = _inferEncryptionMethod(mkPairs({ confirmedSampleCount: 80, likelySampleCount: 10 }), 9000, 30);
  assert.equal(m.method, "copy-delete");
  assert.equal(m.confidence, "high");          // 0.89 confirmedFrac
  assert.ok(m.filesPerSecond > 0);
});

test("encryption method: originals gone with no deleted entry → overwrite", () => {
  const m = _inferEncryptionMethod(mkPairs({ confirmedSampleCount: 4, likelySampleCount: 96 }), 5000, 20);
  assert.equal(m.method, "overwrite");
});

test("encryption method: no pair mapping → indeterminate", () => {
  const m = _inferEncryptionMethod(mkPairs({ confirmedSampleCount: 0, likelySampleCount: 0 }), 1000, 10);
  assert.equal(m.method, "indeterminate");
  assert.equal(m.confidence, "low");
});

test("encryption method: balanced → mixed", () => {
  const m = _inferEncryptionMethod(mkPairs({ confirmedSampleCount: 40, likelySampleCount: 60 }), 4000, 40);
  assert.equal(m.method, "mixed");
});

// ---------- _buildRecoveryProspects ----------

test("recovery: copy-delete with no backups hit → Moderate, carving viable", () => {
  const op = mkPairs({ confirmedSampleCount: 70, likelySampleCount: 20, confirmedPairs: 7000, likelyPairs: 2000 });
  const method = _inferEncryptionMethod(op, 9000, 30);
  const r = _buildRecoveryProspects(op, method, 0, { cleanup: [], drops: [], timestomped: [], deletedEncrypted: [] });
  assert.equal(r.outlook, "Moderate");
  assert.equal(r.carvableCount, 7000);
  assert.equal(r.avenues.find((a) => a.name.includes("carving")).viability, "Viable");
});

test("recovery: overwrite + backups encrypted → Low", () => {
  const op = mkPairs({ confirmedSampleCount: 5, likelySampleCount: 95, confirmedPairs: 500, likelyPairs: 9500 });
  const method = _inferEncryptionMethod(op, 10000, 25);
  const r = _buildRecoveryProspects(op, method, 1200, { cleanup: [], drops: [], timestomped: [], deletedEncrypted: [] });
  assert.equal(r.outlook, "Low");
  assert.equal(r.backupsEncrypted, 1200);
  assert.equal(r.avenues.find((a) => a.name.includes("Offline")).viability, "On-host compromised");
});

test("recovery: at exactly 30% carvable with backups encrypted → Low (boundary, <=0.3)", () => {
  // mixed method (confirmedFrac 0.35) so the overwrite branch doesn't fire; carvableShare = 300/1000 = 0.3.
  const op = mkPairs({ confirmedSampleCount: 35, likelySampleCount: 65, confirmedPairs: 300, likelyPairs: 700 });
  const method = _inferEncryptionMethod(op, 1000, 20);
  assert.equal(method.method, "mixed");
  const r = _buildRecoveryProspects(op, method, 500, { cleanup: [], drops: [], timestomped: [], deletedEncrypted: [] });
  assert.equal(r.outlook, "Low"); // 0.3 <= 0.3 with backups encrypted → Low, not Moderate
});

test("recovery: resident originals are extrapolated and bump a Low outlook", () => {
  // sampled: 10 resident of 100 sample → scale 100 → ~1000 resident recoverable.
  const op = mkPairs({ confirmedSampleCount: 8, likelySampleCount: 92, confirmedPairs: 800, likelyPairs: 9200,
    residentSampleCount: 10, sampleSize: 100, samplePopulation: 10000, sampled: true });
  const method = _inferEncryptionMethod(op, 10000, 20); // overwrite → Low
  const r = _buildRecoveryProspects(op, method, 0, { cleanup: [], drops: [], timestomped: [], deletedEncrypted: [] });
  assert.equal(r.residentRecoverableCount, 1000);
  assert.equal(r.outlook, "Low–Moderate");
});

// ---------- _buildIncidentSummary ----------

test("incident verdict: large fast attack with backups + low recovery → Critical", () => {
  const op = mkPairs({ confirmedSampleCount: 5, likelySampleCount: 95, confirmedPairs: 500, likelyPairs: 9500 });
  const method = _inferEncryptionMethod(op, 184000, 192);
  const recovery = _buildRecoveryProspects(op, method, 1200, { cleanup: [{}], drops: [{}], timestomped: [], deletedEncrypted: [] });
  const s = _buildIncidentSummary({
    encryptedCount: 184000, totalEncryptedSizeBytes: 980 * 1024 * 1024 * 1024, durationMinutes: 192,
    filesPerMinute: 958, peakPerMinute: 450, firstTs: "2024-01-15 10:14:23",
    ransomNoteCount: 1200, notePathCount: 980, backupRecoveryTotal: 1200,
    deletedEncrypted: 500, timestompedCount: 0, antiForensicsCount: 2, method, recovery,
  });
  assert.equal(s.severity, "Critical");
  assert.match(s.headline, /^Critical: 184,000 files/);
  assert.match(s.narrative, /starting 2024-01-15 10:14:23 UTC/);
  assert.match(s.narrative, /in-place overwrite/);
  assert.match(s.narrative, /Recovery outlook: Low/);
  assert.ok(s.factors.some((f) => f.label === "Backups hit" && f.value === "1,200"));
});

test("incident verdict: tiny benign-scale event → Low", () => {
  const op = mkPairs({ confirmedSampleCount: 30, likelySampleCount: 5, confirmedPairs: 30, likelyPairs: 5 });
  const method = _inferEncryptionMethod(op, 35, 4);
  const recovery = _buildRecoveryProspects(op, method, 0, { cleanup: [], drops: [], timestomped: [], deletedEncrypted: [] });
  const s = _buildIncidentSummary({
    encryptedCount: 35, totalEncryptedSizeBytes: 2 * 1024 * 1024, durationMinutes: 4,
    filesPerMinute: 8, peakPerMinute: 12, firstTs: "2024-03-01 02:00:00",
    ransomNoteCount: 0, notePathCount: 0, backupRecoveryTotal: 0,
    deletedEncrypted: 0, timestompedCount: 0, antiForensicsCount: 0, method, recovery,
  });
  assert.equal(s.severity, "Low");
});

// ---------- _identifyFamily ----------

const notes = (...names) => names.map((fileName) => ({ fileName }));

test("family: LockBit by extension", () => {
  const f = _identifyFamily([".lockbit"], []);
  assert.equal(f.top.name, "LockBit");
  assert.equal(f.top.confidence, "high");
  assert.deepEqual(f.top.matchedOn, ["extension"]);
});

test("family: STOP/Djvu by its distinctive _readme.txt note", () => {
  const f = _identifyFamily([".docx.locked"], notes("_readme.txt"));
  assert.equal(f.top.name, "STOP/Djvu");
  assert.deepEqual(f.top.matchedOn, ["ransom note"]);
  assert.equal(f.top.confidence, "medium"); // note-only is weaker than a family-specific extension
});

test("family: extension + note both match → confirmed, ranked first", () => {
  const f = _identifyFamily([".akira"], notes("akira_readme.txt", "readme.txt"));
  assert.equal(f.top.name, "Akira");
  assert.equal(f.top.confidence, "confirmed");
  assert.deepEqual(f.top.matchedOn.sort(), ["extension", "ransom note"]);
});

test("family: no signature match → empty candidates with guidance note", () => {
  const f = _identifyFamily([".xyzzy"], notes("some-random-name.txt"));
  assert.equal(f.candidates.length, 0);
  assert.equal(f.top, null);
  assert.match(f.note, /No known-family signature/);
});

test("family: Dharma/CrySiS by its namesake .crysis extension", () => {
  const f = _identifyFamily([".crysis"], []);
  assert.equal(f.top.name, "Dharma");
});

test("family: tolerates null / fileName-less ransom-note entries", () => {
  const f = _identifyFamily([".lockbit"], [null, undefined, {}, { fileName: "restore-my-files.txt" }]);
  assert.equal(f.top.name, "LockBit");
  assert.equal(f.top.confidence, "confirmed"); // ext + note both matched, null entries ignored
});

test("family: WannaCry by extension and note", () => {
  const f = _identifyFamily([".wncry"], notes("@please_read_me@.txt"));
  assert.equal(f.top.name, "WannaCry");
  assert.equal(f.top.confidence, "confirmed");
});

// ---------- _familyForExtension (auto-detect family flagging) ----------

test("family-for-extension: known family extensions resolve, case-insensitively", () => {
  assert.equal(_familyForExtension(".lockbit"), "LockBit");
  assert.equal(_familyForExtension(".LOCKBIT"), "LockBit");
  assert.equal(_familyForExtension(".akira"), "Akira");
  assert.equal(_familyForExtension(".crysis"), "Dharma");
  assert.equal(_familyForExtension(".basta"), "Black Basta");
});

test("family-for-extension: unknown / empty extensions return null", () => {
  assert.equal(_familyForExtension(".xyzzy"), null);
  assert.equal(_familyForExtension(""), null);
  assert.equal(_familyForExtension(null), null);
});

// ---------- _buildMitreMapping ----------

test("MITRE: encryption always maps T1486; backups → T1490; timestomp → T1070.006; deletion → T1485/T1070.004", () => {
  const m = _buildMitreMapping({
    encryptedCount: 5000, ransomNoteCount: 12, backupRecoveryTotal: 40,
    deletedEncrypted: 300, timestompedCount: 25,
    antiForensics: { cleanup: [{}, {}], drops: [{}] },
  });
  const ids = m.map((t) => t.id);
  assert.ok(ids.includes("T1486"));
  assert.ok(ids.includes("T1490"));
  assert.ok(ids.includes("T1485"));
  assert.ok(ids.includes("T1070.004"));
  assert.ok(ids.includes("T1070.006"));
  assert.match(m.find((t) => t.id === "T1486").url, /attack\.mitre\.org\/techniques\/T1486\//);
  assert.match(m.find((t) => t.id === "T1070.006").url, /T1070\/006\//);
});

test("MITRE: clean impact-only event maps just T1486", () => {
  const m = _buildMitreMapping({ encryptedCount: 80, ransomNoteCount: 0, backupRecoveryTotal: 0, deletedEncrypted: 0, timestompedCount: 0, antiForensics: { cleanup: [], drops: [] } });
  assert.deepEqual(m.map((t) => t.id), ["T1486"]);
});

// ---------- _buildIncidentTimeline ----------

test("incident timeline: fuses streams, finds window + peak + onset", () => {
  const tl = _buildIncidentTimeline({
    timeline: [
      { bucket: "2024-01-15 10:14", count: 20 },
      { bucket: "2024-01-15 10:15", count: 400 }, // peak
      { bucket: "2024-01-15 10:16", count: 120 },
    ],
    ransomNotes: [{ created: "2024-01-15 10:15:30" }, { created: "2024-01-15 10:15:50" }, { created: "2024-01-15 10:16:10" }],
    suspiciousFiles: [{ created: "2024-01-15 10:13:05" }],
    usnEnrichment: {
      preciseStartTime: "2024-01-15 10:14:02",
      deleteBuckets: [{ bucket: "2024-01-15 10:16", count: 90 }],
      overwriteBuckets: [{ bucket: "2024-01-15 10:15", count: 380 }],
    },
    firstTs: "2024-01-15 10:14:02",
  });
  assert.equal(tl.startMs, Date.UTC(2024, 0, 15, 10, 13)); // earliest = payload drop 10:13
  assert.equal(tl.endMs, Date.UTC(2024, 0, 15, 10, 16));
  assert.equal(tl.onsetMs, Date.UTC(2024, 0, 15, 10, 14)); // preciseStartTime minute
  assert.equal(tl.peakCount, 400);
  assert.equal(tl.peakMs, Date.UTC(2024, 0, 15, 10, 15));
  assert.equal(tl.encryption.length, 3);
  assert.equal(tl.notes.length, 2);     // 10:15 (x2 binned) + 10:16
  assert.equal(tl.notes.find((n) => n.ms === Date.UTC(2024, 0, 15, 10, 15)).count, 2);
  assert.equal(tl.totals.notes, 3);
  assert.equal(tl.totals.deletes, 90);
  assert.equal(tl.totals.overwrites, 380);
});

test("incident timeline: no datable events → null", () => {
  assert.equal(_buildIncidentTimeline({ timeline: [], ransomNotes: [], suspiciousFiles: [], usnEnrichment: null }), null);
});

test("incident timeline: tolerates null bucket/created entries", () => {
  const tl = _buildIncidentTimeline({
    timeline: [{ bucket: null, count: 5 }, { bucket: "2024-02-01 03:00", count: 10 }],
    ransomNotes: [null, { created: null }, { created: "2024-02-01 03:01:00" }],
    suspiciousFiles: null, usnEnrichment: undefined, firstTs: null,
  });
  assert.equal(tl.encryption.length, 1);
  assert.equal(tl.notes.length, 1);
});

test("_rwBucketMs parses minute and second forms as UTC", () => {
  assert.equal(_rwBucketMs("2024-01-15 10:14"), Date.UTC(2024, 0, 15, 10, 14));
  assert.equal(_rwBucketMs("2024-01-15 10:14:59"), Date.UTC(2024, 0, 15, 10, 14)); // seconds dropped to the minute
  assert.equal(_rwBucketMs("2024-01-15T10:14:00"), Date.UTC(2024, 0, 15, 10, 14));
  assert.equal(_rwBucketMs("garbage"), null);
  assert.equal(_rwBucketMs(null), null);
});

// ---------- _buildBlastTreemap (squarified layout) ----------

test("blast treemap: rects tile the space, in bounds, areas proportional to encryptedCount", () => {
  const dirs = [
    { path: ".\\Finance", encryptedCount: 5000, totalCount: 5200, ratio: 0.96 },
    { path: ".\\Users\\alice", encryptedCount: 2000, totalCount: 8000, ratio: 0.25 },
    { path: ".\\Shared", encryptedCount: 1500, totalCount: 1500, ratio: 1.0 },
    { path: ".\\HR", encryptedCount: 800, totalCount: 1000, ratio: 0.8 },
    { path: ".\\Archive", encryptedCount: 200, totalCount: 4000, ratio: 0.05 },
  ];
  const W = 1000, H = 400;
  const tm = _buildBlastTreemap(dirs, W, H);
  assert.equal(tm.rects.length, 5);
  assert.equal(tm.shown, 5);
  assert.equal(tm.totalDirs, 5);
  // all rects within bounds
  for (const r of tm.rects) {
    assert.ok(r.x >= -0.01 && r.y >= -0.01, `rect origin in bounds: ${r.path}`);
    assert.ok(r.x + r.w <= W + 0.5 && r.y + r.h <= H + 0.5, `rect extent in bounds: ${r.path}`);
    assert.ok(r.w >= 0 && r.h >= 0);
  }
  // total rect area ≈ canvas area (squarify tiles the full space)
  const area = tm.rects.reduce((s, r) => s + r.w * r.h, 0);
  assert.ok(Math.abs(area - W * H) / (W * H) < 0.02, `area covers canvas (got ${Math.round(area)} vs ${W * H})`);
  // proportionality: Finance (5000) rect area ≈ 2.5× Users (2000)
  const fin = tm.rects.find((r) => r.path === ".\\Finance");
  const usr = tm.rects.find((r) => r.path === ".\\Users\\alice");
  const ratio = (fin.w * fin.h) / (usr.w * usr.h);
  assert.ok(Math.abs(ratio - 2.5) < 0.15, `area ratio proportional to value (got ${ratio.toFixed(2)})`);
});

test("blast treemap: caps at 16 directories, sorted by encryptedCount desc", () => {
  const dirs = Array.from({ length: 30 }, (_, i) => ({ path: `.\\d${i}`, encryptedCount: (30 - i) * 10, totalCount: (30 - i) * 10, ratio: 1 }));
  const tm = _buildBlastTreemap(dirs);
  assert.equal(tm.shown, 16);
  assert.equal(tm.totalDirs, 30);
  assert.equal(tm.rects[0].path, ".\\d0"); // largest first
});

test("blast treemap: empty / zero-value input → null", () => {
  assert.equal(_buildBlastTreemap([]), null);
  assert.equal(_buildBlastTreemap([{ path: ".\\x", encryptedCount: 0 }]), null);
  assert.equal(_buildBlastTreemap(null), null);
});

// ---------- _buildScoping (by area / user) ----------

test("scoping: aggregates by top-level area and by user profile", () => {
  const encDirs = [
    { path: ".\\Users\\alice\\Documents", count: 1200 },
    { path: ".\\Users\\alice\\Desktop", count: 300 },
    { path: ".\\Users\\bob\\Documents", count: 500 },
    { path: ".\\ProgramData\\SQL", count: 2000 },
    { path: ".\\Users\\Public\\Shared", count: 100 }, // Public excluded from user scoping
  ];
  const s = _buildScoping(encDirs, 4100);
  // areas
  assert.equal(s.byArea.find((a) => a.name === "ProgramData").count, 2000);
  assert.equal(s.byArea.find((a) => a.name === "Users").count, 2100); // alice 1500 + bob 500 + public 100
  // users (Public excluded)
  assert.equal(s.userCount, 2);
  assert.equal(s.byUser.find((u) => u.name === "alice").count, 1500);
  assert.equal(s.byUser.find((u) => u.name === "bob").count, 500);
  assert.equal(s.byUser.find((u) => u.name === "Public"), undefined);
  // pct relative to encryptedCount (4100)
  assert.ok(Math.abs(s.byArea.find((a) => a.name === "ProgramData").pct - 0.488) < 0.002);
  assert.equal(s.coverage, 1); // total 4100 == encryptedCount
});

test("scoping: merges areas/users case-insensitively, keeps first-seen casing", () => {
  const s = _buildScoping([
    { path: ".\\Users\\Alice\\Docs", count: 100 },
    { path: ".\\users\\alice\\Desktop", count: 50 },  // same area + user, different casing
    { path: ".\\USERS\\ALICE\\Pics", count: 25 },
  ], 175);
  assert.equal(s.areaCount, 1);
  assert.equal(s.byArea[0].name, "Users");   // first-seen casing
  assert.equal(s.byArea[0].count, 175);
  assert.equal(s.userCount, 1);
  assert.equal(s.byUser[0].name, "Alice");
  assert.equal(s.byUser[0].count, 175);
});

test("scoping: single user → targeted note", () => {
  const s = _buildScoping([{ path: ".\\Users\\victim\\Documents", count: 800 }], 800);
  assert.equal(s.userCount, 1);
  assert.match(s.note, /single user profile \(victim\)/);
});

test("scoping: coverage <1 when encryptedCount exceeds the considered dirs", () => {
  const s = _buildScoping([{ path: ".\\Users\\a\\x", count: 100 }], 1000);
  assert.equal(s.coverage, 0.1);
});

test("scoping: empty / zero → null", () => {
  assert.equal(_buildScoping([], 0), null);
  assert.equal(_buildScoping([{ path: ".\\x", count: 0 }], 0), null);
  assert.equal(_buildScoping(null, 100), null);
});

// ---------- EVTX cross-artifact correlation helpers ----------

test("evtx cols: resolves timestamp/eventID/text columns to SAFE names (EvtxECmd)", () => {
  const meta = mkEvtxMeta(["TimeCreated", "EventId", "Channel", "ExecutableInfo", "PayloadData1", "PayloadData5", "Computer"]);
  const c = _rwResolveEvtxCols(meta);
  assert.equal(c.ts, "c0");   // TimeCreated
  assert.equal(c.eid, "c1");  // EventId
  assert.ok(c.textCols.includes("c3")); // ExecutableInfo
  assert.ok(c.textCols.includes("c4")); // PayloadData1
});

test("evtx cols: resolves Hayabusa columns (Timestamp / EventID / Details)", () => {
  const c = _rwResolveEvtxCols(mkEvtxMeta(["Timestamp", "Channel", "EventID", "RuleTitle", "Details", "ExtraFieldInfo"]));
  assert.equal(c.ts, "c0");
  assert.equal(c.eid, "c2");
  assert.ok(c.textCols.includes("c4")); // Details
});

test("looksLikeEvtx: raw-evtx by sourceFormat; EvtxECmd/Hayabusa by headers; MFT is not", () => {
  assert.equal(_rwLooksLikeEvtx({ sourceFormat: "raw-evtx" }), true);
  assert.equal(_rwLooksLikeEvtx(mkEvtxMeta(["TimeCreated", "EventId", "ExecutableInfo"])), true);
  assert.equal(_rwLooksLikeEvtx(mkEvtxMeta(["Timestamp", "EventID", "Details"])), true);
  assert.equal(_rwLooksLikeEvtx(mkEvtxMeta(["Extension", "FileName", "ParentPath"])), false); // MFT
  assert.equal(_rwLooksLikeEvtx(null), false);
});

test("categorize evasion: VSS / backup / recovery / log-clear / service map to MITRE", () => {
  assert.deepEqual(_rwCategorizeEvasion("4688", "C:\\Windows\\System32\\vssadmin.exe delete shadows /all /quiet"), { category: "Volume Shadow Copies deleted", technique: "T1490" });
  assert.deepEqual(_rwCategorizeEvasion("1", "wbadmin delete catalog -quiet"), { category: "Windows backups deleted", technique: "T1490" });
  assert.equal(_rwCategorizeEvasion("1", "bcdedit /set {default} recoveryenabled No").technique, "T1490");
  assert.equal(_rwCategorizeEvasion("1", "cipher /w:C").technique, "T1490");
  assert.deepEqual(_rwCategorizeEvasion("1102", ""), { category: "Security event log cleared", technique: "T1070.001" });
  assert.equal(_rwCategorizeEvasion("1", "wevtutil cl Security").technique, "T1070.001");
  assert.equal(_rwCategorizeEvasion("7045", "").technique, "T1569.002");
  // bare tool reference without a destructive verb → "review" (no technique claimed, avoids T1490 FP)
  assert.equal(_rwCategorizeEvasion("4688", "vssadmin list shadows").technique, null);
  assert.equal(_rwCategorizeEvasion("4104", "some unrelated text").technique, null);
});

test("MITRE mapping folds in EVTX evidence (T1490 strengthened, T1070.001 / T1569.002 added)", () => {
  const m = _buildMitreMapping({
    encryptedCount: 5000, ransomNoteCount: 3, backupRecoveryTotal: 10, deletedEncrypted: 0, timestompedCount: 0,
    antiForensics: { cleanup: [], drops: [] },
    evtx: { byTechnique: { "T1490": 4, "T1070.001": 2, "T1569.002": 1 } },
  });
  const t1490 = m.find((t) => t.id === "T1490");
  assert.ok(t1490 && /EVTX shadow-copy/.test(t1490.basis)); // strengthened with EVTX basis
  assert.ok(m.some((t) => t.id === "T1070.001"));
  assert.ok(m.some((t) => t.id === "T1569.002"));
});

// ---------- formatters ----------

test("formatters: bytes and duration", () => {
  assert.equal(_fmtBytes(0), "0 B");
  assert.equal(_fmtBytes(512), "512 B");
  assert.equal(_fmtBytes(1024), "1 KB");
  assert.equal(_fmtBytes(1536), "1.5 KB");
  assert.equal(_fmtBytes(5 * 1024 * 1024 * 1024), "5 GB");
  assert.equal(_fmtDurationShort(0), "<1m");
  assert.equal(_fmtDurationShort(42), "42m");
  assert.equal(_fmtDurationShort(192), "3h12m");
  assert.equal(_fmtDurationShort(120), "2h");
});

// --- Process-execution correlation (Q7b) ---

test("extract proc fields: Sysmon EID 1 flattened EventData", () => {
  const txt = "RuleName: - UtcTime: 2026-05-30 12:00:01 Image: C:\\Users\\Public\\locker.exe FileVersion: - CommandLine: \"C:\\Users\\Public\\locker.exe\" -enc ParentImage: C:\\Windows\\System32\\cmd.exe ParentCommandLine: cmd.exe /c locker.exe User: VICTIM\\jdoe IntegrityLevel: High";
  const f = _rwExtractProcFields(txt);
  assert.equal(f.image, "C:\\Users\\Public\\locker.exe");
  assert.equal(f.cmdLine, "\"C:\\Users\\Public\\locker.exe\" -enc");
  assert.equal(f.parentImage, "C:\\Windows\\System32\\cmd.exe");
  assert.equal(f.user, "VICTIM\\jdoe");
});

test("extract proc fields: Security EID 4688 field names (NewProcessName / SubjectUserName)", () => {
  const txt = "SubjectUserName: jdoe SubjectDomainName: VICTIM NewProcessName: C:\\ProgramData\\svc.exe ProcessCommandLine: svc.exe /run ParentProcessName: C:\\Windows\\explorer.exe TokenElevationType: %%1936";
  const f = _rwExtractProcFields(txt);
  assert.equal(f.image, "C:\\ProgramData\\svc.exe");
  assert.equal(f.cmdLine, "svc.exe /run");
  assert.equal(f.parentImage, "C:\\Windows\\explorer.exe");
  assert.equal(f.user, "jdoe");
});

test("extract proc fields: Hayabusa Details with broken-bar separators", () => {
  const txt = "Proc: C:\\Temp\\ryuk.exe ¦ Cmdline: ryuk.exe 8 ¦ ParentCmdline: C:\\Windows\\psexesvc.exe ¦ User: SYSTEM ¦ LID: 0x3e7";
  const f = _rwExtractProcFields(txt);
  assert.equal(f.image, "C:\\Temp\\ryuk.exe");
  assert.equal(f.cmdLine, "ryuk.exe 8");
  assert.equal(f.parentImage, "C:\\Windows\\psexesvc.exe"); // falls back to ParentCmdline
  assert.equal(f.user, "SYSTEM");
});

test("extract proc fields: command line containing commas is not truncated", () => {
  const f = _rwExtractProcFields("Image: C:\\a.exe CommandLine: a.exe -p one,two,three -q\nUser: SYSTEM");
  assert.equal(f.cmdLine, "a.exe -p one,two,three -q");
  assert.equal(f.user, "SYSTEM");
});

test("extract proc fields: missing fields → nulls, empty/garbage → all null", () => {
  const f = _rwExtractProcFields("Image: C:\\only.exe");
  assert.equal(f.image, "C:\\only.exe");
  assert.equal(f.cmdLine, null);
  assert.equal(f.parentImage, null);
  assert.equal(f.user, null);
  const g = _rwExtractProcFields("");
  assert.deepEqual(g, { image: null, cmdLine: null, parentImage: null, user: null });
  const h = _rwExtractProcFields(null);
  assert.deepEqual(h, { image: null, cmdLine: null, parentImage: null, user: null });
});

test("basename: final path component, lowercased, quote-stripped", () => {
  assert.equal(_rwBasename("C:\\Users\\Public\\Locker.EXE"), "locker.exe");
  assert.equal(_rwBasename("/usr/bin/foo"), "foo");
  assert.equal(_rwBasename("\"C:\\a\\b.exe\""), "b.exe");
  assert.equal(_rwBasename("bare.exe"), "bare.exe");
  assert.equal(_rwBasename(null), "");
});

test("proc match: confirms via image basename equality and bounded cmdline token", () => {
  assert.equal(_rwProcMatchesFile({ image: "C:\\Users\\Public\\locker.exe" }, "locker.exe"), true);
  assert.equal(_rwProcMatchesFile({ image: "C:\\Windows\\System32\\cmd.exe", cmdLine: "cmd.exe /c \"C:\\Temp\\locker.exe\" -enc" }, "locker.exe"), true);
  // quoted token in command line, image is the shell
  assert.equal(_rwProcMatchesFile({ cmdLine: "powershell -c .\\dropper.exe" }, "dropper.exe"), true);
});

// --- In-place / overwrite encryption detection (Q7c) ---

test("inplace category: business data in scope; code/backups/system excluded", () => {
  assert.equal(_rwInPlaceCategory(".docx"), "Documents");
  assert.equal(_rwInPlaceCategory("xlsx"), "Spreadsheets"); // dot-less tolerated
  assert.equal(_rwInPlaceCategory(".jpg"), "Images & Design");
  assert.equal(_rwInPlaceCategory(".mdf"), "Databases");
  assert.equal(_rwInPlaceCategory(".ps1"), null);  // Source Code — excluded (dev churn)
  assert.equal(_rwInPlaceCategory(".bak"), null);  // Backups & Recovery — excluded (DB churn)
  assert.equal(_rwInPlaceCategory(".exe"), null);
  assert.equal(_rwInPlaceCategory(null), null);
});

test("find burst: picks densest contiguous run, respects gap, honors minFiles", () => {
  const bk = [
    { bucket: "2026-05-30 01:00", cnt: 5, dirCount: 2 },   // isolated (>5min gap) + below min → dropped
    { bucket: "2026-05-30 03:00", cnt: 40, dirCount: 5 },
    { bucket: "2026-05-30 03:01", cnt: 50, dirCount: 6 },
    { bucket: "2026-05-30 03:02", cnt: 30, dirCount: 4 },
    { bucket: "2026-05-30 09:00", cnt: 35, dirCount: 3 },  // separate run, smaller total
  ];
  const b = _rwFindBurst(bk, { maxGapMin: 5, minFiles: 30 });
  assert.equal(b.total, 120);
  assert.equal(b.peak, 50);
  assert.equal(b.dirPeak, 6);
  assert.equal(b.durationMinutes, 3);
  assert.equal(b.buckets.length, 3);
});

test("find burst: nothing reaches minFiles → null; empty → null", () => {
  assert.equal(_rwFindBurst([{ bucket: "2026-05-30 01:00", cnt: 5, dirCount: 1 }], { minFiles: 30 }), null);
  assert.equal(_rwFindBurst([], {}), null);
  assert.equal(_rwFindBurst(null, {}), null);
});

const _ipBurst = (over = {}) => ({
  startMs: 0, endMs: 0, total: over.total ?? 200, peak: over.peak ?? 60, dirPeak: over.dirPeak ?? 6,
  durationMinutes: over.durationMinutes ?? 4,
  buckets: over.buckets ?? [
    { bucket: "2026-05-30 02:00", count: 60, dirCount: 6 },
    { bucket: "2026-05-30 02:01", count: 70, dirCount: 5 },
    { bucket: "2026-05-30 02:02", count: 40, dirCount: 4 },
    { bucket: "2026-05-30 02:03", count: 30, dirCount: 3 },
  ],
});
const _ipSamples = (n = 12) => Array.from({ length: n }, (_, i) => ({
  fileName: `report${i}.docx`, parentPath: `.\\Users\\u${i % 4}\\Documents`, extension: i % 2 ? ".docx" : ".xlsx",
  created0x10: "2026-05-20 10:00:00", lastMod0x10: "2026-05-30 02:01:30", lastMod0x30: "2026-05-20 10:00:00",
}));
const _ipExt = [{ extension: ".docx", count: 120 }, { extension: ".xlsx", count: 80 }];

test("inplace: MFT-only burst → available, MEDIUM, suspicion-only (no USN)", () => {
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst(), samples: _ipSamples(), extBreakdown: _ipExt, usnOverwriteNoRename: null, processCorrelation: null });
  assert.equal(r.available, true);
  assert.equal(r.confidence, "medium"); // MFT-only ceiling
  assert.equal(r.isSuspicionOnly, true);
  assert.equal(r.candidateFileCount, 200);
  assert.equal(r.signals.find((s) => s.id === "S3").fired, false);
  assert.equal(r.signals.find((s) => s.id === "S4").fired, true);
  assert.equal(r.extensionBreakdown.length, 2);
  assert.ok(r.disclaimer && /not proof/i.test(r.disclaimer));
});

test("inplace: USN DataOverwrite-without-rename aligned → HIGH, not suspicion-only", () => {
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst(), samples: _ipSamples(), extBreakdown: _ipExt, usnOverwriteNoRename: { total: 180, alignedMinutes: 3, overwriteTotal: 170, overwriteAligned: 3 }, processCorrelation: null });
  assert.equal(r.confidence, "high");
  assert.equal(r.isSuspicionOnly, false);
  assert.equal(r.signals.find((s) => s.id === "S3").fired, true);
});

test("inplace: DataExtend-only aligned (no DataOverwrite) caps at MEDIUM, stays suspicion-only", () => {
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst(), samples: _ipSamples(), extBreakdown: _ipExt, usnOverwriteNoRename: { total: 100, alignedMinutes: 3, overwriteTotal: 0, overwriteAligned: 0 }, processCorrelation: null });
  assert.equal(r.confidence, "medium"); // DataExtend can be benign growth — never alone reaches high
  assert.equal(r.isSuspicionOnly, true);
  assert.equal(r.signals.find((s) => s.id === "S3").fired, false);
});

test("inplace: freshly-created-heavy burst is force-downgraded to LOW even with DataOverwrite", () => {
  // created0x10 ≈ lastMod0x10 (within grace) → files were CREATED in the window, not rewritten
  const fresh = Array.from({ length: 10 }, (_, i) => ({ fileName: `new${i}.docx`, parentPath: `.\\Users\\u${i % 4}\\Documents`, extension: i % 2 ? ".docx" : ".xlsx", created0x10: "2026-05-30 02:00:00", lastMod0x10: "2026-05-30 02:01:30", lastMod0x30: "2026-05-30 02:00:00" }));
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst(), samples: fresh, extBreakdown: _ipExt, usnOverwriteNoRename: { total: 180, alignedMinutes: 3, overwriteTotal: 170, overwriteAligned: 3 }, processCorrelation: null });
  assert.equal(r.confidence, "low");
  assert.match(r.reason, /created|bulk file creation|not in-place/i);
});

test("inplace: UNRECOGNIZED process surfaces a caveat but does NOT downgrade (no false benign)", () => {
  const pc = { available: true, processes: [{ image: "C:\\Users\\bob\\AppData\\Local\\AcmeBackup\\datasync.exe", cmdLine: "", risky: false, evasion: false, matchedPayload: false }] };
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst(), samples: _ipSamples(), extBreakdown: _ipExt, usnOverwriteNoRename: { total: 180, alignedMinutes: 3, overwriteTotal: 170, overwriteAligned: 3 }, processCorrelation: pc });
  assert.equal(r.evtxDisposition, "none");
  assert.equal(r.confidence, "high"); // unknown process is NOT auto-benign — detection preserved
  assert.match(r.reason, /unrecognized process/i);
});

test("inplace: benign updater/sync dominant in EVTX → force-downgrade to LOW (even with USN)", () => {
  const pc = { available: true, processes: [{ image: "C:\\Windows\\System32\\OneDrive.exe", cmdLine: "", risky: false, evasion: false, matchedPayload: false }] };
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst(), samples: _ipSamples(), extBreakdown: _ipExt, usnOverwriteNoRename: { total: 180, alignedMinutes: 3, overwriteTotal: 170, overwriteAligned: 3 }, processCorrelation: pc });
  assert.equal(r.evtxDisposition, "benign-actor");
  assert.equal(r.confidence, "low");
  assert.match(r.reason, /updater|sync|indexer/i);
});

test("inplace: suspicious process elevates medium → HIGH (no USN)", () => {
  const pc = { available: true, processes: [{ image: "C:\\Temp\\locker.exe", evasion: true, risky: true, matchedPayload: true }] };
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst(), samples: _ipSamples(), extBreakdown: _ipExt, usnOverwriteNoRename: null, processCorrelation: pc });
  assert.equal(r.evtxDisposition, "suspicious-process");
  assert.equal(r.confidence, "high");
});

test("inplace: missing FN/created columns → unavailable with honest reason, no crash", () => {
  const r = _buildInPlaceAssessment({ hasFnCol: false });
  assert.equal(r.available, false);
  assert.match(r.reason, /FN-modified|LastModified0x30/);
});

test("inplace: no burst, or burst below minFiles → unavailable", () => {
  assert.equal(_buildInPlaceAssessment({ hasFnCol: true, burst: null, samples: [], extBreakdown: [] }).available, false);
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst({ total: 10 }), samples: [], extBreakdown: [] });
  assert.equal(r.available, false);
});

test("inplace: single-folder low-spread burst stays LOW with a refresh caveat", () => {
  const r = _buildInPlaceAssessment({ hasFnCol: true, burst: _ipBurst({ dirPeak: 1 }),
    samples: [{ fileName: "a.docx", parentPath: ".\\Users\\x\\App", extension: ".docx", created0x10: "2026-05-20 10:00:00", lastMod0x10: "2026-05-30 02:01:00", lastMod0x30: "2026-05-20 10:00:00" }],
    extBreakdown: [{ extension: ".docx", count: 200 }], usnOverwriteNoRename: null, processCorrelation: null });
  assert.equal(r.available, true);
  assert.equal(r.confidence, "low");
  assert.equal(r.signals.find((s) => s.id === "S4").fired, false);
  assert.match(r.reason, /spread|velocity|single-application/i);
});

test("proc match: REJECTS substring collisions on common names (the verifier's FP class)", () => {
  // "net.exe" must NOT confirm via "inet.exe"
  assert.equal(_rwProcMatchesFile({ image: "C:\\Windows\\System32\\inetsrv\\inet.exe" }, "net.exe"), false);
  // "setup.exe" must NOT confirm via "adobesetup.exe"
  assert.equal(_rwProcMatchesFile({ image: "C:\\Temp\\adobesetup.exe" }, "setup.exe"), false);
  // filename only mentioned mid-token in an unrelated path component
  assert.equal(_rwProcMatchesFile({ cmdLine: "C:\\logs\\notlocker.exe.log" }, "locker.exe"), false);
  assert.equal(_rwProcMatchesFile({ image: "", cmdLine: "" }, "locker.exe"), false);
  assert.equal(_rwProcMatchesFile({ image: "C:\\a\\b.exe" }, ""), false);
});
