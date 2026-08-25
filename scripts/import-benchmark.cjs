#!/usr/bin/env node
/**
 * import-benchmark.cjs — repeatable, end-to-end import smoke test / benchmark.
 *
 * Drives the REAL import code (parsers/index.js parseFile → TimelineDB.insertBatchArrays →
 * finalizeImport → buildIndexesAsync → mergeTabs) against a generated synthetic forensic CSV,
 * and reports per-phase timings + throughput. Use it to validate the import-speed changes on
 * analyst-class hardware at realistic scale (the >5GB batch tier only engages above 5GB).
 *
 * One deliberate divergence from production: the parse runs SINGLE-THREADED in this process,
 * whereas the real import runs in a worker_thread (import-worker.js) with EXCLUSIVE locking and a
 * DB-adopt step. The code paths exercised are identical; treat the parse MB/s as a close proxy /
 * conservative lower bound, not the exact production figure. (This is restated in the summary.)
 *
 * better-sqlite3 is built for Electron's Node ABI, so this MUST run under Electron-as-Node:
 *
 *   # ~75MB quick smoke (default):
 *   ELECTRON_RUN_AS_NODE=1 ./node_modules/.bin/electron scripts/import-benchmark.cjs
 *
 *   # the real test — a 20GB import (give the heap room, like the import worker gets):
 *   NODE_OPTIONS="--max-old-space-size=16384" ELECTRON_RUN_AS_NODE=1 \
 *     ./node_modules/.bin/electron scripts/import-benchmark.cjs --gb 20 --keep
 *
 * Flags:
 *   --rows N     generate N data rows           (default 300000)
 *   --gb G       generate ~G gigabytes instead  (overrides --rows)
 *   --cols wide  use the wide (~25-col) schema   (default ~13-col EVTX-ish)
 *   --no-merge   skip the tab-merge phase
 *   --no-index   skip the index/ANALYZE phase (parse+insert throughput only)
 *   --keep       leave the generated CSV + temp DBs on disk
 *   --out DIR    scratch directory (default: a temp dir under the OS temp folder)
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

// ── Resolve the real modules (this file lives in scripts/) ──────────────────
const REPO = path.resolve(__dirname, "..");
let TimelineDB, parseFile, csv;
try {
  TimelineDB = require(path.join(REPO, "electron/db.js"));
  ({ parseFile } = require(path.join(REPO, "electron/parsers/index.js")));
  csv = require(path.join(REPO, "electron/parsers/csv.js"));
} catch (e) {
  if (e && /ERR_DLOPEN_FAILED|was compiled against|NODE_MODULE_VERSION/.test(String(e.message))) {
    console.error("\n  better-sqlite3 failed to load — run this UNDER ELECTRON, e.g.:\n");
    console.error("    ELECTRON_RUN_AS_NODE=1 ./node_modules/.bin/electron scripts/import-benchmark.cjs\n");
  }
  throw e;
}

// ── Tiny arg parser ─────────────────────────────────────────────────────────
function parseArgs(argv) {
  const a = { rows: 300000, gb: 0, cols: "default", merge: true, index: true, keep: false, out: null };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t === "--rows") a.rows = Math.max(1, parseInt(argv[++i], 10) || a.rows);
    else if (t === "--gb") a.gb = Math.max(0, parseFloat(argv[++i]) || 0);
    else if (t === "--cols") a.cols = String(argv[++i] || "default");
    else if (t === "--no-merge") a.merge = false;
    else if (t === "--no-index") a.index = false;
    else if (t === "--keep") a.keep = true;
    else if (t === "--out") a.out = argv[++i];
  }
  return a;
}

// ── Synthetic forensic data generation (deterministic, streaming) ───────────
const SCHEMAS = {
  default: ["datetime", "EventID", "Channel", "Provider", "Computer", "SubjectUserName",
    "TargetUserName", "ProcessName", "CommandLine", "ParentProcessName", "IpAddress",
    "LogonType", "Message"],
  wide: ["datetime", "EventID", "Channel", "Provider", "Computer", "SubjectUserName",
    "SubjectDomainName", "TargetUserName", "TargetDomainName", "LogonId", "ProcessName",
    "ProcessId", "CommandLine", "ParentProcessName", "ParentProcessId", "IntegrityLevel",
    "IpAddress", "IpPort", "LogonType", "AuthPackage", "WorkstationName", "Hashes",
    "ParentCommandLine", "User", "Message"],
};
const EVENT_IDS = [4624, 4625, 4688, 4672, 4634, 1, 3, 7, 11, 13, 7045, 4697, 5140, 4720];
const CHANNELS = ["Security", "System", "Microsoft-Windows-Sysmon/Operational",
  "Microsoft-Windows-PowerShell/Operational", "Application"];
const PROCS = ["C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\powershell.exe",
  "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\lsass.exe",
  "C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe", "C:\\Windows\\System32\\rundll32.exe"];
const USERS = ["administrator", "jsmith", "svc_backup", "victim", "SYSTEM", "dwilson", "attacker"];
const IPS = ["10.0.0.5", "192.168.1.20", "172.16.4.99", "10.0.0.1", "203.0.113.44", "-"];

function pad(n, w) { return String(n).padStart(w, "0"); }
function fmtTs(epochSec) {
  // UTC "YYYY-MM-DD HH:MM:SS" — the app's canonical naive-UTC display form.
  const d = new Date(epochSec * 1000);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1, 2)}-${pad(d.getUTCDate(), 2)} ` +
    `${pad(d.getUTCHours(), 2)}:${pad(d.getUTCMinutes(), 2)}:${pad(d.getUTCSeconds(), 2)}`;
}
function csvField(s) {
  // RFC 4180: quote if the value contains a comma, quote, CR or LF; double internal quotes.
  if (s.indexOf(",") !== -1 || s.indexOf('"') !== -1 || s.indexOf("\n") !== -1 || s.indexOf("\r") !== -1) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

const BASE_EPOCH = Math.floor(Date.parse("2024-01-01T00:00:00Z") / 1000);

function buildRow(i, schema) {
  const eid = EVENT_IDS[i % EVENT_IDS.length];
  const proc = PROCS[i % PROCS.length];
  const parent = PROCS[(i + 3) % PROCS.length];
  const user = USERS[i % USERS.length];
  const target = USERS[(i + 2) % USERS.length];
  // A command line that often contains commas + occasional quotes → exercises the quote-aware path.
  const cmd = `${proc} -enc SQBFAFgA -id ${i} -args a,b,c,"flag${i % 7}" /server:${IPS[i % IPS.length]}`;
  const msg = `Event ${eid} observed for user ${user}, process "${proc}" (pid ${1000 + (i % 60000)}), ` +
    `parent ${parent}, logon type ${i % 12}. Correlation ${i}-${(i * 2654435761) >>> 8}.`;
  const v = {
    datetime: fmtTs(BASE_EPOCH + i),
    EventID: String(eid),
    Channel: CHANNELS[i % CHANNELS.length],
    Provider: "Microsoft-Windows-Security-Auditing",
    Computer: i % 50 === 0 ? "DC01.corp.local" : `WKS-${pad(i % 250, 3)}.corp.local`,
    SubjectUserName: user,
    SubjectDomainName: "CORP",
    TargetUserName: target,
    TargetDomainName: "CORP",
    LogonId: "0x" + (0x3e7 + (i % 90000)).toString(16),
    ProcessName: proc,
    ProcessId: String(1000 + (i % 60000)),
    CommandLine: cmd,
    ParentProcessName: parent,
    ParentProcessId: String(500 + (i % 4000)),
    IntegrityLevel: ["Low", "Medium", "High", "System"][i % 4],
    IpAddress: IPS[i % IPS.length],
    IpPort: String(1024 + (i % 64000)),
    LogonType: String(i % 12),
    AuthPackage: ["NTLM", "Kerberos", "Negotiate"][i % 3],
    WorkstationName: `WKS-${pad(i % 250, 3)}`,
    Hashes: "SHA256=" + ((i * 2654435761) >>> 0).toString(16).padStart(8, "0").repeat(8),
    ParentCommandLine: `${parent} /c run,step${i % 9}`,
    User: `CORP\\${user}`,
    Message: msg,
  };
  return schema.map((h) => csvField(v[h] != null ? v[h] : ""));
}

async function generateCsv(filePath, schema, opts, log) {
  const ws = fs.createWriteStream(filePath);
  const targetBytes = opts.gb > 0 ? Math.floor(opts.gb * 1024 * 1024 * 1024) : 0;
  const maxRows = targetBytes > 0 ? Infinity : opts.rows;

  // Backpressure-aware write. On a backpressured write, attach drain+error listeners that BOTH
  // remove each other when either fires — so a multi-GB generation never accumulates listeners
  // (the naive per-write ws.once("error") leaks one listener per write).
  let streamErr = null;
  ws.on("error", (e) => { streamErr = e; });
  const write = (s) => new Promise((res, rej) => {
    if (streamErr) return rej(streamErr);
    if (ws.write(s)) { res(); return; }
    const onDrain = () => { ws.removeListener("error", onErr); res(); };
    const onErr = (e) => { ws.removeListener("drain", onDrain); rej(e); };
    ws.once("drain", onDrain);
    ws.once("error", onErr);
  });

  await write(schema.join(",") + "\n");
  let i = 0, bytes = 0, lastLog = 0;
  while (i < maxRows) {
    // Build a chunk of rows per write to amortise promise overhead.
    let chunk = "";
    for (let k = 0; k < 2000 && i < maxRows; k++, i++) chunk += buildRow(i, schema).join(",") + "\n";
    bytes += Buffer.byteLength(chunk);
    await write(chunk);
    if (targetBytes > 0 && bytes >= targetBytes) break;
    if (bytes - lastLog >= 512 * 1024 * 1024) { lastLog = bytes; log(`  generating… ${fmtBytes(bytes)} (${i.toLocaleString()} rows)`); }
  }
  await new Promise((res, rej) => ws.end((err) => (err ? rej(err) : res())));
  return { rows: i, bytes };
}

// ── Reporting helpers ───────────────────────────────────────────────────────
function fmtBytes(b) {
  if (b >= 1024 ** 3) return (b / 1024 ** 3).toFixed(2) + " GB";
  if (b >= 1024 ** 2) return (b / 1024 ** 2).toFixed(1) + " MB";
  if (b >= 1024) return (b / 1024).toFixed(1) + " KB";
  return b + " B";
}
function now() { return Number(process.hrtime.bigint()) / 1e6; } // fractional ms
function secs(ms) { return (ms / 1000).toFixed(2) + "s"; }
// Sub-second-friendly: query latencies are often single-digit ms, where "0.00s" reads as no data.
function qdur(ms) { return ms < 1000 ? (ms < 10 ? ms.toFixed(1) : Math.round(ms)) + "ms" : (ms / 1000).toFixed(2) + "s"; }
function ratioSuffix(cold, warm, extra) {
  const e = extra ? ` — ${extra}` : "";
  if (warm > 0.05) return `  (${(cold / warm).toFixed(1)}× faster${e})`;
  return extra ? `  (${extra})` : "";
}
function log(...a) { console.log(...a); }

// ── Main ────────────────────────────────────────────────────────────────────
(async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const schema = SCHEMAS[opts.cols] || SCHEMAS.default;
  const scratch = opts.out || fs.mkdtempSync(path.join(os.tmpdir(), "tle-bench-"));
  fs.mkdirSync(scratch, { recursive: true });
  const csvPath = path.join(scratch, "timeline.csv");
  const csvPath2 = path.join(scratch, "timeline2.csv");

  const heapLimit = require("v8").getHeapStatistics().heap_size_limit;
  log("─".repeat(72));
  log("IRFlow Timeline — import benchmark");
  log("─".repeat(72));
  log(`schema:      ${opts.cols} (${schema.length} columns)`);
  log(`scratch:     ${scratch}`);
  log(`heap limit:  ${fmtBytes(heapLimit)}  (import workers run with ~16GB)`);
  // Show the batch sizing the parser WILL pick at each tier — makes the >5GB change visible
  // even on a small run that does not itself cross the 5GB threshold.
  const smallBs = csv.computeImportBatchSize(schema.length, 1 * 1024 ** 3);
  const largeBs = csv.computeImportBatchSize(schema.length, 6 * 1024 ** 3);
  log(`batch size:  ≤5GB → ${smallBs.toLocaleString()} rows  |  >5GB → ${largeBs.toLocaleString()} rows  ` +
    `(${(largeBs / smallBs).toFixed(2)}× fewer commits on huge files)`);
  log("");

  // 1) generate
  log(opts.gb > 0 ? `Generating ~${opts.gb}GB CSV…` : `Generating ${opts.rows.toLocaleString()} rows…`);
  let t = now();
  const gen = await generateCsv(csvPath, schema, opts, log);
  const genMs = now() - t;
  const fileBytes = fs.statSync(csvPath).size;
  log(`  generated ${gen.rows.toLocaleString()} rows, ${fmtBytes(fileBytes)} in ${secs(genMs)}`);
  log("");

  const db = new TimelineDB();
  const results = {};

  // 2) parse + insert (the dominant phase — where batch-size + cache changes land)
  log("Importing (parse + insert)…");
  db._dbPathHint = path.join(scratch, "tab0.db");
  t = now();
  const parsed = await parseFile(csvPath, "bench0", db, null, undefined, fileBytes);
  const parseMs = now() - t;
  db.finalizeImport("bench0");
  const rc = parsed.rowCount;
  results.parse = parseMs;
  log(`  ${rc.toLocaleString()} rows in ${secs(parseMs)}  →  ` +
    `${(fileBytes / 1024 / 1024 / (parseMs / 1000)).toFixed(1)} MB/s, ` +
    `${Math.round(rc / (parseMs / 1000)).toLocaleString()} rows/s`);
  log("");

  // Two representative first queries an analyst runs immediately. Columns sanitize to c0..cN —
  // datetime → c0, EventID → c1.
  //  (A) chronological render — ORDER BY sort_datetime(c0) — the canonical "show me the timeline".
  //      The timestamp column is eagerly indexed in BOTH the ≤5GB and >5GB tiers (buildIndexesAsync
  //      builds idx_sort_c0 for ts cols in both), so its warm speedup is REPRESENTATIVE of a real
  //      >5GB import. This is the headline number.
  //  (B) categorical filter — GROUP BY EventID (c1), a NON-timestamp column. On >5GB files these are
  //      indexed LAZILY (db.js buildIndexesAsync eager-indexes only ts cols when isLargeFile), so at
  //      real scale (B) stays a full scan until that column is first sorted — ANALYZE still helps the
  //      planner but there is no index seek. Reported separately so the headline isn't inflated.
  const sortQ = () => {
    const d = db.databases.get("bench0").db;
    const t0 = now();
    d.prepare(`SELECT * FROM data ORDER BY sort_datetime(c0) LIMIT 500`).all();
    return now() - t0;
  };
  const catQ = () => {
    const d = db.databases.get("bench0").db;
    const t0 = now();
    d.prepare(`SELECT c1 AS EventID, COUNT(*) AS n FROM data GROUP BY c1 ORDER BY n DESC LIMIT 20`).all();
    return now() - t0;
  };
  const isLargeRun = fileBytes > 5 * 1024 * 1024 * 1024;
  results.sortCold = sortQ();
  results.catCold = catQ();
  log(`First query COLD (no index / no planner stats):`);
  log(`  (A) chronological sort   ${qdur(results.sortCold)}`);
  log(`  (B) categorical GROUP BY ${qdur(results.catCold)}`);

  // 3) index build + ANALYZE (the headline first-query fix for large files)
  if (opts.index) {
    log("Building indexes + ANALYZE…");
    t = now();
    await db.buildIndexesAsync("bench0");
    results.index = now() - t;
    log(`  done in ${secs(results.index)}`);
    results.sortWarm = sortQ();
    results.catWarm = catQ();
    log(`Same queries WARM (after index build + ANALYZE):`);
    log(`  (A) chronological sort   ${qdur(results.sortWarm)}` +
      ratioSuffix(results.sortCold, results.sortWarm, "representative of >5GB"));
    log(`  (B) categorical GROUP BY ${qdur(results.catWarm)}` +
      ratioSuffix(results.catCold, results.catWarm) +
      (isLargeRun ? "" : `  ⚠ on a real >5GB import EventID is lazily indexed — no index seek`));
  }
  log("");

  // 4) merge two tabs (exercises the mergeTabs bulk-cache fix)
  if (opts.merge) {
    log("Importing a 2nd tab + merging (exercises merge cache)…");
    const opts2 = { ...opts, rows: Math.min(opts.gb > 0 ? 1000000 : opts.rows, gen.rows), gb: 0 };
    await generateCsv(csvPath2, schema, opts2, () => {});
    const fileBytes2 = fs.statSync(csvPath2).size;
    db._dbPathHint = path.join(scratch, "tab1.db");
    const parsed2 = await parseFile(csvPath2, "bench1", db, null, undefined, fileBytes2);
    db.finalizeImport("bench1");
    db._dbPathHint = path.join(scratch, "merged.db");
    t = now();
    await db.mergeTabs("benchmerged", [
      // tsCol MUST be passed — it mirrors production (src/App.jsx passes tsCol: selectedTsCol).
      // Without it, mergeTabs maps no source timestamp column and the unified `datetime` column
      // comes out entirely empty, so the per-row timestamp copy + post-merge datetime index would
      // run over dummy data and the phase would be unrepresentative. "datetime" is the unsanitized
      // header the harness wrote; db.js maps it to the source's safe column via colMap.
      { tabId: "bench0", tabName: "timeline", tsCol: "datetime" },
      { tabId: "bench1", tabName: "timeline2", tsCol: "datetime" },
    ]);
    results.merge = now() - t;
    const totalMerged = rc + parsed2.rowCount;
    log(`  merged ${totalMerged.toLocaleString()} rows in ${secs(results.merge)}  →  ` +
      `${Math.round(totalMerged / (results.merge / 1000)).toLocaleString()} rows/s`);
    // Correctness: (1) merged row count == sum of sources, AND (2) the unified datetime column is
    // populated, not empty. Unified headers are [_Source, datetime, …] → datetime is the safe col c1.
    const mDb = db.databases.get("benchmerged").db;
    const mergedCount = mDb.prepare("SELECT COUNT(*) AS n FROM data").get().n;
    const dtFilled = mDb.prepare("SELECT COUNT(*) AS n FROM data WHERE c1 != ''").get().n;
    log(`  merged row count   = ${mergedCount.toLocaleString()} (expected ${totalMerged.toLocaleString()})` +
      (mergedCount === totalMerged ? "  ✓" : "  ✗ MISMATCH"));
    log(`  datetime populated = ${dtFilled.toLocaleString()}/${mergedCount.toLocaleString()}` +
      (dtFilled === mergedCount ? "  ✓" : "  ✗ EMPTY — merge tsCol mapping broken"));
  }
  log("");

  // ── Summary ────────────────────────────────────────────────────────────────
  log("─".repeat(72));
  log("Summary");
  log("─".repeat(72));
  log(`  file size            ${fmtBytes(fileBytes)} (${rc.toLocaleString()} rows, ${schema.length} cols)`);
  log(`  parse + insert       ${secs(results.parse)}   (${(fileBytes / 1024 / 1024 / (results.parse / 1000)).toFixed(1)} MB/s, single-thread)`);
  if (opts.index) log(`  index + ANALYZE      ${secs(results.index)}`);
  log(`  sort query  cold→warm ${qdur(results.sortCold)} → ${opts.index ? qdur(results.sortWarm) : "—"}   (timestamp; representative of >5GB)`);
  log(`  group query cold→warm ${qdur(results.catCold)} → ${opts.index ? qdur(results.catWarm) : "—"}   (categorical; lazily indexed on >5GB)`);
  if (opts.merge) log(`  merge two tabs       ${secs(results.merge)}`);
  log("─".repeat(72));
  log("Note: parse runs single-threaded in-process here; the production import runs in a");
  log("worker_thread (import-worker.js) with EXCLUSIVE locking + a DB-adopt step. These numbers");
  log("are a close proxy / conservative lower bound for parse throughput, not the exact prod path.");
  log("─".repeat(72));

  // ── Cleanup ──────────────────────────────────────────────────────────────
  if (!opts.keep) {
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch {}
    log(`(cleaned ${scratch})`);
  } else {
    log(`(kept artifacts in ${scratch})`);
  }
  // TimelineDB holds a 5-min WAL setInterval — exit explicitly.
  process.exit(0);
})().catch((e) => {
  console.error("\nBENCHMARK FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
