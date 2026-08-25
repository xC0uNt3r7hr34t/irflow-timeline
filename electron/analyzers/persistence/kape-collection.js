/**
 * analyzers/persistence/kape-collection.js — discover persistence artifacts in a KAPE folder
 *
 * A KAPE package is a folder, not a file, and the persistence analyzer only ever saw one
 * imported file at a time. This walks a collection and reports what is in it, so an analyst
 * can point at `U42-TECH-TOut` (or `Azeroth-File/M_Out`) instead of importing 112 EVTX files
 * one at a time and still missing the 204 task definitions entirely.
 *
 * Two layouts, both handled:
 *   raw targets    <root>\<Drive>\Windows\System32\{winevt\Logs\*.evtx, Tasks\*, config\*}
 *                  <root>\<Drive>\Users\<user>\NTUSER.DAT
 *   module output  <root>\{EventLogs,Registry,...}\*.csv   (EvtxECmd / RECmd output)
 *
 * SAFETY: the scan is scope-confined. Every path is resolved through realpath and must land
 * inside the realpath of the chosen root, so a symlink planted in evidence cannot walk the
 * analyst's filesystem. Depth, file count and per-directory entries are all bounded.
 */

const fs = require("fs");
const path = require("path");
const { dbg } = require("../../logger");

const DEFAULTS = {
  maxDepth: 14,
  maxFiles: 300000,
  maxEntriesPerDir: 20000,
  csvHeaderBytes: 4096,
};

// Directories that cannot hold a persistence artifact but can hold a great many files.
const SKIP_DIRS = /^(?:\$Recycle\.Bin|System Volume Information|WinSxS|Windows\.old|node_modules|\.git)$/i;

const HIVE_BASENAMES = /^(?:SYSTEM|SOFTWARE|SAM|SECURITY|DEFAULT|COMPONENTS|DRIVERS|BCD-Template)$/i;
// Transaction logs and dirty-page files sit beside a hive and are not themselves readable hives.
const HIVE_SIDECAR = /\.(?:LOG\d*|regtrans-ms|blf|chk)$/i;

const isTaskXmlPath = (rel) => /(?:^|[\\/])Windows[\\/]System32[\\/]Tasks[\\/]/i.test(rel);

/**
 * Which hive a file is, from its name and where it sits.
 * Returns null when the file is not a registry hive.
 */
function classifyHive(filePath, rel) {
  const base = path.basename(filePath);
  if (HIVE_SIDECAR.test(base)) return null;
  if (/^NTUSER\.DAT$/i.test(base)) {
    const m = /[\\/]Users[\\/]([^\\/]+)[\\/]/i.exec(rel) || /[\\/]ServiceProfiles[\\/]([^\\/]+)[\\/]/i.exec(rel);
    return { hive: "NTUSER", user: m ? m[1] : "" };
  }
  if (/^UsrClass\.dat$/i.test(base)) {
    const m = /[\\/]Users[\\/]([^\\/]+)[\\/]/i.exec(rel);
    return { hive: "USRCLASS", user: m ? m[1] : "" };
  }
  if (/^Amcache\.hve$/i.test(base)) return { hive: "AMCACHE", user: "" };
  // The machine hives are extension-less and only meaningful under a config directory —
  // "SOFTWARE" as a bare folder name elsewhere in evidence is not a hive.
  if (HIVE_BASENAMES.test(base) && /[\\/]config[\\/][^\\/]+$/i.test(rel)) {
    return { hive: base.toUpperCase(), user: "" };
  }
  return null;
}

/**
 * Classify a KAPE module-output CSV from its header row, so the caller knows which
 * importer/analyzer shape it feeds. Reads only the first few KB.
 */
function classifyModuleCsv(filePath, { headerBytes = DEFAULTS.csvHeaderBytes } = {}) {
  let head = "";
  let fd = null;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(headerBytes);
    const read = fs.readSync(fd, buf, 0, headerBytes, 0);
    head = buf.subarray(0, read).toString("utf8");
  } catch {
    return { kind: "unknown", headers: [] };
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already gone */ } }
  }
  const firstLine = (head.split(/\r?\n/, 1)[0] || "").replace(/^﻿/, "");
  const headers = firstLine.split(",").map((h) => h.trim().replace(/^"|"$/g, ""));
  const has = (re) => headers.some((h) => re.test(h));

  if (has(/^PayloadData1$/i) && has(/^MapDescription$/i)) return { kind: "evtxecmd", headers };
  if (has(/^HiveType$/i) && has(/^KeyPath$/i) && has(/^ValueName$/i)) return { kind: "recmd-batch", headers };
  if (has(/^RuleTitle$/i) && has(/^Details$/i) && has(/^Channel$/i)) return { kind: "hayabusa", headers };

  // RECmd writes one detail CSV per plugin, each with its own schema. Ask the analyzer's
  // own plugin detector rather than guessing — it is the thing that has to consume them.
  const detect = (pats) => { for (const p of pats) { const f = headers.find((h) => p.test(h)); if (f) return f; } return null; };
  let plugin = null;
  try {
    plugin = require("./registry-shapes").detectRegistryPlugin(headers, detect);
  } catch { /* fall through to the filename heuristic */ }
  if (plugin) {
    return { kind: "recmd-plugin", plugin: plugin.shape.id, pluginLabel: plugin.shape.label, projects: !!plugin.shape.projects, headers };
  }

  // RECmd names its detail files "<timestamp>_<PluginName>__<hive path>.csv". Recognizing
  // the name lets the UI say "Services plugin, unsupported schema" instead of "unknown".
  const nameMatch = /^\d+_([A-Za-z0-9]+)__/.exec(path.basename(filePath));
  if (nameMatch && /[\\/]Registry[\\/]/i.test(filePath)) {
    return { kind: "recmd-plugin", plugin: nameMatch[1].toLowerCase(), pluginLabel: `RECmd ${nameMatch[1]} plugin`, projects: false, headers };
  }
  if (!has(/^KeyPath$/i) && (has(/^HivePath$/i) || has(/^HiveType$/i))) return { kind: "recmd-plugin", projects: false, headers };
  if (has(/^EventI[dD]$/i)) return { kind: "evtx-csv", headers };
  return { kind: "unknown", headers };
}

/**
 * Host name for the collection.
 *
 * NOT taken from KAPE's ConsoleLog: its "Machine name:" is the machine that RAN KAPE. On a
 * mounted-image collection that is the examiner's workstation, so trusting it would label
 * every finding with the analyst's own hostname. The SYSTEM hive is the authoritative
 * source (read separately, once a hive parser is in play); everything here is a fallback
 * and is reported as inferred.
 */
function deriveCollectionName(root, relPaths) {
  const clean = String(root || "").replace(/[\\/]+$/, "");
  const base = path.basename(clean);

  // KAPE destinations are conventionally "<HOST>-TOut" / "<HOST>_T_Out" / "<HOST>-MOut".
  const stripped = base.replace(/[-_ ](?:t|m)_?out$/i, "").replace(/[-_ ](?:triage|target|module)s?$/i, "");
  if (stripped && stripped !== base) return { host: stripped, source: "collection-folder" };

  // ...or the output folder IS the marker ("Azeroth-File/T_Out"), in which case the host is
  // named by its parent, not by the literal string "T_Out".
  if (/^(?:t|m)_?out$/i.test(base) || /^(?:targets?|modules?|triage)$/i.test(base)) {
    const parent = path.basename(path.dirname(clean));
    if (parent && !/^[/\\]?$/.test(parent)) {
      return { host: parent.replace(/[-_ ]?(?:file|triage|collection)$/i, "") || parent, source: "collection-folder" };
    }
  }

  // <root>\<MachineName>\<DriveLetter>\Windows\... — the machine folder sits above the drive.
  for (const rel of relPaths) {
    const segs = rel.split(/[\\/]+/).filter(Boolean);
    for (let i = 1; i < segs.length; i++) {
      if (/^[A-Za-z](?:%3A|:)?$/.test(segs[i])) {
        if (i >= 1 && !/^[A-Za-z](?:%3A|:)?$/.test(segs[i - 1])) return { host: segs[i - 1], source: "collection-path" };
        return { host: "", source: "none" };
      }
    }
  }
  return { host: base || "", source: base ? "collection-folder" : "none" };
}

/**
 * Walk a collection and bucket every persistence-relevant artifact.
 *
 * @param rootDir  the folder the analyst chose
 * @param opts     {maxDepth, maxFiles, maxEntriesPerDir}
 * @returns {{root, host, hostSource, layout, artifacts, stats, warnings, error}}
 */
function scanCollection(rootDir, opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };
  const empty = {
    artifacts: { taskXml: [], hives: [], evtx: [], moduleCsv: [] },
    stats: { filesSeen: 0, dirsSeen: 0, skipped: 0, truncated: false },
    warnings: [],
  };

  let rootReal;
  try {
    rootReal = fs.realpathSync(path.resolve(String(rootDir || "")));
  } catch (err) {
    return { ...empty, root: rootDir || "", host: "", hostSource: "none", layout: null, error: `Cannot open folder: ${err.message}` };
  }
  let rootStat;
  try {
    rootStat = fs.statSync(rootReal);
  } catch (err) {
    return { ...empty, root: rootReal, host: "", hostSource: "none", layout: null, error: `Cannot read folder: ${err.message}` };
  }
  if (!rootStat.isDirectory()) {
    return { ...empty, root: rootReal, host: "", hostSource: "none", layout: null, error: "Not a folder — select a KAPE collection directory." };
  }

  const artifacts = { taskXml: [], hives: [], evtx: [], moduleCsv: [] };
  const warnings = [];
  const stats = { filesSeen: 0, dirsSeen: 0, skipped: 0, truncated: false };
  const relPaths = [];
  // Guard against directory cycles reached through symlinks or bind mounts.
  const visitedDirs = new Set();

  const walk = (dir, depth) => {
    if (stats.truncated) return;
    if (depth > cfg.maxDepth) { stats.skipped++; return; }

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      stats.skipped++;
      if (warnings.length < 20) warnings.push(`Cannot read ${path.relative(rootReal, dir) || "."}: ${err.message}`);
      return;
    }
    stats.dirsSeen++;
    if (entries.length > cfg.maxEntriesPerDir) {
      warnings.push(`${path.relative(rootReal, dir) || "."} holds ${entries.length} entries — only the first ${cfg.maxEntriesPerDir} were scanned.`);
      entries = entries.slice(0, cfg.maxEntriesPerDir);
    }

    for (const entry of entries) {
      if (stats.truncated) return;
      const full = path.join(dir, entry.name);

      // Resolve through symlinks and refuse anything that leaves the chosen root.
      let real;
      try {
        real = fs.realpathSync(full);
      } catch {
        stats.skipped++;
        continue;
      }
      if (real !== rootReal && !real.startsWith(rootReal + path.sep)) {
        stats.skipped++;
        if (warnings.length < 20) warnings.push(`Skipped ${entry.name}: resolves outside the selected folder.`);
        continue;
      }

      let st;
      try {
        st = fs.statSync(real);
      } catch {
        stats.skipped++;
        continue;
      }

      if (st.isDirectory()) {
        if (SKIP_DIRS.test(entry.name)) { stats.skipped++; continue; }
        if (visitedDirs.has(real)) { stats.skipped++; continue; }
        visitedDirs.add(real);
        walk(full, depth + 1);
        continue;
      }
      if (!st.isFile()) { stats.skipped++; continue; }

      stats.filesSeen++;
      if (stats.filesSeen > cfg.maxFiles) {
        stats.truncated = true;
        warnings.push(`Stopped after ${cfg.maxFiles.toLocaleString()} files — the selected folder is larger than a triage collection.`);
        return;
      }

      const rel = path.relative(rootReal, full);
      relPaths.push(rel);
      const ext = path.extname(entry.name).toLowerCase();
      const record = { path: full, relPath: rel, size: st.size, mtimeMs: st.mtimeMs };

      if (isTaskXmlPath(rel)) {
        artifacts.taskXml.push(record);
        continue;
      }
      if (ext === ".evtx") {
        artifacts.evtx.push({ ...record, channel: path.basename(entry.name, ".evtx").replace(/%4/g, "/") });
        continue;
      }
      const hive = classifyHive(full, rel);
      if (hive) {
        artifacts.hives.push({ ...record, ...hive });
        continue;
      }
      if (ext === ".csv") {
        // KAPE's own run logs are not evidence. (SkipLog ships as "..._SkipLog.csv.csv".)
        if (/_(?:CopyLog|SkipLog|ConsoleLog)(?:\.csv)*$/i.test(entry.name)) continue;
        artifacts.moduleCsv.push({ ...record, ...classifyModuleCsv(full, cfg) });
      }
    }
  };

  visitedDirs.add(rootReal);
  walk(rootReal, 0);

  const { host, source } = deriveCollectionName(rootReal, relPaths);
  const hasRaw = artifacts.taskXml.length > 0 || artifacts.hives.length > 0 || artifacts.evtx.length > 0;
  const hasModule = artifacts.moduleCsv.length > 0;
  const layout = hasRaw && hasModule ? "mixed" : hasRaw ? "raw" : hasModule ? "module" : null;

  if (!layout) {
    warnings.push("No EVTX, registry hives, scheduled-task definitions or KAPE module CSVs found in this folder.");
  }

  dbg("KAPE-COLLECTION", `scanned ${stats.filesSeen} files in ${rootReal}`, {
    tasks: artifacts.taskXml.length, hives: artifacts.hives.length, evtx: artifacts.evtx.length, csv: artifacts.moduleCsv.length,
  });

  return { root: rootReal, host, hostSource: source, layout, artifacts, stats, warnings, error: null };
}

module.exports = {
  scanCollection,
  classifyHive,
  classifyModuleCsv,
  deriveCollectionName,
  isTaskXmlPath,
  DEFAULTS,
};
