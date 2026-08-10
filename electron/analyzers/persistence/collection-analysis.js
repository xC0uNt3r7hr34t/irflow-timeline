/**
 * analyzers/persistence/collection-analysis.js — analyze a KAPE folder, not a file
 *
 * The persistence analyzer worked on one imported tab at a time. A KAPE package is a
 * folder holding hundreds of artifacts, and the two that matter most were unreachable:
 *
 *   • 204 scheduled-task DEFINITIONS under Windows\System32\Tasks. The analyzer had never
 *     read one. It inferred Hidden / RunLevel / ComHandler / triggers by scraping fragments
 *     out of event payloads (hence `_taskXmlPartial`), and it could only see tasks that
 *     happened to FIRE inside the log window. A task registered for persistence and waiting
 *     for its trigger left no event at all.
 *   • The RECmd Services and TaskCache plugin CSVs, which need no import to read.
 *
 * This reads those directly and runs them through the ordinary rule/scoring/clustering
 * engine, so a collection scan produces the same shape of result as any other scan.
 *
 * EVTX files and raw registry hives are DISCOVERED and reported but not parsed here: they
 * belong in the import pipeline (worker-backed, streamed to SQLite), and once imported the
 * multi-source scan correlates them. The result says exactly what was left unread rather
 * than quietly presenting partial coverage as complete.
 */

const fs = require("fs");
const path = require("path");
const { dbg } = require("../../logger");
const { scanCollection } = require("./kape-collection");
const { parseTaskXml, taskNameFromPath } = require("./task-xml");
const { getPersistenceAnalysis } = require("./index");
const { detectRegistryPlugin, projectPluginRows } = require("./registry-shapes");
const { clusterIncidents } = require("./incidents");

const MAX_TASK_FILE_BYTES = 2 * 1024 * 1024; // a task definition is a few KB; anything larger is not one
const MAX_CSV_BYTES = 256 * 1024 * 1024;

/**
 * Render a parsed task back into the XML-ish text the engine's task extractors read.
 *
 * The engine already knows how to pull Hidden/RunLevel/ComHandler/triggers/Command out of
 * task XML — that code exists because event payloads sometimes carry fragments of it. Here
 * it is handed the COMPLETE definition, so every flag resolves and nothing is marked
 * partial. Reusing that path rather than adding a second extractor keeps one set of
 * semantics for "what does this task do".
 */
function taskToHaystackFields(task) {
  const parts = [];
  const add = (k, v) => { if (v !== undefined && v !== null && String(v).trim() !== "") parts.push(`<${k}>${v}</${k}>`); };
  add("Hidden", task.hidden ? "true" : "false");
  add("RunLevel", task.runLevel);
  add("UserId", task.principal);
  add("Author", task.author);
  for (const a of task.actions || []) {
    add("Command", a.command);
    add("Arguments", a.arguments);
  }
  for (const cls of task.comHandlers || []) parts.push(`<ComHandler><ClassId>${cls}</ClassId></ComHandler>`);
  for (const t of task.triggers || []) {
    const tag = { boot: "BootTrigger", logon: "LogonTrigger", registration: "RegistrationTrigger", time: "TimeTrigger", calendar: "CalendarTrigger", idle: "IdleTrigger", event: "EventTrigger", session: "SessionStateChangeTrigger" }[t];
    if (tag) parts.push(`<${tag}/>`);
  }
  return parts.join("");
}

/**
 * Read every task definition in the collection and turn each into an analyzer row.
 * The synthetic event id "TASKXML" is matched by the "Scheduled Task Defined" rule.
 */
function readTaskDefinitions(taskFiles, { host, maxFiles = 5000 } = {}) {
  const rows = [];
  const warnings = [];
  let unreadable = 0;
  let notATask = 0;

  const files = taskFiles.slice(0, maxFiles);
  if (taskFiles.length > files.length) {
    warnings.push(`Only the first ${maxFiles.toLocaleString()} of ${taskFiles.length.toLocaleString()} task definitions were read.`);
  }

  for (const f of files) {
    if (f.size > MAX_TASK_FILE_BYTES) { notATask++; continue; }
    let buf;
    try {
      buf = fs.readFileSync(f.path);
    } catch {
      unreadable++;
      continue;
    }
    const taskName = taskNameFromPath(f.relPath) || taskNameFromPath(f.path) || `\\${path.basename(f.path)}`;
    const task = parseTaskXml(buf, { taskName });
    if (!task) { notATask++; continue; }

    // Registration date is the task's own claim; the file mtime is when the collection saw
    // it. Prefer the former, fall back to the latter so every row can be placed in time.
    const ts = task.registrationDate || new Date(f.mtimeMs).toISOString().replace("T", " ").slice(0, 19);

    rows.push({
      _rowid: rows.length + 1,
      eventId: "TASKXML",
      channel: "Microsoft-Windows-TaskScheduler/Operational",
      ts,
      computer: host || "",
      user: task.principal || "",
      // Field names the raw-EVTX haystack already serializes (see RAW_EVTX_HAYSTACK_FIELDS).
      evTaskName: task.taskName,
      evTaskPath: task.command,
      evUserContext: task.principal,
      evTaskContent: taskToHaystackFields(task),
      _taskXml: task,
      _sourceFile: f.relPath,
    });
  }

  if (unreadable > 0) warnings.push(`${unreadable} task definition${unreadable === 1 ? "" : "s"} could not be read.`);
  if (notATask > 0) warnings.push(`${notATask} file${notATask === 1 ? "" : "s"} under Tasks\\ ${notATask === 1 ? "is" : "are"} not a task definition and ${notATask === 1 ? "was" : "were"} skipped.`);
  return { rows, warnings };
}

/** Minimal RFC-4180 row splitter — enough for the fixed, tool-generated CSVs KAPE emits. */
function parseCsv(text, { maxRows = 200000 } = {}) {
  const rows = [];
  let field = "";
  let row = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false;
      } else field += c;
      continue;
    }
    if (c === '"') { inQuotes = true; continue; }
    if (c === ",") { row.push(field); field = ""; continue; }
    if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
      if (rows.length >= maxRows) return rows;
      continue;
    }
    field += c;
  }
  if (field !== "" || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}

/**
 * RECmd names each plugin detail file "<ts>_<Plugin>__<source hive path>.csv", with the
 * hive path's separators flattened to underscores. That suffix is the ONLY place the hive
 * is recorded — the plugin CSVs themselves have no HiveType column — and without it a
 * projected key path ("ROOT\ControlSet001\Services\X") cannot be resolved to
 * HKLM\SYSTEM\... and matches no rule at all.
 */
function hiveFromPluginFileName(basename) {
  const m = /__(.+?)(?:\.csv)?$/i.exec(String(basename || ""));
  if (!m) return { hiveType: "", hivePath: "" };
  const flat = m[1];
  const hivePath = flat.replace(/_/g, "\\");
  const leaf = flat.split("_").pop() || "";
  if (/^NTUSER(?:\.DAT)?$/i.test(leaf)) return { hiveType: "NTUSER", hivePath };
  if (/^UsrClass(?:\.dat)?$/i.test(leaf)) return { hiveType: "USRCLASS", hivePath };
  if (/^Amcache(?:\.hve)?$/i.test(leaf)) return { hiveType: "AMCACHE", hivePath };
  if (/^(?:SYSTEM|SOFTWARE|SAM|SECURITY|DEFAULT|COMPONENTS|DRIVERS)$/i.test(leaf)) {
    return { hiveType: leaf.toUpperCase(), hivePath };
  }
  return { hiveType: "", hivePath };
}

/**
 * Read the RECmd CSVs that can be projected into registry rows without an import:
 * the batch output (KeyPath/ValueName) and the Services / TaskCache plugin details.
 */
function readRegistryCsvs(moduleCsvs, { host } = {}) {
  const rows = [];
  const warnings = [];
  const sources = [];

  for (const csv of moduleCsvs) {
    const usable = csv.kind === "recmd-batch" || (csv.kind === "recmd-plugin" && csv.projects);
    if (!usable) continue;
    if (csv.size > MAX_CSV_BYTES) { warnings.push(`${path.basename(csv.path)} is too large to read in place — import it as a tab instead.`); continue; }

    let text;
    try {
      text = fs.readFileSync(csv.path, "utf8").replace(/^﻿/, "");
    } catch (err) {
      warnings.push(`Cannot read ${path.basename(csv.path)}: ${err.message}`);
      continue;
    }
    const parsed = parseCsv(text);
    if (parsed.length < 2) continue;
    const headers = parsed[0].map((h) => h.trim());
    const detect = (pats) => { for (const p of pats) { const f = headers.find((h) => p.test(h)); if (f) return f; } return null; };
    const idx = Object.fromEntries(headers.map((h, i) => [h, i]));
    const dataRows = parsed.slice(1).map((r, i) => {
      const o = { _rowid: rows.length + i + 1 };
      for (const h of headers) o[h] = r[idx[h]] ?? "";
      return o;
    });

    if (csv.kind === "recmd-batch") {
      const cols = {
        keyPath: detect([/^KeyPath$/i]), valueName: detect([/^ValueName$/i]), valueData: detect([/^ValueData$/i]),
        valueData2: detect([/^ValueData2$/i]), valueData3: detect([/^ValueData3$/i]),
        hivePath: detect([/^HivePath$/i]), hiveType: detect([/^HiveType$/i]),
        ts: detect([/^LastWriteTimestamp$/i]),
      };
      for (const r of dataRows) {
        rows.push({
          _rowid: r._rowid,
          keyPath: r[cols.keyPath] || "", valueName: r[cols.valueName] || "", valueData: r[cols.valueData] || "",
          valueData2: cols.valueData2 ? r[cols.valueData2] : "", valueData3: cols.valueData3 ? r[cols.valueData3] : "",
          hivePath: cols.hivePath ? r[cols.hivePath] : "", hiveType: cols.hiveType ? r[cols.hiveType] : "",
          ts: cols.ts ? r[cols.ts] : "", computer: host || "",
          _sourceFile: csv.relPath,
        });
      }
      sources.push({ file: csv.relPath, kind: "recmd-batch", rows: dataRows.length });
      continue;
    }

    // Plugin detail CSV — reuse the analyzer's own projection.
    const plugin = detectRegistryPlugin(headers, detect);
    if (!plugin?.shape?.projects) continue;
    const aliased = dataRows.map((r) => {
      const o = { _rowid: r._rowid };
      for (const [key, col] of Object.entries(plugin.cols)) if (col) o[key] = r[col];
      return o;
    });
    const projected = projectPluginRows(plugin, aliased);
    // The CSV itself does not say which hive it came from — its filename does.
    const fromName = hiveFromPluginFileName(path.basename(csv.path));
    for (const p of projected) {
      rows.push({
        ...p,
        hiveType: p.hiveType || fromName.hiveType,
        hivePath: p.hivePath || fromName.hivePath,
        computer: host || "",
        _sourceFile: csv.relPath,
      });
    }
    sources.push({ file: csv.relPath, kind: plugin.shape.id, rows: projected.length });
  }

  return { rows, warnings, sources };
}

/** Build the synthetic meta the engine needs when rows are supplied directly. */
function syntheticMeta(mode, rows) {
  const headers = [];
  const colMap = {};
  for (const row of rows.slice(0, 50)) {
    for (const key of Object.keys(row)) {
      if (key.startsWith("_") || colMap[key]) continue;
      headers.push(key); colMap[key] = key;
    }
  }
  if (mode === "evtx") {
    if (!colMap.EventID) { headers.push("EventID"); colMap.EventID = "eventId"; }
  } else {
    if (!colMap.KeyPath) { headers.push("KeyPath"); colMap.KeyPath = "keyPath"; }
    if (!colMap.ValueName) { headers.push("ValueName"); colMap.ValueName = "valueName"; }
  }
  return { tabId: "__kape_collection__", headers, colMap, db: null };
}

/**
 * Analyze a KAPE collection folder.
 *
 * @param rootDir   folder the analyst selected (must already be path-authorized by the caller)
 * @param options   analyzer options (disabledRules, customRules, …)
 * @param ctx       TimelineDB helpers
 */
function analyzeCollection(rootDir, options = {}, ctx = {}) {
  const scan = scanCollection(rootDir, options.scan || {});
  if (scan.error) {
    return { items: [], incidents: [], warnings: scan.warnings || [], stats: {}, collection: scan, error: scan.error };
  }

  const warnings = [...(scan.warnings || [])];
  const host = options.computerName || scan.host || "";

  const { rows: taskRows, warnings: taskWarnings } = readTaskDefinitions(scan.artifacts.taskXml, { host });
  const { rows: regRows, warnings: regWarnings, sources: regSources } = readRegistryCsvs(scan.artifacts.moduleCsv, { host });
  warnings.push(...taskWarnings, ...regWarnings);

  const analyzerCtx = { applyStandardFilters: () => {}, ensureIndex: () => {}, ...ctx };
  const allItems = [];
  const passes = [];

  const runPass = (mode, rows) => {
    if (rows.length === 0) return null;
    try {
      const res = getPersistenceAnalysis(syntheticMeta(mode, rows), {
        ...options, mode, _prequeriedRows: rows, columns: {},
      }, analyzerCtx);
      if (res?.error) { warnings.push(`${mode} pass: ${res.error}`); return null; }
      // The 4104-unavailable notice is meaningless here: a folder scan reads task
      // definitions and registry exports, never a PowerShell log.
      for (const w of res.warnings || []) if (!/PowerShell 4104/i.test(w)) warnings.push(w);
      if (res.items?.length) allItems.push(...res.items);
      passes.push({ mode, items: res.items?.length || 0 });
      return res;
    } catch (err) {
      warnings.push(`${mode} pass failed — ${err.message}`);
      dbg("KAPE-COLLECTION", `${mode} pass failed`, { error: err.message });
      return null;
    }
  };

  const taskResult = runPass("evtx", taskRows);
  const regResult = runPass("registry", regRows);

  // Tag every finding with the file it came from, so a collection result is as navigable
  // as a tab-based one even though there is no grid row to jump to.
  for (const item of allItems) {
    if (!item._sourceTab) item._sourceTab = scan.host || path.basename(scan.root);
    item._sourceCollection = scan.root;
  }

  const incidents = clusterIncidents(allItems, { crossModeRegistry: true });

  const byCategory = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of allItems) {
    byCategory[item.category] = (byCategory[item.category] || 0) + 1;
    bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
  }
  const byIncidentSeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of incidents) byIncidentSeverity[inc.severity] = (byIncidentSeverity[inc.severity] || 0) + 1;

  // Coverage is stated, never implied. An analyst must be able to see that 112 EVTX files
  // and 21 hives in this folder were NOT read by this scan.
  const unread = {
    evtx: scan.artifacts.evtx.length,
    hives: scan.artifacts.hives.length,
    otherCsv: scan.artifacts.moduleCsv.filter((c) => c.kind !== "recmd-batch" && !(c.kind === "recmd-plugin" && c.projects)).length,
  };
  if (unread.evtx > 0) {
    warnings.push(`${unread.evtx} EVTX file${unread.evtx === 1 ? "" : "s"} in this collection were not read — import them as tabs and run a multi-source scan to correlate service installs, process creation and PowerShell activity.`);
  }
  if (unread.hives > 0) {
    warnings.push(`${unread.hives} registry hive${unread.hives === 1 ? "" : "s"} were found but not parsed — load the RECmd batch/plugin output for this collection to cover Run keys, services and Winlogon.`);
  }

  return {
    items: allItems,
    incidents,
    warnings,
    collectionScan: true,
    collection: {
      root: scan.root, host, hostSource: options.computerName ? "user" : scan.hostSource,
      layout: scan.layout,
      counts: {
        taskXml: scan.artifacts.taskXml.length,
        hives: scan.artifacts.hives.length,
        evtx: scan.artifacts.evtx.length,
        moduleCsv: scan.artifacts.moduleCsv.length,
      },
      read: { taskDefinitions: taskRows.length, registryRows: regRows.length, registrySources: regSources },
      unread,
      stats: scan.stats,
    },
    columns: {},
    detectedMode: taskRows.length && regRows.length ? "mixed" : (taskRows.length ? "evtx" : "registry"),
    stats: {
      total: allItems.length,
      incidentCount: incidents.length,
      byCategory,
      bySeverity,
      byIncidentSeverity,
      suspicious: allItems.filter((i) => i.isSuspicious).length,
      suspiciousIncidents: incidents.filter((i) => i.isSuspicious).length,
      uniqueComputers: new Set(allItems.map((i) => i.computer).filter(Boolean)).size,
      categoriesFound: Object.keys(byCategory).length,
      taskDefinitionsRead: taskRows.length,
      registryRowsRead: regRows.length,
      registryInventorySuppressed: regResult?.stats?.registryInventorySuppressed || 0,
      passes,
    },
    error: null,
  };
}

module.exports = {
  analyzeCollection,
  hiveFromPluginFileName,
  readTaskDefinitions,
  readRegistryCsvs,
  taskToHaystackFields,
  parseCsv,
};
