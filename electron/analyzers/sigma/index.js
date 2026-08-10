/**
 * sigma/index.js — Sigma Rule Scanner Orchestrator
 *
 * Scans a dataset against Sigma rules using a two-phase approach:
 *   Phase 1: SQL pre-filter by logsource (channel + EventID)
 *   Phase 2: In-memory predicate evaluation per rule
 *
 * Groups rules by logsource to minimize SQL queries.
 * Handles all data formats: raw EVTX, EvtxECmd, Hayabusa, Chainsaw.
 */

const { dbg } = require("../../logger");
const { mapLogsource, logsourceKey } = require("./logsource-mapper");
const { createFieldResolver } = require("./field-mapper");
const { compileDetection } = require("./condition-compiler");
const { getAllRules, getCacheStatus } = require("./rule-cache");
const { SigmaResultStore } = require("./result-store");
const { resolveDatasetFormat } = require("./format-detect");
const { severityHistogram, sortMatchesBySeverity } = require("./match-utils");
const { ensureSigmaFilterIndexes } = require("./sigma-filter-indexes");
const { buildGroupSelectClause, MATCH_DETAIL_FIELDS } = require("./scan-columns");

/**
 * Scan a dataset against Sigma rules.
 *
 * @param {object} meta - Database handle { db, headers, colMap, tabId }
 * @param {object} options
 * @param {string[]} [options.levels] - Filter rules by level: ["critical","high","medium","low"]
 * @param {string[]} [options.statuses] - Filter rules by status: ["stable","test","experimental"]
 * @param {string[]} [options.categories] - Filter by Sigma category
 * @param {number} [options.maxRowsPerQuery=1000000] - Max candidate rows per logsource query
 * @param {Function} [onProgress] - Progress callback: { phase, rulesEvaluated, totalRules, matchesFound }
 * @returns {{ matches: Array, stats: object, errors: string[], warnings: string[] }}
 */
async function scanSigmaRules(meta, options = {}, onProgress) {
  if (!meta || !meta.db) return { matches: [], stats: {}, errors: ["No database"], warnings: [] };

  const {
    levels = ["critical", "high", "medium", "low", "informational"],
    statuses = ["stable", "test", "experimental"],
    categories = null, // null = all
    maxRowsPerQuery = 5000000, // per-logsource cap; scan streams (db.iterate) so this bounds CPU/time, not memory. Keep in sync with JS_SIGMA_MAX_ROWS_PER_QUERY (sigmaModalHelpers.js)
    resultStorePath = null,
    previewLimit = 2000,
    isCancelled = null,
    disabledRuleIds = [],
  } = options;

  const db = meta.db;
  const errors = [];
  const warnings = [];

  // Detect format (or honor an explicit analyst override via options.formatOverride)
  const fmt = resolveDatasetFormat(meta, options.formatOverride);
  const { isEvtxECmd, isHayabusa, isChainsaw, isRawEvtx } = fmt.flags;
  const formatFlags = fmt.flags;
  if (fmt.overridden) {
    dbg("SIGMA", `Format overridden to ${fmt.label} (auto-detected ${fmt.detectedLabel})`);
    warnings.push(`Format set to ${fmt.label} by override (auto-detected ${fmt.detectedLabel}).`);
  } else {
    dbg("SIGMA", `Format detected: ${fmt.label}`);
  }

  // Create field resolver
  const resolve = createFieldResolver(meta, formatFlags);

  // Detect key columns for SQL pre-filtering
  const detect = (pats) => { for (const p of pats) { const f = meta.headers.find(h => p.test(h)); if (f) return meta.colMap[f]; } return null; };
  const eidCol = detect([/^EventID$/i, /^event_id$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]);
  const channelCol = detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]);
  const tsCol = detect([/^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, /^UtcTime$/i, ...(isChainsaw ? [/^system_time$/i] : [])]);
  const computerCol = detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]);

  // Load rules
  const { rules: allRules, cachedCount, customCount, compatibilityReport, ruleSnapshotHash } = getAllRules();
  dbg("SIGMA", `Loaded ${allRules.length} rules (cached: ${cachedCount}, custom: ${customCount})`);

  if (allRules.length === 0) {
    return {
      matches: [], eventRows: [], stats: { totalRules: 0, matchedRules: 0, totalMatches: 0, rowsScanned: 0, bySeverity: {}, ruleCompatibility: compatibilityReport || null, ruleSnapshotHash: ruleSnapshotHash || null, format: fmt.label },
      errors: ["No Sigma rules loaded. Download rules from SigmaHQ GitHub or import custom YAML rules first."],
      warnings,
    };
  }

  // Filter rules by user preferences
  const levelSet = new Set(levels);
  const statusSet = new Set(statuses);
  const disabledSet = new Set((disabledRuleIds || []).map((id) => String(id || "").trim().toLowerCase()).filter(Boolean));
  const filteredRules = allRules.filter(r => {
    if (r.id && disabledSet.has(String(r.id).toLowerCase())) return false;
    if (!levelSet.has(r.level)) return false;
    if (!statusSet.has(r.status)) return false;
    if (r.logsource.product && r.logsource.product !== "windows") return false;
    if (categories && r.logsource.category && !categories.includes(r.logsource.category)) return false;
    return true;
  });
  const compatibleRules = filteredRules.filter((r) => r._compatibility?.supported !== false);
  const skippedIncompatible = filteredRules.length - compatibleRules.length;
  const skippedSuppressed = disabledSet.size ? allRules.filter((r) => r.id && disabledSet.has(String(r.id).toLowerCase())).length : 0;
  dbg("SIGMA", `Filtered to ${filteredRules.length} rules (levels: ${levels.join(",")}, statuses: ${statuses.join(",")})`);

  if (filteredRules.length === 0 || compatibleRules.length === 0) {
    return {
      matches: [], eventRows: [], stats: { totalRules: allRules.length, selectedRules: filteredRules.length, compatibleRules: compatibleRules.length, skippedIncompatibleRules: skippedIncompatible, skippedSuppressedRules: skippedSuppressed, matchedRules: 0, totalMatches: 0, rowsScanned: 0, bySeverity: {}, ruleCompatibility: compatibilityReport || null, ruleSnapshotHash: ruleSnapshotHash || null, format: fmt.label },
      errors: [filteredRules.length === 0
        ? `All ${allRules.length} rules were filtered out by severity/status/category filters. Adjust filters and try again.`
        : `All ${filteredRules.length} selected rules are incompatible with the JS Sigma engine. Check the rule compatibility report.`],
      warnings,
    };
  }
  if (skippedIncompatible > 0) {
    warnings.push(`${skippedIncompatible.toLocaleString()} selected rule${skippedIncompatible === 1 ? " was" : "s were"} skipped due to unsupported JS Sigma compatibility syntax/logsource. Check the compatibility report.`);
  }
  if (skippedSuppressed > 0) {
    warnings.push(`${skippedSuppressed.toLocaleString()} disabled/noisy rule${skippedSuppressed === 1 ? " was" : "s were"} skipped by Detection Settings suppression.`);
  }

  // Group rules by logsource
  const ruleGroups = new Map(); // logsourceKey -> { logsource, rules: [], compiled: [] }
  for (const rule of compatibleRules) {
    const key = logsourceKey(rule.logsource);
    if (!ruleGroups.has(key)) {
      ruleGroups.set(key, { logsource: rule.logsource, rules: [], compiled: [] });
    }
    const group = ruleGroups.get(key);
    group.rules.push(rule);
    try {
      const predicate = compileDetection(rule.detection);
      group.compiled.push({ rule, predicate });
    } catch (err) {
      warnings.push(`Rule "${rule.title}": compilation failed — ${err.message}`);
    }
  }
  dbg("SIGMA", `${ruleGroups.size} logsource groups`);

  // Results
  const matches = []; // rule-level summaries
  const eventRows = []; // preview rows in persisted mode, capped rows in legacy mode
  const resultStore = resultStorePath ? new SigmaResultStore({ dbPath: resultStorePath }) : null;
  const resultBuffer = [];
  const RESULT_FLUSH_SIZE = 1000;
  const assertNotCancelled = () => {
    if (typeof isCancelled === "function" && isCancelled()) {
      throw Object.assign(new Error("Job cancelled"), { cancelled: true });
    }
  };
  const flushResultBuffer = () => {
    if (!resultStore || resultBuffer.length === 0) return;
    resultStore.addRows(resultBuffer.splice(0, resultBuffer.length));
  };
  const addEventRow = (evtRow) => {
    if (resultStore) {
      if (eventRows.length < previewLimit) eventRows.push(evtRow);
      resultBuffer.push(evtRow);
      if (resultBuffer.length >= RESULT_FLUSH_SIZE) flushResultBuffer();
      return;
    }
    if (eventRows.length < MAX_EVENT_ROWS) {
      eventRows.push(evtRow);
    } else if (!eventRowsCapped) {
      eventRowsCapped = true;
    }
  };
  const ruleMatches = new Map(); // rule.id -> { count, firstTs, lastTs, sampleRows }
  let totalRulesEvaluated = 0;
  let totalRowsScanned = 0;
  let truncatedGroups = 0; // track if any logsource group hit the row limit
  // Hard cap on per-event rows to prevent OOM with broad rules. Aggregation continues past the cap;
  // only the materialized per-event timeline is truncated.
  const MAX_EVENT_ROWS = 100000;
  let eventRowsCapped = false;

  const rowCount = meta.rowCount || 0;
  const yieldInterval = rowCount >= 1_000_000 ? 5000 : 1000;

  try {
    onProgress?.({ phase: "indexing", text: "Preparing EventID/Channel indexes for scan..." });
    const { built: sigmaIndexesBuilt, columns: sigmaIndexCols } = ensureSigmaFilterIndexes(meta);
    if (sigmaIndexesBuilt > 0) {
      warnings.push(
        `Built ${sigmaIndexesBuilt} EventID/Channel index${sigmaIndexesBuilt === 1 ? "" : "es"} before scanning (${sigmaIndexCols.join(", ")}) — this one-time step speeds up large-tab JS Sigma scans.`,
      );
    }

    // Process each logsource group
    let groupIdx = 0;
    for (const [key, group] of ruleGroups) {
      assertNotCancelled();
      groupIdx++;
      if (group.compiled.length === 0) continue;

      const mapped = mapLogsource(group.logsource);
      if (mapped.skip) continue; // non-Windows logsource

      // Build SQL WHERE for logsource pre-filter
      const whereParts = [];
      const params = [];

    // EventID filter
      if (eidCol && mapped.eids.length > 0) {
        whereParts.push(`${eidCol} IN (${mapped.eids.map(() => "?").join(",")})`);
        params.push(...mapped.eids);
      }

    // Channel filter — different strategy per format
    // For EvtxECmd: single CSV contains ALL channels, so Channel column is always populated
    //   and contains full names like "Microsoft-Windows-Sysmon/Operational"
    // For raw EVTX: Channel column has the same full names
    // For Hayabusa: Channel column has abbreviated names (Sec, Sys, Sysmon)
      if (channelCol && mapped.channels.length > 0) {
        // For EvtxECmd combined CSVs, use OR with both short and full channel names
        const channelConds = [];
        for (const ch of mapped.channels) {
          channelConds.push(`LOWER(${channelCol}) LIKE ?`);
          params.push(`%${ch}%`);
          // Also match full Windows channel names for EvtxECmd
          const fullChannelMap = {
            sysmon: "sysmon/operational",
            security: "security",
            system: "system",
            powershell: "powershell/operational",
            taskscheduler: "task scheduler/operational",
            "wmi-activity": "wmi-activity/operational",
          };
          if (fullChannelMap[ch] && fullChannelMap[ch] !== ch) {
            channelConds.push(`LOWER(${channelCol}) LIKE ?`);
            params.push(`%${fullChannelMap[ch]}%`);
          }
        }
        // For EvtxECmd, also match Provider column which has names like "Microsoft-Windows-Sysmon"
        const providerCol = detect([/^Provider$/i]);
        if (providerCol && providerCol !== channelCol) {
          for (const ch of mapped.channels) {
            channelConds.push(`LOWER(${providerCol}) LIKE ?`);
            params.push(`%${ch}%`);
          }
        }
        whereParts.push(`(${channelConds.join(" OR ")})`);
      }

      // For logsources with no specific channel/EID constraints (e.g., service: security with no category),
      // avoid scanning the entire dataset — at least require channel match
      if (whereParts.length === 0 && mapped.channels.length === 0 && mapped.eids.length === 0) {
        // Skip logsource groups with no constraints to avoid full table scans
        dbg("SIGMA", `Skipping group ${key}: no channel or EID constraints`);
        continue;
      }

      const whereClause = whereParts.length > 0 ? `WHERE ${whereParts.join(" AND ")}` : "";
      const selectClause = buildGroupSelectClause(meta, formatFlags, group.rules, {
        tsCol, computerCol, eidCol, channelCol,
      });
      const sql = `SELECT ${selectClause} FROM data ${whereClause} LIMIT ${maxRowsPerQuery}`;

    let rowsScannedForGroup = 0;
    try {
      const stmt = db.prepare(sql);
      const iterator = stmt.iterate(...params);

      dbg("SIGMA", `Group ${groupIdx}/${ruleGroups.size} (${key}): streaming candidate rows, ${group.compiled.length} rules`);

      // Evaluate all rules against each row
      for (const row of iterator) {
        rowsScannedForGroup++;
        if (rowsScannedForGroup > 0 && rowsScannedForGroup % yieldInterval === 0) {
          assertNotCancelled();
          await new Promise(r => setImmediate(r));
          onProgress?.({
            phase: "scanning",
            groupsCompleted: groupIdx - 1,
            totalGroups: ruleGroups.size,
            rulesEvaluated: totalRulesEvaluated,
            totalRules: compatibleRules.length,
            matchesFound: ruleMatches.size,
            rowsScanned: totalRowsScanned + rowsScannedForGroup,
            currentGroup: key,
            groupProgress: `${rowsScannedForGroup} rows`,
          });
        }
        for (const { rule, predicate } of group.compiled) {
          try {
            if (predicate(resolve, row)) {
              // Match found — update rule summary
              const ruleId = rule.id || rule.title;
              if (!ruleMatches.has(ruleId)) {
                ruleMatches.set(ruleId, { rule, count: 0, firstTs: row._ts || "", lastTs: row._ts || "", sampleRows: [], hosts: new Set() });
              }
              const rm = ruleMatches.get(ruleId);
              rm.count++;
              if (row._ts && (!rm.firstTs || row._ts < rm.firstTs)) rm.firstTs = row._ts;
              if (row._ts && (!rm.lastTs || row._ts > rm.lastTs)) rm.lastTs = row._ts;
              if (row._host) rm.hosts.add(String(row._host).toUpperCase());
              if (rm.sampleRows.length < 5) {
                const sample = { _rid: row._rid, _ts: row._ts, _host: row._host };
                for (const f of MATCH_DETAIL_FIELDS) {
                  const v = resolve(f, row);
                  if (v) sample[f] = v.substring(0, 200);
                }
                rm.sampleRows.push(sample);
              }

              // Build per-event row with individual columns for each field
              const eventId = resolve("EventID", row) || row.EventID || row.EventId || row.eventId || row.id || "";
              const userName = resolve("TargetUserName", row) || resolve("User", row) || resolve("SubjectUserName", row) || row.UserName || "";
              const channel = row.Channel || row.channel || row.Provider || "";

              const evtRow = {
                Timestamp: row._ts || "",
                Computer: row._host || "",
                Channel: channel,
                EventID: String(eventId),
                Level: rule.level,
                RuleID: rule.id || "",
                RuleTitle: rule.title,
                User: userName,
                MITRE: (rule.mitre || []).join(", "),
                Description: (rule.description || "").substring(0, 300),
                Category: rule.logsource.category || rule.logsource.service || "",
                Author: rule.author || "",
                SourceTabId: meta.tabId || "",
                SourceRowId: row._rid || "",
              };

              // Resolve each Sigma field into its own column
              for (const f of MATCH_DETAIL_FIELDS) {
                const v = resolve(f, row);
                if (v && v.length > 0) evtRow[f] = v.substring(0, 500);
              }

              // For EvtxECmd: also resolve from raw EvtxECmd-specific columns
              if (isEvtxECmd) {
                if (!evtRow.Image && row.ExecutableInfo) evtRow.Image = String(row.ExecutableInfo).trim();
                if (row.MapDescription) evtRow.MapDescription = String(row.MapDescription).trim().substring(0, 300);
                if (row.RemoteHost) evtRow.RemoteHost = String(row.RemoteHost).trim();
              }

              // For raw EVTX: include all non-system EventData columns
              if (isRawEvtx) {
                for (const h of meta.headers) {
                  if (["datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message"].includes(h)) continue;
                  if (evtRow[h]) continue; // already resolved
                  const v = row[h];
                  if (v && String(v).trim()) evtRow[h] = String(v).trim().substring(0, 500);
                }
              }

              addEventRow(evtRow);
            }
          } catch (_) { /* skip rule errors for individual rows */ }
        }
      }
      } catch (err) {
        if (err?.cancelled) throw err;
        errors.push(`Logsource query failed (${key}): ${err.message}`);
        continue;
      }

      totalRowsScanned += rowsScannedForGroup;
      if (rowsScannedForGroup >= maxRowsPerQuery) {
        truncatedGroups++;
        warnings.push(`Logsource group "${key}" hit row limit (${maxRowsPerQuery.toLocaleString()} rows) — some detections may be incomplete`);
      }
      dbg("SIGMA", `Group ${groupIdx}/${ruleGroups.size} (${key}): ${rowsScannedForGroup} candidate rows, ${group.compiled.length} rules`);

      totalRulesEvaluated += group.compiled.length;
      onProgress?.({
        phase: "scanning",
        groupsCompleted: groupIdx,
        totalGroups: ruleGroups.size,
        rulesEvaluated: totalRulesEvaluated,
        totalRules: compatibleRules.length,
        matchesFound: ruleMatches.size,
        rowsScanned: totalRowsScanned,
      });
    }
    flushResultBuffer();
  } catch (err) {
    if (resultStore) {
      try { resultStore.close(); } catch {}
      SigmaResultStore.destroy(resultStorePath);
    }
    throw err;
  }

  // Build final matches array
  for (const [, rm] of ruleMatches) {
    matches.push({
      ruleId: rm.rule.id,
      title: rm.rule.title,
      level: rm.rule.level,
      status: rm.rule.status,
      description: rm.rule.description,
      author: rm.rule.author,
      category: rm.rule.logsource.category || rm.rule.logsource.service || "",
      mitre: rm.rule.mitre,
      tactics: rm.rule.tactics,
      tags: rm.rule.tags,
      falsepositives: rm.rule.falsepositives,
      matchCount: rm.count,
      firstSeen: rm.firstTs,
      lastSeen: rm.lastTs,
      hosts: [...rm.hosts],
      sampleRows: rm.sampleRows,
      isCustom: !!rm.rule._isCustom,
    });
  }

  // Sort by severity then match count (shared with the Hayabusa engine)
  sortMatchesBySeverity(matches);

  const persistedSummary = resultStore
    ? resultStore.finalize({
      engine: "IRFlow Sigma Engine",
      sourceFormat: fmt.label,
    })
    : null;

  const stats = {
    totalRules: compatibleRules.length,
    selectedRules: filteredRules.length,
    skippedIncompatibleRules: skippedIncompatible,
    skippedSuppressedRules: skippedSuppressed,
    compatibleRules: compatibleRules.length,
    matchedRules: matches.length,
    totalMatches: matches.reduce((s, m) => s + m.matchCount, 0),
    rowsScanned: totalRowsScanned,
    truncatedGroups,
    maxRowsPerQuery,
    eventRowsCapped: resultStore ? false : eventRowsCapped,
    eventRowCap: resultStore ? null : MAX_EVENT_ROWS,
    bySeverity: severityHistogram(matches),
    format: fmt.label,
    detectedFormat: fmt.detectedLabel,
    formatOverridden: fmt.overridden,
    ruleCompatibility: compatibilityReport || null,
    ruleSnapshotHash: ruleSnapshotHash || null,
  };

  onProgress?.({ phase: "done", ...stats });

  // Sort event rows by timestamp (Hayabusa-style chronological view)
  eventRows.sort((a, b) => (a.Timestamp || "").localeCompare(b.Timestamp || ""));

  if (resultStore) resultStore.close();

  return {
    matches,
    eventRows,
    resultDbPath: persistedSummary?.dbPath || null,
    resultHeaders: persistedSummary?.headers || null,
    eventRowCount: persistedSummary?.rowCount ?? eventRows.length,
    stats,
    errors,
    warnings,
  };
}

module.exports = { scanSigmaRules, getCacheStatus, getAllRules };
