// Rule health / coverage report for Process Inspector.
// Pure: detMap + rule catalog + sequences → report model for the UI.

import { PI_ALL_RULES, PI_RULE_GROUPS } from "./process-inspector.js";
import { SEQ_DEFS } from "./process-inspector-pipeline.js";

const SEV_RANK = { critical: 3, high: 2, medium: 1, med: 1, low: 0 };
const severityRank = (rule) => SEV_RANK[String(rule?.sev || "").toLowerCase()] ?? -1;
const compareRulePriority = (a, b) =>
  severityRank(b) - severityRank(a)
  || (b.hits || 0) - (a.hits || 0)
  || String(a.id || "").localeCompare(String(b.id || ""));

/**
 * Aggregate which built-in and custom rules fired on a scored process tree.
 *
 * @param {Map} detMap - key → detection result from buildDetectionMap
 * @param {object} opts
 * @param {Set|null} opts.disabledRules
 * @param {Array} opts.customRules - raw custom rule list (pre-compile)
 * @param {Map|null} opts.seqMap - key → sequence hits array
 * @param {Array} opts.ruleCatalog - defaults to PI_ALL_RULES
 * @param {Array} opts.seqDefs - defaults to SEQ_DEFS
 */
export function buildRuleHealthReport(detMap, opts = {}) {
  const disabled = opts.disabledRules || new Set();
  const catalog = opts.ruleCatalog || PI_ALL_RULES;
  const customRules = opts.customRules || [];
  const seqDefs = opts.seqDefs || SEQ_DEFS;
  const seqMap = opts.seqMap || null;

  const hitCounts = new Map(); // ruleId → count
  const hitLevels = new Map(); // ruleId → max level seen
  const behaviorHits = new Map();
  const techniqueHits = new Map();
  let processesScored = 0;
  let processesDetected = 0;

  if (detMap?.size) {
    for (const det of detMap.values()) {
      processesScored++;
      if ((det?.level || 0) > 0) processesDetected++;
      for (const e of (det?.evidence || [])) {
        const id = e.ruleId || (e.cat === "chain" ? "chain" : "unknown");
        hitCounts.set(id, (hitCounts.get(id) || 0) + 1);
        const lv = e.level ?? 0;
        if (!hitLevels.has(id) || lv > hitLevels.get(id)) hitLevels.set(id, lv);
        if (e.beh) behaviorHits.set(e.beh, (behaviorHits.get(e.beh) || 0) + 1);
        for (const tid of (e.tid || [])) {
          if (tid) techniqueHits.set(tid, (techniqueHits.get(tid) || 0) + 1);
        }
      }
      // Behaviors / techniques also on the aggregated det
      for (const b of (det?.behaviors || [])) {
        if (b) behaviorHits.set(b, behaviorHits.get(b) || 0);
      }
    }
  }

  const builtIn = catalog.map((rule) => {
    const id = rule.id;
    const hits = hitCounts.get(id) || 0;
    const disabledOn = disabled.has(id);
    const defaultLevel = SEV_RANK[rule.sev] ?? rule.level ?? 0;
    return {
      id,
      name: rule.name || id,
      group: rule.group || "misc",
      sev: rule.sev || (defaultLevel >= 3 ? "critical" : defaultLevel === 2 ? "high" : defaultLevel === 1 ? "medium" : "low"),
      technique: rule.technique || (Array.isArray(rule.tid) ? rule.tid.join(", ") : ""),
      hits,
      maxLevelSeen: hitLevels.get(id) ?? null,
      disabled: disabledOn,
      status: disabledOn ? "disabled" : hits > 0 ? "fired" : "silent",
      chain: !!rule.chain || String(id).match(/^pi-(0|1|2|18|60)$/),
    };
  });

  // Custom rules appear as custom-N in evidence
  const custom = customRules.map((cr, i) => {
    const id = `custom-${i}`;
    const hits = hitCounts.get(id) || 0;
    return {
      id,
      name: cr.name || `Custom ${i + 1}`,
      group: "custom",
      sev: cr.severity || "medium",
      technique: cr.technique || "",
      behavior: cr.behavior || "",
      hits,
      status: hits > 0 ? "fired" : "silent",
      pattern: cr.pattern || "",
      parentProcess: cr.parentProcess || "",
      processName: cr.processName || "",
    };
  });

  // Orphan rule IDs seen in evidence but not in catalog (shouldn't happen often)
  const knownIds = new Set([...builtIn.map((r) => r.id), ...custom.map((r) => r.id)]);
  const orphans = [];
  for (const [id, hits] of hitCounts) {
    if (knownIds.has(id)) continue;
    if (String(id).startsWith("custom-")) continue;
    const level = hitLevels.get(id) ?? 1;
    const sev = level >= 3 ? "critical" : level >= 2 ? "high" : level >= 1 ? "medium" : "low";
    orphans.push({ id, hits, status: "fired", name: id, group: "other", sev });
  }

  const byGroup = {};
  for (const g of (PI_RULE_GROUPS || [])) {
    byGroup[g.id] = {
      id: g.id,
      label: g.label,
      fired: 0,
      silent: 0,
      disabled: 0,
      hits: 0,
    };
  }
  byGroup.custom = { id: "custom", label: "Custom Rules", fired: 0, silent: 0, disabled: 0, hits: 0 };
  byGroup.other = { id: "other", label: "Other", fired: 0, silent: 0, disabled: 0, hits: 0 };

  for (const r of [...builtIn, ...custom, ...orphans]) {
    const g = byGroup[r.group] || byGroup.other;
    if (r.status === "fired") g.fired++;
    else if (r.status === "disabled") g.disabled++;
    else g.silent++;
    g.hits += r.hits || 0;
  }

  // Sequence health
  const seqHitCounts = new Map();
  if (seqMap?.size) {
    for (const hits of seqMap.values()) {
      for (const h of (hits || [])) {
        const id = h.seqId || h.id;
        if (!id) continue;
        seqHitCounts.set(id, (seqHitCounts.get(id) || 0) + 1);
      }
    }
  }
  const sequences = seqDefs.map((s) => ({
    id: s.id,
    name: s.name,
    tid: s.tid || [],
    hits: seqHitCounts.get(s.id) || 0,
    status: (seqHitCounts.get(s.id) || 0) > 0 ? "fired" : "silent",
  }));

  const builtInFired = builtIn.filter((r) => r.status === "fired");
  const builtInSilent = builtIn.filter((r) => r.status === "silent");
  const builtInDisabled = builtIn.filter((r) => r.status === "disabled");

  const topFired = [...builtIn, ...custom, ...orphans]
    .filter((r) => r.hits > 0)
    .sort(compareRulePriority)
    .slice(0, 15);

  const techniques = [...techniqueHits.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([tid, count]) => ({ tid, count }));

  const behaviors = [...behaviorHits.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([beh, count]) => ({ beh, count }));

  return {
    processesScored,
    processesDetected,
    summary: {
      catalogSize: builtIn.length,
      fired: builtInFired.length,
      silent: builtInSilent.length,
      disabled: builtInDisabled.length,
      customFired: custom.filter((r) => r.status === "fired").length,
      customTotal: custom.length,
      sequencesFired: sequences.filter((s) => s.status === "fired").length,
      sequencesTotal: sequences.length,
      coveragePct: builtIn.length
        ? Math.round((builtInFired.length / Math.max(1, builtIn.length - builtInDisabled.length)) * 100)
        : 0,
    },
    builtIn,
    custom,
    orphans,
    byGroup: Object.values(byGroup).filter((g) => g.fired + g.silent + g.disabled > 0),
    sequences,
    topFired,
    techniques,
    behaviors,
    silentHighValue: builtInSilent
      .filter((r) => r.sev === "critical" || r.sev === "high")
      .sort(compareRulePriority)
      .slice(0, 20),
  };
}

/** Plain-text export for copy/download. */
export function formatRuleHealthReportText(report) {
  if (!report) return "";
  const s = report.summary;
  const lines = [
    "Process Inspector — Rule Health Report",
    `Processes scored: ${s.processesScored ?? report.processesScored}`,
    `Detected: ${report.processesDetected}`,
    `Built-in: ${s.fired} fired / ${s.silent} silent / ${s.disabled} disabled (of ${s.catalogSize})`,
    `Coverage (enabled rules that fired): ${s.coveragePct}%`,
    `Custom: ${s.customFired}/${s.customTotal} fired`,
    `Sequences: ${s.sequencesFired}/${s.sequencesTotal} fired`,
    "",
    "Fired rules (severity first):",
    ...report.topFired.map((r) => `  ${r.hits}×  [${r.sev}] ${r.id} — ${r.name}`),
    "",
    "Silent high-value rules (enabled, no hits):",
    ...(report.silentHighValue.length
      ? report.silentHighValue.map((r) => `  [${r.sev}] ${r.id} — ${r.name}`)
      : ["  (none)"]),
    "",
    "Sequences:",
    ...report.sequences.map((s) => `  ${s.hits}×  ${s.id} — ${s.name}`),
    "",
    "Techniques:",
    ...(report.techniques.length
      ? report.techniques.map((t) => `  ${t.count}×  ${t.tid}`)
      : ["  (none)"]),
  ];
  return lines.join("\n");
}
