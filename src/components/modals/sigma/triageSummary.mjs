export const TRIAGE_SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

function clean(value) {
  return String(value ?? "").trim();
}

function firstNonEmpty(row, keys) {
  for (const key of keys) {
    const value = clean(row?.[key]);
    if (value) return value;
  }
  return "";
}

export function sigmaRuleKey(match = {}) {
  return clean(match.ruleId || match.ruleFile || match.title || match.RuleID || match.RuleTitle);
}

function normalizeSeverity(level) {
  const text = clean(level).toLowerCase();
  return Object.prototype.hasOwnProperty.call(TRIAGE_SEVERITY_RANK, text) ? text : "informational";
}

function parseMitreList(value) {
  if (Array.isArray(value)) return value.flatMap(parseMitreList);
  return clean(value)
    .split(/[,\s;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function addCount(map, key, weight = 1) {
  const value = clean(key);
  if (!value || value === "-") return;
  map.set(value, (map.get(value) || 0) + weight);
}

function topEntries(map, limit = 10, options = {}) {
  const maxCount = options.maxCount ?? Infinity;
  return [...map.entries()]
    .filter(([, count]) => count <= maxCount)
    .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

function topEntriesDesc(map, limit = 10) {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

function normalizeAggregateEntries(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => ({
      value: clean(item?.value ?? item?.name ?? item?.title),
      count: Number(item?.count || item?.hits || 0) || 0,
    }))
    .filter((item) => item.value);
}

function mergeTime(current, next, direction) {
  const value = clean(next);
  if (!value) return current || "";
  if (!current) return value;
  return direction === "min"
    ? (value < current ? value : current)
    : (value > current ? value : current);
}

export function buildSigmaTriageSummary({ matches = [], eventRows = [], aggregates = null, reviewed = {}, falsePositives = {} } = {}) {
  const hostCounts = new Map();
  const userCounts = new Map();
  const processCounts = new Map();
  const mitreCounts = new Map();
  const tacticCounts = new Map();
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  let firstSeen = "";
  let lastSeen = "";

  for (const row of eventRows || []) {
    const host = firstNonEmpty(row, ["Computer", "Hostname", "Host", "ComputerName"]);
    const user = firstNonEmpty(row, ["User", "TargetUserName", "SubjectUserName", "UserName"]);
    const proc = firstNonEmpty(row, ["Image", "Proc", "ProcessName", "CommandLine", "Cmdline"]);
    addCount(hostCounts, host);
    addCount(userCounts, user);
    addCount(processCounts, proc);
    const ts = firstNonEmpty(row, ["Timestamp", "datetime", "TimeCreated", "UtcTime"]);
    firstSeen = mergeTime(firstSeen, ts, "min");
    lastSeen = mergeTime(lastSeen, ts, "max");
    parseMitreList(row.MITRE || row.MitreTags || row.MitreTactics).forEach((item) => {
      if (/^t\d{4}/i.test(item)) addCount(mitreCounts, item.toUpperCase());
      else addCount(tacticCounts, item);
    });
  }

  const annotatedMatches = (matches || []).map((match) => {
    const key = sigmaRuleKey(match);
    const level = normalizeSeverity(match.level);
    const count = Number(match.matchCount || match.count || 0) || 0;
    severityCounts[level] = (severityCounts[level] || 0) + count;
    for (const host of match.hosts || []) addCount(hostCounts, host, count || 1);
    for (const item of parseMitreList(match.mitre)) addCount(mitreCounts, item.toUpperCase(), count || 1);
    for (const item of parseMitreList(match.tactics)) addCount(tacticCounts, item, count || 1);
    firstSeen = mergeTime(firstSeen, match.firstSeen, "min");
    lastSeen = mergeTime(lastSeen, match.lastSeen, "max");
    return {
      ...match,
      _triageKey: key,
      _triageLevel: level,
      _triageReviewed: !!reviewed[key],
      _triageFalsePositive: !!falsePositives[key],
      _triageRank: TRIAGE_SEVERITY_RANK[level] ?? 99,
      _triageHitCount: count,
    };
  });

  const priorityFindings = annotatedMatches
    .slice()
    .sort((a, b) => {
      if (a._triageFalsePositive !== b._triageFalsePositive) return a._triageFalsePositive ? 1 : -1;
      if (a._triageReviewed !== b._triageReviewed) return a._triageReviewed ? 1 : -1;
      return a._triageRank - b._triageRank || b._triageHitCount - a._triageHitCount || clean(a.title).localeCompare(clean(b.title));
    });

  const aggregateSeverityCounts = aggregates?.severityCounts && typeof aggregates.severityCounts === "object"
    ? { ...severityCounts, ...aggregates.severityCounts }
    : severityCounts;

  return {
    priorityFindings,
    criticalHigh: priorityFindings.filter((match) => match._triageRank <= TRIAGE_SEVERITY_RANK.high),
    affectedHosts: normalizeAggregateEntries(aggregates?.affectedHosts).slice(0, 12).length
      ? normalizeAggregateEntries(aggregates?.affectedHosts).slice(0, 12)
      : topEntriesDesc(hostCounts, 12),
    firstSeen: clean(aggregates?.firstSeen) || firstSeen,
    lastSeen: clean(aggregates?.lastSeen) || lastSeen,
    mitreTechniques: normalizeAggregateEntries(aggregates?.mitreTechniques).slice(0, 12).length
      ? normalizeAggregateEntries(aggregates?.mitreTechniques).slice(0, 12)
      : topEntriesDesc(mitreCounts, 12),
    mitreTactics: normalizeAggregateEntries(aggregates?.mitreTactics).slice(0, 12).length
      ? normalizeAggregateEntries(aggregates?.mitreTactics).slice(0, 12)
      : topEntriesDesc(tacticCounts, 12),
    topRules: annotatedMatches.slice().sort((a, b) => b._triageHitCount - a._triageHitCount || a._triageRank - b._triageRank).slice(0, 10),
    rareHosts: normalizeAggregateEntries(aggregates?.rareHosts).slice(0, 8).length
      ? normalizeAggregateEntries(aggregates?.rareHosts).slice(0, 8)
      : topEntries(hostCounts, 8, { maxCount: 1 }),
    rareUsers: normalizeAggregateEntries(aggregates?.rareUsers).slice(0, 8).length
      ? normalizeAggregateEntries(aggregates?.rareUsers).slice(0, 8)
      : topEntries(userCounts, 8, { maxCount: 1 }),
    rareProcesses: normalizeAggregateEntries(aggregates?.rareProcesses).slice(0, 8).length
      ? normalizeAggregateEntries(aggregates?.rareProcesses).slice(0, 8)
      : topEntries(processCounts, 8, { maxCount: 1 }),
    severityCounts: aggregateSeverityCounts,
  };
}
