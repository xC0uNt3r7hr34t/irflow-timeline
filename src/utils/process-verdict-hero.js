// Verdict-first summary for Process Inspector results.
// Pure: data + detection/story maps → hero model for the results banner.

const SEV_RANK = { 3: "critical", 2: "high", 1: "medium", 0: "clean" };

const _sevLabel = (level) => SEV_RANK[level] || "clean";

/**
 * Summarize link quality from tree stats.linkCounts.
 * @returns {{ mode: "guid"|"mixed"|"pid"|"unknown", guidPct: number, label: string }}
 */
export const summarizeLinkQuality = (stats = {}) => {
  const counts = stats.linkCounts || {};
  let total = 0;
  let guid = 0;
  let pid = 0;
  for (const [src, n] of Object.entries(counts)) {
    const c = Number(n) || 0;
    total += c;
    if (src === "guid") guid += c;
    else if (src === "pid-logon" || src === "pid-session" || src === "pid-host" || src === "resolved") pid += c;
  }
  if (total === 0) {
    // Fall back to useGuid flag if present on data
    return { mode: "unknown", guidPct: 0, label: "Link quality unknown", guid, pid, total };
  }
  const guidPct = Math.round((guid / total) * 100);
  let mode = "mixed";
  let label = `Mixed linking (${guidPct}% GUID)`;
  if (guidPct >= 85) {
    mode = "guid";
    label = `GUID-linked (${guidPct}%)`;
  } else if (guidPct <= 15) {
    mode = "pid";
    label = `PID-linked (${100 - guidPct}% PID/session)`;
  }
  return { mode, guidPct, label, guid, pid, total };
};

/**
 * Telemetry completeness chips from tree build stats.
 * EID 1/4688 are implied by tree build; 5/4689 = terminate, 10 = access, 4673/4674 = privilege.
 */
export const summarizeTelemetryCompleteness = (stats = {}) => {
  const term = Number(stats.terminateMatched) || 0;
  const access = Number(stats.accessMatched) || 0;
  const priv = Number(stats.privilegeMatched) || 0;
  const net = Number(stats.networkMatched) || 0;
  const dns = Number(stats.dnsMatched) || 0;
  const img = Number(stats.imageLoadMatched) || 0;
  const file = Number(stats.fileCreateMatched) || 0;
  const total = Number(stats.totalProcesses) || 0;
  return {
    processCreate: { id: "1/4688", label: "Process Create", present: total > 0, count: total },
    terminate: { id: "5/4689", label: "Terminate", present: term > 0, count: term },
    processAccess: { id: "10", label: "Process Access", present: access > 0, count: access },
    privilegeUse: { id: "4673/4674", label: "Privilege Use", present: priv > 0, count: priv },
    network: { id: "3", label: "Network", present: net > 0, count: net },
    dns: { id: "22", label: "DNS", present: dns > 0, count: dns },
    imageLoad: { id: "7", label: "Image Load", present: img > 0, count: img },
    fileCreate: { id: "11", label: "File Create", present: file > 0, count: file },
  };
};

/**
 * Build the verdict hero model after a successful tree build.
 *
 * @param {object} opts
 * @param {object} opts.data - getProcessTree result ({ processes, stats, useGuid })
 * @param {Map} opts.detMap - process key → detection info
 * @param {Array} opts.stories - incident stories (already ranked)
 * @param {Array} opts.clusters - chain clusters (optional fallback when no stories)
 */
export const buildProcessVerdictHero = ({ data, detMap, stories = [], clusters = [] } = {}) => {
  const processes = data?.processes || [];
  const stats = data?.stats || {};
  const total = processes.length || stats.totalProcesses || 0;

  let worstLevel = 0;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let detected = 0;
  const techniqueCounts = new Map();

  if (detMap?.size) {
    for (const det of detMap.values()) {
      const lv = det?.level || 0;
      if (lv <= 0) continue;
      detected++;
      if (lv > worstLevel) worstLevel = lv;
      if (lv >= 3) critical++;
      else if (lv === 2) high++;
      else if (lv === 1) medium++;
      for (const tid of (det.techniques || [])) {
        if (!tid) continue;
        techniqueCounts.set(tid, (techniqueCounts.get(tid) || 0) + 1);
      }
    }
  }

  // Stories already triage-sorted by the pipeline; take top 3.
  const topStories = (stories || []).slice(0, 3).map((s) => ({
    id: s.id,
    title: s.title || s.leadReason || "Investigation story",
    level: s.level || 0,
    hostname: s.hostname || "",
    leadReason: s.leadReason || "",
    eventCount: s.eventCount || 0,
    techniques: (s.techniques || []).slice(0, 4),
    anchorKey: s.anchorKey || null,
  }));

  // If no stories yet, surface top clusters as pseudo-stories for the hero.
  const topClusters = (!topStories.length && clusters?.length)
    ? clusters
      .filter((c) => (c.level || 0) > 0)
      .slice(0, 3)
      .map((c) => ({
        id: c.id,
        title: c.reason || "Suspicious chain",
        level: c.level || 0,
        hostname: c.hostname || "",
        leadReason: c.reason || "",
        eventCount: c.count || 0,
        techniques: [],
        anchorKey: c.members?.[0]?.key || null,
      }))
    : [];

  const headlines = topStories.length ? topStories : topClusters;

  const techniques = [...techniqueCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 8)
    .map(([tid, count]) => ({ tid, count }));

  const linkQuality = summarizeLinkQuality(stats);
  if (data?.useGuid && linkQuality.mode === "unknown") {
    linkQuality.mode = "guid";
    linkQuality.label = "GUID-linked";
  } else if (data?.useGuid === false && linkQuality.mode === "unknown") {
    linkQuality.mode = "pid";
    linkQuality.label = "PID-linked";
  }

  const telemetry = summarizeTelemetryCompleteness(stats);
  const truncated = !!stats.truncated;

  let verdict = "clean";
  let verdictText = "No high-signal process detections";
  if (worstLevel >= 3) {
    verdict = "critical";
    verdictText = `${critical} critical detection${critical !== 1 ? "s" : ""} — investigate first`;
  } else if (worstLevel === 2) {
    verdict = "high";
    verdictText = `${high} high-severity detection${high !== 1 ? "s" : ""}`;
  } else if (worstLevel === 1) {
    verdict = "medium";
    verdictText = `${medium} medium-severity detection${medium !== 1 ? "s" : ""}`;
  }

  if (headlines[0]?.title && worstLevel > 0) {
    verdictText = headlines[0].title;
  }

  return {
    verdict,
    verdictText,
    worstLevel,
    counts: { total, detected, critical, high, medium },
    topStories: headlines,
    techniques,
    linkQuality,
    telemetry,
    truncated,
    totalProcesses: total,
    maxDepth: stats.maxDepth || 0,
    rootCount: stats.rootCount || 0,
  };
};

export const verdictTone = (verdict, th) => {
  if (verdict === "critical") return th.sev.critical;
  if (verdict === "high") return th.sev.high;
  if (verdict === "medium") return th.sev.med;
  return th.sev.clean || th.success;
};
