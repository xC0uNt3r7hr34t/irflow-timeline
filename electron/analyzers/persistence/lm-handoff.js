/**
 * analyzers/persistence/lm-handoff.js — publish persistence into the lateral-movement graph
 *
 * The two analyzers answered different halves of the same question and never spoke:
 *
 *   lateral movement   "WKS02 reached DC01"        — an edge, with no idea what happened next
 *   persistence        "DC01 gained a service"     — a finding, with no idea who caused it
 *
 * What an analyst wants from a triage package is the sentence both halves make together:
 * *DC01 was reached from WKS02 and a service appeared two minutes later*. A host that
 * received a pivot AND gained persistence in the same window is a confirmed hop, not a
 * logon that might be noise.
 *
 * Persistence supplies the join key (`item.remoteOrigin` = {sourceHost, sourceIp, logonId})
 * and this module attaches the result to lateral movement's graph nodes. It is deliberately
 * PURE — it takes both result sets and returns annotated copies, so neither analyzer has to
 * import the other and build-graph.js is untouched.
 */

const { corrHost } = require("./incidents");

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const worstOf = (a, b) => ((SEVERITY_ORDER[a] ?? 4) <= (SEVERITY_ORDER[b] ?? 4) ? a : b);

/**
 * Roll persistence incidents up per host.
 *
 * @param incidents  incidents from getPersistenceAnalysis / getMultiSourcePersistence
 * @returns Map<canonicalHost, summary>
 */
function summarizePersistenceByHost(incidents = []) {
  const byHost = new Map();
  for (const inc of incidents) {
    const host = corrHost(inc.computer);
    if (!host) continue;
    let entry = byHost.get(host);
    if (!entry) {
      entry = {
        host,
        count: 0,
        maxScore: 0,
        worstSeverity: "low",
        categories: new Set(),
        suspicious: 0,
        remoteOrigin: 0,
        sources: new Set(),
        firstSeen: "",
        lastSeen: "",
        topIncidents: [],
      };
      byHost.set(host, entry);
    }
    entry.count++;
    entry.maxScore = Math.max(entry.maxScore, inc.triageScore || 0);
    entry.worstSeverity = worstOf(inc.severity, entry.worstSeverity);
    if (inc.category) entry.categories.add(inc.category);
    if (inc.isSuspicious) entry.suspicious++;
    for (const it of inc.items || []) {
      if (it.remoteOrigin) {
        entry.remoteOrigin++;
        const src = it.remoteOrigin.sourceHost || it.remoteOrigin.sourceIp;
        if (src) entry.sources.add(src);
      }
    }
    if (inc.firstSeen && (!entry.firstSeen || inc.firstSeen < entry.firstSeen)) entry.firstSeen = inc.firstSeen;
    if (inc.lastSeen && (!entry.lastSeen || inc.lastSeen > entry.lastSeen)) entry.lastSeen = inc.lastSeen;
    entry.topIncidents.push(inc);
  }
  for (const entry of byHost.values()) {
    entry.categories = [...entry.categories];
    entry.sources = [...entry.sources];
    entry.topIncidents.sort((a, b) => (b.triageScore || 0) - (a.triageScore || 0));
    entry.topIncidents = entry.topIncidents.slice(0, 5).map((i) => ({
      id: i.id, title: i.title, category: i.category, severity: i.severity,
      triageScore: i.triageScore, artifact: i.artifact, firstSeen: i.firstSeen,
    }));
  }
  return byHost;
}

/**
 * The pivot edges persistence can prove: every finding that carries a remote origin is an
 * assertion that `sourceHost -> targetHost` was not just a logon but a logon that LEFT
 * something behind.
 *
 * @returns Array<{source, target, user, logonId, logonType, via, incidents, maxScore, worstSeverity}>
 */
function derivePivotEdges(incidents = []) {
  const edges = new Map();
  for (const inc of incidents) {
    const target = corrHost(inc.computer);
    for (const it of inc.items || []) {
      const ro = it.remoteOrigin;
      if (!ro) continue;
      const source = corrHost(ro.sourceHost) || ro.sourceIp;
      if (!source || !target || source === target) continue;
      const key = `${source}|${target}|${ro.logonId || ro.via}`;
      let e = edges.get(key);
      if (!e) {
        e = {
          source, target,
          sourceIp: ro.sourceIp || "",
          user: ro.user || "",
          logonId: ro.logonId || "",
          logonType: ro.logonType || "",
          via: ro.via,
          firstSeen: ro.timestamp || "",
          incidents: [],
          maxScore: 0,
          worstSeverity: "low",
          categories: new Set(),
        };
        edges.set(key, e);
      }
      if (!e.incidents.includes(inc.id)) e.incidents.push(inc.id);
      e.maxScore = Math.max(e.maxScore, inc.triageScore || 0);
      e.worstSeverity = worstOf(inc.severity, e.worstSeverity);
      if (inc.category) e.categories.add(inc.category);
    }
  }
  return [...edges.values()]
    .map((e) => ({ ...e, categories: [...e.categories] }))
    .sort((a, b) => b.maxScore - a.maxScore);
}

/**
 * Annotate lateral movement's graph nodes with what persistence found on each host.
 *
 * Returns NEW node objects — the LM result is not mutated, so this can be applied to a
 * cached graph without corrupting it.
 *
 * A node gains:
 *   persistence     the per-host rollup (null when nothing was found there)
 *   confirmedHop    true when the host BOTH received a pivot in the graph AND gained
 *                   persistence attributed to a remote origin — the thing an analyst is
 *                   actually looking for in a triage package.
 */
function annotateGraphWithPersistence(nodes = [], incidents = [], { edges = [] } = {}) {
  const byHost = summarizePersistenceByHost(incidents);
  if (byHost.size === 0) return nodes.map((n) => ({ ...n, persistence: null, confirmedHop: false }));

  // Which hosts the logon graph says were reached from somewhere else.
  const inboundTargets = new Set();
  for (const e of edges) {
    const t = corrHost(e.target);
    const s = corrHost(e.source);
    if (t && s && t !== s) inboundTargets.add(t);
  }

  return nodes.map((node) => {
    const host = corrHost(node.id || node.label);
    const p = byHost.get(host);
    if (!p) return { ...node, persistence: null, confirmedHop: false };
    const summary = {
      count: p.count,
      maxScore: p.maxScore,
      worstSeverity: p.worstSeverity,
      categories: p.categories,
      suspicious: p.suspicious,
      remoteOrigin: p.remoteOrigin,
      sources: p.sources,
      firstSeen: p.firstSeen,
      lastSeen: p.lastSeen,
      topIncidents: p.topIncidents,
    };
    // Either half alone is ambiguous: an inbound logon may be routine administration, and
    // persistence may be locally installed software. Together they are a hop that stuck.
    const confirmedHop = p.remoteOrigin > 0 || (inboundTargets.has(host) && p.suspicious > 0);
    return { ...node, persistence: summary, confirmedHop };
  });
}

/**
 * Join a persistence result to a lateral-movement result.
 *
 * @returns {{nodes, pivotEdges, byHost, stats}}
 */
function joinPersistenceToLateralMovement(lmResult = {}, persistenceResult = {}) {
  const incidents = persistenceResult.incidents || [];
  const nodes = annotateGraphWithPersistence(lmResult.nodes || [], incidents, { edges: lmResult.edges || [] });
  const pivotEdges = derivePivotEdges(incidents);
  const byHost = summarizePersistenceByHost(incidents);
  const confirmedHops = nodes.filter((n) => n.confirmedHop);

  return {
    nodes,
    pivotEdges,
    byHost: Object.fromEntries([...byHost.entries()].map(([h, v]) => [h, {
      count: v.count, maxScore: v.maxScore, worstSeverity: v.worstSeverity,
      categories: v.categories, suspicious: v.suspicious, remoteOrigin: v.remoteOrigin,
      sources: v.sources, topIncidents: v.topIncidents,
    }])),
    stats: {
      hostsWithPersistence: byHost.size,
      confirmedHops: confirmedHops.length,
      confirmedHopHosts: confirmedHops.map((n) => n.id),
      pivotEdgeCount: pivotEdges.length,
      remoteOriginIncidents: incidents.filter((i) => (i.items || []).some((it) => it.remoteOrigin)).length,
    },
  };
}

module.exports = {
  summarizePersistenceByHost,
  derivePivotEdges,
  annotateGraphWithPersistence,
  joinPersistenceToLateralMovement,
};
