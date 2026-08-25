/**
 * Deterministic, directed layout for the Lateral Movement network graph.
 *
 * Authentication graphs are usually shallow (many sources converging on one
 * target) rather than generic social graphs. A directed layered layout keeps
 * source -> target flow readable and reserves enough vertical space for host
 * labels, while still packing disconnected components predictably.
 */

export const LATERAL_GRAPH_DEFAULTS = Object.freeze({
  width: 1440,
  height: 520,
  padX: 200,
  padY: 54,
  componentGap: 48,
  rowGap: 62,
  maxNodes: 500,
  maxEdges: 1200,
});

export const LATERAL_IDENTITY_NODE_PREFIX = "lm-identity:";

const _id = (node) => String(node?.id || "");
const _rank = (node) =>
  (node?.isOutlier ? 1_000_000 : 0)
  + (Number(node?.riskScore) || 0) * 100
  + (Number(node?.eventCount) || 0);

export function selectLateralGraphNodes(nodes = [], maxNodes = LATERAL_GRAPH_DEFAULTS.maxNodes) {
  if (nodes.length <= maxNodes) return [...nodes];
  return [...nodes]
    .sort((a, b) => _rank(b) - _rank(a) || _id(a).localeCompare(_id(b)))
    .slice(0, maxNodes);
}

const _edgeId = (edge) => `${String(edge?.source || "")}->${String(edge?.target || "")}`;
const _edgeSignalCount = (edge) =>
  (Array.isArray(edge?.flags) ? edge.flags.length : 0)
  + (Array.isArray(edge?.findingIds) ? edge.findingIds.length : 0)
  + (Array.isArray(edge?.relatedFindings) ? edge.relatedFindings.length : 0);

/**
 * Bound SVG complexity while retaining the links most useful to an analyst.
 * The tuple comparison avoids letting a very noisy low-risk edge outrank a
 * high-risk edge, and the final ID comparison makes selection deterministic.
 */
export function selectLateralGraphEdges(edges = [], maxEdges = LATERAL_GRAPH_DEFAULTS.maxEdges) {
  if (edges.length <= maxEdges) return [...edges];
  return [...edges]
    .sort((a, b) =>
      (Number(b?.riskScore) || 0) - (Number(a?.riskScore) || 0)
      || _edgeSignalCount(b) - _edgeSignalCount(a)
      || (Number(b?.count) || 0) - (Number(a?.count) || 0)
      || _edgeId(a).localeCompare(_edgeId(b)))
    .slice(0, maxEdges);
}

const _identityText = (value) => String(value ?? "").trim();
const _identityKey = (value) => _identityText(value).toLocaleLowerCase();
const _knownIdentity = (value) => {
  const text = _identityText(value);
  return !!text && !/^(?:-|\\-|-\s*\\\s*-|\(unknown\)|unknown|n\/a|none|null)$/i.test(text);
};
const _dedupeText = (values = []) => {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const text = _identityText(value);
    const key = _identityKey(text);
    if (!text || seen.has(key)) continue;
    seen.add(key);
    out.push(text);
  }
  return out;
};
const _dedupeRefs = (refs = []) => {
  const seen = new Set();
  const out = [];
  for (const ref of refs) {
    if (!ref || ref.rowId == null) continue;
    const key = `${String(ref.tabId ?? "")}:${String(ref.rowId)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ tabId: ref.tabId, rowId: ref.rowId });
  }
  return out;
};
const _mergeBreakdown = (into, from) => {
  for (const [eventId, count] of Object.entries(from || {})) {
    into[eventId] = (Number(into[eventId]) || 0) + (Number(count) || 0);
  }
};
const _userActivityCount = (edge, user) => {
  const matchingEpisodes = (edge?.episodes || []).filter((episode) =>
    _identityKey(episode?.user) === _identityKey(user));
  const exact = matchingEpisodes.reduce((sum, episode) => sum + (Number(episode?.count) || 0), 0);
  if (exact > 0) return { count: exact, approximate: false };
  const users = _dedupeText(edge?.users || []);
  const total = Math.max(1, Number(edge?.count) || 1);
  if (users.length <= 1) return { count: total, approximate: false };
  // The aggregate edge proves that each listed identity participated, but it
  // cannot support a per-user event total when episode attribution is absent.
  // Keep the path visible without manufacturing a proportional count.
  return { count: 1, approximate: true };
};

export const isLateralIdentityNodeId = (value) =>
  String(value || "").startsWith(LATERAL_IDENTITY_NODE_PREFIX);

/**
 * Build an evidence-backed identity overlay for the host graph.
 *
 * Known accounts are shared across every host pair, which makes a single user's
 * multi-machine path visible. Edges with no attributable account receive a
 * pair-scoped unresolved identity node so unrelated unknown activity is never
 * merged into one misleading super-node.
 */
export function buildLateralIdentityGraph(hostNodes = [], hostEdges = []) {
  const nodesById = new Map();
  for (const node of hostNodes || []) {
    const id = _id(node);
    if (!id) continue;
    nodesById.set(id, { ...node, id, label: node?.label || id, nodeType: "host" });
  }

  const identityNodes = new Map();
  const links = new Map();
  const unattributedEdges = [];

  const getIdentity = (edge, rawUser, unresolved = false) => {
    const source = _identityText(edge?.source) || "(unknown source)";
    const target = _identityText(edge?.target) || "(unknown target)";
    const label = unresolved ? "(identity unavailable)" : _identityText(rawUser);
    const key = unresolved
      ? `unknown:${_identityKey(source)}->${_identityKey(target)}`
      : _identityKey(label);
    const id = `${LATERAL_IDENTITY_NODE_PREFIX}${key}`;
    if (!identityNodes.has(id)) {
      identityNodes.set(id, {
        id,
        label,
        identity: label,
        nodeType: "identity",
        unresolved,
        eventCount: 0,
        riskScore: 0,
        sourceHosts: new Set(),
        targetHosts: new Set(),
        techniques: new Set(),
        relatedHostEdges: [],
        evidenceRefs: [],
        attributionApproximate: false,
        firstSeen: "",
        lastSeen: "",
      });
    }
    return identityNodes.get(id);
  };

  const addLink = (source, target, identityNode, edge, phase, activity) => {
    const key = `${source}->${target}`;
    if (!links.has(key)) {
      links.set(key, {
        source,
        target,
        graphKind: "identity-link",
        phase,
        identityId: identityNode.id,
        identity: identityNode.identity,
        count: 0,
        riskScore: 0,
        users: new Set(),
        techniques: new Set(),
        logonTypes: new Set(),
        flags: new Set(),
        eventBreakdown: {},
        relatedHostEdges: [],
        evidenceRefs: [],
        attributionApproximate: false,
        firstSeen: "",
        lastSeen: "",
      });
    }
    const link = links.get(key);
    link.count += activity.count;
    link.attributionApproximate = link.attributionApproximate || activity.approximate;
    link.riskScore = Math.max(link.riskScore, Number(edge?.riskScore) || 0);
    link.users.add(identityNode.identity);
    if (edge?.technique) link.techniques.add(edge.technique);
    for (const technique of edge?.otherTechniques || []) if (technique) link.techniques.add(technique);
    for (const logonType of edge?.logonTypes || []) if (logonType != null) link.logonTypes.add(String(logonType));
    for (const flag of edge?.flags || []) if (flag) link.flags.add(flag);
    _mergeBreakdown(link.eventBreakdown, edge?.eventBreakdown);
    link.relatedHostEdges.push(edge);
    link.evidenceRefs = _dedupeRefs([...link.evidenceRefs, ...(edge?.evidenceRefs || [])]);
    if (edge?.firstSeen && (!link.firstSeen || edge.firstSeen < link.firstSeen)) link.firstSeen = edge.firstSeen;
    if (edge?.lastSeen && (!link.lastSeen || edge.lastSeen > link.lastSeen)) link.lastSeen = edge.lastSeen;
  };

  for (const edge of hostEdges || []) {
    const source = _identityText(edge?.source);
    const target = _identityText(edge?.target);
    if (!source || !target || source === target || !nodesById.has(source) || !nodesById.has(target)) continue;
    const knownUsers = _dedupeText(edge?.users || []).filter(_knownIdentity);
    const identities = knownUsers.length > 0
      ? knownUsers.map((user) => getIdentity(edge, user, false))
      : [getIdentity(edge, "", true)];
    if (knownUsers.length === 0) unattributedEdges.push(edge);

    for (const identityNode of identities) {
      const activity = _userActivityCount(edge, identityNode.identity);
      identityNode.eventCount += activity.count;
      identityNode.attributionApproximate = identityNode.attributionApproximate || activity.approximate;
      identityNode.riskScore = Math.max(identityNode.riskScore, Number(edge?.riskScore) || 0);
      identityNode.sourceHosts.add(source);
      identityNode.targetHosts.add(target);
      if (edge?.technique) identityNode.techniques.add(edge.technique);
      for (const technique of edge?.otherTechniques || []) if (technique) identityNode.techniques.add(technique);
      identityNode.relatedHostEdges.push(edge);
      identityNode.evidenceRefs = _dedupeRefs([...identityNode.evidenceRefs, ...(edge?.evidenceRefs || [])]);
      if (edge?.firstSeen && (!identityNode.firstSeen || edge.firstSeen < identityNode.firstSeen)) identityNode.firstSeen = edge.firstSeen;
      if (edge?.lastSeen && (!identityNode.lastSeen || edge.lastSeen > identityNode.lastSeen)) identityNode.lastSeen = edge.lastSeen;

      addLink(source, identityNode.id, identityNode, edge, "source-to-identity", activity);
      addLink(identityNode.id, target, identityNode, edge, "identity-to-target", activity);
    }
  }

  const finalizedIdentities = [...identityNodes.values()].map((node) => ({
    ...node,
    sourceHosts: [...node.sourceHosts].sort(),
    targetHosts: [...node.targetHosts].sort(),
    techniques: [...node.techniques].sort(),
    relatedHostEdges: [...new Set(node.relatedHostEdges)],
    aliases: node.unresolved ? [] : [node.identity],
    itemRowids: node.evidenceRefs.map((ref) => ref.rowId),
  }));

  const finalizedLinks = [...links.values()].map((link) => {
    const techniques = [...link.techniques];
    const relatedHostEdges = [...new Set(link.relatedHostEdges)];
    return {
      ...link,
      users: [...link.users],
      techniques,
      technique: techniques[0] || "Identity attribution",
      logonTypes: [...link.logonTypes],
      flags: [...link.flags],
      relatedHostEdges,
      hostSource: relatedHostEdges.length === 1 ? relatedHostEdges[0].source : "",
      hostTarget: relatedHostEdges.length === 1 ? relatedHostEdges[0].target : "",
      itemRowids: link.evidenceRefs.map((ref) => ref.rowId),
    };
  });

  return {
    nodes: [...nodesById.values(), ...finalizedIdentities],
    edges: finalizedLinks,
    identityNodes: finalizedIdentities,
    unattributedEdges,
  };
}

function _components(nodes, edges) {
  const ids = new Set(nodes.map(_id));
  const adj = new Map(nodes.map((n) => [_id(n), new Set()]));
  for (const edge of edges) {
    const s = String(edge?.source || "");
    const t = String(edge?.target || "");
    if (!ids.has(s) || !ids.has(t) || s === t) continue;
    adj.get(s).add(t);
    adj.get(t).add(s);
  }

  const visited = new Set();
  const out = [];
  for (const node of [...nodes].sort((a, b) => _id(a).localeCompare(_id(b)))) {
    const start = _id(node);
    if (visited.has(start)) continue;
    const members = [];
    const queue = [start];
    visited.add(start);
    while (queue.length) {
      const cur = queue.shift();
      members.push(cur);
      for (const next of [...(adj.get(cur) || [])].sort()) {
        if (visited.has(next)) continue;
        visited.add(next);
        queue.push(next);
      }
    }
    out.push(members);
  }
  return out.sort((a, b) => b.length - a.length || a[0].localeCompare(b[0]));
}

function _levelsForComponent(component, edges, byId) {
  const members = new Set(component);
  const outgoing = new Map(component.map((id) => [id, []]));
  const incoming = new Map(component.map((id) => [id, 0]));
  for (const edge of edges) {
    const s = String(edge?.source || "");
    const t = String(edge?.target || "");
    if (!members.has(s) || !members.has(t) || s === t) continue;
    outgoing.get(s).push(t);
    incoming.set(t, (incoming.get(t) || 0) + 1);
  }

  let roots = component.filter((id) => (incoming.get(id) || 0) === 0);
  if (roots.length === 0) {
    roots = [...component]
      .sort((a, b) =>
        (outgoing.get(b)?.length || 0) - (outgoing.get(a)?.length || 0)
        || _rank(byId.get(b)) - _rank(byId.get(a))
        || a.localeCompare(b))
      .slice(0, 1);
  }

  const level = new Map(roots.map((id) => [id, 0]));
  const queue = [...roots].sort();
  while (queue.length) {
    const cur = queue.shift();
    const nextLevel = (level.get(cur) || 0) + 1;
    for (const next of [...(outgoing.get(cur) || [])].sort()) {
      const prior = level.get(next);
      if (prior == null || nextLevel < prior) {
        level.set(next, nextLevel);
        queue.push(next);
      }
    }
  }

  // Cycle-only/unreachable members stay visible in the least misleading place:
  // one column after the deepest directed layer.
  const deepest = Math.max(0, ...level.values());
  for (const id of component) {
    if (!level.has(id)) level.set(id, deepest + 1);
  }
  return level;
}

/**
 * @returns {{positions: object, width: number, height: number, components: number}}
 */
export function layoutLateralMovementGraph(nodes = [], edges = [], options = {}) {
  const cfg = { ...LATERAL_GRAPH_DEFAULTS, ...options };
  if (!nodes.length) return { positions: {}, width: cfg.width, height: cfg.height, components: 0 };

  const selected = selectLateralGraphNodes(nodes, cfg.maxNodes);
  const byId = new Map(selected.map((n) => [_id(n), n]));
  const ids = new Set(byId.keys());
  const visibleEdges = selectLateralGraphEdges(
    edges.filter((e) => ids.has(String(e?.source || "")) && ids.has(String(e?.target || ""))),
    cfg.maxEdges,
  );
  const components = _components(selected, visibleEdges);

  const weights = components.map((component) => Math.max(1, component.length));
  const totalWeight = weights.reduce((sum, value) => sum + value, 0);
  const gapCount = Math.max(0, components.length - 1);
  const availableH = Math.max(1, cfg.height - cfg.padY * 2);
  const componentGap = gapCount > 0
    ? Math.min(cfg.componentGap, (availableH / gapCount) * 0.55)
    : 0;
  const usableH = Math.max(1, availableH - componentGap * gapCount);
  const positions = {};
  let top = cfg.padY;

  components.forEach((component, componentIndex) => {
    const bandH = components.length === 1
      ? usableH
      : usableH * (weights[componentIndex] / totalWeight);
    const levelMap = _levelsForComponent(component, visibleEdges, byId);
    const maxLevel = Math.max(0, ...levelMap.values());
    const byLevel = new Map();
    for (const id of component) {
      const level = levelMap.get(id) || 0;
      if (!byLevel.has(level)) byLevel.set(level, []);
      byLevel.get(level).push(id);
    }

    for (const [level, levelIds] of byLevel) {
      levelIds.sort((a, b) =>
        _rank(byId.get(b)) - _rank(byId.get(a))
        || a.localeCompare(b));
      const x = maxLevel === 0
        ? cfg.width / 2
        : cfg.padX + (level / maxLevel) * (cfg.width - cfg.padX * 2);
      const gap = bandH / (levelIds.length + 1);
      levelIds.forEach((id, index) => {
        positions[id] = {
          x,
          y: top + gap * (index + 1),
          level,
          component: componentIndex,
        };
      });
    }
    top += bandH + componentGap;
  });

  return { positions, width: cfg.width, height: cfg.height, components: components.length };
}
