const REF_ARRAY_FIELDS = [
  "evidenceRefs",
  "sourceRows",
];

const REF_OBJECT_FIELDS = [
  "evidenceRef",
  "_sourceRef",
];

const ROW_ID_ARRAY_FIELDS = [
  "itemRowids",
  "rowIds",
  "rowids",
  "rids",
];

const NESTED_ITEM_FIELDS = [
  "events",
  "hops",
  "sessions",
  "episodes",
  "preAuthEvents",
];

const asPositiveRowId = (value) => {
  const rowId = Number(value);
  return Number.isInteger(rowId) && rowId > 0 ? rowId : null;
};

const asList = (value) => Array.isArray(value) ? value : [];

const indexById = (items = []) => {
  const out = new Map();
  for (const item of asList(items)) {
    if (item?.id) out.set(String(item.id), item);
  }
  return out;
};

/**
 * Collect exact source-row references from analyzer result objects.
 *
 * Lateral Movement output can carry evidence directly (`evidenceRefs`) or via
 * related findings/incidents. This keeps the UI action layer independent from
 * the specific result type: edge, RDP session, finding, incident, campaign, etc.
 */
export function collectEvidenceRefs(item, options = {}) {
  const fallbackTabId = options.fallbackTabId;
  const findingsById = options.findingsById || indexById(options.relatedFindings);
  const incidentsById = options.incidentsById || indexById(options.relatedIncidents);
  const refs = [];
  const seenRefs = new Set();
  const seenItems = new Set();

  const pushRef = (ref, fallback = fallbackTabId) => {
    if (!ref) return;
    const tabId = ref.tabId ?? ref.sourceTabId ?? ref.SourceTabId ?? ref._sourceTabId ?? fallback;
    const rowId = asPositiveRowId(ref.rowId ?? ref.sourceRowId ?? ref.SourceRowId ?? ref._sourceRowId ?? ref.__idx ?? ref.rid ?? ref.id);
    if (!tabId || !rowId) return;
    const key = `${String(tabId)}:${rowId}`;
    if (seenRefs.has(key)) return;
    seenRefs.add(key);
    refs.push({ tabId, rowId });
  };

  const visit = (current) => {
    if (!current || typeof current !== "object") return;
    if (seenItems.has(current)) return;
    seenItems.add(current);

    for (const field of REF_ARRAY_FIELDS) {
      for (const ref of asList(current[field])) pushRef(ref);
    }
    for (const field of REF_OBJECT_FIELDS) {
      pushRef(current[field]);
    }
    for (const field of ROW_ID_ARRAY_FIELDS) {
      for (const rowId of asList(current[field])) pushRef({ rowId }, fallbackTabId);
    }

    for (const field of NESTED_ITEM_FIELDS) {
      for (const nested of asList(current[field])) visit(nested);
    }

    for (const findingId of asList(current.findingIds)) {
      const finding = findingsById.get(String(findingId));
      if (finding) visit(finding);
    }
    for (const findingId of asList(current.findings).filter((v) => typeof v === "string")) {
      const finding = findingsById.get(String(findingId));
      if (finding) visit(finding);
    }
    for (const incidentId of asList(current.incidentIds)) {
      const incident = incidentsById.get(String(incidentId));
      if (incident) visit(incident);
    }
    for (const incidentId of asList(current.incidents).filter((v) => typeof v === "string")) {
      const incident = incidentsById.get(String(incidentId));
      if (incident) visit(incident);
    }
  };

  visit(item);
  return refs;
}

export function groupEvidenceRefs(refs = [], fallbackTabId = null) {
  const grouped = new Map();
  for (const ref of asList(refs)) {
    const tabId = ref?.tabId ?? fallbackTabId;
    const rowId = asPositiveRowId(ref?.rowId);
    if (!tabId || !rowId) continue;
    const key = String(tabId);
    if (!grouped.has(key)) grouped.set(key, { tabId, rowIds: [] });
    if (!grouped.get(key).rowIds.includes(rowId)) grouped.get(key).rowIds.push(rowId);
  }
  return grouped;
}
