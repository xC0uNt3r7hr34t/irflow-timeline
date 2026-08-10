/**
 * evidence.js — evidence-reference helpers for the lateral-movement analyzer.
 *
 * Factory returning the evidence-ref helper cluster, extracted verbatim from
 * getLateralMovement(). Findings/edges carry evidenceRefs ({tabId,rowId}) that
 * link them back to source rows for drill-down. These closures capture only
 * `meta` (for meta.tabId) and each other, so they extract cleanly as a factory.
 *
 * @param {object} meta - tab metadata ({ tabId, ... })
 * @returns the evidence-ref helper cluster (underscore-named to match call sites)
 */
function createEvidenceHelpers(meta) {
  const _makeEvidenceRef = ({ tabId, rowId, sourceTab, sourceFormat } = {}) => {
    const numericRowId = Number(rowId);
    if (!tabId || !Number.isFinite(numericRowId) || numericRowId <= 0) return null;
    const ref = { tabId, rowId: numericRowId };
    if (sourceTab) ref.sourceTab = sourceTab;
    if (sourceFormat) ref.sourceFormat = sourceFormat;
    return ref;
  };
  const _dedupeEvidenceRefs = (refs = []) => {
    const seen = new Set();
    const out = [];
    for (const ref of refs || []) {
      const clean = _makeEvidenceRef(ref || {});
      if (!clean) continue;
      const key = `${clean.tabId}:${clean.rowId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(clean);
    }
    return out;
  };
  const _rowEvidenceRef = (row) => {
    if (row?._sourceRef) return _makeEvidenceRef(row._sourceRef);
    const rowId = row?._sourceRowId ?? row?._rid ?? row?._rowid ?? row?.rowId;
    return _makeEvidenceRef({
      tabId: row?._sourceTabId || row?.tabId || meta.tabId,
      rowId,
      sourceTab: row?._sourceTab,
      sourceFormat: row?._sourceFormat,
    });
  };
  const _refsFromEvents = (events = []) => _dedupeEvidenceRefs(events.flatMap((evt) => evt?.evidenceRefs || []));
  const _refsFromHits = (hits = []) => _dedupeEvidenceRefs(hits.flatMap((hit) => {
    const refs = [];
    if (Array.isArray(hit?.evidenceRefs)) refs.push(...hit.evidenceRefs);
    if (hit?.evidenceRef) refs.push(hit.evidenceRef);
    if (hit?.rid != null && meta.tabId !== "__multi_source__") refs.push({ tabId: meta.tabId, rowId: hit.rid });
    return refs;
  }));
  const _rowidsFromRefs = (refs = []) => _dedupeEvidenceRefs(refs).map((ref) => ref.rowId);
  const _attachEvidenceRefs = (target, refs = []) => {
    const evidenceRefs = _dedupeEvidenceRefs([...(target?.evidenceRefs || []), ...refs]);
    if (evidenceRefs.length > 0) {
      target.evidenceRefs = evidenceRefs;
      target.itemRowids = _rowidsFromRefs(evidenceRefs);
    }
    return target;
  };
  return { _makeEvidenceRef, _dedupeEvidenceRefs, _rowEvidenceRef, _refsFromEvents, _refsFromHits, _rowidsFromRefs, _attachEvidenceRefs };
}

module.exports = { createEvidenceHelpers };
