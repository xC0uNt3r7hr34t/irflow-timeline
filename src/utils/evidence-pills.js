/**
 * Evidence pills — shared helpers.
 *
 * Pills are typed evidence labels (`{text, type}`) emitted by analysis
 * backends (currently Persistence and Lateral Movement). They live in two
 * places in the UI:
 *
 *   1. Inside the analysis modal that produced them — already wired.
 *   2. Inline on each affected row in the main timeline grid — added by this
 *      module via the `evidencePillsByRowid` map on the active tab.
 *
 * The grid renderer reads `ct.evidencePillsByRowid?.[row.__idx]` and shows a
 * <Badge> per pill in a sticky `__evidence__` column.
 */

/** Map a pill `type` to a Badge tone. */
export function pillToneFor(type) {
  switch (type) {
    case "execution":
      return "danger";
    case "credential":
      return "warning";
    case "correlation":
      return "info";
    case "target":
      return "success";
    case "context":
    default:
      return "neutral";
  }
}

/**
 * Distribute incident-level pills onto the source rows that produced them.
 *
 * Persistence incidents carry `itemRowids: number[]` and `evidencePills: {text,type}[]`.
 * Each rowid in the list inherits a copy of the pills, deduped by `text`.
 *
 * Returns `{ [rowid]: pill[] }`. Returns an empty object if no incidents have
 * pills, so callers can simply check `Object.keys(...).length > 0` for presence.
 */
export function buildPillsByRowid(incidents) {
  const map = {};
  if (!Array.isArray(incidents)) return map;
  for (const inc of incidents) {
    const pills = inc?.evidencePills;
    const rowids = inc?.itemRowids;
    if (!Array.isArray(pills) || pills.length === 0) continue;
    if (!Array.isArray(rowids) || rowids.length === 0) continue;
    for (const rid of rowids) {
      if (rid == null) continue;
      const existing = map[rid];
      if (!existing) {
        map[rid] = pills.slice();
        continue;
      }
      // Merge new pills, deduped by `text`
      const seen = new Set(existing.map((p) => p.text));
      for (const p of pills) {
        if (!seen.has(p.text)) {
          existing.push(p);
          seen.add(p.text);
        }
      }
    }
  }
  return map;
}
