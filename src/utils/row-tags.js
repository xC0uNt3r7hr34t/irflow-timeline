/** Normalize SQLite row ids so map lookups stay consistent (number keys). */
export function normalizeRowId(rowId) {
  const n = Number(rowId);
  return Number.isFinite(n) ? n : rowId;
}

/** Build `{ [rowId]: string[] }` from getAllTagData() rows. */
export function buildRowTagsMap(tagData = []) {
  const rowTags = {};
  for (const entry of tagData) {
    const rowid = normalizeRowId(entry?.rowid);
    const tag = entry?.tag;
    if (!tag) continue;
    if (!rowTags[rowid]) rowTags[rowid] = [];
    rowTags[rowid].push(tag);
  }
  return rowTags;
}

export function tagsForRow(rowTags, rowId) {
  return rowTags?.[normalizeRowId(rowId)] || [];
}

/** Merge tag data for a fetched row window without dropping tags outside the window. */
export function mergeRowTagsForWindow(prevRowTags, fetchedRows = [], fetchedRowTags = {}) {
  const merged = { ...(prevRowTags || {}) };
  for (const row of fetchedRows) {
    const id = normalizeRowId(row?.__idx);
    if (!Number.isFinite(id)) continue;
    const next = fetchedRowTags[id] || fetchedRowTags[row.__idx];
    if (Array.isArray(next) && next.length > 0) merged[id] = next;
    else delete merged[id];
  }
  return merged;
}
