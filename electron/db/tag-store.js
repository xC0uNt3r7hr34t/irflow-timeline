/**
 * Bookmark/tag methods mixed into TimelineDB.
 */
const { dbg } = require("../logger");

class TagStoreMethods {
  /**
   * Toggle bookmark on a row
   */
  _invalidateCountCache(tabId) {
    const meta = this.databases.get(tabId);
    if (meta) { meta._countCache = null; meta._histoCache = null; }
    // Also clear analysis preview caches — they depend on filtered/tagged data
    if (this._ptPreviewCache) {
      const prefix = JSON.stringify(tabId);
      for (const k of this._ptPreviewCache.keys()) { if (k.startsWith("[" + prefix + ",")) this._ptPreviewCache.delete(k); }
    }
    if (this._lmPreviewCache) {
      const prefix = JSON.stringify(tabId);
      for (const k of this._lmPreviewCache.keys()) { if (k.startsWith("[" + prefix + ",")) this._lmPreviewCache.delete(k); }
    }
  }

  toggleBookmark(tabId, rowId) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    const exists = meta.bmCheckStmt.get(rowId);
    if (exists) {
      meta.bmDeleteStmt.run(rowId);
      return false;
    } else {
      meta.bmInsertStmt.run(rowId);
      return true;
    }
  }

  /**
   * Bulk toggle bookmarks
   */
  setBookmarks(tabId, rowIds, add = true) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    const stmt = add ? meta.bmInsertStmt : meta.bmDeleteStmt;
    const tx = meta.db.transaction((ids) => {
      for (const id of ids) stmt.run(id);
    });
    tx(rowIds);
  }

  /**
   * Get bookmark count
   */
  getBookmarkCount(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return 0;
    return meta.bmCountStmt.get().cnt;
  }

  /**
   * Get all bookmarked row IDs
   */
  getBookmarkedIds(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db
      .prepare("SELECT rowid FROM bookmarks")
      .all()
      .map((r) => r.rowid);
  }

  // ── Tag operations ─────────────────────────────────────────────

  addTag(tabId, rowId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    const id = Number(rowId);
    if (!Number.isInteger(id) || id <= 0 || !tag) return;
    this._invalidateCountCache(tabId);
    meta.tagInsertStmt.run(id, tag);
  }

  removeTag(tabId, rowId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    const id = Number(rowId);
    if (!Number.isInteger(id) || id <= 0 || !tag) return;
    this._invalidateCountCache(tabId);
    meta.tagDeleteStmt.run(id, tag);
  }

  getTagsForRows(tabId, rowIds) {
    const meta = this.databases.get(tabId);
    if (!meta) return {};
    const result = {};
    for (let i = 0; i < rowIds.length; i += 500) {
      const batch = rowIds.slice(i, i + 500);
      const placeholders = batch.map(() => "?").join(",");
      const rows = meta.db.prepare(`SELECT rowid, tag FROM tags WHERE rowid IN (${placeholders})`).all(...batch);
      for (const r of rows) {
        if (!result[r.rowid]) result[r.rowid] = [];
        result[r.rowid].push(r.tag);
      }
    }
    return result;
  }

  getAllTags(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db.prepare("SELECT tag, COUNT(*) as cnt FROM tags GROUP BY tag ORDER BY cnt DESC").all();
  }

  getAllTagData(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db.prepare("SELECT rowid, tag FROM tags").all();
  }

  /**
   * Fetch raw rows by SQLite rowid, preserving the requested order.
   * Returns rows mapped back to original header names plus `__idx`.
   */
  getRowsByIds(tabId, rowIds) {
    const meta = this.databases.get(tabId);
    if (!meta || !Array.isArray(rowIds) || rowIds.length === 0) return [];
    const ids = [...new Set(rowIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0))];
    if (ids.length === 0) return [];

    const rowsById = new Map();
    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    for (let i = 0; i < ids.length; i += 500) {
      const batch = ids.slice(i, i + 500);
      const placeholders = batch.map(() => "?").join(",");
      const sql = `SELECT data.rowid as _rowid, ${colList} FROM data WHERE data.rowid IN (${placeholders})`;
      const rawRows = meta.db.prepare(sql).all(...batch);
      for (const raw of rawRows) {
        const row = { __idx: raw._rowid };
        for (let c = 0; c < meta.safeCols.length; c++) {
          row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
        }
        rowsById.set(raw._rowid, row);
      }
    }

    return ids.map((id) => rowsById.get(id)).filter(Boolean);
  }

  /**
   * Gather all data needed for HTML report generation.
   * Returns bookmarked rows, tagged rows grouped by tag, and summary stats.
   */
  getReportData(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;

    try {
      const d = meta.db;
      const colList = meta.safeCols.map((c) => c.safe).join(", ");
      const mapRow = (raw) => {
        const row = {};
        for (let c = 0; c < meta.safeCols.length; c++) {
          row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
        }
        return row;
      };

      // Cap the number of detail rows materialized into the report. A bulk bookmark/tag
      // operation (e.g. Sigma "tag all imported rows") can mark millions of rows; loading
      // every one's full column data into JS objects and then building one giant HTML
      // string can blow past the V8 heap and OOM-kill the process. Counts/summaries below
      // still reflect true totals — only the per-row detail tables are bounded.
      const MAX_REPORT_ROWS = 50000;

      // Bookmarked rows (full data, capped)
      const bookmarkedRows = d.prepare(
        `SELECT ${colList} FROM data WHERE rowid IN (SELECT rowid FROM bookmarks) ORDER BY rowid LIMIT ?`
      ).all(MAX_REPORT_ROWS).map(mapRow);

      // Tags: unique tags with counts
      const tagSummary = d.prepare(
        "SELECT tag, COUNT(*) as cnt FROM tags GROUP BY tag ORDER BY cnt DESC"
      ).all();

      // Tagged rows grouped by tag (single JOIN query instead of per-tag N+1, capped)
      const taggedGroups = {};
      let taggedTruncated = false;
      if (tagSummary.length > 0) {
        const allTaggedRows = d.prepare(
          `SELECT t.tag, ${colList} FROM data d INNER JOIN tags t ON d.rowid = t.rowid ORDER BY t.tag, d.rowid LIMIT ?`
        ).all(MAX_REPORT_ROWS + 1);
        if (allTaggedRows.length > MAX_REPORT_ROWS) {
          taggedTruncated = true;
          allTaggedRows.length = MAX_REPORT_ROWS;
        }
        for (const row of allTaggedRows) {
          const tag = row.tag;
          if (!taggedGroups[tag]) taggedGroups[tag] = [];
          const mapped = {};
          for (let c = 0; c < meta.safeCols.length; c++) {
            mapped[meta.safeCols[c].original] = row[meta.safeCols[c].safe] ?? "";
          }
          taggedGroups[tag].push(mapped);
        }
      }

      // Summary stats
      const totalRows = meta.rowCount;
      const bookmarkCount = d.prepare("SELECT COUNT(*) as cnt FROM bookmarks").get().cnt;
      const tagCount = d.prepare("SELECT COUNT(DISTINCT tag) as cnt FROM tags").get().cnt;
      const taggedRowCount = d.prepare("SELECT COUNT(DISTINCT rowid) as cnt FROM tags").get().cnt;

      // Timestamp range (from first ts column if available)
      let tsRange = null;
      if (meta.tsColumns && meta.tsColumns.size > 0) {
        const firstTsCol = [...meta.tsColumns][0];
        const safeCol = meta.colMap[firstTsCol];
        if (safeCol) {
          const range = d.prepare(
            `SELECT MIN(${safeCol}) as earliest, MAX(${safeCol}) as latest FROM data WHERE ${safeCol} IS NOT NULL AND ${safeCol} != ''`
          ).get();
          if (range?.earliest) tsRange = { column: firstTsCol, earliest: range.earliest, latest: range.latest };
        }
      }

      return {
        headers: meta.headers,
        totalRows,
        bookmarkCount,
        bookmarkedRows,
        tagSummary,
        taggedGroups,
        tagCount,
        taggedRowCount,
        tsRange,
        maxReportRows: MAX_REPORT_ROWS,
        bookmarkedTruncated: bookmarkCount > bookmarkedRows.length,
        taggedTruncated,
      };
    } catch (e) {
      dbg("DB", `getReportData error`, { tabId, error: e.message });
      return null;
    }
  }

  bulkAddTags(tabId, tagMap) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    const tx = meta.db.transaction(() => {
      for (const [rowId, tags] of Object.entries(tagMap)) {
        for (const tag of tags) meta.tagInsertStmt.run(Number(rowId), tag);
      }
    });
    tx();
    this._invalidateCountCache(tabId);
  }

  bulkAddTagToRows(tabId, rowIds, tag) {
    const meta = this.databases.get(tabId);
    if (!meta || !tag || !Array.isArray(rowIds) || rowIds.length === 0) return { tagged: 0 };
    const ids = [...new Set(rowIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0))];
    if (ids.length === 0) return { tagged: 0 };
    let tagged = 0;
    const tx = meta.db.transaction((batch) => {
      for (const rowId of batch) tagged += meta.tagInsertStmt.run(rowId, tag).changes || 0;
    });
    for (let i = 0; i < ids.length; i += 5000) tx(ids.slice(i, i + 5000));
    this._invalidateCountCache(tabId);
    return { tagged };
  }

  /**
   * Bulk-tag rows within specific time ranges directly in SQL.
   * ranges = [{ from, to, tag }] — e.g. [{ from: "2024-01-15 08:30", to: "2024-01-15 10:45", tag: "Session 1" }]
   * Never materializes rowIds in JS — pure SQL INSERT...SELECT.
   */
  bulkTagByTimeRange(tabId, colName, ranges) {
    const meta = this.databases.get(tabId);
    if (!meta || ranges.length === 0) return { taggedCount: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { taggedCount: 0 };
    this._invalidateCountCache(tabId);
    const db = meta.db;
    let taggedCount = 0;
    const tx = db.transaction(() => {
      for (const { from, to, tag } of ranges) {
        // Guard against null/undefined bounds — Heatmap suspicious-window
        // builders can produce null bucket fields when timestamps fail to parse.
        // Skipping silently is safer than throwing in the middle of a transaction.
        if (typeof from !== "string" || typeof to !== "string" || !tag) continue;
        const fromTs = from.length === 16 ? from + ":00" : from;
        const toTs = to.length === 16 ? to + ":59" : to;
        // Normalize the column with sort_datetime() so the range compares
        // chronologically regardless of stored format (US M/D/YYYY h:mm AM/PM, epoch,
        // ISO). The bounds are already ISO-lexical ("YYYY-MM-DD HH:MM:SS"), which is
        // exactly sort_datetime()'s output space. A raw text compare mis-tags or tags
        // nothing for non-ISO columns. Matches the sort/histogram/gap query paths.
        const result = db.prepare(`
          INSERT OR IGNORE INTO tags (rowid, tag)
          SELECT rowid, ? FROM data
          WHERE sort_datetime(${safeCol}) >= ? AND sort_datetime(${safeCol}) <= ?
            AND ${safeCol} IS NOT NULL AND ${safeCol} != ''
        `).run(tag, fromTs, toTs);
        taggedCount += result.changes;
      }
    });
    tx();
    return { taggedCount };
  }

  /**
   * Bulk tag all rows matching current filters.
   * Uses INSERT...SELECT — never materializes rowIds in JS.
   */
  bulkRemoveTagFiltered(tabId, tag, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta || !tag) return { removed: 0 };

    try {
      const db = meta.db;
      const params = [tag];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);

      if (whereConditions.length === 0) {
        const RECOGNIZED = new Set(["columnFilters", "checkboxFilters", "bookmarkedOnly", "tagFilter", "dateRangeFilters", "advancedFilters", "searchTerm", "searchMode", "searchCondition", "rowIdFilter", "excludedRowIds"]);
        const unknown = Object.keys(options || {}).filter((k) => !RECOGNIZED.has(k));
        if (unknown.length > 0) {
          return { removed: 0, error: `Refused to remove tag: unrecognized filter option(s) [${unknown.join(", ")}] matched no rows (would have removed the tag from the entire tab).` };
        }
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      const result = db.prepare(`
        DELETE FROM tags
        WHERE tag = ?
          AND rowid IN (SELECT data.rowid FROM data ${whereClause})
      `).run(...params);
      this._invalidateCountCache(tabId);
      return { removed: result.changes };
    } catch (e) {
      dbg("DB", `bulkRemoveTagFiltered error`, { tabId, error: e.message });
      return { removed: 0, error: e.message };
    }
  }

  bulkTagFiltered(tabId, tag, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta || !tag) return { tagged: 0 };

    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);

      // Guard against silently tagging EVERY row when a caller passes an UNRECOGNIZED filter shape
      // (e.g. a typo'd `{ filters: [...] }`) that _applyStandardFilters drops. An empty options
      // object ({}) remains a valid intentional tag-all (e.g. Sigma result tagging).
      if (whereConditions.length === 0) {
        const RECOGNIZED = new Set(["columnFilters", "checkboxFilters", "bookmarkedOnly", "tagFilter", "dateRangeFilters", "advancedFilters", "searchTerm", "searchMode", "searchCondition", "rowIdFilter", "excludedRowIds"]);
        const unknown = Object.keys(options || {}).filter((k) => !RECOGNIZED.has(k));
        if (unknown.length > 0) {
          return { tagged: 0, error: `Refused to tag: unrecognized filter option(s) [${unknown.join(", ")}] matched no rows (would have tagged the entire tab).` };
        }
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      const result = db.prepare(`INSERT OR IGNORE INTO tags (rowid, tag) SELECT data.rowid, ? FROM data ${whereClause}`).run(tag, ...params);
      this._invalidateCountCache(tabId);
      return { tagged: result.changes };
    } catch (e) {
      dbg("DB", `bulkTagFiltered error`, { tabId, error: e.message });
      return { tagged: 0, error: e.message };
    }
  }

  /**
   * Bulk bookmark (or un-bookmark) all rows matching current filters.
   * Uses INSERT...SELECT / DELETE...SELECT — never materializes rowIds in JS.
   */
  bulkBookmarkFiltered(tabId, add, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { affected: 0 };

    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      let result;
      if (add) {
        result = db.prepare(`INSERT OR IGNORE INTO bookmarks (rowid) SELECT data.rowid FROM data ${whereClause}`).run(...params);
      } else {
        result = db.prepare(`DELETE FROM bookmarks WHERE rowid IN (SELECT data.rowid FROM data ${whereClause})`).run(...params);
      }
      this._invalidateCountCache(tabId);
      return { affected: result.changes };
    } catch (e) {
      dbg("DB", `bulkBookmarkFiltered error`, { tabId, error: e.message });
      return { affected: 0, error: e.message };
    }
  }

}

module.exports = TagStoreMethods.prototype;
