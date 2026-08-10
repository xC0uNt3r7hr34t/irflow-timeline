module.exports = function registerTagHandlers(safeHandle, safeSend, { db }) {
  safeHandle('toggle-bookmark', (_e, { tabId, rowId }) => {
    return db.toggleBookmark(tabId, rowId);
  });

  safeHandle('set-bookmarks', (_e, { tabId, rowIds, add }) => {
    db.setBookmarks(tabId, rowIds, add);
    return true;
  });

  safeHandle('get-bookmark-count', (_e, { tabId }) => {
    return db.getBookmarkCount(tabId);
  });

  safeHandle('add-tag', (_e, { tabId, rowId, tag }) => {
    db.addTag(tabId, rowId, tag);
    return true;
  });

  safeHandle('remove-tag', (_e, { tabId, rowId, tag }) => {
    db.removeTag(tabId, rowId, tag);
    return true;
  });

  safeHandle('get-all-tags', (_e, { tabId }) => {
    return db.getAllTags(tabId);
  });

  safeHandle('get-all-tag-data', (_e, { tabId }) => {
    return db.getAllTagData(tabId);
  });

  safeHandle('bulk-add-tags', (_e, { tabId, tagMap }) => {
    db.bulkAddTags(tabId, tagMap);
    return true;
  });

  safeHandle('bulk-tag-by-time-range', (_e, { tabId, colName, ranges }) => {
    return db.bulkTagByTimeRange(tabId, colName, ranges);
  });

  safeHandle('bulk-tag-filtered', (_e, { tabId, tag, options }) => {
    return db.bulkTagFiltered(tabId, tag, options);
  });

  safeHandle('bulk-bookmark-filtered', (_e, { tabId, add, options }) => {
    return db.bulkBookmarkFiltered(tabId, add, options);
  });
};
