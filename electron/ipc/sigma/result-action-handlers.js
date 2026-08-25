const { dialog } = require("electron");

module.exports = function registerSigmaResultActionHandlers(ctx) {
  const {
    safeHandle,
    db,
    SigmaResultStore,
    _activeWindow,
    _resolveJob,
    _importJobAsTab,
    _importResultStoreAsTab,
    _getJobHtmlReport,
    _getSourceRowsForRule,
    _importSourceRowsAsTab,
  } = ctx;

  safeHandle("sigma-open-dir-results-as-tab", async (event, { name, jobId }) => {
    const job = _resolveJob(jobId);
    if (job?.resultDbPath) return _importResultStoreAsTab(job, name);
    if (!job?.rows || job.rows.length === 0) return { error: "No scan results to open" };
    const result = await _importJobAsTab(job.rows, name);
    if (!result.error) job.rows = null;
    return result;
  });

  safeHandle("sigma-export-html-report", async (event, { jobId } = {}) => {
    const job = _resolveJob(jobId);
    const htmlReport = _getJobHtmlReport(job);
    if (!htmlReport) return { error: "No HTML report available" };
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showSaveDialog(win, {
      defaultPath: `hayabusa-report-${new Date().toISOString().slice(0, 10)}.html`,
      filters: [{ name: "HTML Files", extensions: ["html"] }],
    });
    if (result.canceled || !result.filePath) return { canceled: true };
    const fsp = require("fs/promises");
    await fsp.writeFile(result.filePath, htmlReport, "utf8");
    return { saved: true, path: result.filePath };
  });

  safeHandle("sigma-get-html-report", (event, { jobId } = {}) => {
    const job = _resolveJob(jobId);
    return _getJobHtmlReport(job);
  });

  safeHandle("sigma-export-dir-csv", async (event, { jobId } = {}) => {
    const job = _resolveJob(jobId);
    if (job?.resultDbPath) {
      const win = typeof _activeWindow === "function" ? _activeWindow() : null;
      const result = await dialog.showSaveDialog(win, {
        defaultPath: `sigma-timeline-${new Date().toISOString().slice(0, 10)}.csv`,
        filters: [{ name: "CSV Files", extensions: ["csv"] }],
      });
      if (result.canceled || !result.filePath) return { canceled: true };
      const store = SigmaResultStore.open(job.resultDbPath);
      try {
        const exported = await store.exportCsv(result.filePath);
        return { saved: true, path: result.filePath, rowCount: exported.rowCount };
      } finally {
        store.close();
      }
    }
    if (!job?.rows || job.rows.length === 0) return { error: "No scan results" };
    const rows = job.rows;
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showSaveDialog(win, {
      defaultPath: `sigma-timeline-${new Date().toISOString().slice(0, 10)}.csv`,
      filters: [{ name: "CSV Files", extensions: ["csv"] }],
    });
    if (result.canceled || !result.filePath) return { canceled: true };

    const allKeys = new Set();
    const sampleSize = Math.min(rows.length, 1000);
    for (let i = 0; i < sampleSize; i++) {
      for (const k of Object.keys(rows[i])) {
        if (!k.startsWith("_") || k === "_SourceFile") allKeys.add(k);
      }
    }
    const PRIORITY = ["Timestamp", "Computer", "Channel", "EventID", "Level", "RuleTitle", "User", "MITRE",
      "Image", "CommandLine", "Cmdline", "Proc", "ParentImage", "Details", "ExtraFieldInfo",
      "_SourceFile", "RecordID", "RuleFile", "Tags"];
    const headers = [...PRIORITY.filter((k) => allKeys.has(k)), ...[...allKeys].filter((k) => !PRIORITY.includes(k)).sort()];
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;

    const ws = require("fs").createWriteStream(result.filePath);
    ws.write(headers.join(",") + "\n");
    for (const row of rows) {
      ws.write(headers.map((h) => esc(row[h])).join(",") + "\n");
    }
    await new Promise((resolve) => ws.end(resolve));
    return { saved: true, path: result.filePath, rowCount: rows.length };
  });

  safeHandle("sigma-export-dir-json", async (event, { matchesOnly, jobId } = {}) => {
    const job = _resolveJob(jobId);
    if (job?.resultDbPath && !matchesOnly) {
      const win = typeof _activeWindow === "function" ? _activeWindow() : null;
      const result = await dialog.showSaveDialog(win, {
        defaultPath: `sigma-results-${new Date().toISOString().slice(0, 10)}.json`,
        filters: [{ name: "JSON Files", extensions: ["json"] }],
      });
      if (result.canceled || !result.filePath) return { canceled: true };
      const store = SigmaResultStore.open(job.resultDbPath);
      try {
        const exported = await store.exportJson(result.filePath);
        return { saved: true, path: result.filePath, rowCount: exported.rowCount };
      } finally {
        store.close();
      }
    }
    if (!job?.rows || job.rows.length === 0) return { error: "No scan results" };
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showSaveDialog(win, {
      defaultPath: `sigma-results-${new Date().toISOString().slice(0, 10)}.json`,
      filters: [{ name: "JSON Files", extensions: ["json"] }],
    });
    if (result.canceled || !result.filePath) return { canceled: true };

    const fsp = require("fs/promises");
    const data = matchesOnly ? { eventRows: [] } : { eventRows: job.rows };
    await fsp.writeFile(result.filePath, JSON.stringify(data, null, 2), "utf8");
    return { saved: true, path: result.filePath, rowCount: job.rows.length };
  });

  safeHandle("sigma-get-source-rows", (event, { jobId, ruleId, title } = {}) => {
    return _getSourceRowsForRule(jobId, { ruleId, title });
  });

  safeHandle("sigma-open-source-rows-as-tab", async (event, { jobId, ruleId, title, name, postAction } = {}) => {
    return _importSourceRowsAsTab(jobId, { ruleId, title }, name, postAction);
  });

  safeHandle("sigma-tag-matches", (event, { jobId, ruleId, title, tag } = {}) => {
    if (!tag) return { tagged: 0 };
    const sourceRows = _getSourceRowsForRule(jobId, { ruleId, title });
    const byTab = new Map();
    for (const r of sourceRows) {
      if (!r.tabId || !r.rowId) continue;
      if (!byTab.has(r.tabId)) byTab.set(r.tabId, []);
      byTab.get(r.tabId).push(r.rowId);
    }
    let tagged = 0;
    for (const [sourceTabId, rowIds] of byTab) {
      const res = db.bulkAddTagToRows
        ? db.bulkAddTagToRows(sourceTabId, rowIds, tag)
        : null;
      tagged += res?.tagged || 0;
    }
    return { tagged, sourceRows: sourceRows.length, tabs: [...byTab.keys()] };
  });

  safeHandle("sigma-bookmark-matches", (event, { jobId, ruleId, title, add = true } = {}) => {
    const sourceRows = _getSourceRowsForRule(jobId, { ruleId, title });
    const byTab = new Map();
    for (const r of sourceRows) {
      if (!r.tabId || !r.rowId) continue;
      if (!byTab.has(r.tabId)) byTab.set(r.tabId, []);
      byTab.get(r.tabId).push(r.rowId);
    }
    let affected = 0;
    for (const [sourceTabId, rowIds] of byTab) {
      db.setBookmarks(sourceTabId, rowIds, add);
      affected += rowIds.length;
    }
    return { affected, sourceRows: sourceRows.length, tabs: [...byTab.keys()] };
  });
};
