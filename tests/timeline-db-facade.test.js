const test = require("node:test");
const assert = require("node:assert/strict");

const TimelineDB = require("../electron/db");
const queryStore = require("../electron/db/query-store");
const tagStore = require("../electron/db/tag-store");
const timelineAnalytics = require("../electron/db/timeline-analytics");
const { previewMultiSourceLateralMovement } = require("../electron/analyzers/lateral-movement/multi-source");

const EVTXECMD_LM_HEADERS = [
  "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
  "Provider", "Channel", "Computer", "UserName", "RemoteHost",
  "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6",
];

function makeEvtxEcmdPreviewMeta(rowCount = 3) {
  const colMap = {};
  EVTXECMD_LM_HEADERS.forEach((h, i) => { colMap[h] = `c${i}`; });
  const db = {
    prepare(sql) {
      return {
        all() {
          if (/GROUP BY/i.test(sql)) return [{ eid: "4624", cnt: rowCount }];
          return [];
        },
        get() {
          if (/COUNT\(\*\)\s+as\s+cnt/i.test(sql)) return { cnt: rowCount };
          const out = { total: rowCount, src_ip: 0, src_nonnull: rowCount };
          for (const [, key] of sql.matchAll(/\bas\s+null_([a-zA-Z0-9_]+)/g)) out[`null_${key}`] = 0;
          return out;
        },
      };
    },
  };
  return { tabId: "evtxecmd-preview", headers: EVTXECMD_LM_HEADERS, colMap, db };
}

test("TimelineDB facade exposes methods from extracted DB modules", () => {
  for (const name of ["queryRows", "getRowIdsInRange", "countRowsByIdsMatching", "findSearchMatch", "_applyStandardFilters", "_applyRowIdFilter", "_applyExcludedRowIds", "_buildOrderExpression", "exportQuery", "getColumnStats", "searchCount"]) {
    assert.equal(TimelineDB.prototype[name], queryStore[name], `${name} should be mixed in from query-store`);
  }

  for (const name of ["toggleBookmark", "setBookmarks", "addTag", "bulkAddTagToRows", "bulkTagFiltered", "bulkBookmarkFiltered"]) {
    assert.equal(TimelineDB.prototype[name], tagStore[name], `${name} should be mixed in from tag-store`);
  }

  for (const name of ["getHistogramData", "getGapAnalysis", "getLogSourceCoverage", "getBurstAnalysis", "getStackingData"]) {
    assert.equal(TimelineDB.prototype[name], timelineAnalytics[name], `${name} should be mixed in from timeline-analytics`);
  }
});

test("standard filters support exact row-id filters without SQL parameters", () => {
  const whereConditions = [];
  const params = [];

  queryStore._applyStandardFilters.call(queryStore, {
    rowIdFilter: [42, "43", 42, 0, -1, "bad", 12.5],
  }, { colMap: {} }, whereConditions, params);

  assert.deepEqual(whereConditions, ["data.rowid IN (42,43)"]);
  assert.deepEqual(params, []);
});

test("standard filters can represent an intentionally empty exact row-id filter", () => {
  const whereConditions = [];
  const params = [];

  queryStore._applyStandardFilters.call(queryStore, {
    rowIdFilter: ["bad", 0, -1],
  }, { colMap: {} }, whereConditions, params);

  assert.deepEqual(whereConditions, ["0"]);
  assert.deepEqual(params, []);
});

test("Lateral Movement preview prefers EvtxECmd PayloadData1 over subject UserName", () => {
  const instance = Object.create(TimelineDB.prototype);
  instance.databases = new Map([["tab-evtxecmd", makeEvtxEcmdPreviewMeta()]]);
  instance._lmPreviewCache = new Map();
  instance._isHayabusaDataset = () => false;
  instance._isChainsawLogonDataset = () => false;
  instance._applyStandardFilters = () => {};
  instance._ensureIndex = () => {};

  const result = TimelineDB.prototype.previewLateralMovement.call(instance, "tab-evtxecmd", {});

  assert.equal(result.error, undefined);
  assert.equal(result.isEvtxECmd, true);
  assert.equal(result.resolvedColumns.user, "PayloadData1");
  assert.equal(result.columnQuality.user.mapped, true);
});

test("Multi-source Lateral Movement preview uses EvtxECmd target user column", () => {
  const meta = makeEvtxEcmdPreviewMeta(7);
  const result = previewMultiSourceLateralMovement(
    [{ meta, tabId: "tab-evtxecmd", label: "EvtxECmd Logons" }],
    {},
    {
      isHayabusaDataset: () => false,
      isChainsawLogonDataset: () => false,
      applyStandardFilters: () => {},
    },
  );

  assert.equal(result.error, null);
  assert.equal(result.tabs[0].format, "EvtxECmd");
  assert.equal(result.tabs[0].columns.user, "PayloadData1");
  assert.equal(result.tabs[0].eventCount, 7);
});

test("extracted tag methods still work through the TimelineDB facade with tab metadata", () => {
  const calls = [];
  const instance = Object.create(TimelineDB.prototype);
  instance.databases = new Map();
  instance._isBuilding = () => false;
  instance.databases.set("tab-1", {
    _countCache: { sig: "old", cnt: 10 },
    _histoCache: { sig: "old", data: [] },
    bmCheckStmt: { get: () => null },
    bmInsertStmt: { run: (rowId) => calls.push(["insertBookmark", rowId]) },
    bmDeleteStmt: { run: (rowId) => calls.push(["deleteBookmark", rowId]) },
    tagInsertStmt: { run: (rowId, tag) => { calls.push(["insertTag", rowId, tag]); return { changes: 1 }; } },
    tagDeleteStmt: { run: (rowId, tag) => calls.push(["deleteTag", rowId, tag]) },
    db: { transaction: (fn) => (...args) => fn(...args) },
  });

  assert.equal(instance.toggleBookmark("tab-1", 42), true);
  instance.addTag("tab-1", 42, "Important");
  instance.removeTag("tab-1", 42, "Important");
  assert.deepEqual(instance.bulkAddTagToRows("tab-1", [42, "43", 42, -1, "bad"], "Sigma"), { tagged: 2 });

  const meta = instance.databases.get("tab-1");
  assert.equal(meta._countCache, null);
  assert.equal(meta._histoCache, null);
  assert.deepEqual(calls, [
    ["insertBookmark", 42],
    ["insertTag", 42, "Important"],
    ["deleteTag", 42, "Important"],
    ["insertTag", 42, "Sigma"],
    ["insertTag", 43, "Sigma"],
  ]);
});

test("TimelineDB can adopt a worker-created tab database", (t) => {
  const workerDb = new TimelineDB();
  const tabId = "worker-tab";
  try {
    workerDb.createTab(tabId, ["TimeCreated", "EventID"]);
  } catch (err) {
    workerDb.closeAll();
    if (err?.code === "ERR_DLOPEN_FAILED") {
      t.skip("better-sqlite3 native module is not built for this Node runtime");
      return;
    }
    throw err;
  }
  workerDb.insertBatchArrays(tabId, [
    ["2026-01-02T03:04:05Z", "4624"],
    ["2026-01-02T03:05:05Z", "4625"],
  ]);
  const finalized = workerDb.finalizeImport(tabId);
  const descriptor = workerDb.getTabWorkerDescriptor(tabId);
  workerDb.releaseTab(tabId);
  workerDb.closeAll();

  const mainDb = new TimelineDB();
  try {
    mainDb.adoptTabFromFile(tabId, { ...descriptor, ...finalized });
    const rows = mainDb.queryRows(tabId, {
      offset: 0,
      limit: 10,
      sortCol: "TimeCreated",
      sortDir: "asc",
    });

    assert.equal(rows.totalFiltered, 2);
    assert.equal(rows.rows[0].EventID, "4624");
    assert.deepEqual(mainDb.getFtsStatus(tabId), { ready: false, building: false });
  } finally {
    mainDb.closeAll();
  }
});
