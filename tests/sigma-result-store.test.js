const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { SigmaResultStore, orderedHeaders } = require("../electron/analyzers/sigma/result-store");

test("SigmaResultStore persists preview rows, headers, and source row lookups", (t) => {
  const dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "tle-sigma-store-test-")), "results.sqlite");
  t.after(() => SigmaResultStore.destroy(dbPath));

  let store;
  try {
    store = new SigmaResultStore({ dbPath });
  } catch (err) {
    if (err?.code === "ERR_DLOPEN_FAILED") {
      t.skip("better-sqlite3 native module is not built for this Node runtime");
      return;
    }
    throw err;
  }
  store.addRows([
    {
      Timestamp: "2026-01-01T00:00:02Z",
      Computer: "HOST2",
      RuleID: "rule-1",
      RuleTitle: "Suspicious Process",
      SourceTabId: "tab-a",
      SourceRowId: 20,
      CommandLine: "powershell.exe -nop",
    },
    {
      Timestamp: "2026-01-01T00:00:01Z",
      Computer: "HOST1",
      RuleID: "rule-1",
      RuleTitle: "Suspicious Process",
      SourceTabId: "tab-a",
      SourceRowId: 10,
      Image: "powershell.exe",
    },
    {
      Timestamp: "2026-01-01T00:00:03Z",
      Computer: "HOST3",
      RuleID: "rule-2",
      RuleTitle: "Other Rule",
      SourceTabId: "tab-b",
      SourceRowId: 5,
    },
  ]);
  const summary = store.finalize({ engine: "test" });
  assert.equal(summary.rowCount, 3);
  assert.ok(summary.headers.includes("RuleID"));
  assert.ok(summary.headers.includes("CommandLine"));
  store.close();

  const reopened = SigmaResultStore.open(dbPath);
  try {
    assert.equal(reopened.rowCount, 3);
    assert.deepEqual(reopened.getPreview(2).map((row) => row.SourceRowId), [10, 20]);
    assert.deepEqual(
      reopened.getSourceRowsForRule({ ruleId: "rule-1", ruleTitle: "Suspicious Process" }),
      [
        { tabId: "tab-a", rowId: 10 },
        { tabId: "tab-a", rowId: 20 },
      ],
    );
    assert.deepEqual([...reopened.iterateRows()].map((row) => row.Computer), ["HOST1", "HOST2", "HOST3"]);
    const aggregates = reopened.getTriageAggregates();
    assert.equal(aggregates.totalRows, 3);
    assert.deepEqual(aggregates.affectedHosts.slice(0, 2), [
      { value: "HOST1", count: 1 },
      { value: "HOST2", count: 1 },
    ]);
    assert.ok(aggregates.rareProcesses.some((item) => item.value === "powershell.exe"));
    assert.ok(aggregates.topRules.some((item) => item.value === "Suspicious Process" && item.count === 2));
  } finally {
    reopened.close();
  }
});

test("orderedHeaders keeps analyst columns first and stable extras after", () => {
  assert.deepEqual(
    orderedHeaders(["zz_extra", "RuleTitle", "_debug", "Timestamp", "Computer"]),
    ["Timestamp", "Computer", "RuleTitle", "zz_extra", "_debug"],
  );
});
