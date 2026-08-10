const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadModalRegistry() {
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "modals", "modalRegistry.js"), "utf8");
  const munged = src.replace(/^export\s+function\s+/gm, "function ");
  const names = [
    "updateModal",
    "openBulkActionsModal",
    "openLateralMovementModal",
	    "openPersistenceModal",
	    "openRdpBitmapCacheModal",
	    "openRansomwareModal",
    "openUsnAnalysisModal",
  ];
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(`${munged}\n;Object.assign(globalThis, { ${names.join(", ")} });`, ctx);
  return ctx;
}

const registry = loadModalRegistry();

test("modal registry builders preserve analyzer defaults", () => {
  const lateral = registry.openLateralMovementModal({ user: "UserName" }, { chainsawSyntheticTarget: "LOCAL_HOST" });
  assert.equal(lateral.type, "lateralMovement");
  assert.deepEqual(lateral.columns, { user: "UserName" });
  assert.equal(lateral.excludeLocal, true);
  assert.equal(lateral.lmIntent, "balanced");
  assert.equal(lateral.lmPreviewLoading, true);
  assert.equal(lateral.chainsawSyntheticTarget, "LOCAL_HOST");
  assert.equal(Object.prototype.toString.call(lateral.lmDisabledRules), "[object Set]");

  const persistence = registry.openPersistenceModal({ mode: "registry" });
  assert.equal(persistence.type, "persistence");
  assert.equal(persistence.mode, "registry");
  assert.equal(persistence.paPreviewLoading, true);
  assert.equal(persistence.paSortBy, "triage");
  assert.equal(Object.prototype.toString.call(persistence.disabledRules), "[object Set]");

  const ransomware = registry.openRansomwareModal({ usnTabId: "usn-1" });
  assert.equal(ransomware.type, "ransomware");
  assert.equal(ransomware.noteMatchMode, "exact");
  assert.equal(ransomware.usnTabId, "usn-1");

	  const bulk = registry.openBulkActionsModal();
	  assert.equal(bulk.type, "bulkActions");
	  assert.equal(bulk.tagName, "");
	  assert.equal(bulk.tagColor, "#E85D2A");
	  assert.equal(bulk.result, null);

	  const rdp = registry.openRdpBitmapCacheModal();
	  assert.equal(rdp.type, "rdpBitmapCache");
	  assert.equal(rdp.phase, "input");
	  assert.equal(Array.isArray(rdp.paths), true);
	  assert.equal(rdp.paths.length, 0);
	  assert.equal(rdp.options.collage, true);
	  assert.equal(rdp.options.width, 64);
	  assert.equal(Array.isArray(rdp.historyRecords), true);
	  assert.equal(rdp.historyRecords.length, 0);
	  assert.equal(rdp.result, null);
	  assert.equal(rdp.packageResult, null);
	  assert.equal(rdp.packageExporting, false);
	});

test("USN modal builder creates independent analysis and expansion maps", () => {
  const first = registry.openUsnAnalysisModal();
  const second = registry.openUsnAnalysisModal();

  assert.equal(first.type, "usnAnalysis");
  assert.equal(first.phase, "input");
  assert.equal(first.analyses.renames, true);
  assert.equal(first.usnExpanded.renames, true);
  assert.notEqual(first.analyses, first.usnExpanded);
  assert.notEqual(first.analyses, second.analyses);

  first.analyses.renames = false;
  assert.equal(second.analyses.renames, true);
});

test("updateModal only updates the active modal type", () => {
  const prev = { type: "stacking", loading: true, data: null };
  const next = registry.updateModal("stacking", { loading: false, data: [1] })(prev);
  assert.equal(next.type, "stacking");
  assert.equal(next.loading, false);
  assert.equal(next.data.length, 1);
  assert.equal(next.data[0], 1);

  const wrongType = { type: "ads", loading: true };
  assert.equal(registry.updateModal("stacking", { loading: false })(wrongType), wrongType);

  const unchanged = registry.updateModal("ads", () => null)(wrongType);
  assert.equal(unchanged, wrongType);
});
