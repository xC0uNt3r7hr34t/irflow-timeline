// Regression test for the Multi-Source Lateral Movement crash (release review H1).
//
// Bug: the extracted analyzer's detectTabColumns() read the dataset detectors off
// the ctx object — ctx.isHayabusaDataset(meta) / ctx.isChainsawLogonDataset(meta) —
// but db.js never put those helpers on the ctx it builds for multi-source. So
// ctx.isHayabusaDataset was undefined and invoking it threw
// "TypeError: ctx.isHayabusaDataset is not a function". The throw is OUTSIDE the
// per-tab try block, so it propagated and the whole feature produced no results for
// its only intended use case (>= 2 tabs). The single-tab path was unaffected because
// it imports the detectors directly from evtx-utils.
//
// Fix: multi-source.js imports { isHayabusaDataset, isChainsawLogonDataset } from
// ../evtx-utils and calls them directly (mirroring the single-tab analyzer).
//
// Why the existing suite missed it: tests/lateral-movement-evtxecmd.test.js builds a
// stub ctx that INCLUDES isHayabusaDataset/isChainsawLogonDataset, so it never hit the
// production ctx shape that omits them. This test uses the EXACT ctx db.js passes.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  getMultiSourceLateralMovement,
  previewMultiSourceLateralMovement,
} = require("../electron/analyzers/lateral-movement/multi-source");

// Minimal tab stub. detectTabColumns() only reads meta.headers; every per-tab DB
// query in the analyzer is either empty here or wrapped in try/catch, so an
// empty-result db keeps the analyzer on the no-throw path. That leaves the ctx-missing-
// detectors regression as the only thing that can throw (it crashes in detectTabColumns,
// which runs before the empty-data early return).
function stubTab(tabId, headers) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const db = {
    prepare() {
      return {
        get() { return { cnt: 0 }; },
        all() { return []; },
      };
    },
  };
  return { meta: { db, headers, colMap, tabId }, tabId, label: tabId };
}

// EXACT ctx shape db.js builds for getMultiSourceLateralMovement (electron/db.js:1145-1149).
// Critically it does NOT include isHayabusaDataset / isChainsawLogonDataset — reproducing
// the production condition that crashed before the fix.
function realMultiSourceCtx() {
  return {
    applyStandardFilters() {},
    ensureIndex() {},
    lmPreviewCache: new Map(),
  };
}

// EXACT ctx shape db.js builds for previewMultiSourceLateralMovement (electron/db.js:1165-1168) —
// only applyStandardFilters; also lacks the detectors.
function realPreviewCtx() {
  return { applyStandardFilters() {} };
}

// EvtxECmd KAPE Security export (RemoteHost + PayloadData1 ⇒ isEvtxECmd).
const EVTXECMD_HEADERS = ["TimeCreated", "EventId", "Computer", "RemoteHost", "PayloadData1", "PayloadData2", "Channel"];
// Raw Windows Security.evtx export (Standard format; no EvtxECmd/Hayabusa/Chainsaw markers).
const RAW_SECURITY_HEADERS = ["datetime", "EventID", "Computer", "IpAddress", "TargetUserName", "LogonType", "Provider", "Channel"];

test("getMultiSourceLateralMovement does not crash when the db.js ctx omits the dataset detectors (>=2 tabs)", () => {
  const metas = [
    stubTab("tab-evtxecmd", EVTXECMD_HEADERS),
    stubTab("tab-raw-security", RAW_SECURITY_HEADERS),
  ];
  let result;
  assert.doesNotThrow(() => {
    result = getMultiSourceLateralMovement(metas, { excludeServiceAccounts: false }, realMultiSourceCtx());
  });
  assert.ok(result && typeof result === "object", "must return a result object");
  assert.ok("nodes" in result && "edges" in result, "result must have the lateral-movement shape");
  // primaryColumns is taken from the first detected tab (EvtxECmd) — proves
  // detectTabColumns ran and the detectors resolved (false for EvtxECmd) instead of throwing.
  assert.equal(result.columns && result.columns._isEvtxECmd, true, "first tab must be classified as EvtxECmd");
});

test("previewMultiSourceLateralMovement does not crash and classifies formats when its ctx omits the detectors", () => {
  const metas = [
    stubTab("tab-evtxecmd", EVTXECMD_HEADERS),
    stubTab("tab-raw-security", RAW_SECURITY_HEADERS),
  ];
  let preview;
  assert.doesNotThrow(() => {
    preview = previewMultiSourceLateralMovement(metas, {}, realPreviewCtx());
  });
  assert.ok(Array.isArray(preview.tabs) && preview.tabs.length === 2, "preview must classify both tabs");
  const formats = preview.tabs.map((t) => t.format);
  // Both branches of the detector logic must resolve correctly (proves the direct
  // evtx-utils import works in place of the missing ctx helpers).
  assert.ok(formats.includes("EvtxECmd"), `expected an EvtxECmd tab, got ${JSON.stringify(formats)}`);
  assert.ok(formats.includes("Standard"), `expected a Standard tab, got ${JSON.stringify(formats)}`);
});
