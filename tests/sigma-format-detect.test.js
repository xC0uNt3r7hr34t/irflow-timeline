// Dataset format detection + analyst override (electron/analyzers/sigma/format-detect.js).

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  detectDatasetFormat,
  resolveDatasetFormat,
  normalizeFormatId,
  flagsForFormat,
} = require("../electron/analyzers/sigma/format-detect");

const meta = (headers) => ({ headers });

test("detectDatasetFormat recognizes each known format from headers", () => {
  assert.equal(detectDatasetFormat(meta(["RemoteHost", "PayloadData1", "Channel"])), "evtxecmd");
  // Raw EVTX: datetime + Provider, and none of the more specific signatures.
  assert.equal(detectDatasetFormat(meta(["datetime", "Provider", "EventID", "Channel", "Image"])), "rawevtx");
  // No recognizable signature.
  assert.equal(detectDatasetFormat(meta(["foo", "bar"])), "unknown");
  assert.equal(detectDatasetFormat(meta([])), "unknown");
});

test("normalizeFormatId accepts aliases and rejects junk", () => {
  assert.equal(normalizeFormatId("EvtxECmd"), "evtxecmd");
  assert.equal(normalizeFormatId("kape"), "evtxecmd");
  assert.equal(normalizeFormatId("Raw EVTX"), "rawevtx");
  assert.equal(normalizeFormatId("raw_evtx"), "rawevtx");
  assert.equal(normalizeFormatId("Hayabusa"), "hayabusa");
  assert.equal(normalizeFormatId("nonsense"), null);
  assert.equal(normalizeFormatId(""), null);
  assert.equal(normalizeFormatId(null), null);
});

test("flagsForFormat sets exactly one flag", () => {
  assert.deepEqual(flagsForFormat("evtxecmd"), { isEvtxECmd: true, isHayabusa: false, isChainsaw: false, isRawEvtx: false });
  assert.deepEqual(flagsForFormat("rawevtx"), { isEvtxECmd: false, isHayabusa: false, isChainsaw: false, isRawEvtx: true });
  assert.deepEqual(flagsForFormat("unknown"), { isEvtxECmd: false, isHayabusa: false, isChainsaw: false, isRawEvtx: false });
});

test("resolveDatasetFormat: a recognized override wins over detection", () => {
  const m = meta(["RemoteHost", "PayloadData1"]); // auto-detects evtxecmd
  const r = resolveDatasetFormat(m, "rawevtx");
  assert.equal(r.format, "rawevtx");
  assert.equal(r.label, "Raw EVTX");
  assert.equal(r.detected, "evtxecmd");
  assert.equal(r.detectedLabel, "EvtxECmd");
  assert.equal(r.overridden, true);
  assert.equal(r.flags.isRawEvtx, true);
});

test("resolveDatasetFormat: no/unknown override falls back to detection (not overridden)", () => {
  const m = meta(["RemoteHost", "PayloadData1"]);
  for (const override of [undefined, null, "", "nonsense"]) {
    const r = resolveDatasetFormat(m, override);
    assert.equal(r.format, "evtxecmd", `override ${JSON.stringify(override)} should fall back to detection`);
    assert.equal(r.overridden, false);
  }
});

test("resolveDatasetFormat: override equal to detection is not flagged as overridden", () => {
  const m = meta(["RemoteHost", "PayloadData1"]);
  const r = resolveDatasetFormat(m, "evtxecmd");
  assert.equal(r.format, "evtxecmd");
  assert.equal(r.overridden, false, "selecting the already-detected format is a no-op override");
});
