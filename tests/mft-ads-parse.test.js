// Tests for the raw-$MFT non-Zone ADS stream enumeration added to the parser (T5).
// Pure byte/array logic — runs under plain `node --test` (no SQLite binding needed).

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseMftRecord, buildMftRow, MFT_COLUMNS } = require("../electron/parsers/mft");

// Build a minimal 1024-byte base MFT record with one resident, named $DATA attribute.
// nameLen is in UTF-16 code units; content bytes are placed at contentOffset.
function makeRecord({ streamName, content, nonResident = false, realSize = 0 }) {
  const buf = Buffer.alloc(1024);
  buf.write("FILE", 0, "ascii");
  buf.writeUInt16LE(48, 4);    // fixupOffset
  buf.writeUInt16LE(1, 6);     // fixupCount = 1 → applyFixup is a no-op
  buf.writeUInt16LE(1, 16);    // sequence number
  buf.writeUInt16LE(56, 20);   // first attribute offset
  buf.writeUInt16LE(1, 22);    // flags: in-use
  buf.writeUInt32LE(100, 44);  // entry number

  const a = 56;                // $DATA attribute start
  const nameUnits = streamName.length;
  const nameOff = 24;
  const contentOff = nameOff + nameUnits * 2 + 2; // after the name (kept even)
  buf.writeUInt32LE(0x80, a);            // type = $DATA
  buf[a + 8] = nonResident ? 1 : 0;
  buf[a + 9] = nameUnits;                // name length (UTF-16 units)
  buf.writeUInt16LE(nameOff, a + 10);    // name offset
  if (nonResident) {
    buf.writeBigUInt64LE(BigInt(realSize), a + 48); // real data size
  } else {
    buf.writeUInt32LE(content.length, a + 16);      // content size
    buf.writeUInt16LE(contentOff, a + 20);          // content offset
    for (let i = 0; i < content.length; i++) buf[a + contentOff + i] = content[i];
  }
  buf.write(streamName, a + nameOff, "utf16le");
  const attrLen = 8 * Math.ceil((contentOff + (nonResident ? 0 : content.length)) / 8) + 8;
  buf.writeUInt32LE(attrLen, a + 4);
  buf.writeUInt32LE(0xFFFFFFFF, a + attrLen); // attribute-list terminator
  return buf;
}

test("parser: schema and row are aligned (AdsStreamCount/AdsStreams appended)", () => {
  assert.ok(MFT_COLUMNS.includes("AdsStreamCount") && MFT_COLUMNS.includes("AdsStreams"));
  const { rec } = parseMftRecord(makeRecord({ streamName: "payload", content: Buffer.from([0x4d, 0x5a, 0x90, 0x00]) }), 0);
  const row = buildMftRow(rec, new Map(), new Map([[5, "."]]));
  assert.equal(row.length, MFT_COLUMNS.length, "row array length must equal the column count");
  assert.equal(row[MFT_COLUMNS.indexOf("HasAds")], "True");
});

test("parser: resident named non-Zone stream is captured with size + PE/MZ exec sniff", () => {
  const { rec } = parseMftRecord(makeRecord({ streamName: "payload", content: Buffer.from([0x4d, 0x5a, 0x90, 0x00]) }), 0);
  assert.equal(rec.hasAds, true);
  assert.ok(Array.isArray(rec.adsStreams) && rec.adsStreams.length === 1);
  assert.equal(rec.adsStreams[0].name, "payload");
  assert.equal(rec.adsStreams[0].size, 4n);
  assert.equal(rec.adsStreams[0].exec, true, "MZ header → executable content");
  const row = buildMftRow(rec, new Map(), new Map([[5, "."]]));
  assert.equal(row[MFT_COLUMNS.indexOf("AdsStreamCount")], "1");
  assert.equal(row[MFT_COLUMNS.indexOf("AdsStreams")], "!payload(4)", "'!' marks resident PE/MZ content");
});

test("parser: resident named non-Zone stream WITHOUT MZ is not flagged exec ('.' flag)", () => {
  const { rec } = parseMftRecord(makeRecord({ streamName: "config", content: Buffer.from("hello") }), 0);
  assert.equal(rec.adsStreams[0].name, "config");
  assert.equal(rec.adsStreams[0].exec, false);
  const row = buildMftRow(rec, new Map(), new Map([[5, "."]]));
  assert.equal(row[MFT_COLUMNS.indexOf("AdsStreams")], ".config(5)", "always-prefix one flag char ('.' = non-exec)");
});

test("parser: a stream NAME beginning with '!' cannot forge the exec flag", () => {
  // non-MZ content, but the name itself starts with '!' — the always-present leading flag must be '.'
  const { rec } = parseMftRecord(makeRecord({ streamName: "!readme", content: Buffer.from("hi") }), 0);
  assert.equal(rec.adsStreams[0].name, "!readme");
  assert.equal(rec.adsStreams[0].exec, false);
  const row = buildMftRow(rec, new Map(), new Map([[5, "."]]));
  assert.equal(row[MFT_COLUMNS.indexOf("AdsStreams")], ".!readme(2)", "leading '.' flag, real name '!readme' preserved");
});

test("parser: non-resident named stream captures real size, no content sniff", () => {
  const { rec } = parseMftRecord(makeRecord({ streamName: "big", content: Buffer.alloc(0), nonResident: true, realSize: 1048576 }), 0);
  assert.equal(rec.adsStreams[0].name, "big");
  assert.equal(rec.adsStreams[0].size, 1048576n);
  assert.equal(rec.adsStreams[0].exec, false, "non-resident content is not in the MFT to sniff");
});

test("parser: Zone.Identifier stream goes to ZoneIdContents, NOT the non-Zone ADS list", () => {
  const { rec } = parseMftRecord(makeRecord({ streamName: "Zone.Identifier", content: Buffer.from("[ZoneTransfer]\r\nZoneId=3\r\n") }), 0);
  assert.equal(rec.hasAds, true);
  assert.equal(rec.adsStreams, null, "Zone.Identifier is not a non-Zone stream");
  assert.match(rec.zoneId, /ZoneId=3/);
  const row = buildMftRow(rec, new Map(), new Map([[5, "."]]));
  assert.equal(row[MFT_COLUMNS.indexOf("AdsStreamCount")], "", "no non-Zone streams → empty count");
  assert.match(row[MFT_COLUMNS.indexOf("ZoneIdContents")], /ZoneId=3/);
});
