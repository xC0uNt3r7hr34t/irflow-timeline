// Regression test for CSV UTF-8 chunk-boundary corruption (release review L3).
//
// The comma-delimited quote-aware path (Path A) decoded each stream chunk independently
// with chunk.toString("utf-8") and carried an already-decoded STRING across chunks, so a
// multi-byte UTF-8 char split across a 4MB/128MB read boundary decoded to U+FFFD on both
// halves and was permanently lost. Fix routes Path A through a node:string_decoder
// StringDecoder, which buffers a trailing partial multi-byte sequence across writes.
//
// This builds a >4MB CSV with a single "é" positioned so its two UTF-8 bytes straddle the
// 4 MiB read boundary, parses it through the real parser with a stub DB, and asserts the
// character survives intact.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { parseCSVStream } = require("../electron/parsers/csv");

test("CSV parser preserves a multi-byte UTF-8 char split across a 4 MiB chunk boundary", async () => {
  const HWM = 4 * 1024 * 1024; // parser's read buffer for files <500MB; chunk1 = bytes[0, HWM)
  const header = "id,val\n"; // 7 bytes; row 1 begins at byte offset 7, value 'a's at offset 9
  // Place é's first byte (0xC3) at the last index of chunk 1 (HWM-1) so its second byte
  // (0xA9) lands at the start of chunk 2.
  const aCount = HWM - 1 - 9;
  const row1 = "1," + "a".repeat(aCount) + "é" + "more\n";
  const content = Buffer.from(header + row1 + "2,hello\n", "utf8");

  // Sanity: é's lead byte really straddles the boundary.
  assert.equal(content[HWM - 1], 0xc3, "é lead byte should sit at chunk1's last index");
  assert.equal(content[HWM], 0xa9, "é continuation byte should start chunk2");

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "csv-boundary-"));
  const file = path.join(dir, "boundary.csv");
  fs.writeFileSync(file, content);

  const rows = [];
  const db = {
    createTab() {},
    insertBatchArrays(_tabId, arr) { for (const r of arr) rows.push(r); },
    finalizeImport() { return {}; },
  };

  try {
    await parseCSVStream(file, "t1", db, () => {});
    const r1 = rows.find((r) => r[0] === "1");
    assert.ok(r1, "row id=1 should be parsed");
    assert.ok(!r1[1].includes("�"), "value must not contain the U+FFFD replacement char");
    assert.ok(r1[1].endsWith("émore"), `value must end with intact "émore", got tail: ${JSON.stringify(r1[1].slice(-8))}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
