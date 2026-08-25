// CSV/TSV encoding tests (lower-tier fix): UTF-16 sources must be detected and decoded,
// not rejected as binary, and non-ASCII text must survive intact. (The UTF-8
// chunk-boundary StringDecoder fix is exercised implicitly by the round-trips.)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { detectEncoding, parseCSVStream } = require("../electron/parsers/csv");

// ───────────────────────── detectEncoding ─────────────────────────

test("detectEncoding: BOMs", () => {
  assert.equal(detectEncoding(Buffer.from("﻿Name,Path\n", "utf16le")), "utf-16le"); // FF FE BOM
  assert.equal(detectEncoding(Buffer.from([0xFE, 0xFF, 0x00, 0x4E])), "utf-16be"); // FE FF BOM + "N"
  assert.equal(detectEncoding(Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from("Name,Path\n", "utf8")])), "utf-8"); // UTF-8 BOM
});

test("detectEncoding: BOM-less UTF-16LE via heuristic; plain UTF-8 stays UTF-8", () => {
  assert.equal(detectEncoding(Buffer.from("Name,Path\nabc,def\nghi,jkl\n", "utf16le")), "utf-16le");
  assert.equal(detectEncoding(Buffer.from("Name,Path\nabc,def\nghi,jkl\n", "utf8")), "utf-8");
  // A UTF-8 file with accented (multibyte) data must NOT be misdetected as UTF-16.
  assert.equal(detectEncoding(Buffer.from("Name,Path\név",  "utf8")), "utf-8");
  assert.equal(detectEncoding(Buffer.from("a", "utf8")), "utf-8"); // < 2 bytes
});

// ───────────────────────── parseCSVStream round-trips ─────────────────────────

function mockDb() {
  const rows = [];
  let headers = null;
  return {
    createTab(_id, hdrs) { headers = hdrs; },
    insertBatchArrays(_id, batch) { for (const r of batch) rows.push(r); },
    finalizeImport() { return { rowCount: rows.length, tsColumns: new Set(), numericColumns: new Set() }; },
    _rows: () => rows,
    _headers: () => headers,
  };
}

function withTempFile(buf, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-csv-enc-"));
  const p = path.join(dir, "in.csv");
  fs.writeFileSync(p, buf);
  return Promise.resolve(body(p)).finally(() => fs.rmSync(dir, { recursive: true, force: true }));
}

test("parseCSVStream decodes a UTF-16LE (BOM) CSV with non-ASCII data instead of rejecting it", async () => {
  const content = "Name,Path\névil,C:\\Témp\\中.exe\nКто,D:\\данные\n";
  const buf = Buffer.from("﻿" + content, "utf16le");
  await withTempFile(buf, async (p) => {
    const db = mockDb();
    const result = await parseCSVStream(p, "t1", db);
    assert.deepEqual(db._headers(), ["Name", "Path"]);
    assert.equal(result.rowCount, 2);
    assert.deepEqual(db._rows()[0], ["évil", "C:\\Témp\\中.exe"]);
    assert.deepEqual(db._rows()[1], ["Кто", "D:\\данные"]);
  });
});

test("parseCSVStream decodes a BOM-less UTF-16LE TSV via the heuristic", async () => {
  const content = "Name\tPath\nfoo\tC:\\rép\nbar\tD:\\日本\n";
  const buf = Buffer.from(content, "utf16le"); // no BOM
  await withTempFile(buf, async (p) => {
    const db = mockDb();
    const result = await parseCSVStream(p, "t2", db);
    assert.deepEqual(db._headers(), ["Name", "Path"]);
    assert.equal(result.rowCount, 2);
    assert.deepEqual(db._rows()[0], ["foo", "C:\\rép"]);
    assert.deepEqual(db._rows()[1], ["bar", "D:\\日本"]);
  });
});

test("parseCSVStream still handles UTF-8 with non-ASCII data (no regression)", async () => {
  const content = "Name,Path\névil,C:\\Témp\\中.exe\n";
  await withTempFile(Buffer.from(content, "utf8"), async (p) => {
    const db = mockDb();
    const result = await parseCSVStream(p, "t3", db);
    assert.deepEqual(db._headers(), ["Name", "Path"]);
    assert.equal(result.rowCount, 1);
    assert.deepEqual(db._rows()[0], ["évil", "C:\\Témp\\中.exe"]);
  });
});

test("parseCSVStream still rejects genuinely binary (UTF-8-context null bytes)", async () => {
  const buf = Buffer.from([0x4E, 0x61, 0x6D, 0x65, 0x00, 0x01, 0x02, 0x03]); // "Name" + nulls, no UTF-16 pattern
  await withTempFile(buf, async (p) => {
    const db = mockDb();
    await assert.rejects(() => parseCSVStream(p, "t4", db), /binary/i);
  });
});
