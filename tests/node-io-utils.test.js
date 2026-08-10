const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");

const { extractTarGzBuffer, extractZip, normalizeSha256, sha256File } = require("../electron/analyzers/sigma/node-io-utils");

function zipArchive(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(entries)) {
    const nameBuf = Buffer.from(name);
    const raw = Buffer.from(content);
    const compressed = zlib.deflateRawSync(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBuf, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt32LE(0, 34);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);
    offset += local.length + nameBuf.length + compressed.length;
  }
  const centralOffset = offset;
  const centralBuffer = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(Object.keys(entries).length, 8);
  eocd.writeUInt16LE(Object.keys(entries).length, 10);
  eocd.writeUInt32LE(centralBuffer.length, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  return Buffer.concat([...locals, centralBuffer, eocd]);
}

function tarHeader(name, size, type = "0") {
  const header = Buffer.alloc(512, 0);
  header.write(name, 0, Math.min(Buffer.byteLength(name), 100));
  header.write("0000777\0", 100);
  header.write("0000000\0", 108);
  header.write("0000000\0", 116);
  header.write(size.toString(8).padStart(11, "0") + "\0", 124);
  header.write("00000000000\0", 136);
  header.fill(" ", 148, 156);
  header.write(type, 156);
  header.write("ustar\0", 257);
  header.write("00", 263);
  return header;
}

function tarGzArchive(entries) {
  const parts = [];
  for (const [name, content] of Object.entries(entries)) {
    const raw = Buffer.from(content);
    parts.push(tarHeader(name, raw.length), raw);
    const pad = (512 - (raw.length % 512)) % 512;
    if (pad) parts.push(Buffer.alloc(pad, 0));
  }
  parts.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(parts));
}

test("node IO utils extract ZIP archives without shelling out", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-zip-"));
  const zipPath = path.join(dir, "archive.zip");
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

  fs.writeFileSync(zipPath, zipArchive({ "hayabusa/hayabusa": "binary", "hayabusa/config/default.yml": "rules" }));
  extractZip(zipPath, dir);

  assert.equal(fs.readFileSync(path.join(dir, "hayabusa", "hayabusa"), "utf8"), "binary");
  assert.equal(fs.readFileSync(path.join(dir, "hayabusa", "config", "default.yml"), "utf8"), "rules");
});

test("node IO utils extract tar.gz archives without shelling out", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-targz-"));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

  extractTarGzBuffer(tarGzArchive({ "repo/rules/windows/test.yml": "title: Test Rule\n" }), dir);

  assert.equal(fs.readFileSync(path.join(dir, "repo", "rules", "windows", "test.yml"), "utf8"), "title: Test Rule\n");
});

// ───────────────────────── SHA-256 download integrity ─────────────────────────

test("normalizeSha256 accepts GitHub digests, bare hex, and rejects junk", () => {
  const hex = "a".repeat(64);
  assert.equal(normalizeSha256(`sha256:${hex}`), hex);
  assert.equal(normalizeSha256(hex), hex);
  assert.equal(normalizeSha256(`SHA256:${"A".repeat(64)}`), "a".repeat(64), "case-insensitive + prefix-insensitive");
  assert.equal(normalizeSha256(null), null);
  assert.equal(normalizeSha256(""), null);
  assert.equal(normalizeSha256("sha256:notlongenough"), null);
  assert.equal(normalizeSha256("a".repeat(63)), null, "63 hex chars is not a sha256");
  assert.equal(normalizeSha256(`sha256:${"g".repeat(64)}`), null, "non-hex rejected");
});

test("sha256File matches Node's crypto digest of the file bytes", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-sha-"));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const filePath = path.join(dir, "blob.bin");
  const bytes = crypto.randomBytes(200000); // multi-chunk to exercise streaming
  fs.writeFileSync(filePath, bytes);

  const expected = crypto.createHash("sha256").update(bytes).digest("hex");
  assert.equal(await sha256File(filePath), expected);
  // Known-answer: sha256("") is the well-known empty-string digest.
  const emptyPath = path.join(dir, "empty.bin");
  fs.writeFileSync(emptyPath, "");
  assert.equal(await sha256File(emptyPath), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});
