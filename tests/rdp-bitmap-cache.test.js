const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");

const {
  collectRdpBitmapCacheFiles,
  isRdpBitmapCacheFile,
  getCacheFileKind,
  parseExtractionOutput,
  buildBmcToolsInvocation,
  convertBmpToPng,
  createExtractionManifest,
} = require("../electron/analyzers/rdp-bitmap-cache");

function makeBmpV4(width, height, pixelsBgra) {
  const dibSize = 108;
  const pixelOffset = 14 + dibSize;
  const rowStride = width * 4;
  const imageSize = rowStride * height;
  const out = Buffer.alloc(pixelOffset + imageSize);
  out.write("BM", 0, "ascii");
  out.writeUInt32LE(out.length, 2);
  out.writeUInt32LE(pixelOffset, 10);
  out.writeUInt32LE(dibSize, 14);
  out.writeInt32LE(width, 18);
  out.writeInt32LE(height, 22);
  out.writeUInt16LE(1, 26);
  out.writeUInt16LE(32, 28);
  out.writeUInt32LE(3, 30);
  out.writeUInt32LE(imageSize, 34);
  out.writeUInt32LE(0x00ff0000, 14 + 40);
  out.writeUInt32LE(0x0000ff00, 14 + 44);
  out.writeUInt32LE(0x000000ff, 14 + 48);
  out.writeUInt32LE(0xff000000, 14 + 52);
  Buffer.from(pixelsBgra).copy(out, pixelOffset);
  return out;
}

function getFirstPngIdatPixels(png) {
  let offset = 8;
  while (offset < png.length) {
    const length = png.readUInt32BE(offset);
    const type = png.toString("ascii", offset + 4, offset + 8);
    if (type === "IDAT") return zlib.inflateSync(png.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
  }
  throw new Error("PNG IDAT chunk not found");
}

test("RDP bitmap cache scanner finds bcache and cache???? files recursively", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rdp-cache-"));
  t.after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

  const cacheDir = path.join(root, "Users", "alice", "AppData", "Local", "Microsoft", "Terminal Server Client", "Cache");
  const unrelatedDir = path.join(root, "Users", "alice", "Documents");
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.mkdirSync(unrelatedDir, { recursive: true });
  fs.writeFileSync(path.join(cacheDir, "bcache24.bmc"), "bmc");
  fs.writeFileSync(path.join(cacheDir, "Cache0000.bin"), "bin");
  fs.writeFileSync(path.join(cacheDir, "cache123.bin"), "not enough digits");
  fs.writeFileSync(path.join(unrelatedDir, "Cache0001.txt"), "wrong extension");

  assert.equal(isRdpBitmapCacheFile("bcache24.bmc"), true);
  assert.equal(isRdpBitmapCacheFile("Cache0000.bin"), true);
  assert.equal(isRdpBitmapCacheFile("cache123.bin"), false);
  assert.equal(getCacheFileKind("Cache0000.bin"), "cache-bin");

  const result = await collectRdpBitmapCacheFiles(root);
  assert.equal(result.files.length, 2);
  assert.equal(result.summary.bcacheCount, 1);
  assert.equal(result.summary.cacheBinCount, 1);
  assert.deepEqual(result.summary.users, ["alice"]);
  assert.ok(result.files.every((file) => file.isExpectedCachePath));
});

test("RDP bitmap cache output parser summarizes tiles and collages", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rdp-output-"));
  t.after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

  const subdir = path.join(root, "Cache0000");
  fs.mkdirSync(subdir);
  fs.writeFileSync(path.join(subdir, "000001.bmp"), "tile-one");
  fs.writeFileSync(path.join(subdir, "000002.PNG"), "tile-two");
  fs.writeFileSync(path.join(root, "Cache0000_collage.bmp"), "collage");
  fs.writeFileSync(path.join(root, "notes.txt"), "ignore");

  const result = await parseExtractionOutput(root);
  assert.equal(result.summary.imageCount, 3);
  assert.equal(result.summary.tileCount, 2);
  assert.equal(result.summary.collageCount, 1);
  assert.equal(result.images.find((image) => image.name === "000001.bmp").tileIndex, 1);
});

test("RDP bitmap cache preview converter turns bmc-tools BMP output into browser-safe PNG", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rdp-preview-"));
  t.after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

  const bmpPath = path.join(root, "tile.bmp");
  const pngPath = path.join(root, "tile.png");
  const nativePngPath = path.join(root, "tile-native.png");
  fs.writeFileSync(bmpPath, makeBmpV4(2, 1, [
    0x00, 0x00, 0xff, 0xff,
    0x00, 0xff, 0x00, 0xff,
  ]));

  const result = await convertBmpToPng(bmpPath, pngPath, { maxDimension: 64 });
  const png = fs.readFileSync(pngPath);
  const pixels = getFirstPngIdatPixels(png);

  assert.equal(result.width, 2);
  assert.equal(result.height, 1);
  assert.deepEqual([...png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.equal(pixels[0], 0);
  assert.deepEqual([...pixels.subarray(1, 9)], [
    0xff, 0x00, 0x00, 0xff,
    0x00, 0xff, 0x00, 0xff,
  ]);

  const nativeResult = await convertBmpToPng(bmpPath, nativePngPath, { maxDimension: 0 });
  assert.equal(nativeResult.width, 2);
  assert.equal(nativeResult.height, 1);
  assert.equal(nativeResult.scaled, false);
});

test("RDP bitmap cache runner builds shell-free bmc-tools invocation", () => {
  const py = buildBmcToolsInvocation({
    toolPath: "/opt/tools/bmc-tools.py",
    sourcePath: "/evidence/Terminal Server Client/Cache",
    destPath: "/tmp/rdp cache",
    includeOld: true,
    collage: true,
    width: 32,
    kape: true,
  });

  assert.equal(py.command, "python3");
  assert.deepEqual(py.args.slice(0, 4), ["/opt/tools/bmc-tools.py", "-s", "/evidence/Terminal Server Client/Cache", "-d"]);
  assert.ok(py.args.includes("-o"));
  assert.ok(py.args.includes("-b"));
  assert.ok(py.args.includes("-k"));
  assert.match(py.commandLine, /"\/evidence\/Terminal Server Client\/Cache"/);

  const binary = buildBmcToolsInvocation({
    toolPath: "/opt/tools/bmc-tools",
    sourcePath: "/evidence/cache0000.bin",
    destPath: "/tmp/out",
    collage: false,
  });
  assert.equal(binary.command, "/opt/tools/bmc-tools");
  assert.equal(binary.args[0], "-s");
  assert.equal(binary.args.includes("-b"), false);
});

test("RDP bitmap cache manifest records input and output hashes", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rdp-manifest-"));
  t.after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

  const input = path.join(root, "Cache0000.bin");
  const output = path.join(root, "000001.bmp");
  fs.writeFileSync(input, "input");
  fs.writeFileSync(output, "output");

  const manifest = await createExtractionManifest({
    sourcePaths: [root],
    cacheFiles: [{ path: input, name: "Cache0000.bin", kind: "cache-bin" }],
    parsedOutput: {
      images: [{ path: output, name: "000001.bmp", kind: "tile" }],
      summary: { imageCount: 1, tileCount: 1, collageCount: 0, totalBytes: 6 },
    },
    tool: { name: "bmc-tools", version: "test" },
    invocation: { commandLine: "python3 bmc-tools.py -s source -d dest" },
  });

  assert.equal(manifest.artifactType, "rdp-bitmap-cache");
  assert.equal(manifest.inputCount, 1);
  assert.equal(manifest.outputCount, 1);
  assert.match(manifest.inputs[0].sha256, /^[a-f0-9]{64}$/);
  assert.match(manifest.outputs[0].sha256, /^[a-f0-9]{64}$/);
  assert.match(manifest.snapshotHash, /^[a-f0-9]{64}$/);
});
