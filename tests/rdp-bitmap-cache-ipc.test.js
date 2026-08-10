const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const registerRdpBitmapCacheHandlers = require("../electron/ipc/rdp-bitmap-cache-handlers");
const { PathAuthorizer } = require("../electron/utils/path-authorizer");
const {
  createRdpBitmapHandlers,
  resolveToolPath,
} = registerRdpBitmapCacheHandlers._private;

function makeFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rdp-bitmap-ipc-"));
  const cacheDir = path.join(root, "Users", "alice", "AppData", "Local", "Microsoft", "Terminal Server Client", "Cache");
  const outsideDir = path.join(root, "outside");
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.mkdirSync(outsideDir, { recursive: true });
  fs.writeFileSync(path.join(cacheDir, "bcache24.bmc"), "bmc");
  fs.writeFileSync(path.join(cacheDir, "cache0001.bin"), "bin");
  fs.writeFileSync(path.join(cacheDir, "notes.txt"), "ignore");
  fs.writeFileSync(path.join(outsideDir, "cache0002.bin"), "outside");
  return { root, cacheDir, outsideDir };
}

function fakeApp(root) {
  return {
    getPath(name) {
      if (name === "userData") return path.join(root, "user-data");
      return root;
    },
    getAppPath() {
      return path.join(root, "app");
    },
  };
}

test("RDP bitmap source selection authorizes selected paths and returns preflight summary", async () => {
  const { root, cacheDir } = makeFixture();
  const handlers = createRdpBitmapHandlers({
    appLike: fakeApp(root),
    dialog: {
      showOpenDialog: async () => ({ canceled: false, filePaths: [cacheDir] }),
    },
  });

  const selected = await handlers.selectSource();

  assert.deepEqual(selected.paths, [fs.realpathSync.native(cacheDir)]);
  assert.equal(selected.preflight.ready, true);
  assert.equal(selected.preflight.summary.fileCount, 2);
  assert.equal(selected.preflight.summary.bcacheCount, 1);
  assert.equal(selected.preflight.summary.cacheBinCount, 1);
  assert.deepEqual(selected.preflight.summary.users, ["alice"]);

  const repeatedPreflight = await handlers.preflight(null, { paths: [cacheDir] });
  assert.equal(repeatedPreflight.summary.fileCount, 2);

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap preflight rejects unselected paths", async () => {
  const { root, cacheDir, outsideDir } = makeFixture();
  const handlers = createRdpBitmapHandlers({
    appLike: fakeApp(root),
    dialog: {
      showOpenDialog: async () => ({ canceled: false, filePaths: [cacheDir] }),
    },
  });
  await handlers.selectSource();

  await assert.rejects(
    () => handlers.preflight(null, { paths: [outsideDir] }),
    /not authorized/,
  );

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap extraction reports missing bmc-tools before spawning", async () => {
  const { root, cacheDir } = makeFixture();
  const progress = [];
  const handlers = createRdpBitmapHandlers({
    appLike: fakeApp(root),
    dialog: {
      showOpenDialog: async () => ({ canceled: false, filePaths: [cacheDir] }),
    },
    safeSend: (channel, payload) => progress.push({ channel, payload }),
  });
  await handlers.selectSource();

  const result = await handlers.extract(null, { paths: [cacheDir], options: { jobId: "rdp-test" } });

  assert.equal(result.ok, false);
  assert.equal(result.code, "BMC_TOOLS_NOT_CONFIGURED");
  assert.equal(result.preflight.summary.fileCount, 2);
  assert.equal(progress.length, 0);

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap tool selection authorizes a Python bmc-tools script", async () => {
  const { root } = makeFixture();
  const toolPath = path.join(root, "bmc-tools.py");
  fs.writeFileSync(toolPath, "#!/usr/bin/env python3\n");
  const handlers = createRdpBitmapHandlers({
    appLike: fakeApp(root),
    dialog: {
      showOpenDialog: async () => ({ canceled: false, filePaths: [toolPath] }),
    },
  });

  const status = await handlers.selectTool();

  assert.equal(status.installed, true);
  assert.equal(status.source, "selected");
  assert.equal(status.mode, "python-script");
  assert.equal(status.toolPath, fs.realpathSync.native(toolPath));

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap tool status finds bundled bmc-tools under app tools directory", () => {
  const { root } = makeFixture();
  const appLike = fakeApp(root);
  const bundledDir = path.join(appLike.getAppPath(), "tools", "bmc-tools");
  fs.mkdirSync(bundledDir, { recursive: true });
  fs.writeFileSync(path.join(bundledDir, "bmc-tools.py"), "#!/usr/bin/env python3\n");
  const handlers = createRdpBitmapHandlers({
    appLike,
    dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) },
  });

  const status = handlers.toolStatus();

  assert.equal(status.installed, true);
  assert.equal(status.source, "bundled");
  assert.equal(status.mode, "python-script");
  assert.equal(status.toolPath, fs.realpathSync.native(path.join(bundledDir, "bmc-tools.py")));

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap extraction accepts explicit bundled tool path without user tool authorization", () => {
  const { root } = makeFixture();
  const appLike = fakeApp(root);
  const bundledDir = path.join(appLike.getAppPath(), "tools", "bmc-tools");
  const bundledPath = path.join(bundledDir, "bmc-tools.py");
  fs.mkdirSync(bundledDir, { recursive: true });
  fs.writeFileSync(bundledPath, "#!/usr/bin/env python3\n");

  const status = resolveToolPath(new PathAuthorizer(), { toolPath: bundledPath }, appLike);

  assert.equal(status.installed, true);
  assert.equal(status.source, "bundled");
  assert.equal(status.mode, "python-script");
  assert.equal(status.toolPath, fs.realpathSync.native(bundledPath));

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap extraction still rejects explicit unselected custom tool path", () => {
  const { root } = makeFixture();
  const appLike = fakeApp(root);
  const toolPath = path.join(root, "custom-bmc-tools.py");
  fs.writeFileSync(toolPath, "#!/usr/bin/env python3\n");

  assert.throws(
    () => resolveToolPath(new PathAuthorizer(), { toolPath }, appLike),
    /not authorized for rdp-bitmap-tool/,
  );

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap history lists and loads app-managed extraction manifests", async () => {
  const { root, cacheDir } = makeFixture();
  const appLike = fakeApp(root);
  const outputDir = path.join(appLike.getPath("userData"), "rdp-bitmap-cache", "extractions", "2026-04-29-test");
  fs.mkdirSync(outputDir, { recursive: true });
  const imagePath = path.join(outputDir, "000001.bmp");
  fs.writeFileSync(imagePath, "bitmap");
  const manifest = {
    schemaVersion: 1,
    artifactType: "rdp-bitmap-cache",
    sourcePaths: [cacheDir],
    startedAt: "2026-04-29T00:00:00.000Z",
    completedAt: "2026-04-29T00:00:01.000Z",
    outputDir,
    tool: { name: "bmc-tools", path: "/tools/bmc-tools.py" },
    invocation: { commandLine: "python3 bmc-tools.py -s source -d dest" },
    inputCount: 1,
    outputCount: 1,
    inputs: [{ path: path.join(cacheDir, "bcache24.bmc"), name: "bcache24.bmc", kind: "bcache", size: 3, user: "alice", directory: cacheDir }],
    outputs: [{ path: imagePath, relativePath: "000001.bmp", name: "000001.bmp", kind: "tile", tileIndex: 1, size: 6, sha256: "abc123" }],
    outputSummary: { imageCount: 1, tileCount: 1, collageCount: 0, totalBytes: 6, folders: ["."] },
    warnings: [],
    errors: [],
    snapshotHash: "snapshot-test",
  };
  fs.writeFileSync(path.join(outputDir, "manifest.json"), JSON.stringify(manifest, null, 2));
  const handlers = createRdpBitmapHandlers({
    appLike,
    dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) },
    shell: { openPath: async () => "" },
  });

  const history = await handlers.listHistory(null, { limit: 5 });
  assert.equal(history.ok, true);
  assert.equal(history.records.length, 1);
  assert.equal(history.records[0].snapshotHash, "snapshot-test");
  assert.equal(history.records[0].imageCount, 1);

  const loaded = await handlers.loadHistory(null, { outputDir: history.records[0].outputDir });
  assert.equal(loaded.ok, true);
  assert.equal(loaded.history, true);
  assert.equal(loaded.manifest.snapshotHash, "snapshot-test");
  assert.equal(loaded.preflight.summary.fileCount, 1);
  assert.equal(loaded.output.summary.imageCount, 1);
  assert.equal(loaded.output.images[0].sha256, "abc123");

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap evidence package exports manifest, inventories, and recovered images", async () => {
  const { root, cacheDir } = makeFixture();
  const appLike = fakeApp(root);
  const outputDir = path.join(appLike.getPath("userData"), "rdp-bitmap-cache", "extractions", "2026-04-29-package");
  fs.mkdirSync(outputDir, { recursive: true });
  const imagePath = path.join(outputDir, "tiles", "000001.bmp");
  fs.mkdirSync(path.dirname(imagePath), { recursive: true });
  fs.writeFileSync(imagePath, "bitmap");
  const manifest = {
    schemaVersion: 1,
    artifactType: "rdp-bitmap-cache",
    sourcePaths: [cacheDir],
    startedAt: "2026-04-29T00:00:00.000Z",
    completedAt: "2026-04-29T00:00:01.000Z",
    outputDir,
    tool: { name: "bmc-tools", path: "/tools/bmc-tools.py" },
    invocation: { commandLine: "python3 bmc-tools.py -s source -d dest" },
    inputCount: 1,
    outputCount: 1,
    inputs: [{ path: path.join(cacheDir, "bcache24.bmc"), name: "bcache24.bmc", kind: "bcache", size: 3, user: "alice", directory: cacheDir, sha256: "input-sha" }],
    outputs: [{ path: imagePath, relativePath: "tiles/000001.bmp", name: "000001.bmp", kind: "tile", tileIndex: 1, size: 6, sha256: "output-sha" }],
    outputSummary: { imageCount: 1, tileCount: 1, collageCount: 0, totalBytes: 6, folders: ["tiles"] },
    warnings: [],
    errors: [],
    snapshotHash: "snapshot-package",
  };
  fs.writeFileSync(path.join(outputDir, "manifest.json"), JSON.stringify(manifest, null, 2));
  const handlers = createRdpBitmapHandlers({
    appLike,
    dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) },
    shell: { openPath: async () => "" },
  });

  const exported = await handlers.exportPackage(null, { outputDir });

  assert.equal(exported.ok, true);
  assert.equal(exported.imageCount, 1);
  assert.equal(exported.inputCount, 1);
  assert.equal(fs.existsSync(path.join(exported.packageDir, "README.txt")), true);
  assert.equal(fs.existsSync(path.join(exported.packageDir, "manifest.json")), true);
  assert.equal(fs.existsSync(path.join(exported.packageDir, "input-files.csv")), true);
  assert.equal(fs.existsSync(path.join(exported.packageDir, "output-images.csv")), true);
  assert.equal(fs.existsSync(path.join(exported.packageDir, "bmc-tools-command.txt")), true);
  assert.equal(fs.existsSync(path.join(exported.packageDir, "images", "tiles", "000001.bmp")), true);
  assert.match(fs.readFileSync(path.join(exported.packageDir, "README.txt"), "utf8"), /RDP Bitmap Cache evidence package/);

  fs.rmSync(root, { recursive: true, force: true });
});

test("RDP bitmap handlers register expected IPC channels", () => {
  const handlers = {};
  const safeHandle = (channel, fn) => { handlers[channel] = fn; };
  registerRdpBitmapCacheHandlers(safeHandle, () => {}, {
    app: fakeApp(os.tmpdir()),
    dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) },
    shell: { openPath: async () => "" },
  });

  assert.equal(typeof handlers["rdp-bitmap-select-source"], "function");
  assert.equal(typeof handlers["rdp-bitmap-select-tool"], "function");
  assert.equal(typeof handlers["rdp-bitmap-tool-status"], "function");
  assert.equal(typeof handlers["rdp-bitmap-list-history"], "function");
  assert.equal(typeof handlers["rdp-bitmap-load-history"], "function");
  assert.equal(typeof handlers["rdp-bitmap-export-package"], "function");
  assert.equal(typeof handlers["rdp-bitmap-preflight"], "function");
  assert.equal(typeof handlers["rdp-bitmap-extract"], "function");
  assert.equal(typeof handlers["rdp-bitmap-cancel"], "function");
  assert.equal(typeof handlers["rdp-bitmap-open-output-folder"], "function");
  assert.equal(typeof handlers["rdp-bitmap-preview-image"], "function");
});
