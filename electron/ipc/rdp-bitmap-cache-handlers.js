const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { PathAuthorizer, isPathInside } = require("../utils/path-authorizer");
const { openDialogOptions } = require("../utils/open-dialog");
const {
  collectRdpBitmapCacheFiles,
  convertBmpToPng,
  MANIFEST_FILE_NAME,
  parseExtractionOutput,
  runBmcTools,
} = require("../analyzers/rdp-bitmap-cache");

const SOURCE_SCOPE = "rdp-bitmap-source";
const TOOL_SCOPE = "rdp-bitmap-tool";
const OUTPUT_SCOPE = "rdp-bitmap-output";
const PACKAGE_SCOPE = "rdp-bitmap-package";

function loadElectronObject() {
  try {
    const electron = require("electron");
    return electron && typeof electron === "object" ? electron : {};
  } catch {
    return {};
  }
}

const electron = loadElectronObject();

function randomId(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

function toPathList(paths) {
  if (Array.isArray(paths)) return paths.filter((p) => typeof p === "string" && p.trim());
  if (typeof paths === "string" && paths.trim()) return [paths];
  return [];
}

function statSyncSafe(targetPath) {
  try {
    return fs.statSync(targetPath);
  } catch {
    return null;
  }
}

function authorizeSource(authorizer, targetPath) {
  const st = statSyncSafe(targetPath);
  if (!st) throw new Error(`Source path does not exist: ${targetPath}`);
  return authorizer.authorize(SOURCE_SCOPE, targetPath, {
    recursive: st.isDirectory(),
    label: st.isDirectory() ? "RDP Bitmap Cache source folder" : "RDP Bitmap Cache source file",
  });
}

function authorizeSelectedSources(authorizer, paths) {
  return toPathList(paths).map((targetPath) => authorizeSource(authorizer, targetPath));
}

function assertAuthorizedSources(authorizer, paths) {
  const sourcePaths = toPathList(paths);
  if (!sourcePaths.length) throw new Error("Select an RDP Bitmap Cache source file or folder first.");
  return sourcePaths.map((targetPath) => authorizer.assertAuthorized(SOURCE_SCOPE, targetPath));
}

function buildPreflightResponse(collected) {
  const summary = {
    ...collected.summary,
    scannedFileCount: collected.scannedFileCount,
    skippedSymlinks: collected.skippedSymlinks,
  };
  const warnings = [...(collected.warnings || [])];
  if (!summary.fileCount) {
    warnings.unshift("No RDP Bitmap Cache files were found. Expected bcache*.bmc or cache????.bin files.");
  }
  return {
    ready: summary.fileCount > 0,
    sourcePaths: collected.sourcePaths,
    files: collected.files,
    summary,
    warnings,
    errors: [],
  };
}

async function preflightSources(authorizer, paths, options = {}) {
  const sourcePaths = assertAuthorizedSources(authorizer, paths);
  const collected = await collectRdpBitmapCacheFiles(sourcePaths, {
    recursive: options.recursive !== false,
    followSymlinks: !!options.followSymlinks,
    maxDepth: options.maxDepth,
    maxFiles: options.maxFiles,
  });
  return buildPreflightResponse(collected);
}

function getAppPath(appLike, name) {
  if (appLike && typeof appLike.getPath === "function") {
    try {
      return appLike.getPath(name);
    } catch {
      return null;
    }
  }
  return null;
}

function getUserDataRoot(appLike) {
  return getAppPath(appLike, "userData") || path.join(os.tmpdir(), "irflow-timeline");
}

function getAppBasePath(appLike) {
  if (appLike && typeof appLike.getAppPath === "function") {
    try {
      return appLike.getAppPath();
    } catch {
      return process.cwd();
    }
  }
  return process.cwd();
}

function candidateToolPaths(appLike = electron.app) {
  const candidates = [];
  const resourcesPath = process.resourcesPath;
  const appPath = getAppBasePath(appLike);
  const names = [
    ["tools", "bmc-tools", "bmc-tools.py"],
    ["tools", "bmc-tools", "bmc-tools"],
    ["tools", "bmc-tools", "bmc-tools.exe"],
  ];
  for (const root of [resourcesPath, appPath].filter(Boolean)) {
    for (const parts of names) candidates.push(path.join(root, ...parts));
  }
  return [...new Set(candidates)];
}

let _pythonInterpreter; // undefined = not yet probed; string = found; null = none found
function resolvePythonInterpreter() {
  if (_pythonInterpreter !== undefined) return _pythonInterpreter;
  const { spawnSync } = require("child_process");
  for (const cmd of ["python3", "python"]) {
    try {
      const r = spawnSync(cmd, ["--version"], { stdio: "ignore", timeout: 5000, shell: false });
      if (!r.error && r.status === 0) { _pythonInterpreter = cmd; return cmd; }
    } catch { /* try next */ }
  }
  _pythonInterpreter = null;
  return null;
}

function describeToolPath(toolPath, source = "selected") {
  const canonical = fs.realpathSync.native(toolPath);
  const mode = /\.py$/i.test(path.basename(canonical)) ? "python-script" : "binary";
  const status = { installed: true, source, toolPath: canonical, mode };
  if (mode === "python-script") {
    // bmc-tools.py needs a Python interpreter at runtime. Surface availability so the UI
    // can warn up front instead of failing later with a cryptic `spawn python3 ENOENT`.
    const py = resolvePythonInterpreter();
    status.pythonAvailable = !!py;
    status.pythonInterpreter = py || null;
  }
  return status;
}

function isBundledToolPath(toolPath, appLike = electron.app) {
  if (!toolPath) return false;
  let canonical;
  try {
    canonical = fs.realpathSync.native(toolPath);
  } catch {
    return false;
  }

  return candidateToolPaths(appLike).some((candidate) => {
    try {
      return fs.existsSync(candidate) && statSyncSafe(candidate)?.isFile() && fs.realpathSync.native(candidate) === canonical;
    } catch {
      return false;
    }
  });
}

function getToolStatus({ appLike = electron.app, selectedToolPath = null } = {}) {
  if (selectedToolPath && fs.existsSync(selectedToolPath)) {
    return describeToolPath(selectedToolPath, "selected");
  }
  for (const candidate of candidateToolPaths(appLike)) {
    if (fs.existsSync(candidate) && statSyncSafe(candidate)?.isFile()) {
      return describeToolPath(candidate, "bundled");
    }
  }
  return {
    installed: false,
    source: null,
    toolPath: null,
    mode: null,
    candidates: candidateToolPaths(appLike),
  };
}

function resolveToolPath(authorizer, options = {}, appLike = electron.app) {
  if (options.toolPath) {
    if (isBundledToolPath(options.toolPath, appLike)) {
      return describeToolPath(options.toolPath, "bundled");
    }
    const canonical = authorizer.assertAuthorized(TOOL_SCOPE, options.toolPath);
    return getToolStatus({ appLike, selectedToolPath: canonical });
  }
  return getToolStatus({ appLike });
}

function slugFromSourcePaths(sourcePaths) {
  const first = sourcePaths[0] || "cache";
  return path.basename(first).replace(/[^a-z0-9._-]+/gi, "_").slice(0, 64) || "cache";
}

function makeOutputDir(sourcePaths, appLike = electron.app) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const slug = slugFromSourcePaths(sourcePaths);
  return path.join(getExtractionRoot(appLike), `${stamp}-${slug}-${crypto.randomBytes(3).toString("hex")}`);
}

function getExtractionRoot(appLike = electron.app) {
  return path.join(getUserDataRoot(appLike), "rdp-bitmap-cache", "extractions");
}

function getPackageRoot(appLike = electron.app) {
  return path.join(getUserDataRoot(appLike), "rdp-bitmap-cache", "packages");
}

function getPreviewRoot(appLike = electron.app) {
  return path.join(getUserDataRoot(appLike), "rdp-bitmap-cache", "previews");
}

async function ensureOutputDir(authorizer, sourcePaths, appLike = electron.app) {
  const outputDir = makeOutputDir(sourcePaths, appLike);
  await fsp.mkdir(outputDir, { recursive: true });
  authorizer.authorize(OUTPUT_SCOPE, outputDir, {
    recursive: true,
    appManaged: true,
    label: "RDP Bitmap Cache extraction output",
  });
  return outputDir;
}

async function readJsonFile(filePath) {
  return JSON.parse(await fsp.readFile(filePath, "utf8"));
}

function csvCell(value) {
  if (value === null || value === undefined) return "";
  const text = String(value);
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function writeCsv(filePath, rows, columns) {
  const header = columns.map((col) => csvCell(col.label)).join(",");
  const lines = rows.map((row) => columns.map((col) => csvCell(typeof col.value === "function" ? col.value(row) : row[col.value])).join(","));
  return fsp.writeFile(filePath, [header, ...lines].join("\n") + "\n", "utf8");
}

async function copyFileIntoPackage(srcPath, destPath) {
  await fsp.mkdir(path.dirname(destPath), { recursive: true });
  await fsp.copyFile(srcPath, destPath);
  const st = await fsp.stat(destPath);
  return st.size;
}

async function packageFileSize(filePath) {
  try {
    const st = await fsp.stat(filePath);
    if (st.isFile()) return st.size;
    if (!st.isDirectory()) return 0;
    const entries = await fsp.readdir(filePath);
    let total = 0;
    for (const entry of entries) total += await packageFileSize(path.join(filePath, entry));
    return total;
  } catch {
    return 0;
  }
}

function safePackageName(value, fallback = "artifact") {
  return String(value || fallback)
    .replace(/[^a-z0-9._-]+/gi, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || fallback;
}

function makePackageDir(record, appLike = electron.app) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const snapshot = safePackageName(String(record.manifest?.snapshotHash || "snapshot").slice(0, 12), "snapshot");
  return path.join(getPackageRoot(appLike), `${stamp}-${snapshot}-${crypto.randomBytes(3).toString("hex")}`);
}

async function getManagedOutputDir(appLike, outputDir) {
  const root = getExtractionRoot(appLike);
  await fsp.mkdir(root, { recursive: true });
  const rootReal = fs.realpathSync.native(root);
  const outputReal = fs.realpathSync.native(outputDir);
  if (!isPathInside(outputReal, rootReal)) {
    throw new Error("RDP Bitmap Cache output is not inside the app-managed extraction history.");
  }
  return outputReal;
}

async function getManagedOutputFile(appLike, filePath) {
  if (!filePath) throw new Error("RDP Bitmap Cache image path is required.");
  const root = getExtractionRoot(appLike);
  await fsp.mkdir(root, { recursive: true });
  const rootReal = fs.realpathSync.native(root);
  const fileReal = fs.realpathSync.native(filePath);
  if (!isPathInside(fileReal, rootReal)) {
    throw new Error("RDP Bitmap Cache image is not inside the app-managed extraction history.");
  }
  return fileReal;
}

async function createImagePreview(appLike, authorizer, imagePath, options = {}) {
  const canonical = await getManagedOutputFile(appLike, imagePath);
  const ext = path.extname(canonical).toLowerCase();
  if (![".bmp", ".png", ".jpg", ".jpeg"].includes(ext)) {
    throw new Error(`Unsupported RDP Bitmap Cache preview format: ${ext || "unknown"}`);
  }
  if (ext !== ".bmp") {
    return { ok: true, imagePath: canonical, previewPath: canonical, converted: false };
  }

  const sourceStat = await fsp.stat(canonical);
  const previewRoot = getPreviewRoot(appLike);
  const maxDimension = Number.isFinite(options.maxDimension) ? Math.floor(options.maxDimension) : 2048;
  const previewSizeKey = maxDimension > 0 ? String(maxDimension) : "native";
  const digest = crypto.createHash("sha256").update(canonical).digest("hex").slice(0, 20);
  const previewPath = path.join(previewRoot, `${digest}-${previewSizeKey}.png`);
  const previewStat = await fsp.stat(previewPath).catch(() => null);
  if (!previewStat || previewStat.mtimeMs < sourceStat.mtimeMs) {
    await convertBmpToPng(canonical, previewPath, {
      maxDimension,
    });
  }

  authorizer.authorize(OUTPUT_SCOPE, previewRoot, {
    recursive: true,
    appManaged: true,
    label: "RDP Bitmap Cache image previews",
  });
  const finalStat = await fsp.stat(previewPath);
  return {
    ok: true,
    imagePath: canonical,
    previewPath,
    converted: true,
    maxDimension,
    size: finalStat.size,
  };
}

function summarizeInputFiles(inputs = []) {
  const summary = { fileCount: 0, bcacheCount: 0, cacheBinCount: 0, totalBytes: 0, users: [], cacheDirectories: [] };
  const users = new Set();
  const dirs = new Set();
  for (const input of inputs || []) {
    summary.fileCount += 1;
    if (input.kind === "bcache") summary.bcacheCount += 1;
    if (input.kind === "cache-bin") summary.cacheBinCount += 1;
    summary.totalBytes += Number(input.size) || 0;
    if (input.user) users.add(input.user);
    if (input.directory) dirs.add(input.directory);
  }
  summary.users = [...users].sort((a, b) => a.localeCompare(b));
  summary.cacheDirectories = [...dirs].sort((a, b) => a.localeCompare(b));
  return summary;
}

function mergeOutputHashes(parsedOutput, manifest) {
  const byPath = new Map((manifest?.outputs || []).map((image) => [image.path, image]));
  const byRelative = new Map((manifest?.outputs || []).map((image) => [image.relativePath || image.name, image]));
  const parsedImages = parsedOutput?.images || [];
  const images = parsedImages.length
    ? parsedImages.map((image) => {
      const prior = byPath.get(image.path) || byRelative.get(image.relativePath || image.name) || null;
      return { ...(prior || {}), ...image, sha256: prior?.sha256 || image.sha256 || null };
    })
    : (manifest?.outputs || []);
  return {
    outputDir: parsedOutput?.outputDir || manifest?.outputDir || null,
    images,
    summary: parsedOutput?.summary?.imageCount !== undefined ? parsedOutput.summary : (manifest?.outputSummary || null),
    warnings: [...(manifest?.warnings || []), ...(parsedOutput?.warnings || [])],
  };
}

function historyRecordFromManifest(outputDir, manifest, manifestStat = null) {
  const summary = manifest?.outputSummary || {};
  return {
    outputDir,
    manifestPath: path.join(outputDir, MANIFEST_FILE_NAME),
    snapshotHash: manifest?.snapshotHash || null,
    sourcePaths: manifest?.sourcePaths || [],
    startedAt: manifest?.startedAt || null,
    completedAt: manifest?.completedAt || null,
    modifiedAt: manifestStat?.mtime?.toISOString?.() || null,
    inputCount: manifest?.inputCount || manifest?.inputs?.length || 0,
    outputCount: manifest?.outputCount || manifest?.outputs?.length || 0,
    imageCount: summary.imageCount || manifest?.outputCount || 0,
    tileCount: summary.tileCount || 0,
    collageCount: summary.collageCount || 0,
    totalBytes: summary.totalBytes || 0,
    tool: manifest?.tool || null,
  };
}

async function readExtractionRecord(appLike, outputDir) {
  const canonical = await getManagedOutputDir(appLike, outputDir);
  const manifestPath = path.join(canonical, MANIFEST_FILE_NAME);
  const manifest = await readJsonFile(manifestPath);
  const parsedOutput = await parseExtractionOutput(canonical);
  const output = mergeOutputHashes(parsedOutput, manifest);
  const inputSummary = summarizeInputFiles(manifest.inputs || []);
  return {
    ok: true,
    history: true,
    outputDir: canonical,
    sourcePaths: manifest.sourcePaths || [],
    output,
    manifest,
    manifestPath,
    preflight: {
      ready: true,
      sourcePaths: manifest.sourcePaths || [],
      files: manifest.inputs || [],
      summary: inputSummary,
      warnings: manifest.warnings || [],
      errors: manifest.errors || [],
    },
  };
}

function buildPackageReadme(record, packageDir, copiedImageCount) {
  const manifest = record.manifest || {};
  const summary = record.output?.summary || manifest.outputSummary || {};
  const inputs = manifest.inputs || [];
  const sourcePaths = manifest.sourcePaths || record.sourcePaths || [];
  const commandLine = manifest.invocation?.commandLine || "";
  return [
    "IRFlow RDP Bitmap Cache evidence package",
    "",
    "Purpose:",
    "This package contains recovered RDP Bitmap Cache images and extraction metadata generated by IRFlow Timeline.",
    "",
    `Package directory: ${packageDir}`,
    `Extraction output: ${record.outputDir || ""}`,
    `Started: ${manifest.startedAt || ""}`,
    `Completed: ${manifest.completedAt || ""}`,
    `Snapshot hash: ${manifest.snapshotHash || ""}`,
    `Tool: ${manifest.tool?.name || "bmc-tools"}`,
    `Tool path: ${manifest.tool?.path || ""}`,
    "",
    "Source paths:",
    ...(sourcePaths.length ? sourcePaths.map((sourcePath) => `- ${sourcePath}`) : ["- none recorded"]),
    "",
    "Counts:",
    `- Input cache files: ${manifest.inputCount || inputs.length || 0}`,
    `- Recovered images copied: ${copiedImageCount}`,
    `- Total images recorded: ${summary.imageCount || manifest.outputCount || 0}`,
    `- Tiles: ${summary.tileCount || 0}`,
    `- Collages: ${summary.collageCount || 0}`,
    "",
    "Files:",
    "- manifest.json: original extraction manifest with input/output hashes and command metadata",
    "- input-files.csv: cache file metadata and hashes recorded during extraction",
    "- output-images.csv: recovered image metadata and hashes",
    "- images/: copied recovered bitmap/cache output images, preserving relative paths where available",
    "- bmc-tools-command.txt: exact command line used when recorded",
    "",
    "Evidence note:",
    "Original cache source files are not copied into this package. Their paths and SHA-256 hashes are recorded in manifest.json and input-files.csv.",
    "",
    commandLine ? `Command line:\n${commandLine}\n` : "",
  ].filter((line) => line !== null && line !== undefined).join("\n");
}

async function exportExtractionPackage(appLike, authorizer, outputDir) {
  const record = await readExtractionRecord(appLike, outputDir);
  const packageDir = makePackageDir(record, appLike);
  await fsp.mkdir(packageDir, { recursive: true });

  let copiedBytes = 0;
  const manifestDest = path.join(packageDir, MANIFEST_FILE_NAME);
  copiedBytes += await copyFileIntoPackage(record.manifestPath, manifestDest);

  const imagesDir = path.join(packageDir, "images");
  const copiedImages = [];
  for (const image of record.output?.images || []) {
    if (!image?.path) continue;
    try {
      const canonicalImage = fs.realpathSync.native(image.path);
      if (!isPathInside(canonicalImage, record.outputDir)) continue;
      const relativePath = image.relativePath || image.name || path.basename(canonicalImage);
      const dest = path.join(imagesDir, ...relativePath.split(/[\\/]+/).map((part) => safePackageName(part, "image")));
      copiedBytes += await copyFileIntoPackage(canonicalImage, dest);
      copiedImages.push({ ...image, packagedAs: path.relative(packageDir, dest) });
    } catch {
      copiedImages.push({ ...image, packagedAs: null, packageError: "Could not copy image from extraction output" });
    }
  }

  await writeCsv(path.join(packageDir, "input-files.csv"), record.manifest?.inputs || [], [
    { label: "path", value: "path" },
    { label: "name", value: "name" },
    { label: "kind", value: "kind" },
    { label: "size", value: "size" },
    { label: "user", value: "user" },
    { label: "directory", value: "directory" },
    { label: "sha256", value: "sha256" },
    { label: "hashError", value: "hashError" },
  ]);
  await writeCsv(path.join(packageDir, "output-images.csv"), copiedImages, [
    { label: "relativePath", value: "relativePath" },
    { label: "name", value: "name" },
    { label: "kind", value: "kind" },
    { label: "tileIndex", value: "tileIndex" },
    { label: "size", value: "size" },
    { label: "modifiedAt", value: "modifiedAt" },
    { label: "sha256", value: "sha256" },
    { label: "packagedAs", value: "packagedAs" },
    { label: "packageError", value: "packageError" },
  ]);

  if (record.manifest?.invocation?.commandLine) {
    await fsp.writeFile(path.join(packageDir, "bmc-tools-command.txt"), `${record.manifest.invocation.commandLine}\n`, "utf8");
  }
  await fsp.writeFile(path.join(packageDir, "README.txt"), buildPackageReadme(record, packageDir, copiedImages.filter((image) => image.packagedAs).length), "utf8");

  const packageBytes = await packageFileSize(packageDir);
  authorizer.authorize(PACKAGE_SCOPE, packageDir, {
    recursive: true,
    appManaged: true,
    label: "RDP Bitmap Cache evidence package",
  });
  authorizer.authorize(OUTPUT_SCOPE, packageDir, {
    recursive: true,
    appManaged: true,
    label: "RDP Bitmap Cache evidence package",
  });
  return {
    ok: true,
    packageDir,
    sourceOutputDir: record.outputDir,
    imageCount: copiedImages.filter((image) => image.packagedAs).length,
    inputCount: record.manifest?.inputCount || record.manifest?.inputs?.length || 0,
    bytesCopied: copiedBytes,
    packageBytes,
    manifestPath: manifestDest,
  };
}

async function listExtractionHistory(appLike, limit = 20) {
  const root = getExtractionRoot(appLike);
  await fsp.mkdir(root, { recursive: true });
  const entries = await fsp.readdir(root, { withFileTypes: true }).catch(() => []);
  const records = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const outputDir = path.join(root, entry.name);
    const manifestPath = path.join(outputDir, MANIFEST_FILE_NAME);
    try {
      const [manifest, manifestStat] = await Promise.all([readJsonFile(manifestPath), fsp.stat(manifestPath)]);
      records.push(historyRecordFromManifest(outputDir, manifest, manifestStat));
    } catch {
      continue;
    }
  }
  records.sort((a, b) => String(b.completedAt || b.modifiedAt || "").localeCompare(String(a.completedAt || a.modifiedAt || "")));
  return records.slice(0, Math.max(1, Math.min(Number(limit) || 20, 100)));
}

function createRdpBitmapHandlers({
  authorizer = new PathAuthorizer(),
  activeExtractions = new Map(),
  appLike = electron.app,
  dialog = electron.dialog,
  shell = electron.shell,
  activeWindow = null,
  safeSend = () => {},
} = {}) {
  const getWindow = () => (typeof activeWindow === "function" ? activeWindow() : activeWindow);

  return {
    async selectSource() {
      if (!dialog?.showOpenDialog) throw new Error("Native file selection is unavailable.");
      const result = await dialog.showOpenDialog(getWindow(), openDialogOptions({
        title: "Select RDP Bitmap Cache Source",
        buttonLabel: "Select Cache Source",
        properties: ["openFile", "openDirectory", "multiSelections"],
        prefer: "file",
        filters: [
          { name: "RDP Bitmap Cache", extensions: ["bmc", "bin"] },
          { name: "All Files", extensions: ["*"] },
        ],
      }));
      if (result.canceled || !result.filePaths?.length) return null;
      const grants = authorizeSelectedSources(authorizer, result.filePaths);
      const preflight = await preflightSources(authorizer, result.filePaths);
      return {
        paths: grants.map((grant) => grant.path),
        grants,
        preflight,
      };
    },

    // Cache folder counterpart (e.g. …\Terminal Server Client\Cache) for platforms where
    // one dialog cannot offer both files and directories.
    async selectSourceFolder() {
      if (!dialog?.showOpenDialog) throw new Error("Native file selection is unavailable.");
      const result = await dialog.showOpenDialog(getWindow(), openDialogOptions({
        title: "Select RDP Bitmap Cache Folder",
        buttonLabel: "Select Cache Folder",
        message: "Choose a Terminal Server Client cache folder containing bcache*.bmc / cache*.bin files.",
        properties: ["openDirectory", "multiSelections"],
      }));
      if (result.canceled || !result.filePaths?.length) return null;
      const grants = authorizeSelectedSources(authorizer, result.filePaths);
      const preflight = await preflightSources(authorizer, result.filePaths);
      return {
        paths: grants.map((grant) => grant.path),
        grants,
        preflight,
      };
    },

    async selectTool() {
      if (!dialog?.showOpenDialog) throw new Error("Native file selection is unavailable.");
      const result = await dialog.showOpenDialog(getWindow(), openDialogOptions({
        title: "Select bmc-tools",
        buttonLabel: "Select bmc-tools",
        properties: ["openFile"],
        filters: [
          { name: "bmc-tools", extensions: ["py", "exe", "*"] },
        ],
      }));
      if (result.canceled || !result.filePaths?.length) return null;
      const grant = authorizer.authorize(TOOL_SCOPE, result.filePaths[0], {
        recursive: false,
        label: "bmc-tools executable or Python script",
      });
      return getToolStatus({ appLike, selectedToolPath: grant.path });
    },

    toolStatus() {
      return getToolStatus({ appLike });
    },

    async listHistory(_event, { limit } = {}) {
      const records = await listExtractionHistory(appLike, limit);
      for (const record of records) {
        try {
          authorizer.authorize(OUTPUT_SCOPE, record.outputDir, {
            recursive: true,
            appManaged: true,
            label: "RDP Bitmap Cache extraction output",
          });
        } catch {}
      }
      return { ok: true, root: getExtractionRoot(appLike), records };
    },

    async loadHistory(_event, { outputDir } = {}) {
      const record = await readExtractionRecord(appLike, outputDir);
      authorizer.authorize(OUTPUT_SCOPE, record.outputDir, {
        recursive: true,
        appManaged: true,
        label: "RDP Bitmap Cache extraction output",
      });
      return record;
    },

    async exportPackage(_event, { outputDir } = {}) {
      if (!outputDir) throw new Error("RDP Bitmap Cache extraction output is required before exporting an evidence package.");
      return exportExtractionPackage(appLike, authorizer, outputDir);
    },

    preflight(_event, { paths, options } = {}) {
      return preflightSources(authorizer, paths, options || {});
    },

    async extract(_event, { paths, options } = {}) {
      const jobId = options?.jobId || randomId("rdp-bitmap");
      const sourcePaths = assertAuthorizedSources(authorizer, paths);
      const preflight = await preflightSources(authorizer, sourcePaths, options?.scanOptions || {});
      if (!preflight.ready) {
        return {
          ok: false,
          jobId,
          code: "NO_RDP_BITMAP_CACHE_FILES",
          error: "No RDP Bitmap Cache files were found in the selected source.",
          preflight,
        };
      }
      if (sourcePaths.length !== 1) {
        return {
          ok: false,
          jobId,
          code: "MULTIPLE_SOURCES_UNSUPPORTED",
          error: "Extraction expects one selected cache file or one parent folder. Select a parent folder to process multiple cache files together.",
          preflight,
        };
      }

      const tool = resolveToolPath(authorizer, options || {}, appLike);
      if (!tool.installed) {
        return {
          ok: false,
          jobId,
          code: "BMC_TOOLS_NOT_CONFIGURED",
          error: "bmc-tools is not bundled or selected yet. Select a bmc-tools executable/script before extracting cache images.",
          tool,
          preflight,
        };
      }
      if (tool.mode === "python-script" && !tool.pythonAvailable) {
        return {
          ok: false,
          jobId,
          code: "PYTHON_NOT_FOUND",
          error: "bmc-tools is a Python script, but no Python interpreter (python3 or python) was found on PATH. Install Python 3 (e.g. Xcode Command Line Tools or python.org) or select a standalone bmc-tools binary.",
          tool,
          preflight,
        };
      }

      const outputDir = await ensureOutputDir(authorizer, sourcePaths, appLike);
      const controller = new AbortController();
      activeExtractions.set(jobId, controller);
      safeSend("rdp-bitmap-progress", {
        jobId,
        phase: "preflight",
        text: `Found ${preflight.summary.fileCount} cache files`,
        summary: preflight.summary,
      });

      try {
        const result = await runBmcTools({
          ...options,
          toolPath: tool.toolPath,
          pythonPath: tool.pythonInterpreter || "python3",
          sourcePath: sourcePaths[0],
          destPath: outputDir,
          cacheFiles: preflight.files,
          signal: controller.signal,
          onProgress: (progress) => safeSend("rdp-bitmap-progress", { jobId, ...progress }),
        });
        return {
          ...result,
          jobId,
          sourcePaths,
          outputDir,
          tool,
          preflight,
        };
      } catch (err) {
        return {
          ok: false,
          jobId,
          cancelled: !!err.cancelled,
          error: err.message,
          sourcePaths,
          outputDir,
          tool,
          preflight,
        };
      } finally {
        activeExtractions.delete(jobId);
      }
    },

    cancel(_event, { jobId } = {}) {
      if (!jobId || !activeExtractions.has(jobId)) {
        return { ok: false, cancelled: false, error: "No active RDP Bitmap Cache extraction matched that job ID." };
      }
      activeExtractions.get(jobId).abort();
      return { ok: true, cancelled: true };
    },

    async openOutputFolder(_event, { outputDir } = {}) {
      const canonical = authorizer.assertAuthorized(OUTPUT_SCOPE, outputDir);
      if (!shell?.openPath) throw new Error("Native folder opening is unavailable.");
      const error = await shell.openPath(canonical);
      return { ok: !error, error: error || null, outputDir: canonical };
    },

    async previewImage(_event, { imagePath, options } = {}) {
      return createImagePreview(appLike, authorizer, imagePath, options || {});
    },
  };
}

module.exports = function registerRdpBitmapCacheHandlers(safeHandle, safeSend, context = {}) {
  const handlers = createRdpBitmapHandlers({
    safeSend,
    appLike: context.app || electron.app,
    dialog: context.dialog || electron.dialog,
    shell: context.shell || electron.shell,
    activeWindow: context._activeWindow || context.mainWindow || null,
  });

  safeHandle("rdp-bitmap-select-source", handlers.selectSource);
  safeHandle("rdp-bitmap-select-source-folder", handlers.selectSourceFolder);
  safeHandle("rdp-bitmap-select-tool", handlers.selectTool);
  safeHandle("rdp-bitmap-tool-status", handlers.toolStatus);
  safeHandle("rdp-bitmap-list-history", handlers.listHistory);
  safeHandle("rdp-bitmap-load-history", handlers.loadHistory);
  safeHandle("rdp-bitmap-export-package", handlers.exportPackage);
  safeHandle("rdp-bitmap-preflight", handlers.preflight);
  safeHandle("rdp-bitmap-extract", handlers.extract);
  safeHandle("rdp-bitmap-cancel", handlers.cancel);
  safeHandle("rdp-bitmap-open-output-folder", handlers.openOutputFolder);
  safeHandle("rdp-bitmap-preview-image", handlers.previewImage);
};

module.exports._private = {
  SOURCE_SCOPE,
  TOOL_SCOPE,
  OUTPUT_SCOPE,
  PACKAGE_SCOPE,
  buildPreflightResponse,
  createRdpBitmapHandlers,
  getExtractionRoot,
  getPackageRoot,
  getPreviewRoot,
  getToolStatus,
  isBundledToolPath,
  resolveToolPath,
  createImagePreview,
  exportExtractionPackage,
  listExtractionHistory,
  makeOutputDir,
};
