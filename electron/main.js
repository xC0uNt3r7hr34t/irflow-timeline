/**
 * main.js — Electron main process for IRFlow Timeline (Windows build)
 *
 * Windows-specific changes from macOS original:
 *  - BrowserWindow: removed titleBarStyle/trafficLightPosition/vibrancy (macOS only);
 *    replaced with frame:true, standard Windows chrome.
 *  - app.on("open-file") removed — macOS-only; Windows file association is handled
 *    via process.argv / second-instance instead.
 *  - second-instance handler added for single-instance enforcement + argv file opens.
 *  - app.requestSingleInstanceLock() called before createWindow.
 *  - macOS-only menu items removed: "services", "hide", "hideOthers", "unhide",
 *    "front", "zoom" (Window submenu), "about" (moved to Help).
 *  - Window submenu simplified for Windows (minimize, separator, close).
 *  - "App" top-level menu removed; Quit/About moved into File/Help menus.
 *  - updater "not-configured" message updated to reference latest-win.yml.
 *  - Log path uses app.getPath("userData") instead of os.homedir() to stay
 *    inside the user's AppData\Roaming folder on Windows.
 *  - All path.join() calls already use Node's cross-platform path module — no changes needed.
 *  - PDF export: loadURL with data: URI works on Windows; no change needed.
 */

const { app, BrowserWindow, Menu, dialog, ipcMain, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const https = require("https");
const TimelineDB = require("./db");
const { parseFile, getXLSXSheets, getSQLiteTables, isSQLiteFile, validatePlasoFile, extractResidentData } = require("./parser");
const { createUpdateController } = require("./updater");

// Raise V8 heap limit to 16 GB for large forensic files.
const v8 = require("v8");
v8.setFlagsFromString("--max-old-space-size=16384");
app.commandLine.appendSwitch("js-flags", "--max-old-space-size=16384");

let mainWindow;
const db = new TimelineDB();
let tabCounter = 0;
const _tabMeta = new Map(); // tabId -> { filePath, sourceFormat }

// ── Recent files persistence ──────────────────────────────────────────────────
const RECENT_FILES_MAX = 10;
const _recentFilesPath = path.join(app.getPath("userData"), "recent-files.json");

function _loadRecentFiles() {
  try {
    if (fs.existsSync(_recentFilesPath))
      return JSON.parse(fs.readFileSync(_recentFilesPath, "utf8")).slice(0, RECENT_FILES_MAX);
  } catch {}
  return [];
}

function _saveRecentFiles(files) {
  try { fs.writeFileSync(_recentFilesPath, JSON.stringify(files), "utf8"); } catch {}
}

let _menuRebuildTimer = null;
function addRecentFile(filePath) {
  const files = _loadRecentFiles().filter((f) => f !== filePath);
  files.unshift(filePath);
  if (files.length > RECENT_FILES_MAX) files.length = RECENT_FILES_MAX;
  _saveRecentFiles(files);
  if (_menuRebuildTimer) clearTimeout(_menuRebuildTimer);
  _menuRebuildTimer = setTimeout(() => { _menuRebuildTimer = null; _rebuildMenu(); }, 500);
  safeSend("recent-files-updated", files);
}

// ── Debug trace logger ────────────────────────────────────────────────────────
const { dbg, debugLogPath } = require("./logger");
dbg("INIT", `IRFlow Timeline starting (Windows), debug log: ${debugLogPath}`);

// ── Global crash guards ───────────────────────────────────────────────────────
process.on("uncaughtException", (err) => {
  dbg("CRASH", "Uncaught exception", { message: err?.message, stack: err?.stack });
  try {
    dialog.showErrorBox(
      "IRFlow Timeline Error",
      `An unexpected error occurred:\n\n${err.message}\n\nThe application will attempt to continue.`
    );
  } catch (_) {}
});

process.on("unhandledRejection", (reason) => {
  dbg("CRASH", "Unhandled rejection", { message: reason?.message || String(reason), stack: reason?.stack });
});

// ── Safe IPC helpers ──────────────────────────────────────────────────────────
function safeHandle(channel, handler) {
  ipcMain.handle(channel, async (event, ...args) => {
    dbg("IPC", `→ ${channel}`, args?.length > 0
      ? { argKeys: typeof args[0] === "object" && args[0] ? Object.keys(args[0]) : undefined }
      : undefined);
    try {
      const result = await handler(event, ...args);
      dbg("IPC", `← ${channel} OK`);
      return result;
    } catch (err) {
      dbg("IPC", `← ${channel} ERROR`, { message: err?.message, stack: err?.stack });
      return { __ipcError: true, message: err?.message || "Unknown error" };
    }
  });
}

function _activeWindow() {
  return (mainWindow && !mainWindow.isDestroyed()) ? mainWindow : null;
}

function safeSend(channel, data) {
  try {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
      mainWindow.webContents.send(channel, data);
    }
  } catch (e) { /* window closed mid-send */ }
}

const updateController = createUpdateController({
  getWindow: _activeWindow,
  sendStatus: (payload) => safeSend("updater-state", payload),
});

// ── Import queue ──────────────────────────────────────────────────────────────
const _importQueue = [];
let _importRunning = false;
const _pendingIndexTabs = [];

function enqueueImport(filePath, opts) {
  let fileName = opts?.fileName;
  if (!fileName) { try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); } }
  let fileSize = 0; try { fileSize = fs.statSync(filePath).size; } catch {}
  _importQueue.push({ filePath, fileName, fileSize, ...opts });
  if (!opts?.skipRecent) addRecentFile(filePath);
  _broadcastQueue();
  _processQueue();
}

function _broadcastQueue() {
  const pending = _importQueue.map((q) => ({ fileName: q.fileName, fileSize: q.fileSize }));
  safeSend("import-queue", { pending, running: _importRunning });
}

async function _processQueue() {
  if (_importRunning || _importQueue.length === 0) return;
  _importRunning = true;

  while (_importQueue.length > 0) {
    const item = _importQueue.shift();
    _broadcastQueue();

    const memBefore = process.memoryUsage();
    dbg("QUEUE", `Starting import: ${item.fileName}`, {
      heapMB: Math.round(memBefore.heapUsed / 1048576),
      rssMB: Math.round(memBefore.rss / 1048576),
      queueRemaining: _importQueue.length,
    });

    try {
      await importFile(item.filePath, item.tabId, item.sheetName, item.tableName, item.fileName);
    } catch (err) {
      dbg("QUEUE", `importFile failed for ${item.fileName}`, { error: err?.message });
      safeSend("import-error", {
        tabId: item.tabId || null,
        fileName: item.fileName,
        error: err?.message || "Import failed",
      });
    }
    _broadcastQueue();

    if (_importQueue.length > 0) {
      await new Promise((r) => setTimeout(r, 100));
      if (global.gc) { try { global.gc(); } catch {} }
    }
  }

  _importRunning = false;
  _broadcastQueue();
  _buildDeferredIndexes();
}

function _buildDeferredIndexes() {
  if (_pendingIndexTabs.length === 0) return;
  const tabs = _pendingIndexTabs.splice(0);
  dbg("QUEUE", `Building deferred indexes for ${tabs.length} tabs`);

  const MAX_CONCURRENT = 2;
  let active = 0;
  let idx = 0;

  const buildNext = () => {
    while (active < MAX_CONCURRENT && idx < tabs.length) {
      const tabId = tabs[idx++];
      active++;
      db.buildIndexesAsync(tabId, (progress) => {
        safeSend("index-progress", { tabId, ...progress });
      }).then(() => {
        const tabInfo = _tabMeta.get(tabId);
        if (tabInfo?.sourceFormat === "raw-mft") {
          for (const [tid, tmeta] of _tabMeta) {
            if (tmeta.sourceFormat === "raw-usnjrnl") {
              const reResolve = db.resolveUsnPaths(tid, tabId);
              if (reResolve.resolved > 0) {
                safeSend("usn-paths-updated", { tabId: tid, resolveStats: reResolve });
              }
            }
          }
        }
        return db.buildFtsAsync(tabId, (progress) => {
          safeSend("fts-progress", { tabId, ...progress });
        });
      }).catch((err) => {
        console.error(`Index/FTS build failed for tab ${tabId}:`, err?.message || err);
        safeSend("fts-progress", { tabId, indexed: 0, total: 0, done: true, error: err?.message });
      }).finally(() => {
        active--;
        buildNext();
      });
    }
  };
  buildNext();
}

// ── Windows lifecycle ─────────────────────────────────────────────────────────
// On Windows (and Linux) all windows closing should quit the app.
app.on("window-all-closed", () => {
  db.closeAll();
  app.quit();
});

// No macOS "activate" / re-open behaviour needed on Windows.

app.on("before-quit", () => {
  db.closeAll();
  try { if (_vtCacheDb) { _vtCacheDb.close(); _vtCacheDb = null; } } catch {}
});

// ── Single-instance lock + Windows file-open via argv ─────────────────────────
// On Windows, opening a file association passes the path as argv[1] (packaged)
// or argv[2] (dev, because argv[1] is the entry script).
// The second-instance event fires when a user double-clicks a file while the
// app is already running — we grab the path from the new instance's argv.

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on("second-instance", (_event, argv, _workingDir) => {
    // Bring existing window to front
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
    // Extract the file path from the second instance's command line.
    const filePath = _extractFileArgFromArgv(argv);
    if (filePath && fs.existsSync(filePath)) {
      enqueueImport(filePath);
    }
  });
}

/**
 * Return the first non-flag argument from argv that looks like a file path,
 * skipping Electron internals (--switches, the app path, "." etc.).
 */
function _extractFileArgFromArgv(argv) {
  // argv[0] = electron / exe, argv[1] = app path in dev / first real arg in packaged
  const candidates = argv.slice(app.isPackaged ? 1 : 2);
  for (const arg of candidates) {
    if (!arg.startsWith("-") && arg !== "." && path.isAbsolute(arg)) {
      return arg;
    }
  }
  return null;
}

// ── Window ────────────────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 950,
    minWidth: 900,
    minHeight: 600,
    // Windows: use standard frame (no macOS traffic lights / vibrancy).
    frame: true,
    backgroundColor: "#0f1114",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
    show: false,
  });

  const isDev = !app.isPackaged;
  if (isDev) {
    mainWindow.loadURL("http://localhost:5173");
  } else {
    mainWindow.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();

    // Check if a file path was passed via argv on first launch
    const fileArg = _extractFileArgFromArgv(process.argv);
    if (fileArg && fs.existsSync(fileArg)) {
      enqueueImport(fileArg);
    }

    updateController.scheduleStartupCheck();
  });

  mainWindow.on("closed", () => { mainWindow = null; });

  // Forward right-click coordinates to renderer via IPC.
  mainWindow.webContents.on("context-menu", (event, params) => {
    event.preventDefault();
    safeSend("native-context-menu", { x: params.x, y: params.y });
  });

  // Route window.open(_blank) calls to the system browser via shell.openExternal.
  // Required on Windows with contextIsolation:true — without this, window.open(_blank)
  // is silently blocked and VT links, MITRE links, website links etc. never open.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://") || url.startsWith("http://")) {
      shell.openExternal(url).catch(() => {});
    }
    return { action: "deny" };
  });

  buildMenu();
}

// ── File import ───────────────────────────────────────────────────────────────
async function importFile(filePath, preTabId, preSheetName, preTableName, preFileName) {
  const tabId = preTabId || `tab_${++tabCounter}_${Date.now()}`;
  let fileName = preFileName;
  if (!fileName) { try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); } }
  const ext = path.extname(filePath).toLowerCase();
  dbg("IMPORT", `importFile called`, { filePath, tabId, ext, preSheetName, preTableName });

  let fileSize = 0;
  try { fileSize = fs.statSync(filePath).size; } catch {}
  const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024 * 1024;

  if ((ext === ".xlsx" || ext === ".xlsm") && fileSize > LARGE_FILE_THRESHOLD) {
    const sizeGB = (fileSize / (1024 ** 3)).toFixed(1);
    const limitGB = (LARGE_FILE_THRESHOLD / (1024 ** 3)).toFixed(0);
    if (mainWindow) {
      await dialog.showMessageBox(_activeWindow(), {
        type: "error",
        title: "XLSX Too Large",
        message: `This workbook is ${sizeGB} GB`,
        detail: `XLSX/XLSM imports above ${limitGB} GB are not supported in this build. Convert the workbook to CSV and import the CSV instead.`,
        buttons: ["OK"],
      });
    }
    dbg("IMPORT", `Blocked oversized XLSX import`, { filePath, sizeGB, limitGB });
    safeSend("import-error", {
      tabId,
      fileName,
      error: `XLSX/XLSM imports above ${limitGB} GB are not supported — convert to CSV first`,
    });
    return;
  }

  if (fileSize > LARGE_FILE_THRESHOLD && mainWindow) {
    const sizeGB = (fileSize / (1024 ** 3)).toFixed(1);
    const ramGB = Math.round(os.totalmem() / (1024 ** 3));
    const { response } = await dialog.showMessageBox(_activeWindow(), {
      type: "warning",
      title: "Large File Warning",
      message: `This file is ${sizeGB} GB`,
      detail: `Importing very large files requires significant memory and may take a long time. The application may become unresponsive or crash.\n\nSystem RAM: ${ramGB} GB\n\nFor Plaso files this large, consider using psort to export a filtered CSV first.`,
      buttons: ["Import Anyway", "Cancel"],
      defaultId: 1,
      cancelId: 1,
    });
    if (response === 1) {
      dbg("IMPORT", `User cancelled large file import`, { filePath, sizeGB });
      safeSend("import-error", { tabId, fileName, error: `Import cancelled — file is ${sizeGB} GB` });
      return;
    }
    dbg("IMPORT", `User chose to proceed with large file`, { filePath, sizeGB, ramGB });
  }

  let sheetName = preSheetName;
  if (sheetName && (ext === ".xlsx" || ext === ".xlsm") && !Number.isFinite(Number(sheetName))) {
    try {
      const sheets = await getXLSXSheets(filePath);
      const matched = sheets.find((s) => s.name === sheetName);
      if (matched) sheetName = matched.id;
    } catch (e) {
      dbg("IMPORT", `sheet name remap failed`, { filePath, sheetName, error: e.message });
    }
  }
  if (!sheetName && (ext === ".xlsx" || ext === ".xls" || ext === ".xlsm")) {
    try {
      dbg("IMPORT", `getXLSXSheets calling...`, { filePath });
      const sheets = await getXLSXSheets(filePath);
      dbg("IMPORT", `getXLSXSheets returned`, { sheetCount: sheets.length, sheets: sheets.map((s) => s.name) });
      if (sheets.length > 1) {
        safeSend("sheet-selection", { tabId, fileName, filePath, sheets });
        return;
      }
    } catch (e) {
      dbg("IMPORT", `getXLSXSheets failed`, { error: e.message, stack: e.stack });
    }
  }

  let tableName = preTableName;
  if (!tableName && (ext === ".sqlite" || ext === ".db" || isSQLiteFile(filePath))) {
    try {
      const check = validatePlasoFile(filePath);
      if (!check.valid) {
        dbg("IMPORT", `getSQLiteTables calling...`, { filePath });
        const tables = await getSQLiteTables(filePath);
        dbg("IMPORT", `getSQLiteTables returned`, { tableCount: tables.length, tables: tables.map((t) => t.name) });
        if (tables.length === 0) {
          safeSend("import-error", { tabId, fileName, error: "No importable tables found in SQLite database" });
          return;
        }
        if (tables.length > 1) {
          safeSend("table-selection", { tabId, fileName, filePath, tables });
          return;
        }
        tableName = tables[0].name;
      }
    } catch (e) {
      dbg("IMPORT", `getSQLiteTables failed`, { error: e.message, stack: e.stack });
      safeSend("import-error", { tabId, fileName, error: e.message || "Failed to read SQLite database" });
      return;
    }
  }

  dbg("IMPORT", `calling startImport`, { tabId, sheetName, tableName });
  await startImport(filePath, tabId, fileName, sheetName, fileSize, tableName);
}

async function startImport(filePath, tabId, fileName, sheetName, preFileSize, tableName) {
  dbg("IMPORT", `startImport begin`, { filePath, tabId, fileName, sheetName, tableName });
  let fileSize = preFileSize || 0;
  if (!fileSize) { try { fileSize = fs.statSync(filePath).size; } catch {} }

  safeSend("import-start", { tabId, fileName, filePath, fileSize });

  try {
    dbg("IMPORT", `calling parseFile...`);
    let _lastMemCheck = 0;
    const result = await parseFile(filePath, tabId, db, (rows, bytesRead, totalBytes) => {
      safeSend("import-progress", {
        tabId,
        rowsImported: rows,
        bytesRead,
        totalBytes,
        percent: totalBytes > 0 ? Math.round((bytesRead / totalBytes) * 100) : 0,
      });

      const now = Date.now();
      if (now - _lastMemCheck > 30000) {
        _lastMemCheck = now;
        const mem = process.memoryUsage();
        const heapGB = mem.heapUsed / (1024 ** 3);
        const rssGB = mem.rss / (1024 ** 3);
        dbg("IMPORT", `Memory check during import`, {
          heapGB: heapGB.toFixed(2), rssGB: rssGB.toFixed(2),
          rowsImported: rows, percent: totalBytes > 0 ? Math.round((bytesRead / totalBytes) * 100) : 0,
        });
        if (heapGB > 12) {
          dbg("IMPORT", `WARNING: heap usage ${heapGB.toFixed(1)}GB approaching 16GB limit`);
          safeSend("import-memory-warning", { tabId, heapGB: heapGB.toFixed(1), rssGB: rssGB.toFixed(1) });
        }
      }
    }, sheetName, fileSize, tableName);
    dbg("IMPORT", `parseFile complete`, { headers: result.headers?.length, rowCount: result.rowCount, tsColumns: result.tsColumns?.length });

    _tabMeta.set(tabId, { filePath, sourceFormat: result.sourceFormat || null });

    let resolveStats = null;
    if (result.sourceFormat === "raw-usnjrnl") {
      let mftTabId = null;
      for (const [tid, tmeta] of _tabMeta) {
        if (tmeta.sourceFormat === "raw-mft") { mftTabId = tid; break; }
      }
      dbg("IMPORT", `Resolving USN parent paths (rewind)`, { mftAvailable: !!mftTabId });
      resolveStats = db.resolveUsnPaths(tabId, mftTabId);
      dbg("IMPORT", `USN path resolution complete`, resolveStats);
    }

    if (result.sourceFormat === "raw-mft") {
      for (const [tid, tmeta] of _tabMeta) {
        if (tmeta.sourceFormat === "raw-usnjrnl") {
          dbg("IMPORT", `Re-resolving USN paths for ${tid} with new MFT data`);
          const reResolve = db.resolveUsnPaths(tid, tabId);
          dbg("IMPORT", `USN re-resolution complete`, reResolve);
          safeSend("usn-paths-updated", { tabId: tid, resolveStats: reResolve });
        }
      }
    }

    dbg("IMPORT", `querying initial rows...`);
    const initialData = db.queryRows(tabId, { offset: 0, limit: 5000, sortCol: null, sortDir: "asc" });
    dbg("IMPORT", `initial rows fetched`, { rowCount: initialData.rows?.length, totalFiltered: initialData.totalFiltered });

    const emptyColumns = db.getEmptyColumns(tabId);
    dbg("IMPORT", `sending import-complete`);

    safeSend("import-complete", {
      tabId,
      fileName,
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
      initialRows: initialData.rows,
      totalFiltered: initialData.totalFiltered,
      emptyColumns,
      sourceFormat: result.sourceFormat || null,
      resolveStats,
      tableName: tableName || null,
    });

    if (_importQueue.length > 0) {
      dbg("IMPORT", `Deferring index/FTS build for ${tabId} (${_importQueue.length} imports queued)`);
      _pendingIndexTabs.push(tabId);
    } else {
      db.buildIndexesAsync(tabId, (progress) => {
        safeSend("index-progress", { tabId, ...progress });
      }).then(() => {
        const tabInfo = _tabMeta.get(tabId);
        if (tabInfo?.sourceFormat === "raw-mft") {
          for (const [tid, tmeta] of _tabMeta) {
            if (tmeta.sourceFormat === "raw-usnjrnl") {
              dbg("IMPORT", `Post-index re-resolving USN paths for ${tid} with MFT ${tabId}`);
              const reResolve = db.resolveUsnPaths(tid, tabId);
              dbg("IMPORT", `USN post-index re-resolution complete`, reResolve);
              if (reResolve.resolved > 0) {
                safeSend("usn-paths-updated", { tabId: tid, resolveStats: reResolve });
              }
            }
          }
        }
        return db.buildFtsAsync(tabId, (progress) => {
          safeSend("fts-progress", { tabId, ...progress });
        });
      }).catch((err) => {
        console.error(`Index/FTS build failed for tab ${tabId}:`, err?.message || err);
        safeSend("fts-progress", { tabId, indexed: 0, total: 0, done: true, error: err?.message });
      });
    }
  } catch (err) {
    dbg("IMPORT", `startImport FAILED`, { error: err.message, stack: err.stack });
    try { db.closeTab(tabId); } catch (_) {}
    safeSend("import-error", { tabId, fileName, error: err.message });
  }
}

// ── IPC Handlers ──────────────────────────────────────────────────────────────

safeHandle("open-file-dialog", async () => {
  const result = await dialog.showOpenDialog(_activeWindow(), {
    properties: ["openFile", "multiSelections"],
    filters: [
      { name: "All Supported Files", extensions: ["*"] },
      { name: "CSV Files", extensions: ["csv", "tsv", "txt", "log"] },
      { name: "Excel Files", extensions: ["xlsx", "xls", "xlsm"] },
      { name: "EVTX Files", extensions: ["evtx"] },
      { name: "Plaso / Timeline Files", extensions: ["plaso", "timeline"] },
      { name: "SQLite Databases", extensions: ["sqlite", "db"] },
      { name: "NTFS Artifacts ($MFT, $J)", extensions: ["mft", "bin"] },
    ],
  });
  if (result.canceled) return null;
  for (const fp of result.filePaths) enqueueImport(fp);
  return true;
});

safeHandle("check-for-updates", async () => updateController.checkForUpdatesFromRenderer());
safeHandle("install-update", async () => updateController.installUpdate());

safeHandle("get-recent-files", () => _loadRecentFiles());

safeHandle("open-recent-file", (event, { filePath }) => {
  if (fs.existsSync(filePath)) {
    enqueueImport(filePath);
    return true;
  }
  const files = _loadRecentFiles().filter((f) => f !== filePath);
  _saveRecentFiles(files);
  _rebuildMenu();
  return { error: "File not found" };
});

safeHandle("clear-recent-files", () => {
  _saveRecentFiles([]);
  _rebuildMenu();
  return true;
});

safeHandle("query-rows", (event, { tabId, options }) => db.queryRows(tabId, options));
safeHandle("toggle-bookmark", (event, { tabId, rowId }) => db.toggleBookmark(tabId, rowId));
safeHandle("set-bookmarks", (event, { tabId, rowIds, add }) => { db.setBookmarks(tabId, rowIds, add); return true; });
safeHandle("get-bookmark-count", (event, { tabId }) => db.getBookmarkCount(tabId));
safeHandle("add-tag", (event, { tabId, rowId, tag }) => { db.addTag(tabId, rowId, tag); return true; });
safeHandle("remove-tag", (event, { tabId, rowId, tag }) => { db.removeTag(tabId, rowId, tag); return true; });
safeHandle("get-all-tags", (event, { tabId }) => db.getAllTags(tabId));
safeHandle("get-all-tag-data", (event, { tabId }) => db.getAllTagData(tabId));
safeHandle("get-rows-by-ids", (event, { tabId, rowIds }) => db.getRowsByIds(tabId, rowIds));
safeHandle("get-bookmarked-ids", (event, { tabId }) => db.getBookmarkedIds(tabId));
safeHandle("bulk-add-tags", (event, { tabId, tagMap }) => { db.bulkAddTags(tabId, tagMap); return true; });

safeHandle("load-ioc-file", async () => {
  const result = await dialog.showOpenDialog(_activeWindow(), {
    properties: ["openFile"],
    filters: [
      { name: "IOC Files", extensions: ["txt", "csv", "ioc", "tsv", "xlsx", "xls"] },
      { name: "All Files", extensions: ["*"] },
    ],
    title: "Open IOC List",
  });
  if (result.canceled || !result.filePaths.length) return null;
  const filePath = result.filePaths[0];
  const fileName = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();

  const IOC_VALUE_HEADERS = new Set([
    "ioc_value", "ioc", "indicator", "value", "observable", "artifact",
    "indicator_value", "observable_value", "ioc_data", "data", "pattern",
  ]);

  function findIocColumn(headerRow) {
    if (!headerRow || headerRow.length === 0) return -1;
    for (let i = 0; i < headerRow.length; i++) {
      const h = String(headerRow[i]).trim().toLowerCase().replace(/[\s-]+/g, "_");
      if (IOC_VALUE_HEADERS.has(h)) return i;
    }
    return -1;
  }

  function looksLikeHeader(row) {
    return row.length > 1 && row.every((c) => {
      const s = String(c).trim();
      return s.length < 30 && /^[a-zA-Z_\s-]+$/.test(s);
    });
  }

  try {
    if (ext === ".xlsx" || ext === ".xls") {
      const XLSX = require("xlsx");
      const wb = XLSX.readFile(filePath);
      const values = [];
      for (const sheetName of wb.SheetNames) {
        const sheet = wb.Sheets[sheetName];
        const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: "" });
        if (rows.length === 0) continue;
        const iocCol = looksLikeHeader(rows[0]) ? findIocColumn(rows[0]) : -1;
        if (iocCol >= 0) {
          for (let r = 1; r < rows.length; r++) {
            const v = String(rows[r][iocCol] || "").trim();
            if (v) values.push(v);
          }
        } else {
          for (const row of rows) {
            for (const cell of row) {
              const v = String(cell).trim();
              if (v) values.push(v);
            }
          }
        }
      }
      return { content: values.join("\n"), fileName };
    }
    let raw = fs.readFileSync(filePath, "utf-8");
    if (ext === ".csv" || ext === ".tsv") {
      const delim = ext === ".tsv" ? "\t" : ",";
      const lines = raw.split(/\r?\n/);
      if (lines.length > 1) {
        const headerCells = lines[0].split(delim).map((c) => c.trim().replace(/^"|"$/g, ""));
        const iocCol = looksLikeHeader(headerCells) ? findIocColumn(headerCells) : -1;
        if (iocCol >= 0) {
          const values = [];
          for (let i = 1; i < lines.length; i++) {
            const cells = lines[i].split(delim).map((c) => c.trim().replace(/^"|"$/g, ""));
            const v = (cells[iocCol] || "").trim();
            if (v) values.push(v);
          }
          raw = values.join("\n");
        } else {
          raw = lines.map((l) => l.split(delim).map((c) => c.trim().replace(/^"|"$/g, "")).join("\n")).join("\n");
        }
      }
    }
    return { content: raw, fileName };
  } catch (e) {
    return { error: e.message };
  }
});

safeHandle("match-iocs", (event, { tabId, iocPatterns, batchSize }) => db.matchIocs(tabId, iocPatterns, batchSize || 200));

safeHandle("close-tab", (event, { tabId }) => {
  const pendingIdx = _pendingIndexTabs.indexOf(tabId);
  if (pendingIdx !== -1) _pendingIndexTabs.splice(pendingIdx, 1);
  try {
    db.closeTab(tabId);
  } finally {
    _tabMeta.delete(tabId);
  }
  return true;
});

safeHandle("get-column-stats", (event, { tabId, colName, options }) => db.getColumnStats(tabId, colName, options));
safeHandle("get-column-unique-values", (event, { tabId, colName, options }) => db.getColumnUniqueValues(tabId, colName, options));
safeHandle("get-empty-columns", (event, { tabId }) => db.getEmptyColumns(tabId));
safeHandle("get-group-values", (event, { tabId, groupCol, options }) => db.getGroupValues(tabId, groupCol, options));

safeHandle("export-filtered", async (event, { tabId, options }) => {
  const result = await dialog.showSaveDialog(_activeWindow(), {
    defaultPath: "filtered_export.csv",
    filters: [
      { name: "CSV (Comma-separated)", extensions: ["csv"] },
      { name: "TSV (Tab-separated)", extensions: ["tsv"] },
      { name: "Excel Workbook (.xlsx)", extensions: ["xlsx"] },
    ],
  });
  if (result.canceled) return false;

  const exportData = db.exportQuery(tabId, options);
  if (!exportData) return false;

  const ext = path.extname(result.filePath).toLowerCase();

  if (ext === ".xlsx") {
    const ExcelJS = require("exceljs");
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Export");

    sheet.addRow(exportData.headers);
    const headerRow = sheet.getRow(1);
    headerRow.font = { bold: true };
    headerRow.eachCell((cell) => {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF161B22" } };
      cell.font = { bold: true, color: { argb: "FF58A6FF" } };
    });

    const colCount = exportData.headers.length;
    const maxLens = new Array(colCount);
    for (let i = 0; i < colCount; i++) maxLens[i] = (exportData.headers[i] || "").length;

    let count = 0;
    try {
      for (const rawRow of exportData.iterator) {
        const values = exportData.safeCols.map((sc, i) => {
          const val = rawRow[sc] ?? "";
          const len = val.length;
          if (len > maxLens[i]) maxLens[i] = len;
          return val;
        });
        sheet.addRow(values);
        count++;
        if (count % 100000 === 0) safeSend("export-progress", { count });
      }
    } catch (e) {
      dbg("MAIN", `XLSX export interrupted after ${count} rows`, { error: e.message });
    }

    sheet.columns.forEach((col, i) => {
      col.width = Math.min(Math.max((maxLens[i] || 8) + 2, 8), 60);
    });

    await workbook.xlsx.writeFile(result.filePath);
    return { count, filePath: result.filePath };
  }

  const delimiter = ext === ".tsv" ? "\t" : ",";
  const writeStream = fs.createWriteStream(result.filePath, { encoding: "utf-8" });
  writeStream.write(exportData.headers.join(delimiter) + "\n");

  let count = 0;
  try {
    for (const rawRow of exportData.iterator) {
      const values = exportData.safeCols.map((sc) => {
        const val = rawRow[sc] ?? "";
        if (delimiter === "\t") {
          return val.includes("\t") || val.includes("\n") ? val.replace(/\t/g, " ").replace(/\n/g, " ") : val;
        }
        return val.includes(",") || val.includes('"') || val.includes("\n")
          ? `"${val.replace(/"/g, '""')}"`
          : val;
      });
      const ok = writeStream.write(values.join(delimiter) + "\n");
      if (!ok) await new Promise((r) => writeStream.once("drain", r));
      count++;
      if (count % 100000 === 0) safeSend("export-progress", { count });
    }
  } catch (e) {
    dbg("MAIN", `CSV/TSV export interrupted after ${count} rows`, { error: e.message });
  }

  await new Promise((resolve, reject) => {
    writeStream.on("error", reject);
    writeStream.on("finish", resolve);
    writeStream.end();
  });
  return { count, filePath: result.filePath };
});

safeHandle("extract-resident-data", async (event, { tabId }) => {
  const meta = _tabMeta.get(tabId);
  if (!meta || meta.sourceFormat !== "raw-mft") return { error: "This tab is not a raw MFT file" };
  if (!fs.existsSync(meta.filePath)) return { error: `Original MFT file no longer exists: ${meta.filePath}` };

  const result = await dialog.showOpenDialog(_activeWindow(), {
    title: "Choose output folder for resident data extraction",
    properties: ["openDirectory", "createDirectory"],
    buttonLabel: "Extract Here",
  });
  if (result.canceled || !result.filePaths[0]) return { canceled: true };

  const extractResult = await extractResidentData(meta.filePath, result.filePaths[0], (processed, total) => {
    safeSend("extract-resident-progress", {
      tabId, processed, total,
      percent: total > 0 ? Math.round((processed / total) * 100) : 0,
    });
  });
  return extractResult;
});

safeHandle("analyze-ransomware", (event, { tabId, encryptedExt, ransomNotePattern, noteMatchMode, usnTabId }) => {
  const meta = _tabMeta.get(tabId);
  if (!meta || meta.sourceFormat !== "raw-mft") return { error: "This feature requires a raw MFT tab." };
  let resolvedUsnTabId = null;
  if (usnTabId) {
    const usnMeta = _tabMeta.get(usnTabId);
    if (usnMeta?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId;
  }
  if (!resolvedUsnTabId) {
    for (const [tid, tmeta] of _tabMeta) {
      if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") { resolvedUsnTabId = tid; break; }
    }
  }
  return db.analyzeRansomware(tabId, { encryptedExt, ransomNotePattern, noteMatchMode, usnTabId: resolvedUsnTabId, progressCb: (p) => safeSend("rw-progress", p) });
});

safeHandle("scan-ransomware-extensions", (event, { tabId }) => {
  const meta = _tabMeta.get(tabId);
  if (!meta || meta.sourceFormat !== "raw-mft") return { error: "This feature requires a raw MFT tab." };
  return db.scanRansomwareExtensions(tabId, (p) => safeSend("rw-progress", p));
});

safeHandle("detect-timestomping", (event, { tabId }) => db.detectTimestomping(tabId));

safeHandle("get-file-activity-heatmap", (event, { tabId }) => {
  const meta = _tabMeta.get(tabId);
  if (!meta || meta.sourceFormat !== "raw-mft") return { error: "This feature requires a raw MFT tab." };
  return db.getFileActivityHeatmap(tabId, (p) => safeSend("hm-progress", p));
});

safeHandle("analyze-ads", (event, { tabId }) => db.analyzeADS(tabId));
safeHandle("analyze-usn-journal", (event, { tabId, startTime, endTime, analyses, pathFilter, mftTabId }) => db.analyzeUsnJournal(tabId, { startTime, endTime, analyses, pathFilter, mftTabId }));

safeHandle("save-text-file", async (event, { content, defaultPath, filters }) => {
  const result = await dialog.showSaveDialog(_activeWindow(), { defaultPath, filters });
  if (result.canceled) return null;
  await fsp.writeFile(result.filePath, content, "utf-8");
  return { filePath: result.filePath };
});

safeHandle("export-ransomware-pdf", async (event, { html, defaultName }) => {
  const result = await dialog.showSaveDialog(_activeWindow(), {
    defaultPath: defaultName || "ransomware_report.pdf",
    filters: [{ name: "PDF Document", extensions: ["pdf"] }],
  });
  if (result.canceled) return null;
  const win = new BrowserWindow({ show: false, width: 900, height: 1200, webPreferences: { offscreen: true } });
  try {
    await win.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(html));
    await new Promise((r) => setTimeout(r, 500));
    const pdfBuf = await win.webContents.printToPDF({ printBackground: true, preferCSSPageSize: true, margins: { top: 0, bottom: 0, left: 0, right: 0 } });
    await fsp.writeFile(result.filePath, pdfBuf);
    return { filePath: result.filePath };
  } finally {
    win.destroy();
  }
});

safeHandle("generate-report", async (event, { tabId, fileName, tagColors, vtEnrichment }) => {
  const reportData = db.getReportData(tabId);
  if (!reportData) return { error: "No data available" };

  const result = await dialog.showSaveDialog(_activeWindow(), {
    defaultPath: `${fileName.replace(/\.[^.]+$/, "")}_report.html`,
    filters: [{ name: "HTML Report", extensions: ["html"] }],
  });
  if (result.canceled) return null;

  const html = buildReportHtml(reportData, fileName, tagColors, vtEnrichment);
  await fsp.writeFile(result.filePath, html, "utf-8");
  return { filePath: result.filePath };
});

safeHandle("select-sheet", (event, { filePath, tabId, fileName, sheetName }) => {
  enqueueImport(filePath, { tabId, sheetName, skipRecent: true });
});

safeHandle("select-table", (event, { filePath, tabId, fileName, tableName }) => {
  enqueueImport(filePath, { tabId, tableName, fileName, skipRecent: true });
});

safeHandle("select-tables-all", (event, { filePath, tables }) => {
  let baseName; try { baseName = decodeURIComponent(path.basename(filePath)); } catch { baseName = path.basename(filePath); }
  for (const t of tables) {
    const tabId = `tab_${++tabCounter}_${Date.now()}`;
    enqueueImport(filePath, { tabId, tableName: t.name, fileName: `${baseName} [${t.name}]`, skipRecent: true });
  }
});

safeHandle("get-tab-info", (event, { tabId }) => db.getTabInfo(tabId));
safeHandle("get-fts-status", (event, { tabId }) => db.getFtsStatus(tabId));
safeHandle("search-count", (event, { tabId, searchTerm, searchMode, searchCondition }) => db.searchCount(tabId, searchTerm, searchMode, searchCondition));
safeHandle("get-histogram-data", (event, { tabId, colName, options }) => db.getHistogramData(tabId, colName, options));
safeHandle("get-stacking-data", (event, { tabId, colName, options }) => db.getStackingData(tabId, colName, options));
safeHandle("get-gap-analysis", (event, { tabId, colName, gapThresholdMinutes, options }) => db.getGapAnalysis(tabId, colName, gapThresholdMinutes, options));
safeHandle("get-log-source-coverage", (event, { tabId, sourceCol, tsCol, options }) => db.getLogSourceCoverage(tabId, sourceCol, tsCol, options));
safeHandle("get-burst-analysis", (event, { tabId, colName, windowMinutes, thresholdMultiplier, options }) => db.getBurstAnalysis(tabId, colName, windowMinutes, thresholdMultiplier, options));
safeHandle("get-process-tree", (event, { tabId, options }) => db.getProcessTree(tabId, options));
safeHandle("preview-process-tree", (event, { tabId, options }) => db.previewProcessTree(tabId, options));
safeHandle("get-process-inspector-context", (event, { tabId, options }) => db.getProcessInspectorContext(tabId, options));
safeHandle("preview-lateral-movement", (event, { tabId, options }) => db.previewLateralMovement(tabId, options));
safeHandle("get-lateral-movement", (event, { tabId, options }) => db.getLateralMovement(tabId, options));
safeHandle("preview-persistence-analysis", (event, { tabId, options }) => db.previewPersistenceAnalysis(tabId, options));
safeHandle("get-persistence-analysis", (event, { tabId, options }) => db.getPersistenceAnalysis(tabId, options));
safeHandle("bulk-tag-by-time-range", (event, { tabId, colName, ranges }) => db.bulkTagByTimeRange(tabId, colName, ranges));
safeHandle("bulk-tag-filtered", (event, { tabId, tag, options }) => db.bulkTagFiltered(tabId, tag, options));
safeHandle("bulk-bookmark-filtered", (event, { tabId, add, options }) => db.bulkBookmarkFiltered(tabId, add, options));

safeHandle("merge-tabs", async (event, { mergedTabId, sources }) => {
  try {
    safeSend("import-start", { tabId: mergedTabId, fileName: "Merged Timeline", filePath: "(merged)" });

    const result = db.mergeTabs(mergedTabId, sources, (progress) => {
      safeSend("import-progress", {
        tabId: mergedTabId,
        rowsImported: progress.current,
        bytesRead: progress.current,
        totalBytes: progress.total,
        percent: progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0,
      });
    });

    const initialData = db.queryRows(mergedTabId, { offset: 0, limit: 5000, sortCol: "datetime", sortDir: "asc" });
    const emptyColumns = db.getEmptyColumns(mergedTabId);

    safeSend("import-complete", {
      tabId: mergedTabId,
      fileName: "Merged Timeline",
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
      initialRows: initialData.rows,
      totalFiltered: initialData.totalFiltered,
      emptyColumns,
    });

    db.buildIndexesAsync(mergedTabId, (progress) => {
      safeSend("index-progress", { tabId: mergedTabId, ...progress });
    }).then(() => {
      return db.buildFtsAsync(mergedTabId, (progress) => {
        safeSend("fts-progress", { tabId: mergedTabId, ...progress });
      });
    }).catch((err2) => {
      console.error(`Index/FTS build failed for merged tab ${mergedTabId}:`, err2?.message || err2);
      safeSend("fts-progress", { tabId: mergedTabId, indexed: 0, total: 0, done: true, error: err2?.message });
    });

    return { success: true, rowCount: result.rowCount };
  } catch (err) {
    try { db.closeTab(mergedTabId); } catch (_) {}
    safeSend("import-error", { tabId: mergedTabId, fileName: "Merged Timeline", error: err.message });
    return { success: false, error: err.message };
  }
});

safeHandle("save-session", async (event, { sessionData }) => {
  const result = await dialog.showSaveDialog(_activeWindow(), {
    defaultPath: "session.tle",
    filters: [{ name: "TLE Session", extensions: ["tle"] }],
  });
  if (result.canceled) return null;
  await fsp.writeFile(result.filePath, JSON.stringify(sessionData, null, 2), "utf-8");
  return result.filePath;
});

safeHandle("load-session", async () => {
  const result = await dialog.showOpenDialog(_activeWindow(), {
    properties: ["openFile"],
    filters: [{ name: "TLE Session", extensions: ["tle"] }],
  });
  if (result.canceled || !result.filePaths.length) return null;
  try {
    const raw = fs.readFileSync(result.filePaths[0], "utf-8");
    return JSON.parse(raw);
  } catch (e) {
    return { error: e.message };
  }
});

safeHandle("import-files", async (event, { filePaths }) => {
  for (const fp of filePaths) { if (fs.existsSync(fp)) enqueueImport(fp); }
  return true;
});

safeHandle("import-file-for-restore", async (event, { filePath, sheetName, tableName }) => {
  if (!fs.existsSync(filePath)) return { error: `File not found: ${filePath}` };
  const tabId = `tab_${++tabCounter}_${Date.now()}`;
  let fileName; try { fileName = decodeURIComponent(path.basename(filePath)); } catch { fileName = path.basename(filePath); }
  enqueueImport(filePath, { tabId, sheetName: sheetName || undefined, tableName: tableName || undefined, skipRecent: true });
  return { tabId, fileName };
});

// ── Filter Presets ────────────────────────────────────────────────────────────
const presetsPath = path.join(app.getPath("userData"), "filter-presets.json");
const piAnalystProfilePath = path.join(app.getPath("userData"), "process-inspector-profile.json");

safeHandle("load-filter-presets", () => {
  try { return JSON.parse(fs.readFileSync(presetsPath, "utf-8")); }
  catch { return []; }
});

safeHandle("save-filter-presets", async (event, { presets }) => {
  await fsp.writeFile(presetsPath, JSON.stringify(presets, null, 2));
  return true;
});

safeHandle("load-pi-analyst-profile", () => {
  try {
    const raw = JSON.parse(fs.readFileSync(piAnalystProfilePath, "utf-8"));
    return {
      version: 1,
      suppressions: Array.isArray(raw?.suppressions) ? raw.suppressions : [],
      baselines: Array.isArray(raw?.baselines) ? raw.baselines : [],
      updatedAt: raw?.updatedAt || null,
    };
  } catch {
    return { version: 1, suppressions: [], baselines: [], updatedAt: null };
  }
});

safeHandle("save-pi-analyst-profile", async (event, { profile }) => {
  const next = {
    version: 1,
    suppressions: Array.isArray(profile?.suppressions) ? profile.suppressions : [],
    baselines: Array.isArray(profile?.baselines) ? profile.baselines : [],
    updatedAt: new Date().toISOString(),
  };
  await fsp.writeFile(piAnalystProfilePath, JSON.stringify(next, null, 2));
  return next;
});

// ── VirusTotal API Integration ────────────────────────────────────────────────
const _vtSettingsPath = path.join(app.getPath("userData"), "vt-settings.json");

function _loadVtSettings() {
  try {
    if (fs.existsSync(_vtSettingsPath)) return JSON.parse(fs.readFileSync(_vtSettingsPath, "utf8"));
  } catch {}
  return { apiKey: "", rateLimit: 4, cacheTtlHours: 24 };
}

function _saveVtSettings(settings) {
  try { fs.writeFileSync(_vtSettingsPath, JSON.stringify(settings), "utf8"); } catch {}
}

safeHandle("vt-set-api-key", async (event, { apiKey, rateLimit, cacheTtlHours }) => {
  const settings = _loadVtSettings();
  if (apiKey !== undefined) settings.apiKey = apiKey;
  if (rateLimit !== undefined) settings.rateLimit = rateLimit;
  if (cacheTtlHours !== undefined) settings.cacheTtlHours = cacheTtlHours;
  _saveVtSettings(settings);
  return true;
});

safeHandle("vt-get-api-key", async () => {
  const s = _loadVtSettings();
  const hasKey = !!(s.apiKey && s.apiKey.length > 0);
  const maskedKey = hasKey ? s.apiKey.slice(0, 4) + "..." + s.apiKey.slice(-4) : "";
  return { hasKey, maskedKey, rateLimit: s.rateLimit || 4, cacheTtlHours: s.cacheTtlHours || 24 };
});

safeHandle("vt-clear-api-key", async () => {
  const settings = _loadVtSettings();
  settings.apiKey = "";
  _saveVtSettings(settings);
  return true;
});

let _vtCacheDb = null;
function _openVtCache() {
  if (_vtCacheDb) return _vtCacheDb;
  const Database = require("better-sqlite3");
  const cachePath = path.join(app.getPath("userData"), "vt-cache.db");
  _vtCacheDb = new Database(cachePath);
  _vtCacheDb.pragma("journal_mode = WAL");
  _vtCacheDb.exec(`CREATE TABLE IF NOT EXISTS vt_cache (
    ioc TEXT PRIMARY KEY,
    category TEXT,
    vt_response TEXT,
    fetched_at INTEGER,
    score TEXT
  )`);
  return _vtCacheDb;
}

function _vtCacheKey(ioc, category) {
  if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) return ioc.toLowerCase();
  if (category === "Domain_Name") return ioc.toLowerCase();
  if (/^IPv[46]_Address(:Port)?$/.test(category)) return ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
  if (category === "URL") return ioc.toLowerCase();
  return ioc;
}

function _vtCacheLookup(ioc, category, ttlHours) {
  const cache = _openVtCache();
  const key = _vtCacheKey(ioc, category);
  const row = cache.prepare("SELECT * FROM vt_cache WHERE ioc = ?").get(key);
  if (!row) return null;
  if (Date.now() - row.fetched_at > ttlHours * 3600 * 1000) return null;
  try { return JSON.parse(row.vt_response); } catch { return null; }
}

function _vtCacheStore(ioc, category, result) {
  const cache = _openVtCache();
  const key = _vtCacheKey(ioc, category);
  cache.prepare("INSERT OR REPLACE INTO vt_cache (ioc, category, vt_response, fetched_at, score) VALUES (?, ?, ?, ?, ?)")
    .run(key, category, JSON.stringify(result), Date.now(), result.score || "");
}

function _isPrivateIp(ip) {
  const clean = ip.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
  if (/^10\./.test(clean)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(clean)) return true;
  if (/^192\.168\./.test(clean)) return true;
  if (/^127\./.test(clean)) return true;
  if (clean === "::1" || clean === "0:0:0:0:0:0:0:1") return true;
  return false;
}

function _vtApiRequest(endpoint, apiKey) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "www.virustotal.com",
      path: `/api/v3/${endpoint}`,
      method: "GET",
      headers: { "x-apikey": apiKey, "Accept": "application/json" },
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => { resolve({ statusCode: res.statusCode, headers: res.headers, body: data }); });
    });
    req.on("error", (err) => reject(err));
    req.setTimeout(30000, () => { req.destroy(); reject(new Error("Request timeout")); });
    req.end();
  });
}

function _vtEndpoint(ioc, category) {
  if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) return `files/${ioc}`;
  if (category === "Domain_Name") return `domains/${ioc}`;
  if (/^IPv[46]_Address(:Port)?$/.test(category)) {
    const clean = ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    return `ip_addresses/${clean}`;
  }
  if (category === "URL") {
    const id = Buffer.from(ioc).toString("base64url");
    return `urls/${id}`;
  }
  return null;
}

function _vtUrl(ioc, category) {
  if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) return `https://www.virustotal.com/gui/file/${ioc}`;
  if (category === "Domain_Name") return `https://www.virustotal.com/gui/domain/${ioc}`;
  if (/^IPv[46]_Address(:Port)?$/.test(category)) {
    const clean = ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    return `https://www.virustotal.com/gui/ip-address/${clean}`;
  }
  if (category === "URL") {
    const crypto = require("crypto");
    const sha256 = crypto.createHash("sha256").update(ioc).digest("hex");
    return `https://www.virustotal.com/gui/url/${sha256}`;
  }
  return null;
}

function _parseVtResponse(ioc, category, statusCode, body) {
  const vtUrl = _vtUrl(ioc, category);
  const queriedAt = Date.now();
  if (statusCode === 404) return { ioc, found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0, score: "Not Found", verdict: "not_found", vtUrl, error: null, queriedAt };
  if (statusCode === 401) return { ioc, found: false, score: "", verdict: "error", vtUrl, error: "Invalid API key", queriedAt };
  if (statusCode === 429) return { ioc, found: false, score: "", verdict: "error", vtUrl, error: "Rate limited (429)", queriedAt };
  if (statusCode < 200 || statusCode >= 300) return { ioc, found: false, score: "", verdict: "error", vtUrl, error: `HTTP ${statusCode}`, queriedAt };
  try {
    const json = JSON.parse(body);
    const attrs = json?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected + (stats.timeout || 0);
    const detected = malicious + suspicious;
    const score = `${detected}/${total}`;
    const verdict = total === 0 ? "not_found" : malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean";
    const threatLabel = attrs.popular_threat_classification?.suggested_threat_label || null;
    return { ioc, found: total > 0, malicious, suspicious, harmless, undetected, total, score, verdict, vtUrl, error: null, threatLabel, queriedAt };
  } catch {
    return { ioc, found: false, score: "", verdict: "error", vtUrl, error: "Failed to parse response", queriedAt };
  }
}

// Rolling rate-limiter (requests per second window)
const _vtRequestTimes = [];
async function _vtRateLimitWait(rateLimit) {
  const windowMs = 1000;
  _vtRequestTimes.push(Date.now());
  if (_vtRequestTimes.length > rateLimit) _vtRequestTimes.shift();
  const now = Date.now();
  if (_vtRequestTimes.length < rateLimit) return;
  const waitUntil = _vtRequestTimes[0] + windowMs;
  const waitMs = waitUntil - now + 50;
  if (waitMs > 0) await new Promise((r) => setTimeout(r, waitMs));
}

safeHandle("vt-lookup-single", async (event, { ioc, category }) => {
  const settings = _loadVtSettings();
  if (!settings.apiKey) return { ioc, error: "No API key configured" };
  const endpoint = _vtEndpoint(ioc, category);
  if (!endpoint) return { ioc, score: "N/A", verdict: "unsupported", error: null };
  if (/^IPv[46]_Address(:Port)?$/.test(category) && _isPrivateIp(ioc)) return { ioc, found: false, score: "Private IP", verdict: "private", vtUrl: null, error: null };
  const cached = _vtCacheLookup(ioc, category, settings.cacheTtlHours || 24);
  if (cached) return cached;
  await _vtRateLimitWait(settings.rateLimit || 4);
  try {
    const res = await _vtApiRequest(endpoint, settings.apiKey);
    if (res.statusCode === 429) {
      const retryAfter = parseInt(res.headers["retry-after"] || "60", 10);
      await new Promise((r) => setTimeout(r, retryAfter * 1000));
      const res2 = await _vtApiRequest(endpoint, settings.apiKey);
      const result = _parseVtResponse(ioc, category, res2.statusCode, res2.body);
      if (!result.error || res2.statusCode === 404) _vtCacheStore(ioc, category, result);
      return result;
    }
    const result = _parseVtResponse(ioc, category, res.statusCode, res.body);
    if (!result.error || res.statusCode === 404) _vtCacheStore(ioc, category, result);
    return result;
  } catch (err) {
    return { ioc, error: err.message, score: "", verdict: "error" };
  }
});

const _vtBulkJobs = new Map();
let _vtBulkIdCounter = 0;

safeHandle("vt-bulk-lookup", async (event, { iocs, requestId: clientId }) => {
  const settings = _loadVtSettings();
  if (!settings.apiKey) return { error: "No API key configured" };

  const requestId = clientId || `vt-bulk-${++_vtBulkIdCounter}`;
  const job = { cancelled: false };
  _vtBulkJobs.set(requestId, job);

  (async () => {
    const total = iocs.length;
    let completed = 0;
    const seenKeys = new Map();

    for (const { raw, category } of iocs) {
      if (job.cancelled || (mainWindow && mainWindow.isDestroyed())) break;
      const endpoint = _vtEndpoint(raw, category);
      let result;
      const normKey = _vtCacheKey(raw, category);
      if (seenKeys.has(normKey)) {
        result = { ...seenKeys.get(normKey), ioc: raw };
        completed++;
        safeSend("vt-progress", { requestId, completed, total, result });
        continue;
      }
      if (!endpoint) {
        result = { ioc: raw, score: "N/A", verdict: "unsupported", error: null };
      } else if (/^IPv[46]_Address(:Port)?$/.test(category) && _isPrivateIp(raw)) {
        result = { ioc: raw, found: false, score: "Private IP", verdict: "private", vtUrl: null, error: null };
      } else {
        const cached = _vtCacheLookup(raw, category, settings.cacheTtlHours || 24);
        if (cached) {
          result = cached;
        } else {
          try {
            await _vtRateLimitWait(settings.rateLimit || 4);
            if (job.cancelled) break;
            const res = await _vtApiRequest(endpoint, settings.apiKey);
            if (res.statusCode === 401) {
              safeSend("vt-progress", { requestId, completed, total, result: { ioc: raw, error: "Invalid API key", verdict: "error" } });
              safeSend("vt-complete", { requestId, completed, total, error: "Invalid API key" });
              _vtBulkJobs.delete(requestId);
              return;
            }
            if (res.statusCode === 429) {
              const retryAfter = parseInt(res.headers["retry-after"] || "60", 10);
              const sleepEnd = Date.now() + retryAfter * 1000;
              while (Date.now() < sleepEnd && !job.cancelled) {
                await new Promise((r) => setTimeout(r, Math.min(2000, sleepEnd - Date.now())));
              }
              if (job.cancelled) break;
              const res2 = await _vtApiRequest(endpoint, settings.apiKey);
              result = _parseVtResponse(raw, category, res2.statusCode, res2.body);
              if (!result.error || res2.statusCode === 404) _vtCacheStore(raw, category, result);
            } else {
              result = _parseVtResponse(raw, category, res.statusCode, res.body);
              if (!result.error || res.statusCode === 404) _vtCacheStore(raw, category, result);
            }
          } catch (err) {
            result = { ioc: raw, error: err.message, score: "", verdict: "error" };
          }
        }
      }
      if (!result.error) seenKeys.set(normKey, result);
      completed++;
      safeSend("vt-progress", { requestId, completed, total, result });
    }
    safeSend("vt-complete", { requestId, completed, total, cancelled: job.cancelled });
    _vtBulkJobs.delete(requestId);
  })().catch((err) => {
    console.error(`VT bulk lookup failed for ${requestId}:`, err?.message || err);
    safeSend("vt-complete", { requestId, completed: 0, total: iocs.length, error: err?.message || "Unknown error" });
    _vtBulkJobs.delete(requestId);
  });

  return { requestId };
});

safeHandle("vt-cancel", async (event, { requestId }) => {
  const job = _vtBulkJobs.get(requestId);
  if (job) job.cancelled = true;
  return true;
});

safeHandle("vt-clear-cache", async () => {
  const cache = _openVtCache();
  const info = cache.prepare("DELETE FROM vt_cache").run();
  return { cleared: info.changes };
});

safeHandle("vt-get-related", async (event, { ioc, category }) => {
  const settings = _loadVtSettings();
  if (!settings.apiKey) return { error: "No API key configured" };

  const rels = [];
  if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) {
    rels.push({ type: "Contacted Domains", endpoint: `files/${ioc}/contacted_domains` });
    rels.push({ type: "Contacted IPs", endpoint: `files/${ioc}/contacted_ips` });
    rels.push({ type: "Contacted URLs", endpoint: `files/${ioc}/contacted_urls` });
  } else if (category === "Domain_Name") {
    rels.push({ type: "Communicating Files", endpoint: `domains/${ioc}/communicating_files` });
    rels.push({ type: "DNS Resolutions", endpoint: `domains/${ioc}/resolutions` });
  } else if (/^IPv[46]_Address(:Port)?$/.test(category)) {
    const clean = ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    rels.push({ type: "Communicating Files", endpoint: `ip_addresses/${clean}/communicating_files` });
    rels.push({ type: "DNS Resolutions", endpoint: `ip_addresses/${clean}/resolutions` });
  } else if (category === "URL") {
    const id = Buffer.from(ioc).toString("base64url");
    rels.push({ type: "Contacted Domains", endpoint: `urls/${id}/contacted_domains` });
    rels.push({ type: "Contacted IPs", endpoint: `urls/${id}/contacted_ips` });
  } else {
    return { error: "Unsupported IOC type for relationships" };
  }

  const results = [];
  const errors = [];
  for (const rel of rels) {
    try {
      await _vtRateLimitWait(settings.rateLimit || 4);
      let res = await _vtApiRequest(`${rel.endpoint}?limit=10`, settings.apiKey);
      if (res.statusCode === 429) {
        const retryAfter = parseInt(res.headers["retry-after"] || "60", 10);
        await new Promise((r) => setTimeout(r, retryAfter * 1000));
        res = await _vtApiRequest(`${rel.endpoint}?limit=10`, settings.apiKey);
      }
      if (res.statusCode === 401) return { ioc, relationships: [], error: "Invalid API key" };
      if (res.statusCode === 200) {
        const json = JSON.parse(res.body);
        const items = (json.data || []).map((item) => {
          const attrs = item.attributes || {};
          if (item.type === "file") {
            const stats = attrs.last_analysis_stats || {};
            return { id: item.id, type: "file", name: attrs.meaningful_name || attrs.name || item.id, score: `${(stats.malicious || 0) + (stats.suspicious || 0)}/${(stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)}`, malicious: stats.malicious || 0, threatLabel: attrs.popular_threat_classification?.suggested_threat_label || null };
          } else if (item.type === "domain") {
            return { id: item.id, type: "domain", name: item.id };
          } else if (item.type === "ip_address") {
            return { id: item.id, type: "ip", name: item.id };
          } else if (item.type === "url") {
            return { id: item.id, type: "url", name: attrs.url || item.id };
          } else if (item.type === "resolution") {
            return { id: attrs.ip_address || attrs.host_name || item.id, type: "resolution", name: attrs.ip_address || attrs.host_name || item.id, date: attrs.date };
          }
          return { id: item.id, type: item.type, name: item.id };
        });
        if (items.length > 0) results.push({ type: rel.type, items });
      } else if (res.statusCode !== 404) {
        errors.push(`${rel.type}: HTTP ${res.statusCode}`);
      }
    } catch (err) {
      errors.push(`${rel.type}: ${err.message || "Network error"}`);
    }
  }
  return { ioc, relationships: results, error: errors.length > 0 ? errors.join("; ") : undefined };
});

// ── Windows Application Menu ──────────────────────────────────────────────────
// Differences from the macOS menu:
//  - No top-level "IRFlow Timeline" app menu (macOS convention).
//  - "About" moved into Help.
//  - Quit moved into File.
//  - macOS-only roles removed: services, hide, hideOthers, unhide, front, zoom.
//  - Window submenu simplified (minimize + close only).
//  - "role: close" closes window (not quit) — keep it in File for closing the current file view.
function _rebuildMenu() { buildMenu(); }

function buildMenu() {
  const recentFiles = _loadRecentFiles();
  const recentSubmenu = recentFiles.length > 0
    ? [
        ...recentFiles.map((fp) => ({
          label: path.basename(fp),
          toolTip: fp,
          click: () => {
            if (fs.existsSync(fp)) {
              enqueueImport(fp);
            } else {
              const files = _loadRecentFiles().filter((f) => f !== fp);
              _saveRecentFiles(files);
              _rebuildMenu();
              safeSend("recent-files-updated", files);
              dialog.showMessageBox(_activeWindow(), { type: "warning", title: "File Not Found", message: "The file no longer exists at this location.", detail: fp, buttons: ["OK"] }).catch(() => {});
            }
          },
        })),
        { type: "separator" },
        { label: "Clear Recent", click: () => { _saveRecentFiles([]); _rebuildMenu(); } },
      ]
    : [{ label: "No Recent Files", enabled: false }];

  const template = [
    {
      label: "File",
      submenu: [
        {
          label: "Open...",
          accelerator: "CmdOrCtrl+O",
          click: () => mainWindow?.webContents.send("trigger-open"),
        },
        {
          label: "Open Recent",
          submenu: recentSubmenu,
        },
        { type: "separator" },
        {
          label: "Save Session...",
          accelerator: "CmdOrCtrl+S",
          click: () => mainWindow?.webContents.send("trigger-save-session"),
        },
        {
          label: "Open Session...",
          accelerator: "CmdOrCtrl+Shift+O",
          click: () => mainWindow?.webContents.send("trigger-load-session"),
        },
        { type: "separator" },
        {
          label: "Export Filtered View...",
          accelerator: "CmdOrCtrl+E",
          click: () => mainWindow?.webContents.send("trigger-export"),
        },
        {
          label: "Generate Report...",
          accelerator: "CmdOrCtrl+Shift+R",
          click: () => mainWindow?.webContents.send("trigger-generate-report"),
        },
        { type: "separator" },
        {
          label: "Close Tab",
          accelerator: "CmdOrCtrl+W",
          click: () => mainWindow?.webContents.send("trigger-close-tab"),
        },
        {
          label: "Close All Tabs",
          accelerator: "CmdOrCtrl+Shift+Q",
          click: () => mainWindow?.webContents.send("trigger-close-all-tabs"),
        },
        { type: "separator" },
        // Windows convention: Quit is in File menu
        { role: "quit" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" }, { role: "redo" }, { type: "separator" },
        { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" },
        { type: "separator" },
        {
          label: "Find...",
          accelerator: "CmdOrCtrl+F",
          click: () => mainWindow?.webContents.send("trigger-search"),
        },
        {
          label: "Find in All Tabs...",
          accelerator: "CmdOrCtrl+Shift+F",
          click: () => mainWindow?.webContents.send("trigger-crossfind"),
        },
      ],
    },
    {
      label: "Tools",
      submenu: [
        {
          label: "Datetime Format",
          submenu: [
            { label: "Default (raw)", click: () => mainWindow?.webContents.send("set-datetime-format", "") },
            { label: "yyyy-MM-dd HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss") },
            { label: "yyyy-MM-dd HH:mm:ss.fff", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss.fff") },
            { label: "yyyy-MM-dd HH:mm:ss.fffffff", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss.fffffff") },
            { label: "MM/dd/yyyy HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "MM/dd/yyyy HH:mm:ss") },
            { label: "dd/MM/yyyy HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "dd/MM/yyyy HH:mm:ss") },
            { label: "yyyy-MM-dd", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd") },
          ],
        },
        {
          label: "Timezone",
          submenu: [
            { label: "UTC", click: () => mainWindow?.webContents.send("set-timezone", "UTC") },
            { label: "US/Eastern (EST/EDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/New_York") },
            { label: "US/Central (CST/CDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Chicago") },
            { label: "US/Mountain (MST/MDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Denver") },
            { label: "US/Pacific (PST/PDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Los_Angeles") },
            { label: "Europe/London (GMT/BST)", click: () => mainWindow?.webContents.send("set-timezone", "Europe/London") },
            { label: "Europe/Berlin (CET/CEST)", click: () => mainWindow?.webContents.send("set-timezone", "Europe/Berlin") },
            { label: "Asia/Tokyo (JST)", click: () => mainWindow?.webContents.send("set-timezone", "Asia/Tokyo") },
            { label: "Asia/Shanghai (CST)", click: () => mainWindow?.webContents.send("set-timezone", "Asia/Shanghai") },
            { label: "Australia/Sydney (AEST/AEDT)", click: () => mainWindow?.webContents.send("set-timezone", "Australia/Sydney") },
            { label: "Local (system)", click: () => mainWindow?.webContents.send("set-timezone", "local") },
          ],
        },
        { type: "separator" },
        {
          label: "Font Size",
          submenu: [
            { label: "Increase", accelerator: "CmdOrCtrl+Plus", click: () => mainWindow?.webContents.send("set-font-size", "increase") },
            { label: "Decrease", accelerator: "CmdOrCtrl+-", click: () => mainWindow?.webContents.send("set-font-size", "decrease") },
            { type: "separator" },
            ...[9, 10, 11, 12, 13, 14, 16, 18].map((s) => ({
              label: `${s}px`, click: () => mainWindow?.webContents.send("set-font-size", s),
            })),
          ],
        },
        { type: "separator" },
        {
          label: "Reset Column Widths",
          accelerator: "CmdOrCtrl+R",
          click: () => mainWindow?.webContents.send("trigger-reset-columns"),
        },
        {
          label: "Toggle Histogram",
          click: () => mainWindow?.webContents.send("trigger-histogram"),
        },
        { type: "separator" },
        {
          label: "Theme",
          submenu: [
            { label: "Dark", click: () => mainWindow?.webContents.send("set-theme", "dark") },
            { label: "Light", click: () => mainWindow?.webContents.send("set-theme", "light") },
          ],
        },
        { type: "separator" },
        {
          label: "VirusTotal API Key...",
          click: () => mainWindow?.webContents.send("trigger-vt-settings"),
        },
      ],
    },
    {
      label: "View",
      submenu: [
        {
          label: "Toggle Bookmarked Only",
          accelerator: "CmdOrCtrl+B",
          click: () => mainWindow?.webContents.send("trigger-bookmark-toggle"),
        },
        {
          label: "Column Manager",
          accelerator: "CmdOrCtrl+Shift+C",
          click: () => mainWindow?.webContents.send("trigger-column-manager"),
        },
        {
          label: "Conditional Formatting",
          accelerator: "CmdOrCtrl+Shift+L",
          click: () => mainWindow?.webContents.send("trigger-color-rules"),
        },
        { type: "separator" },
        { role: "togglefullscreen" },
        { type: "separator" },
        { role: "zoomIn" }, { role: "zoomOut" }, { role: "resetZoom" },
        { type: "separator" },
        { role: "toggleDevTools" },
      ],
    },
    {
      // Windows: simplified Window menu — no macOS front/zoom/front roles
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "close" },
      ],
    },
    {
      label: "Help",
      submenu: [
        {
          label: "Keyboard Shortcuts",
          accelerator: "CmdOrCtrl+/",
          click: () => mainWindow?.webContents.send("trigger-shortcuts"),
        },
        {
          label: "Check for Updates...",
          click: () => {
            if (_activeWindow()) safeSend("trigger-check-for-updates");
            else updateController.checkForUpdates();
          },
        },
        { type: "separator" },
        {
          label: "EZ Tools Website",
          click: () => shell.openExternal("https://ericzimmerman.github.io/"),
        },
        { type: "separator" },
        // About belongs in Help on Windows (no dedicated app menu)
        { role: "about" },
      ],
    },
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ── HTML Report Builder ───────────────────────────────────────────────────────
function buildReportHtml(data, fileName, tagColors = {}, vtEnrichment = null) {
  const esc = (s) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  const allReportRows = [...data.bookmarkedRows];
  for (const rows of Object.values(data.taggedGroups)) {
    for (const r of rows) allReportRows.push(r);
  }
  const usedHeaders = data.headers.filter((h) =>
    allReportRows.some((r) => r[h] && String(r[h]).trim())
  );

  const renderTable = (rows, headers) => {
    if (rows.length === 0) return '<p style="color:#9a9590;font-style:italic;">No events</p>';
    let html = '<div class="table-wrap"><table><thead><tr>';
    for (const h of headers) html += `<th>${esc(h)}</th>`;
    html += "</tr></thead><tbody>";
    for (const row of rows) {
      html += "<tr>";
      for (const h of headers) html += `<td>${esc(row[h])}</td>`;
      html += "</tr>";
    }
    html += "</tbody></table></div>";
    return html;
  };

  let body = "";

  body += `<div class="report-header">
    <h1>IRFlow Timeline Report</h1>
    <div class="meta">
      <span>Source: <strong>${esc(fileName)}</strong></span>
      <span>Generated: <strong>${now}</strong></span>
    </div>
  </div>`;

  body += `<div class="cards">
    <div class="card"><div class="card-val">${data.totalRows.toLocaleString()}</div><div class="card-label">Total Rows</div></div>
    <div class="card"><div class="card-val">${data.bookmarkCount.toLocaleString()}</div><div class="card-label">Bookmarked</div></div>
    <div class="card"><div class="card-val">${data.taggedRowCount.toLocaleString()}</div><div class="card-label">Tagged Rows</div></div>
    <div class="card"><div class="card-val">${data.tagCount}</div><div class="card-label">Unique Tags</div></div>
  </div>`;

  if (data.tsRange) {
    body += `<div class="ts-range">
      <strong>Timeline Span (${esc(data.tsRange.column)}):</strong>
      ${esc(data.tsRange.earliest)} &mdash; ${esc(data.tsRange.latest)}
    </div>`;
  }

  if (data.tagSummary.length > 0) {
    body += '<div class="section"><h2>Tag Breakdown</h2><div class="tag-chips">';
    for (const { tag, cnt } of data.tagSummary) {
      const color = tagColors[tag] || "#8b949e";
      body += `<span class="tag-chip" style="border-color:${color};color:${color};background:${color}22">${esc(tag)} <strong>${cnt}</strong></span>`;
    }
    body += "</div></div>";
  }

  if (vtEnrichment && vtEnrichment.perIocResults && vtEnrichment.results) {
    const vtr = vtEnrichment.results;
    const perIoc = vtEnrichment.perIocResults;
    const vtIocs = perIoc.filter((ioc) => vtr[ioc.raw]);
    const vtMatched = vtIocs.filter((ioc) => ioc.hits > 0);
    const vtFeedOnly = vtIocs.filter((ioc) => ioc.hits === 0);
    const malicious = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "malicious");
    const suspicious = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "suspicious");
    const clean = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "clean");
    const notFound = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "not_found" || vtr[ioc.raw]?.verdict === "private");
    const feedMal = vtFeedOnly.filter((ioc) => vtr[ioc.raw]?.verdict === "malicious").length;
    const feedSus = vtFeedOnly.filter((ioc) => vtr[ioc.raw]?.verdict === "suspicious").length;
    const feedClean = vtFeedOnly.filter((ioc) => vtr[ioc.raw]?.verdict === "clean").length;

    body += '<div class="section"><h2>VirusTotal IOC Enrichment</h2>';
    body += '<div class="cards">';
    body += `<div class="card" style="border-color:#f85149"><div class="card-val" style="color:#f85149">${malicious.length}</div><div class="card-label">Malicious</div></div>`;
    body += `<div class="card" style="border-color:#d29922"><div class="card-val" style="color:#d29922">${suspicious.length}</div><div class="card-label">Suspicious</div></div>`;
    body += `<div class="card" style="border-color:#3fb950"><div class="card-val" style="color:#3fb950">${clean.length}</div><div class="card-label">Clean</div></div>`;
    body += `<div class="card"><div class="card-val">${notFound.length}</div><div class="card-label">Not Found</div></div>`;
    body += '</div>';
    if (feedMal + feedSus + feedClean > 0) {
      const parts = [];
      if (feedMal > 0) parts.push(`<span style="color:#f85149">${feedMal} malicious</span>`);
      if (feedSus > 0) parts.push(`<span style="color:#d29922">${feedSus} suspicious</span>`);
      if (feedClean > 0) parts.push(`<span style="color:#3fb950">${feedClean} clean</span>`);
      body += `<div style="text-align:center;font-size:11px;color:#8b949e;margin-top:4px">Feed only: ${parts.join(" · ")} <span style="opacity:0.7">(no timeline hits)</span></div>`;
    }
    if (vtIocs.length > 0) {
      const verdictOrder = { malicious: 0, suspicious: 1, clean: 2, not_found: 3, private: 3 };
      const sorted = [...vtIocs].sort((a, b) => (verdictOrder[vtr[a.raw]?.verdict] ?? 4) - (verdictOrder[vtr[b.raw]?.verdict] ?? 4));
      body += '<div class="table-wrap"><table><thead><tr>';
      body += '<th>IOC</th><th>Category</th><th>VT Score</th><th>Verdict</th><th>Threat</th><th>Queried At</th><th>Timeline Hits</th>';
      body += '</tr></thead><tbody>';
      for (const ioc of sorted) {
        const r = vtr[ioc.raw];
        const verdict = r?.verdict || "unknown";
        const verdictColor = verdict === "malicious" ? "#f85149" : verdict === "suspicious" ? "#d29922" : verdict === "clean" ? "#3fb950" : "#8b949e";
        body += '<tr>';
        body += `<td style="font-family:monospace;font-size:12px">${esc(ioc.raw)}</td>`;
        body += `<td>${esc(ioc.category.replace(/_/g, " "))}</td>`;
        body += `<td style="font-family:monospace"><span style="color:${verdictColor};font-weight:700">${esc(r?.score || "—")}</span></td>`;
        body += `<td><span style="background:${verdictColor}22;color:${verdictColor};border:1px solid ${verdictColor}66;padding:1px 8px;border-radius:3px;font-size:11px;font-weight:600">${esc(verdict)}</span></td>`;
        body += `<td style="font-size:11px;color:${verdictColor};font-style:italic">${r?.threatLabel ? esc(r.threatLabel) : "—"}</td>`;
        body += `<td style="font-size:11px;font-family:monospace;color:#8b949e;white-space:nowrap">${r?.queriedAt ? new Date(r.queriedAt).toISOString().replace("T", " ").slice(0, 19) + "Z" : "—"}</td>`;
        body += `<td style="text-align:right;font-family:monospace">${ioc.hits > 0 ? ioc.hits.toLocaleString() : "—"}</td>`;
        body += '</tr>';
      }
      body += '</tbody></table></div>';
    }
    body += '</div>';
  }

  if (data.bookmarkedRows.length > 0) {
    body += `<div class="section"><h2>Bookmarked Events (${data.bookmarkCount})</h2>`;
    body += renderTable(data.bookmarkedRows, usedHeaders);
    body += "</div>";
  }

  for (const { tag, cnt } of data.tagSummary) {
    const rows = data.taggedGroups[tag] || [];
    if (rows.length === 0) continue;
    const color = tagColors[tag] || "#8b949e";
    body += `<div class="section">
      <h2><span class="tag-badge" style="background:${color}33;color:${color};border:1px solid ${color}66">${esc(tag)}</span> (${cnt} events)</h2>`;
    body += renderTable(rows, usedHeaders);
    body += "</div>";
  }

  if (data.bookmarkedRows.length === 0 && data.tagSummary.length === 0) {
    body += '<div class="section"><p style="color:#9a9590;font-style:italic;text-align:center;padding:40px 0;">No bookmarked or tagged events to include in report.<br>Bookmark events with the star icon or tag them to include in the report.</p></div>';
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IRFlow Report — ${esc(fileName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f1114;color:#e0ddd8;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;padding:30px;max-width:1400px;margin:0 auto}
.report-header{border-bottom:2px solid #E85D2A;padding-bottom:16px;margin-bottom:24px}
.report-header h1{font-size:22px;font-weight:700;color:#E85D2A}
.meta{display:flex;gap:24px;color:#9a9590;font-size:12px;margin-top:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:#181b20;border:1px solid #2a2d33;border-radius:8px;padding:16px;text-align:center}
.card-val{font-size:24px;font-weight:700;color:#E85D2A}
.card-label{font-size:11px;color:#9a9590;text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.ts-range{background:#181b20;border:1px solid #2a2d33;border-radius:6px;padding:10px 16px;margin-bottom:24px;font-size:12px;color:#9a9590}
.section{margin-bottom:32px}
.section h2{font-size:16px;font-weight:600;margin-bottom:12px;color:#e0ddd8;display:flex;align-items:center;gap:8px}
.tag-chips{display:flex;flex-wrap:wrap;gap:8px}
.tag-chip{padding:4px 12px;border:1px solid;border-radius:20px;font-size:12px}
.tag-chip strong{margin-left:4px}
.tag-badge{padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600}
.table-wrap{overflow-x:auto;border:1px solid #2a2d33;border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:11px;font-family:'Cascadia Code','Consolas','Courier New',monospace}
th{position:sticky;top:0;background:#181b20;color:#E85D2A;padding:8px 10px;text-align:left;border-bottom:2px solid #2a2d33;white-space:nowrap;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.04em}
td{padding:5px 10px;border-bottom:1px solid #1a1d22;color:#e0ddd8;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:nth-child(even){background:#141720}
tr:hover{background:rgba(232,93,42,.08)}
footer{margin-top:40px;padding-top:16px;border-top:1px solid #2a2d33;color:#5c5752;font-size:10px;text-align:center}
@media print{body{background:#fff;color:#1c1917}th{background:#f7f5f3;color:#E85D2A}td{color:#1c1917;border-color:#e0dbd6}.card{border-color:#e0dbd6;background:#faf8f6}tr:nth-child(even){background:#faf8f6}.report-header{border-color:#E85D2A}.ts-range{background:#faf8f6;border-color:#e0dbd6}}
</style>
</head>
<body>
${body}
<footer>Generated by IRFlow Timeline &mdash; ${now}</footer>
</body>
</html>`;
}

// ── Boot ──────────────────────────────────────────────────────────────────────
app.whenReady().then(createWindow);
