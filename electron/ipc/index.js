/**
 * ipc/index.js — Register all IPC handler groups
 *
 * Each handler module exports a registration function:
 *   (safeHandle, safeSend, context) => void
 *
 * The context object provides shared dependencies (db, _tabMeta, etc.)
 * so handler modules don't need to import main.js globals.
 */

const registerQueryHandlers = require("./query-handlers");
const registerTagHandlers = require("./tag-handlers");
const registerAnalysisHandlers = require("./analysis-handlers");
const registerExportHandlers = require("./export-handlers");
const registerSessionHandlers = require("./session-handlers");
const registerVtHandlers = require("./vt-handlers");
const registerSigmaHandlers = require("./sigma-handlers");
const registerJobHandlers = require("./job-handlers");
const registerRdpBitmapCacheHandlers = require("./rdp-bitmap-cache-handlers");
const registerAiHistoryHandlers = require("./ai-history-handlers");
const registerTriageHandlers = require("./triage-handlers");

function registerAll(safeHandle, safeSend, context) {
  registerQueryHandlers(safeHandle, safeSend, context);
  registerTagHandlers(safeHandle, safeSend, context);
  registerAnalysisHandlers(safeHandle, safeSend, context);
  registerExportHandlers(safeHandle, safeSend, context);
  registerSessionHandlers(safeHandle, safeSend, context);
  registerJobHandlers(safeHandle, safeSend, context);
  registerVtHandlers(safeHandle, safeSend, context);
  registerSigmaHandlers(safeHandle, safeSend, context);
  registerRdpBitmapCacheHandlers(safeHandle, safeSend, context);
  registerAiHistoryHandlers(safeHandle, safeSend, context);
  registerTriageHandlers(safeHandle, safeSend, context);
}

module.exports = { registerAll };
