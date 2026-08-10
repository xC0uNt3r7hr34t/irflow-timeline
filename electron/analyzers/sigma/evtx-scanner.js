/**
 * sigma/evtx-scanner.js - public facade for Hayabusa EVTX scanning.
 *
 * Keep this file as the compatibility boundary for IPC and tests. The actual
 * scanner responsibilities live under ./evtx-scanner/ so binary management,
 * command construction, progress parsing, output parsing, rule updates, and
 * scan orchestration can evolve independently.
 */

const {
  findHayabusa,
  downloadHayabusa,
  getHayabusaStatus,
  updateHayabusa,
  runLevelTuning,
  getLevelTuningPath,
  getRulesConfigDir,
  getGeoIpStatus,
  downloadGeoIp,
  getGeoIpDir,
} = require("./evtx-scanner/binary-manager");
const {
  getAvailableProfiles,
} = require("./evtx-scanner/command-builder");
const {
  updateHayabusaRules,
  getHayabusaRulesUpdateMeta,
} = require("./evtx-scanner/rule-updater");
const {
  scanEvtxDirectory,
  findEvtxFiles,
  runLogonSummary,
  runComputerMetrics,
  runEidMetrics,
  runLogMetrics,
  runSearch,
  runPivotKeywords,
  runExtractBase64,
  cancelScan,
} = require("./evtx-scanner/scan-runner");
const {
  MAX_EVENT_ROWS,
  parseHayabusaCsv,
  parseHayabusaJsonl,
} = require("./evtx-scanner/output-parser");

module.exports = {
  scanEvtxDirectory,
  findEvtxFiles,
  findHayabusa,
  downloadHayabusa,
  getHayabusaStatus,
  updateHayabusaRules,
  getHayabusaRulesUpdateMeta,
  updateHayabusa,
  runLogonSummary,
  runComputerMetrics,
  runEidMetrics,
  runLogMetrics,
  runSearch,
  runPivotKeywords,
  runExtractBase64,
  runLevelTuning,
  getLevelTuningPath,
  getRulesConfigDir,
  getAvailableProfiles,
  getGeoIpStatus,
  downloadGeoIp,
  getGeoIpDir,
  cancelScan,
  MAX_EVENT_ROWS,
  _parseHayabusaCsvForTest: parseHayabusaCsv,
  _parseHayabusaJsonlForTest: parseHayabusaJsonl,
};
