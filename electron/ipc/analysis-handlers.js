const fs = require("fs");
const { dialog } = require("electron");
const { openDialogOptions } = require("../utils/open-dialog");

module.exports = function registerAnalysisHandlers(safeHandle, safeSend, { db, _tabMeta, extractResidentData, _activeWindow, runAnalyzerJob }) {
  const analyze = (method, payload, fallback) => {
    if (runAnalyzerJob) return runAnalyzerJob(method, payload);
    return fallback();
  };

  safeHandle("extract-resident-data", async (event, { tabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This tab is not a raw MFT file" };
    }
    if (!fs.existsSync(meta.filePath)) {
      return { error: `Original MFT file no longer exists: ${meta.filePath}` };
    }

    const result = await dialog.showOpenDialog(_activeWindow(), openDialogOptions({
      title: "Choose output folder for resident data extraction",
      properties: ["openDirectory", "createDirectory"],
      buttonLabel: "Extract Here",
    }));
    if (result.canceled || !result.filePaths[0]) return { canceled: true };

    const extractResult = await extractResidentData(meta.filePath, result.filePaths[0], (processed, total) => {
      safeSend("extract-resident-progress", {
        tabId, processed, total,
        percent: total > 0 ? Math.round((processed / total) * 100) : 0,
      });
    });
    return extractResult;
  });

  // Ransomware MFT Analysis
  safeHandle("analyze-ransomware", (event, { tabId, encryptedExt, ransomNotePattern, noteMatchMode, usnTabId, evtxTabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This feature requires a raw MFT tab." };
    }
    let resolvedUsnTabId = null;
    if (usnTabId) {
      const usnMeta = _tabMeta.get(usnTabId);
      if (usnMeta?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId;
    }
    if (!resolvedUsnTabId) {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") {
          resolvedUsnTabId = tid;
          break;
        }
      }
    }
    // Optional EVTX tab for defense-evasion correlation. EVTX CSVs (EvtxECmd/Hayabusa/Chainsaw)
    // carry no sourceFormat, so resolve by header signature.
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") {
      const m = _tabMeta.get(evtxTabId);
      if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId;
    }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; }
      }
    }
    return analyze(
      "analyzeRansomware",
      { tabId, options: { encryptedExt, ransomNotePattern, noteMatchMode, usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.analyzeRansomware(tabId, { encryptedExt, ransomNotePattern, noteMatchMode, usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId, progressCb: (p) => safeSend("rw-progress", p) })
    );
  });

  safeHandle("scan-ransomware-extensions", (event, { tabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This feature requires a raw MFT tab." };
    }
    return analyze(
      "scanRansomwareExtensions",
      { tabId },
      () => db.scanRansomwareExtensions(tabId, (p) => safeSend("rw-progress", p))
    );
  });

  // Timestomping Detector — auto-resolve companion USN ($J) + EVTX (Sysmon) tabs for cross-artifact
  // corroboration (Sysmon EID 2 FileCreateTime, USN FileCreate contradiction). '__none__' opts out.
  safeHandle("detect-timestomping", (event, { tabId, usnTabId, evtxTabId }) => {
    let resolvedUsnTabId = null;
    if (usnTabId && usnTabId !== "__none__") { const m = _tabMeta.get(usnTabId); if (m?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId; }
    if (!resolvedUsnTabId && usnTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") { resolvedUsnTabId = tid; break; } }
    }
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") { const m = _tabMeta.get(evtxTabId); if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId; }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; } }
    }
    return analyze(
      "detectTimestomping",
      { tabId, options: { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.detectTimestomping(tabId, { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId })
    );
  });

  // File Activity Heatmap
  safeHandle("get-file-activity-heatmap", (event, { tabId, usnTabId, evtxTabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This feature requires a raw MFT tab." };
    }
    // Auto-resolve a companion USN ($J) tab for forgery-resistant corroboration of $SI-derived
    // windows. '__none__' lets the caller explicitly opt out.
    let resolvedUsnTabId = null;
    if (usnTabId && usnTabId !== "__none__") {
      const m = _tabMeta.get(usnTabId);
      if (m?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId;
    }
    if (!resolvedUsnTabId && usnTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") { resolvedUsnTabId = tid; break; }
      }
    }
    // Auto-resolve a companion EVTX tab for process-execution corroboration. EVTX CSVs
    // (EvtxECmd/Hayabusa/Chainsaw) carry no sourceFormat, so detect by header signature.
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") {
      const m = _tabMeta.get(evtxTabId);
      if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId;
    }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; }
      }
    }
    return analyze(
      "getFileActivityHeatmap",
      { tabId, options: { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.getFileActivityHeatmap(tabId, { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId, progressCb: (p) => safeSend("hm-progress", p) })
    );
  });

  // ADS Analyzer
  safeHandle("analyze-ads", (event, { tabId, usnTabId, evtxTabId }) => {
    // Auto-resolve companion USN ($J) + EVTX tabs for cross-artifact corroboration of ADS/MOTW
    // events (StreamChange / Sysmon EID 15). '__none__' opts out.
    let resolvedUsnTabId = null;
    if (usnTabId && usnTabId !== "__none__") { const m = _tabMeta.get(usnTabId); if (m?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId; }
    if (!resolvedUsnTabId && usnTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") { resolvedUsnTabId = tid; break; } }
    }
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") { const m = _tabMeta.get(evtxTabId); if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId; }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; } }
    }
    return analyze(
      "analyzeADS",
      { tabId, options: { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.analyzeADS(tabId, { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId })
    );
  });

  // AI Secret & Leak Scan — credential/key/PII detection over an AI history tab.
  safeHandle("analyze-ai-history", (event, { tabId, mode, redact, salt }) => {
    const m = _tabMeta.get(tabId);
    if (!m || typeof m.sourceFormat !== "string" || !m.sourceFormat.startsWith("ai-history-")) {
      return { error: "This tab is not an AI history timeline." };
    }
    const normalizedSalt = salt != null && String(salt).trim() ? String(salt).slice(0, 256) : undefined;
    const options = { mode: mode === "deep" ? "deep" : "quick", redact: redact !== false, salt: normalizedSalt };
    return analyze(
      "analyzeAiHistory",
      { tabId, options },
      // Inline-fallback progress must use the same channel the worker path routes to
      // (main.js legacyProgressChannel → "analysis-progress"), which the modal listens on.
      () => db.analyzeAiHistory(tabId, { ...options, progressCb: (p) => safeSend("analysis-progress", { phase: "ai-secrets", ...p }) })
    );
  });

  // USN Journal Analysis
  safeHandle("analyze-usn-journal", (event, { tabId, startTime, endTime, analyses, pathFilter, mftTabId }) => {
    return analyze(
      "analyzeUsnJournal",
      { tabId, options: { startTime, endTime, analyses, pathFilter, mftTabId } },
      () => db.analyzeUsnJournal(tabId, { startTime, endTime, analyses, pathFilter, mftTabId })
    );
  });

  // IOC Matching
  safeHandle("match-iocs", (event, { tabId, iocPatterns, batchSize }) => {
    return analyze(
      "matchIocs",
      { tabId, options: { iocPatterns, batchSize: batchSize || 200 } },
      () => db.matchIocs(tabId, iocPatterns, batchSize || 200)
    );
  });

};
