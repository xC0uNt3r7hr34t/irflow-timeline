const { parentPort, workerData } = require("worker_threads");
const TimelineDB = require("../db");

let cancelled = false;

parentPort.on("message", (message = {}) => {
  if (message.type === "cancel") cancelled = true;
});

function progress(payload) {
  parentPort.postMessage({ type: "progress", progress: { jobId: workerData.jobId, ...payload } });
}

function assertNotCancelled() {
  if (cancelled) throw Object.assign(new Error("Job cancelled"), { cancelled: true });
}

function callAnalyzer(db, method, payload = {}) {
  const { tabId, tabIds, options = {} } = payload;
  switch (method) {
    case "getProcessTree":
      return db.getProcessTree(tabId, options);
    case "previewProcessTree":
      return db.previewProcessTree(tabId, options);
    case "getProcessInspectorContext":
      return db.getProcessInspectorContext(tabId, options);
    case "previewLateralMovement":
      return db.previewLateralMovement(tabId, options);
    case "detectKapeCollectionHost":
      return db.detectKapeCollectionHost(tabId);
    case "getLateralMovement":
      return db.getLateralMovement(tabId, {
        ...options,
        progressCb: (p) => progress({ phase: "lateral-movement", method: "getLateralMovement", tabId, ...p }),
      });
    case "getMultiSourceLateralMovement":
      return db.getMultiSourceLateralMovement(tabIds, {
        ...options,
        progressCb: (p) => progress({ phase: "lateral-movement", method: "getMultiSourceLateralMovement", tabIds, ...p }),
      });
    case "previewMultiSourceLateralMovement":
      return db.previewMultiSourceLateralMovement(tabIds, options);
    case "previewPersistenceAnalysis":
      return db.previewPersistenceAnalysis(tabId, options);
    case "getPersistenceAnalysis":
      return db.getPersistenceAnalysis(tabId, options);
    case "previewMultiSourcePersistence":
      return db.previewMultiSourcePersistence(tabIds, options);
    case "getMultiSourcePersistence":
      return db.getMultiSourcePersistence(tabIds, options);
    case "getPersistencePivotJoin":
      return db.getPersistencePivotJoin(tabIds, options);
    case "analyzeKapeCollection":
      return require("../analyzers/persistence/collection-analysis").analyzeCollection(payload.dir, options, {});
    case "scanRansomwareExtensions":
      return db.scanRansomwareExtensions(tabId, (p) => progress({ phase: "ransomware-scan", tabId, ...p }));
    case "analyzeRansomware":
      return db.analyzeRansomware(tabId, {
        ...options,
        progressCb: (p) => progress({ phase: "ransomware", tabId, ...p }),
      });
    case "detectTimestomping":
      return db.detectTimestomping(tabId, { ...options });
    case "getFileActivityHeatmap":
      return db.getFileActivityHeatmap(tabId, {
        ...options,
        progressCb: (p) => progress({ phase: "heatmap", tabId, ...p }),
      });
    case "analyzeADS":
      return db.analyzeADS(tabId, { ...options });
    case "analyzeAiHistory":
      return db.analyzeAiHistory(tabId, {
        ...options,
        progressCb: (p) => progress({ phase: "ai-secrets", tabId, ...p }),
      });
    case "analyzeUsnJournal":
      return db.analyzeUsnJournal(tabId, options);
    case "matchIocs":
      return db.matchIocs(tabId, options.iocPatterns, options.batchSize || 200);
    default:
      throw new Error(`Unknown analyzer method: ${method}`);
  }
}

(async () => {
  const { method, payload, tabs = [] } = workerData;
  const db = new TimelineDB();
  try {
    for (const descriptor of tabs) {
      db.adoptTabFromFile(descriptor.tabId, descriptor);
    }

    assertNotCancelled();
    progress({ phase: "running", method, progress: 0 });
    const result = callAnalyzer(db, method, payload);
    assertNotCancelled();
    progress({ phase: "completed", method, progress: 100, done: true });

    for (const descriptor of tabs) {
      try { db.releaseTab(descriptor.tabId); } catch {}
    }
    db.closeAll();
    parentPort.postMessage({ type: "result", result });
  } catch (err) {
    for (const descriptor of tabs) {
      try { db.releaseTab(descriptor.tabId); } catch {}
    }
    try { db.closeAll(); } catch {}
    if (err?.cancelled) {
      process.exit(1);
      return;
    }
    parentPort.postMessage({
      type: "result",
      result: { error: err?.message || "Analyzer failed", stack: err?.stack },
    });
  }
})();
