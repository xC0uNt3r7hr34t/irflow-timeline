// start-persistence-analysis: the job-handle route behind the modal's Cancel button.
//
// get-persistence-analysis goes through runAnalyzerJob(), which throws away the job id,
// so the renderer had nothing to pass to jobs-cancel — "Cancel" set a local flag, hid the
// modal, and left the analyzer worker grinding through the whole tab before its result
// was discarded. This handler hands the id back, mirroring start-process-tree.

const test = require("node:test");
const assert = require("node:assert/strict");

const registerQueryHandlers = require("../electron/ipc/query-handlers");

function register(deps) {
  const handlers = {};
  const sent = [];
  registerQueryHandlers(
    (channel, handler) => { handlers[channel] = handler; },
    (channel, payload) => { sent.push([channel, payload]); },
    deps,
  );
  return { handlers, sent };
}

test("persistence start IPC returns a job id and emits completion with that id", async () => {
  const result = { items: [], incidents: [], stats: {} };
  const promise = Promise.resolve(result);
  const startCalls = [];

  const { handlers, sent } = register({
    db: {},
    startAnalyzerJob(method, payload, options) {
      startCalls.push({ method, payload, options });
      return { jobId: "job-persistence-1", promise };
    },
  });

  const started = handlers["start-persistence-analysis"](null, {
    tabId: "tab-1",
    options: { mode: "evtx", disabledRules: ["evtx-3"] },
  });

  assert.deepEqual(started, { jobId: "job-persistence-1" });
  assert.deepEqual(startCalls, [{
    method: "getPersistenceAnalysis",
    payload: { tabId: "tab-1", options: { mode: "evtx", disabledRules: ["evtx-3"] } },
    options: { metadata: { feature: "persistence" } },
  }]);

  await promise;
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(sent, [["persistence-analysis-complete", { jobId: "job-persistence-1", result }]]);
});

test("a cancelled persistence job reports back as cancelled, not as an error", async () => {
  const err = Object.assign(new Error("Job cancelled"), { cancelled: true });
  const promise = Promise.reject(err);
  promise.catch(() => {}); // keep the rejection from going unhandled before the handler attaches

  const { handlers, sent } = register({
    db: {},
    startAnalyzerJob: () => ({ jobId: "job-persistence-2", promise }),
  });

  handlers["start-persistence-analysis"](null, { tabId: "tab-1", options: {} });
  await promise.catch(() => {});
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(sent.length, 1);
  const [channel, payload] = sent[0];
  assert.equal(channel, "persistence-analysis-complete");
  assert.equal(payload.jobId, "job-persistence-2");
  assert.equal(payload.cancelled, true);
  assert.match(payload.error, /cancelled/i);
});

test("the multi-tab scan is job-backed too, so Cancel works there as well", async () => {
  const result = { items: [], incidents: [], multiSource: true, stats: {} };
  const promise = Promise.resolve(result);
  const startCalls = [];

  const { handlers, sent } = register({
    db: {},
    startAnalyzerJob(method, payload, options) {
      startCalls.push({ method, payload, options });
      return { jobId: "job-persistence-multi", promise };
    },
  });

  const started = handlers["start-multi-source-persistence"](null, {
    tabIds: ["tab-1", "tab-2"],
    options: { mode: "auto" },
  });

  assert.deepEqual(started, { jobId: "job-persistence-multi" });
  assert.equal(startCalls[0].method, "getMultiSourcePersistence");
  assert.deepEqual(startCalls[0].payload.tabIds, ["tab-1", "tab-2"]);

  await promise;
  await new Promise((resolve) => setImmediate(resolve));
  // Same completion channel as the single-tab scan, so the modal needs one listener.
  assert.deepEqual(sent, [["persistence-analysis-complete", { jobId: "job-persistence-multi", result }]]);
});

test("multi-source preview and scan are exposed as plain handlers as well", () => {
  const calls = [];
  const { handlers } = register({
    db: {
      previewMultiSourcePersistence: (tabIds, options) => { calls.push(["preview", tabIds, options]); return { tabs: [] }; },
      getMultiSourcePersistence: (tabIds, options) => { calls.push(["get", tabIds, options]); return { items: [] }; },
    },
  });
  handlers["preview-multi-source-persistence"](null, { tabIds: ["a"], options: {} });
  handlers["get-multi-source-persistence"](null, { tabIds: ["a", "b"], options: {} });
  assert.equal(calls[0][0], "preview");
  assert.deepEqual(calls[1][1], ["a", "b"]);
});

test("a collection folder cannot be scanned until it has been chosen in a dialog", () => {
  // The renderer must not be able to name an arbitrary path and have the main process
  // read it. Authorization comes from the folder picker, nowhere else.
  const { handlers } = register({ db: {}, startAnalyzerJob: () => ({ jobId: "j", promise: Promise.resolve({}) }) });
  assert.throws(
    () => handlers["scan-kape-collection"](null, { dir: "/etc" }),
    (err) => err.code === "PATH_NOT_AUTHORIZED",
    "an unauthorized path must be refused",
  );
  assert.throws(
    () => handlers["analyze-kape-collection"](null, { dir: "/etc", options: {} }),
    (err) => err.code === "PATH_NOT_AUTHORIZED",
  );
});

test("picking a folder authorizes it, and the scan then runs as a cancellable job", async () => {
  const os = require("node:os");
  const fsx = require("node:fs");
  const pathx = require("node:path");
  const dir = fsx.mkdtempSync(pathx.join(os.tmpdir(), "kape-ipc-"));
  fsx.mkdirSync(pathx.join(dir, "C", "Windows", "System32", "Tasks"), { recursive: true });

  // Stand in for the folder picker so the authorize step can be driven from a test.
  const electronPath = require.resolve("electron");
  const realElectron = require.cache[electronPath];
  require.cache[electronPath] = {
    id: electronPath, filename: electronPath, loaded: true, exports: {
      dialog: { showOpenDialog: async () => ({ canceled: false, filePaths: [dir] }) },
    },
  };

  try {
    const result = { items: [], incidents: [], collectionScan: true, stats: {} };
    const promise = Promise.resolve(result);
    const startCalls = [];
    const { handlers, sent } = register({
      db: {},
      _activeWindow: () => null,
      startAnalyzerJob(method, payload, options) { startCalls.push({ method, payload, options }); return { jobId: "job-collection-1", promise }; },
    });

    // Before the picker runs, the very same path is refused.
    assert.throws(() => handlers["analyze-kape-collection"](null, { dir, options: {} }),
      (err) => err.code === "PATH_NOT_AUTHORIZED");

    const picked = await handlers["select-kape-collection"](null, {});
    assert.equal(picked.canceled, false);
    assert.equal(picked.dir, dir);
    assert.ok(picked.scan, "the picker returns the scan so the config screen can show what is in the folder");

    const started = handlers["analyze-kape-collection"](null, { dir, options: {} });
    assert.deepEqual(started, { jobId: "job-collection-1" });
    assert.equal(startCalls[0].method, "analyzeKapeCollection");
    assert.equal(startCalls[0].payload.dir, fsx.realpathSync(dir));

    await promise;
    await new Promise((resolve) => setImmediate(resolve));
    // Same completion channel as every other persistence scan, so Cancel and the result
    // handler in the modal are shared rather than duplicated.
    assert.deepEqual(sent, [["persistence-analysis-complete", { jobId: "job-collection-1", result }]]);
  } finally {
    if (realElectron) require.cache[electronPath] = realElectron; else delete require.cache[electronPath];
    fsx.rmSync(dir, { recursive: true, force: true });
  }
});

test("without a worker pool the handler falls back to an inline result", () => {
  const result = { items: [{ name: "Service Installed" }], incidents: [], stats: {} };
  const { handlers, sent } = register({
    db: { getPersistenceAnalysis: () => result },
    // no startAnalyzerJob
  });

  const started = handlers["start-persistence-analysis"](null, { tabId: "tab-1", options: {} });
  assert.deepEqual(started, { result });
  assert.deepEqual(sent, [], "the inline path must not emit a completion event");
});
