const test = require("node:test");
const assert = require("node:assert/strict");

const registerQueryHandlers = require("../electron/ipc/query-handlers");

test("process tree start IPC returns a job id and emits completion with that id", async () => {
  const handlers = {};
  const sent = [];
  const result = { processes: [{ key: "p1" }], roots: ["p1"] };
  const promise = Promise.resolve(result);
  const startCalls = [];

  registerQueryHandlers(
    (channel, handler) => { handlers[channel] = handler; },
    (channel, payload) => { sent.push([channel, payload]); },
    {
      db: {},
      startAnalyzerJob(method, payload, options) {
        startCalls.push({ method, payload, options });
        return { jobId: "job-process-tree-1", promise };
      },
    },
  );

  const started = handlers["start-process-tree"](null, {
    tabId: "tab-1",
    options: { maxRows: 50 },
  });

  assert.deepEqual(started, { jobId: "job-process-tree-1" });
  assert.deepEqual(startCalls, [{
    method: "getProcessTree",
    payload: { tabId: "tab-1", options: { maxRows: 50 } },
    options: { metadata: { feature: "processTree" } },
  }]);

  await promise;
  await new Promise((resolve) => setImmediate(resolve));

  assert.deepEqual(sent, [[
    "process-tree-complete",
    { jobId: "job-process-tree-1", result },
  ]]);
});
