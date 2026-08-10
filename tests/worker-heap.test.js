"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { JobManager } = require("../electron/jobs/job-manager");
const { workerResourceLimits, workerHeapMb, DEFAULT_WORKER_HEAP_MB } = require("../electron/utils/worker-heap");

test("workerResourceLimits sets a generous old-space cap for worker threads", () => {
  const prev = process.env.TLE_WORKER_HEAP_MB;
  delete process.env.TLE_WORKER_HEAP_MB;
  try {
    assert.deepEqual(workerResourceLimits(), { maxOldGenerationSizeMb: DEFAULT_WORKER_HEAP_MB });
    assert.equal(workerHeapMb(), DEFAULT_WORKER_HEAP_MB);
  } finally {
    if (prev != null) process.env.TLE_WORKER_HEAP_MB = prev;
    else delete process.env.TLE_WORKER_HEAP_MB;
  }
});

test("TLE_WORKER_HEAP_MB overrides default worker heap", () => {
  const prev = process.env.TLE_WORKER_HEAP_MB;
  process.env.TLE_WORKER_HEAP_MB = "12288";
  try {
    assert.deepEqual(workerResourceLimits(), { maxOldGenerationSizeMb: 12288 });
  } finally {
    if (prev != null) process.env.TLE_WORKER_HEAP_MB = prev;
    else delete process.env.TLE_WORKER_HEAP_MB;
  }
});

test("JobManager starts workers with resourceLimits instead of invalid execArgv heap flags", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-heap-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "ok-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort } = require("worker_threads");',
      'parentPort.postMessage({ type: "result", result: { ok: true } });',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { promise } = manager.startWorkerJob({ type: "heap-smoke", worker: workerPath });
  assert.deepEqual(await promise, { ok: true });
});

test("JobManager delivers transient results without retaining the completed payload", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-transient-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "result-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort } = require("worker_threads");',
      'parentPort.postMessage({ type: "result", result: { rows: ["large-query-payload"] } });',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const { jobId, promise } = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    retainResult: false,
  });

  assert.deepEqual(await promise, { rows: ["large-query-payload"] });
  assert.equal(manager.jobs.has(jobId), false);
  assert.equal(manager.list().some((job) => job.id === jobId), false);
});

test("JobManager queues workers when a concurrency limit is reached", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-queue-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "delay-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort, workerData } = require("worker_threads");',
      'setTimeout(() => parentPort.postMessage({ type: "result", result: { id: workerData.id } }), 40);',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const first = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "first" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });
  const second = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "second" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });

  const statuses = new Map(manager.list().map((job) => [job.id, job.status]));
  assert.equal(statuses.get(first.jobId), "running");
  assert.equal(statuses.get(second.jobId), "queued");

  assert.deepEqual(await first.promise, { id: "first" });
  assert.deepEqual(await second.promise, { id: "second" });
  assert.equal(manager.list().find((job) => job.id === second.jobId)?.status, "completed");
});

test("JobManager can cancel a queued worker before it starts", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-worker-queue-cancel-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const workerPath = path.join(tmp, "delay-worker.js");
  fs.writeFileSync(
    workerPath,
    [
      '"use strict";',
      'const { parentPort, workerData } = require("worker_threads");',
      'setTimeout(() => parentPort.postMessage({ type: "result", result: { id: workerData.id } }), 40);',
      "",
    ].join("\n"),
  );

  const manager = new JobManager({ safeSend: () => {}, dbg: () => {} });
  const first = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "first" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });
  const second = manager.startWorkerJob({
    type: "query",
    worker: workerPath,
    workerData: { id: "second" },
    concurrencyKey: "query",
    maxConcurrent: 1,
  });

  assert.deepEqual(manager.cancel(second.jobId), { ok: true });
  await assert.rejects(second.promise, /Job cancelled/);
  assert.deepEqual(await first.promise, { id: "first" });
  assert.equal(manager.list().find((job) => job.id === second.jobId)?.status, "cancelled");
});
