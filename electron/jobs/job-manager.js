const path = require("path");
const { Worker } = require("worker_threads");
const { workerResourceLimits } = require("../utils/worker-heap");

class JobManager {
  constructor({ safeSend, dbg }) {
    this.safeSend = safeSend || (() => {});
    this.dbg = dbg || (() => {});
    this.jobs = new Map();
    this.queues = new Map();
    this.counter = 0;
  }

  startWorkerJob({
    type,
    worker,
    workerData = {},
    channels = {},
    metadata = {},
    concurrencyKey = null,
    maxConcurrent = 0,
    retainResult = true,
  }) {
    const jobId = workerData.jobId || `${type || "job"}_${++this.counter}_${Date.now()}`;
    const startedAt = Date.now();
    const workerPath = path.isAbsolute(worker) ? worker : path.join(__dirname, worker);
    const limit = Number.isFinite(maxConcurrent) && maxConcurrent > 0 ? Math.floor(maxConcurrent) : 0;
    const queueKey = limit > 0 ? (concurrencyKey || type || workerPath) : null;

    const job = {
      id: jobId,
      type,
      status: "queued",
      startedAt,
      updatedAt: startedAt,
      metadata,
      worker: null,
      workerPath,
      workerData: { ...workerData, jobId, type },
      channels,
      concurrencyKey: queueKey,
      maxConcurrent: limit,
      retainResult: retainResult !== false,
      result: null,
      error: null,
      _resolve: null,
      _reject: null,
    };
    this.jobs.set(jobId, job);

    const promise = new Promise((resolve, reject) => {
      job._resolve = resolve;
      job._reject = reject;
      this._schedule(job);
    }).finally(() => {
      setTimeout(() => this._prune(), 10 * 60 * 1000).unref?.();
    });

    job.promise = promise;
    return { jobId, promise };
  }

  cancel(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return { ok: false, error: "Job not found" };
    if (job.status === "queued") {
      this._removeQueued(job);
      job.status = "cancelled";
      job.updatedAt = Date.now();
      this._emitJob(job, { phase: "cancelled", done: true });
      const err = new Error("Job cancelled");
      err.cancelled = true;
      const reject = job._reject;
      reject?.(err);
      this._releaseTransientJob(job);
      return { ok: true };
    }
    if (!job.worker || job.status !== "running") return { ok: false, status: job.status };
    job.status = "cancelling";
    job.updatedAt = Date.now();
    this._emitJob(job, { phase: "cancelling" });
    try { job.worker.postMessage({ type: "cancel" }); } catch {}
    setTimeout(() => {
      if (job.worker && job.status === "cancelling") {
        try { job.worker.terminate(); } catch {}
      }
    }, 250).unref?.();
    return { ok: true };
  }

  cancelWhere(predicate) {
    let cancelled = 0;
    for (const job of this.jobs.values()) {
      if (!predicate(job)) continue;
      const result = this.cancel(job.id);
      if (result.ok) cancelled++;
    }
    return cancelled;
  }

  terminateAll() {
    for (const job of this.jobs.values()) {
      if (!job.worker) continue;
      job.status = "cancelled";
      job.updatedAt = Date.now();
      try { job.worker.terminate(); } catch {}
    }
  }

  list() {
    return [...this.jobs.values()].map((job) => this._serialize(job));
  }

  _emitJob(job, progress = {}) {
    const normalizedProgress = this._normalizeProgress(job, progress);
    const payload = {
      job: this._serialize(job),
      progress: {
        jobId: job.id,
        type: job.type,
        ...normalizedProgress,
      },
    };
    try { this.safeSend("job-progress", payload); } catch {}
  }

  _schedule(job) {
    if (!job.concurrencyKey || this._runningCount(job.concurrencyKey) < job.maxConcurrent) {
      this._startThread(job);
      return;
    }

    const queue = this.queues.get(job.concurrencyKey) || [];
    queue.push(job);
    this.queues.set(job.concurrencyKey, queue);
    this._emitJob(job, { phase: "queued", progress: 0 });
  }

  _startThread(job) {
    job.status = "running";
    job.updatedAt = Date.now();
    const thread = new Worker(job.workerPath, {
      workerData: job.workerData,
      resourceLimits: workerResourceLimits(),
    });
    job.worker = thread;

    this._emitJob(job, { phase: "started", progress: 0 });

    thread.on("message", (message = {}) => {
      if (message.type === "progress") {
        const normalizedProgress = this._normalizeProgress(job, message.progress || {});
        job.updatedAt = Date.now();
        this._emitJob(job, normalizedProgress);
        if (job.channels.progress) this.safeSend(job.channels.progress, normalizedProgress);
        return;
      }

      if (message.type === "event" && message.channel) {
        this.safeSend(message.channel, message.payload);
        return;
      }

      if (message.type === "result") {
        job.status = "completed";
        job.updatedAt = Date.now();
        if (job.retainResult) job.result = message.result;
        this._emitJob(job, { phase: "completed", progress: 100, done: true });
        if (job.channels.complete) this.safeSend(job.channels.complete, message.result);
        const resolve = job._resolve;
        resolve?.(message.result);
        this._releaseTransientJob(job);
      }
    });

    thread.on("error", (err) => {
      job.status = job.status === "cancelling" ? "cancelled" : "failed";
      job.updatedAt = Date.now();
      job.error = err?.message || String(err);
      this._emitJob(job, { phase: job.status, error: job.error, done: true });
      const reject = job._reject;
      reject?.(err);
      this._releaseTransientJob(job);
    });

    thread.on("exit", (code) => {
      job.worker = null;
      const key = job.concurrencyKey;
      const done = job.status === "completed" || job.status === "failed" || job.status === "cancelled";
      if (!done) {
        if (job.status === "cancelling" || code === 1) {
          job.status = "cancelled";
          job.updatedAt = Date.now();
          this._emitJob(job, { phase: "cancelled", done: true });
          const err = new Error("Job cancelled");
          err.cancelled = true;
          const reject = job._reject;
          reject?.(err);
          this._releaseTransientJob(job);
        } else if (code !== 0) {
          job.status = "failed";
          job.updatedAt = Date.now();
          job.error = `Worker exited with code ${code}`;
          this._emitJob(job, { phase: "failed", error: job.error, done: true });
          const reject = job._reject;
          reject?.(new Error(job.error));
          this._releaseTransientJob(job);
        }
      }
      if (key) this._drainQueue(key);
    });
  }

  _runningCount(key) {
    let count = 0;
    for (const job of this.jobs.values()) {
      if (job.concurrencyKey === key && job.worker && (job.status === "running" || job.status === "cancelling")) {
        count++;
      }
    }
    return count;
  }

  _removeQueued(job) {
    const key = job.concurrencyKey;
    if (!key) return;
    const queue = this.queues.get(key);
    if (!queue) return;
    const next = queue.filter((queued) => queued.id !== job.id);
    if (next.length) this.queues.set(key, next);
    else this.queues.delete(key);
  }

  _drainQueue(key) {
    const queue = this.queues.get(key);
    if (!queue?.length) return;
    while (queue.length > 0) {
      const next = queue[0];
      if (this._runningCount(key) >= next.maxConcurrent) break;
      queue.shift();
      if (next.status === "queued") this._startThread(next);
    }
    if (!queue.length) this.queues.delete(key);
  }

  /**
   * Query jobs return large, short-lived row windows. Their awaiting IPC handler still receives
   * the result, but the manager must not retain the fulfilled Promise/result graph for the normal
   * ten-minute job-history window.
   */
  _releaseTransientJob(job) {
    if (!job || job.retainResult) return;
    job.result = null;
    job.promise = null;
    job._resolve = null;
    job._reject = null;
    this.jobs.delete(job.id);
  }

  _normalizeProgress(job, progress = {}) {
    const metadata = job?.metadata || {};
    return {
      ...(metadata.tabId && !progress.tabId ? { tabId: metadata.tabId } : null),
      ...(metadata.fileName && !progress.fileName ? { fileName: metadata.fileName } : null),
      ...progress,
    };
  }

  _serialize(job) {
    return {
      id: job.id,
      type: job.type,
      status: job.status,
      startedAt: job.startedAt,
      updatedAt: job.updatedAt,
      metadata: job.metadata,
      error: job.error,
    };
  }

  _prune() {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [id, job] of this.jobs) {
      if (job.worker) continue;
      if (job.updatedAt < cutoff) this.jobs.delete(id);
    }
  }
}

module.exports = { JobManager };
