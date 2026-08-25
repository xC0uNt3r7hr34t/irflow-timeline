/**
 * extract-abort.js — per-job cooperative cancel for AI history extraction.
 *
 * Each extract run gets its own abort token so concurrent main-thread fallbacks
 * (profile + triage) do not cancel one another (G1).
 */

class AiHistoryExtractAbortedError extends Error {
  constructor() {
    super("AI history extraction canceled");
    this.name = "AiHistoryExtractAbortedError";
    this.canceled = true;
  }
}

/** @type {Map<string, { aborted: boolean }>} */
const _tokens = new Map();

/**
 * @param {string} [jobId] — optional stable id (e.g. worker job id)
 * @returns {{ jobId: string, reset: () => void, abort: () => void, checkAbort: () => void, dispose: () => void }}
 */
function createAiHistoryExtractAbortToken(jobId) {
  const id = jobId || `ai-extract-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const state = { aborted: false };
  _tokens.set(id, state);
  return {
    jobId: id,
    reset() { state.aborted = false; },
    abort() { state.aborted = true; },
    checkAbort() {
      if (state.aborted) throw new AiHistoryExtractAbortedError();
    },
    dispose() { _tokens.delete(id); },
  };
}

/** Cancel one job or every active token when jobId omitted. */
function requestAiHistoryExtractAbort(jobId) {
  if (jobId) {
    const state = _tokens.get(jobId);
    if (state) state.aborted = true;
    return;
  }
  for (const state of _tokens.values()) state.aborted = true;
}

function isAiHistoryExtractAborted(jobId) {
  if (jobId) return !!_tokens.get(jobId)?.aborted;
  for (const state of _tokens.values()) {
    if (state.aborted) return true;
  }
  return false;
}

/** @deprecated Prefer per-job tokens; cancels all active tokens. */
function resetAiHistoryExtractAbort() {
  for (const state of _tokens.values()) state.aborted = false;
}

function throwIfAiHistoryExtractAborted(jobId) {
  if (isAiHistoryExtractAborted(jobId)) throw new AiHistoryExtractAbortedError();
}

module.exports = {
  AiHistoryExtractAbortedError,
  createAiHistoryExtractAbortToken,
  requestAiHistoryExtractAbort,
  isAiHistoryExtractAborted,
  resetAiHistoryExtractAbort,
  throwIfAiHistoryExtractAborted,
};
