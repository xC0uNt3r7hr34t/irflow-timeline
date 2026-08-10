// Async Process Inspector detection scoring helpers.
// Thin wrapper around buildDetectionMapChunked for the modal + tests.

import {
  buildDetectionMap,
  buildDetectionMapChunked,
  makeDetMapRuleKey,
} from "./process-inspector-pipeline.js";

export { makeDetMapRuleKey, buildDetectionMap, buildDetectionMapChunked };

const DEFAULT_BATCH = 2500;
/** Trees larger than this use chunked scoring with progress callbacks. */
export const PROCESS_TREE_SCORE_ASYNC_THRESHOLD = 4000;

/**
 * Score a process tree, using chunked async path for large sets.
 *
 * @param {object} data - tree result { processes }
 * @param {object} opts - disabledRules, customRules, analystProfile
 * @param {{ onProgress?: Function, signal?: { cancelled?: boolean }, batchSize?: number }} asyncOpts
 * @returns {Promise<Map>}
 */
export async function scoreProcessTree(data, opts = {}, asyncOpts = {}) {
  const total = data?.processes?.length || 0;
  const batchSize = Math.max(200, Number(asyncOpts.batchSize) || DEFAULT_BATCH);
  const onProgress = asyncOpts.onProgress;
  const signal = asyncOpts.signal;

  if (total <= PROCESS_TREE_SCORE_ASYNC_THRESHOLD) {
    const m = buildDetectionMap(data, opts);
    onProgress?.({ done: total, total, percent: 100 });
    return m;
  }

  return buildDetectionMapChunked(data, opts, {
    batchSize,
    onProgress,
    shouldCancel: () => !!(signal && signal.cancelled),
  });
}

export { DEFAULT_BATCH as PROCESS_TREE_SCORE_BATCH };
