/**
 * sigma/match-utils.js — shared rule-match aggregation helpers.
 *
 * Both detection engines (the in-app JS Sigma engine in index.js and the
 * Hayabusa engine in evtx-scanner/scan-runner.js) build a severity histogram
 * and sort matches by severity. Keeping that logic here guarantees the two
 * engines normalize/count severities identically — the convergence test asserts
 * against this single source of truth.
 *
 * Pure (no native deps) so it is unit-testable under plain `node --test`.
 */

// Lower number = higher severity (sorts first).
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

// The canonical severity buckets, highest-first.
const SEVERITIES = ["critical", "high", "medium", "low", "informational"];

/**
 * Count rule-level matches per severity bucket.
 * @param {Array<{level:string}>} matches
 * @returns {{critical:number,high:number,medium:number,low:number,informational:number}}
 */
function severityHistogram(matches) {
  const histogram = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const match of matches || []) {
    if (Object.prototype.hasOwnProperty.call(histogram, match.level)) {
      histogram[match.level]++;
    }
  }
  return histogram;
}

/**
 * Sort matches in place: by severity (critical first), then by match count desc.
 * Unknown levels sort last. Returns the same array for chaining.
 */
function sortMatchesBySeverity(matches) {
  return matches.sort((a, b) =>
    (SEV_ORDER[a.level] ?? 5) - (SEV_ORDER[b.level] ?? 5)
    || (b.matchCount || 0) - (a.matchCount || 0));
}

module.exports = { SEV_ORDER, SEVERITIES, severityHistogram, sortMatchesBySeverity };
