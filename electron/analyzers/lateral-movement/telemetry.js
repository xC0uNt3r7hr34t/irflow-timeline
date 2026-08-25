/**
 * telemetry.js — coverage/account telemetry trackers for the lateral-movement analyzer.
 *
 * Factory returning the per-host, per-user, and dataset-wide event counters and
 * their bump helpers, extracted verbatim from getLateralMovement(). The returned
 * Maps are populated during the parse + scan loops and later read by the telemetry
 * coverage computation and accounts aggregation. The closures capture only these
 * Maps (and the not-a-user guard regex), so they extract cleanly as a factory.
 *
 * @returns telemetry tracker cluster (Maps + bump helpers, underscore-named to match call sites)
 */
function createTelemetryTracker() {
  // Per-host telemetry coverage: { host -> Map<eid, count> }
  // Populated by both the logon-event loop below and the secondary scan loop (process/service/task events).
  // Used to compute per-host telemetry confidence so analysts can see which hosts have weak coverage.
  const hostTelemetry = new Map();
  const _bumpHostTelemetry = (host, eid) => {
    if (!host || !eid) return;
    if (!hostTelemetry.has(host)) hostTelemetry.set(host, new Map());
    const m = hostTelemetry.get(host);
    m.set(eid, (m.get(eid) || 0) + 1);
  };
  // Per-user event counts (for Accounts aggregation: kerberos, ntlm, explicit creds, etc.)
  // Populated raw (pre-filter) so coverage reflects what the data actually contains.
  // Also tracks the first-seen original-cased username for each upper-key so Pass 4
  // can create new accounts via _getAcct() for users that exist ONLY in raw event
  // counts (Kerberos/NTLM/4672) and never produced a graph edge.
  const userEventCounts = new Map();
  const userEventOriginalName = new Map(); // upperKey -> first-seen original casing
  // Per-user event counts SCOPED to the lateral-movement population: only events
  // that survived the exclusion filters (real non-local source, non-service /
  // non-machine account). These are the PRIMARY counts shown in the Accounts tab
  // and used for scoring/Class — so host-wide local/service 4672/4648 noise cannot
  // masquerade as lateral movement. `userEventCounts` (raw) is kept as a secondary,
  // clearly-labeled reference. By construction scoped ⊆ raw for every (user, eid).
  const userEventCountsScoped = new Map();
  // Earliest successful-logon (4624) timestamp per user across ALL events (raw,
  // pre-filter — incl. excluded local/service logons). Lets the Accounts aggregation
  // measure "failures before first success" against the account's TRUE first success
  // so a prior local success doesn't mislabel later remote retries as brute force.
  const userFirstSuccessTs = new Map();
  // Guard: reject session metadata strings that are not user accounts (EvtxECmd PD leak)
  const _notAUserEarly = /^(Session(\s*ID)?|TargetSession|Source)\s*:\s*\d+$|^\s*reason\s+code\b|^PayloadData\d/i;
  const _bumpUserEvent = (u, eid, ts) => {
    if (!u || !eid || _notAUserEarly.test(u)) return;
    const key = u.toUpperCase();
    if (!userEventOriginalName.has(key)) userEventOriginalName.set(key, u);
    if (!userEventCounts.has(key)) userEventCounts.set(key, new Map());
    const m = userEventCounts.get(key);
    m.set(eid, (m.get(eid) || 0) + 1);
    if (eid === "4624" && ts) {
      const cur = userFirstSuccessTs.get(key);
      if (!cur || ts < cur) userFirstSuccessTs.set(key, ts);
    }
  };
  // Same shape as _bumpUserEvent but only called AFTER the exclusion filters pass.
  const _bumpUserEventScoped = (u, eid) => {
    if (!u || !eid || _notAUserEarly.test(u)) return;
    const key = u.toUpperCase();
    if (!userEventCountsScoped.has(key)) userEventCountsScoped.set(key, new Map());
    const m = userEventCountsScoped.get(key);
    m.set(eid, (m.get(eid) || 0) + 1);
  };
  // Dataset-wide event counts (for top-level coverage warnings)
  const datasetEventCounts = new Map();
  const _bumpDatasetEvent = (eid) => {
    if (!eid) return;
    datasetEventCounts.set(eid, (datasetEventCounts.get(eid) || 0) + 1);
  };
  return {
    hostTelemetry, userEventCounts, userEventCountsScoped, userEventOriginalName, datasetEventCounts, userFirstSuccessTs,
    _bumpHostTelemetry, _bumpUserEvent, _bumpUserEventScoped, _bumpDatasetEvent,
  };
}

module.exports = { createTelemetryTracker };
