// Chain seeding used to stop at the first 100 raw chains. Because the hop list is in
// ascending time order, that meant only the earliest activity in a busy dataset ever
// produced chains — every later pivot was silently invisible, which also zeroed the
// Lateral Pivot findings and the chain-membership triage bonus for that activity.
//
// Chains are now capped after dedup and ranked by length then frequency, so the
// longest and most repeated chains survive regardless of when they occurred.

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

const HEADERS = ["TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType", "Channel", "Provider"];

function makeStub(rows) {
  const colMap = {};
  HEADERS.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    HEADERS.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });
  const db = {
    prepare(sql) {
      return {
        get() { if (/COUNT\(\*\)/i.test(sql)) return { cnt: rowsByCN.length || 1 }; return null; },
        all() {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) {
            const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
            return rowsByCN.map((r) => {
              const out = { _rowid: r._rowid };
              for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
              return out;
            });
          }
          return [];
        },
      };
    },
  };
  return {
    meta: { db, headers: HEADERS, colMap, tabId: "lm-chain-cap-test" },
    ctx: {
      applyStandardFilters() {},
      ensureIndex() {},
      isChainsawLogonDataset: () => false,
      isHayabusaDataset: () => false,
    },
  };
}

function hop(ts, src, dst, user) {
  return {
    TimeCreated: ts, EventId: "4624", Computer: dst, IpAddress: src,
    TargetUserName: user, LogonType: "3", Channel: "Security",
    Provider: "Microsoft-Windows-Security-Auditing",
  };
}

// Pad the timeline with many short, distinct 2-hop chains, then put the single longest
// chain at the very END. Under the old seed-time cap the long one was never reached.
function chainRows() {
  const rows = [];
  const t = (mins) => new Date(Date.UTC(2026, 2, 10, 0, 0, 0) + mins * 60000).toISOString().replace(".000Z", "Z");

  let minute = 0;
  for (let i = 0; i < 140; i++) {
    const user = `CORP\\user${i}`;
    // Each pair is distinct so they dedup into separate chains.
    rows.push(hop(t(minute), `10.1.${Math.floor(i / 250)}.${i % 250}`, `HOPA${i}`, user));
    rows.push(hop(t(minute + 1), `HOPA${i}`, `HOPB${i}`, user));
    minute += 5;
  }

  // The interesting one, last in time: a 4-hop pivot by one operator.
  const late = minute + 60;
  rows.push(hop(t(late), "10.9.9.9", "PIVOT1", "CORP\\operator"));
  rows.push(hop(t(late + 2), "PIVOT1", "PIVOT2", "CORP\\operator"));
  rows.push(hop(t(late + 4), "PIVOT2", "PIVOT3", "CORP\\operator"));
  rows.push(hop(t(late + 6), "PIVOT3", "DC01", "CORP\\operator"));
  return rows;
}

test("the longest chain survives even when it occurs last", () => {
  const { meta, ctx } = makeStub(chainRows());
  const res = getLateralMovement(meta, {}, ctx);

  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(res.chains.length > 0, "expected chains");

  const deepest = res.chains.reduce((a, b) => (b.hops > a.hops ? b : a));
  assert.ok(
    deepest.hops >= 4,
    `the 4-hop late chain should survive the cap, deepest kept was ${deepest.hops} hops`,
  );
  assert.ok(
    deepest.path.includes("DC01") && deepest.path.includes("PIVOT2"),
    `expected the operator pivot path, got ${JSON.stringify(deepest.path)}`,
  );
});

test("chains are ranked longest-first and the cap is reported", () => {
  const { meta, ctx } = makeStub(chainRows());
  const res = getLateralMovement(meta, {}, ctx);

  // Ranking: the first chain must be at least as long as the last.
  assert.ok(
    res.chains[0].hops >= res.chains[res.chains.length - 1].hops,
    "chains should be ordered longest-first",
  );
  assert.ok(res.chains.length <= 500, `cap not applied, got ${res.chains.length} chains`);

  // stats.longestChain must reflect the real deepest chain, not a truncation artifact.
  if (res.stats && typeof res.stats.longestChain === "number") {
    assert.ok(res.stats.longestChain >= 4, `stats.longestChain should see the 4-hop chain, got ${res.stats.longestChain}`);
  }
});
