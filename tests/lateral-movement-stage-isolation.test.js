// The analyzer pipeline used to run under a single try/catch, so an exception in any
// late stage (accounts aggregation, campaign clustering, RDP scoring...) discarded every
// finding the earlier stages had already produced and returned a blank result with only
// an `error` string. Each stage is now isolated: it degrades to an empty result of its
// own shape, records a warning, and the rest of the analysis survives.

const test = require("node:test");
const assert = require("node:assert/strict");

const accountsModule = require("../electron/analyzers/lateral-movement/assemble/accounts");
const rdpScoringModule = require("../electron/analyzers/lateral-movement/processing/rdp-scoring");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

const LM_INDEX = require.resolve("../electron/analyzers/lateral-movement");

// index.js destructures its stage functions at require time, so replacing an export
// after the fact has no effect on the binding it already captured. Swap the export on
// the (cached) dependency module first, then force index.js to re-evaluate so it
// destructures the stand-in.
function withFailingStage(moduleObj, key, fn) {
  const original = moduleObj[key];
  moduleObj[key] = () => { throw new Error(`synthetic ${key} failure`); };
  delete require.cache[LM_INDEX];
  try {
    const { getLateralMovement: patched } = require("../electron/analyzers/lateral-movement");
    return fn(patched);
  } finally {
    moduleObj[key] = original;
    delete require.cache[LM_INDEX];
    require("../electron/analyzers/lateral-movement");
  }
}

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
    meta: { db, headers: HEADERS, colMap, tabId: "lm-stage-isolation-test" },
    ctx: {
      applyStandardFilters() {},
      ensureIndex() {},
      isChainsawLogonDataset: () => false,
      isHayabusaDataset: () => false,
    },
  };
}

// Five failed logons from one source inside five minutes — enough to raise Brute Force
// in the spine, well before any of the stages we sabotage below.
function bruteForceRows() {
  const rows = [];
  for (let i = 0; i < 6; i++) {
    rows.push({
      TimeCreated: `2026-03-10T08:0${i}:00Z`,
      EventId: "4625",
      Computer: "DC01",
      IpAddress: "10.10.10.5",
      TargetUserName: "CORP\\attacker",
      LogonType: "3",
      Channel: "Security",
      Provider: "Microsoft-Windows-Security-Auditing",
    });
  }
  return rows;
}

test("a late-stage crash no longer discards the findings earlier stages produced", () => {
  const { meta, ctx } = makeStub(bruteForceRows());

  const res = withFailingStage(accountsModule, "aggregateAccounts",
    (analyze) => analyze(meta, {}, ctx));

  // Previously: error set, findings [] — the whole analysis lost.
  assert.ok(!res.error, `analysis should survive one bad stage, got error: ${res.error}`);
  assert.ok(
    res.findings.some((f) => /brute force/i.test(f.category) || /brute force/i.test(f.title)),
    `expected the Brute Force finding to survive, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );
  // The broken stage degrades to its empty shape...
  assert.deepEqual(res.accounts, [], "the failed stage should yield its empty shape");
  // ...and says so, so a thin result is visibly thin rather than quietly wrong.
  assert.ok(
    res.warnings.some((w) => /Accounts failed/i.test(w) && /synthetic aggregateAccounts failure/i.test(w)),
    `expected a stage warning naming the failure, got ${JSON.stringify(res.warnings)}`,
  );
});

test("an earlier-stage crash still lets the remaining stages run", () => {
  const { meta, ctx } = makeStub(bruteForceRows());

  const res = withFailingStage(rdpScoringModule, "scoreRdpSessions",
    (analyze) => analyze(meta, {}, ctx));

  assert.ok(!res.error, `analysis should survive, got error: ${res.error}`);
  assert.ok(
    res.warnings.some((w) => /RDP scoring failed/i.test(w)),
    `expected an RDP scoring warning, got ${JSON.stringify(res.warnings)}`,
  );
  // Accounts runs after RDP scoring, so it must still have produced output.
  assert.ok(Array.isArray(res.accounts), "accounts should still be an array");
  assert.ok(
    res.accounts.some((a) => /attacker/i.test(a.user || a.name || "")),
    `accounts aggregation should still have run, got ${JSON.stringify(res.accounts.map((a) => a.user || a.name))}`,
  );
});

test("a healthy run records no stage warnings", () => {
  const { meta, ctx } = makeStub(bruteForceRows());
  const res = getLateralMovement(meta, {}, ctx);
  assert.ok(!res.error);
  assert.equal(
    res.warnings.filter((w) => / failed: /.test(w)).length, 0,
    `clean run should not report stage failures, got ${JSON.stringify(res.warnings)}`,
  );
});
