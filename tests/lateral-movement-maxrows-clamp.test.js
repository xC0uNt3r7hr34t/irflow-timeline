// maxRows arrives from the renderer and is interpolated directly into the LIMIT clause
// (it cannot be a bound parameter in the prepared-statement shape the analyzer uses), so
// it must be coerced and range-clamped before it ever reaches SQL. Without this, a
// renderer-supplied string lands verbatim in the query text.

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

const HEADERS = ["TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType", "Channel", "Provider"];

// Captures the SQL text of the spine query so we can assert on the emitted LIMIT.
function makeStub(rows) {
  const colMap = {};
  HEADERS.forEach((h, i) => { colMap[h] = `c${i}`; });
  const seenSql = [];

  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    HEADERS.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });

  const db = {
    prepare(sql) {
      seenSql.push(sql);
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

  const meta = { db, headers: HEADERS, colMap, tabId: "lm-clamp-test" };
  const ctx = {
    applyStandardFilters() {},
    ensureIndex() {},
    isChainsawLogonDataset: () => false,
    isHayabusaDataset: () => false,
  };
  return { meta, ctx, seenSql };
}

const ROW = {
  TimeCreated: "2026-03-10T08:00:00Z", EventId: "4624", Computer: "HOST01",
  IpAddress: "10.10.10.5", TargetUserName: "CORP\\attacker", LogonType: "3",
  Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing",
};

// The spine query is the one selecting bracketed aliases from data.
function spineLimit(seenSql) {
  const spine = seenSql.find((s) => /FROM\s+data/i.test(s) && /\bas\s+\[/.test(s) && /\bLIMIT\b/i.test(s));
  assert.ok(spine, "expected a spine SELECT with a LIMIT");
  const m = spine.match(/LIMIT\s+(\S+)\s*$/i);
  assert.ok(m, `could not read LIMIT from: ${spine.slice(-80)}`);
  return m[1];
}

function runWith(maxRows) {
  const { meta, ctx, seenSql } = makeStub([ROW]);
  const res = getLateralMovement(meta, { maxRows }, ctx);
  return { res, limit: spineLimit(seenSql) };
}

test("a SQL-injection payload in maxRows never reaches the query", () => {
  const { res, limit } = runWith("1; DROP TABLE data;--");
  assert.match(limit, /^\d+$/, `LIMIT must be a bare integer, got ${limit}`);
  assert.equal(limit, "500000", "an unparseable maxRows falls back to the default");
  assert.ok(!res.error, `analyzer errored: ${res.error}`);
});

test("maxRows is coerced to an integer and range-clamped", () => {
  assert.equal(runWith(250000).limit, "250000", "a sane value passes through");
  assert.equal(runWith("250000").limit, "250000", "numeric strings are accepted");
  assert.equal(runWith(12.7).limit, "1000", "fractions floor, then clamp to the floor bound");
  assert.equal(runWith(0).limit, "500000", "zero falls back rather than returning nothing");
  assert.equal(runWith(-5).limit, "500000", "negatives fall back");
  assert.equal(runWith(NaN).limit, "500000", "NaN falls back");
  assert.equal(runWith(undefined).limit, "500000", "omitted uses the default");
  assert.equal(runWith(99999999).limit, "2000000", "absurd values clamp to the ceiling");
});
