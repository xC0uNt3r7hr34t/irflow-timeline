// Triage scoring used to run mid-pipeline, but seven emitters ran *after* it:
// Lateral Pivot, Operator Host, Anomalous Hostname, Concurrent RDP, Kerberoasting,
// AS-REP Roasting, DCSync and the Sysmon RDP-client findings. Those never received a
// triageScore, so the UI rendered them as 0 and sorted them below a low-severity
// First-Seen (score 3) — a critical DCSync landed at the bottom of the triage list.
// They were also invisible to relatedFindingIds and incident clustering.
//
// Every emitter now runs before scoring, so these assertions hold for the whole
// findings array rather than just the ones the spine produced.

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

const HEADERS = [
  "TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType",
  "Channel", "Provider", "TicketEncryptionType", "ServiceName", "TicketOptions", "PreAuthType",
  "Properties", "SubjectUserName",
];

function makeStub(headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });

  // Own-query detectors filter on a single event id: WHERE cN = 'VALUE'.
  function credentialQuery(sql) {
    if (!/data\.rowid\s+as\s+_rid/i.test(sql)) return null;
    if (/\bas\s+_alltext/i.test(sql)) return null;
    const wh = sql.match(/WHERE\s+(c\d+)\s*=\s*'([^']+)'/i);
    if (!wh) return null;
    const [, filterCol, filterVal] = wh;
    const aliasPairs = [...sql.matchAll(/(data\.rowid|c\d+)\s+as\s+(_[a-zA-Z0-9_]+)/g)];
    const limitMatch = sql.match(/LIMIT\s+(\d+)/i);
    const limit = limitMatch ? Number(limitMatch[1]) : rowsByCN.length;
    return rowsByCN
      .filter((r) => String(r[filterCol] == null ? "" : r[filterCol]) === filterVal)
      .slice(0, limit)
      .map((r) => {
        const out = {};
        for (const [, srcExpr, alias] of aliasPairs) out[alias] = srcExpr === "data.rowid" ? r._rowid : r[srcExpr];
        return out;
      });
  }

  function aliasRows(sql) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    if (aliasMatches.length === 0) return null;
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
      return out;
    });
  }

  const db = {
    prepare(sql) {
      return {
        get() { if (/COUNT\(\*\)/i.test(sql)) return { cnt: rowsByCN.length || 1 }; return null; },
        all() {
          const cred = credentialQuery(sql);
          if (cred) return cred;
          const aliased = aliasRows(sql);
          if (aliased) return aliased;
          return [];
        },
      };
    },
  };

  return {
    meta: { db, headers, colMap, tabId: "lm-triage-completeness-test" },
    ctx: {
      applyStandardFilters() {},
      ensureIndex() {},
      isChainsawLogonDataset: () => false,
      isHayabusaDataset: () => false,
    },
  };
}

function krbRow(ts, user, spn, enc) {
  return {
    TimeCreated: ts, EventId: "4769", Computer: "DC01", IpAddress: "10.0.0.9",
    TargetUserName: user, LogonType: "", Channel: "Security",
    Provider: "Microsoft-Windows-Security-Auditing",
    TicketEncryptionType: enc, ServiceName: spn, TicketOptions: "0x40810000", PreAuthType: "",
    Properties: "", SubjectUserName: "",
  };
}

function logonRow(ts, src, dst, user, logonType = "3") {
  return {
    TimeCreated: ts, EventId: "4624", Computer: dst, IpAddress: src,
    TargetUserName: user, LogonType: logonType, Channel: "Security",
    Provider: "Microsoft-Windows-Security-Auditing",
    TicketEncryptionType: "", ServiceName: "", TicketOptions: "", PreAuthType: "",
    Properties: "", SubjectUserName: "",
  };
}

// A run that produces BOTH a spine finding (First Seen, low) and a late-emitter
// finding (Kerberoasting, high/critical) so their relative ranking is observable.
function mixedRun() {
  const rows = [
    // A brand-new pair to a DC via Type 9 clears the First-Seen FP guard, yielding a
    // low-severity "First Seen" finding from the spine.
    logonRow("2026-03-10T08:10:00Z", "10.0.0.50", "DC01", "CORP\\alice", "9"),
    // RC4 burst across 5 distinct SPNs -> Kerberoasting (emitted after triage today).
    krbRow("2026-03-10T08:00:00Z", "CORP\\attacker", "MSSQLSvc/sql01:1433", "0x17"),
    krbRow("2026-03-10T08:01:00Z", "CORP\\attacker", "FTPSVC/ftp01", "0x17"),
    krbRow("2026-03-10T08:02:00Z", "CORP\\attacker", "MSSQLSvc/sql02:1433", "0x17"),
    krbRow("2026-03-10T08:03:00Z", "CORP\\attacker", "FTPSVC/ftp02", "0x17"),
    krbRow("2026-03-10T08:04:00Z", "CORP\\attacker", "MSSQLSvc/sql03:1433", "0x17"),
    krbRow("2026-03-10T07:00:00Z", "CORP\\alice", "HOST/ws01", "0x12"),
    krbRow("2026-03-10T07:01:00Z", "CORP\\bob", "HOST/ws02", "0x12"),
    krbRow("2026-03-10T07:02:00Z", "CORP\\carol", "HOST/ws03", "0x12"),
    krbRow("2026-03-10T07:03:00Z", "CORP\\dave", "HOST/ws04", "0x12"),
    krbRow("2026-03-10T07:04:00Z", "CORP\\erin", "HOST/ws05", "0x12"),
    krbRow("2026-03-10T07:05:00Z", "CORP\\frank", "HOST/ws06", "0x12"),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  return getLateralMovement(meta, {}, ctx);
}

test("every finding carries a numeric triageScore", () => {
  const res = mixedRun();
  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(res.findings.length > 1, `need several findings to be meaningful, got ${res.findings.length}`);

  const unscored = res.findings.filter((f) => typeof f.triageScore !== "number");
  assert.deepEqual(
    unscored.map((f) => f.category), [],
    "these categories are emitted after scoring and never get a triageScore",
  );
});

test("every finding carries relatedFindingIds", () => {
  const res = mixedRun();
  const missing = res.findings.filter((f) => !Array.isArray(f.relatedFindingIds));
  assert.deepEqual(
    missing.map((f) => f.category), [],
    "late-emitted findings were skipped by the related-findings pass",
  );
});

test("a high-severity late finding outranks a low-severity spine finding", () => {
  const res = mixedRun();
  const krb = res.findings.find((f) => f.category === "Kerberoasting");
  const firstSeen = res.findings.find((f) => /first seen/i.test(f.category));

  assert.ok(krb, `expected a Kerberoasting finding, got ${JSON.stringify(res.findings.map((f) => f.category))}`);
  assert.ok(firstSeen, `expected a First Seen finding, got ${JSON.stringify(res.findings.map((f) => f.category))}`);

  assert.ok(
    krb.triageScore > firstSeen.triageScore,
    `Kerberoasting (${krb.severity}, score ${krb.triageScore}) must outrank First Seen (${firstSeen.severity}, score ${firstSeen.triageScore})`,
  );
  assert.ok(
    res.findings.indexOf(krb) < res.findings.indexOf(firstSeen),
    "and must sort above it",
  );
});

test("findings are ordered by triage score descending", () => {
  const res = mixedRun();
  const scores = res.findings.map((f) => f.triageScore);
  for (let i = 1; i < scores.length; i++) {
    assert.ok(
      scores[i - 1] >= scores[i],
      `findings not sorted at index ${i}: ${scores[i - 1]} then ${scores[i]} (a later stage re-sorted them)`,
    );
  }
});
