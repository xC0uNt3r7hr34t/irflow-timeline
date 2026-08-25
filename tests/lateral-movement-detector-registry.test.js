// The renderer used to hand-maintain the event-id list and always pass it, so several
// shipped detectors could never fire in production even though their unit tests passed
// (those call the analyzer directly with an explicit eventIds list). The registry makes
// the enabled detectors decide which events are fetched.
//
// Guards two things:
//   1. registry invariants — the derived lists stay consistent with the declarations
//   2. end-to-end — a run that specifies no eventIds actually fires the detectors the
//      renderer's old list starved: Admin Share Access (5140/5145) and 4771 brute force.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  DETECTORS, SPINE_EVENT_IDS, PREVIEW_EVENT_IDS, OWN_QUERY_EVENT_IDS,
  SCAN_FAMILY_IDS, resolveSpineEventIds, buildDetectorCatalog,
} = require("../electron/analyzers/lateral-movement/detector-registry");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

// The event ids the renderer's LM_RULES table produced. Kept here as the regression
// anchor: these are exactly the ids that used to reach the analyzer.
const LEGACY_UI_EVENT_IDS = [
  "1149", "21", "22", "23", "24", "25", "39", "40", "4624", "4625", "4648",
  "4672", "4778", "4779", "4634", "4647", "4688", "1", "7045", "4697", "4698",
];

test("registry invariants hold", () => {
  const ids = DETECTORS.map((d) => d.id);
  assert.equal(new Set(ids).size, ids.length, "detector ids must be unique");

  for (const d of DETECTORS) {
    const modes = ["spineEids", "scanFamilies", "ownQueryEids"].filter((k) => d[k]);
    assert.equal(modes.length, 1, `${d.id} must declare exactly one acquisition mode, got ${modes.join()}`);
    assert.ok(d.label, `${d.id} needs a label`);
    assert.ok(d.uiGroup, `${d.id} needs a uiGroup`);
  }

  // Every declared spine id must appear in the derived union.
  for (const d of DETECTORS) {
    for (const eid of d.spineEids || []) {
      assert.ok(SPINE_EVENT_IDS.includes(eid), `${eid} (${d.id}) missing from SPINE_EVENT_IDS`);
    }
  }

  // The preview must never under-report relative to what the analysis will fetch.
  for (const eid of [...SPINE_EVENT_IDS, ...OWN_QUERY_EVENT_IDS]) {
    assert.ok(PREVIEW_EVENT_IDS.includes(eid), `${eid} is analysed but not previewed`);
  }

  // Scan families must match the table process-service-scan.js actually queries.
  const ACTUAL_FAMILIES = ["process", "service", "task", "namedpipe", "createthread", "openprocess", "wmisub"];
  for (const fam of SCAN_FAMILY_IDS) {
    assert.ok(ACTUAL_FAMILIES.includes(fam), `unknown scan family "${fam}" — process-service-scan.js has no such family`);
  }
});

test("the registry covers every event id the legacy renderer list requested", () => {
  // Process/service/task ids are served by the scan families, not the spine.
  const scanServed = new Set(["4688", "1", "7045", "4697", "4698"]);
  for (const eid of LEGACY_UI_EVENT_IDS) {
    if (scanServed.has(eid)) continue;
    assert.ok(SPINE_EVENT_IDS.includes(eid), `regression: ${eid} was requested before but is no longer covered`);
  }
});

test("the registry restores the event ids the renderer list omitted", () => {
  // These are the starved ones. Each must now be fetched by default.
  for (const eid of ["5140", "5145", "4776", "4771", "20", "32", "33", "34", "35", "4769"]) {
    assert.ok(!LEGACY_UI_EVENT_IDS.includes(eid), `test premise wrong: ${eid} was not actually missing`);
    assert.ok(SPINE_EVENT_IDS.includes(eid), `${eid} still missing from the default spine set`);
  }
});

test("disabling a detector only drops event ids nothing else claims", () => {
  // 4625 is shared by bruteforce, password-spray and cred-compromise.
  const withoutBrute = resolveSpineEventIds(["bruteforce"]);
  assert.ok(withoutBrute.includes("4625"), "4625 must survive — password spray still needs it");
  assert.ok(!withoutBrute.includes("4771"), "4771 is exclusive to brute force and should drop");

  // 5140/5145 are exclusive to admin share.
  const withoutShare = resolveSpineEventIds(["adminshare"]);
  assert.ok(!withoutShare.includes("5140"));
  assert.ok(!withoutShare.includes("5145"));

  // Core detectors cannot be switched off.
  const disableEverything = resolveSpineEventIds(DETECTORS.map((d) => d.id));
  assert.ok(disableEverything.includes("4624"), "the logon graph is core and must always be fetched");

  // Custom rule ids are additive.
  assert.ok(resolveSpineEventIds([], ["9999"]).includes("9999"));
});

test("an explicit eventIds list is still honored (tests / restored sessions)", () => {
  const catalog = buildDetectorCatalog();
  assert.ok(catalog.length === DETECTORS.length);
  assert.ok(catalog.every((d) => Array.isArray(d.eventIds)));
});

// ── End-to-end: the previously-dead detectors now fire on a default run ──────────

const HEADERS = [
  "TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType",
  "Channel", "Provider", "ShareName", "RelativeTargetName", "SubStatus",
];

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
        all(...args) {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) {
            // Honour the IN (...) filter so the test reflects what the analyzer asked for.
            const eids = new Set(args.map(String));
            const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
            const eidCol = colMap.EventId;
            return rowsByCN
              .filter((r) => eids.size === 0 || eids.has(String(r[eidCol])))
              .map((r) => {
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
    meta: { db, headers: HEADERS, colMap, tabId: "lm-registry-test" },
    ctx: {
      applyStandardFilters() {},
      ensureIndex() {},
      isChainsawLogonDataset: () => false,
      isHayabusaDataset: () => false,
    },
  };
}

function row(eid, opts = {}) {
  return {
    TimeCreated: opts.ts || "2026-03-10T08:00:00Z",
    EventId: eid,
    Computer: opts.computer || "FS01",
    IpAddress: opts.ip || "10.10.10.5",
    TargetUserName: opts.user != null ? opts.user : "CORP\\attacker",
    LogonType: opts.logonType || "3",
    Channel: "Security",
    Provider: "Microsoft-Windows-Security-Auditing",
    ShareName: opts.shareName || "",
    RelativeTargetName: opts.relativeTargetName || "",
    SubStatus: opts.subStatus || "",
  };
}

test("Admin Share Access fires on a run that specifies no eventIds", () => {
  const rows = [
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3" }),
    row("5140", { ts: "2026-03-10T08:00:05Z", shareName: "\\\\*\\ADMIN$" }),
    row("5145", { ts: "2026-03-10T08:00:06Z", shareName: "\\\\*\\IPC$", relativeTargetName: "svcctl" }),
  ];
  const { meta, ctx } = makeStub(rows);

  // No eventIds — exactly what the renderer will now send.
  const res = getLateralMovement(meta, {}, ctx);
  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(
    res.findings.some((f) => /admin share/i.test(f.category)),
    `expected an Admin Share Access finding, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );

  // ...and is still starved when the legacy list is passed explicitly, which is the bug.
  const { meta: m2, ctx: c2 } = makeStub(rows);
  const legacy = getLateralMovement(m2, { eventIds: LEGACY_UI_EVENT_IDS }, c2);
  assert.ok(
    !legacy.findings.some((f) => /admin share/i.test(f.category)),
    "sanity: the legacy renderer list should not surface share findings",
  );
});

test("4771 Kerberos brute force fires on a run that specifies no eventIds", () => {
  const rows = [];
  for (let i = 0; i < 6; i++) {
    rows.push(row("4771", { ts: `2026-03-10T09:0${i}:00Z`, computer: "DC01", subStatus: "0x18" }));
  }
  const { meta, ctx } = makeStub(rows);
  const res = getLateralMovement(meta, {}, ctx);

  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(
    res.findings.some((f) => /brute force/i.test(f.category)),
    `expected a Kerberos Brute Force finding, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );
});
