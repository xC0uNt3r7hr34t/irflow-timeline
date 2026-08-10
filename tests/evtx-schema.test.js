// Regression test for raw EVTX schema discovery skew.
//
// Bug: the EVTX parser samples the first SAMPLE_LIMIT (500) records to
// discover EventData field names, then finalizes the schema. If those first
// 500 records are skewed toward a single event type that doesn't carry the
// fields a downstream analyzer needs, those columns never enter the schema
// and every later record's values for them are silently dropped at row
// build time.
//
// Real-world failure: a Security.evtx where the first ~14k records were all
// scheduled-task / object-access events (no IpAddress, no WorkstationName,
// no TargetUserName) caused the lateral movement analyzer to fail with
// "Cannot detect source host column".
//
// Fix: union a hardcoded list of well-known Security/Sysmon EventData field
// names into the discovered set before finalizing the schema. This test
// asserts that list is comprehensive enough for the analyzers to detect
// their required columns from a Security-typical schema.

const test = require("node:test");
const assert = require("node:assert/strict");
const { getEvtxWellKnownDataFields } = require("../electron/utils/dfir-event-fields");

const wellKnown = getEvtxWellKnownDataFields();
const wellKnownSet = new Set(wellKnown);

test("EVTX schema includes the columns lateral movement requires", () => {
  // Lateral movement source-host detection set (electron/analyzers/lateral-movement/index.js).
  // The analyzer fails with "Cannot detect source host column" if NONE of these resolve.
  for (const required of ["IpAddress", "WorkstationName"]) {
    assert.ok(wellKnownSet.has(required), `EVTX_WELL_KNOWN_DATA_FIELDS must include ${required}`);
  }
  // Target user (analyzers/lateral-movement/index.js:63)
  assert.ok(wellKnownSet.has("TargetUserName"), "must include TargetUserName for user resolution");
  // Logon type
  assert.ok(wellKnownSet.has("LogonType"), "must include LogonType");
});

test("EVTX schema includes columns process tree analyzer needs for Security 4688", () => {
  // electron/analyzers/process-tree/index.js auto-detects via NewProcessId, NewProcessName, etc.
  for (const f of ["NewProcessId", "NewProcessName", "ProcessId", "CommandLine"]) {
    assert.ok(wellKnownSet.has(f), `process tree needs ${f} in default schema`);
  }
});

test("EVTX schema includes RDP / TerminalServices fields", () => {
  // ClientName / ClientAddress for 4778/4779; SessionID for 21/22/23/24/25
  for (const f of ["ClientName", "ClientAddress", "SessionID"]) {
    assert.ok(wellKnownSet.has(f), `RDP correlation needs ${f}`);
  }
});

test("EVTX schema includes share-access fields", () => {
  for (const f of ["ShareName", "RelativeTargetName", "AccessMask"]) {
    assert.ok(wellKnownSet.has(f), `share access detection needs ${f}`);
  }
});

test("EVTX schema includes Kerberos fields", () => {
  for (const f of ["ServiceName", "TicketEncryptionType"]) {
    assert.ok(wellKnownSet.has(f), `Kerberoast detection needs ${f}`);
  }
});

test("EVTX_WELL_KNOWN_DATA_FIELDS has no duplicates", () => {
  assert.equal(wellKnownSet.size, wellKnown.length, "duplicates in well-known field list");
});
