const test = require("node:test");
const assert = require("node:assert/strict");

const { usnSourceInfoToString } = require("../electron/parsers/usn");

test("SourceInfo 0 = user-driven (empty string, so the analyzer's userCond keeps it)", () => {
  assert.strictEqual(usnSourceInfoToString(0), "");
});

test("SourceInfo decodes each USN_SOURCE_* flag", () => {
  assert.strictEqual(usnSourceInfoToString(0x00000001), "DataManagement");
  assert.strictEqual(usnSourceInfoToString(0x00000002), "AuxiliaryData");
  assert.strictEqual(usnSourceInfoToString(0x00000004), "ReplicationManagement");
  assert.strictEqual(usnSourceInfoToString(0x00000008), "ClientReplicationManagement");
});

test("SourceInfo decodes combined flags in canonical order", () => {
  assert.strictEqual(usnSourceInfoToString(0x00000005), "DataManagement|ReplicationManagement");
  assert.strictEqual(usnSourceInfoToString(0x0000000f), "DataManagement|AuxiliaryData|ReplicationManagement|ClientReplicationManagement");
});

test("a non-zero SourceInfo is always non-empty (so it is excluded from user-driven volume)", () => {
  for (const v of [0x1, 0x2, 0x4, 0x8, 0x5, 0xf]) {
    assert.ok(usnSourceInfoToString(v).length > 0, `0x${v.toString(16)} should be non-empty`);
  }
});
