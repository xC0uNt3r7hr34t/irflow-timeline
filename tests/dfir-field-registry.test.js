const test = require("node:test");
const assert = require("node:assert/strict");

const {
  FIELD_REGISTRY,
  getCompactAliasDefinitions,
  getEvtxWellKnownDataFields,
  getFieldAliases,
  getKvExtractableFields,
  isDfirKvField,
  resolveConcept,
} = require("../electron/utils/dfir-event-fields");

test("DFIR field registry resolves analyst concepts and common source aliases", () => {
  assert.equal(resolveConcept("CommandLine"), "process.command_line");
  assert.equal(resolveConcept("IpAddress"), "network.source_ip");
  assert.equal(resolveConcept("TargetUserName"), "identity.target_user");
  assert.equal(resolveConcept("process.image"), "process.image");

  assert.deepEqual(getFieldAliases("CommandLine", { source: "kv", includeLabel: false }), [
    "CommandLine",
    "Cmdline",
    "ProcessCommandLine",
  ]);
  assert.ok(getFieldAliases("IpAddress").includes("SourceNetworkAddress"));
  assert.ok(getFieldAliases("Image", { source: "chainsaw", includeLabel: false }).includes("Event.EventData.Image"));
});

test("DFIR field registry exposes the Hayabusa KV extraction allowlist", () => {
  const fields = getKvExtractableFields();
  assert.ok(fields.includes("Cmdline"));
  assert.ok(fields.includes("Proc"));
  assert.ok(fields.includes("TargetUserName"));
  assert.ok(fields.includes("SourceNetworkAddress"));
  assert.ok(isDfirKvField("CommandLine"));
  assert.ok(isDfirKvField("TgtUser"));
  assert.equal(isDfirKvField("StorageId"), false);
});

test("DFIR field registry drives compact alias blob definitions", () => {
  const defs = getCompactAliasDefinitions();
  const labels = defs.map((def) => def.label);
  assert.ok(labels.includes("ProcessId"));
  assert.ok(labels.includes("CommandLine"));
  assert.ok(labels.includes("TargetUserName"));
  assert.ok(labels.includes("IpAddress"));
  assert.equal(new Set(labels).size, labels.length, "compact labels should be unique");
});

test("DFIR field registry keeps EVTX parser well-known fields centralized", () => {
  const wellKnown = getEvtxWellKnownDataFields();
  for (const required of ["TargetUserName", "LogonType", "IpAddress", "NewProcessName", "CommandLine", "ClientAddress"]) {
    assert.ok(wellKnown.includes(required), `${required} must be part of the EVTX well-known schema`);
  }
  assert.equal(new Set(wellKnown).size, wellKnown.length, "well-known EVTX fields should not contain duplicates");
});

test("DFIR field registry alias arrays do not contain duplicates", () => {
  for (const [concept, entry] of Object.entries(FIELD_REGISTRY)) {
    for (const key of ["aliases", "kvAliases", "chainsawAliases"]) {
      if (!Array.isArray(entry[key])) continue;
      assert.equal(new Set(entry[key]).size, entry[key].length, `${concept}.${key} has duplicates`);
    }
  }
});
