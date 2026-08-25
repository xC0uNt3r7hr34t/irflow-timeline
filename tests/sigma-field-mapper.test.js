const test = require("node:test");
const assert = require("node:assert/strict");

const { createFieldResolver, CHAINSAW_MAP, KV_ALIASES } = require("../electron/analyzers/sigma/field-mapper");
const { getFieldAliases } = require("../electron/utils/dfir-event-fields");

test("Sigma field resolver extracts KAPE EvtxECmd payload aliases", () => {
  const meta = {
    headers: ["RemoteHost", "PayloadData1", "PayloadData2", "MapDescription", "ExecutableInfo"],
    colMap: {
      RemoteHost: "c0",
      PayloadData1: "c1",
      PayloadData2: "c2",
      MapDescription: "c3",
      ExecutableInfo: "c4",
    },
  };
  const resolve = createFieldResolver(meta, { isEvtxECmd: true, isHayabusa: false, isChainsaw: false });
  const row = {
    RemoteHost: "10.0.0.5",
    PayloadData1: "TgtUser: alice ¦ SrcIP: 10.0.0.5 ¦ LogonType: 3",
    PayloadData2: "Cmdline: powershell.exe -nop ¦ Proc: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    MapDescription: "ServiceName: WinRM",
    ExecutableInfo: "",
  };

  assert.equal(resolve("TargetUserName", row), "alice");
  assert.equal(resolve("IpAddress", row), "10.0.0.5");
  assert.equal(resolve("CommandLine", row), "powershell.exe -nop");
  assert.equal(resolve("Image", row), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  assert.equal(resolve("ServiceName", row), "WinRM");
});

test("Sigma field resolver aliases are backed by the shared DFIR field registry", () => {
  assert.deepEqual(KV_ALIASES.CommandLine, getFieldAliases("CommandLine", { source: "kv", includeLabel: false }));
  assert.deepEqual(CHAINSAW_MAP.EventID, getFieldAliases("EventID", { source: "chainsaw", includeLabel: false }));
});

test("Sigma field resolver uses registry chainsaw aliases", () => {
  const meta = {
    headers: ["id", "Event.EventData.CommandLine", "process_name", "target_username"],
    colMap: {},
  };
  const resolve = createFieldResolver(meta, { isEvtxECmd: false, isHayabusa: false, isChainsaw: true });
  const row = {
    id: "4688",
    "Event.EventData.CommandLine": "cmd.exe /c whoami",
    process_name: "C:\\Windows\\System32\\cmd.exe",
    target_username: "alice",
  };

  assert.equal(resolve("EventID", row), "4688");
  assert.equal(resolve("CommandLine", row), "cmd.exe /c whoami");
  assert.equal(resolve("Image", row), "C:\\Windows\\System32\\cmd.exe");
  assert.equal(resolve("TargetUserName", row), "alice");
});
