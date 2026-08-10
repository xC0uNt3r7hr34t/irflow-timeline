const test = require("node:test");
const assert = require("node:assert/strict");
const { buildGroupSelectClause } = require("../electron/analyzers/sigma/scan-columns");

test("buildGroupSelectClause omits unused EvtxECmd columns", () => {
  const meta = {
    headers: ["TimeCreated", "EventId", "Channel", "Computer", "Image", "CommandLine", "PayloadData1", "PayloadData2", "UnusedCol"],
    colMap: {
      TimeCreated: "c0",
      EventId: "c1",
      Channel: "c2",
      Computer: "c3",
      Image: "c4",
      CommandLine: "c5",
      PayloadData1: "c6",
      PayloadData2: "c7",
      UnusedCol: "c8",
    },
  };
  const rules = [{
    detection: {
      selection: { "Image|endswith": "cmd.exe" },
      condition: "selection",
    },
  }];
  const sql = buildGroupSelectClause(meta, { isEvtxECmd: true, isHayabusa: false, isChainsaw: false, isRawEvtx: false }, rules, {
    tsCol: "c0",
    computerCol: "c3",
    eidCol: "c1",
    channelCol: "c2",
  });
  assert.match(sql, /c4 as \[Image\]/);
  assert.match(sql, /c6 as \[PayloadData1\]/);
  assert.doesNotMatch(sql, /UnusedCol/);
  assert.doesNotMatch(sql, /c8 as \[UnusedCol\]/);
});
