const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

test("Hayabusa CSV parser preserves RuleID in rows and summaries", async (t) => {
  let scanner;
  try {
    scanner = require("../electron/analyzers/sigma/evtx-scanner");
  } catch (err) {
    if (err?.code === "ERR_DLOPEN_FAILED") {
      t.skip("better-sqlite3 native module is not built for this Node runtime");
      return;
    }
    throw err;
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-hayabusa-parser-"));
  const csvPath = path.join(dir, "hayabusa.csv");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  fs.writeFileSync(csvPath, [
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID,MitreTactics,MitreTags,OtherTags,RecordID,Details,ExtraFieldInfo,RuleFile,RuleID,EvtxFile",
    "2026-01-01T00:00:00Z,Suspicious Logon,high,HOST1,Security,4624,TA0001,attack.initial_access,detection.test,123,User: admin ¦ Cmdline: powershell.exe -nop ¦ StorageId: noisy,,rules/suspicious.yml,rule-123,/case/Security.evtx",
  ].join("\n"));

  const parsed = await scanner._parseHayabusaCsvForTest(csvPath, null, null, {});
  assert.equal(parsed.eventRows[0].RuleID, "rule-123");
  assert.equal(parsed.eventRows[0].RuleTitle, "Suspicious Logon");
  assert.equal(parsed.eventRows[0].Cmdline, "powershell.exe -nop");
  assert.equal(parsed.eventRows[0].StorageId, undefined);
  assert.equal(parsed.ruleMatches.get("rule-123").ruleId, "rule-123");
  assert.equal(parsed.ruleMatches.get("rule-123").title, "Suspicious Logon");
});
