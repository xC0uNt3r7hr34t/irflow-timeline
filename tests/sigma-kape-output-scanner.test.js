const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const XLSX = require("xlsx");

const {
  classifyEvtxEcmdHeaders,
  collectKapeOutputFiles,
  summarizeKapeSelection,
} = require("../electron/analyzers/sigma/kape-output-scanner");

function writeWorkbook(filePath, rows) {
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  XLSX.utils.book_append_sheet(wb, ws, "Sheet1");
  XLSX.writeFile(wb, filePath);
}

test("EvtxECmd output scanner only accepts validated event-log output files recursively", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-kape-output-"));
  const nested = path.join(dir, "nested");
  fs.mkdirSync(nested);
  fs.writeFileSync(path.join(dir, "EvtxECmd_Output.csv"), "TimeCreated,EventID,Provider,Channel,Computer,PayloadData1\n2026-01-01,4624,Microsoft-Windows-Security-Auditing,Security,HOST,Target: DOMAIN\\\\user\n");
  fs.writeFileSync(path.join(dir, "ConsoleLog.txt"), "This is a KAPE console log, not event output.\n");
  fs.writeFileSync(path.join(dir, "NTUSER.csv"), "KeyPath,ValueName,ValueData\nSoftware\\\\Test,Name,Value\n");
  writeWorkbook(path.join(nested, "Security.xlsx"), [
    ["TimeCreated", "EventID", "Provider", "Channel", "Computer", "MapDescription"],
    ["2026-01-01", "4624", "Microsoft-Windows-Security-Auditing", "Security", "HOST", "An account was successfully logged on"],
  ]);
  fs.writeFileSync(path.join(nested, "ignore.evtx"), "");

  t.after(() => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  });

  const files = collectKapeOutputFiles([dir]);
  assert.equal(files.length, 2);
  assert.deepEqual(files.map((file) => path.basename(file.path)).sort(), ["EvtxECmd_Output.csv", "Security.xlsx"]);

  const summary = summarizeKapeSelection([dir]);
  assert.equal(summary.fileCount, 2);
  assert.equal(summary.rejectedCandidateCount, 1);
  assert.ok(summary.unsupportedFileCount >= 2);
  assert.ok(summary.ignoredCount >= 3);
  assert.ok(summary.totalBytes > 0);
});

test("EvtxECmd header classifier rejects unrelated KAPE CSV headers", () => {
  assert.equal(
    classifyEvtxEcmdHeaders(["TimeCreated", "EventID", "Provider", "Channel", "Computer", "PayloadData1"]).valid,
    true,
  );
  assert.equal(
    classifyEvtxEcmdHeaders(["KeyPath", "ValueName", "ValueData"]).valid,
    false,
  );
  assert.equal(
    classifyEvtxEcmdHeaders(["Timestamp", "Computer", "Message"]).valid,
    false,
  );
});
