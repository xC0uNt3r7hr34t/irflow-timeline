// Regression test for orphaned bmc-tools output on failure/cancel (release review L6).
//
// runBmcTools mkdirs destPath, then writes manifest.json only after a clean exit. On a
// non-zero exit or cancel it rejected BEFORE the manifest write, leaving partial BMP tiles
// in an output dir that listHistory can't see (it requires a manifest) and that was never
// cleaned up — so repeated failures/cancels accumulated junk under userData. Fix removes
// the output dir on the error path before propagating.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { runBmcTools } = require("../electron/analyzers/rdp-bitmap-cache/runner");

test("runBmcTools removes the output dir on a failed extraction (no orphaned partial output)", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bmc-cleanup-"));
  const dest = path.join(dir, "extraction-out");

  // Use the Node binary as the "tool": it exits non-zero when handed bmc-tools args
  // (-s/-d/...), exercising the non-zero-exit error path deterministically without
  // depending on python3/bmc-tools being installed.
  await assert.rejects(
    () => runBmcTools({ toolPath: process.execPath, sourcePath: dir, destPath: dest }),
    /exited with code|bmc-tools/i,
    "a non-zero tool exit should reject"
  );

  assert.equal(fs.existsSync(dest), false, "failed extraction must not leave an orphaned output dir behind");
  fs.rmSync(dir, { recursive: true, force: true });
});
