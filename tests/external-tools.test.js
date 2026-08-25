// Tier-2 external-tool first-run fixes:
//   1. Hayabusa auto-download asset patterns (were mac-intel / linux-gnu /
//      linux-aarch64-gnu — which match NO real release asset, so download failed on
//      Intel macOS and all Linux).
//   2. RDP bmc-tools.py needs a Python interpreter; tool status now surfaces whether one
//      is available instead of failing later with `spawn python3 ENOENT`.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { hayabusaAssetPattern } = require("../electron/analyzers/sigma/evtx-scanner/binary-manager");
const { getToolStatus } = require("../electron/ipc/rdp-bitmap-cache-handlers")._private;

// ───────────────────────── Hayabusa asset patterns ─────────────────────────

test("hayabusaAssetPattern matches the real release asset names for each platform", () => {
  // Verified against the live Yamato-Security/hayabusa GitHub releases + bundle-hayabusa.sh.
  assert.equal(hayabusaAssetPattern("darwin", "arm64"), "mac-aarch64");
  assert.equal(hayabusaAssetPattern("darwin", "x64"), "mac-x64");
  assert.equal(hayabusaAssetPattern("win32", "x64"), "win-x64");
  assert.equal(hayabusaAssetPattern("win32", "arm64"), "win-aarch64");
  assert.equal(hayabusaAssetPattern("linux", "x64"), "lin-x64-gnu");
  assert.equal(hayabusaAssetPattern("linux", "arm64"), "lin-aarch64-gnu");
});

test("hayabusaAssetPattern never emits the old broken names", () => {
  const produced = [
    hayabusaAssetPattern("darwin", "x64"),
    hayabusaAssetPattern("linux", "x64"),
    hayabusaAssetPattern("linux", "arm64"),
  ];
  const stale = ["mac-intel", "linux-gnu", "linux-aarch64-gnu"];
  for (const p of produced) assert.ok(!stale.includes(p), `stale asset name leaked: ${p}`);
});

test("hayabusaAssetPattern returns null for unsupported platforms", () => {
  assert.equal(hayabusaAssetPattern("freebsd", "x64"), null);
  assert.equal(hayabusaAssetPattern("sunos", "x64"), null);
});

// ───────────────────────── RDP bmc-tools Python availability ─────────────────────────

function withTempTool(name, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-rdp-tool-"));
  try {
    const toolPath = path.join(dir, name);
    fs.writeFileSync(toolPath, "#!/usr/bin/env python3\n");
    return body(toolPath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("RDP tool status surfaces Python availability for a .py tool", () => {
  withTempTool("bmc-tools.py", (toolPath) => {
    const status = getToolStatus({ selectedToolPath: toolPath });
    assert.equal(status.installed, true);
    assert.equal(status.mode, "python-script");
    assert.equal(typeof status.pythonAvailable, "boolean");
    assert.ok(status.pythonInterpreter === null || typeof status.pythonInterpreter === "string");
    // If an interpreter is reported available, it must be named (so the runner can use it).
    if (status.pythonAvailable) assert.ok(status.pythonInterpreter);
    else assert.equal(status.pythonInterpreter, null);
  });
});

test("RDP tool status omits Python fields for a non-Python binary tool", () => {
  withTempTool("bmc-tools", (toolPath) => {
    const status = getToolStatus({ selectedToolPath: toolPath });
    assert.equal(status.installed, true);
    assert.equal(status.mode, "binary");
    assert.equal(status.pythonAvailable, undefined);
    assert.equal(status.pythonInterpreter, undefined);
  });
});
