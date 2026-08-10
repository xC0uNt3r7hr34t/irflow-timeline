// Hayabusa subprocess lifecycle: spawn / crash / cancel + binary self-test.
//
// Drives the real subprocess code in scan-process.js against a *fake* hayabusa
// (a tiny shell script), so we exercise spawn, exit-code handling, the partial-
// output-on-crash path, and cancellation without a real binary or better-sqlite3.
// scan-process.js depends only on Node core + the pure progress parser, so this
// runs under plain `node --test`.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  runScanProcess,
  cancelScan,
  isCancelled,
  unregisterScanProc,
  isAbnormalExit,
} = require("../electron/analyzers/sigma/evtx-scanner/scan-process");
const { verifyHayabusaBinary } = require("../electron/analyzers/sigma/evtx-scanner/binary-manager");

const POSIX = process.platform !== "win32";

// A fake "hayabusa" executable: parses -o / --mode and behaves per mode.
const FAKE_HAYABUSA = `#!/bin/sh
out=""
mode="success"
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    --mode) mode="$2"; shift 2;;
    *) shift;;
  esac
done
echo "Loading detection rules..." 1>&2
case "$mode" in
  success) [ -n "$out" ] && printf 'Timestamp,RuleTitle\\n2026,Test\\n' > "$out"; exit 0;;
  crash-with-output) [ -n "$out" ] && printf 'Timestamp,RuleTitle\\npartial' > "$out"; echo "[ERROR] boom" 1>&2; exit 3;;
  crash-no-output) echo "[ERROR] cannot read evtx" 1>&2; exit 3;;
  # exec so the spawned process *becomes* sleep — killing it directly closes the
  # stderr pipe and fires 'close' immediately (no orphaned child holding the fd).
  hang) exec sleep 10;;
esac
`;

function makeWorkspace(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-scan-proc-"));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const bin = path.join(dir, "fake-hayabusa.sh");
  fs.writeFileSync(bin, FAKE_HAYABUSA, { mode: 0o755 });
  return { dir, bin };
}

function progressStub() {
  let stderr = "";
  return {
    handleChunk: (chunk) => { stderr += chunk.toString(); },
    startTicker: () => null,
    getStderr: () => stderr,
  };
}

test("runScanProcess: clean exit resolves exitCode 0 and produces output", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "result.csv");

  const result = await runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "success"],
    cwd: dir,
    scanJobId: null,
    progressParser: progressStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  assert.equal(result.cancelled, false);
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.equal(isAbnormalExit(result), false);
  assert.ok(fs.existsSync(out));
});

test("runScanProcess: crash WITH partial output resolves with the non-zero code (not a hard failure)", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "result.csv");

  const result = await runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "crash-with-output"],
    cwd: dir,
    scanJobId: null,
    progressParser: progressStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  // The key behavior: a crash that left output is NOT silently treated as success.
  assert.equal(result.cancelled, false);
  assert.equal(result.exitCode, 3);
  assert.equal(isAbnormalExit(result), true, "non-zero exit must be flagged abnormal so results read as partial");
  assert.ok(result.errorLines.some((l) => /\[ERROR\]/.test(l)), "stderr [ERROR] lines are surfaced");
  assert.ok(fs.existsSync(out), "partial output is preserved for inspection");
});

test("runScanProcess: crash with NO output rejects (hard failure)", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "never-written.csv");

  await assert.rejects(
    runScanProcess({
      hayabusaPath: bin,
      args: ["-o", out, "--mode", "crash-no-output"],
      cwd: dir,
      scanJobId: null,
      progressParser: progressStub(),
      tempFiles: [out],
      actualOutput: out,
    }),
    /exited with code 3/
  );
});

test("runScanProcess: cancellation kills the process and resolves cancelled", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "result.csv");
  const jobId = "test-cancel-job";
  t.after(() => unregisterScanProc(jobId));

  const promise = runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "hang"],
    cwd: dir,
    scanJobId: jobId,
    progressParser: progressStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  // Give the process a moment to actually start, then cancel it.
  await new Promise((r) => setTimeout(r, 150));
  const cancel = cancelScan(jobId);
  assert.equal(cancel.cancelled, true);
  assert.equal(isCancelled(jobId), true);

  const result = await promise;
  assert.equal(result.cancelled, true, "a cancelled scan resolves cancelled, not as an error or success");
});

test("runScanProcess: a non-existent binary rejects with a start failure", async (t) => {
  const { dir } = makeWorkspace(t);
  await assert.rejects(
    runScanProcess({
      hayabusaPath: path.join(dir, "does-not-exist"),
      args: [],
      cwd: dir,
      scanJobId: null,
      progressParser: progressStub(),
      tempFiles: [],
      actualOutput: null,
    }),
    /Failed to start Hayabusa/
  );
});

// ───────────────────────── binary self-test ─────────────────────────

test("verifyHayabusaBinary: accepts a binary that prints a Hayabusa banner", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir } = makeWorkspace(t);
  const good = path.join(dir, "good");
  fs.writeFileSync(good, '#!/bin/sh\necho "Hayabusa v3.9.0"\n', { mode: 0o755 });
  const out = await verifyHayabusaBinary(good);
  assert.match(out, /hayabusa/i);
});

test("verifyHayabusaBinary: rejects a binary that runs but isn't Hayabusa", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir } = makeWorkspace(t);
  const wrong = path.join(dir, "wrong");
  fs.writeFileSync(wrong, '#!/bin/sh\necho "some other tool"\nexit 0\n', { mode: 0o755 });
  await assert.rejects(verifyHayabusaBinary(wrong), /self-test failed/i);
});

test("verifyHayabusaBinary: rejects a binary that cannot execute", async (t) => {
  const { dir } = makeWorkspace(t);
  await assert.rejects(verifyHayabusaBinary(path.join(dir, "missing")), /failed to execute/i);
});
