const fsp = require("fs/promises");
const path = require("path");
const { spawn } = require("child_process");

const { parseExtractionOutput } = require("./parser");
const { createExtractionManifest } = require("./manifest");

const MANIFEST_FILE_NAME = "manifest.json";

function quoteArg(value) {
  const s = String(value ?? "");
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(s)) return s;
  return `"${s.replace(/(["\\$`])/g, "\\$1")}"`;
}

function buildBmcToolsInvocation({
  toolPath,
  pythonPath = "python3",
  sourcePath,
  destPath,
  count = null,
  verbose = false,
  includeOld = false,
  collage = true,
  width = 64,
  kape = false,
} = {}) {
  if (!toolPath) throw new Error("bmc-tools path is required");
  if (!sourcePath) throw new Error("RDP bitmap cache source path is required");
  if (!destPath) throw new Error("RDP bitmap cache destination path is required");

  const isPythonScript = /\.py$/i.test(path.basename(toolPath));
  const command = isPythonScript ? pythonPath : toolPath;
  const args = isPythonScript ? [toolPath] : [];
  args.push("-s", sourcePath, "-d", destPath);
  if (Number.isFinite(count) && count > 0) args.push("-c", String(Math.floor(count)));
  if (verbose) args.push("-v");
  if (includeOld) args.push("-o");
  if (collage) args.push("-b");
  if (Number.isFinite(width) && width > 0) args.push("-w", String(Math.floor(width)));
  if (kape) args.push("-k");

  return {
    command,
    args,
    commandLine: [command, ...args].map(quoteArg).join(" "),
  };
}

async function runBmcTools(options = {}) {
  const {
    toolPath,
    sourcePath,
    destPath,
    cacheFiles = [],
    signal,
    onProgress,
  } = options;
  await fsp.mkdir(destPath, { recursive: true });
  const invocation = buildBmcToolsInvocation(options);
  const startedAt = new Date().toISOString();
  const stdout = [];
  const stderr = [];

  onProgress?.({ phase: "starting", text: "Starting bmc-tools", commandLine: invocation.commandLine });

  const exitInfo = await new Promise((resolve, reject) => {
    const child = spawn(invocation.command, invocation.args, {
      cwd: path.dirname(toolPath),
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });

    const abort = () => {
      child.kill("SIGTERM");
      reject(Object.assign(new Error("RDP bitmap cache extraction cancelled"), { cancelled: true }));
    };
    if (signal?.aborted) {
      abort();
      return;
    }
    signal?.addEventListener?.("abort", abort, { once: true });

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout.push(text);
      onProgress?.({ phase: "running", stream: "stdout", text });
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr.push(text);
      onProgress?.({ phase: "running", stream: "stderr", text });
    });
    child.on("error", reject);
    child.on("close", (code, signalName) => {
      signal?.removeEventListener?.("abort", abort);
      if (code !== 0) {
        const detail = stderr.join("").trim() || stdout.join("").trim() || signalName || "unknown error";
        reject(new Error(`bmc-tools exited with code ${code}: ${detail}`));
        return;
      }
      resolve({ code, signal: signalName });
    });
  }).catch(async (err) => {
    // On cancel or non-zero exit the manifest is never written below, so any partial BMP
    // tiles bmc-tools already wrote are orphaned — invisible to history (which requires a
    // manifest) and never garbage-collected. Best-effort remove the output dir before
    // propagating so repeated cancels/failures don't accumulate junk under userData.
    await fsp.rm(destPath, { recursive: true, force: true }).catch(() => {});
    throw err;
  });

  const completedAt = new Date().toISOString();
  onProgress?.({ phase: "parsing-output", text: "Parsing extracted bitmap output" });
  const parsedOutput = await parseExtractionOutput(destPath);
  const manifest = await createExtractionManifest({
    sourcePaths: [sourcePath],
    cacheFiles,
    parsedOutput,
    tool: { name: "bmc-tools", path: toolPath },
    invocation,
    startedAt,
    completedAt,
    outputDir: destPath,
    warnings: parsedOutput.warnings,
  });
  const manifestPath = path.join(destPath, MANIFEST_FILE_NAME);
  await fsp.writeFile(manifestPath, JSON.stringify(manifest, null, 2), "utf8");

  onProgress?.({ phase: "completed", text: "RDP bitmap cache extraction complete", imageCount: parsedOutput.summary.imageCount });
  return {
    ok: true,
    exitInfo,
    stdout: stdout.join(""),
    stderr: stderr.join(""),
    output: parsedOutput,
    manifest,
    manifestPath,
  };
}

module.exports = {
  MANIFEST_FILE_NAME,
  quoteArg,
  buildBmcToolsInvocation,
  runBmcTools,
};
