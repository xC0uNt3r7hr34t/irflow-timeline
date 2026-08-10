const fs = require("fs");
const crypto = require("crypto");

function sha256String(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function fileRecordWithHash(file) {
  const filePath = typeof file === "string" ? file : file.path;
  const base = typeof file === "string" ? { path: file } : { ...file };
  try {
    return { ...base, sha256: await sha256File(filePath) };
  } catch (err) {
    return { ...base, sha256: null, hashError: err.message };
  }
}

async function createExtractionManifest({
  sourcePaths = [],
  cacheFiles = [],
  parsedOutput = null,
  outputImages = null,
  tool = {},
  invocation = {},
  startedAt = null,
  completedAt = null,
  outputDir = null,
  warnings = [],
  errors = [],
  hashOutputs = true,
} = {}) {
  const inputs = [];
  for (const file of cacheFiles) inputs.push(await fileRecordWithHash(file));

  const rawOutputs = outputImages || parsedOutput?.images || [];
  const outputs = [];
  if (hashOutputs) {
    for (const image of rawOutputs) outputs.push(await fileRecordWithHash(image));
  } else {
    outputs.push(...rawOutputs.map((image) => ({ ...image, sha256: null })));
  }

  const snapshotBasis = {
    sourcePaths,
    tool,
    commandLine: invocation.commandLine || "",
    inputHashes: inputs.map((f) => [f.path, f.sha256]),
    outputHashes: outputs.map((f) => [f.path, f.sha256]),
  };

  return {
    schemaVersion: 1,
    artifactType: "rdp-bitmap-cache",
    sourcePaths,
    startedAt,
    completedAt,
    outputDir,
    tool,
    invocation,
    inputCount: inputs.length,
    outputCount: outputs.length,
    inputs,
    outputs,
    outputSummary: parsedOutput?.summary || null,
    warnings,
    errors,
    snapshotHash: sha256String(JSON.stringify(snapshotBasis)),
  };
}

module.exports = {
  sha256String,
  sha256File,
  createExtractionManifest,
};
