const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const { dbg } = require("../../../logger");
const { getHayabusaRulesDir, snapshotRuleDirectory, diffRuleSnapshots } = require("../rule-diff");
const { cleanOutputLines } = require("./progress-parser");
const { findHayabusa, downloadHayabusa, getHayabusaStatus, ensureDefaultNoisyRules } = require("./binary-manager");

const UPDATE_META_FILE = "irflow-hayabusa-rule-update.json";

function getUpdateMetaPath(binPath) {
  if (!binPath) return null;
  return path.join(path.dirname(binPath), UPDATE_META_FILE);
}

function writeUpdateMeta(binPath, meta) {
  const filePath = getUpdateMetaPath(binPath);
  if (!filePath) return null;
  try {
    fs.writeFileSync(filePath, JSON.stringify(meta, null, 2), "utf8");
    return filePath;
  } catch {
    return null;
  }
}

function getHayabusaRulesUpdateMeta(binPath = null) {
  const target = binPath || findHayabusa();
  const filePath = getUpdateMetaPath(target);
  if (!filePath) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

async function updateHayabusaRules(onProgress) {
  let binPath = findHayabusa();
  if (!binPath) {
    onProgress?.("installing", "Hayabusa not found - downloading first...");
    binPath = await downloadHayabusa(onProgress);
  }

  const rulesDir = getHayabusaRulesDir(binPath);
  const beforeRules = snapshotRuleDirectory(rulesDir);
  onProgress?.("rules-summary", `Current rules before update: ${beforeRules.count.toLocaleString()}`, {
    ruleDiff: {
      rulesDir,
      beforeCount: beforeRules.count,
      currentRuleCount: beforeRules.count,
      addedCount: 0,
      removedCount: 0,
      changedCount: 0,
      lastUpdateTime: beforeRules.capturedAt,
      latestRuleMtime: beforeRules.latestRuleMtime,
    },
  });

  onProgress?.("updating", "Updating Hayabusa detection rules...");
  const commandArgs = ["update-rules"];
  const commandLine = `"${binPath}" ${commandArgs.join(" ")}`;
  dbg("HAYABUSA", `Updating rules via: ${commandLine}`);

  return new Promise((resolve, reject) => {
    const output = [];
    const emitChunk = (chunk, source) => {
      const lines = cleanOutputLines(chunk);
      if (lines.length === 0) return;
      output.push(...lines.map((line) => ({ source, line })));
      onProgress?.("rules-output", lines[lines.length - 1], { lines, source });
    };
    const proc = spawn(binPath, commandArgs, {
      cwd: path.dirname(binPath),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let timedOut = false;
    let closed = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      onProgress?.("rules-output", "Hayabusa rule update timed out after 120 seconds; stopping process...", {
        lines: ["Hayabusa rule update timed out after 120 seconds; stopping process..."],
        source: "timeout",
      });
      try { proc.kill("SIGTERM"); } catch {}
      setTimeout(() => {
        try {
          if (!closed) proc.kill("SIGKILL");
        } catch {}
      }, 2000);
    }, 120000);

    proc.stdout.on("data", (chunk) => emitChunk(chunk, "stdout"));
    proc.stderr.on("data", (chunk) => emitChunk(chunk, "stderr"));
    proc.on("error", (err) => {
      clearTimeout(timeout);
      reject(new Error(`Failed to start Hayabusa rule update: ${err.message}`));
    });
    proc.on("close", (code) => {
      closed = true;
      clearTimeout(timeout);
      const lines = output.map((entry) => entry.line);
      const status = getHayabusaStatus();
      if (code !== 0) {
        const detail = timedOut
          ? "Rule update timed out after 120 seconds"
          : (lines.slice(-6).join("\n") || `exit code ${code}`);
        dbg("HAYABUSA", `update-rules failed: ${detail}`);
        reject(new Error(`Rule update failed: ${detail}`));
        return;
      }

      dbg("HAYABUSA", `update-rules done: ${lines.slice(-10).join(" | ") || "OK"}`);
      const defaultTuning = ensureDefaultNoisyRules(binPath);
      if (defaultTuning.updated) {
        const detail = `Applied IRFlow default noisy rule tuning: ${defaultTuning.added.length} rule${defaultTuning.added.length === 1 ? "" : "s"} added to noisy_rules.txt`;
        output.push({ source: "irflow", line: detail });
        onProgress?.("rules-output", detail, { lines: [detail], source: "irflow" });
      }
      const afterRules = snapshotRuleDirectory(rulesDir);
      const ruleDiff = diffRuleSnapshots(beforeRules, afterRules);
      const summary = `Hayabusa rules updated: +${ruleDiff.addedCount.toLocaleString()} / -${ruleDiff.removedCount.toLocaleString()} / ${ruleDiff.changedCount.toLocaleString()} changed (${ruleDiff.currentRuleCount.toLocaleString()} current)`;
      const updateMeta = {
        updatedAt: new Date().toISOString(),
        command: "update-rules",
        commandLine,
        commandArgs,
        version: status.version,
        path: binPath,
        rulesDir,
        ruleDiff,
        output: lines.join("\n"),
        lines,
        lineCount: lines.length,
      };
      const updateMetaPath = writeUpdateMeta(binPath, updateMeta);
      onProgress?.("done", summary, { lines: [summary], ruleDiff });
      resolve({
        success: true,
        command: "update-rules",
        commandLine,
        commandArgs,
        version: status.version,
        path: binPath,
        rulesDir,
        ruleDiff,
        updateMetaPath,
        output: lines.join("\n"),
        lines,
        lineCount: lines.length,
      });
    });
  });
}

module.exports = {
  updateHayabusaRules,
  getHayabusaRulesUpdateMeta,
};
