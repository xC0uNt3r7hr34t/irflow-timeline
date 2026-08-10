const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const RULE_EXTENSIONS = new Set([".yml", ".yaml"]);
const EXCLUDED_DIRS = new Set([".git", "config", "node_modules", "__MACOSX"]);

function getHayabusaRulesDir(binPath) {
  if (!binPath) return null;
  return path.join(path.dirname(binPath), "rules");
}

function toIsoTime(value) {
  if (!Number.isFinite(value) || value <= 0) return null;
  return new Date(value).toISOString();
}

function hashFile(filePath) {
  const hash = crypto.createHash("sha256");
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest("hex");
}

function snapshotRuleDirectory(rulesDir) {
  const capturedAt = new Date().toISOString();
  const files = {};
  let latestMtimeMs = 0;

  if (!rulesDir || !fs.existsSync(rulesDir)) {
    return {
      rulesDir: rulesDir || null,
      exists: false,
      capturedAt,
      count: 0,
      latestRuleMtime: null,
      snapshotHash: hashSnapshotFiles(files),
      files,
    };
  }

  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name)) walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!RULE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;

      try {
        const stat = fs.statSync(fullPath);
        const relativePath = path.relative(rulesDir, fullPath).split(path.sep).join("/");
        files[relativePath] = {
          hash: hashFile(fullPath),
          size: stat.size,
          mtimeMs: stat.mtimeMs,
        };
        if (stat.mtimeMs > latestMtimeMs) latestMtimeMs = stat.mtimeMs;
      } catch {
        // Rules can be rewritten during updates; skip transient read failures.
      }
    }
  };

  walk(rulesDir);

  return {
    rulesDir,
    exists: true,
    capturedAt,
    count: Object.keys(files).length,
    latestRuleMtime: toIsoTime(latestMtimeMs),
    snapshotHash: hashSnapshotFiles(files),
    files,
  };
}

function hashSnapshotFiles(files = {}) {
  const hash = crypto.createHash("sha256");
  for (const relativePath of Object.keys(files).sort()) {
    const entry = files[relativePath] || {};
    hash.update(relativePath);
    hash.update("\0");
    hash.update(entry.hash || "");
    hash.update("\0");
    hash.update(String(entry.size || 0));
    hash.update("\n");
  }
  return hash.digest("hex");
}

function diffRuleSnapshots(before, after, options = {}) {
  const sampleLimit = Number.isFinite(options.sampleLimit) ? Math.max(0, options.sampleLimit) : 50;
  const beforeFiles = before?.files || {};
  const afterFiles = after?.files || {};
  const beforePaths = new Set(Object.keys(beforeFiles));
  const afterPaths = new Set(Object.keys(afterFiles));
  const added = [];
  const removed = [];
  const changed = [];

  for (const filePath of afterPaths) {
    if (!beforePaths.has(filePath)) {
      added.push(filePath);
    } else if (beforeFiles[filePath]?.hash !== afterFiles[filePath]?.hash) {
      changed.push(filePath);
    }
  }

  for (const filePath of beforePaths) {
    if (!afterPaths.has(filePath)) removed.push(filePath);
  }

  added.sort((a, b) => a.localeCompare(b));
  removed.sort((a, b) => a.localeCompare(b));
  changed.sort((a, b) => a.localeCompare(b));

  return {
    rulesDir: after?.rulesDir || before?.rulesDir || null,
    beforeCount: before?.count || 0,
    currentRuleCount: after?.count || 0,
    beforeSnapshotHash: before?.snapshotHash || null,
    currentSnapshotHash: after?.snapshotHash || null,
    addedCount: added.length,
    removedCount: removed.length,
    changedCount: changed.length,
    addedRules: added.slice(0, sampleLimit),
    removedRules: removed.slice(0, sampleLimit),
    changedRules: changed.slice(0, sampleLimit),
    addedOverflow: Math.max(0, added.length - sampleLimit),
    removedOverflow: Math.max(0, removed.length - sampleLimit),
    changedOverflow: Math.max(0, changed.length - sampleLimit),
    lastUpdateTime: after?.capturedAt || null,
    latestRuleMtime: after?.latestRuleMtime || null,
  };
}

module.exports = {
  diffRuleSnapshots,
  getHayabusaRulesDir,
  snapshotRuleDirectory,
};
