const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

const VALID_OUTPUT_MODES = new Set(["csv", "json", "jsonl"]);
const VALID_PROFILES = new Set([
  "minimal",
  "standard",
  "verbose",
  "all-field-info",
  "all-field-info-verbose",
  "super-verbose",
  "timesketch-minimal",
  "timesketch-verbose",
]);
const VALID_RULE_SETS = new Set(["all", "core", "core+", "core++", "et", "th"]);
const RULE_FRESH_DAYS = 30;

function countFiles(rootDir, predicate, skipDirNames = new Set()) {
  let count = 0;
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
        if (!skipDirNames.has(entry.name)) walk(fullPath);
      } else if (entry.isFile() && predicate(entry.name, fullPath)) {
        count += 1;
      }
    }
  };
  walk(rootDir);
  return count;
}

function statDirectory(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return { exists: false, isDirectory: false };
  try {
    const stat = fs.statSync(dirPath);
    return { exists: true, isDirectory: stat.isDirectory() };
  } catch {
    return { exists: false, isDirectory: false };
  }
}

function isReadableFile(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return false;
    fs.accessSync(filePath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function normalizeList(value) {
  if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
  if (typeof value === "string") return value.split(",").map((v) => v.trim()).filter(Boolean);
  return [];
}

function invalidEids(values) {
  return normalizeList(values).filter((value) => !/^\d{1,6}$/.test(value));
}

function parseDateLike(value) {
  if (!value) return null;
  const text = String(value).trim();
  if (!text) return null;
  const normalized = text.includes("T") ? text : text.replace(" ", "T");
  const parsed = Date.parse(normalized);
  return Number.isNaN(parsed) ? NaN : parsed;
}

function safeRealPath(targetPath) {
  try {
    return fs.realpathSync.native(path.resolve(targetPath));
  } catch {
    return null;
  }
}

function isInsidePath(candidatePath, rootPath) {
  const candidate = safeRealPath(candidatePath);
  const root = safeRealPath(rootPath);
  if (!candidate || !root) return false;
  if (candidate === root) return true;
  const relative = path.relative(root, candidate);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function daysSinceIso(isoValue) {
  if (!isoValue) return null;
  const parsed = Date.parse(isoValue);
  if (!Number.isFinite(parsed)) return null;
  return Math.max(0, Math.floor((Date.now() - parsed) / 86400000));
}

function validateEvtxScanRequest(dirPath, options = {}) {
  const errors = [];
  const warnings = [];
  const summary = {
    dirPath: dirPath || null,
    evtxFileCount: 0,
    customRuleCount: null,
    geoIpFileCount: null,
    outputMode: options.outputMode || "csv",
    profile: options.profile || "verbose",
    ruleSet: options.ruleSet || "all",
    presetName: options.presetName || null,
    presetSummary: options.presetSummary || null,
    selectedLevels: normalizeList(options.levels),
    selectedStatuses: normalizeList(options.statuses),
    hayabusaInstalled: !!options.hayabusaStatus?.installed,
    hayabusaVersion: options.hayabusaStatus?.version || null,
    hayabusaRuleCount: options.hayabusaRuleState?.hayabusaRuleCount ?? null,
    hayabusaRulesLastUpdate: options.hayabusaRuleState?.hayabusaRulesLastUpdate || null,
    hayabusaRulesCurrent: null,
  };

  const targetDir = statDirectory(dirPath);
  if (!targetDir.exists) {
    errors.push("EVTX directory does not exist.");
  } else if (!targetDir.isDirectory) {
    errors.push("EVTX target is not a directory.");
  } else {
    summary.evtxFileCount = countFiles(dirPath, (name) => /\.evtx$/i.test(name));
    if (summary.evtxFileCount === 0) errors.push("No .evtx files were found in the selected directory.");
  }

  if (!VALID_OUTPUT_MODES.has(summary.outputMode)) {
    errors.push(`Unsupported output mode: ${summary.outputMode}.`);
  }
  if (!VALID_PROFILES.has(summary.profile)) {
    errors.push(`Unsupported Hayabusa output profile: ${summary.profile}.`);
  }
  if (!VALID_RULE_SETS.has(summary.ruleSet)) {
    errors.push(`Unsupported rule set: ${summary.ruleSet}.`);
  }

  if (Array.isArray(options.levels) && options.levels.length === 0) {
    errors.push("At least one severity level must be selected.");
  }
  if (Array.isArray(options.statuses) && options.statuses.length === 0) {
    errors.push("At least one rule status must be selected.");
  }

  if (!options.hayabusaStatus?.installed) {
    warnings.push("Hayabusa is not installed; the first scan will install it before scanning.");
  }
  if (options.hayabusaStatus?.installed) {
    if (summary.hayabusaRuleCount === 0) {
      warnings.push("Hayabusa rules are not present; run Update Rules before scanning for best coverage.");
      summary.hayabusaRulesCurrent = false;
    } else if (summary.hayabusaRuleCount == null) {
      warnings.push("Hayabusa rule count is unknown; run Update Rules if this is a new installation.");
      summary.hayabusaRulesCurrent = null;
    }

    const ruleAgeDays = daysSinceIso(summary.hayabusaRulesLastUpdate);
    if (ruleAgeDays == null) {
      if (summary.hayabusaRuleCount > 0) warnings.push("Hayabusa rule freshness is unknown; run Update Rules if the cache may be stale.");
    } else {
      summary.hayabusaRuleAgeDays = ruleAgeDays;
      summary.hayabusaRulesCurrent = ruleAgeDays <= RULE_FRESH_DAYS;
      if (ruleAgeDays > RULE_FRESH_DAYS) {
        warnings.push(`Hayabusa rules appear ${ruleAgeDays} days old; run Update Rules for current detections.`);
      }
    }
  }

  const start = parseDateLike(options.timelineStart);
  const end = parseDateLike(options.timelineEnd);
  if (Number.isNaN(start)) warnings.push(`Timeline start may not be parsed correctly: ${options.timelineStart}`);
  if (Number.isNaN(end)) warnings.push(`Timeline end may not be parsed correctly: ${options.timelineEnd}`);
  if (Number.isFinite(start) && Number.isFinite(end) && start > end) {
    errors.push("Timeline start must be earlier than timeline end.");
  }

  const badIncludeEids = invalidEids(options.includeEids);
  const badExcludeEids = invalidEids(options.excludeEids);
  if (badIncludeEids.length > 0) errors.push(`Invalid include Event ID values: ${badIncludeEids.join(", ")}.`);
  if (badExcludeEids.length > 0) errors.push(`Invalid exclude Event ID values: ${badExcludeEids.join(", ")}.`);

  if (options.rulesPath) {
    const rulesDir = statDirectory(options.rulesPath);
    if (!rulesDir.exists) {
      errors.push("Custom rules directory does not exist.");
    } else if (!rulesDir.isDirectory) {
      errors.push("Custom rules path is not a directory.");
    } else {
      summary.customRuleCount = countFiles(options.rulesPath, (name) => /\.ya?ml$/i.test(name), new Set([".git", "config", "node_modules"]));
      if (summary.customRuleCount === 0) {
        errors.push("Custom rules directory does not contain any .yml or .yaml rule files.");
      }
    }
  }

  if (options.rulesConfig) {
    if (!isReadableFile(options.rulesConfig)) {
      errors.push("Rules config file does not exist or is not readable.");
    } else {
      if (!/\.ya?ml$/i.test(path.basename(options.rulesConfig))) {
        warnings.push("Rules config file does not use a .yml or .yaml extension.");
      }
      try {
        yaml.load(fs.readFileSync(options.rulesConfig, "utf8"));
      } catch (err) {
        errors.push(`Rules config YAML is invalid: ${err.message}`);
      }
    }
    if (!options.rulesPath) {
      warnings.push("Rules config selected without a custom rules directory; confirm the config matches the active Hayabusa rules.");
    } else if (!isInsidePath(options.rulesConfig, options.rulesPath)) {
      warnings.push("Rules config is outside the selected custom rules directory; confirm the config belongs to those rules.");
    }
  } else if (options.rulesPath && fs.existsSync(path.join(options.rulesPath, "config"))) {
    warnings.push("Custom rules directory contains a config folder, but no rules config file was selected.");
  }

  if (options.geoIpDir) {
    const geoDir = statDirectory(options.geoIpDir);
    if (!geoDir.exists || !geoDir.isDirectory) {
      warnings.push("GeoIP directory does not exist or is not a directory; GeoIP enrichment will be skipped.");
    } else {
      summary.geoIpFileCount = countFiles(options.geoIpDir, (name) => /\.mmdb$/i.test(name));
      if (summary.geoIpFileCount === 0) {
        warnings.push("GeoIP directory does not contain .mmdb files; GeoIP enrichment will be skipped.");
      }
    }
  }

  if (options.enableAllRules) {
    warnings.push("Enable ALL rules can produce noisy, deprecated, and unsupported detections.");
  }
  if (options.scanAllEvtxFiles) {
    warnings.push("Scan ALL EVTX files can take significantly longer on large collections.");
  }
  if (summary.ruleSet === "all" && !options.eidFilter) {
    warnings.push("Broad All Rules scan without EID filter may increase runtime and false positives.");
  }
  if (summary.ruleSet === "all" && !options.provenRules) {
    warnings.push("All Rules is not limited to proven rules; expect more experimental or noisy matches.");
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    summary,
  };
}

module.exports = {
  VALID_OUTPUT_MODES,
  VALID_PROFILES,
  VALID_RULE_SETS,
  validateEvtxScanRequest,
};
