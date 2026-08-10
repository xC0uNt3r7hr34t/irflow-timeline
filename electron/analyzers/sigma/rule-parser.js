/**
 * sigma/rule-parser.js — Sigma YAML Rule Parser
 *
 * Parses Sigma YAML rules into normalized JSON objects.
 * Handles single rules and multi-document YAML files.
 */

const yaml = require("js-yaml");
const fs = require("fs");
const path = require("path");

function normalizeRuleDoc(doc, filePath = "", docIndex = 0) {
  if (!doc || !doc.detection || !doc.title) return null;

  // Normalize logsource
  const logsource = doc.logsource || {};
  const tags = (doc.tags || []).map(t => String(t).toLowerCase());

  // Extract MITRE technique IDs from tags
  const mitre = tags
    .filter(t => t.startsWith("attack.t"))
    .map(t => t.replace("attack.", "").toUpperCase());

  // Extract MITRE tactics from tags
  const tactics = tags
    .filter(t => t.startsWith("attack.") && !t.startsWith("attack.t"))
    .map(t => t.replace("attack.", ""));

  return {
    id: doc.id || "",
    title: doc.title || "",
    status: doc.status || "test",
    level: doc.level || "medium",
    description: doc.description || "",
    author: doc.author || "",
    date: doc.date || "",
    modified: doc.modified || "",
    logsource: {
      product: logsource.product || "",
      category: logsource.category || "",
      service: logsource.service || "",
    },
    detection: doc.detection,
    falsepositives: doc.falsepositives || [],
    tags,
    mitre,
    tactics,
    references: doc.references || [],
    _filePath: filePath,
    _fileName: filePath ? path.basename(filePath) : "",
    _docIndex: docIndex,
  };
}

/**
 * Parse a Sigma YAML string into all normalized rule objects.
 * @param {string} content - YAML content
 * @param {string} [filePath] - Source file path for metadata
 * @returns {{rules: object[], report: object}}
 */
function parseRulesDetailed(content, filePath = "") {
  const report = {
    filesScanned: filePath ? 1 : 0,
    documentsScanned: 0,
    parsed: 0,
    skipped: 0,
    skippedRules: [],
    parseErrors: [],
  };
  try {
    const docs = yaml.loadAll(content);
    report.documentsScanned = docs.length;
    const rules = [];
    for (let i = 0; i < docs.length; i++) {
      const rule = normalizeRuleDoc(docs[i], filePath, i);
      if (rule) {
        rules.push(rule);
        report.parsed++;
      } else {
        report.skipped++;
        report.skippedRules.push({
          type: "skipped-rule",
          value: "invalid_sigma_document",
          filePath,
          fileName: filePath ? path.basename(filePath) : "",
          docIndex: i,
          detail: "YAML document is missing required title or detection fields",
        });
      }
    }
    return { rules, report };
  } catch (err) {
    report.parseErrors.push({
      type: "parse-error",
      value: "yaml_parse_error",
      filePath,
      fileName: filePath ? path.basename(filePath) : "",
      detail: err.message || String(err),
    });
    report.skipped++;
    return { rules: [], report };
  }
}

/**
 * Parse a single Sigma YAML string into the first valid normalized rule object.
 * Kept for backward compatibility with older callers.
 */
function parseRule(content, filePath = "") {
  return parseRulesDetailed(content, filePath).rules[0] || null;
}

function mergeReports(target, source) {
  target.filesScanned += source.filesScanned || 0;
  target.documentsScanned += source.documentsScanned || 0;
  target.parsed += source.parsed || 0;
  target.skipped += source.skipped || 0;
  target.skippedRules.push(...(source.skippedRules || []));
  target.parseErrors.push(...(source.parseErrors || []));
}

/**
 * Parse all Sigma YAML files in a directory (recursively).
 * @param {string} dirPath - Directory path
 * @param {Function} [onProgress] - Progress callback: (parsed, total)
 * @returns {Array} Array of parsed rules
 */
function parseDirectory(dirPath, onProgress) {
  return parseDirectoryDetailed(dirPath, onProgress).rules;
}

function parseDirectoryDetailed(dirPath, onProgress) {
  const rules = [];
  const files = [];
  const report = {
    filesScanned: 0,
    documentsScanned: 0,
    parsed: 0,
    skipped: 0,
    skippedRules: [],
    parseErrors: [],
  };

  // Collect all .yml/.yaml files recursively
  const walk = (dir) => {
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (/\.ya?ml$/i.test(entry.name)) files.push(full);
      }
    } catch (_) { /* skip unreadable directories */ }
  };
  walk(dirPath);

  for (let i = 0; i < files.length; i++) {
    try {
      const content = fs.readFileSync(files[i], "utf8");
      const parsed = parseRulesDetailed(content, files[i]);
      rules.push(...parsed.rules);
      mergeReports(report, parsed.report);
    } catch (err) {
      report.filesScanned++;
      report.skipped++;
      report.parseErrors.push({
        type: "parse-error",
        value: "file_read_error",
        filePath: files[i],
        fileName: path.basename(files[i]),
        detail: err.message || String(err),
      });
    }
    if (onProgress && i % 100 === 0) onProgress(i, files.length);
  }
  if (onProgress) onProgress(files.length, files.length);

  return { rules, report };
}

/**
 * Parse a single YAML file (may contain one rule).
 */
function parseFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    return parseRule(content, filePath);
  } catch (_) {
    return null;
  }
}

function parseFileDetailed(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    return parseRulesDetailed(content, filePath);
  } catch (err) {
    return {
      rules: [],
      report: {
        filesScanned: 1,
        documentsScanned: 0,
        parsed: 0,
        skipped: 1,
        skippedRules: [],
        parseErrors: [{
          type: "parse-error",
          value: "file_read_error",
          filePath,
          fileName: path.basename(filePath),
          detail: err.message || String(err),
        }],
      },
    };
  }
}

module.exports = { parseRule, parseRulesDetailed, parseDirectory, parseDirectoryDetailed, parseFile, parseFileDetailed };
