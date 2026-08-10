/**
 * sigma/rule-compatibility.js — static compatibility checks for the JS Sigma engine.
 *
 * This is intentionally conservative. The JS engine is a compatibility scanner,
 * not full pySigma/Hayabusa parity, so unsupported syntax should be visible to
 * analysts instead of silently producing incomplete coverage.
 */

const { CATEGORY_MAP, SERVICE_MAP, mapLogsource } = require("./logsource-mapper");

const SUPPORTED_MODIFIERS = new Set([
  "all",
  "base64",
  "base64offset",
  "cidr",
  "contains",
  "endswith",
  "exists",
  "fieldref",
  "gt",
  "gte",
  "lt",
  "lte",
  "re",
  "startswith",
  "utf16",
  "utf16le",
  "wide",
  "windash",
]);

const CONDITION_OPERATORS = new Set(["and", "or", "not", "of", "them", "all"]);
const UNSUPPORTED_CONDITION_WORDS = new Set(["near", "by", "sequence", "ordered", "within"]);

function issueKey(issue) {
  return [issue.type, issue.value, issue.ruleId || issue.ruleTitle || "", issue.filePath || ""].join("|");
}

function summarizeIssues(issues, limit = 25) {
  const seen = new Set();
  const out = [];
  for (const issue of issues || []) {
    const key = issueKey(issue);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(issue);
    if (out.length >= limit) break;
  }
  return out;
}

function addCount(map, key) {
  if (!key) return;
  map[key] = (map[key] || 0) + 1;
}

function getRuleLabel(rule) {
  return rule?.id || rule?.title || rule?.ruleId || rule?.ruleTitle || rule?._fileName || "unknown rule";
}

function inspectDetectionNode(node, ctx, path = "") {
  if (!node || typeof node !== "object") return;

  if (!Array.isArray(node) && path === "") {
    for (const [groupName, groupValue] of Object.entries(node)) {
      if (groupName === "condition" || groupName === "timeframe") continue;
      inspectDetectionNode(groupValue, ctx, groupName);
    }
    return;
  }

  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const item = node[i];
      if (item && typeof item === "object") {
        inspectDetectionNode(item, ctx, `${path}[${i}]`);
      } else {
        ctx.unsupportedConditions.push({
          type: "unsupported-condition",
          value: "list_scalar_detection_item",
          detail: `Detection list item at ${path || "detection"} is not a field map`,
        });
      }
    }
    return;
  }

  for (const [rawKey, rawValue] of Object.entries(node)) {
    if (rawKey === "condition" || rawKey === "timeframe") continue;

    if (rawKey.includes("|")) {
      const [field, ...mods] = rawKey.split("|");
      for (const mod of mods.map((item) => String(item || "").toLowerCase()).filter(Boolean)) {
        if (!SUPPORTED_MODIFIERS.has(mod)) {
          ctx.unsupportedModifiers.push({
            type: "unsupported-modifier",
            value: mod,
            field,
            detail: `${rawKey} uses unsupported modifier |${mod}`,
          });
        }
      }
    }

    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of values) {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        ctx.unsupportedConditions.push({
          type: "unsupported-condition",
          value: "object_search_value",
          field: rawKey,
          detail: `${rawKey} uses an object search value`,
        });
      }
    }
  }
}

function detectionGroupNames(detection = {}) {
  return Object.keys(detection).filter((name) => name !== "condition" && name !== "timeframe");
}

function inspectCondition(rule, ctx) {
  const detection = rule?.detection || {};
  const conditions = Array.isArray(detection.condition) ? detection.condition : [detection.condition];
  const groupNames = detectionGroupNames(detection);

  if (!detection.condition) {
    ctx.unsupportedConditions.push({
      type: "unsupported-condition",
      value: "missing_condition",
      detail: "Detection block has no condition",
    });
    return;
  }

  for (const condition of conditions) {
    if (typeof condition !== "string") {
      ctx.unsupportedConditions.push({
        type: "unsupported-condition",
        value: "non_string_condition",
        detail: "Condition is not a string",
      });
      continue;
    }

    const lowered = condition.toLowerCase();
    for (const word of UNSUPPORTED_CONDITION_WORDS) {
      if (new RegExp(`\\b${word}\\b`, "i").test(condition)) {
        ctx.unsupportedConditions.push({
          type: "unsupported-condition",
          value: word,
          detail: `Condition operator "${word}" is not supported by the JS engine`,
        });
      }
    }

    if (condition.includes("|")) {
      ctx.unsupportedConditions.push({
        type: "unsupported-condition",
        value: "condition_pipe",
        detail: "Condition pipe syntax is not supported by the JS engine",
      });
    }

    const open = (condition.match(/\(/g) || []).length;
    const close = (condition.match(/\)/g) || []).length;
    if (open !== close) {
      ctx.unsupportedConditions.push({
        type: "unsupported-condition",
        value: "unbalanced_parentheses",
        detail: "Condition has unbalanced parentheses",
      });
    }

    const tokens = lowered.match(/[a-z0-9_.*-]+/g) || [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (/^\d+$/.test(token) || CONDITION_OPERATORS.has(token)) continue;
      if (tokens[i - 1] === "of") {
        if (token === "them") continue;
        if (token.endsWith("*")) {
          const prefix = token.slice(0, -1);
          const matches = groupNames.filter((name) => name.toLowerCase().startsWith(prefix));
          if (matches.length === 0) {
            ctx.unsupportedConditions.push({
              type: "unsupported-condition",
              value: "empty_condition_wildcard",
              detail: `Condition pattern "${token}" matches no detection groups`,
            });
          }
        } else if (!groupNames.some((name) => name.toLowerCase() === token)) {
          ctx.unsupportedConditions.push({
            type: "unsupported-condition",
            value: "missing_condition_group",
            detail: `Condition references missing group "${token}"`,
          });
        }
        continue;
      }
      if (!groupNames.some((name) => name.toLowerCase() === token)) {
        ctx.unsupportedConditions.push({
          type: "unsupported-condition",
          value: "unknown_condition_token",
          detail: `Condition token "${token}" is not a known detection group/operator`,
        });
      }
    }
  }
}

function inspectLogsource(rule, ctx) {
  const logsource = rule?.logsource || {};
  const product = String(logsource.product || "").toLowerCase();
  const category = String(logsource.category || "").toLowerCase();
  const service = String(logsource.service || "").toLowerCase();
  const mapped = mapLogsource({ product, category, service });

  if (product && product !== "windows") {
    ctx.unsupportedLogsources.push({
      type: "unsupported-logsource",
      value: `product:${product}`,
      detail: "Only Windows Sigma logsources are scanned by the JS compatibility engine",
    });
  }
  if (category && !CATEGORY_MAP[category]) {
    ctx.logsourceWarnings.push({
      type: "logsource-warning",
      value: `category:${category}`,
      detail: "Category is not mapped to concrete Windows channels/Event IDs",
    });
  }
  if (service && !SERVICE_MAP[service]) {
    ctx.logsourceWarnings.push({
      type: "logsource-warning",
      value: `service:${service}`,
      detail: "Service is not mapped to a concrete Windows channel",
    });
  }
  if (!mapped.skip && mapped.channels.length === 0 && mapped.eids.length === 0) {
    ctx.unsupportedLogsources.push({
      type: "unsupported-logsource",
      value: "unmapped_windows_logsource",
      detail: "No SQL prefilter can be built; the scanner skips unconstrained logsources to avoid full table scans",
    });
  }
}

function decorateIssue(rule, issue) {
  return {
    ...issue,
    ruleId: rule?.id || "",
    ruleTitle: rule?.title || "",
    filePath: rule?._sourceRepoRelativePath || rule?._filePath || "",
    fileName: rule?._fileName || "",
  };
}

function analyzeRuleCompatibility(rule = {}) {
  const ctx = {
    unsupportedConditions: [],
    unsupportedModifiers: [],
    unsupportedLogsources: [],
    logsourceWarnings: [],
  };

  inspectCondition(rule, ctx);
  inspectDetectionNode(rule.detection, ctx);
  inspectLogsource(rule, ctx);

  const unsupportedConditions = summarizeIssues(ctx.unsupportedConditions.map((issue) => decorateIssue(rule, issue)), 100);
  const unsupportedModifiers = summarizeIssues(ctx.unsupportedModifiers.map((issue) => decorateIssue(rule, issue)), 100);
  const unsupportedLogsources = summarizeIssues(ctx.unsupportedLogsources.map((issue) => decorateIssue(rule, issue)), 100);
  const logsourceWarnings = summarizeIssues(ctx.logsourceWarnings.map((issue) => decorateIssue(rule, issue)), 100);
  const supported = unsupportedConditions.length === 0 && unsupportedModifiers.length === 0 && unsupportedLogsources.length === 0;

  return {
    supported,
    ruleKey: getRuleLabel(rule),
    unsupportedConditions,
    unsupportedModifiers,
    unsupportedLogsources,
    logsourceWarnings,
  };
}

function annotateRuleCompatibility(rule) {
  if (!rule || typeof rule !== "object") return rule;
  rule._compatibility = analyzeRuleCompatibility(rule);
  return rule;
}

function buildRuleCompatibilityReport(rules = [], parseReport = {}) {
  const unsupportedConditions = [];
  const unsupportedModifiers = [];
  const unsupportedLogsources = [];
  const logsourceWarnings = [];
  const unsupportedRuleKeys = new Set();
  const byModifier = {};
  const byLogsource = {};
  const byCondition = {};

  for (const rule of rules || []) {
    const compat = rule?._compatibility || analyzeRuleCompatibility(rule);
    if (!compat.supported) unsupportedRuleKeys.add(getRuleLabel(rule));
    for (const issue of compat.unsupportedConditions || []) {
      unsupportedConditions.push(issue);
      addCount(byCondition, issue.value);
    }
    for (const issue of compat.unsupportedModifiers || []) {
      unsupportedModifiers.push(issue);
      addCount(byModifier, issue.value);
    }
    for (const issue of compat.unsupportedLogsources || []) {
      unsupportedLogsources.push(issue);
      addCount(byLogsource, issue.value);
    }
    for (const issue of compat.logsourceWarnings || []) logsourceWarnings.push(issue);
  }

  const parsed = rules.length;
  const skipped = Number(parseReport.skipped || parseReport.skippedDocs || 0) || 0;
  const unsupportedRules = unsupportedRuleKeys.size;
  return {
    parsed,
    skipped,
    compatible: Math.max(0, parsed - unsupportedRules),
    unsupportedRules,
    unsupportedConditionRules: new Set(unsupportedConditions.map(getRuleLabel)).size,
    unsupportedModifierRules: new Set(unsupportedModifiers.map(getRuleLabel)).size,
    unsupportedLogsourceRules: new Set(unsupportedLogsources.map(getRuleLabel)).size,
    unsupportedConditions: summarizeIssues(unsupportedConditions),
    unsupportedModifiers: summarizeIssues(unsupportedModifiers),
    unsupportedLogsources: summarizeIssues(unsupportedLogsources),
    logsourceWarnings: summarizeIssues(logsourceWarnings),
    byCondition,
    byModifier,
    byLogsource,
    filesScanned: parseReport.filesScanned || parseReport.files || 0,
    documentsScanned: parseReport.documentsScanned || parseReport.docs || parsed + skipped,
    parseErrors: summarizeIssues(parseReport.parseErrors || [], 20),
    skippedRules: summarizeIssues(parseReport.skippedRules || [], 20),
  };
}

module.exports = {
  SUPPORTED_MODIFIERS,
  analyzeRuleCompatibility,
  annotateRuleCompatibility,
  buildRuleCompatibilityReport,
};
