/**
 * analyzers/ai-history — AI-specific secret / credential / PII leak detector.
 *
 * Scans AI-assistant query history (prompts the subject typed + model responses) for leaked
 * secrets — API keys, tokens, private keys, hardcoded credentials — and, in Deep mode, PII and
 * high-entropy "unknown" secrets. Emits findings with a MITRE ATT&CK mapping. Same analyzer
 * contract as the others: analyzeAiHistory(meta, opts) receives the tab DB meta (meta.db
 * better-sqlite3 handle + meta.colMap name->c0..cN) and returns { findings, summary }. The core
 * (analyzeAiHistoryRows) is pure and unit-testable without a SQLite binding.
 *
 * Two-stage detection:
 *   1. catalog regex (detection-rules.js), each run through compileSafeRegex (ReDoS guard + 64KB
 *      per-value cap) so a malformed/expensive rule is dropped rather than hanging the process;
 *   2. precision layer (validators.js): structural validators (Luhn/IBAN/entropy) + a placeholder
 *      allow-list drop false matches; a Deep-mode entropy pass catches secrets no named rule knows.
 *
 * Secrets are redacted by default (first4…last4 + length) and fingerprinted (salted SHA-256) so
 * cleartext can be revealed per-row in the UI but is never required for correlation. The cleartext
 * `match` is returned in-memory for reveal; callers must strip it from any on-disk export.
 */

const crypto = require("crypto");
const { dbg } = require("../../logger");
const { compileSafeRegex, MAX_VALUE_LEN } = require("../../utils/safe-regex");
const { AI_DETECTION_RULES } = require("./detection-rules");
const {
  isPlaceholderValue,
  isKnownExampleValue,
  isPublicTestCardNumber,
  scanEntropyCandidates,
  classifyEntropyCandidate,
  redactValue,
  fingerprint,
} = require("./validators");

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const SNIPPET_PAD = 48; // chars of context around a match
const MAX_MATCHES_PER_RULE_PER_TEXT = 100;

/** Compile + safety-gate the raw rule catalog once at load. Unsafe/invalid rules are skipped. */
function compileRules(rawRules) {
  const out = [];
  for (const r of rawRules || []) {
    // flags default to "i", but "" must stay case-sensitive (token formats) — nullish, not ||.
    const compiled = compileSafeRegex(r.regex, r.flags != null ? r.flags : "i");
    if (compiled.error) {
      dbg("AIHIST", "skip unsafe AI detection rule", { id: r.id, error: compiled.error });
      continue;
    }
    out.push({ ...r, _test: compiled.test, _re: compiled.re });
  }
  return out;
}

const COMPILED_RULES = compileRules(AI_DETECTION_RULES);

function roleMatches(scope, role) {
  if (!scope || scope === "any") return true;
  return scope === String(role || "").toLowerCase();
}

/** Keep the most specific detector when several match the same span; the rest become alsoMatched. */
function rulePriority(r) {
  switch (r.category) {
    case "private-key": return 5;
    case "secret-cloud":
    case "secret-scm":
    case "secret-ai":
    case "secret-payment":
    case "secret-messaging": return 4;
    case "secret-generic": return 3;
    case "pii": return 2;
    case "high-entropy": return 1;
    default: return 0;
  }
}

function spansOverlap(i1, l1, i2, l2) {
  return i1 < i2 + l2 && i2 < i1 + l1;
}

/** Inline mask for snippet display (no length suffix — that lives in `redacted`). */
function maskInline(value) {
  const s = String(value || "");
  if (s.length <= 8) return "•".repeat(Math.max(1, s.length));
  return `${s.slice(0, 4)}${"•".repeat(Math.min(8, s.length - 8))}${s.slice(-4)}`;
}

function adjustedRuleForValue(rule, value) {
  if (rule.id === "pii-credit-card" && isPublicTestCardNumber(value)) {
    return {
      ...rule,
      title: "Credit Card Number (public test number)",
      severity: "low",
      confidence: "informational",
      publicTestValue: true,
    };
  }
  return rule;
}

function validatedConfidence(rule) {
  return rule.validatedConfidence || "verified";
}

/**
 * Catalog matches for one text/role. Pure. Returns
 * [{ rule, value, matchText, index, confidence }] after validators + placeholder filtering.
 */
function findMatchesInText(text, role, rules = COMPILED_RULES) {
  if (!text) return [];
  const s = typeof text === "string" ? text : String(text);
  const bounded = s.length > MAX_VALUE_LEN ? s.slice(0, MAX_VALUE_LEN) : s;
  const out = [];
  for (const r of rules) {
    if (!roleMatches(r.roleScope, role)) continue;
    // Fresh global clone so every same-rule secret in the message is reported without leaking
    // lastIndex state across rows. The per-rule cap bounds pathological high-density rows.
    const flags = r._re.flags.includes("g") ? r._re.flags : `${r._re.flags}g`;
    const probe = new RegExp(r._re.source, flags);
    let m;
    let seenForRule = 0;
    while ((m = probe.exec(bounded)) !== null) {
      if (++seenForRule > MAX_MATCHES_PER_RULE_PER_TEXT) break;
      let value = r.valueGroup && m[r.valueGroup] != null ? String(m[r.valueGroup]) : m[0];
      let matchText = m[0];
      let valIdx = r.valueGroup && m[r.valueGroup] != null
        ? (bounded.indexOf(m[r.valueGroup], m.index) >= 0 ? bounded.indexOf(m[r.valueGroup], m.index) : m.index)
        : m.index;
      if (typeof r.extract === "function") {
        try {
          const extracted = r.extract(bounded, m, { value, matchText, index: valIdx });
          if (extracted?.value) {
            value = String(extracted.value);
            matchText = String(extracted.matchText || extracted.value);
            valIdx = extracted.index != null ? Number(extracted.index) : valIdx;
          }
        } catch {
          value = r.valueGroup && m[r.valueGroup] != null ? String(m[r.valueGroup]) : m[0];
          matchText = m[0];
          valIdx = r.valueGroup && m[r.valueGroup] != null
            ? (bounded.indexOf(m[r.valueGroup], m.index) >= 0 ? bounded.indexOf(m[r.valueGroup], m.index) : m.index)
            : m.index;
        }
      }
      if (!isPlaceholderValue(value) && !isKnownExampleValue(value)) {
        let confidence = r.confidence || "suspicious";
        let rule = r;
        let ok = true;
        if (typeof r.validate === "function") {
          ok = false;
          try { ok = !!r.validate(value, m, bounded); } catch { ok = false; }
          if (ok) confidence = validatedConfidence(r);
        }
        if (ok) {
          rule = adjustedRuleForValue(r, value);
          if (rule.publicTestValue) confidence = rule.confidence || "informational";
          out.push({ rule, value, matchText, index: valIdx, confidence, priority: rulePriority(rule) });
        }
      }
      if (m.index === probe.lastIndex) probe.lastIndex++;
    }
  }
  return out;
}

/** Deep-mode entropy pass — catches high-entropy secrets no named rule matched. */
function findEntropyHits(text, existing) {
  const s = typeof text === "string" ? text : String(text || "");
  const bounded = s.length > MAX_VALUE_LEN ? s.slice(0, MAX_VALUE_LEN) : s;
  const out = [];
  for (const c of scanEntropyCandidates(bounded)) {
    if (existing.some((h) => spansOverlap(h.index, h.matchText.length, c.index, c.value.length))) continue;
    const cls = classifyEntropyCandidate(c, bounded);
    if (!cls) continue;
    out.push({
      rule: {
        id: "high-entropy", title: "High-entropy string (possible secret)", category: "high-entropy",
        severity: cls.severity, mitreId: "T1552.001", mitreName: "Unsecured Credentials: Credentials In Files",
      },
      value: c.value, matchText: c.value, index: c.index, confidence: cls.confidence, priority: 1,
    });
  }
  return out;
}

/** Resolve overlapping spans to the highest-priority detector; fold the rest into alsoMatched. */
function dedupeOverlaps(hits) {
  const sorted = [...hits].sort((a, b) =>
    b.priority - a.priority
    || (SEVERITY_RANK[b.rule.severity] || 0) - (SEVERITY_RANK[a.rule.severity] || 0));
  const kept = [];
  for (const h of sorted) {
    const owner = kept.find((k) => spansOverlap(k.index, k.matchText.length, h.index, h.matchText.length));
    if (owner) {
      if (owner.rule.id !== h.rule.id) (owner.alsoMatched = owner.alsoMatched || []).push(h.rule.id);
      continue;
    }
    kept.push(h);
  }
  return kept;
}

function leakDirectionFor(role) {
  const r = String(role || "").toLowerCase();
  if (r === "user") return "user→service";
  if (r === "assistant") return "service→user";
  return "";
}

function buildFinding(hit, row, ctx) {
  const r = hit.rule;
  const role = row.role || "";
  const text = ctx.text;
  const start = Math.max(0, hit.index - SNIPPET_PAD);
  const end = Math.min(text.length, hit.index + hit.matchText.length + SNIPPET_PAD);
  let seg = text.slice(start, end);
  if (ctx.redact) {
    seg = seg.split(hit.value).join(maskInline(hit.value));
    if (hit.matchText !== hit.value) seg = seg.split(hit.matchText).join(maskInline(hit.matchText));
  }
  const snippet = `${start > 0 ? "…" : ""}${seg}${end < text.length ? "…" : ""}`.replace(/\s+/g, " ").trim();

  const finding = {
    ruleId: r.id,
    category: r.category,
    title: r.title,
    severity: r.severity,
    confidence: hit.confidence,
    mitreId: r.mitreId || "",
    mitreName: r.mitreName || "",
    rowId: row.rowId != null ? String(row.rowId) : "",
    recordId: row.recordId != null ? String(row.recordId) : "",
    timestamp: row.timestamp || "",
    tool: row.tool || "",
    role,
    sessionId: row.sessionId || "",
    sourceFile: row.sourceFile || "",
    lineNumber: row.lineNumber || "",
    workspace: row.workspace || "",
    messageId: row.messageId || "",
    leakDirection: leakDirectionFor(role),
    redacted: redactValue(hit.value),
    fingerprint: fingerprint(hit.value, ctx.salt),
    alsoMatched: hit.alsoMatched || [],
    snippet,
  };
  // Cleartext for per-row reveal. In-memory only — callers MUST strip before any on-disk export.
  finding.match = hit.value;
  return finding;
}

function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory = {};
  const byConfidence = {};
  const mitreMap = new Map();
  const rowKeys = new Set();
  const fingerprints = new Set();
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    byConfidence[f.confidence] = (byConfidence[f.confidence] || 0) + 1;
    if (f.recordId != null) rowKeys.add(String(f.recordId));
    if (f.fingerprint) fingerprints.add(f.fingerprint);
    if (f.mitreId) {
      const e = mitreMap.get(f.mitreId) || { id: f.mitreId, name: f.mitreName || "", count: 0 };
      e.count += 1;
      mitreMap.set(f.mitreId, e);
    }
  }
  let severity = "info";
  if (bySeverity.critical) severity = "critical";
  else if (bySeverity.high) severity = "high";
  else if (bySeverity.medium) severity = "medium";
  else if (bySeverity.low) severity = "low";
  const mitre = [...mitreMap.values()].sort((a, b) => b.count - a.count);
  return {
    severity,
    total: findings.length,
    flaggedRows: rowKeys.size,
    uniqueSecrets: fingerprints.size,
    bySeverity,
    byCategory,
    byConfidence,
    mitre,
  };
}

function buildScanContext(opts = {}) {
  const mode = opts.mode === "deep" ? "deep" : "quick";
  return {
    mode,
    redact: opts.redact !== false,
    salt: opts.salt != null ? String(opts.salt) : crypto.randomBytes(8).toString("hex"),
    rules: (opts.rules || COMPILED_RULES).filter((r) => mode === "deep" || r.mode !== "deep"),
  };
}

function scanRow(row, ctx) {
  const role = String(row.role || "").toLowerCase();
  const text = typeof row.text === "string" ? row.text : String(row.text || "");
  if (!text) return [];
  const hits = findMatchesInText(text, role, ctx.rules);
  if (ctx.mode === "deep") hits.push(...findEntropyHits(text, hits));
  if (!hits.length) return [];
  return dedupeOverlaps(hits).map((hit) => buildFinding(hit, row, { redact: ctx.redact, salt: ctx.salt, text }));
}

function sortFindings(findings) {
  findings.sort((a, b) =>
    (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
    || (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
  return findings;
}

/**
 * Core: scan an array of normalized AI rows.
 * @param {Array<{recordId,timestamp,tool,role,sessionId,sourceFile,workspace,messageId,text}>} rows
 * @param {{ rules?:Array, mode?:"quick"|"deep", redact?:boolean, salt?:string }} [opts]
 * @returns {{ findings: Array, summary: object }}
 */
function analyzeAiHistoryRows(rows, opts = {}) {
  const ctx = buildScanContext(opts);
  const findings = [];
  for (const row of rows || []) {
    const rowFindings = scanRow(row, ctx);
    for (const finding of rowFindings) findings.push(finding);
  }
  sortFindings(findings);
  return { findings, summary: summarize(findings) };
}

const EMPTY = Object.freeze({
  findings: [],
  summary: { severity: "info", total: 0, flaggedRows: 0, uniqueSecrets: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, byCategory: {}, byConfidence: {}, mitre: [] },
});

/**
 * Tab-DB entry point (mirrors analyzeADS(meta)). Scans COALESCE(FullText, Summary) per row.
 * NOTE: merged/triage AI tabs may have FullText slimmed to '' (only the <=500-char Summary preview
 * is stored) unless the import retained it; on those tabs detection is limited to the preview.
 */
function analyzeAiHistory(meta, opts = {}) {
  if (!meta || !meta.db || !meta.colMap) return { ...EMPTY, error: "No timeline data for this tab." };
  const col = (name) => meta.colMap[name];
  const cSummary = col("Summary");
  const cFull = col("FullText");
  if (!cSummary && !cFull) return { ...EMPTY, error: "Not an AI history tab (no Summary/FullText column)." };

  const cRecord = col("RecordId");
  const cRole = col("Role");
  const cTool = col("Tool");
  const cTs = col("Timestamp");
  const cSession = col("SessionId");
  const cSource = col("SourceFile");
  const cLine = col("LineNumber");
  const cWorkspace = col("Workspace");
  const cMessage = col("MessageId");

  const selCols = [...new Set([cSummary, cFull, cRecord, cRole, cTool, cTs, cSession, cSource, cLine, cWorkspace, cMessage].filter(Boolean))];
  let stmt;
  let total = 0;
  try {
    total = meta.db.prepare(`SELECT COUNT(*) AS n FROM data`).get().n;
    stmt = meta.db.prepare(`SELECT data.rowid AS _rowid, ${selCols.join(", ")} FROM data`);
  } catch (e) {
    return { ...EMPTY, error: `AI history scan failed: ${e.message}` };
  }

  const progressCb = typeof opts.progressCb === "function" ? opts.progressCb : null;
  const ctx = buildScanContext(opts);
  const findings = [];
  let rowsWithFullText = 0;
  let rowsSummaryOnly = 0;
  let maxScannedChars = 0;
  let scanned = 0;
  for (const rec of stmt.iterate()) {
    const full = cFull && rec[cFull] != null ? String(rec[cFull]) : "";
    const summary = cSummary && rec[cSummary] != null ? String(rec[cSummary]) : "";
    const hasFullText = !!(cFull && full.trim());
    const text = hasFullText ? full : summary;
    if (hasFullText) rowsWithFullText++;
    else if (text.trim()) rowsSummaryOnly++;
    maxScannedChars = Math.max(maxScannedChars, Math.min(text.length, MAX_VALUE_LEN));

    const row = {
      rowId: rec._rowid,
      recordId: cRecord ? rec[cRecord] : "",
      timestamp: cTs ? rec[cTs] : "",
      tool: cTool ? rec[cTool] : "",
      role: cRole ? rec[cRole] : "",
      sessionId: cSession ? rec[cSession] : "",
      sourceFile: cSource ? rec[cSource] : "",
      lineNumber: cLine ? rec[cLine] : "",
      workspace: cWorkspace ? rec[cWorkspace] : "",
      messageId: cMessage ? rec[cMessage] : "",
      text,
    };
    for (const finding of scanRow(row, ctx)) findings.push(finding);
    if (progressCb && ++scanned % 5000 === 0) progressCb({ phase: "ai-secrets", processed: scanned, total });
  }
  if (progressCb) progressCb({ phase: "ai-secrets", processed: total, total });

  sortFindings(findings);
  const result = { findings, summary: summarize(findings) };
  // Surface the FullText-coverage caveat so the UI can warn when scanning a slimmed merged tab.
  result.fullTextAvailable = rowsWithFullText > 0;
  result.rowsWithFullText = rowsWithFullText;
  result.rowsSummaryOnly = rowsSummaryOnly;
  result.maxScannedChars = maxScannedChars;
  result.scanValueCharLimit = MAX_VALUE_LEN;
  return result;
}

module.exports = {
  analyzeAiHistory,
  analyzeAiHistoryRows,
  findMatchesInText,
  compileRules,
  COMPILED_RULES,
  SEVERITY_RANK,
  MAX_MATCHES_PER_RULE_PER_TEXT,
};
