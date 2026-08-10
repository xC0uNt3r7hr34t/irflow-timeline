/**
 * Safe wrapper around user-supplied regex patterns.
 *
 * JavaScript's regex engine has no native timeout, so a malformed user pattern
 * like `(.+)+` against a long input string can hang the main process via
 * catastrophic backtracking. This helper applies three practical mitigations:
 *
 *   1. Pattern length cap — reject patterns longer than MAX_PATTERN_LEN.
 *   2. Nested-quantifier detection — reject heuristically-dangerous patterns
 *      like `(\w+)+` or `(.+)*` before compiling.
 *   3. Per-value input cap — bound the string length the regex tests against,
 *      so even a slow regex can't run forever on a multi-MB cell value.
 *
 * Returns { test, re } on success or { error } on rejection. Callers should
 * treat rejected patterns as "no match" rather than throwing.
 *
 * Used by:
 *   - electron/db/runtime-functions.js — SQLite REGEXP function (advanced
 *     filters, column unique values regex search)
 *   - electron/analyzers/ransomware.js — ransom note pattern in regex mode
 *   - electron/analyzers/sigma/condition-compiler.js — Sigma |re + wildcard matchers
 *   - electron/analyzers/persistence/index.js — user custom-rule patterns
 *   - electron/db.js — matchIocs user IOC patterns
 */
const MAX_PATTERN_LEN = 1024;
const MAX_VALUE_LEN = 65536; // 64 KiB — caps per-row work on giant cell values

// Heuristic: reject patterns with nested quantifiers — a group that itself
// contains a variable-length quantifier and is then repeated. Catches the common
// catastrophic-backtracking shapes `(\w+)+`, `(.+)*`, `(a|b)*+`, AND brace forms
// `(a{1,9999})*` / `(.*a){1,9999}` (which the prior `[+*]`-only heuristic missed).
// A "variable-length quantifier" is `+`, `*`, or a comma'd `{n,}`/`{n,m}` range;
// fixed `{n}` and quantifier-free groups like `(abc){1,3}` are intentionally left
// alone. False positives are possible but rare in DFIR queries — users hitting one
// should restructure rather than wait minutes for results.
const NESTED_QUANTIFIER_RE = /\([^)]*(?:[+*]|\{\d+,\d*\})[^)]*\)(?:[+*]|\{\d+,\d*\})/;

function compileSafeRegex(pattern, flags = "i") {
  if (typeof pattern !== "string") return { error: "Pattern must be a string" };
  if (pattern.length === 0) return { error: "Pattern is empty" };
  if (pattern.length > MAX_PATTERN_LEN) {
    return { error: `Pattern too long (max ${MAX_PATTERN_LEN} chars)` };
  }
  if (NESTED_QUANTIFIER_RE.test(pattern)) {
    return { error: "Pattern contains nested quantifiers (catastrophic backtracking risk)" };
  }
  let re;
  try {
    re = new RegExp(pattern, flags);
  } catch (e) {
    return { error: e.message };
  }
  return {
    re,
    test: (value) => {
      if (value == null) return false;
      const s = typeof value === "string" ? value : String(value);
      const bounded = s.length > MAX_VALUE_LEN ? s.slice(0, MAX_VALUE_LEN) : s;
      return re.test(bounded);
    },
  };
}

/**
 * Convenience wrapper: returns a bounded (value) => boolean tester for `pattern`,
 * or null if the pattern is empty / too long / unsafe / invalid. Callers treat null
 * as "never match". Use this for untrusted patterns (Sigma |re, IOC patterns, custom
 * detection rules) where a plain predicate is more convenient than the {test,re} object.
 */
function safeRegexTester(pattern, flags = "i") {
  const compiled = compileSafeRegex(pattern, flags);
  return compiled.error ? null : compiled.test;
}

module.exports = { compileSafeRegex, safeRegexTester, MAX_PATTERN_LEN, MAX_VALUE_LEN };
