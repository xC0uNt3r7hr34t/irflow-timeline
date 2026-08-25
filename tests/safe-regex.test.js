// Tests for the ReDoS guard (release review M3). The refactor added compileSafeRegex
// but only wired it into the SQLite REGEXP UDF + ransomware matcher; M3 routes the
// other untrusted-pattern sites (Sigma |re, persistence custom rules, matchIocs)
// through it and hardens the nested-quantifier heuristic to also catch {n,m} bombs.

const test = require("node:test");
const assert = require("node:assert/strict");
const { compileSafeRegex, safeRegexTester } = require("../electron/utils/safe-regex");

test("compileSafeRegex rejects classic nested-quantifier ReDoS shapes", () => {
  for (const p of ["(a+)+$", "(\\w+)+", "(.+)*", "(.+)+x"]) {
    assert.ok(compileSafeRegex(p, "i").error, `should reject ${p}`);
  }
});

test("compileSafeRegex now also rejects brace-quantifier ReDoS bombs (hardened heuristic)", () => {
  // These slipped through the prior [+*]-only NESTED_QUANTIFIER_RE.
  for (const p of ["(a{1,9999})*$", "(.*a){1,9999}", "(a+){2,}", "(\\d+){5,}"]) {
    assert.ok(compileSafeRegex(p, "i").error, `should reject ${p}`);
  }
});

test("compileSafeRegex still accepts safe patterns (no false positives on common shapes)", () => {
  // Quantifier-free groups, fixed {n}/bounded {n,m} repeats of plain groups, and
  // anchored character-class quantifiers are all safe and must NOT be rejected.
  for (const p of [
    "powershell\\.exe",
    "(?:Run|RunOnce|RunServices)",
    "(abc){1,3}",
    "Target:\\s*\\S+",
    "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
    "Signed:\\s*false",
  ]) {
    assert.equal(compileSafeRegex(p, "i").error, undefined, `should accept ${p}`);
  }
});

test("compileSafeRegex bounds per-value input length to MAX_VALUE_LEN", () => {
  const { test: t } = compileSafeRegex("needle", "i");
  // 'needle' sits past the 64 KiB cap, so the bounded tester does not see it.
  assert.equal(t("a".repeat(70000) + "needle"), false);
  assert.equal(t("needle in a haystack"), true);
});

test("safeRegexTester returns a working predicate, or null for unsafe/invalid/empty patterns", () => {
  const ok = safeRegexTester("foo", "i");
  assert.equal(typeof ok, "function");
  assert.equal(ok("a FOObar"), true);
  assert.equal(ok("nope"), false);
  assert.equal(safeRegexTester("(a+)+$", "i"), null); // unsafe (nested quantifier)
  assert.equal(safeRegexTester("(", "i"), null);      // invalid syntax
  assert.equal(safeRegexTester("", "i"), null);       // empty
});
