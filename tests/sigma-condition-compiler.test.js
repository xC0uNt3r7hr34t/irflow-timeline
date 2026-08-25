// Unit tests for the Sigma condition compiler (electron/analyzers/sigma/condition-compiler.js).
//
// This file was previously untested and held two Critical correctness bugs:
//   1. `and`/`or` were parsed at one flat precedence level → wrong verdicts on rules
//      mixing the operators without parentheses.
//   2. `*` / `?` wildcards in values were matched as literal characters → rules like
//      `Image|endswith: '*\powershell.exe'` silently never matched (false negatives).
// These tests lock in the fixes and cover the existing modifiers/operators as regression.

const test = require("node:test");
const assert = require("node:assert/strict");

const { compileDetection } = require("../electron/analyzers/sigma/condition-compiler");

// Field resolver: read a value straight off a plain object row.
const resolve = (field, row) => row[field];

// Compile a full detection block and evaluate it against a row.
const evalDet = (detection, row) => compileDetection(detection)(resolve, row);

// Single-field helper: match one `field|mods: value` against a field value.
function m(fieldSpec, searchValue, fieldValue) {
  const base = fieldSpec.split("|")[0];
  return evalDet({ sel: { [fieldSpec]: searchValue }, condition: "sel" }, { [base]: fieldValue });
}

// Named single-key selections for condition/precedence tests.
const DET = (condition) => ({
  selA: { A: "1" },
  selB: { B: "1" },
  selC: { C: "1" },
  condition,
});

// ───────────────────────── Bug 1: and/or precedence ─────────────────────────

test("precedence: `a or b and c` parses as `a or (b and c)`", () => {
  // A=1,B=0,C=0 → correct: T or (F and F) = T ; buggy flat: (T or F) and F = F
  assert.equal(evalDet(DET("selA or selB and selC"), { A: "1", B: "0", C: "0" }), true);
  // A=1,B=1,C=0 → correct: T or (T and F) = T ; buggy flat: (T or T) and F = F
  assert.equal(evalDet(DET("selA or selB and selC"), { A: "1", B: "1", C: "0" }), true);
  // A=0,B=1,C=0 → T? correct: F or (T and F) = F
  assert.equal(evalDet(DET("selA or selB and selC"), { A: "0", B: "1", C: "0" }), false);
});

test("precedence: `a and b or c` parses as `(a and b) or c`", () => {
  assert.equal(evalDet(DET("selA and selB or selC"), { A: "0", B: "0", C: "1" }), true);
  assert.equal(evalDet(DET("selA and selB or selC"), { A: "1", B: "0", C: "0" }), false);
  assert.equal(evalDet(DET("selA and selB or selC"), { A: "1", B: "1", C: "0" }), true);
});

test("precedence: parentheses override (force or-first)", () => {
  assert.equal(evalDet(DET("(selA or selB) and selC"), { A: "1", B: "0", C: "0" }), false);
  assert.equal(evalDet(DET("(selA or selB) and selC"), { A: "1", B: "0", C: "1" }), true);
});

test("not binds tighter than and/or", () => {
  assert.equal(evalDet(DET("selA and not selB"), { A: "1", B: "0" }), true);
  assert.equal(evalDet(DET("selA and not selB"), { A: "1", B: "1" }), false);
  // `not selA or selB` = (not selA) or selB
  assert.equal(evalDet(DET("not selA or selB"), { A: "1", B: "1" }), true);
  assert.equal(evalDet(DET("not selA or selB"), { A: "1", B: "0" }), false);
});

// ───────────────────────── Bug 2: wildcard matching ─────────────────────────

test("endswith with leading * wildcard matches (the flagged case)", () => {
  assert.equal(m("Image|endswith", "*\\powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), true);
  assert.equal(m("Image|endswith", "*\\powershell.exe", "C:\\Windows\\System32\\cmd.exe"), false);
});

test("contains with internal * wildcard respects order", () => {
  assert.equal(m("CommandLine|contains", "foo*bar", "xx foo YYY bar zz"), true);
  assert.equal(m("CommandLine|contains", "foo*bar", "xx bar foo zz"), false);
});

test("? matches exactly one character", () => {
  assert.equal(m("Image|endswith", "\\7z?.exe", "C:\\7za.exe"), true);
  assert.equal(m("Image|endswith", "\\7z?.exe", "C:\\7z.exe"), false); // needs exactly one char
});

test("exact match supports wildcards (anchored full-field)", () => {
  assert.equal(m("EventID", "46*", "4624"), true);
  assert.equal(m("EventID", "46*", "5624"), false);
  assert.equal(m("Image", "C:\\a*\\x.exe", "C:\\anything\\here\\x.exe"), true);
});

test("bare * means field present and non-empty", () => {
  assert.equal(m("AttributeValue|contains", "*", "something"), true);
  assert.equal(m("AttributeValue|contains", "*", ""), false);
});

test("escaped \\* and \\? are literal, not wildcards", () => {
  assert.equal(m("CommandLine|contains", "foo\\*bar", "foo*bar"), true);
  assert.equal(m("CommandLine|contains", "foo\\*bar", "fooXbar"), false);
  assert.equal(m("CommandLine|contains", "abc\\?def", "xx abc?def yy"), true);
  assert.equal(m("CommandLine|contains", "abc\\?def", "xx abcZdef yy"), false);
});

test("escaped backslash \\\\ collapses to one literal backslash", () => {
  // Sigma value "a\\b" (escaped) → literal "a\b"
  assert.equal(m("Path|contains", "a\\\\b", "x a\\b x"), true);
  // device-path indicator \\?\GLOBALROOT with escaped specials + a wildcard
  assert.equal(
    m("CommandLine|contains", "\\\\\\\\\\?\\\\GLOBALROOT\\\\Device\\\\HarddiskVolumeShadowCopy*",
      "vssadmin \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3\\foo"),
    true,
  );
});

test("windash expansion combines with wildcards", () => {
  const det = { sel: { "CommandLine|contains|windash": "dir*-s" }, condition: "sel" };
  assert.equal(evalDet(det, { CommandLine: "dir foo -s" }), true);
  assert.equal(evalDet(det, { CommandLine: "dir foo /s" }), true); // dash→slash variant
  assert.equal(evalDet(det, { CommandLine: "dir foo" }), false);
});

test("regex metacharacters in plain (non-wildcard) values are literal", () => {
  // '.' must not act as a regex wildcard
  assert.equal(m("Image|endswith", "a.exe", "x\\a.exe"), true);
  assert.equal(m("Image|endswith", "a.exe", "x\\aXexe"), false);
});

// ───────────────────────── Regression: plain text matching ─────────────────────────

test("plain endswith/startswith/contains/exact are case-insensitive", () => {
  assert.equal(m("Image|endswith", "\\CMD.EXE", "c:\\windows\\cmd.exe"), true);
  assert.equal(m("Image|startswith", "C:\\WIN", "c:\\windows\\cmd.exe"), true);
  assert.equal(m("CommandLine|contains", "WhoAmI", "x whoami /priv"), true);
  assert.equal(m("EventID", "4624", "4624"), true);
  assert.equal(m("EventID", "4624", "4625"), false);
});

test("missing field does not match a non-empty value", () => {
  assert.equal(evalDet({ sel: { "Image|endswith": "\\cmd.exe" }, condition: "sel" }, {}), false);
});

// ───────────────────────── Regression: value lists & |all ─────────────────────────

test("multiple values for a field are OR", () => {
  const det = { sel: { "CommandLine|contains": ["whoami", "net user"] }, condition: "sel" };
  assert.equal(evalDet(det, { CommandLine: "x net user y" }), true);
  assert.equal(evalDet(det, { CommandLine: "ipconfig" }), false);
});

test("|all requires every value to match", () => {
  const det = { sel: { "CommandLine|contains|all": ["foo", "bar"] }, condition: "sel" };
  assert.equal(evalDet(det, { CommandLine: "foo and bar" }), true);
  assert.equal(evalDet(det, { CommandLine: "only foo" }), false);
});

test("null in a value list matches an empty/absent field", () => {
  const det = { sel: { Field: ["a", null] }, condition: "sel" };
  assert.equal(evalDet(det, { Field: "" }), true);
  assert.equal(evalDet(det, { Field: "a" }), true);
  assert.equal(evalDet(det, { Field: "b" }), false);
});

// ───────────────────────── Regression: other modifiers ─────────────────────────

test("|re still matches (case-insensitive)", () => {
  assert.equal(m("CommandLine|re", "b.r", "fooBARbaz"), true);
  assert.equal(m("CommandLine|re", "^abc$", "abc"), true);
  assert.equal(m("CommandLine|re", "^abc$", "abcd"), false);
});

test("|cidr matches IPv4 ranges", () => {
  assert.equal(m("DestinationIp|cidr", "10.0.0.0/8", "10.1.2.3"), true);
  assert.equal(m("DestinationIp|cidr", "10.0.0.0/8", "192.168.1.1"), false);
});

test("|base64 encodes the search value before substring match", () => {
  const enc = Buffer.from("whoami", "utf8").toString("base64"); // d2hvYW1p
  assert.equal(m("CommandLine|base64", "whoami", `prefix ${enc} suffix`), true);
  assert.equal(m("CommandLine|base64", "whoami", "no match here"), false);
});

test("numeric |gt / |lt comparisons", () => {
  assert.equal(m("Count|gt", "5", "10"), true);
  assert.equal(m("Count|gt", "5", "3"), false);
  assert.equal(m("Count|lt", "5", "3"), true);
});

test("|exists checks presence/absence", () => {
  assert.equal(evalDet({ sel: { "Image|exists": true }, condition: "sel" }, { Image: "x" }), true);
  assert.equal(evalDet({ sel: { "Image|exists": true }, condition: "sel" }, {}), false);
  assert.equal(evalDet({ sel: { "Image|exists": false }, condition: "sel" }, {}), true);
});

// ───────────────────────── Regression: condition operators ─────────────────────────

test("`1 of selection*` matches when any wildcard-named group matches", () => {
  const det = { sel_a: { A: "1" }, sel_b: { B: "1" }, other: { C: "1" }, condition: "1 of sel_*" };
  assert.equal(evalDet(det, { A: "1" }), true);
  assert.equal(evalDet(det, { C: "1" }), false); // 'other' isn't a sel_* group
});

test("`all of them` requires every group", () => {
  const det = { selA: { A: "1" }, selB: { B: "1" }, condition: "all of them" };
  assert.equal(evalDet(det, { A: "1", B: "1" }), true);
  assert.equal(evalDet(det, { A: "1" }), false);
});

test("typical `selection and not filter` shape", () => {
  const det = {
    selection: { "Image|endswith": "\\rundll32.exe" },
    filter: { "CommandLine|contains": "legitimate" },
    condition: "selection and not filter",
  };
  assert.equal(evalDet(det, { Image: "C:\\W\\rundll32.exe", CommandLine: "evil.dll" }), true);
  assert.equal(evalDet(det, { Image: "C:\\W\\rundll32.exe", CommandLine: "legitimate stuff" }), false);
});

test("array detection condition (multiple conditions) is OR", () => {
  const det = { selA: { A: "1" }, selB: { B: "1" }, condition: ["selA", "selB"] };
  assert.equal(evalDet(det, { A: "1" }), true);
  assert.equal(evalDet(det, { B: "1" }), true);
  assert.equal(evalDet(det, { C: "1" }), false);
});
