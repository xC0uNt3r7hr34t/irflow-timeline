// Regression test for the Sigma |base64offset non-ASCII false-negative (release review L1).
//
// _base64OffsetVariants computed padding/trim lengths from str.length (UTF-16 code units)
// but base64-encoded the UTF-8 byte representation. For a multi-byte search value whose
// byte length isn't 3-aligned, every alignment variant was mis-trimmed, so a
// |base64offset rule with a non-ASCII literal silently never matched. Fix computes the
// padding/trim from the UTF-8 byte length and builds the padded value in byte space.

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseFieldModifiers } = require("../electron/analyzers/sigma/condition-compiler");

const matches = (spec, searchValue, fieldValue) =>
  parseFieldModifiers(spec).matchFn(fieldValue, searchValue);

// A value embedded in a base64-encoded blob is found at one of the 3 byte alignments.
const blobWith = (value) => Buffer.from("xx" + value + "yy", "utf8").toString("base64");

test("|base64offset matches non-ASCII search values (byte-length math)", () => {
  for (const v of ["café-x", "café", "naïve", "пароль", "日本語コマンド"]) {
    assert.equal(matches("CommandLine|base64offset|contains", v, blobWith(v)), true,
      `non-ASCII base64offset value should match: ${v}`);
  }
});

test("|base64offset still matches ASCII values (no regression)", () => {
  for (const v of ["whoami", "powershell", "Invoke-Expression"]) {
    assert.equal(matches("CommandLine|base64offset|contains", v, blobWith(v)), true, v);
  }
});

test("|base64offset does not falsely match an absent value", () => {
  assert.equal(matches("CommandLine|base64offset|contains", "café-x", Buffer.from("nothing relevant here", "utf8").toString("base64")), false);
  assert.equal(matches("CommandLine|base64offset|contains", "whoami", Buffer.from("benign content", "utf8").toString("base64")), false);
});
