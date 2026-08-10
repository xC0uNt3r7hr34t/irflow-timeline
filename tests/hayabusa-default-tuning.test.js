const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { DEFAULT_NOISY_RULES, ensureDefaultNoisyRules } = require("../electron/analyzers/sigma/evtx-scanner/default-tuning");

test("Hayabusa default tuning marks NotPetya rule noisy idempotently", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-hayabusa-default-tuning-"));
  t.after(() => {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  });

  const binPath = path.join(root, "hayabusa");
  fs.mkdirSync(path.dirname(binPath), { recursive: true });
  fs.writeFileSync(binPath, "", "utf8");

  const first = ensureDefaultNoisyRules(binPath);
  assert.equal(first.updated, true);
  assert.deepEqual(first.added, DEFAULT_NOISY_RULES.map((rule) => rule.id));

  const second = ensureDefaultNoisyRules(binPath);
  assert.equal(second.updated, false);
  assert.deepEqual(second.added, []);

  const noisyPath = path.join(root, "rules", "config", "noisy_rules.txt");
  const contents = fs.readFileSync(noisyPath, "utf8");
  const matches = contents.match(new RegExp(DEFAULT_NOISY_RULES[0].id, "gi")) || [];
  assert.equal(matches.length, 1);
  assert.match(contents, /NotPetya Ransomware Activity/);
});
