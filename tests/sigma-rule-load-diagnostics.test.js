// ruleLoadDiagnostics (electron/analyzers/sigma/evtx-scanner/progress-parser.js):
// turns Hayabusa's reported rule counts into an explanation for empty scans,
// so a bad custom --rules path no longer reads as a silent "no hits".

const test = require("node:test");
const assert = require("node:assert/strict");

const { ruleLoadDiagnostics } = require("../electron/analyzers/sigma/evtx-scanner/progress-parser");

test("0 rules loaded + custom rules path => points the analyst at the path", () => {
  const { warnings } = ruleLoadDiagnostics({ rulesLoaded: 0, rulesAfterFilter: 0, rulesPath: "/case/myrules", matchCount: 0 });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /custom rules path/i);
  assert.match(warnings[0], /\/case\/myrules/);
});

test("0 rules loaded + no custom path => suggests Update Rules", () => {
  const { warnings } = ruleLoadDiagnostics({ rulesLoaded: 0, rulesAfterFilter: 0, rulesPath: null, matchCount: 0 });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /Update Rules/i);
  assert.doesNotMatch(warnings[0], /custom rules path/i);
});

test("rules loaded but all filtered out by channel filter => explains the channel mismatch", () => {
  const { warnings } = ruleLoadDiagnostics({ rulesLoaded: 3000, rulesAfterFilter: 0, rulesPath: null, matchCount: 0 });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /channel filter/i);
  assert.match(warnings[0], /3,000/);
});

test("any matches => no diagnostic (hits prove rules loaded, even if the count regex missed)", () => {
  assert.deepEqual(ruleLoadDiagnostics({ rulesLoaded: 0, rulesAfterFilter: 0, rulesPath: "/x", matchCount: 5 }).warnings, []);
  assert.deepEqual(ruleLoadDiagnostics({ rulesLoaded: 0, rulesAfterFilter: 0, rulesPath: null, matchCount: 1 }).warnings, []);
});

test("healthy scan (rules loaded, survived filter, no matches) => no diagnostic", () => {
  assert.deepEqual(ruleLoadDiagnostics({ rulesLoaded: 3000, rulesAfterFilter: 1200, rulesPath: null, matchCount: 0 }).warnings, []);
});
