// Regression test for Theme #1 — naive (zone-less) timestamps must be read as UTC,
// not host-local.
//
// The main parity suite (forensic-normalize.test.js) runs in the host timezone (UTC in
// CI), so a host-local Date.parse() fallback is invisible to it. Here we spawn a probe
// under several non-UTC zones and assert that naive timestamps which only the
// last-resort parser handles normalize to the SAME, correct UTC instant everywhere.
// Covers both the backend (CJS) and renderer (ESM) copies via the probe.

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const PROBE = path.join(__dirname, "helpers", "tz-probe.cjs");
// Spread of offsets incl. the extremes (Kiritimati = UTC+14) to catch sign errors.
const ZONES = ["America/New_York", "Asia/Kolkata", "Pacific/Kiritimati", "UTC"];

// Inputs that bypass the explicit ISO / US-date / epoch branches and hit the
// last-resort path — exactly the formats that used to shift by the host offset.
const CASES = [
  { input: "2024/07/03 10:05:28",   expect: Date.UTC(2024, 6, 3, 10, 5, 28) },
  { input: "Jul 3 2024 10:05:28",   expect: Date.UTC(2024, 6, 3, 10, 5, 28) },
  { input: "July 3, 2024 10:05:28", expect: Date.UTC(2024, 6, 3, 10, 5, 28) },
  { input: "03-Jul-2024 10:05:28",  expect: Date.UTC(2024, 6, 3, 10, 5, 28) },
];

function probe(tz, inputs) {
  const out = execFileSync(process.execPath, [PROBE, ...inputs], {
    env: { ...process.env, TZ: tz },
    encoding: "utf8",
  });
  return JSON.parse(out).results;
}

for (const tz of ZONES) {
  test(`naive timestamps normalize to UTC under TZ=${tz}`, () => {
    const res = probe(tz, CASES.map((c) => c.input));
    for (const { input, expect } of CASES) {
      assert.equal(res[input].backend, expect, `backend "${input}" @ ${tz}`);
      assert.equal(res[input].renderer, expect, `renderer "${input}" @ ${tz}`);
    }
  });
}

test("naive timestamp ms is identical across all host timezones", () => {
  const inputs = CASES.map((c) => c.input);
  const perZone = ZONES.map((tz) => ({ tz, res: probe(tz, inputs) }));
  for (const input of inputs) {
    const vals = perZone.map((z) => z.res[input].backend);
    assert.equal(new Set(vals).size, 1, `"${input}" drifted across zones: ${JSON.stringify(vals)}`);
  }
});
