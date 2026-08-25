// Forensic verdicts must not depend on where the analyst is sitting.
//
// RDP off-hours scoring used `new Date(startTime).getHours()/.getDay()`. That is wrong
// twice over: a zone-less timestamp is parsed as HOST-LOCAL by ECMA-262, and the hour is
// then READ in host-local too. An analyst in UTC+8 opening the same evidence saw
// different suspicion scores and different "Weekend / Off-hours" flags than a colleague
// in UTC. The app convention (CLAUDE.md) is that naive timestamps are UTC.
//
// Runs the identical fixture under several TZ settings in child processes and requires
// byte-identical scoring.

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const RUNNER = path.join(__dirname, "helpers", "lm-tz-run.cjs");

const ZONES = ["UTC", "Asia/Manila", "America/New_York", "Australia/Sydney"];

// Each run is a child process (TZ must be set before Node starts). Memoize so the three
// tests below share 8 spawns rather than 20 — spawning that many under parallel test
// load made this file intermittently time out.
const _runCache = new Map();
function runUnderTz(tz, style = "naive") {
  const key = `${tz}|${style}`;
  if (!_runCache.has(key)) {
    const out = execFileSync(process.execPath, [RUNNER, style], {
      env: { ...process.env, TZ: tz },
      encoding: "utf8",
      timeout: 60000,
    });
    _runCache.set(key, JSON.parse(out));
  }
  return _runCache.get(key);
}

for (const style of ["naive", "zulu"]) {
  test(`RDP off-hours scoring is identical across analyst timezones (${style} timestamps)`, () => {
    // 02:00 UTC Tuesday is off-hours in UTC. In UTC+8 it is 10:00 (business hours); in
    // UTC-5 it is 21:00 the previous day.
    const results = ZONES.map((tz) => ({ tz, ...runUnderTz(tz, style) }));
    const baseline = results[0];
    for (const r of results.slice(1)) {
      assert.deepEqual(
        r.sessions, baseline.sessions,
        `session scoring under TZ=${r.tz} differs from TZ=${baseline.tz} (${style})`,
      );
    }
  });
}

test("the same instant scores the same whether written naive or with an explicit Z", () => {
  // This is the assertion the old code failed: for naive input its parse-as-local and
  // read-as-local errors cancelled, but a zone-suffixed timestamp parsed as UTC and was
  // then read in local time, shifting the hour by the analyst's offset.
  for (const tz of ZONES) {
    const naive = runUnderTz(tz, "naive");
    const zulu = runUnderTz(tz, "zulu");
    assert.deepEqual(
      zulu.sessions, naive.sessions,
      `TZ=${tz}: "2026-03-10 02:00:00" and "2026-03-10T02:00:00Z" are the same instant and must score identically`,
    );
  }
});

test("off-hours is judged in UTC, not local time", () => {
  for (const style of ["naive", "zulu"]) {
    const r = runUnderTz("Asia/Manila", style);
    const offHours = r.sessions.filter((s) => s.flags.some((f) => /off-hours/i.test(f)));
    assert.ok(
      offHours.length > 0,
      `a 02:00 UTC session must read as off-hours regardless of TZ (${style}), got ${JSON.stringify(r.sessions.map((s) => s.flags))}`,
    );
    assert.ok(
      offHours.every((s) => s.flags.some((f) => /UTC/.test(f))),
      "the flag should say which clock it used",
    );
  }
});
