const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function load() {
  const root = path.join(__dirname, "..");
  const src = fs.readFileSync(path.join(root, "src/utils/process-verdict-hero.js"), "utf8")
    .replace(/^export\s+/gm, "")
    .replace(/export\s*\{[^}]+\}\s*;?/g, "");
  const sandbox = { module: { exports: {} }, exports: {}, console, Math, Number, String, Array, Object, Map, Set, JSON };
  vm.createContext(sandbox);
  vm.runInContext(src + `
    module.exports = {
      buildProcessVerdictHero,
      summarizeLinkQuality,
      summarizeTelemetryCompleteness,
    };
  `, sandbox);
  return sandbox.module.exports;
}

const api = load();

describe("process-verdict-hero", () => {
  it("reports critical verdict from detMap and top stories", () => {
    const detMap = new Map([
      ["a", { level: 3, techniques: ["T1059.001"], reason: "Office → PS" }],
      ["b", { level: 2, techniques: ["T1059.001", "T1105"], reason: "Encoded PS" }],
      ["c", { level: 0, reason: null }],
    ]);
    const stories = [
      { id: "s1", title: "Office macro chain", level: 3, hostname: "WS1", leadReason: "Word → PS", eventCount: 4, techniques: ["T1059.001"], anchorKey: "a" },
      { id: "s2", title: "Secondary", level: 2, hostname: "WS1", leadReason: "x", eventCount: 2, techniques: [], anchorKey: "b" },
    ];
    const hero = api.buildProcessVerdictHero({
      data: {
        processes: [{}, {}, {}],
        stats: {
          totalProcesses: 3,
          truncated: true,
          terminateMatched: 2,
          accessMatched: 0,
          privilegeMatched: 1,
          linkCounts: { guid: 95, "pid-host": 5 },
        },
        useGuid: true,
      },
      detMap,
      stories,
    });
    assert.equal(hero.verdict, "critical");
    assert.equal(hero.counts.critical, 1);
    assert.equal(hero.counts.high, 1);
    assert.equal(hero.truncated, true);
    assert.equal(hero.topStories[0].title, "Office macro chain");
    assert.ok(hero.techniques.some((t) => t.tid === "T1059.001"));
    assert.equal(hero.linkQuality.mode, "guid");
    assert.equal(hero.telemetry.terminate.present, true);
    assert.equal(hero.telemetry.processAccess.present, false);
    assert.equal(hero.telemetry.privilegeUse.present, true);
  });

  it("summarizeLinkQuality classifies PID-heavy trees", () => {
    const q = api.summarizeLinkQuality({ linkCounts: { "pid-logon": 90, guid: 5 } });
    assert.equal(q.mode, "pid");
  });
});
