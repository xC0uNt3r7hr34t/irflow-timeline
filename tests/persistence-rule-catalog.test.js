// Persistence rule-catalog alignment guard.
//
// The persistence modal addresses rules POSITIONALLY (`evtx-<i>` / `reg-<i>`):
// checkboxes, technique presets and intent sets all send those ids to the
// analyzer, which resolves them against its own array indices. The renderer
// keeps a mirror of the rule list purely for display. When the two drift, every
// downstream control silently rewires onto a different rule — e.g. unchecking
// "Registry Value Modified (4657)" disabling the 7040 service rule instead, and
// rules past the end of the mirror becoming invisible and un-disableable.
//
// This test pins the mirror to the engine:
//   src/constants/persistenceRuleCatalog.mjs  ==  electron/analyzers/persistence/rules.js
//
// If it fails, fix the MIRROR to match the analyzer (append new rules at the end
// of the analyzer arrays — never reorder them).

const test = require("node:test");
const assert = require("node:assert/strict");
const { pathToFileURL } = require("node:url");

const { PERSISTENCE_RULE_CATALOG } = require("../electron/analyzers/persistence");

const loadMirror = () =>
  import(pathToFileURL(require.resolve("../src/constants/persistenceRuleCatalog.mjs")).href);

test("analyzer exports a positional rule catalog", () => {
  assert.ok(Array.isArray(PERSISTENCE_RULE_CATALOG.evtx), "evtx catalog missing");
  assert.ok(Array.isArray(PERSISTENCE_RULE_CATALOG.registry), "registry catalog missing");
  assert.ok(PERSISTENCE_RULE_CATALOG.evtx.length > 0);
  assert.ok(PERSISTENCE_RULE_CATALOG.registry.length > 0);
  PERSISTENCE_RULE_CATALOG.evtx.forEach((r, i) => assert.equal(r.id, `evtx-${i}`));
  PERSISTENCE_RULE_CATALOG.registry.forEach((r, i) => assert.equal(r.id, `reg-${i}`));
});

test("modal EVTX rule mirror matches the analyzer rule-for-rule", async () => {
  const { PA_EVTX_RULES } = await loadMirror();
  const engine = PERSISTENCE_RULE_CATALOG.evtx;

  assert.equal(
    PA_EVTX_RULES.length, engine.length,
    `EVTX rule count drift: modal has ${PA_EVTX_RULES.length}, analyzer has ${engine.length}. `
    + "Rules past the end of the modal list fire but cannot be seen or disabled.",
  );

  engine.forEach((eng, i) => {
    const ui = PA_EVTX_RULES[i];
    assert.equal(ui.id, eng.id, `evtx index ${i}: id drift`);
    assert.equal(ui.name, eng.name, `evtx-${i}: modal shows "${ui.name}" but the analyzer runs "${eng.name}"`);
    assert.equal(ui.cat, eng.cat, `evtx-${i} (${eng.name}): category drift`);
    assert.equal(ui.sev, eng.sev, `evtx-${i} (${eng.name}): severity drift`);
    // `hint` drives the pre-scan event-count estimate and the coverage chips.
    assert.equal(ui.hint, eng.hint, `evtx-${i} (${eng.name}): event-id drift`);
  });
});

test("modal registry rule mirror matches the analyzer rule-for-rule", async () => {
  const { PA_REG_RULES } = await loadMirror();
  const engine = PERSISTENCE_RULE_CATALOG.registry;

  assert.equal(
    PA_REG_RULES.length, engine.length,
    `Registry rule count drift: modal has ${PA_REG_RULES.length}, analyzer has ${engine.length}.`,
  );

  engine.forEach((eng, i) => {
    const ui = PA_REG_RULES[i];
    assert.equal(ui.id, eng.id, `reg index ${i}: id drift`);
    assert.equal(ui.name, eng.name, `reg-${i}: modal shows "${ui.name}" but the analyzer runs "${eng.name}"`);
    assert.equal(ui.cat, eng.cat, `reg-${i} (${eng.name}): category drift`);
    assert.equal(ui.sev, eng.sev, `reg-${i} (${eng.name}): severity drift`);
  });
});

test("every rule id referenced by a preset or intent resolves to a real rule", async () => {
  const mirror = await loadMirror();
  const { PA_EVTX_PRESETS, PA_REG_PRESETS, PA_INTENTS } = mirror;
  const evtxMax = mirror.PA_EVTX_RULES.length;
  const regMax = mirror.PA_REG_RULES.length;

  for (const preset of PA_EVTX_PRESETS) {
    assert.ok(preset.rules.length > 0, `EVTX preset "${preset.id}" selects no rules`);
    for (const i of preset.rules) {
      assert.ok(Number.isInteger(i) && i >= 0 && i < evtxMax, `EVTX preset "${preset.id}" references evtx-${i}, out of range`);
    }
  }
  for (const preset of PA_REG_PRESETS) {
    assert.ok(preset.rules.length > 0, `Registry preset "${preset.id}" selects no rules`);
    for (const i of preset.rules) {
      assert.ok(Number.isInteger(i) && i >= 0 && i < regMax, `Registry preset "${preset.id}" references reg-${i}, out of range`);
    }
  }
  for (const intent of PA_INTENTS) {
    for (const id of intent.disabled) {
      const m = /^(evtx|reg)-(\d+)$/.exec(id);
      assert.ok(m, `intent "${intent.id}" has malformed rule id "${id}"`);
      const limit = m[1] === "evtx" ? evtxMax : regMax;
      assert.ok(Number(m[2]) < limit, `intent "${intent.id}" references ${id}, out of range`);
    }
  }
});

test("presets reach every rule the analyzer ships", async () => {
  // A rule outside every preset is only reachable through the Advanced list. That
  // is allowed, but it must be a deliberate choice — this test documents the set.
  const { PA_EVTX_PRESETS, PA_REG_PRESETS, PA_EVTX_RULES, PA_REG_RULES } = await loadMirror();
  const covered = (presets, rules) => {
    const seen = new Set(presets.flatMap((p) => p.rules));
    return rules.map((_, i) => i).filter((i) => !seen.has(i));
  };
  // Account/Domain persistence rules are intentionally always-on (no preset card).
  assert.deepEqual(
    covered(PA_EVTX_PRESETS, PA_EVTX_RULES),
    [22, 23, 24, 25, 26, 27, 28, 29, 30],
    "unexpected set of EVTX rules missing from every preset",
  );
  assert.deepEqual(covered(PA_REG_PRESETS, PA_REG_RULES), [], "every registry rule should belong to a preset");
});

test("low-noise intent disables noisy rules, not high-value ones", async () => {
  const { PA_INTENTS, PA_EVTX_RULES, PA_REG_RULES } = await loadMirror();
  const lowNoise = PA_INTENTS.find((i) => i.id === "low-noise");
  assert.ok(lowNoise, "low-noise intent missing");

  const nameFor = (id) => {
    const m = /^(evtx|reg)-(\d+)$/.exec(id);
    return (m[1] === "evtx" ? PA_EVTX_RULES : PA_REG_RULES)[Number(m[2])].name;
  };
  const disabledNames = [...lowNoise.disabled].map(nameFor);

  // Regression guard for the 31/32/33 index drift: the intent used to disable
  // "Service StartType Changed" while believing it was turning off the noisy
  // 4657 registry fallback.
  assert.ok(disabledNames.includes("Registry Value Modified (4657)"), "low-noise should drop the 4657 registry fallback");
  assert.ok(!disabledNames.includes("Service Installed"), "low-noise must keep service installs");
  assert.ok(!disabledNames.includes("Service StartType Changed"), "low-noise must keep 7040 service start-type changes");
  assert.ok(!disabledNames.includes("WMI Event Subscription"), "low-noise must keep WMI persistence");
});
