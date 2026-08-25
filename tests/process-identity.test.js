const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function strip(src) {
  return src
    .replace(/^\s*import\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+[\w*\s,{}]+\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^export\s+\{[^}]*\}\s*;?\s*$/gm, "")
    .replace(/^export\s+/gm, "");
}

function load() {
  const root = path.join(__dirname, "..");
  const norm = strip(fs.readFileSync(path.join(root, "src/utils/forensic-normalize.js"), "utf8"));
  const id = strip(fs.readFileSync(path.join(root, "src/utils/process-identity.js"), "utf8"));
  const sandbox = { module: { exports: {} }, exports: {}, console, Math, Date, Number, String, Array, Object, Map, Set, JSON, RegExp };
  vm.createContext(sandbox);
  vm.runInContext(norm + "\n" + id + `
    module.exports = {
      processEntityKey, processBasename, processSessionScope,
      processIdentityFromNode, sameProcessEntity,
      normalizeGuid, normalizePid, normalizeHost,
    };
  `, sandbox);
  return sandbox.module.exports;
}

const api = load();

describe("process-identity", () => {
  it("prefers GUID for entity key", () => {
    const k = api.processEntityKey({
      guid: "{AABB-CCDD}",
      pid: "1234",
      hostname: "WS01",
      tsMs: 1,
    });
    assert.equal(k, "guid:aabb-ccdd");
  });

  it("falls back to host|pid|ts when no GUID", () => {
    const k = api.processEntityKey({
      pid: "0x10",
      hostname: "ws01",
      tsMs: 1000,
    });
    assert.ok(k.startsWith("pid:"));
    assert.ok(k.includes("16")); // hex pid normalized
  });

  it("sameProcessEntity matches by GUID", () => {
    const a = api.processIdentityFromNode({ guid: "{X}", pid: "1", hostname: "A" });
    const b = api.processIdentityFromNode({ guid: "X", pid: "9", hostname: "B" });
    assert.equal(api.sameProcessEntity(a, b), true);
  });

  it("processBasename strips path and .exe", () => {
    assert.equal(api.processBasename("C:\\\\Windows\\\\System32\\\\cmd.EXE"), "cmd");
  });
});
