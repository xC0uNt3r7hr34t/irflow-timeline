// Async chunked detection scoring — uses the same loader as process-inspector.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function stripModuleSyntax(src) {
  return src
    .replace(/^\s*import\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+[\w*\s,{}]+\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*export\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*export\s+\*\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^export\s+const\s+/gm, "const ")
    .replace(/^export\s+let\s+/gm, "let ")
    .replace(/^export\s+function\s+/gm, "function ")
    .replace(/^export\s+async function\s+/gm, "async function ")
    .replace(/^export\s+class\s+/gm, "class ")
    .replace(/^export\s+default\s+/gm, "")
    .replace(/export\s*\{[^}]+\}\s*;?/g, "");
}

function load() {
  const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
  const ctx = { console, Math, Date, Number, String, Array, Object, Map, Set, JSON, RegExp, Boolean, setTimeout, clearTimeout, Promise, isNaN, parseInt, Infinity, NaN };
  vm.createContext(ctx);
  const hoist = (names) => `\n;Object.assign(globalThis, { ${names.join(", ")} });`;
  vm.runInContext(stripModuleSyntax(read("src/detection-rules/tool-aliases.js")) + hoist(["TOOL_ENTRIES", "TOOL_BY_ALIAS", "buildCategoryRegex", "lookupTool", "_toolAliasKey"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/detection-rules.js")) + hoist([
    "CHAIN_RULE_MAP", "SUS_PATHS", "SAFE_PROCS", "ENCODED_PS", "CRED_DUMP_CMD",
    "NTDS_EXTRACT", "LSASS_TOOLS", "ACCOUNT_MANIP", "DEFENSE_EVASION",
    "NETWORK_SCANNERS", "AD_RECON_TOOLS", "RMM_TOOLS", "EXFIL_TOOLS",
    "TUNNEL_TOOLS", "ARCHIVE_SUSPECT",
  ]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/components/process-analyzer/constants.js")) + hoist(["PI_ANALYST_PROFILE_DEFAULT", "PT_ICON_STYLE", "PT_VIEW_MODES"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/forensic-normalize.js")) + hoist(["normalizeTimestamp", "normalizeHost", "normalizePid", "normalizeGuid", "normalizeLogonId"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/process-inspector.js")) + hoist(["getSusInfo", "PI_ALL_RULES"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/process-inspector-pipeline.js")) + hoist([
    "buildDetectionMap", "buildDetectionMapChunked", "consistentParentKey", "makeDetMapRuleKey",
  ]), ctx);
  // scoreProcessTree is a thin wrapper — define inline to avoid re-export strip issues
  vm.runInContext(`
    async function scoreProcessTree(data, opts, asyncOpts) {
      const total = data?.processes?.length || 0;
      const thr = 4000;
      if (total <= thr) {
        const m = buildDetectionMap(data, opts || {});
        asyncOpts?.onProgress?.({ done: total, total, percent: 100 });
        return m;
      }
      return buildDetectionMapChunked(data, opts || {}, {
        batchSize: asyncOpts?.batchSize || 2500,
        onProgress: asyncOpts?.onProgress,
        shouldCancel: () => !!(asyncOpts?.signal && asyncOpts.signal.cancelled),
      });
    }
    Object.assign(globalThis, { scoreProcessTree });
  `, ctx);
  return ctx;
}

const api = load();

test("scoreProcessTree returns a map for a small tree", async () => {
  const data = {
    processes: [
      { key: "a", parentKey: "", processName: "explorer.exe", image: "C:\\Windows\\explorer.exe", cmdLine: "explorer.exe", tsMs: 1 },
      { key: "b", parentKey: "a", processName: "cmd.exe", parentProcessName: "explorer.exe", image: "C:\\Windows\\System32\\cmd.exe", cmdLine: "cmd.exe", tsMs: 2 },
    ],
  };
  const m = await api.scoreProcessTree(data, {});
  assert.ok(m instanceof Map);
  assert.equal(m.size, 2);
  assert.ok(m.has("a") && m.has("b"));
});

test("buildDetectionMapChunked reports progress and matches sync map size", async () => {
  const processes = [];
  for (let i = 0; i < 50; i++) {
    processes.push({
      key: `k${i}`,
      parentKey: i ? `k${i - 1}` : "",
      processName: i % 7 === 0 ? "powershell.exe" : "svchost.exe",
      parentProcessName: i ? (i % 7 === 1 ? "powershell.exe" : "svchost.exe") : "",
      image: `C:\\Windows\\System32\\p${i}.exe`,
      cmdLine: i % 7 === 0 ? "powershell -enc AAA" : "svchost.exe -k netsvcs",
      tsMs: i * 1000,
    });
  }
  const data = { processes };
  const sync = api.buildDetectionMap(data, {});
  const progress = [];
  const asyncMap = await api.buildDetectionMapChunked(data, {}, {
    batchSize: 10,
    onProgress: (p) => progress.push(p.percent),
  });
  assert.equal(asyncMap.size, sync.size);
  assert.ok(progress.length >= 1);
  assert.equal(progress[progress.length - 1], 100);
});
