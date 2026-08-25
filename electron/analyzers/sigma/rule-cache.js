/**
 * sigma/rule-cache.js — Sigma Rule Download, Caching, and Management
 *
 * Downloads Sigma rules from SigmaHQ GitHub, caches locally, and manages
 * custom rules from a user-specified local folder.
 *
 * Storage layout (in app.getPath("userData")):
 *   sigma-rules/
 *     meta.json          - { lastUpdate, commitHash, ruleCount, source }
 *     rules.json         - Pre-parsed rules array (avoids re-parsing YAML)
 *     custom/            - User's custom rules (YAML files)
 */

const fs = require("fs");
const path = require("path");
const https = require("https");
const os = require("os");
const crypto = require("crypto");
// Electron's `app` is only available in the main process. This module is also loaded
// inside the Sigma scan worker thread, where the 'electron' module is not resolvable
// in a packaged build (it would throw "Cannot find module 'electron'" and abort the
// whole scan). Guard the require so `app` is simply undefined off the main thread —
// getUserDataPath() then falls back to TLE_USER_DATA_PATH, which sigma-worker.js sets
// from workerData.userDataPath.
let app;
try { ({ app } = require("electron")); } catch { /* worker thread / non-Electron context */ }
const { parseDirectory, parseDirectoryDetailed, parseFile, parseFileDetailed } = require("./rule-parser");
const { annotateRuleCompatibility, buildRuleCompatibilityReport } = require("./rule-compatibility");
const { dbg } = require("../../logger");
const { extractTarGzBuffer } = require("./node-io-utils");

const CACHE_DIR_NAME = "sigma-rules";

// Top Sigma rule repositories used by the cybersecurity industry
const SIGMA_REPOS = [
  { id: "sigmahq", repo: "SigmaHQ/sigma", name: "SigmaHQ (Official)", desc: "Official Sigma rules — 3,000+ community-maintained detections", rulesPath: "rules/windows", default: true },
  { id: "hayabusa", repo: "Yamato-Security/hayabusa-rules", name: "Hayabusa Rules", desc: "4,000+ Windows event log rules optimized for DFIR timelines", rulesPath: "rules", default: true },
  { id: "dfir-report", repo: "The-DFIR-Report/Sigma-Rules", name: "The DFIR Report", desc: "Rules from real-world incident response investigations", rulesPath: "", default: true },
  { id: "mdecrevoisier", repo: "mdecrevoisier/SIGMA-detection-rules", name: "SIGMA Detection Rules", desc: "350+ advanced correlation rules mapped to MITRE ATT&CK", rulesPath: "", default: false },
  { id: "elastic", repo: "elastic/detection-rules", name: "Elastic Security", desc: "Enterprise-grade detection rules from Elastic", rulesPath: "rules", default: false },
  { id: "bls", repo: "blacklanternsecurity/sigma-rules", name: "Black Lantern Security", desc: "Community rules organized by ATT&CK techniques", rulesPath: "", default: false },
  { id: "p4t12ick", repo: "P4T12ICK/Sigma-Rule-Repository", name: "Sigma Rule Repository", desc: "Tested rules with validation documentation", rulesPath: "", default: false },
  { id: "panther", repo: "panther-labs/panther-analysis", name: "Panther Analysis", desc: "Production-grade detections from Panther Labs", rulesPath: "rules/sigma", default: false },
  { id: "socprime", repo: "socprime/SigmaRulesIntegration", name: "SOC Prime", desc: "Free Sigma rules for SIEM integration", rulesPath: "", default: false },
  { id: "mbabinski", repo: "mbabinski/Sigma-Rules", name: "Mbabinski Rules", desc: "Practical SOC-focused correlation rules", rulesPath: "", default: false },
];
const CUSTOM_DIR_NAME = "custom";
const META_FILE = "meta.json";
const RULES_FILE = "rules.json";

/**
 * Get Electron's userData path from either the main process app module or a
 * worker-provided environment variable. Worker threads do not expose
 * electron.app, but they still need read-only access to cached Sigma rules.
 */
function getUserDataPath() {
  if (app?.getPath) return app.getPath("userData");
  if (process.env.TLE_USER_DATA_PATH) return process.env.TLE_USER_DATA_PATH;
  return path.join(os.homedir(), ".irflow-timeline");
}

/**
 * Get the sigma cache directory path.
 */
function getCacheDir() {
  const dir = path.join(getUserDataPath(), CACHE_DIR_NAME);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Get the custom rules directory path.
 */
function getCustomDir() {
  const dir = path.join(getCacheDir(), CUSTOM_DIR_NAME);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Read cached metadata.
 */
function readMeta() {
  try {
    const p = path.join(getCacheDir(), META_FILE);
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (_) {}
  return null;
}

/**
 * Write metadata.
 */
function writeMeta(meta) {
  try {
    fs.writeFileSync(path.join(getCacheDir(), META_FILE), JSON.stringify(meta, null, 2), "utf8");
  } catch (_) {}
}

/**
 * Read cached rules (pre-parsed JSON).
 */
function readCachedRules() {
  try {
    const p = path.join(getCacheDir(), RULES_FILE);
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (_) {}
  return null;
}

/**
 * Write rules to cache.
 */
function writeCachedRules(rules) {
  try {
    fs.writeFileSync(path.join(getCacheDir(), RULES_FILE), JSON.stringify(rules), "utf8");
  } catch (err) {
    dbg("SIGMA", `Failed to write rules cache: ${err.message}`);
  }
}

function hashString(value) {
  return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");
}

function stableRuleForHash(rule) {
  return {
    id: rule.id || "",
    title: rule.title || "",
    status: rule.status || "",
    level: rule.level || "",
    logsource: rule.logsource || {},
    detection: rule.detection || {},
    tags: rule.tags || [],
    sourceRepo: rule._sourceRepo || "",
    filePath: rule._sourceRepoRelativePath || rule._fileName || "",
    docIndex: rule._docIndex || 0,
  };
}

function hashRules(rules = []) {
  const stable = (rules || [])
    .map(stableRuleForHash)
    .sort((a, b) => `${a.sourceRepo}|${a.filePath}|${a.docIndex}|${a.id}|${a.title}`.localeCompare(`${b.sourceRepo}|${b.filePath}|${b.docIndex}|${b.id}|${b.title}`));
  return hashString(JSON.stringify(stable));
}

function hashDirectoryFiles(rootDir) {
  const files = [];
  const walk = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (![".git", "node_modules", "__MACOSX"].includes(entry.name)) walk(full);
        continue;
      }
      if (!entry.isFile() || !/\.ya?ml$/i.test(entry.name)) continue;
      try {
        files.push({
          path: path.relative(rootDir, full).split(path.sep).join("/"),
          hash: crypto.createHash("sha256").update(fs.readFileSync(full)).digest("hex"),
        });
      } catch {}
    }
  };
  if (rootDir && fs.existsSync(rootDir)) walk(rootDir);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return hashString(JSON.stringify(files));
}

function mergeParseReports(reports = []) {
  const out = {
    filesScanned: 0,
    documentsScanned: 0,
    parsed: 0,
    skipped: 0,
    skippedRules: [],
    parseErrors: [],
  };
  for (const report of reports || []) {
    out.filesScanned += report?.filesScanned || 0;
    out.documentsScanned += report?.documentsScanned || 0;
    out.parsed += report?.parsed || 0;
    out.skipped += report?.skipped || 0;
    out.skippedRules.push(...(report?.skippedRules || []));
    out.parseErrors.push(...(report?.parseErrors || []));
  }
  return out;
}

function annotateRules(rules = []) {
  return (rules || []).map((rule) => annotateRuleCompatibility(rule));
}

async function fetchJson(url) {
  const data = await httpsGet(url, { Accept: "application/vnd.github+json" });
  return JSON.parse(data.toString("utf8"));
}

async function resolveRepoRef(repo) {
  const repoData = await fetchJson(`https://api.github.com/repos/${repo}`);
  const branch = repoData.default_branch || "main";
  const commitData = await fetchJson(`https://api.github.com/repos/${repo}/commits/${encodeURIComponent(branch)}`);
  const commitHash = commitData.sha || commitData.commit?.tree?.sha || null;
  return {
    branch,
    commitHash,
    commitDate: commitData.commit?.committer?.date || commitData.commit?.author?.date || null,
    htmlUrl: commitData.html_url || null,
  };
}

/**
 * HTTPS GET helper that follows redirects (GitHub API returns 302s).
 */
function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: { "User-Agent": "IRFlow-Timeline/1.0", ...headers },
    };
    const req = https.get(url, opts, (res) => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpsGet(res.headers.location, headers).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${url}`));
        res.resume();
        return;
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error("Request timeout")); });
  });
}

/**
 * Download a single repo's tarball and extract YAML rules.
 * @param {object} repoInfo - { id, repo, name, rulesPath }
 * @param {Function} onProgress
 * @returns {Promise<{rules: Array, repoSnapshot: object, parseReport: object}>}
 */
async function downloadSingleRepo(repoInfo, onProgress) {
  const { repo, name, rulesPath } = repoInfo;
  onProgress?.("downloading", `Resolving ${name} repository revision...`);

  let repoRef = null;
  try {
    repoRef = await resolveRepoRef(repo);
  } catch (err) {
    dbg("SIGMA", `Failed to resolve ${repo} default branch commit: ${err.message}`);
    repoRef = { branch: "main", commitHash: null, commitDate: null, htmlUrl: null, resolutionError: err.message };
  }

  const tarballRef = repoRef.commitHash || repoRef.branch || "main";
  onProgress?.("downloading", `Fetching ${name}${repoRef.commitHash ? ` @ ${repoRef.commitHash.slice(0, 12)}` : ""}...`);

  const apiUrl = `https://api.github.com/repos/${repo}/tarball/${encodeURIComponent(tarballRef)}`;
  let tarball;
  try {
    tarball = await httpsGet(apiUrl);
  } catch (_) {
    try { tarball = await httpsGet(`https://api.github.com/repos/${repo}/tarball/master`); repoRef.branch = "master"; repoRef.commitHash = null; }
    catch (err2) { throw new Error(`Failed to download ${name}: ${err2.message}`); }
  }

  onProgress?.("extracting", `${name}: ${(tarball.length / 1024 / 1024).toFixed(1)} MB, extracting...`);

  const tmpDir = path.join(getCacheDir(), `_tmp_${repoInfo.id}`);
  if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true });
  fs.mkdirSync(tmpDir, { recursive: true });

  try {
    extractTarGzBuffer(tarball, tmpDir);
  } catch (err) {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    throw new Error(`Failed to extract ${name}: ${err.message}`);
  }

  // Find extracted directory
  const entries = fs.readdirSync(tmpDir).filter(f => !f.startsWith(".") && f !== "rules.tar.gz");
  const extracted = entries[0];
  if (!extracted) { try { fs.rmSync(tmpDir, { recursive: true }); } catch (_) {} throw new Error(`Cannot find extracted directory for ${name}`); }

  // Determine rules directory
  let rulesDir = path.join(tmpDir, extracted);
  if (rulesPath) {
    const sub = path.join(rulesDir, rulesPath);
    if (fs.existsSync(sub)) rulesDir = sub;
  }

  onProgress?.("parsing", `Parsing ${name} rules...`);
  const parsed = parseDirectoryDetailed(rulesDir);
  const rules = parsed.rules;

  // Tag each rule with source repo and a stable relative path for reproducible hashes.
  for (const r of rules) {
    r._sourceRepo = repoInfo.id;
    r._sourceRepoName = name;
    r._sourceRepoRelativePath = r._filePath ? path.relative(rulesDir, r._filePath).split(path.sep).join("/") : r._fileName || "";
  }
  annotateRules(rules);
  const compatibilityReport = buildRuleCompatibilityReport(rules, parsed.report);
  const repoSnapshot = {
    id: repoInfo.id,
    repo,
    name,
    branch: repoRef.branch || null,
    commitHash: repoRef.commitHash || null,
    commitDate: repoRef.commitDate || null,
    commitUrl: repoRef.htmlUrl || null,
    tarballRef,
    rulesPath: rulesPath || "",
    ruleCount: rules.length,
    ruleSnapshotHash: hashRules(rules),
    rawRuleSnapshotHash: hashDirectoryFiles(rulesDir),
    compatibilityReport,
    resolutionError: repoRef.resolutionError || null,
  };

  try { fs.rmSync(tmpDir, { recursive: true }); } catch (_) {}
  return { rules, repoSnapshot, parseReport: parsed.report };
}

/**
 * Download Sigma rules from selected GitHub repositories.
 *
 * @param {string[]} repoIds - Array of repo IDs to download (from SIGMA_REPOS)
 * @param {Function} onProgress - (phase, detail) callback
 * @returns {Promise<{rules: Array, meta: object}>}
 */
async function downloadFromGitHub(repoIdsOrProgress, onProgress) {
  // Backward compat: if first arg is a function, it's the old single-arg signature
  let repoIds;
  if (typeof repoIdsOrProgress === "function") {
    onProgress = repoIdsOrProgress;
    repoIds = SIGMA_REPOS.filter(r => r.default).map(r => r.id);
  } else {
    repoIds = repoIdsOrProgress || SIGMA_REPOS.filter(r => r.default).map(r => r.id);
  }

  const allRules = [];
  const errors = [];
  const repoSnapshots = [];
  const parseReports = [];
  const updateLog = [];
  const startedAt = new Date().toISOString();

  for (let i = 0; i < repoIds.length; i++) {
    const repoInfo = SIGMA_REPOS.find(r => r.id === repoIds[i]);
    if (!repoInfo) { errors.push(`Unknown repo ID: ${repoIds[i]}`); continue; }

    onProgress?.("downloading", `(${i + 1}/${repoIds.length}) Fetching ${repoInfo.name}...`);
    try {
      const repoResult = await downloadSingleRepo(repoInfo, (phase, detail) => {
        updateLog.push(`[${new Date().toISOString()}] ${phase}: ${detail}`);
        onProgress?.(phase, `(${i + 1}/${repoIds.length}) ${detail}`);
      });
      const rules = repoResult.rules || [];
      allRules.push(...rules);
      if (repoResult.repoSnapshot) repoSnapshots.push(repoResult.repoSnapshot);
      if (repoResult.parseReport) parseReports.push(repoResult.parseReport);
      dbg("SIGMA", `Downloaded ${rules.length} rules from ${repoInfo.name}`);
    } catch (err) {
      errors.push(`${repoInfo.name}: ${err.message}`);
      updateLog.push(`[${new Date().toISOString()}] error: ${repoInfo.name}: ${err.message}`);
      dbg("SIGMA", `Failed to download ${repoInfo.name}: ${err.message}`);
    }
  }

  const compatibilityReport = buildRuleCompatibilityReport(allRules, mergeParseReports(parseReports));
  const ruleSnapshotHash = hashRules(allRules);

  // Cache all rules
  writeCachedRules(allRules);
  const meta = {
    lastUpdate: new Date().toISOString(),
    updateStartedAt: startedAt,
    source: "github",
    repos: repoIds,
    repoNames: repoIds.map(id => SIGMA_REPOS.find(r => r.id === id)?.name || id),
    ruleCount: allRules.length,
    ruleSnapshotHash,
    repoSnapshots,
    compatibilityReport,
    updateLog,
    errors: errors.length > 0 ? errors : undefined,
  };
  writeMeta(meta);

  onProgress?.("done", `${allRules.length} rules loaded from ${repoIds.length} repo${repoIds.length > 1 ? "s" : ""}${errors.length > 0 ? ` (${errors.length} failed)` : ""}`);

  return { rules: allRules, meta, errors };
}

/**
 * Get the list of available repositories.
 */
function getAvailableRepos() {
  return SIGMA_REPOS.map(r => ({ id: r.id, name: r.name, desc: r.desc, repo: r.repo, default: r.default }));
}

/**
 * Load rules from a local directory (custom rules or manual import).
 *
 * @param {string} dirPath - Directory containing YAML files
 * @param {Function} onProgress
 * @returns {{ rules: Array, count: number }}
 */
function loadLocalRules(dirPath, onProgress) {
  if (!fs.existsSync(dirPath)) return { rules: [], count: 0 };
  const parsed = parseDirectoryDetailed(dirPath, onProgress);
  const rules = annotateRules(parsed.rules);
  return { rules, count: rules.length, compatibilityReport: buildRuleCompatibilityReport(rules, parsed.report), parseReport: parsed.report };
}

/**
 * Load custom rules from the user's custom rules directory.
 */
function loadCustomRules() {
  return loadCustomRulesDetailed().rules;
}

function loadCustomRulesDetailed() {
  const customDir = getCustomDir();
  if (!fs.existsSync(customDir)) return { rules: [], parseReport: null };
  const parsed = parseDirectoryDetailed(customDir);
  return { rules: annotateRules(parsed.rules), parseReport: parsed.report };
}

/**
 * Import a YAML file into the custom rules directory.
 */
function importCustomRule(filePath) {
  const customDir = getCustomDir();
  const dest = path.join(customDir, path.basename(filePath));
  fs.copyFileSync(filePath, dest);
  const parsed = parseFileDetailed(dest);
  return annotateRules(parsed.rules)[0] || parseFile(dest);
}

/**
 * Deduplicate rules by ID (or title+logsource fallback).
 * When duplicates exist, prefer the rule from the higher-priority source
 * (custom > earlier repo). This prevents inflated match counts when
 * multiple repos ship the same rule (e.g., SigmaHQ + Hayabusa).
 */
function deduplicateRules(rules) {
  const seen = new Map(); // key -> rule
  const deduped = [];
  for (const r of rules) {
    // Prefer rule ID; fall back to title + logsource fingerprint
    const key = r.id
      ? r.id
      : `${r.title}|${r.logsource?.category || ""}|${r.logsource?.service || ""}`;
    if (!key) { deduped.push(r); continue; }
    if (!seen.has(key)) {
      seen.set(key, r);
      deduped.push(r);
    }
    // else: skip duplicate, keep first occurrence (custom rules are prepended)
  }
  return deduped;
}

/**
 * Locate the Sigma rules bundled inside the Hayabusa resources, if present.
 * process.resourcesPath is only defined in the Electron main process; worker threads
 * receive it via TLE_RESOURCES_PATH (set by sigma-worker.js from workerData).
 * @returns {string|null} absolute path to <resources>/hayabusa/rules/sigma, or null
 */
function getBundledSigmaRulesDir() {
  const base = process.resourcesPath || process.env.TLE_RESOURCES_PATH;
  if (!base) return null;
  const dir = path.join(base, "hayabusa", "rules", "sigma");
  try {
    return fs.existsSync(dir) ? dir : null;
  } catch {
    return null;
  }
}

/**
 * One-time offline seed: when no rules have been downloaded yet, populate the cache
 * from the bundled Hayabusa Sigma rule set so the JS Sigma engine works with no network
 * access. Never clobbers an existing download. Idempotent — writes rules.json so the
 * (expensive) directory parse runs at most once per cache.
 *
 * @param {Function} [onProgress] - (phase, detail) callback
 * @returns {{ seeded: boolean, count: number, error?: string }}
 */
function seedBundledRulesIfEmpty(onProgress) {
  const existing = readCachedRules();
  if (existing && existing.length > 0) return { seeded: false, count: existing.length };

  const bundledDir = getBundledSigmaRulesDir();
  if (!bundledDir) return { seeded: false, count: 0 };

  try {
    onProgress?.("parsing", "First-time offline setup: loading bundled Sigma rules...");
    const parsed = parseDirectoryDetailed(bundledDir);
    const rules = annotateRules(parsed.rules);
    if (rules.length === 0) return { seeded: false, count: 0 };

    for (const r of rules) {
      r._sourceRepo = "bundled";
      r._sourceRepoName = "Bundled Sigma Rules";
      r._sourceRepoRelativePath = r._filePath
        ? path.relative(bundledDir, r._filePath).split(path.sep).join("/")
        : (r._fileName || "");
    }

    writeCachedRules(rules);
    const compatibilityReport = buildRuleCompatibilityReport(rules, parsed.report);
    writeMeta({
      lastUpdate: new Date().toISOString(),
      source: "bundled",
      repos: ["bundled"],
      repoNames: ["Bundled Sigma Rules (offline)"],
      ruleCount: rules.length,
      ruleSnapshotHash: hashRules(rules),
      compatibilityReport,
      bundled: true,
    });
    dbg("SIGMA", `Seeded ${rules.length} Sigma rules from bundled Hayabusa rules (${bundledDir})`);
    return { seeded: true, count: rules.length };
  } catch (err) {
    dbg("SIGMA", `Failed to seed bundled Sigma rules: ${err.message}`);
    return { seeded: false, count: 0, error: err.message };
  }
}

/**
 * Get all available rules: cached SigmaHQ + custom rules (deduplicated).
 *
 * @returns {{ rules: Array, meta: object|null, customCount: number }}
 */
function getAllRules() {
  // No downloaded rules yet → seed from the Sigma rules bundled inside the Hayabusa
  // resources (offline-capable). TLS-intercepting corporate/DFIR networks block the
  // GitHub rule download, which would otherwise leave the JS Sigma engine with zero
  // rules ("No Sigma rules loaded"). The seed writes rules.json once, so this parse
  // happens at most once per cache.
  let cached = readCachedRules();
  if (!cached || cached.length === 0) {
    seedBundledRulesIfEmpty();
    cached = readCachedRules();
  }
  const cachedRules = annotateRules(cached || []);
  const custom = loadCustomRulesDetailed();
  const customRules = custom.rules;
  // Mark custom rules
  for (const r of customRules) r._isCustom = true;
  const meta = readMeta();
  // Custom rules first so they take priority in dedup
  const allRules = deduplicateRules([...customRules, ...cachedRules]);
  const compatibilityReport = buildRuleCompatibilityReport(allRules, mergeParseReports([
    meta?.compatibilityReport ? {
      filesScanned: meta.compatibilityReport.filesScanned || 0,
      documentsScanned: meta.compatibilityReport.documentsScanned || 0,
      parsed: meta.compatibilityReport.parsed || cachedRules.length,
      skipped: meta.compatibilityReport.skipped || 0,
      skippedRules: meta.compatibilityReport.skippedRules || [],
      parseErrors: meta.compatibilityReport.parseErrors || [],
    } : null,
    custom.parseReport,
  ].filter(Boolean)));
  return {
    rules: allRules,
    meta,
    cachedCount: cachedRules.length,
    customCount: customRules.length,
    compatibilityReport,
    ruleSnapshotHash: hashRules(allRules),
  };
}

/**
 * Get cache status info for the UI.
 */
function getCacheStatus() {
  let meta = readMeta();
  const customDir = getCustomDir();
  let customCount = 0;
  try {
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) walk(path.join(dir, e.name));
        else if (/\.ya?ml$/i.test(e.name)) customCount++;
      }
    };
    if (fs.existsSync(customDir)) walk(customDir);
  } catch (_) {}

  let compatibilityReport = meta?.compatibilityReport || null;
  let ruleSnapshotHash = meta?.ruleSnapshotHash || null;
  try {
    const all = getAllRules();
    // getAllRules() may have just seeded the cache from bundled rules (writing meta.json),
    // so prefer the meta it returns over the snapshot read before the seed.
    if (all.meta) meta = all.meta;
    compatibilityReport = all.compatibilityReport || compatibilityReport;
    ruleSnapshotHash = all.ruleSnapshotHash || ruleSnapshotHash;
  } catch (_) {}

  return {
    lastUpdate: meta?.lastUpdate || null,
    source: meta?.source || null,
    cachedRuleCount: meta?.ruleCount || 0,
    customRuleCount: customCount,
    customDir,
    cacheDir: getCacheDir(),
    ruleSnapshotHash,
    repoSnapshots: meta?.repoSnapshots || [],
    compatibilityReport,
    updateLog: meta?.updateLog || [],
  };
}

module.exports = {
  downloadFromGitHub,
  loadLocalRules,
  loadCustomRules,
  importCustomRule,
  getAllRules,
  getCacheStatus,
  getCacheDir,
  getCustomDir,
  getAvailableRepos,
  getBundledSigmaRulesDir,
  seedBundledRulesIfEmpty,
  SIGMA_REPOS,
};
