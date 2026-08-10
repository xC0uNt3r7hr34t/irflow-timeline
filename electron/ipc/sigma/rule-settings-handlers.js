const { dialog, shell } = require("electron");
const { openDialogOptions } = require("../../utils/open-dialog");

module.exports = function registerSigmaRuleSettingsHandlers(ctx) {
  const {
    safeHandle,
    safeSend,
    _activeWindow,
    pathAuthorizer,
    detectionSettings,
    ruleSuppression,
    downloadFromGitHub,
    getAvailableRepos,
    getCacheStatus,
    getAllRules,
    loadLocalRules,
    importCustomRule,
    getCustomDir,
    _authorizeAppManagedPaths,
    _authorizePersistedDetectionSettingsPaths,
    _assertDetectionSettingsPathsAuthorized,
    _syncRuleSuppressionsToHayabusa,
  } = ctx;

  safeHandle("sigma-get-repos", () => {
    return getAvailableRepos();
  });

  safeHandle("sigma-get-status", () => {
    _authorizeAppManagedPaths();
    return getCacheStatus();
  });

  safeHandle("sigma-get-detection-settings", () => {
    const settings = detectionSettings.loadDetectionSettings();
    _authorizeAppManagedPaths();
    _authorizePersistedDetectionSettingsPaths(settings);
    return settings;
  });

  safeHandle("sigma-save-detection-settings", (event, { settings } = {}) => {
    const clean = _assertDetectionSettingsPathsAuthorized(settings || {});
    const saved = detectionSettings.saveDetectionSettings(clean);
    _authorizePersistedDetectionSettingsPaths(saved);
    return saved;
  });

  safeHandle("sigma-list-rule-suppressions", () => {
    const suppressions = ruleSuppression.loadRuleSuppressions();
    const sync = _syncRuleSuppressionsToHayabusa(suppressions);
    return {
      suppressions,
      suppressionFile: ruleSuppression.getSuppressionFile(),
      noisyRulesPath: sync.path,
      sync,
    };
  });

  safeHandle("sigma-save-rule-suppressions", (event, { suppressions } = {}) => {
    const saved = ruleSuppression.saveRuleSuppressions(suppressions || []);
    const sync = _syncRuleSuppressionsToHayabusa(saved);
    return {
      suppressions: saved,
      suppressionFile: ruleSuppression.getSuppressionFile(),
      noisyRulesPath: sync.path,
      sync,
    };
  });

  safeHandle("sigma-update-rules", async (event, { repoIds } = {}) => {
    const result = await downloadFromGitHub(repoIds || undefined, (phase, detail) => {
      safeSend("sigma-progress", { phase, detail });
    });
    return { ruleCount: result.rules.length, meta: result.meta, errors: result.errors };
  });

  safeHandle("sigma-load-local", (event, { dirPath }) => {
    pathAuthorizer.assertAuthorized("compat-rules", dirPath);
    const result = loadLocalRules(dirPath);
    return { ruleCount: result.count };
  });

  safeHandle("sigma-import-custom", async (event, { filePath } = {}) => {
    let targetPath = filePath;
    if (!targetPath) {
      const win = typeof _activeWindow === "function" ? _activeWindow() : null;
      const result = await dialog.showOpenDialog(win, openDialogOptions({
        properties: ["openFile"],
        title: "Import Sigma Rule",
        filters: [{ name: "YAML Files", extensions: ["yml", "yaml"] }],
      }));
      if (result.canceled || !result.filePaths?.length) return { success: false, canceled: true };
      targetPath = result.filePaths[0];
      pathAuthorizer.authorize("custom-rule-file", targetPath, {
        recursive: false,
        label: "Selected custom Sigma rule",
      });
    }
    pathAuthorizer.assertAuthorized(["custom-rule-file", "compat-rules"], targetPath);
    const rule = importCustomRule(targetPath);
    return { success: !!rule, rule: rule ? { title: rule.title, level: rule.level } : null };
  });

  safeHandle("sigma-get-custom-dir", () => {
    _authorizeAppManagedPaths();
    return { path: getCustomDir() };
  });

  safeHandle("sigma-open-custom-dir", () => {
    _authorizeAppManagedPaths();
    const dir = getCustomDir();
    shell.openPath(dir);
    return { opened: true, path: dir };
  });

  safeHandle("sigma-get-rules", () => {
    const { rules, meta, cachedCount, customCount, compatibilityReport, ruleSnapshotHash } = getAllRules();
    const byLevel = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    const byCategory = {};
    const byRepo = {};
    for (const r of rules) {
      byLevel[r.level] = (byLevel[r.level] || 0) + 1;
      const cat = r.logsource.category || r.logsource.service || "other";
      byCategory[cat] = (byCategory[cat] || 0) + 1;
      const repo = r._sourceRepoName || "SigmaHQ";
      byRepo[repo] = (byRepo[repo] || 0) + 1;
    }
    return {
      total: rules.length,
      cachedCount,
      customCount,
      byLevel,
      byCategory,
      byRepo,
      meta: { ...(meta || {}), compatibilityReport, ruleSnapshotHash },
      compatibilityReport,
      ruleSnapshotHash,
    };
  });
};
