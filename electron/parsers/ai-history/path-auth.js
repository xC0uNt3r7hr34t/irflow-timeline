/**
 * path-auth.js — PathAuthorizer grants for AI scan / artifact reads (G4).
 */

const { PathAuthorizer } = require("../../utils/path-authorizer");

const SCOPE_SCAN_TARGET = "ai-scan-target";
const SCOPE_ARTIFACT = "ai-artifact";

const _authorizer = new PathAuthorizer();

function authorizeAiScanTarget(targetPath, options = {}) {
  if (!targetPath) return null;
  return _authorizer.authorize(SCOPE_SCAN_TARGET, targetPath, {
    recursive: true,
    label: options.label || "AI collection folder",
    ...options,
  });
}

function authorizeAiArtifactPick(targetPath, options = {}) {
  if (!targetPath) return null;
  return _authorizer.authorize(SCOPE_ARTIFACT, targetPath, {
    recursive: true,
    label: options.label || "AI artifact",
    ...options,
  });
}

/** Grant read access to every root returned by profile discovery. */
function authorizeDiscoveredRoots(roots, collectionRoot) {
  if (collectionRoot) {
    authorizeAiScanTarget(collectionRoot, { label: "AI profile collection" });
  }
  if (!Array.isArray(roots)) return;
  for (const root of roots) {
    if (root?.path) {
      authorizeAiArtifactPick(root.path, { label: root.label || root.tool });
    }
  }
}

function assertAiReadablePath(targetPath, options = {}) {
  return _authorizer.assertAuthorized(
    [SCOPE_ARTIFACT, SCOPE_SCAN_TARGET],
    targetPath,
    { mustExist: options.mustExist !== false },
  );
}

function assertAiScanTarget(targetPath, options = {}) {
  return _authorizer.assertAuthorized(SCOPE_SCAN_TARGET, targetPath, {
    mustExist: options.mustExist !== false,
  });
}

function assertExtractRootsAuthorized(roots, collectionRoot) {
  if (collectionRoot) assertAiScanTarget(collectionRoot);
  if (!Array.isArray(roots)) return;
  for (const root of roots) {
    if (root?.path) assertAiReadablePath(root.path);
  }
}

function getAiPathAuthorizer() {
  return _authorizer;
}

module.exports = {
  SCOPE_SCAN_TARGET,
  SCOPE_ARTIFACT,
  authorizeAiScanTarget,
  authorizeAiArtifactPick,
  authorizeDiscoveredRoots,
  assertAiReadablePath,
  assertAiScanTarget,
  assertExtractRootsAuthorized,
  getAiPathAuthorizer,
};
