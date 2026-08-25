/**
 * resolve-root.js — canonical AI artifact roots (shared by profile scan and triage).
 */

const fs = require("fs");
const path = require("path");

const { canonicalizePath, isPathInside } = require("../../utils/path-authorizer");
const { isClaudeCodeArtifactRoot } = require("./artifact-paths");
const { resolveClaudeDir } = require("./claude-code");
const { resolveCodexHome } = require("./codex");
const { resolveChatgptDir } = require("./chatgpt");
const { resolveGeminiCliRoot } = require("./gemini-cli");
const { resolveCursorRoot } = require("./cursor");
const { resolveCopilotRoot } = require("./copilot");
const { resolveWindsurfUserDir } = require("./windsurf");
const { continueHome } = require("./continue");

function realPathKey(p) {
  try {
    return fs.realpathSync.native ? fs.realpathSync.native(p) : fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/**
 * Walk a triage hit path up to the tool's canonical extract root (same rules as profile scan).
 * @returns {string|null}
 */
function resolveCanonicalAiRoot(tool, hitPath) {
  if (!hitPath) return null;
  let resolved = hitPath;
  switch (tool) {
    case "claude-code":
      resolved = resolveClaudeDir(hitPath) || (isClaudeCodeArtifactRoot(hitPath) ? hitPath : null);
      break;
    case "codex":
      resolved = resolveCodexHome(hitPath);
      break;
    case "chatgpt":
      resolved = resolveChatgptDir(hitPath);
      break;
    case "gemini-cli":
      resolved = resolveGeminiCliRoot(hitPath);
      break;
    case "cursor":
      resolved = resolveCursorRoot(hitPath);
      break;
    case "copilot":
      resolved = resolveCopilotRoot(hitPath);
      break;
    case "windsurf":
      resolved = resolveWindsurfUserDir(hitPath);
      break;
    case "continue":
      resolved = continueHome(hitPath);
      break;
    default:
      resolved = hitPath;
  }
  if (!resolved || !fs.existsSync(resolved)) return null;
  return path.resolve(resolved);
}

/**
 * G4: confine extraction roots to the scan scope the user actually selected (a triage/KAPE
 * folder, or a collection root). Rejects forged/replayed roots that resolve outside the scope
 * or use `..` traversal — the canonicalize step follows symlinks and normalizes the path.
 * @param {{ path: string }[]} roots
 * @param {string} scopeDir
 * @returns {{ allowed: object[], rejected: { root: object, reason: string }[] }}
 */
function confineRootsToScope(roots, scopeDir) {
  if (!scopeDir || !Array.isArray(roots)) return { allowed: roots || [], rejected: [] };
  let scopeReal;
  try {
    scopeReal = canonicalizePath(scopeDir, { mustExist: true });
  } catch {
    return { allowed: [], rejected: roots.map((root) => ({ root, reason: "scan scope not found" })) };
  }
  const allowed = [];
  const rejected = [];
  for (const root of roots) {
    let real;
    try {
      real = canonicalizePath(root.path, { mustExist: true });
    } catch {
      rejected.push({ root, reason: "path not found" });
      continue;
    }
    if (isPathInside(real, scopeReal)) allowed.push(root);
    else rejected.push({ root, reason: "outside scan scope" });
  }
  return { allowed, rejected };
}

module.exports = {
  realPathKey,
  resolveCanonicalAiRoot,
  confineRootsToScope,
};
