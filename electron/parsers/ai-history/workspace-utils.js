/**
 * ai-history/workspace-utils.js — display paths for Workspace column.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

function decodeWorkspaceUri(uri) {
  if (!uri) return "";
  const raw = String(uri).trim();
  if (!raw) return "";
  try {
    if (raw.startsWith("file://")) {
      let p = decodeURIComponent(raw.replace(/^file:\/\//, ""));
      if (process.platform === "win32" && /^\/[A-Za-z]:/.test(p)) p = p.slice(1);
      return p;
    }
    const u = new URL(raw);
    if (u.protocol === "file:") {
      let p = decodeURIComponent(u.pathname);
      if (process.platform === "win32" && /^\/[A-Za-z]:/.test(p)) p = p.slice(1);
      return p;
    }
  } catch { /* ignore */ }
  return raw;
}

/** Human-readable workspace label (basename when path exists). */
function formatWorkspaceDisplay(workspacePath, fallback = "") {
  const p = String(workspacePath || fallback || "").trim();
  if (!p) return "";
  if (p.startsWith("~/.cursor/projects/")) {
    const slug = p.slice("~/.cursor/projects/".length);
    const decoded = decodeCursorProjectSlug(slug);
    if (decoded && decoded !== slug && !decoded.startsWith("~")) return decoded;
  }
  try {
    if (fs.existsSync(p)) return p;
  } catch { /* ignore */ }
  const base = path.basename(p.replace(/[\\/]+$/, ""));
  return base || p;
}

/**
 * Decode Cursor project slug (Users-dfir-Documents-foo) to a filesystem path when possible.
 */
function decodeCursorProjectSlug(slug, cursorHome) {
  if (!slug) return "";
  const home = os.homedir();
  const user = os.userInfo().username;

  if (!slug.includes("-")) {
    const direct = path.join(cursorHome || path.join(home, ".cursor"), "projects", slug);
    try { if (fs.existsSync(direct)) return direct; } catch { /* ignore */ }
    return "";
  }

  if (slug.startsWith("Users-") || slug.startsWith("users-")) {
    const rest = slug.replace(/^users?-/i, "");
    if (rest.toLowerCase().startsWith(`${user.toLowerCase()}-`)) {
      const tail = rest.slice(user.length + 1);
      const tokens = tail.split("-").filter(Boolean);
      let resolved = home;
      let i = 0;
      while (i < tokens.length) {
        let matched = false;
        for (let len = tokens.length - i; len >= 1; len--) {
          const segment = tokens.slice(i, i + len).join("-");
          const candidate = path.join(resolved, segment);
          try {
            if (fs.existsSync(candidate)) {
              resolved = candidate;
              i += len;
              matched = true;
              break;
            }
          } catch { /* ignore */ }
        }
        if (!matched) {
          resolved = path.join(resolved, tokens.slice(i).join("-"));
          break;
        }
      }
      if (resolved !== home) return resolved;
    }
  }

  const projectsDir = path.join(cursorHome || path.join(home, ".cursor"), "projects");
  const joined = path.join(projectsDir, slug.replace(/-/g, path.sep));
  try { if (fs.existsSync(joined)) return joined; } catch { /* ignore */ }
  return "";
}

function workspaceFromCursorTranscriptPath(filePath, cursorHome) {
  const norm = String(filePath || "").replace(/\\/g, "/");
  const m = norm.match(/\/projects\/([^/]+)\/agent-transcripts\//i);
  if (!m) return "";
  const slug = m[1];
  const decoded = decodeCursorProjectSlug(slug, cursorHome);
  return decoded || `~/.cursor/projects/${slug}`;
}

module.exports = {
  decodeWorkspaceUri,
  formatWorkspaceDisplay,
  decodeCursorProjectSlug,
  workspaceFromCursorTranscriptPath,
};
