const fs = require("fs");
const path = require("path");

function canonicalizePath(targetPath, options = {}) {
  const mustExist = options.mustExist !== false;
  if (typeof targetPath !== "string" || targetPath.trim() === "") {
    throw Object.assign(new Error("Path is required."), { code: "PATH_REQUIRED" });
  }

  const resolved = path.resolve(targetPath);
  if (mustExist) {
    try {
      return fs.realpathSync.native(resolved);
    } catch {
      throw Object.assign(new Error(`Path does not exist: ${targetPath}`), { code: "PATH_NOT_FOUND" });
    }
  }

  let current = resolved;
  const missing = [];
  while (!fs.existsSync(current)) {
    missing.unshift(path.basename(current));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  const realParent = fs.existsSync(current) ? fs.realpathSync.native(current) : path.parse(resolved).root;
  return path.join(realParent, ...missing);
}

function isPathInside(candidatePath, rootPath) {
  const candidate = path.resolve(candidatePath);
  const root = path.resolve(rootPath);
  if (candidate === root) return true;
  const relative = path.relative(root, candidate);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function normalizeScopes(scopes) {
  return Array.isArray(scopes) ? scopes.filter(Boolean) : [scopes].filter(Boolean);
}

class PathAuthorizer {
  constructor() {
    this._entries = new Map();
  }

  authorize(scope, targetPath, options = {}) {
    const canonical = canonicalizePath(targetPath, { mustExist: options.mustExist });
    const entry = {
      path: canonical,
      recursive: options.recursive !== false,
      label: options.label || null,
      appManaged: !!options.appManaged,
    };
    const entries = this._entries.get(scope) || [];
    if (!entries.some((existing) => existing.path === entry.path && existing.recursive === entry.recursive)) {
      entries.push(entry);
      this._entries.set(scope, entries);
    }
    return entry;
  }

  authorizeIfExists(scope, targetPath, options = {}) {
    if (!targetPath || !fs.existsSync(path.resolve(targetPath))) return null;
    return this.authorize(scope, targetPath, options);
  }

  isAuthorized(scopes, targetPath, options = {}) {
    let canonical;
    try {
      canonical = canonicalizePath(targetPath, { mustExist: options.mustExist });
    } catch {
      return false;
    }

    for (const scope of normalizeScopes(scopes)) {
      for (const entry of this._entries.get(scope) || []) {
        if (entry.path === canonical) return true;
        if (entry.recursive && isPathInside(canonical, entry.path)) return true;
      }
    }
    return false;
  }

  assertAuthorized(scopes, targetPath, options = {}) {
    if (this.isAuthorized(scopes, targetPath, options)) return canonicalizePath(targetPath, { mustExist: options.mustExist });
    const scopeText = normalizeScopes(scopes).join(", ") || "unknown";
    throw Object.assign(
      new Error(`Path is not authorized for ${scopeText}. Select it in the app before using it.`),
      { code: "PATH_NOT_AUTHORIZED", scopes: normalizeScopes(scopes), path: targetPath },
    );
  }

  snapshot() {
    const result = {};
    for (const [scope, entries] of this._entries.entries()) {
      result[scope] = entries.map((entry) => ({ ...entry }));
    }
    return result;
  }
}

module.exports = {
  PathAuthorizer,
  canonicalizePath,
  isPathInside,
};
