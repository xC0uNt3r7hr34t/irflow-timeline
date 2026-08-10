const fsp = require("fs/promises");
const path = require("path");

const BCACHE_RE = /^bcache.*\.bmc$/i;
const CACHE_BIN_RE = /^cache\d{4}\.bin$/i;
const DEFAULT_MAX_DEPTH = 24;
const DEFAULT_MAX_FILES = 50000;

function splitPathParts(filePath) {
  return String(filePath || "")
    .split(/[\\/]+/)
    .filter(Boolean);
}

function basenameAny(filePath) {
  const parts = splitPathParts(filePath);
  return parts.length ? parts[parts.length - 1] : path.basename(String(filePath || ""));
}

function isRdpBitmapCacheFile(filePathOrName) {
  const base = basenameAny(filePathOrName);
  return BCACHE_RE.test(base) || CACHE_BIN_RE.test(base);
}

function getCacheFileKind(filePathOrName) {
  const base = basenameAny(filePathOrName);
  if (BCACHE_RE.test(base)) return "bcache";
  if (CACHE_BIN_RE.test(base)) return "cache-bin";
  return null;
}

function inferProfileFromPath(filePath) {
  const parts = splitPathParts(filePath);
  let userName = null;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const part = parts[i];
    if (/^Users$/i.test(part) || /^Documents and Settings$/i.test(part)) {
      const candidate = parts[i + 1];
      if (candidate && !/^(All Users|Default|Default User|Public)$/i.test(candidate)) {
        userName = candidate;
        break;
      }
    }
  }

  let cachePathHint = null;
  for (let i = 0; i < parts.length - 1; i += 1) {
    if (/^Terminal Server Client$/i.test(parts[i]) && /^Cache$/i.test(parts[i + 1])) {
      cachePathHint = parts.slice(0, i + 2).join(path.sep);
      break;
    }
  }

  return {
    userName,
    cachePathHint,
    isExpectedCachePath: !!cachePathHint,
  };
}

async function statSafe(filePath) {
  try {
    return await fsp.stat(filePath);
  } catch {
    return null;
  }
}

async function walkDirectory(dirPath, options, state, depth = 0) {
  if (depth > options.maxDepth) {
    state.warnings.push(`Maximum recursion depth reached at ${dirPath}`);
    return;
  }
  if (state.scannedFileCount >= options.maxFiles) {
    state.warnings.push(`Maximum scan file count reached (${options.maxFiles})`);
    return;
  }

  let entries;
  try {
    entries = await fsp.readdir(dirPath, { withFileTypes: true });
  } catch (err) {
    state.warnings.push(`Could not read directory ${dirPath}: ${err.message}`);
    return;
  }

  for (const entry of entries) {
    const childPath = path.join(dirPath, entry.name);
    if (entry.isSymbolicLink()) {
      if (options.followSymlinks) {
        const st = await statSafe(childPath);
        if (st?.isDirectory()) await walkDirectory(childPath, options, state, depth + 1);
        else if (st?.isFile()) await addCandidateFile(childPath, st, state);
      } else {
        state.skippedSymlinks += 1;
      }
      continue;
    }
    if (entry.isDirectory()) {
      if (options.recursive) await walkDirectory(childPath, options, state, depth + 1);
      continue;
    }
    if (entry.isFile()) {
      state.scannedFileCount += 1;
      await addCandidateFile(childPath, null, state);
    }
  }
}

async function addCandidateFile(filePath, knownStat, state) {
  if (!isRdpBitmapCacheFile(filePath)) return;
  const st = knownStat || await statSafe(filePath);
  if (!st?.isFile()) return;
  const profile = inferProfileFromPath(filePath);
  state.files.push({
    path: filePath,
    name: basenameAny(filePath),
    kind: getCacheFileKind(filePath),
    size: st.size,
    mtimeMs: st.mtimeMs,
    ctimeMs: st.ctimeMs,
    modifiedAt: st.mtime.toISOString(),
    createdAt: st.ctime.toISOString(),
    userName: profile.userName,
    cachePathHint: profile.cachePathHint,
    isExpectedCachePath: profile.isExpectedCachePath,
  });
}

function summarizeCacheFiles(files) {
  const summary = {
    fileCount: files.length,
    bcacheCount: 0,
    cacheBinCount: 0,
    totalBytes: 0,
    users: [],
    cacheDirectories: [],
  };
  const users = new Set();
  const dirs = new Set();
  for (const file of files) {
    if (file.kind === "bcache") summary.bcacheCount += 1;
    if (file.kind === "cache-bin") summary.cacheBinCount += 1;
    summary.totalBytes += Number(file.size) || 0;
    if (file.userName) users.add(file.userName);
    dirs.add(file.cachePathHint || path.dirname(file.path));
  }
  summary.users = [...users].sort((a, b) => a.localeCompare(b));
  summary.cacheDirectories = [...dirs].sort((a, b) => a.localeCompare(b));
  return summary;
}

async function collectRdpBitmapCacheFiles(sources, options = {}) {
  const sourceList = Array.isArray(sources) ? sources : [sources].filter(Boolean);
  const scanOptions = {
    recursive: options.recursive !== false,
    followSymlinks: !!options.followSymlinks,
    maxDepth: Number.isFinite(options.maxDepth) ? options.maxDepth : DEFAULT_MAX_DEPTH,
    maxFiles: Number.isFinite(options.maxFiles) ? options.maxFiles : DEFAULT_MAX_FILES,
  };
  const state = {
    files: [],
    warnings: [],
    scannedFileCount: 0,
    skippedSymlinks: 0,
  };

  for (const source of sourceList) {
    const st = await statSafe(source);
    if (!st) {
      state.warnings.push(`Source path does not exist: ${source}`);
      continue;
    }
    if (st.isFile()) {
      state.scannedFileCount += 1;
      await addCandidateFile(source, st, state);
    } else if (st.isDirectory()) {
      await walkDirectory(source, scanOptions, state);
    } else {
      state.warnings.push(`Unsupported source path type: ${source}`);
    }
  }

  state.files.sort((a, b) => a.path.localeCompare(b.path));
  return {
    sourcePaths: sourceList,
    files: state.files,
    summary: summarizeCacheFiles(state.files),
    warnings: state.warnings,
    scannedFileCount: state.scannedFileCount,
    skippedSymlinks: state.skippedSymlinks,
  };
}

module.exports = {
  BCACHE_RE,
  CACHE_BIN_RE,
  isRdpBitmapCacheFile,
  getCacheFileKind,
  inferProfileFromPath,
  summarizeCacheFiles,
  collectRdpBitmapCacheFiles,
};
