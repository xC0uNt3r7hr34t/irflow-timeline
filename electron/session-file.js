const path = require("path");
const fs = require("fs");

function isTleSessionPath(filePath) {
  if (!filePath || typeof filePath !== "string") return false;
  return path.extname(filePath).toLowerCase() === ".tle";
}

function resolveSessionPath(filePath) {
  try {
    return path.resolve(filePath);
  } catch {
    return filePath;
  }
}

function sessionPathExists(filePath) {
  if (!filePath) return false;
  try {
    return fs.existsSync(resolveSessionPath(filePath));
  } catch {
    return false;
  }
}

function isValidSessionPayload(session) {
  if (!session || typeof session !== "object" || Array.isArray(session)) return false;
  if (session.version !== 1) return false;
  if (!Array.isArray(session.tabs)) return false;
  return true;
}

function loadSessionFromPath(filePath) {
  const resolved = resolveSessionPath(filePath);
  if (!sessionPathExists(resolved)) {
    return { error: `Session file not found: ${filePath}` };
  }
  try {
    const raw = fs.readFileSync(resolved, "utf-8");
    const session = JSON.parse(raw);
    if (!isValidSessionPayload(session)) {
      return { error: "Invalid or unsupported session file" };
    }
    return session;
  } catch (e) {
    return { error: e.message || "Failed to read session file" };
  }
}

module.exports = {
  isTleSessionPath,
  resolveSessionPath,
  sessionPathExists,
  isValidSessionPayload,
  loadSessionFromPath,
};
