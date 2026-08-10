const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const zlib = require("zlib");
const crypto = require("crypto");
const { spawn } = require("child_process");

// Normalize a digest string (e.g. GitHub's release-asset "sha256:<hex>", or a bare
// hex string) to a lowercase 64-char hex SHA-256, or null if it isn't one.
function normalizeSha256(digest) {
  if (!digest) return null;
  const text = String(digest).trim().toLowerCase();
  const hex = text.startsWith("sha256:") ? text.slice(7) : text;
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

// Compute the SHA-256 of a file on disk (streamed — safe for large archives).
function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function ensureSafeTarget(rootDir, entryName) {
  const normalizedName = String(entryName || "").replace(/\\/g, "/");
  if (!normalizedName || normalizedName.includes("\0")) return null;
  if (path.isAbsolute(normalizedName)) throw new Error(`Archive entry uses absolute path: ${entryName}`);
  const target = path.resolve(rootDir, normalizedName);
  const root = path.resolve(rootDir);
  if (target !== root && !target.startsWith(root + path.sep)) {
    throw new Error(`Archive entry escapes destination: ${entryName}`);
  }
  return target;
}

function copyDirectoryContents(srcDir, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const src = path.join(srcDir, entry.name);
    const dest = path.join(destDir, entry.name);
    if (entry.isDirectory()) {
      copyDirectoryContents(src, dest);
    } else if (entry.isFile()) {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(src, dest);
    }
  }
}

function findExecutableOnPath(names = []) {
  const pathValue = process.env.PATH || "";
  const candidates = Array.isArray(names) ? names : [names];
  for (const dir of pathValue.split(path.delimiter).filter(Boolean)) {
    for (const name of candidates) {
      const full = path.join(dir, name);
      try {
        if (!fs.existsSync(full)) continue;
        fs.accessSync(full, process.platform === "win32" ? fs.constants.F_OK : fs.constants.X_OK);
        return full;
      } catch {}
    }
  }
  return null;
}

// Reject requests/redirects to private, loopback, link-local, or internal hosts.
// All entry URLs here are public (GitHub); a redirect Location pointing at an
// internal address is an SSRF signal, so we block it as defense-in-depth.
function isBlockedHost(hostname) {
  if (!hostname) return true;
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1); // strip IPv6 brackets
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 0 || a === 127 || a === 10) return true;        // this-host / loopback / private
    if (a === 169 && b === 254) return true;                  // link-local
    if (a === 172 && b >= 16 && b <= 31) return true;         // private
    if (a === 192 && b === 168) return true;                  // private
    return false;
  }
  if (h === "::" || h === "::1") return true;                 // unspecified / loopback
  if (h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true; // link-local / ULA
  if (h.startsWith("::ffff:")) return isBlockedHost(h.slice(7)); // IPv4-mapped IPv6
  return false;
}

function requestUrl(url, opts = {}, redirectCount = 0) {
  const parsed = new URL(url);
  if (isBlockedHost(parsed.hostname)) {
    return Promise.reject(new Error(`Refusing to request non-public host: ${parsed.hostname}`));
  }
  const transport = parsed.protocol === "http:" ? http : https;
  return new Promise((resolve, reject) => {
    const req = transport.get(parsed, { headers: opts.headers || {} }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirectCount >= 5) {
          reject(new Error(`Too many redirects for ${url}`));
          return;
        }
        const nextUrl = new URL(res.headers.location, parsed).toString();
        requestUrl(nextUrl, opts, redirectCount + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode}: ${url}`));
        return;
      }
      resolve(res);
    });
    req.on("error", reject);
    req.setTimeout(opts.timeoutMs || 30000, () => {
      req.destroy(new Error("Request timeout"));
    });
  });
}

async function fetchJson(url, headers = {}) {
  const res = await requestUrl(url, {
    headers: { "User-Agent": "IRFlow-Timeline/1.0", ...headers },
  });
  const chunks = [];
  for await (const chunk of res) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function downloadFile(url, destPath, opts = {}) {
  const tempPath = `${destPath}.download`;
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  try { if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath); } catch {}

  const res = await requestUrl(url, {
    headers: { "User-Agent": "IRFlow-Timeline/1.0", ...(opts.headers || {}) },
    timeoutMs: opts.timeoutMs || 30000,
  });
  const totalBytes = Number(res.headers["content-length"] || opts.totalBytes || 0) || 0;
  const expectedSha256 = normalizeSha256(opts.expectedSha256);
  const hash = crypto.createHash("sha256");
  let downloadedBytes = 0;
  await new Promise((resolve, reject) => {
    const out = fs.createWriteStream(tempPath);
    res.on("data", (chunk) => {
      downloadedBytes += chunk.length;
      hash.update(chunk);
      opts.onProgress?.({ downloadedBytes, totalBytes });
    });
    res.on("error", reject);
    out.on("error", reject);
    out.on("finish", resolve);
    res.pipe(out);
  });

  const sha256 = hash.digest("hex");
  // Verify integrity BEFORE the temp→dest rename so a corrupt/tampered download
  // never lands at the destination path.
  if (expectedSha256 && sha256 !== expectedSha256) {
    try { fs.unlinkSync(tempPath); } catch {}
    throw new Error(`SHA-256 mismatch: expected ${expectedSha256}, got ${sha256}`);
  }
  fs.renameSync(tempPath, destPath);
  return { bytes: downloadedBytes, sha256 };
}

function readZipEocd(buffer) {
  const minOffset = Math.max(0, buffer.length - 22 - 0xffff);
  for (let offset = buffer.length - 22; offset >= minOffset; offset--) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      return {
        totalEntries: buffer.readUInt16LE(offset + 10),
        centralDirSize: buffer.readUInt32LE(offset + 12),
        centralDirOffset: buffer.readUInt32LE(offset + 16),
      };
    }
  }
  throw new Error("Invalid ZIP archive: end of central directory not found");
}

function extractZip(zipPath, destDir) {
  const buffer = fs.readFileSync(zipPath);
  const eocd = readZipEocd(buffer);
  if (eocd.centralDirOffset === 0xffffffff || eocd.centralDirSize === 0xffffffff) {
    throw new Error("ZIP64 archives are not supported by the built-in extractor");
  }
  fs.mkdirSync(destDir, { recursive: true });

  let offset = eocd.centralDirOffset;
  for (let i = 0; i < eocd.totalEntries; i++) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) throw new Error("Invalid ZIP archive: bad central directory header");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLen = buffer.readUInt16LE(offset + 28);
    const extraLen = buffer.readUInt16LE(offset + 30);
    const commentLen = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLen).toString("utf8");
    offset += 46 + nameLen + extraLen + commentLen;

    if (!name || name.startsWith("__MACOSX/")) continue;
    const target = ensureSafeTarget(destDir, name);
    if (!target) continue;
    if (name.endsWith("/")) {
      fs.mkdirSync(target, { recursive: true });
      continue;
    }

    if (buffer.readUInt32LE(localOffset) !== 0x04034b50) throw new Error("Invalid ZIP archive: bad local file header");
    const localNameLen = buffer.readUInt16LE(localOffset + 26);
    const localExtraLen = buffer.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameLen + localExtraLen;
    const compressed = buffer.subarray(dataOffset, dataOffset + compressedSize);
    let data;
    if (method === 0) data = compressed;
    else if (method === 8) data = zlib.inflateRawSync(compressed);
    else throw new Error(`Unsupported ZIP compression method ${method} for ${name}`);
    if (uncompressedSize !== 0xffffffff && data.length !== uncompressedSize) {
      throw new Error(`ZIP extraction size mismatch for ${name}`);
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data);
  }
}

function parseTarNumber(buffer, start, length) {
  const raw = buffer.subarray(start, start + length);
  if (raw[0] & 0x80) {
    let value = BigInt(raw[0] & 0x7f);
    for (let i = 1; i < raw.length; i++) value = (value << 8n) + BigInt(raw[i]);
    return Number(value);
  }
  const text = raw.toString("utf8").replace(/\0.*$/, "").trim();
  return text ? parseInt(text, 8) || 0 : 0;
}

function readTarString(buffer, start, length) {
  return buffer.subarray(start, start + length).toString("utf8").replace(/\0.*$/, "");
}

function parsePaxHeader(buffer) {
  const out = {};
  const text = buffer.toString("utf8");
  let offset = 0;
  while (offset < text.length) {
    const space = text.indexOf(" ", offset);
    if (space === -1) break;
    const length = Number(text.slice(offset, space));
    if (!Number.isFinite(length) || length <= 0) break;
    const record = text.slice(space + 1, offset + length).replace(/\n$/, "");
    const eq = record.indexOf("=");
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    offset += length;
  }
  return out;
}

function extractTarGzBuffer(tarGzBuffer, destDir) {
  const buffer = zlib.gunzipSync(tarGzBuffer);
  fs.mkdirSync(destDir, { recursive: true });
  let offset = 0;
  let nextPax = null;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;

    const name = readTarString(header, 0, 100);
    const prefix = readTarString(header, 345, 155);
    let fullName = prefix ? `${prefix}/${name}` : name;
    const size = parseTarNumber(header, 124, 12);
    const type = readTarString(header, 156, 1) || "0";
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (type === "x") {
      nextPax = parsePaxHeader(buffer.subarray(dataStart, dataEnd));
      offset = dataStart + Math.ceil(size / 512) * 512;
      continue;
    }
    if (nextPax?.path) fullName = nextPax.path;
    nextPax = null;
    const target = ensureSafeTarget(destDir, fullName);

    if (target) {
      if (type === "5") {
        fs.mkdirSync(target, { recursive: true });
      } else if (type === "0" || type === "") {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, buffer.subarray(dataStart, dataEnd));
      }
    }

    offset = dataStart + Math.ceil(size / 512) * 512;
  }
}

function runProcessCapture(command, args = [], opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: opts.cwd,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });
    let stdout = "";
    let stderr = "";
    const maxOutput = opts.maxOutput || 1024 * 1024;
    const append = (current, chunk) => (current + chunk.toString("utf8")).slice(-maxOutput);
    child.stdout.on("data", (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk) => { stderr = append(stderr, chunk); });
    let timeout = null;
    if (opts.timeoutMs) {
      timeout = setTimeout(() => {
        try { child.kill("SIGKILL"); } catch {}
        reject(new Error(`Process timed out: ${command}`));
      }, opts.timeoutMs);
    }
    child.on("error", (err) => {
      if (timeout) clearTimeout(timeout);
      reject(err);
    });
    child.on("close", (code) => {
      if (timeout) clearTimeout(timeout);
      resolve({ code, stdout, stderr });
    });
  });
}

module.exports = {
  copyDirectoryContents,
  downloadFile,
  extractTarGzBuffer,
  extractZip,
  fetchJson,
  findExecutableOnPath,
  normalizeSha256,
  runProcessCapture,
  sha256File,
};
