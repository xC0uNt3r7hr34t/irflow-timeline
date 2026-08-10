const fs = require("fs");
const path = require("path");
const https = require("https");
const { app } = require("electron");
const { dbg } = require("../logger");

// ── VT State ────────────────────────────────────────────────────────
const _vtSettingsPath = path.join(app.getPath("userData"), "vt-settings.json");
let _vtCacheDb = null;
const _vtRequestTimes = [];
const _vtBulkJobs = new Map();
let _vtBulkIdCounter = 0;

// ── VT Helper Functions ─────────────────────────────────────────────

function _getVtSafeStorage() {
  try {
    const { safeStorage } = require("electron");
    if (safeStorage?.isEncryptionAvailable?.()) return safeStorage;
  } catch {}
  return null;
}

function _encryptVtKey(text) {
  const s = String(text || "");
  if (!s) return null;
  const ss = _getVtSafeStorage();
  if (ss) {
    try { return { storage: "safeStorage", value: ss.encryptString(s).toString("base64") }; } catch {}
  }
  return { storage: "plain", value: Buffer.from(s, "utf8").toString("base64") };
}

function _decryptVtKey(secret) {
  if (!secret) return "";
  if (typeof secret === "string") return secret; // legacy plaintext key — migrated on next save
  const ss = _getVtSafeStorage();
  if (secret.storage === "safeStorage") {
    if (!ss) return "";
    try { return ss.decryptString(Buffer.from(secret.value, "base64")); } catch { return ""; }
  }
  if (secret.storage === "plain") {
    try { return Buffer.from(secret.value, "base64").toString("utf8"); } catch { return ""; }
  }
  return "";
}

function _loadVtSettings() {
  try {
    if (fs.existsSync(_vtSettingsPath)) {
      const raw = JSON.parse(fs.readFileSync(_vtSettingsPath, "utf8"));
      return {
        apiKey: _decryptVtKey(raw.apiKeySecret || raw.apiKey || ""),
        rateLimit: raw.rateLimit ?? 4,
        cacheTtlHours: raw.cacheTtlHours ?? 24,
      };
    }
  } catch {}
  return { apiKey: "", rateLimit: 4, cacheTtlHours: 24 };
}

function _saveVtSettings(settings) {
  try {
    // Persist the API key encrypted via safeStorage — never plaintext. 0o600 limits read
    // access on shared analyst machines. Migrates any legacy plaintext apiKey on save.
    const out = {
      apiKeySecret: _encryptVtKey(settings.apiKey || ""),
      rateLimit: settings.rateLimit ?? 4,
      cacheTtlHours: settings.cacheTtlHours ?? 24,
    };
    fs.writeFileSync(_vtSettingsPath, JSON.stringify(out), { encoding: "utf8", mode: 0o600 });
  } catch {}
}

function _openVtCache() {
  if (_vtCacheDb) return _vtCacheDb;
  const Database = require("better-sqlite3");
  const cachePath = path.join(app.getPath("userData"), "vt-cache.db");
  _vtCacheDb = new Database(cachePath);
  _vtCacheDb.pragma("journal_mode = WAL");
  _vtCacheDb.exec(`CREATE TABLE IF NOT EXISTS vt_cache (
    ioc TEXT PRIMARY KEY,
    category TEXT,
    vt_response TEXT,
    fetched_at INTEGER,
    score TEXT
  )`);
  return _vtCacheDb;
}

// Normalize IOC for cache key — avoid duplicate entries for equivalent IOCs
function _vtCacheKey(ioc, category) {
  if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) return ioc.toLowerCase();
  if (category === "Domain_Name") return ioc.toLowerCase();
  if (/^IPv[46]_Address(:Port)?$/.test(category)) return ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
  if (category === "URL") return ioc.toLowerCase();
  return ioc;
}

function _vtCacheLookup(ioc, category, ttlHours) {
  const cache = _openVtCache();
  const key = _vtCacheKey(ioc, category);
  const row = cache.prepare("SELECT * FROM vt_cache WHERE ioc = ?").get(key);
  if (!row) return null;
  const ageMs = Date.now() - row.fetched_at;
  if (ageMs > ttlHours * 3600 * 1000) return null;
  try { return JSON.parse(row.vt_response); } catch { return null; }
}

function _vtCacheStore(ioc, category, result) {
  const cache = _openVtCache();
  const key = _vtCacheKey(ioc, category);
  cache.prepare("INSERT OR REPLACE INTO vt_cache (ioc, category, vt_response, fetched_at, score) VALUES (?, ?, ?, ?, ?)")
    .run(key, category, JSON.stringify(result), Date.now(), result.score || "");
}

// Private IP detection
function _isPrivateIp(ip) {
  const clean = ip.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
  if (/^10\./.test(clean)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(clean)) return true;
  if (/^192\.168\./.test(clean)) return true;
  if (/^127\./.test(clean)) return true;
  if (clean === "::1" || clean === "0:0:0:0:0:0:0:1") return true;
  return false;
}

// VT API request
function _vtApiRequest(endpoint, apiKey) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "www.virustotal.com",
      path: `/api/v3/${endpoint}`,
      method: "GET",
      headers: { "x-apikey": apiKey, "Accept": "application/json" },
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, headers: res.headers, body: data });
      });
    });
    req.on("error", (err) => reject(err));
    req.setTimeout(30000, () => { req.destroy(); reject(new Error("Request timeout")); });
    req.end();
  });
}

// Map IOC category to VT endpoint
function _vtEndpoint(ioc, category) {
  // URL-encode the IOC segment — it originates from loaded forensic data, so a value
  // containing CR/LF or path characters must not be able to manipulate the request path.
  if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) return `files/${encodeURIComponent(ioc)}`;
  if (category === "Domain_Name") return `domains/${encodeURIComponent(ioc)}`;
  if (/^IPv[46]_Address(:Port)?$/.test(category)) {
    const clean = ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    return `ip_addresses/${encodeURIComponent(clean)}`;
  }
  if (category === "URL") {
    const id = Buffer.from(ioc).toString("base64url");
    return `urls/${encodeURIComponent(id)}`;
  }
  return null;
}

// VT URL for browser
function _vtUrl(ioc, category) {
  if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) return `https://www.virustotal.com/gui/file/${ioc}`;
  if (category === "Domain_Name") return `https://www.virustotal.com/gui/domain/${ioc}`;
  if (/^IPv[46]_Address(:Port)?$/.test(category)) {
    const clean = ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
    return `https://www.virustotal.com/gui/ip-address/${clean}`;
  }
  if (category === "URL") {
    const crypto = require("crypto");
    const sha256 = crypto.createHash("sha256").update(ioc).digest("hex");
    return `https://www.virustotal.com/gui/url/${sha256}`;
  }
  return null;
}

function _parseVtResponse(ioc, category, statusCode, body) {
  const vtUrl = _vtUrl(ioc, category);
  const queriedAt = Date.now();
  if (statusCode === 404) {
    return { ioc, found: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0, score: "Not Found", verdict: "not_found", vtUrl, error: null, queriedAt };
  }
  if (statusCode === 401) {
    return { ioc, found: false, score: "", verdict: "error", vtUrl, error: "Invalid API key", queriedAt };
  }
  if (statusCode === 429) {
    return { ioc, found: false, score: "", verdict: "error", vtUrl, error: "Rate limited (429)", queriedAt };
  }
  if (statusCode < 200 || statusCode >= 300) {
    return { ioc, found: false, score: "", verdict: "error", vtUrl, error: `HTTP ${statusCode}`, queriedAt };
  }
  try {
    const json = JSON.parse(body);
    const attrs = json?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected + (stats.timeout || 0);
    const detected = malicious + suspicious;
    const score = `${detected}/${total}`;
    const verdict = total === 0 ? "not_found" : malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean";
    const threatLabel = attrs.popular_threat_classification?.suggested_threat_label || null;
    return { ioc, found: total > 0, malicious, suspicious, harmless, undetected, total, score, verdict, vtUrl, error: null, threatLabel, queriedAt };
  } catch {
    return { ioc, found: false, score: "", verdict: "error", vtUrl, error: "Failed to parse response", queriedAt };
  }
}

// Rate limiter — token bucket
async function _vtRateLimitWait(rateLimit) {
  const windowMs = 60000;
  while (true) {
    const now = Date.now();
    // Remove timestamps older than window
    while (_vtRequestTimes.length > 0 && now - _vtRequestTimes[0] > windowMs) _vtRequestTimes.shift();
    if (_vtRequestTimes.length < rateLimit) {
      _vtRequestTimes.push(now);
      return;
    }
    const waitUntil = _vtRequestTimes[0] + windowMs;
    const waitMs = waitUntil - now + 50;
    await new Promise((r) => setTimeout(r, waitMs));
  }
}

// ── VT IPC Handlers ─────────────────────────────────────────────────

module.exports = function registerVtHandlers(safeHandle, safeSend, { db, mainWindow }) {

  safeHandle("vt-set-api-key", async (event, { apiKey, rateLimit, cacheTtlHours }) => {
    const settings = _loadVtSettings();
    if (typeof apiKey === "string") settings.apiKey = apiKey.trim();
    if (rateLimit !== undefined) settings.rateLimit = rateLimit;
    if (cacheTtlHours !== undefined) settings.cacheTtlHours = cacheTtlHours;
    _saveVtSettings(settings);
    return true;
  });

  safeHandle("vt-get-api-key", async () => {
    const s = _loadVtSettings();
    const hasKey = !!(s.apiKey && s.apiKey.length > 0);
    const maskedKey = hasKey ? s.apiKey.slice(0, 4) + "..." + s.apiKey.slice(-4) : "";
    return { hasKey, maskedKey, rateLimit: s.rateLimit || 4, cacheTtlHours: s.cacheTtlHours || 24 };
  });

  safeHandle("vt-clear-api-key", async () => {
    const settings = _loadVtSettings();
    settings.apiKey = "";
    _saveVtSettings(settings);
    return true;
  });

  // Single IOC lookup
  safeHandle("vt-lookup-single", async (event, { ioc, category }) => {
    const settings = _loadVtSettings();
    if (!settings.apiKey) return { ioc, error: "No API key configured" };

    const endpoint = _vtEndpoint(ioc, category);
    if (!endpoint) return { ioc, score: "N/A", verdict: "unsupported", error: null };

    if (/^IPv[46]_Address(:Port)?$/.test(category) && _isPrivateIp(ioc)) {
      return { ioc, found: false, score: "Private IP", verdict: "private", vtUrl: null, error: null };
    }

    // Check cache
    const cached = _vtCacheLookup(ioc, category, settings.cacheTtlHours || 24);
    if (cached) return cached;

    // API call
    await _vtRateLimitWait(settings.rateLimit || 4);
    try {
      const res = await _vtApiRequest(endpoint, settings.apiKey);
      if (res.statusCode === 429) {
        const retryAfter = parseInt(res.headers["retry-after"] || "60", 10);
        await new Promise((r) => setTimeout(r, retryAfter * 1000));
        const res2 = await _vtApiRequest(endpoint, settings.apiKey);
        const result = _parseVtResponse(ioc, category, res2.statusCode, res2.body);
        if (!result.error || res2.statusCode === 404) _vtCacheStore(ioc, category, result);
        return result;
      }
      const result = _parseVtResponse(ioc, category, res.statusCode, res.body);
      if (!result.error || res.statusCode === 404) _vtCacheStore(ioc, category, result);
      return result;
    } catch (err) {
      return { ioc, error: err.message, score: "", verdict: "error" };
    }
  });

  // Bulk lookup — runs in background with progress events
  safeHandle("vt-bulk-lookup", async (event, { iocs, requestId: clientId }) => {
    const settings = _loadVtSettings();
    if (!settings.apiKey) return { error: "No API key configured" };

    const requestId = clientId || `vt-bulk-${++_vtBulkIdCounter}`;
    const job = { cancelled: false };
    _vtBulkJobs.set(requestId, job);

    // Run in background
    (async () => {
      const total = iocs.length;
      let completed = 0;
      // Track normalized keys already looked up in this batch to avoid duplicate API calls
      // (e.g., 1.2.3.4:80 and 1.2.3.4:443 resolve to the same VT object)
      const seenKeys = new Map(); // normalized key → result

      for (const { raw, category } of iocs) {
        if (job.cancelled || (mainWindow && mainWindow.isDestroyed())) break;

        const endpoint = _vtEndpoint(raw, category);
        let result;

        // Deduplicate: if a normalized-equivalent IOC was already looked up in this batch, reuse its result
        const normKey = _vtCacheKey(raw, category);
        if (seenKeys.has(normKey)) {
          result = { ...seenKeys.get(normKey), ioc: raw };
          completed++;
          safeSend("vt-progress", { requestId, completed, total, result });
          continue;
        }

        if (!endpoint) {
          result = { ioc: raw, score: "N/A", verdict: "unsupported", error: null };
        } else if (/^IPv[46]_Address(:Port)?$/.test(category) && _isPrivateIp(raw)) {
          result = { ioc: raw, found: false, score: "Private IP", verdict: "private", vtUrl: null, error: null };
        } else {
          // Check cache
          const cached = _vtCacheLookup(raw, category, settings.cacheTtlHours || 24);
          if (cached) {
            result = cached;
          } else {
            // API call
            try {
              await _vtRateLimitWait(settings.rateLimit || 4);
              if (job.cancelled) break;
              const res = await _vtApiRequest(endpoint, settings.apiKey);
              if (res.statusCode === 401) {
                safeSend("vt-progress", { requestId, completed, total, result: { ioc: raw, error: "Invalid API key", verdict: "error" } });
                safeSend("vt-complete", { requestId, completed, total, error: "Invalid API key" });
                _vtBulkJobs.delete(requestId);
                return;
              }
              if (res.statusCode === 429) {
                const retryAfter = parseInt(res.headers["retry-after"] || "60", 10);
                // Cancellable sleep — check every 2s instead of blocking for full duration
                const sleepEnd = Date.now() + retryAfter * 1000;
                while (Date.now() < sleepEnd && !job.cancelled) {
                  await new Promise((r) => setTimeout(r, Math.min(2000, sleepEnd - Date.now())));
                }
                if (job.cancelled) break;
                const res2 = await _vtApiRequest(endpoint, settings.apiKey);
                result = _parseVtResponse(raw, category, res2.statusCode, res2.body);
                if (!result.error || res2.statusCode === 404) _vtCacheStore(raw, category, result);
              } else {
                result = _parseVtResponse(raw, category, res.statusCode, res.body);
                if (!result.error || res.statusCode === 404) _vtCacheStore(raw, category, result);
              }
            } catch (err) {
              result = { ioc: raw, error: err.message, score: "", verdict: "error" };
            }
          }
        }

        if (!result.error) seenKeys.set(normKey, result);
        completed++;
        safeSend("vt-progress", { requestId, completed, total, result });
      }

      safeSend("vt-complete", { requestId, completed, total, cancelled: job.cancelled });
      _vtBulkJobs.delete(requestId);
    })().catch((err) => {
      console.error(`VT bulk lookup failed for ${requestId}:`, err?.message || err);
      safeSend("vt-complete", { requestId, completed: 0, total: iocs.length, error: err?.message || "Unknown error" });
      _vtBulkJobs.delete(requestId);
    });

    return { requestId };
  });

  safeHandle("vt-cancel", async (event, { requestId }) => {
    const job = _vtBulkJobs.get(requestId);
    if (job) job.cancelled = true;
    return true;
  });

  safeHandle("vt-clear-cache", async () => {
    const cache = _openVtCache();
    const info = cache.prepare("DELETE FROM vt_cache").run();
    return { cleared: info.changes };
  });

  // VT relationships — pivot from one IOC to related artifacts
  safeHandle("vt-get-related", async (event, { ioc, category }) => {
    const settings = _loadVtSettings();
    if (!settings.apiKey) return { error: "No API key configured" };

    // Build relationship endpoints per IOC type
    const rels = [];
    if (/^(SHA256|SHA1|MD5)_Hash$/.test(category)) {
      const enc = encodeURIComponent(ioc);
      rels.push({ type: "Contacted Domains", endpoint: `files/${enc}/contacted_domains` });
      rels.push({ type: "Contacted IPs", endpoint: `files/${enc}/contacted_ips` });
      rels.push({ type: "Contacted URLs", endpoint: `files/${enc}/contacted_urls` });
    } else if (category === "Domain_Name") {
      const enc = encodeURIComponent(ioc);
      rels.push({ type: "Communicating Files", endpoint: `domains/${enc}/communicating_files` });
      rels.push({ type: "DNS Resolutions", endpoint: `domains/${enc}/resolutions` });
    } else if (/^IPv[46]_Address(:Port)?$/.test(category)) {
      const clean = encodeURIComponent(ioc.replace(/:\d+$/, "").replace(/^\[|\]$/g, ""));
      rels.push({ type: "Communicating Files", endpoint: `ip_addresses/${clean}/communicating_files` });
      rels.push({ type: "DNS Resolutions", endpoint: `ip_addresses/${clean}/resolutions` });
    } else if (category === "URL") {
      const id = encodeURIComponent(Buffer.from(ioc).toString("base64url"));
      rels.push({ type: "Contacted Domains", endpoint: `urls/${id}/contacted_domains` });
      rels.push({ type: "Contacted IPs", endpoint: `urls/${id}/contacted_ips` });
    } else {
      return { error: "Unsupported IOC type for relationships" };
    }

    const results = [];
    const errors = [];
    for (const rel of rels) {
      try {
        await _vtRateLimitWait(settings.rateLimit || 4);
        let res = await _vtApiRequest(`${rel.endpoint}?limit=10`, settings.apiKey);
        // Retry once on 429
        if (res.statusCode === 429) {
          const retryAfter = parseInt(res.headers["retry-after"] || "60", 10);
          await new Promise((r) => setTimeout(r, retryAfter * 1000));
          res = await _vtApiRequest(`${rel.endpoint}?limit=10`, settings.apiKey);
        }
        if (res.statusCode === 401) {
          return { ioc, relationships: [], error: "Invalid API key" };
        }
        if (res.statusCode === 200) {
          const json = JSON.parse(res.body);
          const items = (json.data || []).map((item) => {
            const attrs = item.attributes || {};
            if (item.type === "file") {
              const stats = attrs.last_analysis_stats || {};
              return { id: item.id, type: "file", name: attrs.meaningful_name || attrs.name || item.id, score: `${(stats.malicious || 0) + (stats.suspicious || 0)}/${(stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)}`, malicious: stats.malicious || 0, threatLabel: attrs.popular_threat_classification?.suggested_threat_label || null };
            } else if (item.type === "domain") {
              return { id: item.id, type: "domain", name: item.id };
            } else if (item.type === "ip_address") {
              return { id: item.id, type: "ip", name: item.id };
            } else if (item.type === "url") {
              return { id: item.id, type: "url", name: attrs.url || item.id };
            } else if (item.type === "resolution") {
              return { id: attrs.ip_address || attrs.host_name || item.id, type: "resolution", name: attrs.ip_address || attrs.host_name || item.id, date: attrs.date };
            }
            return { id: item.id, type: item.type, name: item.id };
          });
          if (items.length > 0) results.push({ type: rel.type, items });
        } else if (res.statusCode !== 404) {
          errors.push(`${rel.type}: HTTP ${res.statusCode}`);
        }
      } catch (err) {
        errors.push(`${rel.type}: ${err.message || "Network error"}`);
      }
    }
    return { ioc, relationships: results, error: errors.length > 0 ? errors.join("; ") : undefined };
  });

};
