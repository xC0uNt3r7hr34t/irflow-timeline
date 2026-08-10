/**
 * analyzers/ai-history/validators — the false-positive killers + redaction helpers.
 *
 * The regex catalog (detection-rules.js) is high-recall by design; these pure functions are the
 * precision layer the harness applies after a pattern matches:
 *   - structural validators (Luhn for cards, mod-97 for IBAN) drop format-only false matches;
 *   - Shannon entropy gates ambiguous/keyword-anchored secrets (and powers the "unknown secret" net);
 *   - a placeholder/example allow-list drops `your_api_key`, `<token>`, `xxxx`, `${VAR}`, etc.;
 *   - redactValue + fingerprint keep cleartext off disk while still allowing cross-row correlation.
 *
 * Everything here is a pure function of the matched substring — unit-testable without a SQLite
 * binding, matching the repo's test posture.
 */

const crypto = require("crypto");

/** Shannon entropy in bits/char. Higher = more random (real secrets ~>4.5 for base64, >3 for hex). */
function shannonEntropy(str) {
  const s = String(str || "");
  if (!s) return 0;
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Luhn checksum — validates credit-card-shaped digit runs (13–19 digits, separators stripped). */
function luhnValid(input) {
  const digits = String(input || "").replace(/[^\d]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function cardFormatLikely(input) {
  const raw = String(input || "").trim();
  if (!raw || !/^\d[\d -]*\d$/.test(raw) || /[ -]{2,}/.test(raw)) return false;
  if (!/[ -]/.test(raw)) return true;
  const groups = raw.split(/[ -]/).filter(Boolean);
  if (groups.length === 4) {
    return groups[0].length === 4
      && groups[1].length === 4
      && groups[2].length === 4
      && groups[3].length >= 1
      && groups[3].length <= 7;
  }
  if (groups.length === 3) {
    return groups[0].length === 4
      && groups[1].length === 6
      && (groups[2].length === 4 || groups[2].length === 5);
  }
  return false;
}

function cardIssuerLikely(digits) {
  const len = digits.length;
  const n2 = Number(digits.slice(0, 2));
  const n3 = Number(digits.slice(0, 3));
  const n4 = Number(digits.slice(0, 4));
  const n6 = Number(digits.slice(0, 6));
  if (digits.startsWith("4") && (len === 13 || len === 16 || len === 19)) return true; // Visa
  if (len === 16 && ((n2 >= 51 && n2 <= 55) || (n4 >= 2221 && n4 <= 2720))) return true; // Mastercard
  if (len === 15 && (n2 === 34 || n2 === 37)) return true; // AmEx
  if ((len === 16 || len === 19) && (digits.startsWith("6011") || digits.startsWith("65") || (n3 >= 644 && n3 <= 649) || (n6 >= 622126 && n6 <= 622925))) return true; // Discover
  if (len >= 16 && len <= 19 && n4 >= 3528 && n4 <= 3589) return true; // JCB
  if (len === 14 && ((n3 >= 300 && n3 <= 305) || n2 === 36 || n2 === 38 || n2 === 39)) return true; // Diners
  if (len >= 16 && len <= 19 && digits.startsWith("62")) return true; // UnionPay
  return false;
}

function creditCardLikely(input) {
  const digits = String(input || "").replace(/[^\d]/g, "");
  if (!luhnValid(input)) return false;
  if (/^(.)\1+$/.test(digits)) return false;
  if (!cardFormatLikely(input)) return false;
  return cardIssuerLikely(digits);
}

/** ISO 13616 IBAN mod-97 check. */
function ibanValid(input) {
  const iban = String(input || "").replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const val = code >= 65 && code <= 90 ? code - 55 : code - 48; // A→10 … Z→35, else digit
    remainder = (remainder * (val > 9 ? 100 : 10) + val) % 97;
  }
  return remainder === 1;
}

// Tokens that are obviously documentation placeholders, not real secrets. Matched against the
// captured value only. Targeted on purpose — a real high-entropy secret won't contain these words.
const PLACEHOLDER_RES = [
  /\b(?:example|sample|placeholder|dummy|foobar|lorem|abcdef|deadbeef)\b/i,
  /your[_-]?(?:api|access|secret|client|private)?[_-]?(?:key|token|secret|password|id)?/i,
  /(?:change[_-]?me|insert[_-]?(?:your|the)?[_-]?(?:key|token|here)?|replace[_-]?(?:me|with)|redacted|sanitized|hidden|removed|todo)/i,
  /(?:test[_-]?(?:key|token|secret)|fake[_-]?(?:key|token)|my[_-]?(?:secret|api[_-]?key|token))/i,
  /^<[^>]+>$/,            // <token>
  /^\$\{?[A-Za-z_][\w]*\}?$/, // ${VAR} / $VAR
  /^%[A-Za-z_][\w]*%$/,   // %VAR%
  /^\{\{.*\}\}$/,         // {{ handlebars }}
  /^[*xX•.]{3,}$/,        // xxxx / **** / ....
];

const KNOWN_EXAMPLE_RES = [
  /^AKIAIOSFODNN7EXAMPLE$/i,
  /^ASIAIOSFODNN7EXAMPLE$/i,
  /^AIzaSy(?:A{20,}|B{20,}|C{20,}|[A-Za-z0-9_-]*EXAMPLE[A-Za-z0-9_-]*)$/i,
  /^sk-(?:proj-)?a{10,}T3BlbkFJb{10,}$/i,
  /^sk-ant-api03-?a{20,}$/i,
  /^ghp_(?:1234567890abcdefghijklmnopqrstuvwxyzAB|[A-Za-z0-9]*example[A-Za-z0-9]*)$/i,
  /^github_pat_[A-Za-z0-9_]*example[A-Za-z0-9_]*$/i,
  /^glpat-(?:ABCDEF1234567890abcd|example[A-Za-z0-9_-]*)$/i,
  /^xox[baprs]-123456789012-abcdefghijklmnopqrst$/i,
  /^SG\.[A-Za-z0-9_-]*example[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/i,
];

/** True when the captured value is a documentation placeholder rather than a real secret. */
function isPlaceholderValue(value) {
  const s = String(value || "").trim();
  if (s.length < 4) return true;
  if (/^(.)\1{4,}$/.test(s)) return true;                 // a single char repeated (0000…, aaaa…)
  if (/^(?:0123456789|1234567890|abcdef0123456789)/i.test(s)) return true; // sequential
  for (const re of PLACEHOLDER_RES) if (re.test(s)) return true;
  return false;
}

function isKnownExampleValue(value) {
  const s = String(value || "").trim();
  if (!s) return false;
  return KNOWN_EXAMPLE_RES.some((re) => re.test(s));
}

const SECRET_KEYWORD_RE = /(secret|passwo?r?d|pwd|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth|credential|private[_-]?key|bearer|token)/i;
const PII_PHONE_KEYWORD_RE = /\b(?:phone|mobile|cell|tel|telephone|contact|call|sms|whatsapp|mfa|2fa|otp|voice)\b/i;

/** Is a secret-ish keyword within `window` chars of position `index` in `text`? (context boost) */
function nearKeyword(text, index, window = 40) {
  const s = String(text || "");
  const start = Math.max(0, index - window);
  return SECRET_KEYWORD_RE.test(s.slice(start, index + window));
}

function nearPhoneKeyword(text, index, window = 40) {
  const s = String(text || "");
  const start = Math.max(0, index - window);
  return PII_PHONE_KEYWORD_RE.test(s.slice(start, index + window));
}

function charClassCount(value) {
  const s = String(value || "");
  return [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].reduce((n, re) => n + (re.test(s) ? 1 : 0), 0);
}

function genericCredentialLikely(value, matchText = "") {
  const s = String(value || "").trim();
  if (s.length < 12 || isPlaceholderValue(s) || isKnownExampleValue(s)) return false;
  if (/^(?:true|false|null|none|undefined|admin|password|password1|password12|password123|changeme)$/i.test(s)) return false;
  if (/^[A-Za-z]+$/.test(s) && s.length < 20) return false;
  const entropy = shannonEntropy(s);
  const classes = charClassCount(s);
  const quotedOrConfigLike = /["'`]/.test(matchText) || /\b(?:process\.env|env|export|setx?|config|yaml|json|toml)\b/i.test(matchText);
  if (classes >= 3 && entropy >= 3.0) return true;
  if (classes >= 2 && entropy >= 3.4 && quotedOrConfigLike) return true;
  if (s.length >= 24 && entropy >= 3.5 && /\d/.test(s)) return true;
  return false;
}

const PUBLIC_TEST_CARD_NUMBERS = new Set([
  "4242424242424242",
  "4000056655665556",
  "5555555555554444",
  "2223003122003222",
  "5200828282828210",
  "5105105105105100",
  "378282246310005",
  "371449635398431",
  "6011111111111117",
  "6011000990139424",
  "30569309025904",
  "3566002020360505",
]);

function isPublicTestCardNumber(value) {
  const digits = String(value || "").replace(/[^\d]/g, "");
  return PUBLIC_TEST_CARD_NUMBERS.has(digits);
}

const UUID_RE = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;
const PATH_ROOTS = new Set(["users", "home", "private", "var", "tmp", "opt", "etc", "volumes", "applications", "library", "usr"]);
const PATH_SEGMENT_RE = /(?:^|\/)(?:Users|home|Downloads?|Documents?|Desktop|Library|AppData|ProgramData|Program Files|node_modules|src|dist|build|target|projects?|workspace|workspaces|supabase|dropbox|cursor|claude|codex)(?:\/|$)/i;
const PATH_EXTENSION_RE = /(?:^|\/)[A-Za-z0-9_.-]+\.(?:js|ts|jsx|tsx|json|jsonl|py|rb|go|rs|java|c|cpp|h|hpp|cs|sh|zsh|bash|ps1|ya?ml|toml|env|db|sqlite|vscdb|log|txt|csv|md)(?:$|\/)/i;

function isFilesystemPathLike(value) {
  const s = String(value || "").trim();
  if (!s || /\s/.test(s)) return false;
  const normalized = s.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  const slashCount = (normalized.match(/\//g) || []).length;
  if (/^(?:[A-Za-z]:|~|\.{1,2})\//.test(normalized)) return true;
  if (normalized.startsWith("/") && segments.length >= 2 && PATH_ROOTS.has(String(segments[0] || "").toLowerCase())) return true;
  if (slashCount >= 2 && PATH_SEGMENT_RE.test(normalized)) return true;
  if (slashCount >= 1 && PATH_EXTENSION_RE.test(normalized)) return true;
  return false;
}

/**
 * Extract base64-ish and hex blobs from text for entropy-based "unknown secret" detection.
 * Returns [{ value, index, kind }]. Bounded count so a huge cell can't explode output.
 */
function scanEntropyCandidates(text, max = 200) {
  const s = String(text || "");
  const out = [];
  const push = (re, kind) => {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(s)) !== null && out.length < max) {
      out.push({ value: m[0], index: m.index, kind });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  };
  push(/[A-Za-z0-9+/_-]{20,512}={0,2}/g, "base64");
  push(/\b[0-9a-fA-F]{32,512}\b/g, "hex");
  return out;
}

/**
 * Decide whether an entropy candidate is a likely secret. Precision-first:
 *   - base64: H >= 4.5 alone, or H >= 3.7 when a secret keyword is nearby;
 *   - hex: only when a secret keyword is nearby AND H >= 2.6 (bare hashes/MD5/SHA are NOT secrets);
 *   - never UUIDs, placeholders, pure-alpha words, or all-lowercase-hex with no context.
 * Returns null or { severity, confidence }.
 */
function classifyEntropyCandidate(cand, text) {
  const v = String(cand.value || "");
  if (v.length < 20 || isPlaceholderValue(v) || isKnownExampleValue(v) || UUID_RE.test(v)) return null;
  if (isFilesystemPathLike(v)) return null;
  if (!/\d/.test(v) && !/[+/_=-]/.test(v) && cand.kind === "base64") return null; // looks like a word
  const h = shannonEntropy(v);
  const ctx = nearKeyword(text, cand.index);
  if (cand.kind === "hex") {
    if (!ctx || h < 2.6) return null;
    return { severity: "medium", confidence: "suspicious" };
  }
  // base64
  if (h >= 4.5) return { severity: ctx ? "high" : "medium", confidence: ctx ? "suspicious" : "likely" };
  if (ctx && h >= 3.7) return { severity: "high", confidence: "suspicious" };
  return null;
}

/** Mask a secret for display/storage: first4…last4 + length. Cleartext is never written to disk. */
function redactValue(value) {
  const s = String(value || "");
  const n = s.length;
  if (n <= 8) return `${"•".repeat(Math.max(n, 1))} (${n} chars)`;
  return `${s.slice(0, 4)}${"•".repeat(Math.min(12, n - 8))}${s.slice(-4)} (${n} chars)`;
}

/** Stable per-scan fingerprint for cross-row correlation without persisting cleartext. */
function fingerprint(value, salt) {
  return crypto
    .createHash("sha256")
    .update(`${salt || ""}\x1f${String(value || "")}`)
    .digest("hex")
    .slice(0, 16);
}

module.exports = {
  shannonEntropy,
  luhnValid,
  creditCardLikely,
  ibanValid,
  isPlaceholderValue,
  isKnownExampleValue,
  isFilesystemPathLike,
  nearKeyword,
  nearPhoneKeyword,
  genericCredentialLikely,
  isPublicTestCardNumber,
  scanEntropyCandidates,
  classifyEntropyCandidate,
  redactValue,
  fingerprint,
  SECRET_KEYWORD_RE,
};
