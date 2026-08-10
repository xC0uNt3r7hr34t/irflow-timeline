/**
 * analyzers/ai-history/detection-rules — the curated secret/credential/PII detector catalog.
 *
 * Each rule is matched by analyzers/ai-history/index.js, which compiles `regex` through
 * compileSafeRegex (ReDoS guard: <=1024 chars, no nested quantifiers, 64 KiB value cap) and then
 * applies the `validate` post-filter + placeholder allow-list before emitting a finding.
 *
 * Rule shape:
 *   id          unique slug
 *   title       human label
 *   category    secret-cloud | secret-scm | secret-ai | secret-payment | secret-messaging |
 *               secret-generic | private-key | pii
 *   severity    critical | high | medium | low
 *   regex       JS source string (flat, bounded char-classes — NO quantified groups)
 *   flags       regex flags; "" = case-sensitive (token formats), "i" = keyword-anchored. Default "i".
 *   valueGroup  capture-group index holding the secret VALUE (for redaction/entropy/fingerprint).
 *               Omit / 0 → whole match.
 *   roleScope   "any" | "user" | "assistant" (which speaker's text the rule applies to). Default any.
 *   mitreId/Name ATT&CK mapping (T1552.001 creds, T1552.004 private keys, T1528 app token).
 *   confidence  base label: verified | likely | suspicious | informational.
 *               Engine upgrades validator-backed structural matches to `validatedConfidence` or `verified`.
 *   mode        "deep" → only runs in Deep scan (PII + loose/entropy). Omit → runs in Quick (default).
 *   extract     optional (text, match) => { value, matchText, index } to expand a seed match.
 *   validate    optional (value, match) => boolean post-filter.
 *
 * NOTE: keep regexes flat. compileSafeRegex rejects a group that contains a variable quantifier
 * (plus, star, or open-ended brace range) and is itself repeated. Use bounded char-classes like
 * [A-Za-z0-9]{20,40} instead of a repeated capturing group.
 */

const {
  creditCardLikely,
  ibanValid,
  shannonEntropy,
  genericCredentialLikely,
  nearPhoneKeyword,
} = require("./validators");

const CRED = { mitreId: "T1552.001", mitreName: "Unsecured Credentials: Credentials In Files" };
const PKEY = { mitreId: "T1552.004", mitreName: "Unsecured Credentials: Private Keys" };
const APPTOK = { mitreId: "T1528", mitreName: "Steal Application Access Token" };

const PEM_BEGIN_RE = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/;
const PEM_END_RE = /-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/;
const PEM_LINE_RE = /^[A-Za-z0-9+/=]{4,}$/;
const PEM_SCAN_LIMIT = 12000;

function escapedNewlineLenAt(text, index) {
  if (text.startsWith("\\\\r\\\\n", index)) return 6;
  if (text.startsWith("\\\\n", index) || text.startsWith("\\\\r", index)) return 3;
  if (text.startsWith("\\r\\n", index)) return 4;
  if (text.startsWith("\\n", index) || text.startsWith("\\r", index)) return 2;
  if (text.startsWith("\r\n", index)) return 2;
  if (text[index] === "\n" || text[index] === "\r") return 1;
  return 0;
}

function pemBreakAt(text, index) {
  const nl = escapedNewlineLenAt(text, index);
  if (nl) return { type: "newline", len: nl };
  if (/^\\+["']/.test(text.slice(index, index + 8)) || text[index] === '"' || text[index] === "'") return { type: "quote", len: 0 };
  if (text[index] === "," || text[index] === "}") return { type: "boundary", len: 0 };
  return null;
}

function nextPemBreak(text, start, max) {
  for (let i = start; i < max; i += 1) {
    const br = pemBreakAt(text, i);
    if (br) return { index: i, ...br };
  }
  return { index: max, type: "end", len: 0 };
}

function extractPemPrivateKey(text, match) {
  const start = match.index;
  const seed = match[0];
  const hardEnd = Math.min(text.length, start + PEM_SCAN_LIMIT);
  const rest = text.slice(start, hardEnd);
  const endMatch = PEM_END_RE.exec(rest);
  if (endMatch) {
    const end = start + endMatch.index + endMatch[0].length;
    const value = text.slice(start, end);
    return { value, matchText: value, index: start };
  }

  let cursor = start + seed.length;
  let end = cursor;
  let bodyLines = 0;
  while (cursor < hardEnd) {
    const nl = escapedNewlineLenAt(text, cursor);
    if (!nl) break;
    const lineStart = cursor + nl;
    const br = nextPemBreak(text, lineStart, hardEnd);
    const rawLine = text.slice(lineStart, br.index);
    const line = rawLine.trim();
    if (!line) break;
    if (PEM_END_RE.test(line)) {
      end = lineStart + line.indexOf("-----END") + line.match(PEM_END_RE)[0].length;
      const value = text.slice(start, end);
      return { value, matchText: value, index: start };
    }
    if (!PEM_LINE_RE.test(line)) break;
    bodyLines += 1;
    end = br.index;
    if (br.type !== "newline") break;
    cursor = br.index;
  }

  if (bodyLines > 0 && end > start + seed.length) {
    const value = text.slice(start, end);
    return { value, matchText: value, index: start };
  }
  return { value: seed, matchText: seed, index: start };
}

function pemPrivateKeyLikely(value) {
  const text = String(value || "");
  const begin = PEM_BEGIN_RE.exec(text);
  if (!begin) return false;
  let cursor = begin.index + begin[0].length;
  const hardEnd = Math.min(text.length, begin.index + PEM_SCAN_LIMIT);
  let bodyLines = 0;
  let bodyChars = 0;
  while (cursor < hardEnd) {
    const nl = escapedNewlineLenAt(text, cursor);
    if (!nl) return false;
    const lineStart = cursor + nl;
    const br = nextPemBreak(text, lineStart, hardEnd);
    const line = text.slice(lineStart, br.index).trim();
    if (!line) return false;
    if (PEM_END_RE.test(line)) return bodyChars >= 16;
    if (PEM_LINE_RE.test(line)) {
      bodyLines += 1;
      bodyChars += line.replace(/=/g, "").length;
      if (br.type !== "newline") break;
      cursor = br.index;
      continue;
    }
    return false;
  }
  return bodyChars >= 40 || (bodyLines >= 2 && bodyChars >= 32);
}

const AI_DETECTION_RULES = [
  // ───────────────────────── Cloud provider keys ─────────────────────────
  {
    id: "aws-access-key", title: "AWS Access Key ID", category: "secret-cloud", severity: "high",
    regex: "\\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\\b", flags: "",
    confidence: "likely", ...CRED,
  },
  {
    id: "aws-secret-key", title: "AWS Secret Access Key", category: "secret-cloud", severity: "critical",
    regex: "(?:aws_secret_access_key|aws_secret|secret_access_key)[\"'`]?\\s*[:=]\\s*[\"'`]?([A-Za-z0-9/+]{40})",
    flags: "i", valueGroup: 1, confidence: "suspicious", validatedConfidence: "likely", ...CRED,
    validate: (v) => shannonEntropy(v) >= 3.5,
  },
  {
    id: "gcp-api-key", title: "Google Cloud API Key", category: "secret-cloud", severity: "high",
    regex: "\\bAIza[0-9A-Za-z_\\-]{35}\\b", flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "gcp-oauth-secret", title: "Google OAuth Client Secret", category: "secret-cloud", severity: "high",
    regex: "\\bGOCSPX-[0-9A-Za-z_\\-]{20,40}\\b", flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "azure-storage-conn", title: "Azure Storage Connection String", category: "secret-cloud", severity: "critical",
    regex: "DefaultEndpointsProtocol=https?;AccountName=[0-9a-z]{3,24};AccountKey=([A-Za-z0-9+/=]{50,120})",
    flags: "i", valueGroup: 1, confidence: "likely", ...CRED,
  },
  {
    id: "do-pat", title: "DigitalOcean Personal Access Token", category: "secret-cloud", severity: "high",
    regex: "\\bdop_v1_[0-9a-f]{64}\\b", flags: "", confidence: "likely", ...CRED,
  },

  // ───────────────────────── Source-control / package tokens ─────────────
  {
    id: "github-pat", title: "GitHub Token", category: "secret-scm", severity: "high",
    regex: "\\bgh[pousr]_[0-9A-Za-z]{36,255}\\b", flags: "", confidence: "likely", ...APPTOK,
  },
  {
    id: "github-fine-grained", title: "GitHub Fine-grained PAT", category: "secret-scm", severity: "high",
    regex: "\\bgithub_pat_[0-9A-Za-z_]{22,255}\\b", flags: "", confidence: "likely", ...APPTOK,
  },
  {
    id: "gitlab-pat", title: "GitLab Personal Access Token", category: "secret-scm", severity: "high",
    regex: "\\bglpat-[0-9A-Za-z_\\-]{20,40}\\b", flags: "", confidence: "likely", ...APPTOK,
  },
  {
    id: "npm-token", title: "npm Access Token", category: "secret-scm", severity: "high",
    regex: "\\bnpm_[0-9A-Za-z]{36}\\b", flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "pypi-token", title: "PyPI Upload Token", category: "secret-scm", severity: "high",
    regex: "\\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\\-]{50,}\\b", flags: "", confidence: "likely", ...CRED,
  },

  // ───────────────────────── AI provider keys ────────────────────────────
  {
    id: "openai-key", title: "OpenAI API Key", category: "secret-ai", severity: "critical",
    regex: "\\bsk-(?:proj-)?[A-Za-z0-9_\\-]{20,}T3BlbkFJ[A-Za-z0-9_\\-]{20,}\\b", flags: "",
    confidence: "likely", ...CRED,
  },
  {
    id: "anthropic-key", title: "Anthropic API Key", category: "secret-ai", severity: "critical",
    regex: "\\bsk-ant-[0-9A-Za-z_\\-]{24,}\\b", flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "huggingface-token", title: "Hugging Face Token", category: "secret-ai", severity: "high",
    regex: "\\bhf_[0-9A-Za-z]{30,40}\\b", flags: "", confidence: "likely", ...CRED,
  },

  // ───────────────────────── Payment / comms / messaging ─────────────────
  {
    id: "stripe-live-key", title: "Stripe Live Secret Key", category: "secret-payment", severity: "critical",
    regex: "\\b[sr]k_live_[0-9A-Za-z]{20,40}\\b", flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "stripe-test-key", title: "Stripe Test Secret Key", category: "secret-payment", severity: "low",
    regex: "\\b[sr]k_test_[0-9A-Za-z]{20,40}\\b", flags: "", confidence: "informational", ...CRED,
  },
  {
    id: "sendgrid-key", title: "SendGrid API Key", category: "secret-messaging", severity: "high",
    regex: "\\bSG\\.[0-9A-Za-z_\\-]{22}\\.[0-9A-Za-z_\\-]{43}\\b", flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "twilio-key", title: "Twilio API Key", category: "secret-messaging", severity: "high",
    regex: "\\bSK[0-9a-fA-F]{32}\\b", flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "slack-token", title: "Slack Token", category: "secret-messaging", severity: "high",
    regex: "\\bxox[baprs]-[0-9A-Za-z\\-]{10,72}\\b", flags: "", confidence: "likely", ...APPTOK,
  },
  {
    id: "slack-webhook", title: "Slack Incoming Webhook", category: "secret-messaging", severity: "medium",
    regex: "https://hooks\\.slack\\.com/services/T[0-9A-Z]{8,12}/B[0-9A-Z]{8,12}/[0-9A-Za-z]{20,30}",
    flags: "", confidence: "likely", ...CRED,
  },
  {
    id: "telegram-bot-token", title: "Telegram Bot Token", category: "secret-messaging", severity: "high",
    regex: "\\b\\d{8,10}:[A-Za-z0-9_\\-]{35}\\b", flags: "", confidence: "likely", ...APPTOK,
  },

  // ───────────────────────── Private keys / certs ────────────────────────
  {
    id: "pem-private-key", title: "Private Key (PEM block)", category: "private-key", severity: "critical",
    regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\\s\\S]{0,12000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", flags: "",
    confidence: "likely", extract: extractPemPrivateKey, validate: (v) => pemPrivateKeyLikely(v), ...PKEY,
  },
  {
    id: "putty-private-key", title: "PuTTY Private Key (.ppk)", category: "private-key", severity: "high",
    regex: "PuTTY-User-Key-File-[23]:", flags: "", confidence: "likely", ...PKEY,
  },
  {
    id: "age-secret-key", title: "age Secret Key", category: "private-key", severity: "high",
    regex: "\\bAGE-SECRET-KEY-1[0-9A-Z]{50,60}\\b", flags: "", confidence: "likely", ...PKEY,
  },

  // ───────────────────────── JWT + generic credential shapes ─────────────
  {
    id: "jwt", title: "JSON Web Token (JWT)", category: "secret-generic", severity: "medium",
    regex: "\\beyJ[A-Za-z0-9_=\\-]{10,}\\.eyJ[A-Za-z0-9_=\\-]{10,}\\.[A-Za-z0-9_=\\-]{6,}\\b", flags: "",
    confidence: "likely", ...APPTOK,
  },
  {
    id: "auth-bearer-basic", title: "Authorization Header Credential", category: "secret-generic", severity: "high",
    regex: "authorization[\"'`]?\\s*[:=]\\s*[\"'`]?(?:bearer|basic)\\s+([A-Za-z0-9._~+/=\\-]{8,512})",
    flags: "i", valueGroup: 1, confidence: "suspicious", ...APPTOK,
  },
  {
    id: "url-basic-auth", title: "Credential in URL (user:pass@host)", category: "secret-generic", severity: "high",
    regex: "\\b[a-z][a-z0-9+.\\-]{1,20}://[^\\s:/@]{1,256}:([^\\s:/@]{3,256})@", flags: "i", valueGroup: 1,
    confidence: "suspicious", ...CRED,
  },
  {
    id: "generic-secret-assignment", title: "Hardcoded Credential Assignment", category: "secret-generic", severity: "medium",
    regex: "(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key)[\"'`]?\\s*[:=]\\s*[\"'`]?([^\\s\"'`,;]{8,128})",
    flags: "i", valueGroup: 1, confidence: "suspicious", validatedConfidence: "suspicious", ...CRED,
    validate: (v, m) => genericCredentialLikely(v, m && m[0]),
  },

  // ───────────────────────── PII (Deep scan only) ────────────────────────
  {
    id: "pii-email", title: "Email Address", category: "pii", severity: "low", mode: "deep",
    regex: "\\b[A-Za-z0-9._%+\\-]{1,64}@[A-Za-z0-9.\\-]{1,255}\\.[A-Za-z]{2,24}\\b", flags: "i",
    confidence: "informational",
  },
  {
    id: "pii-ssn", title: "US Social Security Number", category: "pii", severity: "medium", mode: "deep",
    regex: "\\b(?!000|666|9\\d\\d)\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b", flags: "", confidence: "likely",
  },
  {
    id: "pii-credit-card", title: "Credit Card Number", category: "pii", severity: "medium", mode: "deep",
    regex: "\\b\\d{4}[ \\-]?\\d{4}[ \\-]?\\d{4}[ \\-]?\\d{1,7}\\b", flags: "", confidence: "suspicious",
    validate: (v) => creditCardLikely(v),
  },
  {
    id: "pii-iban", title: "IBAN", category: "pii", severity: "medium", mode: "deep",
    regex: "\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b", flags: "", confidence: "suspicious",
    validate: (v) => ibanValid(v),
  },
  {
    id: "pii-phone", title: "Phone Number", category: "pii", severity: "low", mode: "deep",
    regex: "(?<![\\d.])\\+?\\d{1,3}[ .()\\-]{0,3}\\d{3}[ .()\\-]{0,3}\\d{3}[ .()\\-]{0,3}\\d{4}(?!\\d)",
    flags: "", confidence: "informational",
    validate: (_v, m, text) => nearPhoneKeyword(text, m && m.index),
  },
];

module.exports = { AI_DETECTION_RULES };
