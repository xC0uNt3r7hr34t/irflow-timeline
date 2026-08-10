// Command-line decoder for the Process Inspector detail panel.
//
// Attackers routinely hide the real payload behind base64 (PowerShell
// `-EncodedCommand`, certutil/`FromBase64String` blobs, often UTF-16LE and
// sometimes gzip-compressed). This module surfaces the cleartext so an analyst
// doesn't have to leave the timeline to decode it by hand.
//
// Pure / dependency-free and safe in both the Chromium renderer and Node test
// runner: relies only on `atob` and `TextDecoder`, both global in each.

const _B64_CHARS = /^[A-Za-z0-9+/]+={0,2}$/;
// PowerShell encoded-command flags: -e -ec -en -enc -encodedcommand (also `/enc`).
// Captures an optional quote and the base64 blob that follows.
const _ENC_FLAG = /(?:^|\s)[-/](?:e|ec|en|enc|encodedcommand)\s+(['"]?)([A-Za-z0-9+/=]{16,})\1/i;
// Standalone base64 runs (FromBase64String payloads, certutil -decode input, etc.).
const _B64_BLOB = /[A-Za-z0-9+/]{24,}={0,2}/g;

const MAX_PREVIEW = 4000;
const MAX_DECODINGS = 8;
const MAX_DEPTH = 3;

// Share of characters that are printable ASCII or common whitespace. Restricted
// to ASCII on purpose: command-line payloads are overwhelmingly ASCII, and this
// is also what disambiguates the encoding — UTF-8 ASCII bytes misread as UTF-16LE
// decode to high-Unicode (CJK) noise, which must NOT score as "readable".
function printableRatio(s) {
  if (!s || !s.length) return 0;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) ok++;
  }
  return ok / s.length;
}

function b64ToBytes(b64) {
  const clean = (b64 || "").replace(/\s+/g, "");
  if (clean.length < 8 || !_B64_CHARS.test(clean)) return null;
  // Re-pad to a multiple of 4 so atob accepts it.
  const stripped = clean.replace(/=+$/, "");
  const padded = stripped + "=".repeat((4 - (stripped.length % 4)) % 4);
  let bin;
  try {
    bin = atob(padded);
  } catch {
    return null;
  }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Decode raw bytes to text, picking the encoding that yields the most readable
// result. PowerShell encodes commands as UTF-16LE, so that is tried first.
function decodeBytes(bytes) {
  if (!bytes || bytes.length < 2) return null;
  // gzip magic — can't inflate without a dependency, but flag it so the analyst knows.
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return { text: null, encoding: "gzip", note: "gzip-compressed stream — decompress externally to read" };
  }
  let u16 = "";
  let u8 = "";
  try { u16 = new TextDecoder("utf-16le", { fatal: false }).decode(bytes); } catch { u16 = ""; }
  try { u8 = new TextDecoder("utf-8", { fatal: false }).decode(bytes); } catch { u8 = ""; }
  const r16 = printableRatio(u16);
  const r8 = printableRatio(u8);
  if (r16 >= 0.85 && r16 >= r8) return { text: u16, encoding: "utf-16le" };
  if (r8 >= 0.85) return { text: u8, encoding: "utf-8" };
  return null;
}

function pushDecoding(out, seen, decoding) {
  const key = decoding.raw;
  if (key && seen.has(key)) return false;
  if (key) seen.add(key);
  if (decoding.decoded && decoding.decoded.length > MAX_PREVIEW) {
    decoding.truncated = decoding.decoded.length;
    decoding.decoded = decoding.decoded.slice(0, MAX_PREVIEW);
  }
  out.push(decoding);
  return true;
}

// Walk a command line, decode every base64 layer it can, and recurse into the
// cleartext (nested encodings are common: -enc -> a script that FromBase64String's again).
function collect(cmd, depth, seen, out) {
  if (!cmd || typeof cmd !== "string" || depth > MAX_DEPTH || out.length >= MAX_DECODINGS) return;

  const enc = cmd.match(_ENC_FLAG);
  if (enc) {
    const d = decodeBytes(b64ToBytes(enc[2]));
    if (d) {
      const added = pushDecoding(out, seen, {
        source: depth === 0 ? "PowerShell -EncodedCommand" : `PowerShell -EncodedCommand (layer ${depth + 1})`,
        encoding: d.encoding, raw: enc[2], decoded: d.text, note: d.note,
      });
      if (added && d.text) collect(d.text, depth + 1, seen, out);
    }
  }

  const blobs = cmd.match(_B64_BLOB) || [];
  for (const b of blobs) {
    if (out.length >= MAX_DECODINGS) break;
    if (seen.has(b)) continue;
    const d = decodeBytes(b64ToBytes(b));
    if (!d) continue;
    if (d.encoding === "gzip") {
      pushDecoding(out, seen, { source: depth === 0 ? "Base64 blob" : `Base64 blob (layer ${depth + 1})`, encoding: "gzip", raw: b, decoded: null, note: d.note });
      continue;
    }
    // Standalone blobs must decode very cleanly to avoid false hits on long hex/IDs.
    if (d.text && printableRatio(d.text) >= 0.9 && /[ -~]/.test(d.text)) {
      const added = pushDecoding(out, seen, {
        source: depth === 0 ? "Base64 blob" : `Base64 blob (layer ${depth + 1})`,
        encoding: d.encoding, raw: b, decoded: d.text,
      });
      if (added && d.text) collect(d.text, depth + 1, seen, out);
    }
  }
}

// Public: returns { decodings: [{source, encoding, raw, decoded, note?, truncated?}], hasEncoded }.
export function analyzeCommandLine(cmd) {
  const out = [];
  collect(cmd, 0, new Set(), out);
  return { decodings: out, hasEncoded: out.length > 0 };
}

// Lightweight token classifier for highlighting the raw command line. Returns an
// ordered list of { text, type } segments (type ∈ flag|url|ip|path|base64|plain).
const _SEG = /(https?:\/\/[^\s"']+|ftp:\/\/[^\s"']+)|(\b(?:\d{1,3}\.){3}\d{1,3}\b)|((?:^|\s)[-/]{1,2}[A-Za-z][\w-]*)|([A-Za-z]:\\[^\s"']+|\\\\[^\s"']+)|([A-Za-z0-9+/]{24,}={0,2})/g;

export function tokenizeCommandLine(cmd) {
  if (!cmd || typeof cmd !== "string") return [];
  const segs = [];
  let last = 0;
  let m;
  _SEG.lastIndex = 0;
  while ((m = _SEG.exec(cmd))) {
    if (m.index > last) segs.push({ text: cmd.slice(last, m.index), type: "plain" });
    const type = m[1] ? "url" : m[2] ? "ip" : m[3] ? "flag" : m[4] ? "path" : "base64";
    segs.push({ text: m[0], type });
    last = m.index + m[0].length;
  }
  if (last < cmd.length) segs.push({ text: cmd.slice(last), type: "plain" });
  return segs;
}
