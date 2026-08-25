// ── IOC Parsing ───────────────────────────────────────────────────
// Order matters — first match wins. More specific patterns must come before broader ones.
export const IOC_CATEGORY_PATTERNS = [
  // Hashes — exact-length hex strings
  ["SHA256_Hash",  /^[0-9a-f]{64}$/i],
  ["SHA1_Hash",    /^[0-9a-f]{40}$/i],
  ["MD5_Hash",     /^[0-9a-f]{32}$/i],
  // Network — IP with port
  ["IPv4_Address:Port", /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$/],
  // Brackets are REQUIRED for the host:port form — otherwise a plain IPv6 like "fe80::1"
  // or "2001:db8::1" (which ends in ":<hex>") is misread as address:port. Bracket-less
  // IPv6 falls through to the IPv6_Address pattern below.
  ["IPv6_Address:Port", /^\[[0-9a-f:]{2,39}\]:\d{1,5}$/i],
  // Network — plain IPs
  ["IPv4_Address", /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/],
  ["IPv6_Address", /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i],
  // Network — Email
  ["Email_Address", /^[^\s@]+@[^\s@]+\.[^\s@]+$/],
  // Host — Registry keys (HKEY_LOCAL_MACHINE\..., HKLM\..., etc.)
  ["Registry_Key", /^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(\\|$)/i],
  // Host — Named pipes (\\.\pipe\...)
  ["Named_Pipe",   /^\\\\\.\\pipe\\/i],
  // Host — Mutex (Global\..., Local\...)
  ["Mutex",        /^(Global\\|Local\\)/],
  // Host — File paths (C:\..., \\server\..., /usr/... — must have separator after root)
  ["File_Path",    /^([A-Za-z]:\\[^\s]|\\\\[^\\]+\\|\/[^\s]+\/)/],
  // Network — Crypto wallets (Bitcoin, Ethereum, Monero)
  ["Crypto_Wallet", /^(1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-z0-9]{25,90}|0x[0-9a-fA-F]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})$/],
  // Network — User agent strings
  ["User_Agent_String", /^Mozilla\//i],
  // NOTE: File_Name vs Domain_Name is handled by custom logic in parseIocText (not simple regex order)
  // Fallback — "Other" is assigned if nothing matches (handled in parseIocText)
];

// Auto-defang IOC values: undo common obfuscation used in threat intel feeds
export function defangIoc(text) {
  let s = text.trim();
  // Strip protocol first (handles all obfuscated variants):
  // hxxps[://], https[://], hxxps://, https://, hxxp[://], http[://], hxxp://, http://
  s = s.replace(/^h[tx]{2}ps?\s*\[?:\/?\/?\]?\s*/i, "");
  // Also catch plain https?:// and ftp://
  s = s.replace(/^(?:https?|ftp):\/\//i, "");
  // Bracket-dot defanging: [.] [dot] (.) → .
  s = s.replace(/\[\.\]/g, ".").replace(/\[dot\]/gi, ".").replace(/\(\.\)/g, ".");
  // Bracket-colon/at defanging
  s = s.replace(/\[:\]/g, ":").replace(/\[@\]/g, "@");
  // Strip URL path/query/fragment — keep domain (+ optional port)
  // Only if it looks like a domain (contains a dot and slash after it)
  if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?[/?#]/i.test(s)) {
    s = s.split(/[/?#]/)[0];
  }
  // Strip trailing dot (FQDN notation)
  s = s.replace(/\.$/, "");
  return s;
}

export function defangUrl(text) {
  let s = text.trim();
  // Fix obfuscated protocol: hxxps → https, hxxp → http, ftp variants
  s = s.replace(/^hxxps\s*\[?:\/?\/?\]?\s*/i, "https://");
  s = s.replace(/^hxxp\s*\[?:\/?\/?\]?\s*/i, "http://");
  s = s.replace(/^ftp\s*\[?:\/?\/?\]?\s*/i, "ftp://");
  // Ensure plain protocol:// is preserved (not stripped like defangIoc does)
  // Bracket-dot defanging: [.] [dot] (.) → .
  s = s.replace(/\[\.\]/g, ".").replace(/\[dot\]/gi, ".").replace(/\(\.\)/g, ".");
  // Bracket-colon/at defanging
  s = s.replace(/\[:\]/g, ":").replace(/\[@\]/g, "@");
  // Strip trailing FQDN dot in hostname portion (before path)
  s = s.replace(/(\/\/[^/?#]+)\.(\/|$|\?|#)/, "$1$2");
  return s;
}

export function parseIocText(rawText) {
  const lines = rawText.split(/\r?\n/);
  const seen = new Set();
  const iocs = [];
  for (const line of lines) {
    const trimmed = line.replace(/#.*$/, "").trim();
    if (!trimmed) continue;
    // Detect URLs before defanging strips protocol/path
    const isUrl = /^(hxxps?|https?|ftp)\s*\[?:\/?\/?\]?\s*\S/i.test(trimmed) ||
                  /^(hxxps?|https?|ftp):\/\//i.test(trimmed);
    if (isUrl) {
      const clean = defangUrl(trimmed);
      if (!clean || seen.has(clean.toLowerCase())) continue;
      seen.add(clean.toLowerCase());
      iocs.push({ raw: clean, category: "URL" });
      continue;
    }
    // Defang before dedup and categorization
    const clean = defangIoc(trimmed);
    if (!clean || seen.has(clean.toLowerCase())) continue;
    seen.add(clean.toLowerCase());
    let category = "Other";
    for (const [cat, re] of IOC_CATEGORY_PATTERNS) {
      if (re.test(clean)) { category = cat; break; }
    }
    // File_Name vs Domain_Name disambiguation (regex order can't solve this alone)
    if (category === "Other") {
      // Extensions that are NEVER TLDs — always a file name
      const fileOnlyRe = /^[^\\/:*?"<>|\s]+\.(exe|dll|bat|cmd|ps1|psm1|psd1|vbs|vbe|jse|wsf|wsh|hta|msi|msp|mst|scr|sys|cpl|ocx|drv|jar|war|pyc|bash|dat|tmp|sqlite|doc[xm]|xls[xm]|ppt[xm]|rtf|tsv|rar|7z|bz2|xz|vhd|vhdx|vmdk|ova|lnk|cfg|conf|yaml|yml|reg|inf|mui|pf|evtx?|dmp|pcap|cap)$/i;
      // Extensions that COULD be TLDs/domains — need to check if it's a multi-segment domain
      const ambiguousRe = /^[^\\/:*?"<>|\s]+\.(com|net|org|io|sh|py|rs|js|rb|cc|im|ai|app|dev|gg|me|tv|co|de|uk|ru|in|br|au|ph|sg|cat|bin|zip|mov|pdf|doc|csv|xml|json|iso|img|log|db|ax|ini|url|gz|tar)$/i;
      const domainRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?){1,}$/i;
      if (fileOnlyRe.test(clean)) {
        category = "File_Name";
      } else if (ambiguousRe.test(clean) && domainRe.test(clean)) {
        // Has multiple dot-segments (e.g., update-service-cdn.com) → Domain
        // Single segment + ambiguous ext with no subdomain-like parts → also Domain
        // Only treat as File_Name if it looks like a filename (has underscore, starts with uppercase drive-like)
        const dotCount = (clean.match(/\./g) || []).length;
        if (dotCount === 1 && /^[a-z0-9_-]+\.[a-z]+$/i.test(clean)) {
          // Single dot, looks like either file or domain — check for filename indicators
          if (/[_]/.test(clean.split(".")[0])) {
            category = "File_Name"; // underscores are filename-like (e.g., svchost_update.exe)
          } else {
            category = "Domain_Name"; // no underscores, looks like a domain (e.g., update-service-cdn.com)
          }
        } else {
          category = "Domain_Name";
        }
      } else if (domainRe.test(clean)) {
        category = "Domain_Name";
      }
    }
    iocs.push({ raw: clean, category });
  }
  return iocs;
}

export function escapeIocForRegex(ioc) {
  return ioc.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
}
