// Coverage for the previously-untested IOC categorizer (src/utils/ioc-parsing.js),
// including the regression where a bracket-less IPv6 address (e.g. "fe80::1") was
// miscategorized as IPv6_Address:Port because it ends in ":<hex>".

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function load() {
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "utils", "ioc-parsing.js"), "utf8");
  const munged = src
    .replace(/^export\s+const\s+/gm, "const ")
    .replace(/^export\s+function\s+/gm, "function ");
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(munged + "\n;Object.assign(globalThis,{ parseIocText, defangIoc, defangUrl });", ctx);
  return ctx;
}
const { parseIocText } = load();

const cat = (input) => {
  const r = parseIocText(input);
  return r.length === 1 ? r[0].category : r.map((x) => x.category);
};
const one = (input) => parseIocText(input)[0];

test("bracket-less IPv6 is an address, not address:port (regression)", () => {
  assert.equal(cat("fe80::1"), "IPv6_Address");
  assert.equal(cat("2001:db8::1"), "IPv6_Address");
  assert.equal(cat("::1"), "IPv6_Address");
});

test("bracketed IPv6 with a port is IPv6_Address:Port", () => {
  assert.equal(cat("[2001:db8::1]:443"), "IPv6_Address:Port");
});

test("IPv4 plain / with port / CIDR", () => {
  assert.equal(cat("10.0.0.5"), "IPv4_Address");
  assert.equal(cat("10.0.0.5:8080"), "IPv4_Address:Port");
  assert.equal(cat("192.168.1.0/24"), "IPv4_Address");
});

test("hashes by length", () => {
  assert.equal(cat("a".repeat(64)), "SHA256_Hash");
  assert.equal(cat("b".repeat(40)), "SHA1_Hash");
  assert.equal(cat("c".repeat(32)), "MD5_Hash");
});

test("domains, file names, email", () => {
  assert.equal(cat("evil.com"), "Domain_Name");
  assert.equal(cat("update-service-cdn.com"), "Domain_Name");
  assert.equal(cat("svchost.exe"), "File_Name");
  assert.equal(cat("payload.dll"), "File_Name");
  assert.equal(cat("user@example.com"), "Email_Address");
});

test("defanged IOCs are un-obfuscated and categorized", () => {
  assert.equal(one("evil[.]com").raw, "evil.com");
  assert.equal(one("evil[.]com").category, "Domain_Name");
  const url = one("hxxps://evil[.]com/malware.bin");
  assert.equal(url.category, "URL");
  assert.match(url.raw, /^https:\/\/evil\.com/);
});

test("comments are skipped and duplicates deduped", () => {
  const r = parseIocText("# header comment\n10.0.0.5\n10.0.0.5\n");
  assert.equal(r.length, 1);
  assert.equal(r[0].category, "IPv4_Address");
});
