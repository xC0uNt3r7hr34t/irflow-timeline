const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeHostEndpoint,
  isExcludedEndpoint,
  buildObservedHostAliases,
} = require("../electron/analyzers/lateral-movement/endpoint-normalize");

test("normalizes address:port and bracketed IPv6 host values", () => {
  assert.equal(normalizeHostEndpoint("10.2.10.113:3389"), "10.2.10.113");
  assert.equal(normalizeHostEndpoint("[2001:db8::4]:3389"), "2001:DB8::4");
  assert.equal(normalizeHostEndpoint("wks01.example.test."), "WKS01.EXAMPLE.TEST");
});

test("rejects loopback and collector placeholder endpoints", () => {
  for (const value of ["127.0.0.1:0", "::1:0", "[::1]:3389", "-:-", "(empty)", "LOCALHOST"]) {
    assert.equal(isExcludedEndpoint(value), true, `${value} should be excluded`);
  }
  assert.equal(isExcludedEndpoint("10.2.10.113:3389"), false);
});

test("aliases one observed FQDN to its observed short name without cross-domain collisions", () => {
  const safe = buildObservedHostAliases(["WKS2390", "WKS2390.ORIONHUBS.LOCAL", "DC01"]);
  assert.equal(safe.get("WKS2390.ORIONHUBS.LOCAL"), "WKS2390");

  const ambiguous = buildObservedHostAliases([
    "WKS2390",
    "WKS2390.NORTH.EXAMPLE",
    "WKS2390.SOUTH.EXAMPLE",
  ]);
  assert.equal(ambiguous.has("WKS2390.NORTH.EXAMPLE"), false);
  assert.equal(ambiguous.has("WKS2390.SOUTH.EXAMPLE"), false);
});
