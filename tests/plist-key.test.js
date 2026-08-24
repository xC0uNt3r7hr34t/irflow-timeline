"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { readPlistKeyFromBuffer } = require("../electron/utils/plist-key");
const { readPlistKey, readChatgptStatsigServicePlist } = require("../electron/parsers/ai-history/skysight-identity");

const XML = [
  `<?xml version="1.0" encoding="UTF-8"?>`,
  `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`,
  `<plist version="1.0"><dict>`,
  `<key>accountID</key><string>9097b427-4a0c-4a3b-b588-c8eeb7312c08</string>`,
  `<key>userEmail</key><string>subject@example.test</string>`,
  `<key>userID</key><string>user-TESTID</string>`,
  `<key>hasAnyPaidPlanAccount</key><true/>`,
  `<key>totalAccounts</key><integer>1</integer>`,
  `<key>com.Statsig.InternalStore.stableIDKey</key><string>AABBCCDD-1111-2222-3333-444455556666</string>`,
  `</dict></plist>`,
].join("\n");

test("XML plists yield string, integer, and boolean keys without plutil", () => {
  const buf = Buffer.from(XML, "utf8");
  assert.equal(readPlistKeyFromBuffer(buf, "userEmail"), "subject@example.test");
  assert.equal(readPlistKeyFromBuffer(buf, "totalAccounts"), "1");
  assert.equal(readPlistKeyFromBuffer(buf, "hasAnyPaidPlanAccount"), "true");
  assert.equal(readPlistKeyFromBuffer(buf, "com.Statsig.InternalStore.stableIDKey"), "AABBCCDD-1111-2222-3333-444455556666");
  assert.equal(readPlistKeyFromBuffer(buf, "missing"), null);
});

test("binary StatsigService.plist yields the same identity keys on Windows/Linux", () => {
  const fixture = path.join(__dirname, "fixtures", "chatgpt-statsig-service.bplist");
  const buf = fs.readFileSync(fixture);
  assert.equal(readPlistKeyFromBuffer(buf, "userEmail"), "subject@example.test");
  assert.equal(readPlistKeyFromBuffer(buf, "accountID"), "9097b427-4a0c-4a3b-b588-c8eeb7312c08");
  assert.equal(readPlistKeyFromBuffer(buf, "hasAnyPaidPlanAccount"), "true");
  assert.equal(readPlistKeyFromBuffer(buf, "totalAccounts"), "1");
  assert.equal(readPlistKeyFromBuffer(buf, "com.Statsig.InternalStore.stableIDKey"), "AABBCCDD-1111-2222-3333-444455556666");
});

test("readPlistKey falls back to the JS parser when plutil is unavailable", () => {
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "plist-key-"));
  const filePath = path.join(dir, "com.openai.chat.StatsigService.plist");
  fs.writeFileSync(filePath, XML);
  const parsed = readChatgptStatsigServicePlist(filePath);
  assert.equal(parsed.email, "subject@example.test");
  assert.equal(readPlistKey(filePath, "userID"), "user-TESTID");
  fs.rmSync(dir, { recursive: true, force: true });
});
