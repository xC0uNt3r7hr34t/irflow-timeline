"use strict";

const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  parseChatgptTimestamp,
  parseConversationItem,
  extractFromLeveldbBytes,
  extractChatgptDir,
  extractChatgptPath,
  isChatgptAppDir,
  isChatgptAppDirQuick,
  buildChatgptExtractionStats,
  detectConversationBundles,
  detectEncryptedConversationBundles,
  formatChatgptImportNotice,
  isChatgptDataFile,
} = require("../electron/parsers/ai-history/chatgpt");

const FIXTURE_ROOT = path.join(__dirname, "fixtures/ai-history/chatgpt/com.openai.chat");
const FIXTURE_DB = path.join(FIXTURE_ROOT, "messages.db");

let sqliteAvailable = false;

before(() => {
  try {
    const Database = require("better-sqlite3");
    fs.mkdirSync(FIXTURE_ROOT, { recursive: true });
    if (fs.existsSync(FIXTURE_DB)) fs.unlinkSync(FIXTURE_DB);
    const db = new Database(FIXTURE_DB);
    db.exec(`CREATE TABLE messages (
      id INTEGER PRIMARY KEY,
      role TEXT,
      content TEXT,
      created_at TEXT,
      conversation_id TEXT,
      model TEXT
    )`);
    db.prepare(
      `INSERT INTO messages (role, content, created_at, conversation_id, model)
       VALUES (?, ?, ?, ?, ?)`,
    ).run("user", "How do I export logs?", "2026-03-01T10:00:00.000Z", "conv-1", "gpt-4o");
    db.prepare(
      `INSERT INTO messages (role, content, created_at, conversation_id, model)
       VALUES (?, ?, ?, ?, ?)`,
    ).run("assistant", "Use wevtutil or the Event Viewer.", "2026-03-01T10:00:05.000Z", "conv-1", "gpt-4o");
    db.close();
    sqliteAvailable = true;
  } catch {
    sqliteAvailable = false;
  }
});

test("parseChatgptTimestamp handles ISO and unix forms", () => {
  const iso = parseChatgptTimestamp("2026-02-27T00:52:01.958224Z");
  assert.ok(iso);
  const sec = parseChatgptTimestamp("1772153778");
  assert.ok(sec);
  assert.equal(parseChatgptTimestamp(""), null);
});

test("parseConversationItem builds a conversation metadata row", () => {
  const row = parseConversationItem({
    id: "69a0eaa4-2f10-832a-879b-2f990c336843",
    title: "Test chat",
    create_time: "2026-02-27T00:52:01.958224Z",
  }, "test.ldb", {});
  assert.ok(row);
  assert.equal(row.Role, "conversation");
  assert.equal(row.Tool, "ChatGPT");
  assert.match(row.Description, /Conversation/);
});

test("extractFromLeveldbBytes finds items array in raw bytes", () => {
  const rows = [];
  const data = fs.readFileSync(path.join(FIXTURE_ROOT, "Local Storage/leveldb/000003.ldb"));
  extractFromLeveldbBytes(data, "fixture.ldb", {}, rows);
  assert.ok(rows.length >= 1);
  assert.match(rows[0].Summary, /logfile/i);
});

test("extractChatgptDir reads LevelDB metadata from fixture tree", async () => {
  const rows = await extractChatgptDir(FIXTURE_ROOT, { user: "alice" });
  assert.ok(rows.length >= 1);
  assert.equal(rows[0].User, "alice");
});

test("extractChatgptDir reads SQLite messages when better-sqlite3 is available", { skip: !sqliteAvailable && "better-sqlite3 not available" }, async () => {
  const rows = await extractChatgptDir(FIXTURE_ROOT, { user: "bob" });
  const msg = rows.find((r) => r.Role === "user" && r.Summary.includes("export logs"));
  assert.ok(msg, "sqlite user message present");
  assert.equal(msg.Model, "gpt-4o");
});

test("isChatgptAppDir recognizes fixture layout", () => {
  assert.ok(isChatgptAppDir(FIXTURE_ROOT));
  assert.ok(!isChatgptAppDir(__dirname));
});

test("detectEncryptedConversationBundles finds conversations-v2 files", () => {
  const fs = require("fs");
  const os = require("os");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cgpt-enc-"));
  try {
    fs.writeFileSync(path.join(tmp, "conversations-v2-deadbeef"), Buffer.from([0]));
    const hits = detectEncryptedConversationBundles(tmp);
    assert.equal(hits.length, 1);
    const notice = formatChatgptImportNotice(
      buildChatgptExtractionStats([], tmp),
    );
    assert.match(notice, /encrypted conversations-v2/i);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ChatGPT conversations-v3 bundles are discovered and inventoried as opaque evidence", async () => {
  const os = require("node:os");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cgpt-v3-"));
  const projectId = "project-g-p-test";
  const bundleDir = path.join(tmp, projectId, "conversations-v3-account-test");
  const bundlePath = path.join(bundleDir, "11111111-2222-4333-8444-555555555555.data");
  fs.mkdirSync(bundleDir, { recursive: true });
  fs.writeFileSync(bundlePath, Buffer.from([0x23, 0x98, 0x1f, 0x73]));

  try {
    assert.equal(isChatgptAppDirQuick(tmp), true);
    assert.equal(isChatgptAppDir(tmp), true);
    const bundles = detectConversationBundles(tmp);
    assert.equal(bundles.length, 1);
    assert.equal(bundles[0].version, 3);
    assert.equal(bundles[0].projectId, projectId);
    assert.equal(detectEncryptedConversationBundles(tmp).length, 0);

    const rows = await extractChatgptDir(tmp, { user: "analyst" });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].RecordType, "opaque_bundle");
    assert.equal(rows[0].SessionId, "11111111-2222-4333-8444-555555555555");
    assert.equal(rows[0].Workspace, projectId);
    assert.equal(rows[0].User, "analyst");
    assert.equal(rows._chatgptStats.v3BundleCount, 1);
    assert.match(formatChatgptImportNotice(rows._chatgptStats), /opaque conversations-v3/i);

    const direct = await extractChatgptPath(bundlePath);
    assert.equal(direct.length, 1);
    assert.equal(direct[0].SourceFile, bundlePath);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ChatGPT discovery excludes unrelated TipKit SQLite state", () => {
  assert.equal(isChatgptDataFile("/tmp/com.openai.chat/.tipkit/tips-store.db"), false);
});

test("buildChatgptExtractionStats distinguishes metadata-only imports", () => {
  const metaOnly = buildChatgptExtractionStats([
    { RecordType: "conversation", Role: "conversation" },
  ]);
  assert.equal(metaOnly.conversationCount, 1);
  assert.equal(metaOnly.messageCount, 0);
  assert.equal(metaOnly.leveldbMetadataOnly, true);

  const withMsgs = buildChatgptExtractionStats([
    { RecordType: "conversation", Role: "conversation" },
    { RecordType: "message", Role: "user" },
  ]);
  assert.equal(withMsgs.messageCount, 1);
  assert.equal(withMsgs.leveldbMetadataOnly, false);
});

test("formatChatgptImportNotice reports partial bodies with encrypted bundles", () => {
  const stats = {
    conversationCount: 2,
    messageCount: 5,
    leveldbMetadataOnly: false,
    encryptedBundleCount: 1,
  };
  const notice = formatChatgptImportNotice(stats);
  assert.match(notice, /5 message/);
  assert.match(notice, /encrypted conversations-v2/i);
  assert.match(notice, /not decrypted/i);
});

test("extractChatgptPath accepts a single sqlite file", { skip: !sqliteAvailable && "better-sqlite3 not available" }, async () => {
  const rows = await extractChatgptPath(FIXTURE_DB, { user: "u1" });
  assert.equal(rows.length, 2);
});
