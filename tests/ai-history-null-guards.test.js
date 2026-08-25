"use strict";

// Regression guards: a JSON document/line/element that parses to `null` or a primitive must be
// skipped, never dereferenced. These crash classes lived on the single-file import paths (no
// outer try/catch), so a subject could abort an import or hide a transcript with one `null`.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { extractGeminiSessionFile } = require("../electron/parsers/ai-history/gemini-cli");
const { extractContinuePath } = require("../electron/parsers/ai-history/continue");
const { extractCodexDir } = require("../electron/parsers/ai-history/codex");
const { buildSnapshotFromJsonlLines } = require("../electron/parsers/ai-history/copilot");

function tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-nullguard-"));
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  return { dir, p };
}

test("gemini: a session file that is literal `null` returns [] (no crash)", () => {
  const { dir, p } = tmpFile("session-null.json", "null");
  try {
    assert.deepEqual(extractGeminiSessionFile(p, {}), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("gemini: a null message element is skipped, valid messages survive", () => {
  const { dir, p } = tmpFile("session.json", JSON.stringify({
    sessionId: "s1",
    messages: [null, 42, { type: "user", content: "hello there", timestamp: "2024-01-01T00:00:00Z" }],
  }));
  try {
    const rows = extractGeminiSessionFile(p, {});
    assert.equal(rows.length, 1);
    assert.equal(rows[0].Summary, "hello there");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("continue: a null history element is skipped, valid turns survive", async () => {
  const { dir, p } = tmpFile("sess.json", JSON.stringify({
    sessionId: "c1",
    dateCreated: "2024-02-02T00:00:00Z",
    history: [
      null,
      "just a string",
      { message: { role: "user", content: "fix the bug" } },
    ],
  }));
  try {
    const rows = await extractContinuePath(p, {});
    assert.equal(rows.length, 1);
    assert.equal(rows[0].Role, "user");
    assert.match(rows[0].Summary, /fix the bug/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("codex: a null line in history.jsonl is skipped, surrounding rows survive (not discarded)", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-"));
  const root = path.join(dir, ".codex");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "history.jsonl"), [
    JSON.stringify({ session_id: "s1", ts: 1700000000, text: "first prompt" }),
    "null",
    JSON.stringify({ session_id: "s1", ts: 1700000100, text: "second prompt" }),
  ].join("\n") + "\n");
  try {
    const rows = await extractCodexDir(root, {});
    const texts = rows.map((r) => r.Summary).sort();
    assert.deepEqual(texts, ["first prompt", "second prompt"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("copilot: buildSnapshotFromJsonlLines tolerates null/primitive lines", () => {
  const snapshot = buildSnapshotFromJsonlLines([
    "null",
    "42",
    '"a bare string"',
    JSON.stringify({ kind: 2, v: { requestId: "r1", message: "hello", response: "hi" } }),
  ]);
  assert.ok(snapshot, "valid request still produces a snapshot");
  assert.equal(snapshot.requests.length, 1);
});
