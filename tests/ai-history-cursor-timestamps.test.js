"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("fs");
const os = require("os");

const { readTranscriptFile } = require("../electron/parsers/ai-history/cursor");

test("readTranscriptFile uses embedded createdAt instead of file mtime spread", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-ts-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });

  const transcript = path.join(tmp, "agent-transcripts", "sess-1", "sess-1.jsonl");
  fs.mkdirSync(path.dirname(transcript), { recursive: true });
  const lines = [
    JSON.stringify({
      role: "user",
      createdAt: 1704067200000,
      message: { content: [{ type: "text", text: "Question with timestamp" }] },
    }),
    JSON.stringify({
      role: "assistant",
      createdAt: 1704067260000,
      message: { content: [{ type: "text", text: "Answer with timestamp" }] },
    }),
  ];
  fs.writeFileSync(transcript, `${lines.join("\n")}\n`, "utf8");

  const rows = await readTranscriptFile(transcript, { user: "u" });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].Timestamp, "2024-01-01 00:00:00");
  assert.equal(rows[1].Timestamp, "2024-01-01 00:01:00");
  assert.ok(!rows._cursorSyntheticTimestamps);
});
