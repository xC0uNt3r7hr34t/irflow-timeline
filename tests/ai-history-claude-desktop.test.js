"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  listCoworkArtifactFiles,
  countClaudeDesktopExtractFiles,
  parseDesktopMetadataFile,
  normalizeCliSessionId,
  resolveClaudeProjectsDir,
  extractClaudeDesktopDir,
  buildClaudeDesktopImportNotice,
} = require("../electron/parsers/ai-history/claude-desktop");
const { extractClaudeDir } = require("../electron/parsers/ai-history/claude-code");

const FIXTURE_DESKTOP = path.join(__dirname, "fixtures/ai-history/claude-desktop/claude-code-sessions");
const FIXTURE_ROOT = path.join(__dirname, "fixtures/ai-history/claude-desktop");

test("normalizeCliSessionId reads cliSessionId and local_ sessionId fallback", () => {
  assert.equal(normalizeCliSessionId({ cliSessionId: "sess-abc" }), "sess-abc");
  assert.equal(normalizeCliSessionId({ sessionId: "local_uuid-here" }), "uuid-here");
});

test("resolveClaudeProjectsDir finds sibling .claude/projects", () => {
  const projects = resolveClaudeProjectsDir(FIXTURE_DESKTOP);
  assert.ok(projects);
  assert.match(projects, /[\\/]\.claude[\\/]projects$/);
});

test("extractClaudeDesktopDir links metadata to JSONL transcripts", async () => {
  const { rows, stats } = await extractClaudeDesktopDir(FIXTURE_DESKTOP, { user: "testuser" });
  assert.ok(stats.linkedTranscripts >= 1);
  assert.ok(rows.length >= 2);
  const userRow = rows.find((r) => r.MessageId === "msg-user-1");
  assert.ok(userRow);
  assert.equal(userRow.User, "testuser");
});

test("extractClaudeDir routes Desktop sessions root to desktop extractor", async () => {
  const rows = await extractClaudeDir(FIXTURE_DESKTOP, { user: "u1" });
  assert.ok(rows._claudeDesktopStats);
  assert.ok(rows.length >= 2);
});

test("buildClaudeDesktopImportNotice warns on dangling cliSessionId", () => {
  const msg = buildClaudeDesktopImportNotice({ metadataFiles: 2, linkedTranscripts: 0, danglingCli: 2 });
  assert.match(msg, /missing/i);
});

test("extractClaudeDesktopDir recursively parses isolated Cowork transcripts and audit trails", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cowork-"));
  const desktopRoot = path.join(tmp, "local-agent-mode-sessions");
  const container = path.join(desktopRoot, "account", "organization");
  const sessionDir = path.join(container, "local_demo");
  const projectsDir = path.join(sessionDir, ".claude", "projects", "demo");
  fs.mkdirSync(projectsDir, { recursive: true });
  fs.writeFileSync(path.join(container, "local_demo.json"), JSON.stringify({
    sessionId: "local_demo",
    cliSessionId: "cli-demo",
    cwd: "/cowork/project",
    model: "claude-test",
    createdAt: 1785067200000,
    lastActivityAt: 1785067260000,
    title: "Cowork investigation",
  }));
  fs.writeFileSync(path.join(projectsDir, "cli-demo.jsonl"), `${JSON.stringify({
    type: "assistant",
    timestamp: "2026-07-26T12:00:01.000Z",
    sessionId: "cli-demo",
    uuid: "cowork-message",
    message: { role: "assistant", content: [{ type: "text", text: "isolated transcript row" }] },
  })}\n`);
  fs.writeFileSync(path.join(sessionDir, "audit.jsonl"), `${JSON.stringify({
    type: "user",
    session_id: "local_demo",
    uuid: "audit-message",
    parent_tool_use_id: null,
    _audit_timestamp: "2026-07-26T12:00:00.000Z",
    message: { role: "user", content: "audited Cowork prompt" },
  })}\n`);
  fs.writeFileSync(path.join(sessionDir, ".audit-key"), "test-audit-key");

  try {
    const artifacts = listCoworkArtifactFiles(desktopRoot);
    assert.equal(artifacts.transcriptFiles.length, 1);
    assert.equal(artifacts.auditFiles.length, 1);
    assert.equal(artifacts.auditKeyFiles.length, 1);
    assert.equal(countClaudeDesktopExtractFiles(desktopRoot), 3);

    const { rows, stats } = await extractClaudeDesktopDir(desktopRoot, { user: "analyst" });
    assert.equal(stats.nestedTranscripts, 1);
    assert.equal(stats.auditFiles, 1);
    assert.equal(stats.auditKeys, 1);
    assert.equal(stats.linkedTranscripts, 1);
    assert.ok(rows.some((row) => row.MessageId === "cowork-message"));
    const auditRow = rows.find((row) => row.MessageId === "audit-message");
    assert.ok(auditRow);
    assert.equal(auditRow.RecordType, "audit-user");
    assert.equal(auditRow.SessionId, "local_demo");
    assert.equal(auditRow.FullText, "audited Cowork prompt");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
