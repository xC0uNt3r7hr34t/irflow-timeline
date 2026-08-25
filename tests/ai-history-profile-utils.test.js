"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  buildSessionIdColumnFilter,
  aiHistoryQueryIpcOptions,
  aiHistoryDetailCellValue,
  aiHistoryDetailPinnedFields,
  aiHistoryDetailHeaderOrder,
  buildWorkspaceCorrelationTargets,
  resolveAiWorkspacePath,
} = require("../src/utils/ai-history-profile.js");

test("buildSessionIdColumnFilter returns SessionId key", () => {
  assert.deepEqual(buildSessionIdColumnFilter("abc-123"), { SessionId: "abc-123" });
  assert.deepEqual(buildSessionIdColumnFilter(""), {});
});

test("aiHistoryQueryIpcOptions previews FullText instead of omitting it", () => {
  const opts = aiHistoryQueryIpcOptions();
  assert.ok(!opts.omitHeaders?.includes("FullText"));
  assert.equal(opts.truncateColumns.FullText, 240);
  assert.equal(opts.truncateColumns.ToolInput, 2048);
  assert.equal(opts.truncateColumns.ToolCommand, undefined, "exact commands are not shortened in the grid");
});

test("aiHistoryDetailPinnedFields surfaces RecordType tokens and sidechain", () => {
  const pinned = aiHistoryDetailPinnedFields({
    RecordType: "message",
    InputTokens: "1200",
    OutputTokens: "340",
    IsSidechain: "true",
    IsSidechainFalse: "ignored",
  });
  const fields = pinned.map((p) => p.field);
  assert.ok(fields.includes("RecordType"));
  assert.ok(fields.includes("Tokens"));
  assert.ok(fields.includes("IsSidechain"));
  assert.equal(pinned.find((p) => p.field === "Tokens").value, "in 1200 · out 340");
  assert.equal(aiHistoryDetailPinnedFields({ IsSidechain: "false" }).length, 0);
});

test("aiHistoryDetailPinnedFields surfaces exact tool commands and descriptions", () => {
  const pinned = aiHistoryDetailPinnedFields({
    InvokedTool: "Shell",
    ToolCommand: "ls -la \"/tmp/evidence\"",
    ToolDescription: "List evidence",
  });
  assert.deepEqual(
    pinned.map((item) => [item.label, item.value]),
    [
      ["Invoked tool", "Shell"],
      ["Exact command", "ls -la \"/tmp/evidence\""],
      ["Tool description", "List evidence"],
    ],
  );
});

test("aiHistoryDetailHeaderOrder puts pinned columns first", () => {
  const order = aiHistoryDetailHeaderOrder(["Summary", "Tool", "RecordType", "FullText"]);
  assert.deepEqual(order.slice(0, 2), ["RecordType", "Tool"]);
  assert.equal(order[order.length - 1], "FullText");
});

test("aiHistoryDetailCellValue prefers FullText for Summary", () => {
  const row = {
    Summary: "short…",
    FullText: "This is the complete message body with more than five hundred characters worth of investigative detail for the analyst reviewing AI assistant usage during an incident response engagement on the endpoint.",
    Description: "meta",
  };
  const detail = aiHistoryDetailCellValue(row, "Summary");
  assert.ok(detail.length > 100);
  assert.match(detail, /complete message body/);
});

test("resolveAiWorkspacePath decodes file URIs", () => {
  const p = resolveAiWorkspacePath("file:///tmp/demo-project", "");
  assert.match(p, /demo-project/);
});

test("buildWorkspaceCorrelationTargets ignores deferred execution-correlation tabs", () => {
  const tabs = [{
    id: "t1",
    name: "Execution Correlation (10)",
    dataReady: true,
    headers: ["Path", "CorrobCount", "Name"],
  }];
  const targets = buildWorkspaceCorrelationTargets(tabs, "C:\\Tools\\mimikatz.exe");
  assert.equal(targets.length, 0);
});
