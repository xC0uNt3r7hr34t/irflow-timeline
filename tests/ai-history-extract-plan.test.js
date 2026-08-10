"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  isSubagentArtifactPath,
  filterSubagentPaths,
  filterSidechainRows,
} = require("../electron/parsers/ai-history/extract-plan");
const { listSessionJsonlFiles } = require("../electron/parsers/ai-history/claude-code");

test("isSubagentArtifactPath detects subagents folder segments", () => {
  assert.ok(isSubagentArtifactPath("/Users/x/.claude/projects/app/subagents/agent-1/session.jsonl"));
  assert.ok(isSubagentArtifactPath("C:\\Users\\x\\.claude\\projects\\app\\subagents\\sess.jsonl"));
  assert.ok(!isSubagentArtifactPath("/Users/x/.claude/projects/app/main/session.jsonl"));
});

test("listSessionJsonlFiles skips subagents when skipSubagents is default", () => {
  const projects = path.join(__dirname, "fixtures/ai-history/claude-subagents/.claude/projects/demo");
  const all = listSessionJsonlFiles(projects, { includeSubagents: true });
  const mainOnly = listSessionJsonlFiles(projects, {});
  assert.ok(all.length >= mainOnly.length);
  assert.ok(mainOnly.every((p) => !isSubagentArtifactPath(p)));
  assert.ok(all.some((p) => isSubagentArtifactPath(p)));
});

test("filterSubagentPaths removes subagent paths unless includeSubagents", () => {
  const paths = [
    "/a/projects/x/session.jsonl",
    "/a/projects/x/subagents/y/session.jsonl",
  ];
  assert.equal(filterSubagentPaths(paths, {}).length, 1);
  assert.equal(filterSubagentPaths(paths, { includeSubagents: true }).length, 2);
});

test("filterSidechainRows drops inline IsSidechain rows when subagents excluded", () => {
  const rows = [
    { IsSidechain: "true", Summary: "sub-agent turn" },
    { IsSidechain: "false", Summary: "main turn" },
    { IsSidechain: "", Summary: "unflagged" },
  ];
  // default (main only): inline sidechain row dropped
  assert.equal(filterSidechainRows(rows, {}).length, 2);
  assert.equal(filterSidechainRows(rows, { skipSubagents: true }).length, 2);
  // include subagents: everything kept (same array reference, preserves meta)
  assert.equal(filterSidechainRows(rows, { includeSubagents: true }), rows);
  assert.equal(filterSidechainRows(rows, { skipSubagents: false }), rows);
});
