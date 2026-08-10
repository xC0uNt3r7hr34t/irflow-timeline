"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  supplementWindsurfCascadePb,
  buildWindsurfCascadeNotice,
} = require("../electron/parsers/ai-history/windsurf-cascade");

test("supplementWindsurfCascadePb inventories Cascade .pb files", () => {
  const userDir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ws-cascade-"));
  const cascadeDir = path.join(userDir, "globalStorage", "windsurf.cascade", "threads");
  fs.mkdirSync(cascadeDir, { recursive: true });
  fs.writeFileSync(path.join(cascadeDir, "thread-1.pb"), Buffer.from([0x08, 0x01]));

  const { rows, stats } = supplementWindsurfCascadePb(userDir, { user: "u1", host: "h1" });
  assert.equal(stats?.pbCount, 1);
  assert.equal(rows[0].RecordType, "cascade_pb");
  assert.match(rows[0].Timestamp, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  assert.match(buildWindsurfCascadeNotice(stats), /protobuf bodies not decoded/);
  fs.rmSync(userDir, { recursive: true, force: true });
});
