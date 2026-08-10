"use strict";

// Security regression: during forensic triage, Cursor composer extraction used to scan the LIVE
// analyst's own ~/Library/.../Cursor/User (via os.homedir), merging the examiner's private chats
// into the subject timeline and reading outside the authorized scope. User-data dirs must now be
// derived from the supplied (forensic) root so every read stays inside the seized collection.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  listCursorComposerDbs,
  cursorUserDataDirsForRoot,
  deriveUserHomeFromCursorRoot,
} = require("../electron/parsers/ai-history/cursor-composer");

test("composer DB discovery stays inside the forensic root (no live-home escape)", () => {
  const triage = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-triage-cursor-"));
  try {
    const home = path.join(triage, "Users", "jsmith");
    const cursorRoot = path.join(home, ".cursor");
    const userDir = path.join(home, "Library", "Application Support", "Cursor", "User");
    fs.mkdirSync(cursorRoot, { recursive: true });
    fs.mkdirSync(path.join(userDir, "globalStorage"), { recursive: true });
    fs.writeFileSync(path.join(userDir, "globalStorage", "state.vscdb"), "x");

    assert.equal(deriveUserHomeFromCursorRoot(cursorRoot), home);
    assert.deepEqual(cursorUserDataDirsForRoot(cursorRoot), [userDir], "derives the in-scope User dir");

    const dbs = listCursorComposerDbs(cursorRoot);
    assert.ok(
      dbs.includes(path.join(userDir, "globalStorage", "state.vscdb")),
      "finds the in-scope composer DB",
    );
    const root = path.resolve(triage);
    for (const p of dbs) {
      assert.ok(path.resolve(p).startsWith(root + path.sep), `every read must stay under the seized tree: ${p}`);
    }
  } finally {
    fs.rmSync(triage, { recursive: true, force: true });
  }
});

test("deriveUserHomeFromCursorRoot resolves a Cursor User-folder root too", () => {
  const home = path.join(path.sep, "triage", "Users", "bob");
  assert.equal(
    deriveUserHomeFromCursorRoot(path.join(home, "Library", "Application Support", "Cursor", "User")),
    home,
  );
  assert.equal(deriveUserHomeFromCursorRoot(path.join(home, ".config", "Cursor", "User")), home);
});
