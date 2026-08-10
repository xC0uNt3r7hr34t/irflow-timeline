const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { PathAuthorizer, isPathInside } = require("../electron/utils/path-authorizer");

function makeTempTree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tle-path-auth-"));
  const selected = path.join(root, "selected");
  const outside = path.join(root, "outside");
  fs.mkdirSync(selected);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(selected, "event.evtx"), "event");
  fs.writeFileSync(path.join(outside, "secret.evtx"), "secret");
  return { root, selected, outside };
}

test("path authorizer allows selected roots recursively and blocks siblings", () => {
  const { root, selected, outside } = makeTempTree();
  const authorizer = new PathAuthorizer();

  authorizer.authorize("scan-target", selected, { recursive: true });

  assert.equal(authorizer.isAuthorized("scan-target", selected), true);
  assert.equal(authorizer.isAuthorized("scan-target", path.join(selected, "event.evtx")), true);
  assert.equal(authorizer.isAuthorized("scan-target", outside), false);
  assert.equal(authorizer.isAuthorized("scan-target", path.join(outside, "secret.evtx")), false);

  fs.rmSync(root, { recursive: true, force: true });
});

test("path authorizer resolves symlinks before checking scope", () => {
  const { root, selected, outside } = makeTempTree();
  const authorizer = new PathAuthorizer();
  const escapeLink = path.join(selected, "escape");
  fs.symlinkSync(outside, escapeLink, "dir");

  authorizer.authorize("scan-target", selected, { recursive: true });

  assert.equal(authorizer.isAuthorized("scan-target", path.join(escapeLink, "secret.evtx")), false);

  fs.rmSync(root, { recursive: true, force: true });
});

test("path authorizer supports exact selected files", () => {
  const { root, selected } = makeTempTree();
  const authorizer = new PathAuthorizer();
  const selectedFile = path.join(selected, "event.evtx");
  const siblingFile = path.join(selected, "other.evtx");
  fs.writeFileSync(siblingFile, "other");

  authorizer.authorize("custom-rule-file", selectedFile, { recursive: false });

  assert.equal(authorizer.isAuthorized("custom-rule-file", selectedFile), true);
  assert.equal(authorizer.isAuthorized("custom-rule-file", siblingFile), false);

  fs.rmSync(root, { recursive: true, force: true });
});

test("path authorizer accepts any authorized scope from a scope list", () => {
  const { root, selected } = makeTempTree();
  const authorizer = new PathAuthorizer();
  const selectedFile = path.join(selected, "event.evtx");

  authorizer.authorize("hayabusa-rules-config", selectedFile, { recursive: false });

  assert.equal(authorizer.isAuthorized(["hayabusa-rules", "hayabusa-rules-config"], selectedFile), true);
  assert.equal(authorizer.assertAuthorized(["hayabusa-rules", "hayabusa-rules-config"], selectedFile), fs.realpathSync.native(selectedFile));

  fs.rmSync(root, { recursive: true, force: true });
});

test("path authorizer can re-authorize an existing persisted path", () => {
  const { root, selected } = makeTempTree();
  const authorizer = new PathAuthorizer();
  const entry = authorizer.authorizeIfExists("geoip", selected, { recursive: true, label: "Saved GeoIP directory" });

  assert.equal(entry.label, "Saved GeoIP directory");
  assert.equal(authorizer.isAuthorized("geoip", path.join(selected, "event.evtx")), true);

  fs.rmSync(root, { recursive: true, force: true });
});

test("path containment helper treats prefix siblings as outside", () => {
  const root = path.join(os.tmpdir(), "scan");
  assert.equal(isPathInside(path.join(root, "child"), root), true);
  assert.equal(isPathInside(`${root}-sibling`, root), false);
});
