const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const electronRoot = path.join(__dirname, "..", "electron");

function listJsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listJsFiles(full));
    else if (entry.name.endsWith(".js")) out.push(full);
  }
  return out;
}

/** Extract the balanced `showOpenDialog( ... )` argument text for every call in `source`. */
function openDialogCalls(source) {
  const calls = [];
  const needle = "showOpenDialog(";
  let index = source.indexOf(needle);
  while (index !== -1) {
    let depth = 0;
    let end = index + needle.length - 1;
    for (let i = index + needle.length - 1; i < source.length; i++) {
      const char = source[i];
      if (char === "(") depth++;
      else if (char === ")") {
        depth--;
        if (depth === 0) { end = i; break; }
      }
    }
    calls.push(source.slice(index, end + 1));
    index = source.indexOf(needle, end);
  }
  return calls;
}

// Electron cannot show a combined file+directory dialog on Windows/Linux: it silently
// renders a folder picker and ignores `filters`, which is exactly the "I can't choose a
// file type" bug. Any call that asks for both must declare which mode wins off-macOS.
test("every file+directory open dialog declares a platform preference", () => {
  const offenders = [];
  for (const file of listJsFiles(electronRoot)) {
    for (const call of openDialogCalls(fs.readFileSync(file, "utf8"))) {
      const wantsBoth = call.includes('"openFile"') && call.includes('"openDirectory"');
      if (!wantsBoth) continue;
      if (!/\bprefer:/.test(call)) offenders.push(path.relative(electronRoot, file));
    }
  }
  assert.deepEqual(offenders, [], `combined file+directory dialogs missing a "prefer" option: ${offenders.join(", ")}`);
});

test("combined open dialogs go through openDialogOptions", () => {
  const offenders = [];
  for (const file of listJsFiles(electronRoot)) {
    for (const call of openDialogCalls(fs.readFileSync(file, "utf8"))) {
      const wantsBoth = call.includes('"openFile"') && call.includes('"openDirectory"');
      if (wantsBoth && !call.includes("openDialogOptions(")) {
        offenders.push(path.relative(electronRoot, file));
      }
    }
  }
  assert.deepEqual(offenders, [], `dialogs bypassing openDialogOptions: ${offenders.join(", ")}`);
});
