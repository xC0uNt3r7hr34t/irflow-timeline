"use strict";

// Tests for per-user / per-host attribution derived from artifact source paths.

const test = require("node:test");
const assert = require("node:assert/strict");

const { deriveUser, deriveHost, annotateCsvUserHost } = require("../electron/parsers/path-attribution");
const { parseCSVLine, scanCSVRecords } = require("../electron/parsers/csv");

// All annotate tests share the same two injected csv helpers.
const annotate = (csv, root) => annotateCsvUserHost(csv, root, parseCSVLine, scanCSVRecords);

test("deriveUser extracts the profile name from a Users path", () => {
  assert.equal(deriveUser("/cases/WS01/C/Users/jsmith/AppData/Roaming/x.lnk"), "jsmith");
  assert.equal(deriveUser("X:\\Users\\Administrator\\NTUSER.DAT"), "Administrator");
  assert.equal(deriveUser("/cases/C/Documents and Settings/bob/x"), "bob");
  assert.equal(deriveUser("/cases/WS01/C/Windows/Prefetch/CALC-1.pf"), ""); // machine-level
  assert.equal(deriveUser(""), "");
});

test("deriveHost: host folder vs single-host root vs file-in-root", () => {
  assert.equal(deriveHost("/cases/WS01/C/Users/jsmith/x.lnk", "/cases"), "WS01"); // <root>/HOST/C/...
  assert.equal(deriveHost("/cases/WS01/C/Users/jsmith/x.lnk", "/cases/WS01"), "WS01"); // <root>/C/... -> root name
  assert.equal(deriveHost("/cases/host7/C%3A/Users/a/x", "/cases"), "host7"); // url-encoded drive
  assert.equal(deriveHost("/cases/WS01/Users/a/x", "/cases"), "WS01"); // no drive folder, Users is not a host
  assert.equal(deriveHost("/tmp/NTUSER.DAT", "/tmp"), "tmp"); // file directly in root -> root name
  assert.equal(deriveHost("/x/y", ""), "");
  // Empty source path must NOT fall through to path.relative(root, "") (which resolves "" to cwd
  // and yields a "../.." artifact); it falls back to the single-host root name.
  assert.equal(deriveHost("", "/cases/WS01"), "WS01");
  assert.equal(deriveHost(undefined, "/cases/triage/HOST01"), "HOST01");
  assert.equal(deriveHost("", ""), "");
});

test("annotateCsvUserHost appends User,Host from the SourceFile column", () => {
  const csv = [
    "SourceFile,TargetIDAbsolutePath,DriveType",
    "/cases/WS01/C/Users/jsmith/Recent/a.lnk,C:\\evil.exe,Fixed",
    "/cases/WS01/C/Windows/x.lnk,C:\\b.exe,Fixed",
  ].join("\n");
  const out = annotate(csv, "/cases").split("\n");
  assert.equal(out[0], "SourceFile,TargetIDAbsolutePath,DriveType,User,Host");
  assert.match(out[1], /,jsmith,WS01$/);
  assert.match(out[2], /,,WS01$/); // no Users segment -> empty user, host still resolved
});

test("annotateCsvUserHost handles SourceFilename + BOM, and leaves a no-source CSV unchanged", () => {
  const BOM = String.fromCharCode(0xfeff);
  const pf = BOM + "SourceFilename,ExecutableName\n/cases/WS01/C/Windows/Prefetch/CALC-1.pf,CALC.EXE";
  const out = annotate(pf, "/cases").split("\n");
  assert.ok(out[0].endsWith(",User,Host"));
  assert.equal(out[0].charCodeAt(0), 0xfeff, "BOM preserved on the header");
  assert.match(out[1], /,,WS01$/);
  assert.equal(annotate("a,b,c\n1,2,3", "/cases"), "a,b,c\n1,2,3"); // no SourceFile -> unchanged
});

test("annotateCsvUserHost keeps an embedded-newline record intact (quote-aware, not line-split)", () => {
  // LNK Arguments with an embedded newline — a naive \n split would cut this record in two and
  // inject ,User,Host mid-record, corrupting structure and misattributing the row.
  const csv =
    "SourceFile,Arguments,DriveType\n" +
    '/cases/WS01/C/Users/jsmith/Recent/a.lnk,"-cmd one\ntwo",Fixed\n' +
    "/cases/WS01/C/Users/bob/Recent/b.lnk,plain,Fixed\n";
  const annotated = annotate(csv, "/cases");

  // Re-parse the OUTPUT the way the worker/importer does: by logical record, then by header name.
  const recs = [];
  const tail = scanCSVRecords(annotated, (r) => recs.push(r));
  if (tail) recs.push(tail);
  const header = parseCSVLine(recs[0]);
  assert.deepEqual(header.slice(-2), ["User", "Host"]);
  assert.equal(recs.length, 3, "still 3 records (header + 2 data), embedded newline did NOT add a record");

  const row1 = parseCSVLine(recs[1]);
  assert.equal(row1.length, header.length, "data row width matches header width");
  assert.equal(row1[header.indexOf("Arguments")], "-cmd one\ntwo", "embedded newline preserved in its cell");
  assert.equal(row1[header.indexOf("User")], "jsmith");
  assert.equal(row1[header.indexOf("Host")], "WS01");
  assert.equal(parseCSVLine(recs[2])[header.indexOf("User")], "bob");
});

test("annotateCsvUserHost pads a short row so User/Host read back on their own columns", () => {
  // A malformed/truncated row with fewer cells than the header must still expose User/Host by
  // name to the downstream reader (no column-count check previously → silent misattribution).
  const csv =
    "SourceFile,TargetIDAbsolutePath,DriveType\n" +
    "/cases/WS01/C/Users/jsmith/Recent/a.lnk\n"; // only 1 of 3 columns present
  const annotated = annotate(csv, "/cases");
  const recs = [];
  const tail = scanCSVRecords(annotated, (r) => recs.push(r));
  if (tail) recs.push(tail);
  const header = parseCSVLine(recs[0]);
  const row = parseCSVLine(recs[1]);
  assert.equal(row.length, header.length, "short row padded up to header width");
  assert.equal(row[header.indexOf("User")], "jsmith", "User still aligns on its own column");
  assert.equal(row[header.indexOf("Host")], "WS01");
  assert.equal(row[header.indexOf("TargetIDAbsolutePath")], "", "missing middle columns are empty, not User/Host");
});

test("annotateCsvUserHost preserves trailing-newline state", () => {
  const withNl = "SourceFile,X\n/cases/WS01/C/Users/a/x.lnk,1\n";
  const noNl = "SourceFile,X\n/cases/WS01/C/Users/a/x.lnk,1";
  assert.ok(annotate(withNl, "/cases").endsWith("\n"), "trailing newline kept when present");
  assert.ok(!annotate(noNl, "/cases").endsWith("\n"), "no trailing newline added when absent");
});
