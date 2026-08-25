// Tests for the shared NTFS path classifier (electron/utils/path-class.js).
// Pure logic — runs under plain `node --test` (no SQLite binding needed).

const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyPath, isServicingChurn, servicingChurnSqlClause } = require("../electron/utils/path-class");

test("classifyPath: coarse provenance classes (MFT '.\\Path' form, case/separator-insensitive)", () => {
  assert.equal(classifyPath(".\\Windows\\WinSxS\\amd64_foo"), "servicing-churn");
  assert.equal(classifyPath(".\\Windows\\SoftwareDistribution\\Download\\x"), "servicing-churn");
  assert.equal(classifyPath(".\\Windows\\System32\\drivers"), "system", "System32 is system, NOT churn");
  assert.equal(classifyPath(".\\Windows\\Tasks"), "system");
  assert.equal(classifyPath(".\\Program Files\\Vendor\\app"), "program-files");
  assert.equal(classifyPath(".\\Program Files (x86)\\Vendor"), "program-files");
  assert.equal(classifyPath(".\\Users\\bob\\Documents"), "user-profile");
  assert.equal(classifyPath(".\\Users\\bob\\AppData\\Local\\Temp"), "user-profile");
  assert.equal(classifyPath("D:\\staging\\tmp"), "temp-cache");
  assert.equal(classifyPath(".\\Recovery\\stuff"), "other");
  assert.equal(classifyPath(""), "other");
  assert.equal(classifyPath(null), "other");
  // forward-slash form normalizes too
  assert.equal(classifyPath("C:/Windows/WinSxS/x"), "servicing-churn");
  // C:\Windows\Temp is NOT servicing-churn (attacker staging) — tagged 'system', never down-weighted
  assert.equal(classifyPath(".\\Windows\\Temp\\evil.exe"), "system");
  // 'system' is anchored to the volume root — an interior 'windows' dir is not mislabeled
  assert.equal(classifyPath(".\\inetpub\\wwwroot\\windows\\images"), "other", "interior windows dir not 'system'");
});

test("isServicingChurn: narrow to genuinely noisy update/servicing/cache trees", () => {
  assert.equal(isServicingChurn(".\\Windows\\WinSxS\\x"), true);
  assert.equal(isServicingChurn(".\\Windows\\SoftwareDistribution\\y"), true);
  assert.equal(isServicingChurn(".\\Windows\\Installer\\z.msi"), true);
  assert.equal(isServicingChurn(".\\Users\\bob\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE"), true);
  // newly-added benign high-volume servicing trees
  assert.equal(isServicingChurn(".\\Windows\\System32\\DriverStore\\FileRepository\\x"), true);
  assert.equal(isServicingChurn(".\\Windows\\Microsoft.NET\\Framework64\\v4.0\\assembly\\NativeImages_x\\y"), true);
  assert.equal(isServicingChurn(".\\Windows\\Panther\\x"), true);
  assert.equal(isServicingChurn(".\\ProgramData\\Package Cache\\{guid}\\x"), true);
  // must NOT dampen these — attackers use them (carve-outs)
  assert.equal(isServicingChurn(".\\Windows\\System32\\evil.dll"), false, "System32 not dampened");
  assert.equal(isServicingChurn(".\\Windows\\Temp\\dropper.exe"), false, "C:\\Windows\\Temp not dampened (attacker staging)");
  assert.equal(isServicingChurn(".\\$Recycle.Bin\\S-1-5-21\\x"), false);
  assert.equal(isServicingChurn(".\\Users\\bob\\AppData\\Local\\Temp\\x.exe"), false);
  assert.equal(isServicingChurn(".\\Users\\bob\\Downloads"), false);
  assert.equal(isServicingChurn(".\\Program Files\\app"), false);
  assert.equal(isServicingChurn(""), false);
});

test("servicingChurnSqlClause: builds an OR of LOWER(col) LIKE patterns; '0' when no column", () => {
  assert.equal(servicingChurnSqlClause(null), "0");
  assert.equal(servicingChurnSqlClause(""), "0");
  const sql = servicingChurnSqlClause("c3");
  assert.match(sql, /^\(/);
  assert.match(sql, /LOWER\(c3\) LIKE '%\\windows\\winsxs%'/);
  assert.ok(sql.includes(" OR "), "multiple patterns joined with OR");
});
