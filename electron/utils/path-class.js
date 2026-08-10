// Shared NTFS path classifier for DFIR analyzers.
//
// Two jobs:
//  1. classifyPath() — coarse provenance class for display/triage.
//  2. isServicingChurn() / servicingChurnSqlClause() — identify the high-volume Windows
//     OS-update / servicing locations that should be DOWN-WEIGHTED when ranking suspicious
//     activity bursts (Windows Update, WinSxS servicing, AV definition refresh, browser cache).
//
// Deliberately NARROW: the churn set is the genuinely noisy update/servicing/cache trees, NOT
// C:\Windows\System32 proper — attackers drop into System32 (DLL hijack, service binaries), so
// dampening all of System32 would hide real activity. Paths are matched case-insensitively and
// separator-agnostically (the MFT parser emits ".\Windows\WinSxS\..." with backslashes).

// Substrings (lowercase, backslash-separated) that mark OS/servicing/cache churn.
//
// CARVE-OUTS (deliberately ABSENT): C:\Windows\System32, C:\Windows\Temp, C:\$Recycle.Bin, and
// C:\Users\…\AppData\Local\Temp. These are high-volume but ALSO top adversary drop/staging
// locations (service binaries, droppers, ransomware staging — MITRE T1074/T1570). Dampening them
// would hide the very bursts an analyst needs surfaced.
const SERVICING_CHURN = [
  "\\windows\\winsxs",
  "\\windows\\softwaredistribution",
  "\\windows\\servicing",
  "\\windows\\installer",
  "\\windows\\inf",
  "\\windows\\catroot2",
  "\\windows\\prefetch",
  "\\windows\\logs\\cbs",
  "\\windows\\panther",
  "\\windows\\systemtemp",
  "\\windows\\system32\\driverstore",
  "\\assembly\\nativeimages",
  "\\temporary asp.net files",
  "\\programdata\\package cache",
  "\\programdata\\microsoft\\windows defender",
  "\\programdata\\microsoft\\windows\\windows defender",
  "\\appdata\\local\\microsoft\\windows\\inetcache",
  "\\appdata\\local\\microsoft\\windows\\webcache",
  "\\appdata\\local\\microsoft\\windows\\explorer",
  "\\appdata\\local\\google\\chrome\\user data\\default\\cache",
  "\\appdata\\local\\microsoft\\edge\\user data\\default\\cache",
  "\\appdata\\local\\packages",
];

function _norm(p) {
  return String(p || "").toLowerCase().replace(/\//g, "\\");
}

/** True if a path is a high-volume OS/servicing/cache location safe to down-weight. */
function isServicingChurn(p) {
  const s = _norm(p);
  if (!s) return false;
  return SERVICING_CHURN.some((x) => s.includes(x));
}

/**
 * Coarse provenance class:
 *   'servicing-churn' | 'system' | 'program-files' | 'user-profile' | 'temp-cache' | 'other'
 * Order matters — servicing-churn is a subset of system/user trees and is checked first.
 */
function classifyPath(p) {
  const s = _norm(p);
  if (!s) return "other";
  if (isServicingChurn(s)) return "servicing-churn";
  // Anchor \windows\ to the volume root (".\" MFT form or a drive letter) so an interior directory
  // literally named "windows" (e.g. a web root or backup tree) isn't mislabeled 'system'.
  if (/^(\.|[a-z]:)?\\windows\\/.test(s)) return "system";
  if (/\\program files( \(x86\))?\\/.test(s)) return "program-files";
  if (/\\users\\[^\\]+/.test(s)) return "user-profile";
  if (/\\(temp|tmp)(\\|$)/.test(s)) return "temp-cache";
  return "other";
}

/**
 * Build a SQLite boolean expression that matches servicing-churn paths for a given (already-safe)
 * column identifier. Returns "0" when no column is supplied so callers can interpolate it
 * unconditionally. Patterns are constants (no user input); single quotes are escaped defensively.
 */
function servicingChurnSqlClause(colExpr) {
  if (!colExpr) return "0";
  const conds = SERVICING_CHURN.map((x) => `LOWER(${colExpr}) LIKE '%${x.replace(/'/g, "''")}%'`);
  return "(" + conds.join(" OR ") + ")";
}

module.exports = { classifyPath, isServicingChurn, servicingChurnSqlClause, SERVICING_CHURN };
