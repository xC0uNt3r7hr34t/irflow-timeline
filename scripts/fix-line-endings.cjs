#!/usr/bin/env node
/**
 * Normalize shell scripts to LF line endings.
 * Fixes WSL/Git Bash errors like:
 *   $'\r': command not found
 *   set: pipefail: invalid option name
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const TARGETS = [
  "scripts/bundle-hayabusa.sh",
  "scripts/bundle-bmc-tools.sh",
  "build.sh",
];

let fixed = 0;
for (const rel of TARGETS) {
  const file = path.join(ROOT, rel);
  if (!fs.existsSync(file)) continue;
  const raw = fs.readFileSync(file, "utf8");
  const normalized = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized !== raw) {
    fs.writeFileSync(file, normalized, "utf8");
    console.log(`fixed: ${rel}`);
    fixed += 1;
  }
}
console.log(fixed ? `Normalized ${fixed} script(s) to LF.` : "All scripts already use LF line endings.");
