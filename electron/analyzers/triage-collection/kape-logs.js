/**
 * kape-logs.js — read provenance out of the logs KAPE drops beside a collection.
 *
 * KAPE writes `<timestamp>_ConsoleLog.txt` (and `_CopyLog.csv` / `_SkipLog.csv.csv`) into
 * the target destination. Two lines of the console log carry everything we need:
 *
 *   [... | INF] Command line:   --tsource F: --tdest ... --target !SANS_Triage ...
 *   [... | INF] System info: Machine name: RENZ-FORENSIC, 64-bit: true, User: dfir OS: "Windows10" (10.0.22631)
 *
 * The trap: that machine name is the box KAPE RAN ON, which is only the evidence host
 * when the collection was taken live. In the U42 demo package KAPE ran on the examiner
 * workstation `RENZ-FORENSIC` against a mounted image at `F:` — attributing the triage to
 * RENZ-FORENSIC would be wrong and would mis-key every finding.
 */

const fs = require("fs");
const path = require("path");

const CONSOLE_LOG_RE = /_ConsoleLog\.txt$/i;
const COPY_LOG_RE = /_CopyLog\.csv$/i;

/** Find KAPE's own logs directly inside `dir` (they are never nested). */
function findKapeLogs(dir) {
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return { consoleLog: null, copyLog: null }; }
  let consoleLog = null, copyLog = null;
  for (const e of entries) {
    if (!e.isFile()) continue;
    if (!consoleLog && CONSOLE_LOG_RE.test(e.name)) consoleLog = path.join(dir, e.name);
    if (!copyLog && COPY_LOG_RE.test(e.name)) copyLog = path.join(dir, e.name);
  }
  return { consoleLog, copyLog };
}

/**
 * Parse the provenance fields out of a KAPE console log.
 *
 * Reads only the head of the file — the lines we want are always in the first few.
 *
 * @returns {{machineName, tsource, tdest, msource, mdest, targets, modules, os, user, liveCollection}|null}
 */
function parseConsoleLog(filePath) {
  let head = "";
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(8192);
    const bytes = fs.readSync(fd, buf, 0, buf.length, 0);
    head = buf.toString("utf8", 0, bytes);
  } catch {
    return null;
  } finally {
    if (fd != null) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
  if (!head) return null;

  const cmd = (head.match(/Command line:\s*(.+)/) || [])[1] || "";
  const sys = (head.match(/System info:\s*(.+)/) || [])[1] || "";

  const flag = (name) => {
    const m = cmd.match(new RegExp(`--${name}\\s+("[^"]+"|\\S+)`, "i"));
    return m ? m[1].replace(/^"|"$/g, "") : "";
  };

  const machineName = (sys.match(/Machine name:\s*([^,]+)/i) || [])[1]?.trim() || "";
  const os = (sys.match(/OS:\s*"([^"]+)"\s*(\([^)]*\))?/i) || []).slice(1).filter(Boolean).join(" ").trim();
  const user = (sys.match(/User:\s*([^\s]+)/i) || [])[1]?.trim() || "";
  const tsource = flag("tsource");

  return {
    machineName,
    tsource,
    tdest: flag("tdest"),
    msource: flag("msource"),
    mdest: flag("mdest"),
    targets: flag("target"),
    modules: flag("module"),
    os,
    user,
    // A live collection reads the running system drive. Anything else — a mounted image,
    // a shadow copy, an attached disk — means the machine name belongs to the examiner.
    liveCollection: isLiveSourceDrive(tsource),
  };
}

/**
 * True when `--tsource` looks like the running system drive.
 *
 * `C:` is the overwhelmingly common live case. A mounted image is given another letter
 * (`F:`, `E:`, …) or a path, so anything that is not C: is treated as not-live. That is
 * deliberately conservative: mis-labelling a live collection as an image costs us a
 * confidence tier, whereas the reverse attributes evidence to the wrong machine.
 */
function isLiveSourceDrive(tsource) {
  if (!tsource) return false;
  return /^C:\\?$/i.test(String(tsource).trim());
}

module.exports = { findKapeLogs, parseConsoleLog, isLiveSourceDrive };
