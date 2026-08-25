/**
 * host-attribution.js — decide which machine a triage collection came from.
 *
 * This matters more than it looks. Every finding, every cross-artifact join and every
 * multi-host graph is keyed on the host, and an artifact CSV (Amcache, ShimCache,
 * Prefetch) carries no host column at all — so if we get this wrong the whole collection
 * is mis-attributed and there is no downstream check that would catch it.
 *
 * Ladder, strongest first. Each answer carries how it was reached so the UI can show it
 * and the analyst can overrule.
 *
 *   1. KAPE console log, but ONLY for a live `--tsource C:` collection.
 *   2. The `Computer` field of a real event record.  (Authoritative for the EVTX itself.)
 *   3. A machine-name segment in the collection path (`<dest>\<MachineName>\C\...`).
 *   4. The folder name — a label, not an attribution.
 *
 * The trap that motivates rule 1: in the U42 demo package KAPE ran on the examiner
 * workstation `RENZ-FORENSIC` against a mounted image at `F:`. The console log says
 * RENZ-FORENSIC; the evidence host is a `sevenkingdoms.local` member. Trusting the log
 * unconditionally would attribute someone else's triage to the examiner's laptop.
 */

const path = require("path");
const { findKapeLogs, parseConsoleLog } = require("./kape-logs");

const CONFIDENCE = { high: "high", medium: "medium", low: "low", none: "none" };

/**
 * Read the dominant `Computer` value from an EVTX file.
 *
 * Deliberately NOT "the first record": records are ordered oldest-first, and a machine
 * that was renamed (or an imaged VM that has been reused) reports its historic name at
 * the head of the log. The U42 demo package is exactly this case — its TerminalServices
 * log opens with `USERUSE-BIOKEF0` while later records carry other names entirely.
 * Sampling and taking the most frequent value matches what kape-host.js already does for
 * imported tabs, and the returned distribution lets the caller flag a mixed collection.
 *
 * @returns {Promise<{computer: string, distribution: Array<[string, number]>, sampled: number}>}
 */
async function peekEvtxComputer(filePath, maxRecords = 200) {
  const counts = new Map();
  let sampled = 0;
  try {
    const { EvtxFile } = await import("@ts-evtx/core");
    const f = await EvtxFile.open(filePath);
    for (const rec of f.records()) {
      if (sampled >= maxRecords) break;
      let xml;
      try { xml = rec.renderXml(); } catch { continue; }
      if (!xml) continue;
      sampled++;
      const m = xml.match(/<Computer>([^<]+)<\/Computer>/i);
      const v = m && m[1].trim();
      if (v) counts.set(v, (counts.get(v) || 0) + 1);
    }
  } catch { /* unreadable / not an EVTX — fall through to the next rung */ }
  const distribution = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return { computer: distribution[0]?.[0] || "", distribution, sampled };
}

/**
 * A KAPE destination often nests the collection under the machine name
 * (`...\Triage\WKS-1042\C\Windows\...`). Look for the segment immediately above the
 * drive-letter directory.
 */
function hostFromPath(root, samplePath) {
  if (!samplePath) return "";
  const rel = path.relative(root, samplePath);
  if (!rel || rel.startsWith("..")) return "";
  const parts = rel.split(path.sep).filter(Boolean);
  // parts looks like [<maybe machine>, "C", "Windows", ...]; the drive dir is one char.
  const driveIdx = parts.findIndex((p) => /^[A-Za-z]\$?$/.test(p));
  if (driveIdx > 0) {
    const cand = parts[driveIdx - 1];
    if (/^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$/.test(cand)) return cand;
  }
  return "";
}

/**
 * Attribute a collection to a host.
 *
 * @param {string} root            the collection folder
 * @param {object} scan            result of scanTriageDir(root)
 * @param {object} [opts]
 * @param {boolean} [opts.peekEvtx=true]
 * @returns {Promise<{hostname, confidence, source, examinerMachine, kape, notes: string[]}>}
 */
async function attributeHost(root, scan, opts = {}) {
  const notes = [];
  const { consoleLog } = findKapeLogs(root);
  const kape = consoleLog ? parseConsoleLog(consoleLog) : null;

  let examinerMachine = "";
  if (kape?.machineName) {
    if (kape.liveCollection) {
      return {
        hostname: kape.machineName,
        confidence: CONFIDENCE.high,
        source: "kape-console-log",
        examinerMachine: "",
        kape,
        notes,
      };
    }
    // Not a live collection: the machine name is whoever ran KAPE, not the evidence.
    examinerMachine = kape.machineName;
    notes.push(
      `KAPE ran on ${kape.machineName} against ${kape.tsource || "a non-system drive"} — ` +
      "that is the examiner's machine, not the evidence host.",
    );
  }

  // Rung 2: real event records. Prefer the most authoritative populated log — highest LM
  // relevance, then LARGEST, so Security wins over a thin TerminalServices channel that
  // may predate a rename. Empty stubs yield no records and are skipped.
  if (opts.peekEvtx !== false) {
    const { isLikelyEmptyEvtx, lmEvtxRelevance } = require("../../parsers/triage");
    const candidates = (scan?.files?.evtx || [])
      .filter((f) => !isLikelyEmptyEvtx(f.size))
      .sort((a, b) => (lmEvtxRelevance(b.path) - lmEvtxRelevance(a.path)) || (b.size - a.size));
    for (const c of candidates.slice(0, 3)) {
      const { computer, distribution, sampled } = await peekEvtxComputer(c.path);
      if (!computer) continue;
      const share = sampled > 0 ? (distribution[0][1] / sampled) : 0;
      if (distribution.length > 1) {
        notes.push(
          `${path.basename(c.path)} reports ${distribution.length} different Computer values ` +
          `(${distribution.slice(0, 3).map(([n, k]) => `${n} x${k}`).join(", ")}) — the machine was ` +
          "renamed, or this collection spans more than one host.",
        );
      }
      return {
        hostname: computer,
        // A clearly dominant name is trustworthy; a split field is a judgement call.
        confidence: share >= 0.8 ? CONFIDENCE.high : CONFIDENCE.medium,
        source: "evtx-record",
        hostDistribution: distribution,
        examinerMachine,
        kape,
        notes,
      };
    }
  }

  // Rung 3: a machine-name segment in the collection layout.
  const sample = (scan?.paths?.evtx || scan?.paths?.registryHive || scan?.paths?.prefetch || [])[0];
  const fromPath = hostFromPath(root, sample);
  if (fromPath) {
    return { hostname: fromPath, confidence: CONFIDENCE.medium, source: "collection-path", examinerMachine, kape, notes };
  }

  // Rung 4: the folder name is a label only — never treat it as an attribution.
  notes.push("Host could not be determined from the collection; using the folder name as a label.");
  return {
    hostname: path.basename(root),
    confidence: CONFIDENCE.none,
    source: "folder-name",
    examinerMachine,
    kape,
    notes,
  };
}

module.exports = { attributeHost, peekEvtxComputer, hostFromPath, CONFIDENCE };
