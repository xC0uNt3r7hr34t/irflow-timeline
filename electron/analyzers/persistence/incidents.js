/**
 * analyzers/persistence/incidents.js — host identity + incident clustering
 *
 * Extracted from index.js so a MERGED result set (multiple tabs, and both EVTX and
 * registry evidence in one analysis) can be clustered as a single body of findings
 * rather than one incident list per source.
 *
 * An "incident" is one persistence artifact on one host: N raw rows that describe the
 * same thing collapse into one row of triage, keeping every underlying item attached.
 */

const { cleanWrappedField } = require("../evtx-utils");
const { canonicalizeKeyPath } = require("./registry-shapes");
const { parseTimestampMs } = require("../../utils/parse-timestamp");

const INCIDENT_GAP_MS = 3600000; // 60 min — beyond this, the same artifact is a new event
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Canonical host key. Windows logs the SAME machine three ways in one triage package —
 * "U42-TECH", "U42-TECH.sevenkingdoms.local" and "U42-TECH$" — and an exact-string compare
 * treats them as three different hosts, silently costing a finding its corroboration.
 * Reduce to the uppercased short name; leave IP literals alone, since their dots are not
 * a DNS suffix.
 */
function corrHost(value) {
  const s = cleanWrappedField(value).replace(/\$+$/, "").trim();
  if (!s) return "";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s) || s.includes(":")) return s.toUpperCase();
  return s.split(".")[0].toUpperCase();
}

// Some reasons are DAMPENERS / benign context the scorer pushes to explain a downgrade
// (e.g. "Common updater/enterprise autorun"). They must NOT flip isSuspicious=true —
// otherwise the very metric analysts triage by (stats.suspicious) is inflated by items we
// just declared benign.
const isBenignReason = (r) => /^(?:Known enterprise management|Microsoft sync\/service binary|Common enterprise\/system task|Common updater\/enterprise autorun|Correlation signal present but low-fidelity|Standalone script-block signal without strong|IFEO GlobalFlag without Debugger|COM\/shell server in trusted system\/program path|Autorun from protected program path)/i.test(r);
const hasSuspiciousReason = (rs) => (rs || []).some((r) => !isBenignReason(r));

const normalizeArtifact = (a) => (a || "").replace(/^\\+/, "").replace(/\{[0-9a-f-]+\}$/i, "").trim().toLowerCase();

// When the primary artifact is empty, derive a discriminator from details so unrelated
// findings don't all collapse into one "(no artifact)" bucket.
const secondaryArtifact = (it) => {
  const d = it.details || {};
  return d.groupName || d.targetUser || d.memberName || d.samAccountName || d._wmiName
    || d._wmiType || d.namespace || d.operationType || d.valueName || "";
};

/**
 * Identity of a registry VALUE, in whatever shape the evidence arrived.
 *
 * The same write shows up as three different findings depending on the artifact that
 * recorded it:
 *   hive export (RECmd)  keyPath="HKLM\...\Run"          valueName="Updater"
 *   Sysmon EID 13        targetObject="HKLM\...\Run\Updater"   (value name appended)
 *   Security 4657        targetObject="HKLM\...\Run"     valueName="Updater"
 * Each carries a different category and rule name, so the default key splits one event
 * into three incidents once those sources are merged. Joining key + value and folding the
 * path onto its canonical root makes all three the same string.
 */
function registryValueIdentity(item) {
  const d = item?.details || {};
  const keyPath = d.keyPath || d.targetObject || "";
  if (!keyPath || !/\\/.test(keyPath)) return "";
  const valueName = (d.valueName || "").trim();
  const full = valueName ? `${String(keyPath).replace(/\\+$/, "")}\\${valueName}` : keyPath;
  return (canonicalizeKeyPath(full, { hiveType: d.hiveType, hivePath: d.hivePath }) || full).toLowerCase();
}

/**
 * Grouping key for one item.
 *
 * @param it                     the item
 * @param crossModeRegistry      when true, registry values are keyed by the value itself
 *                               rather than by (category, rule name). Only meaningful once
 *                               more than one source is in play — with a single tab there
 *                               is nothing to reconcile, and keying on the value alone
 *                               would change long-established single-tab grouping.
 */
function incidentKey(it, { crossModeRegistry = false } = {}) {
  const host = corrHost(it.computer);
  const user = it.user ? it.user.toLowerCase() : "";
  if (crossModeRegistry) {
    const reg = registryValueIdentity(it);
    if (reg) return ["REGVALUE", host, reg, user].join("|");
  }
  const art = normalizeArtifact(it.artifact);
  const disc = art || normalizeArtifact(secondaryArtifact(it));
  return [it.category || "", it.name || "", host, disc, user].join("|");
}

/**
 * Collapse items into incidents: group by identity, then split each group wherever
 * consecutive observations are more than an hour apart.
 *
 * @returns {Array} incidents, ranked by triage score then severity then first-seen
 */
function clusterIncidents(items, { crossModeRegistry = false } = {}) {
  const groups = new Map();
  for (const it of items) {
    const k = incidentKey(it, { crossModeRegistry });
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(it);
  }

  const incidents = [];
  let nextId = 0;
  for (const [, grp] of groups) {
    grp.sort((a, b) => ((a.timestamp || "") < (b.timestamp || "") ? -1 : (a.timestamp || "") > (b.timestamp || "") ? 1 : 0));
    const clusters = [];
    let cur = [grp[0]];
    for (let i = 1; i < grp.length; i++) {
      // parseTimestampMs treats a naive timestamp as UTC (project convention). `new Date()`
      // read it as LOCAL, so a registry LastWriteTimestamp ("2026-03-15 10:02:00") and the
      // Sysmon event describing the same write ("2026-03-15T10:02:00Z") appeared to be a
      // whole UTC offset apart and split into two incidents on any non-UTC machine.
      const pT = parseTimestampMs(cur[cur.length - 1].timestamp || "");
      const nT = parseTimestampMs(grp[i].timestamp || "");
      if (pT != null && nT != null && Math.abs(nT - pT) <= INCIDENT_GAP_MS) cur.push(grp[i]);
      else { clusters.push(cur); cur = [grp[i]]; }
    }
    clusters.push(cur);

    for (const cl of clusters) {
      const rep = cl.reduce((best, it) => ((it.riskScore || 0) > (best.riskScore || 0) ? it : best), cl[0]);
      const allTs = cl.map((i) => i.timestamp).filter(Boolean).sort();
      const allReasons = [...new Set(cl.flatMap((i) => i.suspiciousReasons || []))];
      const pillSeen = new Set(); const allPills = [];
      for (const it of cl) for (const p of (it.evidencePills || [])) { if (!pillSeen.has(p.text)) { pillSeen.add(p.text); allPills.push(p); } }
      const maxRisk = Math.max(...cl.map((i) => i.triageScore || i.riskScore || 0));
      const worstSev = cl.reduce((b, i) => ((SEVERITY_ORDER[i.severity] ?? 4) < (SEVERITY_ORDER[b] ?? 4) ? i.severity : b), "low");
      const artShort = (rep.artifact || "").split("\\").pop() || secondaryArtifact(rep) || "";
      let title = rep.name;
      if (artShort && artShort.toLowerCase() !== rep.name.toLowerCase()) title = `${artShort} — ${rep.name}`;
      if (rep.computer) title += ` on ${rep.computer}`;

      // Which sources observed this incident — the point of merging in the first place.
      const sourceTabs = [...new Set(cl.map((i) => i._sourceTab).filter(Boolean))];
      const observedBy = [...new Set(cl.map((i) => i.source).filter(Boolean))];
      // Lift the remote origin to the incident: the alerts view shows incidents, and "who
      // planted this" is the one fact an analyst should never have to expand a row to see.
      // The representative item's attribution wins; otherwise the first that has one.
      const remoteOrigin = rep.remoteOrigin || cl.find((i) => i.remoteOrigin)?.remoteOrigin || null;

      incidents.push({
        id: nextId++, category: rep.category, title, severity: worstSev, triageScore: maxRisk,
        computer: rep.computer || "", user: rep.user || "",
        artifact: rep.artifact || secondaryArtifact(rep) || "", command: rep.command || "", source: rep.source || "",
        firstSeen: allTs[0] || "", lastSeen: allTs[allTs.length - 1] || "", occurrenceCount: cl.length,
        items: cl, itemRowids: cl.map((i) => i.rowid),
        suspiciousReasons: allReasons, evidencePills: allPills,
        isSuspicious: hasSuspiciousReason(allReasons), rmmTool: cl.some((i) => i.rmmTool),
        details: rep.details, mode: rep.mode,
        ...(sourceTabs.length > 0 ? { sourceTabs } : {}),
        ...(observedBy.length > 1 ? { observedBy } : {}),
        ...(remoteOrigin ? { remoteOrigin } : {}),
      });
    }
  }

  incidents.sort((a, b) => (b.triageScore - a.triageScore)
    || ((SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4))
    || ((a.firstSeen || "") < (b.firstSeen || "") ? -1 : 1));
  return incidents;
}

module.exports = {
  INCIDENT_GAP_MS,
  SEVERITY_ORDER,
  corrHost,
  isBenignReason,
  hasSuspiciousReason,
  normalizeArtifact,
  secondaryArtifact,
  registryValueIdentity,
  incidentKey,
  clusterIncidents,
};
