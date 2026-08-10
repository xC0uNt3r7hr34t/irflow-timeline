// Remote origin: the join between a persistence artifact and the pivot that planted it.
//
// The two analyzers answered different halves of one question and never spoke:
//
//   lateral movement   "WKS02 reached DC01"     — an edge, with no idea what happened next
//   persistence        "DC01 gained a service"  — a finding, with no idea who caused it
//
// Either half alone is ambiguous: an inbound logon may be routine administration, and a new
// service may be locally installed software. Together they are a hop that stuck. Persistence
// supplies the join key — {sourceHost, sourceIp, logonId} on the finding — and lm-handoff.js
// attaches it to the lateral-movement graph.
//
// Persistence deliberately does NOT grow a logon engine: it owns only the remote-execution
// events whose payload names the machine on the other end (WinRM, WMI-Activity) plus 4624
// read purely as an arrival.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getPersistenceAnalysis } = require("../electron/analyzers/persistence");
const { getMultiSourcePersistence } = require("../electron/analyzers/persistence/multi-source");
const {
  summarizePersistenceByHost, derivePivotEdges, annotateGraphWithPersistence,
  joinPersistenceToLateralMovement,
} = require("../electron/analyzers/persistence/lm-handoff");

function makeTab(label, headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const byCN = rows.map((r, i) => {
    const o = { _rowid: i + 1 };
    headers.forEach((h) => { o[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return o;
  });
  const db = { prepare: (sql) => ({
    get: () => (/COUNT\(\*\)/i.test(sql) ? { cnt: byCN.length } : null),
    all: (...params) => {
      if (/SELECT DISTINCT/i.test(sql)) {
        const idx = Number(/c(\d+) as eid/i.exec(sql)?.[1] ?? -1);
        const want = new Set(params.map(String));
        return [...new Set(byCN.map((r) => r[`c${idx}`]).filter((v) => want.has(String(v))))].map((eid) => ({ eid }));
      }
      if (!/^SELECT\s/i.test(sql) || !/FROM\s+data/i.test(sql) || !/\bas\s+\[/.test(sql)) return [];
      const aliases = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
      let out = byCN.map((r) => { const o = { _rowid: r._rowid }; for (const [, i, a] of aliases) o[a] = r[`c${i}`]; return o; });
      const inPred = /c(\d+) IN \(/.exec(sql);
      if (inPred) {
        const key = aliases.find((x) => x[1] === inPred[1])?.[2];
        const want = new Set(params.map(String));
        if (key) out = out.filter((r) => want.has(String(r[key])));
      }
      return out;
    },
  }) };
  return { meta: { db, headers, colMap, tabId: label }, tabId: label, label };
}
const ctx = { applyStandardFilters() {}, ensureIndex() {} };

const H = ["EventID", "Channel", "datetime", "Computer", "ServiceName", "ImagePath", "StartType", "AccountName",
  "LogonType", "IpAddress", "WorkstationName", "TargetUserName", "TargetLogonId", "ClientMachine", "User", "Operation"];
const ev = (o) => ({ Channel: "", datetime: "2026-03-15T10:00:00Z", Computer: "U42-TECH", ...o });

const svcInstall = (name, at, image = "C:\\Windows\\PSEXESVC.exe") => ev({
  EventID: "7045", Channel: "System", datetime: at,
  ServiceName: name, ImagePath: image, StartType: "demand start", AccountName: "LocalSystem",
});
const rdpLogon = (at, o = {}) => ev({
  EventID: "4624", Channel: "Security", datetime: at,
  LogonType: "10", IpAddress: "10.2.10.78", WorkstationName: "KALI",
  TargetUserName: "administrator", TargetLogonId: "0x3E7A1", ...o,
});

const systemTab = () => makeTab("System.evtx", H, [svcInstall("PSEXESVC", "2026-03-15T10:12:00Z")]);
const securityTab = () => makeTab("Security.evtx", H, [rdpLogon("2026-03-15T10:10:00Z")]);

// ── 4.2 the join key ───────────────────────────────────────────────────────

test("an inbound RDP logon minutes before a service install attributes it to the pivot", () => {
  const res = getMultiSourcePersistence([systemTab(), securityTab()], {}, ctx);
  const svc = res.items.find((i) => i.artifact === "PSEXESVC");
  assert.ok(svc);
  assert.ok(svc.remoteOrigin, "the finding must carry the arrival that explains it");
  assert.equal(svc.remoteOrigin.sourceHost, "KALI");
  assert.equal(svc.remoteOrigin.sourceIp, "10.2.10.78");
  assert.equal(svc.remoteOrigin.logonId, "0x3E7A1", "the logon session id is the join key");
  assert.equal(svc.remoteOrigin.logonType, "10");
  assert.match(svc.remoteOrigin.via, /RDP/i);
  assert.ok(svc.suspiciousReasons.some((r) => /Planted over .* from KALI/i.test(r)));
  assert.equal(res.stats.remoteOriginItems, 1);
});

test("attribution raises the triage score rather than being swallowed by a severity floor", () => {
  const without = getPersistenceAnalysis(systemTab().meta, { mode: "evtx" }, ctx);
  const with_ = getMultiSourcePersistence([systemTab(), securityTab()], {}, ctx);
  const a = without.items.find((i) => i.artifact === "PSEXESVC");
  const b = with_.items.find((i) => i.artifact === "PSEXESVC");
  // PSEXESVC already sits at the critical floor from the malicious-tool name match, which
  // is exactly the case where a Math.max-based bump would vanish.
  assert.ok(b.riskScore > a.riskScore, `expected a higher score with attribution (${a.riskScore} -> ${b.riskScore})`);
});

test("a console logon is not a remote arrival", () => {
  const consoleTab = makeTab("Security.evtx", H, [
    ev({ EventID: "4624", Channel: "Security", datetime: "2026-03-15T10:10:00Z",
      LogonType: "2", IpAddress: "-", WorkstationName: "U42-TECH", TargetUserName: "marie", TargetLogonId: "0x1" }),
  ]);
  const res = getMultiSourcePersistence([systemTab(), consoleTab], {}, ctx);
  assert.equal(res.stats.remoteArrivals, 0, "type 2 is the console, not a pivot");
  assert.ok(!res.items.some((i) => i.remoteOrigin));
});

test("a loopback network logon is not a remote arrival", () => {
  const loopback = makeTab("Security.evtx", H, [
    rdpLogon("2026-03-15T10:10:00Z", { LogonType: "3", IpAddress: "::1", WorkstationName: "U42-TECH" }),
  ]);
  const res = getMultiSourcePersistence([systemTab(), loopback], {}, ctx);
  assert.equal(res.stats.remoteArrivals, 0, "the host talking to itself is not a pivot");
});

test("an arrival outside the window does not attribute", () => {
  const late = makeTab("Security.evtx", H, [rdpLogon("2026-03-14T02:00:00Z")]);
  const res = getMultiSourcePersistence([systemTab(), late], {}, ctx);
  assert.equal(res.stats.remoteArrivals, 1, "the logon is still seen");
  assert.ok(!res.items.some((i) => i.remoteOrigin), "but a day earlier explains nothing");
});

test("the window is configurable", () => {
  const late = makeTab("Security.evtx", H, [rdpLogon("2026-03-15T08:00:00Z")]); // 4h before
  const tight = getMultiSourcePersistence([systemTab(), late], {}, ctx);
  assert.equal(tight.stats.remoteOriginItems, 0);
  const wide = getMultiSourcePersistence([systemTab(), late], { remoteOriginWindowMs: 6 * 3600 * 1000 }, ctx);
  assert.equal(wide.stats.remoteOriginItems, 1);
});

test("a WMI operation naming another machine is an arrival in its own right", () => {
  const wmiTab = makeTab("WMI.evtx", H, [
    ev({ EventID: "5860", Channel: "Microsoft-Windows-WMI-Activity/Operational", datetime: "2026-03-15T10:11:00Z",
      ClientMachine: "KALI", User: "SEVENKINGDOMS\\administrator", Operation: "Start IWbemServices::ExecQuery" }),
  ]);
  const res = getMultiSourcePersistence([systemTab(), wmiTab], {}, ctx);
  const svc = res.items.find((i) => i.artifact === "PSEXESVC");
  assert.ok(svc.remoteOrigin, "WMI ClientMachine is a pivot source even with no 4624");
  assert.equal(svc.remoteOrigin.sourceHost, "KALI");
  assert.match(svc.remoteOrigin.via, /WMI/i);
  // The remote operation is also a finding, and its artifact is the far end.
  const remote = res.items.find((i) => i.category === "Remote Execution");
  assert.ok(remote);
  assert.equal(remote.artifact, "KALI");
});

test("local WMI activity is not reported as remote execution", () => {
  const localWmi = makeTab("WMI.evtx", H, [
    ev({ EventID: "5860", Channel: "Microsoft-Windows-WMI-Activity/Operational", datetime: "2026-03-15T10:11:00Z",
      ClientMachine: "", User: "SYSTEM", Operation: "Start IWbemServices::ExecQuery" }),
  ]);
  const res = getMultiSourcePersistence([systemTab(), localWmi], {}, ctx);
  assert.ok(!res.items.some((i) => i.category === "Remote Execution"),
    "WMI runs constantly on every host; only an operation attributed to another machine is evidence");
});

test("the richer identity wins when several arrivals qualify", () => {
  // A WMI arrival is nearer in time, but the 4624 carries the logon session id.
  const both = makeTab("Mixed.evtx", H, [
    rdpLogon("2026-03-15T10:10:00Z"),
    ev({ EventID: "5860", Channel: "Microsoft-Windows-WMI-Activity/Operational", datetime: "2026-03-15T10:11:30Z",
      ClientMachine: "KALI", User: "administrator", Operation: "ExecMethod" }),
  ]);
  const res = getMultiSourcePersistence([systemTab(), both], {}, ctx);
  const svc = res.items.find((i) => i.artifact === "PSEXESVC");
  assert.equal(svc.remoteOrigin.logonId, "0x3E7A1", "prefer the arrival that supplies the join key");
});

test("registry findings are attributed too, across a merged run's separate passes", () => {
  const REG_H = ["HivePath", "HiveType", "KeyPath", "ValueName", "ValueData", "LastWriteTimestamp", "Computer"];
  const hiveTab = makeTab("SOFTWARE hive", REG_H, [{
    HivePath: "E:\\tout\\U42-TECH\\C\\Windows\\System32\\config\\SOFTWARE", HiveType: "SOFTWARE",
    KeyPath: "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", ValueName: "Updater",
    ValueData: "C:\\Users\\Public\\evil.exe", LastWriteTimestamp: "2026-03-15 10:15:00", Computer: "U42-TECH",
  }]);
  const res = getMultiSourcePersistence([securityTab(), hiveTab], {}, ctx);
  const run = res.items.find((i) => i.category === "Run Keys");
  assert.ok(run, "the registry finding must survive");
  assert.ok(run.remoteOrigin,
    "the EVTX pass sees the logon and the registry pass does not — the arrivals must be handed across");
  assert.equal(run.remoteOrigin.sourceHost, "KALI");
});

// ── 4.3 the handoff to the lateral-movement graph ──────────────────────────

const fakeIncident = (o = {}) => ({
  id: o.id ?? 1, computer: o.computer ?? "U42-TECH", category: o.category ?? "Services",
  title: o.title ?? "PSEXESVC — Service Installed", severity: o.severity ?? "critical",
  triageScore: o.triageScore ?? 9, artifact: o.artifact ?? "PSEXESVC",
  firstSeen: o.firstSeen ?? "2026-03-15T10:12:00Z", lastSeen: o.lastSeen ?? "2026-03-15T10:12:00Z",
  isSuspicious: o.isSuspicious ?? true,
  items: o.items ?? [{ remoteOrigin: { sourceHost: "KALI", sourceIp: "10.2.10.78", user: "administrator", logonId: "0x3E7A1", logonType: "10", via: "RDP logon (4624 type 10)" } }],
});

test("per-host rollup collapses incidents into what a graph node needs", () => {
  const byHost = summarizePersistenceByHost([
    fakeIncident({ id: 1 }),
    fakeIncident({ id: 2, category: "Scheduled Tasks", severity: "medium", triageScore: 5 }),
    fakeIncident({ id: 3, computer: "u42-tech.sevenkingdoms.local", category: "Run Keys", triageScore: 7 }),
  ]);
  assert.equal(byHost.size, 1, "FQDN and short name are one host");
  const h = byHost.get("U42-TECH");
  assert.equal(h.count, 3);
  assert.equal(h.maxScore, 9);
  assert.equal(h.worstSeverity, "critical");
  assert.deepEqual(h.categories.sort(), ["Run Keys", "Scheduled Tasks", "Services"]);
  assert.equal(h.remoteOrigin, 3);
  assert.deepEqual(h.sources, ["KALI"]);
});

test("pivot edges are derived from attributed findings", () => {
  const edges = derivePivotEdges([fakeIncident({ id: 1 }), fakeIncident({ id: 2, category: "Scheduled Tasks" })]);
  assert.equal(edges.length, 1, "same source, target and logon session is one edge");
  assert.equal(edges[0].source, "KALI");
  assert.equal(edges[0].target, "U42-TECH");
  assert.equal(edges[0].logonId, "0x3E7A1");
  assert.deepEqual(edges[0].incidents, [1, 2]);
  assert.deepEqual(edges[0].categories.sort(), ["Scheduled Tasks", "Services"]);
});

test("an unattributed finding produces no pivot edge", () => {
  assert.deepEqual(derivePivotEdges([fakeIncident({ items: [{}] })]), []);
});

test("graph nodes gain a persistence attribute and a confirmed-hop verdict", () => {
  const nodes = [{ id: "U42-TECH", label: "U42-TECH" }, { id: "KALI", label: "KALI" }, { id: "QUIET-HOST", label: "QUIET-HOST" }];
  const edges = [{ source: "KALI", target: "U42-TECH" }];
  const annotated = annotateGraphWithPersistence(nodes, [fakeIncident()], { edges });

  const target = annotated.find((n) => n.id === "U42-TECH");
  assert.ok(target.persistence, "the host that gained persistence is annotated");
  assert.equal(target.persistence.count, 1);
  assert.equal(target.confirmedHop, true, "reached AND kept — that is a hop that stuck");

  const quiet = annotated.find((n) => n.id === "QUIET-HOST");
  assert.equal(quiet.persistence, null);
  assert.equal(quiet.confirmedHop, false);
  // The originals must not be mutated — a cached graph has to stay reusable.
  assert.equal(nodes[0].persistence, undefined);
});

test("persistence with no remote origin on an un-pivoted host is not a confirmed hop", () => {
  const nodes = [{ id: "STANDALONE" }];
  const local = fakeIncident({ computer: "STANDALONE", items: [{}], isSuspicious: true });
  const annotated = annotateGraphWithPersistence(nodes, [local], { edges: [] });
  assert.ok(annotated[0].persistence, "it is still reported");
  assert.equal(annotated[0].confirmedHop, false, "locally installed software is not a hop");
});

test("the join survives a lateral-movement failure", () => {
  const joined = joinPersistenceToLateralMovement({ nodes: [], edges: [] }, { incidents: [fakeIncident()] });
  assert.equal(joined.nodes.length, 0, "no graph to annotate");
  assert.equal(joined.pivotEdges.length, 1, "but persistence can still prove the pivot on its own");
  assert.equal(joined.stats.hostsWithPersistence, 1);
  assert.equal(joined.stats.remoteOriginIncidents, 1);
});

test("the full join reports confirmed hops", () => {
  const lm = { nodes: [{ id: "U42-TECH" }, { id: "KALI" }], edges: [{ source: "KALI", target: "U42-TECH" }] };
  const joined = joinPersistenceToLateralMovement(lm, { incidents: [fakeIncident()] });
  assert.equal(joined.stats.confirmedHops, 1);
  assert.deepEqual(joined.stats.confirmedHopHosts, ["U42-TECH"]);
  assert.equal(joined.stats.pivotEdgeCount, 1);
});
