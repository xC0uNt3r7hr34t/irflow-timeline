/**
 * analyzers/persistence/registry-shapes.js — registry input normalization
 *
 * Registry evidence reaches the persistence analyzer in several mutually incompatible
 * shapes, and the detection rules are written against ONE of them (full `HKLM\...` paths):
 *
 *   RECmd batch export   KeyPath = "ROOT\ControlSet001\Services\EvilSvc"
 *                        HiveType = "SYSTEM", HivePath = "...\config\SYSTEM"
 *   Registry Explorer    KeyPath = "CMI-CreateHive{...}\Software\Microsoft\..."
 *   Security 4657        ObjectName = "\REGISTRY\MACHINE\SOFTWARE\Microsoft\..."
 *   Sysmon 12/13/14      TargetObject = "HKLM\SOFTWARE\Microsoft\..."
 *   RECmd plugin CSVs    no KeyPath/ValueName at all — a projected view of one key
 *                        family (Services, TaskCache, …) with its own column set
 *
 * A hive-relative path has no hive segment, so `\SYSTEM\CurrentControlSet\Services\`
 * style rules match NOTHING on a RECmd export — the richest registry artifact in a KAPE
 * package produced zero service findings. This module folds every shape onto one
 * canonical form before rule matching, and projects the plugin CSVs into the
 * {keyPath, valueName, valueData} triple the rules expect.
 */

// Hive (file) name -> canonical registry root.
const HIVE_ROOTS = {
  SYSTEM: "HKLM\\SYSTEM",
  SOFTWARE: "HKLM\\SOFTWARE",
  SAM: "HKLM\\SAM",
  SECURITY: "HKLM\\SECURITY",
  COMPONENTS: "HKLM\\COMPONENTS",
  DRIVERS: "HKLM\\DRIVERS",
  BCD: "HKLM\\BCD00000000",
  NTUSER: "HKCU",
  USRCLASS: "HKCU\\Software\\Classes",
  DEFAULT: "HKU\\.DEFAULT",
  AMCACHE: "HKLM\\Amcache",
  SYSCACHE: "HKLM\\Syscache",
};

// Null-safe trim. Strips embedded NULs (hive value data is frequently NUL-padded) but
// deliberately leaves inner whitespace alone — "Windows NT" and "Program Files" are
// real path segments.
const _clean = (v) => (v == null ? "" : String(v).replace(/\u0000/g, "").trim());

// Join a root with a hive-relative remainder, collapsing separator noise.
function _join(root, rest) {
  const r = _clean(rest).replace(/^\\+/, "").replace(/\\+$/, "");
  return r ? `${root}\\${r}` : root;
}

/**
 * Resolve which hive a row came from. An explicit HiveType column (RECmd) wins;
 * otherwise the hive file's basename is authoritative — KAPE preserves it.
 */
function hiveNameFor({ hiveType, hivePath } = {}) {
  const t = _clean(hiveType).toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (t) {
    if (t.startsWith("NTUSER")) return "NTUSER";
    if (t.startsWith("USRCLASS")) return "USRCLASS";
    if (HIVE_ROOTS[t]) return t;
  }
  const p = _clean(hivePath);
  if (!p) return "";
  const base = (p.split(/[\\/]/).pop() || "")
    .replace(/\.(?:LOG\d*|regtrans-ms|blf)$/i, "")   // transaction logs sit beside the hive
    .replace(/\.(?:DAT|HVE|HIV|BAK)$/i, "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
  if (!base) return "";
  if (base.startsWith("NTUSER")) return "NTUSER";
  if (base.startsWith("USRCLASS")) return "USRCLASS";
  if (HIVE_ROOTS[base]) return base;
  return "";
}

/**
 * Fold any of the input shapes onto `HKLM\SOFTWARE\...` / `HKCU\...` form.
 * Returns the input unchanged when the hive cannot be determined — a partially
 * normalized path is still better than a mangled one.
 *
 * NOTE: forward slashes are NOT converted to backslashes. Registry KEY NAMES may
 * legitimately contain "/" (e.g. "TCP/IP NetBIOS Helper"), so rewriting them would
 * invent extra path segments.
 */
function canonicalizeKeyPath(keyPath, opts = {}) {
  let kp = _clean(keyPath);
  if (!kp) return "";
  const quoted = /^"([\s\S]*)"$/.exec(kp);
  if (quoted) kp = quoted[1].trim();
  kp = kp.replace(/^\\+/, "");

  // NT object-manager form (Security 4657 ObjectName, some Sysmon exports)
  let m = /^REGISTRY\\MACHINE\\?([\s\S]*)$/i.exec(kp);
  if (m) return _join("HKLM", m[1]);
  m = /^REGISTRY\\USER\\?([\s\S]*)$/i.exec(kp);
  if (m) return _join("HKU", m[1]);

  // Already rooted — normalize the abbreviation only.
  const ROOT_ALIASES = [
    [/^(?:HKEY_LOCAL_MACHINE|HKLM)(?:\\([\s\S]*))?$/i, "HKLM"],
    [/^(?:HKEY_CURRENT_USER|HKCU)(?:\\([\s\S]*))?$/i, "HKCU"],
    [/^(?:HKEY_USERS|HKU)(?:\\([\s\S]*))?$/i, "HKU"],
    [/^(?:HKEY_CLASSES_ROOT|HKCR)(?:\\([\s\S]*))?$/i, "HKCR"],
    [/^(?:HKEY_CURRENT_CONFIG|HKCC)(?:\\([\s\S]*))?$/i, "HKCC"],
  ];
  for (const [re, root] of ROOT_ALIASES) {
    const hit = re.exec(kp);
    if (hit) return _join(root, hit[1] || "");
  }

  // Hive-relative: RECmd writes "ROOT\", Registry Explorer keeps the hive's own root
  // key name ("CMI-CreateHive{GUID}\" for SYSTEM/SOFTWARE, "$$$PROTO.HIV\" for NTUSER).
  kp = kp
    .replace(/^ROOT(?:\\|$)/i, "")
    .replace(/^CMI-CreateHive\{[0-9A-Fa-f-]+\}(?:\\|$)/, "")
    .replace(/^\$\$\$PROTO\.HIV(?:\\|$)/i, "")
    .replace(/^\\+/, "");
  if (!kp) return "";

  const hive = hiveNameFor(opts);
  const root = hive ? HIVE_ROOTS[hive] : "";
  if (!root) return kp;

  // Some exporters keep the hive name as the first segment ("SOFTWARE\Microsoft\...").
  // Don't emit HKLM\SOFTWARE\SOFTWARE\...
  const lead = new RegExp(`^${hive}(?:\\\\|$)`, "i");
  return _join(root, kp.replace(lead, ""));
}

/**
 * Hive scope label + owning user, for the detail panel and evidence pills.
 */
function hiveContext(hivePath, hiveType) {
  const p = _clean(hivePath);
  const userM = /[/\\]Users[/\\]([^/\\]+)[/\\]/i.exec(p);
  const user = userM ? userM[1] : "";
  const hive = hiveNameFor({ hiveType, hivePath: p });
  if (hive === "NTUSER" || hive === "USRCLASS") return { user, hiveScope: "HKCU" };
  if (hive === "AMCACHE") return { user: "", hiveScope: "Amcache" };
  if (hive) return { user: "", hiveScope: HIVE_ROOTS[hive] };
  return { user, hiveScope: "" };
}

// Folder names that show up where a machine name would sit in a collection path.
const NON_HOST_FOLDERS = /^(?:t_?out|m_?out|out|output|triage|kape|targets?|modules?|results?|evidence|collection|acquisition|exports?|temp|tmp|data|cases?|images?|uploads?|windows|users|programdata|config|system32|winevt|logs|shares?|mnt|media|vol(?:ume)?s?|root|home|nas|storage|backups?|archives?)$/i;
const HOSTNAME_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/**
 * Best-effort host name from a collection path. KAPE lays triage output out as
 * `<dest>\<MachineName>\<DriveLetter>\Windows\System32\config\SYSTEM`, so the segment
 * before the drive-letter segment is the machine. Heuristic by nature — callers should
 * mark findings attributed this way so an analyst knows it was inferred, not read.
 */
function deriveCollectionHost(hivePath) {
  const p = _clean(hivePath);
  if (!p) return "";
  const segs = p.split(/[\\/]+/).filter(Boolean);
  for (let i = 1; i < segs.length; i++) {
    if (!/^[A-Za-z](?:%3A|:)?$/i.test(segs[i])) continue;
    const cand = segs[i - 1];
    if (!HOSTNAME_SHAPE.test(cand)) return "";
    if (NON_HOST_FOLDERS.test(cand)) return "";
    if (/^[A-Za-z]:?$/.test(cand)) return "";       // another drive letter, not a machine
    return cand;
  }
  return "";
}

// Registry paths that hold the machine name, most authoritative first.
const COMPUTERNAME_KEYS = [
  { re: /\\Control\\ComputerName\\ComputerName$/i, valueName: /^ComputerName$/i, rank: 0 },
  { re: /\\Control\\ComputerName\\ActiveComputerName$/i, valueName: /^ComputerName$/i, rank: 1 },
  { re: /\\Services\\Tcpip\\Parameters$/i, valueName: /^Hostname$/i, rank: 2 },
];

/**
 * Pull the machine name straight out of the SYSTEM hive when the export includes it.
 * This is the only non-heuristic source available to a registry-only tab.
 */
function hostFromComputerNameKey(rows, { keyPathOf, valueNameOf, valueDataOf }) {
  let best = null;
  for (const row of rows) {
    const kp = _clean(keyPathOf(row));
    if (!kp || !/ComputerName|Tcpip\\Parameters/i.test(kp)) continue;
    for (const cand of COMPUTERNAME_KEYS) {
      if (!cand.re.test(kp)) continue;
      if (!cand.valueName.test(_clean(valueNameOf(row)))) continue;
      const data = _clean(valueDataOf(row));
      if (!data) continue;
      if (!best || cand.rank < best.rank) best = { rank: cand.rank, host: data };
    }
    if (best && best.rank === 0) break;
  }
  return best ? best.host : "";
}

// ── RECmd per-plugin CSV shapes ────────────────────────────────────────────
//
// RECmd writes one detail CSV per plugin next to the batch output. They carry no
// KeyPath/ValueName pair, so mode auto-detection used to return null and the whole
// M_Out/Registry/<ts>/ folder was unreadable ("Cannot detect data type").
//
// `project()` turns one plugin row into the {keyPath, valueName, valueData} triples the
// registry rules match on. Detection is alias-based and deliberately strict: several
// distinct columns must resolve before a shape claims a file, so an unrelated CSV that
// happens to have a "Name" column is never mistaken for a plugin export.

const REGISTRY_PLUGIN_SHAPES = [
  {
    id: "services",
    label: "RECmd Services plugin",
    projects: true,
    columns: {
      svcName: [/^ServiceName$/i, /^Name$/i],
      svcDisplayName: [/^DisplayName$/i, /^Display ?Name$/i],
      svcImagePath: [/^ImagePath$/i, /^Image ?Path$/i],
      svcDll: [/^ServiceDll$/i, /^Service ?DLL$/i],
      svcStartMode: [/^StartMode$/i, /^Start ?Type$/i, /^Start$/i],
      svcType: [/^ServiceType$/i],
      svcAccount: [/^ObjectName$/i, /^ServiceAccount$/i, /^StartName$/i, /^Account$/i],
      svcFailureCommand: [/^FailureCommand$/i, /^Failure ?Command$/i],
      svcControlSet: [/^ControlSet$/i, /^ControlSetNumber$/i, /^Control ?Set$/i],
      // RECmd emits the service's PARENT key ("ROOT\ControlSet001\Services"), which names
      // the real control set instead of making us assume CurrentControlSet.
      svcParentKey: [/^BatchKeyPath$/i],
      hivePath: [/^HivePath$/i, /^Hive ?Path$/i],
      hiveType: [/^HiveType$/i, /^Hive ?Type$/i],
      ts: [/^LastWriteTimestamp$/i, /^KeyLastWriteTimestamp$/i, /^NameKeyLastWrite$/i, /^ParametersKeyLastWrite$/i, /^Timestamp$/i, /^LastWrite$/i],
    },
    required: ["svcName"],
    // At least one path-bearing column AND one service-metadata column — "Name" alone
    // is far too common to claim a file on.
    requiredAny: [["svcImagePath", "svcDll"], ["svcStartMode", "svcType", "svcAccount"]],
    project(row) {
      const name = _clean(row.svcName);
      if (!name) return [];
      // Prefer the parent key RECmd actually reported; fall back to synthesizing one.
      const parent = _clean(row.svcParentKey);
      let base;
      if (parent) {
        base = `${parent.replace(/\\+$/, "")}\\${name}`;
      } else {
        const cs = _clean(row.svcControlSet);
        const csSeg = !cs ? "CurrentControlSet"
          : /^\d+$/.test(cs) ? `ControlSet${cs.padStart(3, "0")}`
            : /^ControlSet/i.test(cs) ? cs
              : cs;
        base = `HKLM\\SYSTEM\\${csSeg}\\Services\\${name}`;
      }
      const meta = {
        _pluginServiceName: name,
        _pluginDisplayName: _clean(row.svcDisplayName) || undefined,
        _pluginStartMode: _clean(row.svcStartMode) || undefined,
        _pluginServiceType: _clean(row.svcType) || undefined,
        _pluginAccount: _clean(row.svcAccount) || undefined,
      };
      const out = [];
      const push = (keyPath, valueName, valueData) => {
        if (!_clean(valueData)) return;
        out.push({ keyPath, valueName, valueData: _clean(valueData), extra: meta });
      };
      push(base, "ImagePath", row.svcImagePath);
      // ServiceDll lives under the service's Parameters subkey.
      push(`${base}\\Parameters`, "ServiceDll", row.svcDll);
      push(base, "FailureCommand", row.svcFailureCommand);
      return out;
    },
  },
  {
    id: "taskcache",
    label: "RECmd TaskCache plugin",
    projects: true,
    // Column names verified against real RECmd output:
    //   Version, BatchKeyPath, KeyName, BatchValueName, Path, CreatedOn, LastStart,
    //   LastStop, TaskState, LastActionResult, Source, Description, SecurityDescriptor, Author
    // The registry TaskCache does NOT decode the Actions blob, so this shape can say a task
    // exists and when it ran, but not what it runs — the task XML under Windows\System32\
    // Tasks is the only place that says that (see ./task-xml.js).
    columns: {
      taskPath: [/^Path$/i, /^TaskPath$/i, /^TaskName$/i, /^Name$/i],
      taskId: [/^KeyName$/i, /^Id$/i, /^TaskId$/i, /^G?UID$/i, /^Guid$/i],
      taskAction: [/^Actions?$/i, /^Command$/i, /^Execute$/i, /^ActionPath$/i],
      taskAuthor: [/^Author$/i],
      taskHidden: [/^Hidden$/i],
      taskState: [/^TaskState$/i],
      taskCreated: [/^CreatedOn$/i],
      taskLastRun: [/^LastStart$/i, /^LastRun(?:Time)?$/i],
      taskNextRun: [/^NextRun(?:Time)?$/i],
      hivePath: [/^HivePath$/i, /^Hive ?Path$/i],
      hiveType: [/^HiveType$/i, /^Hive ?Type$/i],
      ts: [/^CreatedOn$/i, /^LastWriteTimestamp$/i, /^KeyLastWriteTimestamp$/i, /^Timestamp$/i, /^LastWrite$/i],
    },
    required: ["taskPath"],
    requiredAny: [["taskId", "taskAction"], ["taskAuthor", "taskCreated", "taskLastRun", "taskNextRun", "taskHidden", "taskState"]],
    project(row) {
      const path = _clean(row.taskPath);
      if (!path) return [];
      const rel = path.replace(/^\\+/, "");
      const base = `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\${rel}`;
      const action = _clean(row.taskAction);
      const meta = {
        _pluginTaskPath: path,
        _pluginTaskAuthor: _clean(row.taskAuthor) || undefined,
        _pluginTaskHidden: /^(?:true|1|yes)$/i.test(_clean(row.taskHidden)) || undefined,
        _pluginTaskLastRun: _clean(row.taskLastRun) || undefined,
        _pluginTaskState: _clean(row.taskState) || undefined,
      };
      // The action is the evidence; the Id alone is inventory. Emit the action when the
      // plugin resolved one, otherwise a single Id row so the task is still visible.
      if (action) return [{ keyPath: base, valueName: "Actions", valueData: action, extra: { ...meta, _taskRegHasActions: true } }];
      const id = _clean(row.taskId);
      return [{ keyPath: base, valueName: "Id", valueData: id, extra: meta }];
    },
  },
  // Execution artifacts. Recognized so the analyzer can say what the file IS instead of
  // dead-ending on "Cannot detect data type" — but NOT projected: none of their keys can
  // hold a persistence mechanism, so projecting them would only manufacture an
  // authoritative-looking "0 findings".
  {
    id: "userassist",
    label: "RECmd UserAssist plugin",
    projects: false,
    columns: {
      programName: [/^ProgramName$/i, /^Program ?Name$/i],
      runCount: [/^RunCounter$/i, /^RunCount$/i],
      lastExecuted: [/^LastExecuted$/i, /^Last ?Executed$/i],
    },
    required: ["programName"],
    requiredAny: [["runCount", "lastExecuted"]],
  },
  {
    id: "appcompatcache",
    label: "RECmd AppCompatCache plugin",
    projects: false,
    columns: {
      path: [/^Path$/i, /^ProgramName$/i],
      position: [/^CacheEntryPosition$/i, /^ControlSet$/i],
      executed: [/^Executed$/i],
      lastModified: [/^LastModifiedTimeUTC$/i, /^LastModified$/i],
    },
    required: ["path"],
    requiredAny: [["position"], ["executed", "lastModified"]],
  },
  {
    id: "bam",
    label: "RECmd BAM/DAM plugin",
    projects: false,
    columns: {
      program: [/^Program$/i, /^ExecutablePath$/i, /^Path$/i],
      executionTime: [/^ExecutionTime$/i, /^LastExecution(?:Time)?$/i],
      sid: [/^SID$/i, /^UserSid$/i, /^User ?Sid$/i],
    },
    required: ["executionTime"],
    requiredAny: [["program"], ["sid"]],
  },
];

/**
 * Identify a RECmd plugin CSV from its headers.
 *
 * @param headers  the tab's column names
 * @param detect   (patterns) => matching header name or null (the analyzer's own detector)
 * @returns {{ shape, cols }} | null
 */
function detectRegistryPlugin(headers, detect) {
  if (!Array.isArray(headers) || headers.length === 0) return null;
  const has = (re) => headers.some((h) => re.test(h));
  // A real KeyPath/ValueName export is handled by the generic path — never claim it here.
  if (has(/^Key ?Path$/i) && has(/^Value ?Name$/i)) return null;

  for (const shape of REGISTRY_PLUGIN_SHAPES) {
    const cols = {};
    for (const [key, aliases] of Object.entries(shape.columns)) cols[key] = detect(aliases);
    if (!shape.required.every((k) => cols[k])) continue;
    if (!(shape.requiredAny || []).every((group) => group.some((k) => cols[k]))) continue;
    return { shape, cols };
  }
  return null;
}

/**
 * Expand plugin rows into normalized registry rows. Each output row keeps the source
 * `_rowid` so the modal can still pivot back to the grid, and is flagged `_inventory`:
 * a plugin CSV is a snapshot of current STATE, not a record of a change, so every host
 * yields hundreds of them and they must not be ranked like an observed modification.
 */
function projectPluginRows(plugin, rows) {
  if (!plugin?.shape?.projects) return [];
  const out = [];
  for (const row of rows) {
    let projected;
    try {
      projected = plugin.shape.project(row) || [];
    } catch {
      continue; // a malformed row must not abort the whole scan
    }
    for (const p of projected) {
      out.push({
        _rowid: row._rowid,
        keyPath: p.keyPath,
        valueName: p.valueName,
        valueData: p.valueData,
        hivePath: _clean(row.hivePath),
        hiveType: _clean(row.hiveType),
        ts: _clean(row.ts),
        _inventory: true,
        _plugin: plugin.shape.id,
        _pluginLabel: plugin.shape.label,
        ...(p.extra || {}),
      });
    }
  }
  return out;
}

module.exports = {
  HIVE_ROOTS,
  hiveNameFor,
  canonicalizeKeyPath,
  hiveContext,
  deriveCollectionHost,
  hostFromComputerNameKey,
  detectRegistryPlugin,
  projectPluginRows,
  REGISTRY_PLUGIN_SHAPES,
};
