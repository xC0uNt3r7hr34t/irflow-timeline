/**
 * persistenceRuleCatalog.mjs — renderer-side view of the persistence rule sets.
 *
 * MIRRORS electron/analyzers/persistence/rules.js. The persistence modal's
 * enable/disable checkboxes, technique presets and intent sets all key off the
 * POSITIONAL ids below (`evtx-<i>` / `reg-<i>`), which the analyzer derives from
 * its own array indices — so a drift between these two lists silently rewires
 * every checkbox onto the wrong rule.
 *
 * tests/persistence-rule-catalog.test.js pins this file against the analyzer's
 * exported PERSISTENCE_RULE_CATALOG (length + per-index id/cat/name/sev, and
 * event ids for EVTX rules). When you add or change an analyzer rule, update
 * this file in the same commit; append only, never reorder.
 *
 *   cat/name/sev/hint — mirrored from the analyzer (hint = event ids for EVTX,
 *                       a short key-path cue for registry rules).
 *   label             — OPTIONAL renderer-only display name. Purely cosmetic;
 *                       not compared by the test. Falls back to `name`.
 */

export const PA_EVTX_RULES = [
  { id: "evtx-0", cat: "Services", name: "Service Installed", sev: "high", hint: "7045" },
  { id: "evtx-1", cat: "Services", name: "Service Installed", sev: "high", hint: "4697", label: "Service Installed (Security)" },
  { id: "evtx-2", cat: "Scheduled Tasks", name: "Scheduled Task Created", sev: "high", hint: "4698", label: "Task Created" },
  { id: "evtx-3", cat: "Scheduled Tasks", name: "Scheduled Task Deleted", sev: "medium", hint: "4699", label: "Task Deleted" },
  { id: "evtx-4", cat: "Scheduled Tasks", name: "Task Registered", sev: "medium", hint: "106" },
  { id: "evtx-5", cat: "Scheduled Tasks", name: "Task Updated", sev: "medium", hint: "140" },
  { id: "evtx-6", cat: "Scheduled Tasks", name: "Task Process Created", sev: "high", hint: "129" },
  { id: "evtx-7", cat: "Scheduled Tasks", name: "Task Action Started", sev: "medium", hint: "200" },
  { id: "evtx-8", cat: "WMI Persistence", name: "WMI Event Subscription", sev: "critical", hint: "5861" },
  { id: "evtx-9", cat: "WMI Persistence", name: "WMI EventFilter Created", sev: "critical", hint: "19" },
  { id: "evtx-10", cat: "WMI Persistence", name: "WMI EventConsumer Created", sev: "critical", hint: "20" },
  { id: "evtx-11", cat: "WMI Persistence", name: "WMI Binding Created", sev: "critical", hint: "21" },
  { id: "evtx-12", cat: "Registry Autorun", name: "Registry Value Set", sev: "high", hint: "13" },
  { id: "evtx-13", cat: "Registry Modification", name: "Registry Key Created/Deleted", sev: "medium", hint: "12" },
  { id: "evtx-14", cat: "Registry Rename", name: "Registry Key/Value Renamed", sev: "medium", hint: "14" },
  { id: "evtx-15", cat: "Startup Folder", name: "File Created in Startup", sev: "high", hint: "11" },
  { id: "evtx-16", cat: "DLL Hijacking", name: "Unsigned DLL Loaded", sev: "medium", hint: "7" },
  { id: "evtx-17", cat: "Driver Loading", name: "Suspicious Driver Loaded", sev: "critical", hint: "6" },
  { id: "evtx-18", cat: "Process Tampering", name: "Process Tampering Detected", sev: "critical", hint: "25" },
  { id: "evtx-19", cat: "Scheduled Tasks", name: "Task Deleted", sev: "high", hint: "141" },
  { id: "evtx-20", cat: "Scheduled Tasks", name: "Boot Trigger Fired", sev: "medium", hint: "118" },
  { id: "evtx-21", cat: "Scheduled Tasks", name: "Logon Trigger Fired", sev: "medium", hint: "119" },
  { id: "evtx-22", cat: "Account Persistence", name: "User Account Created", sev: "high", hint: "4720" },
  { id: "evtx-23", cat: "Account Persistence", name: "Member Added to Global Security Group", sev: "critical", hint: "4728", label: "Member Added to Global Group" },
  { id: "evtx-24", cat: "Account Persistence", name: "Member Added to Local Security Group", sev: "high", hint: "4732", label: "Member Added to Local Group" },
  { id: "evtx-25", cat: "Account Persistence", name: "Member Added to Universal Security Group", sev: "critical", hint: "4756", label: "Member Added to Universal Group" },
  { id: "evtx-26", cat: "Account Persistence", name: "User Password Reset", sev: "medium", hint: "4724" },
  { id: "evtx-27", cat: "Account Persistence", name: "User Account Changed", sev: "high", hint: "4738" },
  { id: "evtx-28", cat: "Domain Persistence", name: "AD Object Modified", sev: "high", hint: "5136" },
  { id: "evtx-29", cat: "Domain Persistence", name: "AD Object Created", sev: "medium", hint: "5137" },
  { id: "evtx-30", cat: "Domain Persistence", name: "AD Object Deleted", sev: "high", hint: "5141" },
  { id: "evtx-31", cat: "Services", name: "Service StartType Changed", sev: "high", hint: "7040" },
  { id: "evtx-32", cat: "Scheduled Tasks", name: "Task Updated (Security)", sev: "medium", hint: "4702" },
  { id: "evtx-33", cat: "Registry Autorun", name: "Registry Value Modified (4657)", sev: "high", hint: "4657" },
  { id: "evtx-34", cat: "Defender Tampering", name: "Defender Protection Disabled", sev: "high", hint: "5001, 5010, 5012, 5101", label: "Defender Protection Disabled" },
  { id: "evtx-35", cat: "Defender Tampering", name: "Defender Setting Changed", sev: "medium", hint: "5007", label: "Defender Setting Changed" },
  { id: "evtx-36", cat: "Scheduled Tasks", name: "Scheduled Task Defined", sev: "medium", hint: "TASKXML", label: "Task Definition (XML)" },
  { id: "evtx-37", cat: "Remote Execution", name: "WMI Remote Operation", sev: "medium", hint: "5857, 5858, 5860", label: "WMI Remote Operation" },
  { id: "evtx-38", cat: "Remote Execution", name: "WinRM Remote Session", sev: "medium", hint: "145, 161, 169", label: "WinRM Remote Session" },
];

export const PA_REG_RULES = [
  { id: "reg-0", cat: "Run Keys", name: "Run/RunOnce Autostart", sev: "high", hint: "Run, RunOnce" },
  { id: "reg-1", cat: "Services", name: "Service ImagePath/ServiceDll", sev: "high", hint: "Services\\" },
  { id: "reg-2", cat: "Winlogon", name: "Winlogon Shell/Userinit", sev: "critical", hint: "Winlogon" },
  { id: "reg-3", cat: "AppInit DLLs", name: "AppInit_DLLs", sev: "critical", hint: "AppInit_DLLs" },
  { id: "reg-4", cat: "IFEO", name: "Image File Execution Options Debugger", sev: "critical", hint: "Image File Exec Opts", label: "IFEO Debugger" },
  { id: "reg-5", cat: "COM Hijacking", name: "COM Object Server", sev: "high", hint: "InprocServer32" },
  { id: "reg-6", cat: "Shell Extensions", name: "Shell Extension Handler", sev: "medium", hint: "Shell handlers" },
  { id: "reg-7", cat: "Boot Execute", name: "Session Manager BootExecute", sev: "critical", hint: "Session Manager" },
  { id: "reg-8", cat: "BHO", name: "Browser Helper Object", sev: "medium", hint: "Browser Helper" },
  { id: "reg-9", cat: "LSA", name: "LSA Security/Auth Packages", sev: "critical", hint: "Lsa" },
  { id: "reg-10", cat: "Print Monitors", name: "Print Monitor DLL", sev: "high", hint: "Print\\Monitors" },
  { id: "reg-11", cat: "Active Setup", name: "Active Setup StubPath", sev: "high", hint: "Active Setup" },
  { id: "reg-12", cat: "Startup Folder", name: "Startup Folder Registry Path", sev: "high", hint: "Shell Folders" },
  { id: "reg-13", cat: "Scheduled Tasks (Reg)", name: "Scheduled Task in Registry", sev: "medium", hint: "TaskCache" },
  { id: "reg-14", cat: "Network Providers", name: "Network Provider Order", sev: "high", hint: "NetworkProvider" },
  { id: "reg-15", cat: "Logon Script", name: "User Logon Script (Environment)", sev: "high", hint: "UserInitMprLogonScript" },
  { id: "reg-16", cat: "AppCert DLLs", name: "AppCert DLL", sev: "critical", hint: "AppCertDlls" },
  { id: "reg-17", cat: "Silent Process Exit", name: "Silent Process Exit Monitor", sev: "critical", hint: "SilentProcessExit" },
  { id: "reg-18", cat: "Credential Providers", name: "Credential Provider Registration", sev: "high", hint: "Credential Providers" },
  { id: "reg-19", cat: "Command Processor", name: "Command Processor AutoRun", sev: "high", hint: "Command Processor" },
  { id: "reg-20", cat: "Explorer Autoruns", name: "ShellServiceObjectDelayLoad", sev: "high", hint: "ShellServiceObjectDelayLoad" },
  { id: "reg-21", cat: "Netsh Helper DLLs", name: "Netsh Helper DLL", sev: "high", hint: "Netsh" },
  { id: "reg-22", cat: "Screensaver", name: "Screensaver Hijack", sev: "high", hint: "Control Panel\\Desktop" },
  { id: "reg-23", cat: "Office Add-ins", name: "Office Add-in Registration", sev: "high", hint: "Office\\..\\Addins" },
  { id: "reg-24", cat: "Time Providers", name: "Time Provider DLL", sev: "critical", hint: "W32Time\\TimeProviders" },
  { id: "reg-25", cat: "Terminal Server", name: "Terminal Server InitialProgram", sev: "critical", hint: "Terminal Server" },
  { id: "reg-26", cat: "File Association", name: "File Association Hijack", sev: "high", hint: "shell\\open\\command" },
  { id: "reg-27", cat: "Group Policy Scripts", name: "GPO Logon/Startup Script", sev: "high", hint: "Group Policy\\Scripts" },
  { id: "reg-28", cat: "Security Support Provider", name: "LSA Security Support Provider", sev: "critical", hint: "Control\\SecurityProviders" },
  { id: "reg-29", cat: "Environment Hijack", name: "COR_PROFILER .NET Profiler", sev: "high", hint: "Environment" },
  { id: "reg-30", cat: "Winlogon", name: "Winlogon Notify/GPExtensions DLL", sev: "critical", hint: "Winlogon\\Notify" },
  { id: "reg-31", cat: "COM Hijacking", name: "COM TreatAs Redirect", sev: "high", hint: "CLSID\\..\\TreatAs" },
  { id: "reg-32", cat: "Defender Tampering", name: "Defender Exclusion / Protection Disabled", sev: "high", hint: "Defender\\Exclusions" },
];

// Display name for a catalog entry — short label when one is defined, else the
// analyzer's own rule name.
export const paRuleLabel = (r) => r.label || r.name;

// ── Technique preset cards ────────────────────────────────────────────────
// `rules` are indices into PA_EVTX_RULES / PA_REG_RULES above. They live here,
// next to the catalog, so a rule-list change and its preset wiring are reviewed
// together; tests/persistence-rule-catalog.test.js range-checks every index and
// asserts which rules are deliberately left out of all presets.
// Icons are supplied by the modal (PA_PRESET_ICONS), keyed by `id`.
export const PA_EVTX_PRESETS = [
  { id: "svc", name: "Services & Drivers", rules: [0, 1, 17, 31],
    desc: "Service install + driver load + start type change — flags non-standard paths, RMM tools, PsExec" },
  { id: "task", name: "Scheduled Tasks", rules: [2, 3, 4, 5, 6, 7, 19, 20, 21, 32, 36],
    desc: "Task creation, deletion, triggers — GUID tasks, LOLBin actions, boot/logon triggers" },
  { id: "wmi", name: "WMI Persistence", rules: [8, 9, 10, 11],
    desc: "Event consumers/subscriptions — high-confidence persistence indicator" },
  { id: "regsys", name: "Registry & Startup", rules: [12, 13, 14, 15, 33],
    desc: "Autorun value sets, key changes, startup folder drops (Sysmon) plus the Security 4657 fallback" },
  { id: "adv", name: "Advanced Detection", rules: [16, 18],
    desc: "DLL hijacking + process tampering — noisier but catches stealth techniques" },
  { id: "remote", name: "Remote Execution", rules: [37, 38],
    desc: "WinRM and WMI operations attributed to another machine — the arrival that explains how the persistence got here" },
  { id: "defender", name: "Defender Tampering", rules: [34, 35],
    desc: "AV protection disabled or exclusions added via the Defender Operational log" },
];

export const PA_REG_PRESETS = [
  { id: "core", name: "Core Autoruns", rules: [0, 1, 2, 7],
    desc: "Run/RunOnce, service ImagePath, Winlogon shell/userinit, boot execute" },
  { id: "stealth", name: "Stealth Locations", rules: [3, 4, 5, 9, 10, 14, 19, 21],
    desc: "AppInit DLLs, IFEO debugger hijack, COM, LSA packages, print monitors, network providers, cmd AutoRun, Netsh helpers" },
  { id: "shell", name: "Shell & Browser", rules: [6, 8, 20],
    desc: "Explorer shell extensions, browser helper objects, ShellServiceObjectDelayLoad" },
  { id: "supp", name: "Supplementary", rules: [11, 12, 13],
    desc: "Active Setup stub paths, startup folder registry, task definitions" },
  { id: "hijack", name: "Execution Hijacks", rules: [15, 16, 17, 18, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
    desc: "Logon scripts, AppCert/SilentProcessExit, credential providers, screensaver, Office add-ins, time providers, RDP InitialProgram, file associations, GPO scripts, SSP, COR_PROFILER, Winlogon Notify, COM TreatAs, Defender exclusions" },
];

// ── Intent selector ───────────────────────────────────────────────────────
export const PA_INTENTS = [
  { id: "low-noise", label: "Low-noise triage",
    desc: "High-confidence only — services, WMI, core autoruns, account creation, high-value AD changes",
    disabled: [
      // Task lifecycle churn
      "evtx-3", "evtx-4", "evtx-5", "evtx-7", "evtx-19", "evtx-20", "evtx-21",
      // Registry key create/rename churn + unsigned DLL loads
      "evtx-13", "evtx-14", "evtx-16",
      // Routine account maintenance + AD object creation
      "evtx-26", "evtx-27", "evtx-29",
      // Low-fidelity registry fallback (only useful when Sysmon 12/13/14 are absent)
      "evtx-33",
      // Registry locations dominated by OS defaults
      "reg-6", "reg-8", "reg-11", "reg-12", "reg-13",
    ] },
  { id: "balanced", label: "Balanced", desc: "Recommended — all detection categories enabled", disabled: [] },
  { id: "broad", label: "Broad hunt", desc: "Maximum coverage — includes DLL hijacking and task lifecycle", disabled: [] },
];
