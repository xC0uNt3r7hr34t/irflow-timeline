---
description: Persistence Analyzer — 36 EVTX and 33 registry detection rules with automated risk scoring and MITRE ATT&CK mapping.
---

# Persistence Analyzer

The Persistence Analyzer automatically scans your timeline data for Windows persistence mechanisms, scoring each finding by risk level and organizing results by category. It supports both EVTX event logs and registry exports (RECmd CSV and similar), with **69 built-in rule definitions** — **36 EVTX event-log rules** and **33 registry key-family rules** — across services, scheduled tasks, WMI subscriptions, autorun keys, and related locations.

![Persistence Analyzer showing 8648 findings in Timeline view with severity scores, service installations, and category filtering](/dfir-tips/Persistence-Analyzer.png)

## Opening the Persistence Analyzer

- **Menu:** **Tools → Platforms → Windows → Persistence Analyzer**

## Data Source Modes

The analyzer supports tab-level modes plus multi-source and whole-collection scans:

| Mode | Input Data | Best For |
|------|-----------|----------|
| **Auto-detect** | Analyzes column names to determine type | Quick start — let the tool decide |
| **EVTX Logs** | EvtxECmd CSV or parsed EVTX output | Event-based persistence (services, tasks, WMI) |
| **Registry Export** | RECmd or other registry CSV output | Registry-based persistence (Run keys, COM hijacks, LSA) |
| **Multi-source** | Several open tabs in one run | Correlate EVTX + registry (or multiple hosts) without re-import |
| **Analyze KAPE Collection** | A KAPE output **folder** | Folder-level EVTX + registry discovery, incident clustering, and unread-artifact warnings |

In auto-detect mode, the analyzer examines your column headers to determine whether the data contains event log fields (`EventId`, `Channel`, `Provider`) or registry fields (`KeyPath`, `ValueName`, `ValueData`).

### Multi-source and KAPE collection

- **Multi-source** — enable in the config panel and select other open tabs to merge. Formats are detected per tab so service-install events and RECmd rows can cluster into the same incident when they describe the same host/key.
- **Analyze KAPE Collection** — browse to a collection root; IRFlow scans for supported EVTX and registry exports, runs the matching rule packs, clusters findings into **incidents**, and reports coverage gaps (for example EVTX files present but not read). Prefer this when the evidence is still a folder rather than a single imported CSV.

Handoffs from the [Process Inspector](/features/process-tree) detail panel (**Persistence**) open this analyzer with host + time context already applied.

## EVTX Detection Rules

When analyzing event logs, the Persistence Analyzer applies **36 EVTX rule definitions** across multiple log channels:

### Services

| Event ID | Source | Description |
|----------|--------|-------------|
| 7045 | System | New service installed |
| 4697 | Security | Service installed (auditing) |

### Scheduled Tasks

| Event ID | Source | Description |
|----------|--------|-------------|
| 4698 | Security | Scheduled task created |
| 4699 | Security | Scheduled task deleted |
| 106 | Task Scheduler | Task registered |
| 129 | Task Scheduler | Task launch attempt |
| 118 | Task Scheduler | Boot trigger fired |
| 119 | Task Scheduler | Logon trigger fired |
| 140 | Task Scheduler | Task updated |
| 141 | Task Scheduler | Task deleted |
| 200 | Task Scheduler | Task action started |

### WMI Persistence

| Event ID | Source | Description |
|----------|--------|-------------|
| 5861 | WMI-Activity | WMI permanent event consumer registered |
| Sysmon 19 | Sysmon | WMI event filter created |
| Sysmon 20 | Sysmon | WMI event consumer created |
| Sysmon 21 | Sysmon | WMI filter-to-consumer binding |

### Registry Indicators

| Event ID | Source | Category | Description |
|----------|--------|----------|-------------|
| Sysmon 13 | Sysmon | Registry Autorun | Registry value set (autorun modifications) |
| Sysmon 12 | Sysmon | Registry Modification | Registry key created or deleted |
| Sysmon 14 | Sysmon | Registry Rename | Registry key or value renamed |

### File System Indicators

| Event ID | Source | Category | Description |
|----------|--------|----------|-------------|
| Sysmon 11 | Sysmon | Startup Folder | File created in startup directory |
| Sysmon 7 | Sysmon | DLL Hijacking | Unsigned or suspicious DLL loaded |
| Sysmon 6 | Sysmon | Driver Loading | Suspicious driver loaded |
| Sysmon 25 | Sysmon | Process Tampering | Process tampering detected |

### Account Persistence

| Event ID | Source | Description |
|----------|--------|-------------|
| 4720 | Security | User account created |
| 4724 | Security | Password reset attempt |
| 4728 | Security | Member added to global security group |
| 4732 | Security | Member added to local security group |
| 4756 | Security | Member added to universal security group |

## Registry Detection Rules

When analyzing registry exports, the analyzer applies **33 registry key-family rules**. Representative families include:

| Family | Examples | Technique |
|--------|----------|-----------|
| Run / RunOnce | `...\CurrentVersion\Run`, `RunOnce`, `Policies\Explorer\Run` | Autostart execution |
| Services | `...\Services\*\ImagePath`, `ServiceDll` | Service DLL/binary |
| Winlogon / LSA | `Shell`, `Userinit`, `Notify`, Security/Authentication packages | Logon / credential interception |
| IFEO / AppInit / AppCert | Debugger hijack, `AppInit_DLLs`, `AppCertDlls` | DLL injection / API hooking |
| COM / Shell / BHO | `InprocServer32`, shell handlers, Browser Helper Objects | COM / Explorer persistence |
| Boot / Session Manager | `BootExecute`, `SetupExecute` | Pre-logon execution |
| Tasks / GPO / Network | `TaskCache`, Group Policy scripts, `NetworkProvider\Order` | Scheduled / logon scripts |
| Defender tampering | Exclusions, real-time protection disabled | AV weakening (T1562.001) |

Additional rules cover screensaver hijack, Office add-ins, time providers, terminal-server `InitialProgram`, file-association hijacks, environment/COR_PROFILER abuse, and related DFIR-relevant paths. Each built-in registry rule can be toggled in the Detection Rules panel.

## Custom Rules Editor

The configuration panel includes a collapsible **Detection Rules** section where you can manage both built-in and custom rules.

### Managing Built-in Rules

Each built-in EVTX and registry rule has a checkbox toggle. Disable rules that generate noise for your specific environment without removing them. Disabled rules are skipped during analysis.

### Creating Custom Rules

Click **Add Custom Rule** to create a new detection rule:

**EVTX custom rules:**

| Field | Description |
|-------|-------------|
| **Category** | Grouping label shown in results (e.g., "Custom Persistence") |
| **Rule Name** | Descriptive name for the detection |
| **Event IDs** | Comma-separated list of Windows Event IDs to match |
| **Channels** | Comma-separated log channels to filter (optional) |
| **Payload Regex** | Regular expression to filter on event payload content (optional) |
| **Severity** | Critical, High, Medium, or Low |

**Registry custom rules:**

| Field | Description |
|-------|-------------|
| **Category** | Grouping label shown in results |
| **Rule Name** | Descriptive name for the detection |
| **Key Path Pattern** | Regex matching the registry key path |
| **Value Name Filter** | Regex filtering the value name (optional) |
| **Severity** | Critical, High, Medium, or Low |

Custom rules are evaluated alongside built-in rules and appear in results with the same scoring and filtering behavior.

## Risk Scoring

Each detected persistence mechanism receives a risk score on a 0-10 scale. The score is calculated from:

1. **Base severity** -- determined by the persistence technique category (e.g., WMI subscriptions score higher than Run keys)
2. **Suspicious path indicators** -- execution from `\Temp\`, `\AppData\`, `\Downloads\`, or `\ProgramData\` increases the score
3. **Suspicious commands** -- presence of `powershell`, `cmd.exe`, encoded commands, or known LOLBins raises the score
4. **Encoding and download cradle detection** -- Base64-encoded command lines, obfuscated payloads, or PowerShell download cradles (`iex`, `Invoke-Expression`, `DownloadString`, `WebClient`, `BITSTransfer`) add to the score

### Severity Levels

| Level | Score Range | Color |
|-------|-----------|-------|
| **Critical** | 9-10 | Red |
| **High** | 6-8 | Orange |
| **Medium** | 3-5 | Yellow |
| **Low** | 0-2 | Gray |

## Suspicious Detection Badges

Beyond the numeric risk score, findings can receive a red **SUSPICIOUS** badge when specific behavioral patterns are detected:

| Detection | Trigger |
|-----------|---------|
| **Non-standard task path** | Task name doesn't start with a known-good prefix (`\Microsoft\`, `\Google\`, etc.) |
| **GUID-named task** | Task name is a bare GUID (e.g., `\{6D3B4F8C-1234-...}`) — often used by malware to blend in |
| **LOLBin execution** | Command uses `powershell`, `cmd.exe`, `mshta`, `wscript`, or `cscript` in a non-Microsoft task or service |
| **User-writable path** | Executable runs from `\Users\`, `\Temp\`, `\AppData\`, `\Downloads\`, or `\Public\` |
| **Non-standard task deleted** | Event ID 141 for a non-Microsoft task — potential anti-forensics indicator |
| **Browser mimicry** | Service uses a browser name (Chrome, Edge, Firefox) but runs from a non-standard path |

## RMM Tool Detection

Service installations (Event ID 7045) matching known Remote Monitoring and Management tool names are flagged with an orange **RMM** badge. Detected tools include:

AnyDesk, Splashtop, RustDesk, Atera, ScreenConnect, TeamViewer, Supremo, ConnectWise, Bomgar, LogMeIn

RMM tools are not inherently malicious, but they are high-confidence indicators in ransomware and unauthorized access investigations. The badge helps analysts quickly identify remote access tooling in the environment.

## AV/EDR and Browser Whitelisting

The analyzer automatically suppresses known-legitimate findings to reduce noise:

- **AV/EDR vendors** — Service installations from 15 vendors (Cortex XDR, Microsoft Defender, CrowdStrike, SentinelOne, Carbon Black, Sophos, Symantec, McAfee/Trellix, Kaspersky, ESET, Trend Micro, Bitdefender, Cylance, Elastic, Fortinet) are suppressed when they match expected installation paths
- **Browser update services** — Chrome, Edge, Firefox, Brave, Opera, and Vivaldi update services from expected `Program Files` paths are downgraded to low severity

This whitelisting prevents hundreds of false-positive service events from cluttering results while preserving detection of the same service names running from unexpected paths (flagged as browser mimicry).

## Results Interface

After the scan completes, the results panel displays five key statistics:

- **Total Found** -- total number of persistence mechanisms detected
- **Critical** -- count of critical-severity findings
- **High** -- count of high-severity findings
- **Suspicious** -- count of findings with behavioral detection badges
- **Categories** -- number of distinct persistence categories

### Filtering Results

The results panel includes a filter bar with:

- **Search** -- full-text search across all findings
- **Severity filter** -- show only critical, high, medium, or low findings
- **Category filter** -- filter by persistence type (Services, Scheduled Tasks, WMI, Registry Autorun, DLL Hijacking, etc.)

### View Modes

Results can be displayed in three different layouts:

#### Grouped View

Findings organized under collapsible category headers (e.g., "Services", "Scheduled Tasks", "WMI Subscriptions", "Registry Autorun", "DLL Hijacking", "Driver Loading", "Process Tampering"). Each category shows its finding count. Up to 200 items are displayed per category.

#### Timeline View

Findings sorted chronologically, showing when each persistence mechanism was installed. This view reveals the temporal sequence of persistence activity and is limited to 500 items for performance.

#### Table View

A flat tabular view of all findings with sortable columns. No item limit -- all findings are displayed.

### Item Details

Click any finding to expand its details panel showing:

- Full registry path or event log entry
- Command line or executable path
- Timestamp of installation
- Associated user account
- Source host
- Risk score breakdown
- Suspicious reason badges (if any)

### Bulk Operations

Use the checkbox selection to select multiple findings for:

- Bulk tagging in the source timeline
- Filtering the source tab to selected items
- Exporting selected findings

## Cross-Event Correlation

The analyzer automatically correlates related events. For example:

- A scheduled task creation (Event ID 4698) is enriched with the task executable extracted from the XML task definition
- Service installations (Event ID 7045) are correlated with their `ImagePath` to identify the binary
- WMI subscriptions link filter, consumer, and binding events into a single finding

## Filter Awareness

The Persistence Analyzer respects all active filters on the source tab:

- Column filters
- Checkbox filters
- Search terms
- Date range filters
- Bookmark filter
- Advanced filters

This means you can narrow your timeline to a specific time window or host before running the analysis, focusing results on the scope that matters.

## Investigation Tips

::: tip Start with Auto-Detect
Let the analyzer auto-detect your data mode. It correctly identifies EVTX vs registry data in most cases and saves configuration time.
:::

::: tip Focus on Critical and High
Sort by severity and start with critical/high findings. Low-severity items often represent legitimate system services and can be reviewed later if needed.
:::

::: tip Check the SUSPICIOUS Badge
Findings with the red SUSPICIOUS badge deserve immediate attention. GUID-named tasks, LOLBin execution from non-Microsoft services, and anti-forensics task deletion are strong indicators of compromise.
:::

::: tip RMM Tools in Ransomware Cases
In ransomware investigations, check the RMM-tagged findings first. Threat actors commonly deploy AnyDesk, ScreenConnect, or Splashtop for persistent remote access before deploying ransomware.
:::

::: tip Combine with Process Inspector
After identifying a suspicious persistence mechanism, use the [Process Inspector](/features/process-tree) to trace what process installed it and what the persisted binary spawns on execution.
:::

::: tip Correlate with Lateral Movement
Persistence is often installed after lateral movement. Cross-reference persistence timestamps with the [Lateral Movement Tracker](/features/lateral-movement) to identify which hop preceded each persistence installation.
:::

## See Also

- [Process Inspector](/features/process-tree) — trace what process installed each persistence mechanism
- [Lateral Movement Tracker](/features/lateral-movement) — correlate persistence with lateral movement hops
- [IOC Matching](/features/ioc-matching) — match persisted executables and registry paths against threat intel
- [Gap & Burst Analysis](/features/gap-burst-analysis) — identify when persistence was installed relative to other activity
