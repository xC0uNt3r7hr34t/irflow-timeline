/**
 * analyzers/persistence/rules.js — Persistence detection rule definitions
 *
 * Single source of truth for the EVTX + registry rule sets. Hoisted out of
 * getPersistenceAnalysis() so that:
 *   1. the rule objects (and their regexes) are built once at require time
 *      instead of on every analysis run, and
 *   2. PERSISTENCE_RULE_CATALOG can be derived from the same arrays the
 *      analyzer actually runs, giving the renderer a positional rule list
 *      that cannot silently drift from the engine.
 *
 * Rule ORDER IS API: the modal's enable/disable toggles, technique presets and
 * intent sets all key off positional `evtx-<i>` / `reg-<i>` ids. Append new
 * rules at the END of the array; never reorder or splice. tests/persistence-rule-catalog.test.js
 * pins analyzer order against src/constants/persistenceRuleCatalog.mjs.
 */

// --- Detection rules ---
// Regex helper: match "Key: Value" in EvtxECmd PayloadData (pipe-delimited haystack)
// EvtxECmd formats vary: "Name: Svc", "Task: \Path", "ServiceName: Svc", "Image: C:\..."
// Match "Key: Value" and stop at end-of-part, a pipe (EvtxECmd/raw join), OR the
// Hayabusa broken-bar "¦" KV separator — otherwise on Hayabusa/Chainsaw data the
// lazy capture runs past "¦" into the next field, polluting serviceName/taskName/
// member/etc and breaking correlation. The (?:^|\b) anchor stops a short key like
// "Name" from binding inside a longer one ("ServiceName"/"DisplayName"). Commas are
// intentionally NOT delimiters (they appear inside DNs and command lines).
const P = (key) => new RegExp("(?:^|\\b)" + key + ":\\s*(.+?)(?:\\s*$|\\s*[|¦])", "i");
const EVTX_RULES = [
  // --- Services ---
  { category: "Services", name: "Service Installed", eventIds: ["7045"], channels: ["system"], severity: "high",
    // EvtxECmd 7045 (System): PD2="Name: SvcName", PD3="StartType:", PD4="Account:", ExecutableInfo=ImagePath
    // Raw .evtx 7045 spells it out as ServiceName/ImagePath, so try the explicit keys
    // first and fall back to EvtxECmd's bare "Name:"/"Path:".
    extractors: { serviceName: [P("ServiceName"), P("Name")], imagePath: [P("ImagePath"), P("ServiceFileName"), P("Path")], startType: [P("StartType")], account: [P("Account"), P("AccountName")] },
    topFields: ["serviceName", "imagePath", "account"], useExecInfo: "imagePath", payloadFilter: null },
  { category: "Services", name: "Service Installed", eventIds: ["4697"], channels: ["security"], severity: "high",
    // imagePath mirrors 7045 so service-execution correlation (which keys on details.imagePath) works for 4697 too.
    extractors: { serviceName: [P("ServiceName")], imagePath: [P("ServiceFileName"), P("ImagePath"), P("Path")], serviceFile: [P("ServiceFileName")], serviceType: [P("ServiceType")], startType: [P("ServiceStartType")], account: [P("ServiceAccount")] },
    topFields: ["serviceName", "imagePath", "account"], useExecInfo: "imagePath", payloadFilter: null },
  // --- Scheduled Tasks ---
  { category: "Scheduled Tasks", name: "Scheduled Task Created", eventIds: ["4698"], channels: ["security"], severity: "high",
    extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")], command: [P("Command"), P("Arguments"), P("Actions")] },
    topFields: ["taskName", "command", "executable"], useExecInfo: "executable", payloadFilter: null },
  { category: "Scheduled Tasks", name: "Scheduled Task Deleted", eventIds: ["4699"], channels: ["security"], severity: "medium",
    extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")] },
    topFields: ["taskName"], payloadFilter: null },
  { category: "Scheduled Tasks", name: "Task Registered", eventIds: ["106"], channels: ["taskscheduler"], severity: "medium",
    // EvtxECmd 106 (TaskScheduler/Operational): PD2="Task: \Name", ExecutableInfo=empty for this event
    extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
    topFields: ["taskName"], payloadFilter: null },
  { category: "Scheduled Tasks", name: "Task Updated", eventIds: ["140"], channels: ["taskscheduler"], severity: "medium",
    extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
    topFields: ["taskName"], payloadFilter: null },
  { category: "Scheduled Tasks", name: "Task Process Created", eventIds: ["129"], channels: ["taskscheduler"], severity: "high",
    // EvtxECmd 129 (TaskScheduler/Operational): PD2="Task: \Name", PD3="ProcessID:", ExecutableInfo=exe path
    // Raw .evtx 129: TaskName + Path (the launched image) + ProcessID — no ExecutableInfo column,
    // so `executable` has to come from Path or the finding carries no command at all.
    extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], executable: [P("Path")], processId: [P("ProcessID"), P("ProcessId")] },
    topFields: ["taskName", "executable", "processId"], useExecInfo: "executable", payloadFilter: null },
  { category: "Scheduled Tasks", name: "Task Action Started", eventIds: ["200"], channels: ["taskscheduler"], severity: "medium",
    // EvtxECmd 200 (TaskScheduler/Operational): PD2="Task: \Name", ExecutableInfo=action/handler name
    // Raw .evtx 200: TaskName + ActionName (the action's image path or COM handler GUID).
    extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], executable: [P("ActionName")], instanceId: [P("Instance Id"), P("TaskInstanceId")] },
    topFields: ["taskName", "executable"], useExecInfo: "executable", payloadFilter: null },
  // --- WMI ---
  { category: "WMI Persistence", name: "WMI Event Subscription", eventIds: ["5861"], channels: ["wmi-activity"], severity: "critical",
    extractors: { namespace: [P("Namespace")], operation: [P("Operation")], query: [P("Query")], consumer: [P("Consumer")], poss_command: [P("PossibleCause"), P("Command")] },
    topFields: ["operation", "query", "consumer"], payloadFilter: null },
  { category: "WMI Persistence", name: "WMI EventFilter Created", eventIds: ["19"], channels: ["sysmon"], severity: "critical",
    extractors: { name: [P("Name")], query: [P("Query")], eventNamespace: [P("EventNamespace")], operation: [P("Operation")] },
    topFields: ["name", "query", "operation"], payloadFilter: null },
  { category: "WMI Persistence", name: "WMI EventConsumer Created", eventIds: ["20"], channels: ["sysmon"], severity: "critical",
    extractors: { name: [P("Name")], type: [P("Type")], destination: [P("Destination")], operation: [P("Operation")] },
    topFields: ["name", "destination", "type"], payloadFilter: null },
  { category: "WMI Persistence", name: "WMI Binding Created", eventIds: ["21"], channels: ["sysmon"], severity: "critical",
    extractors: { consumer: [P("Consumer")], filter: [P("Filter")], operation: [P("Operation")] },
    topFields: ["consumer", "filter"], payloadFilter: null },
  // --- Registry (Sysmon) ---
  { category: "Registry Autorun", name: "Registry Value Set", eventIds: ["13"], channels: ["sysmon"], severity: "high",
    extractors: { targetObject: [P("TargetObject"), P("TgtObj")], details: [P("Details")], image: [P("Image")] },
    topFields: ["targetObject", "details", "image"],
    payloadFilter: /\\(?:Run|RunOnce|RunServices|Services\\[^\\]*\\(?:ImagePath|Parameters)|Winlogon\\(?:Shell|Userinit|Notify|Taskman|VmApplet|AppSetup)|AppInit_DLLs|Image File Execution Options\\[^\\]*\\Debugger|CurrentVersion\\Explorer\\(?:Shell|User Shell)|Session Manager\\(?:BootExecute|SetupExecute|AppCertDlls)|InprocServer32|LocalServer32|ShellIconOverlay|ShellServiceObjectDelayLoad|ContextMenuHandler|Browser Helper|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\|Control\\SecurityProviders|GPExtensions\\|Group Policy\\Scripts|System\\Scripts\\|TreatAs(?:\\|$)|Windows Defender\\Exclusions|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunOnceEx)|SilentProcessExit\\|Environment\\(?:$|\\)|COR_PROFILER|Credential Provid|PLAP Providers\\|Command Processor\\|Microsoft\\Netsh|Control Panel\\Desktop|Office\\[^\\]*\\[^\\]*\\Addins\\|W32Time\\TimeProviders\\|Terminal Server\\|shell\\open\\command|FileExts\\)/i },
  { category: "Registry Modification", name: "Registry Key Created/Deleted", eventIds: ["12"], channels: ["sysmon"], severity: "medium",
    extractors: { targetObject: [P("TargetObject"), P("TgtObj")], eventType: [P("EventType")], image: [P("Image")] },
    topFields: ["eventType", "targetObject", "image"],
    // NOTE: bare "Services\\" intentionally excluded — CreateKey/DeleteKey on a service
    // key is overwhelmingly benign install/uninstall/update churn. The meaningful signal
    // (ImagePath/ServiceDll SetValue) is caught by EID 13 / 4657 instead.
    payloadFilter: /\\(?:Run|RunOnce|Winlogon|AppInit_DLLs|Image File Execution Options|Session Manager\\(?:BootExecute|AppCertDlls)|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\|Control\\SecurityProviders|GPExtensions\\|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)|SilentProcessExit\\|Credential Provid|PLAP Providers\\|ShellServiceObjectDelayLoad|Command Processor\\|Microsoft\\Netsh|Control Panel\\Desktop|Office\\[^\\]*\\[^\\]*\\Addins\\|W32Time\\TimeProviders\\|Terminal Server\\|shell\\open\\command|FileExts\\)/i },
  { category: "Registry Rename", name: "Registry Key/Value Renamed", eventIds: ["14"], channels: ["sysmon"], severity: "medium",
    extractors: { targetObject: [P("TargetObject")], newName: [P("NewName")], eventType: [P("EventType")] },
    topFields: ["targetObject", "newName"],
    payloadFilter: /\\(?:Run|RunOnce|Services\\|Winlogon|Image File Execution Options|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)|SilentProcessExit\\|AppCertDlls|Credential Provid|PLAP Providers\\|ShellServiceObjectDelayLoad|Command Processor\\|Microsoft\\Netsh|Control Panel\\Desktop|Office\\[^\\]*\\[^\\]*\\Addins\\|W32Time\\TimeProviders\\|Terminal Server\\|shell\\open\\command|FileExts\\)/i },
  // --- File system (Sysmon) ---
  { category: "Startup Folder", name: "File Created in Startup", eventIds: ["11"], channels: ["sysmon"], severity: "high",
    extractors: { targetFilename: [P("TargetFilename")], image: [P("Image")], creationTime: [P("CreationUtcTime")] },
    topFields: ["targetFilename", "image"],
    payloadFilter: /Start Menu\\Programs\\Startup|ProgramData\\Microsoft\\Windows\\Start Menu|\\Startup\\[^\\]*\.(exe|dll|bat|cmd|ps1|vbs|js|lnk|url)$/i },
  { category: "DLL Hijacking", name: "Unsigned DLL Loaded", eventIds: ["7"], channels: ["sysmon"], severity: "medium",
    extractors: { imageLoaded: [P("ImageLoaded")], signed: [P("Signed")], signatureStatus: [P("SignatureStatus")], image: [P("Image")] },
    topFields: ["imageLoaded", "image", "signatureStatus"],
    payloadFilter: /Signed:\s*false/i },
  { category: "Driver Loading", name: "Suspicious Driver Loaded", eventIds: ["6"], channels: ["sysmon"], severity: "critical",
    extractors: { imageLoaded: [P("ImageLoaded")], signed: [P("Signed")], signatureStatus: [P("SignatureStatus")], signer: [P("Signer")] },
    topFields: ["imageLoaded", "signatureStatus", "signer"],
    payloadFilter: /Signed:\s*false|SignatureStatus:\s*(?:Expired|Revoked|Invalid|Unavailable)/i },
  { category: "Process Tampering", name: "Process Tampering Detected", eventIds: ["25"], channels: ["sysmon"], severity: "critical",
    extractors: { type: [P("Type")], image: [P("Image")] },
    topFields: ["image", "type"], payloadFilter: null },
  // --- Task Scheduler lifecycle (anti-forensics / trigger tracking) ---
  { category: "Scheduled Tasks", name: "Task Deleted", eventIds: ["141"], channels: ["taskscheduler"], severity: "high",
    extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], userName: [P("UserName"), P("User")] },
    topFields: ["taskName", "userName"], payloadFilter: null },
  { category: "Scheduled Tasks", name: "Boot Trigger Fired", eventIds: ["118"], channels: ["taskscheduler"], severity: "medium",
    extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
    topFields: ["taskName"], payloadFilter: null },
  { category: "Scheduled Tasks", name: "Logon Trigger Fired", eventIds: ["119"], channels: ["taskscheduler"], severity: "medium",
    extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], userName: [P("UserName"), P("User")] },
    topFields: ["taskName", "userName"], payloadFilter: null },
  // --- Account Persistence (DFIR report-derived: 7/11 reports) ---
  { category: "Account Persistence", name: "User Account Created", eventIds: ["4720"], channels: ["security"], severity: "high",
    extractors: { targetUser: [P("TargetUserName"), P("Target_User_Name")], subjectUser: [P("SubjectUserName")], samAccountName: [P("SamAccountName"), P("SAMAccountName")] },
    topFields: ["targetUser", "subjectUser", "samAccountName"], payloadFilter: null },
  { category: "Account Persistence", name: "Member Added to Global Security Group", eventIds: ["4728"], channels: ["security"], severity: "critical",
    extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName"), P("Member_Name")], memberSid: [P("MemberSid"), P("Member_Sid"), P("Member_Security_ID")], subjectUser: [P("SubjectUserName")] },
    topFields: ["groupName", "memberName", "memberSid", "subjectUser"], payloadFilter: null },
  { category: "Account Persistence", name: "Member Added to Local Security Group", eventIds: ["4732"], channels: ["security"], severity: "high",
    extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName")], memberSid: [P("MemberSid"), P("Member_Sid"), P("Member_Security_ID")], subjectUser: [P("SubjectUserName")] },
    topFields: ["groupName", "memberName", "memberSid", "subjectUser"], payloadFilter: null },
  { category: "Account Persistence", name: "Member Added to Universal Security Group", eventIds: ["4756"], channels: ["security"], severity: "critical",
    extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName")], memberSid: [P("MemberSid"), P("Member_Sid"), P("Member_Security_ID")], subjectUser: [P("SubjectUserName")] },
    topFields: ["groupName", "memberName", "memberSid", "subjectUser"], payloadFilter: null },
  { category: "Account Persistence", name: "User Password Reset", eventIds: ["4724"], channels: ["security"], severity: "medium",
    extractors: { targetUser: [P("TargetUserName")], subjectUser: [P("SubjectUserName")] },
    topFields: ["targetUser", "subjectUser"], payloadFilter: null },
  { category: "Account Persistence", name: "User Account Changed", eventIds: ["4738"], channels: ["security"], severity: "high",
    extractors: {
      targetUser: [P("TargetUserName"), P("Target_User_Name")],
      subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
      samAccountName: [P("SamAccountName"), P("SAMAccountName")],
      scriptPath: [P("ScriptPath"), P("Script_Path")],
      userAccountControl: [P("UserAccountControl"), P("User_Account_Control"), P("NewUacValue")],
      homeDirectory: [P("HomeDirectory"), P("Home_Directory")],
      profilePath: [P("ProfilePath"), P("Profile_Path")],
      userParameters: [P("UserParameters"), P("User_Parameters")],
      primaryGroupId: [P("PrimaryGroupId"), P("Primary_Group_Id")],
      allowedToDelegateTo: [P("AllowedToDelegateTo"), P("Allowed_To_Delegate_To")],
    },
    topFields: ["targetUser", "subjectUser", "scriptPath", "userAccountControl"],
    payloadFilter: null },
  // --- Domain Persistence (AD object changes: 5136/5137/5141) ---
  { category: "Domain Persistence", name: "AD Object Modified", eventIds: ["5136"], channels: ["security"], severity: "high",
    extractors: {
      objectDN: [P("ObjectDN"), P("Object_DN")],
      objectClass: [P("ObjectClass"), P("Object_Class")],
      attributeName: [P("AttributeLDAPDisplayName"), P("Attribute_LDAP_Display_Name"), P("AttributeName")],
      attributeValue: [P("AttributeValue"), P("Attribute_Value")],
      operationType: [P("OperationType"), P("Operation_Type")],
      subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
    },
    topFields: ["objectDN", "attributeName", "attributeValue", "subjectUser"],
    payloadFilter: /(?:AdminSDHolder|CN=Policies|scriptPath|servicePrincipalName|userAccountControl|adminCount|member(?:Of)?|gPCFileSysPath|gPCMachineExtensionNames|gPCUserExtensionNames|msDS-AllowedToDelegateTo|msDS-KeyCredentialLink|SIDHistory|nTSecurityDescriptor)/i },
  { category: "Domain Persistence", name: "AD Object Created", eventIds: ["5137"], channels: ["security"], severity: "medium",
    extractors: {
      objectDN: [P("ObjectDN"), P("Object_DN")],
      objectClass: [P("ObjectClass"), P("Object_Class")],
      subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
    },
    topFields: ["objectDN", "objectClass", "subjectUser"],
    payloadFilter: /(?:AdminSDHolder|CN=Policies|groupPolicyContainer|trustedDomain|msDS-ManagedServiceAccount|msDS-GroupManagedServiceAccount)/i },
  { category: "Domain Persistence", name: "AD Object Deleted", eventIds: ["5141"], channels: ["security"], severity: "high",
    extractors: {
      objectDN: [P("ObjectDN"), P("Object_DN")],
      objectClass: [P("ObjectClass"), P("Object_Class")],
      subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
    },
    topFields: ["objectDN", "objectClass", "subjectUser"],
    payloadFilter: /(?:AdminSDHolder|CN=Policies|groupPolicyContainer|trustedDomain)/i },
  // --- Service start type change (7040): detect auto-start flipping ---
  // 7040 fields: param1 = DISPLAY name, param2 = old start type, param3 = new start type,
  // param4 = SERVICE name. serviceName must prefer param4 — the service-execution
  // correlation below keys 7036/7035 (which report the display name) through
  // SVC_DISPLAY_ALIASES, and 7045 reports the short service name, so binding
  // serviceName to param1 puts this rule on a different key from every other
  // Services rule and the correlation silently misses. param1 is kept as displayName.
  { category: "Services", name: "Service StartType Changed", eventIds: ["7040"], channels: ["system"], severity: "high",
    extractors: {
      serviceName: [P("param4"), P("ServiceName"), P("param1"), P("Name")],
      displayName: [P("param1"), P("DisplayName")],
      oldStartType: [P("param2"), P("OldStartType")],
      newStartType: [P("param3"), P("NewStartType")],
    },
    topFields: ["serviceName", "oldStartType", "newStartType"], payloadFilter: null },
  // --- Security 4702: Scheduled task updated (Security log fallback for 140) ---
  { category: "Scheduled Tasks", name: "Task Updated (Security)", eventIds: ["4702"], channels: ["security"], severity: "medium",
    extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")], command: [P("Command"), P("Actions")] },
    topFields: ["taskName", "command"], payloadFilter: null },
  // --- Security 4657: Registry audit fallback when Sysmon 12/13/14 are absent ---
  { category: "Registry Autorun", name: "Registry Value Modified (4657)", eventIds: ["4657"], channels: ["security"], severity: "high",
    extractors: {
      targetObject: [P("ObjectName"), P("Object Name")],
      valueName: [P("ObjectValueName"), P("Object Value Name")],
      newValue: [P("NewValue"), P("New Value")],
      oldValue: [P("OldValue"), P("Old Value")],
      image: [P("ProcessName"), P("Process Name"), P("SubjectProcessName")],
      subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
    },
    topFields: ["targetObject", "valueName", "newValue", "image"],
    payloadFilter: /\\(?:Run|RunOnce|RunServices|Services\\[^\\]*\\(?:ImagePath|Parameters|ServiceDll|FailureCommand)|Winlogon\\(?:Shell|Userinit|Notify|Taskman|VmApplet|AppSetup)|AppInit_DLLs|LoadAppInit_DLLs|Image File Execution Options\\[^\\]*\\Debugger|CurrentVersion\\Explorer\\(?:Shell|User Shell)|Session Manager\\(?:BootExecute|SetupExecute|AppCertDlls)|InprocServer32|LocalServer32|ShellIconOverlay|ShellServiceObjectDelayLoad|ContextMenuHandler|Browser Helper|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\|Control\\SecurityProviders|GPExtensions\\|Group Policy\\Scripts|System\\Scripts\\|TreatAs(?:\\|$)|Windows Defender\\Exclusions|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunOnceEx)|SilentProcessExit\\|Environment\\(?:$|\\)|COR_PROFILER|Credential Provid|PLAP Providers\\|Command Processor\\|Microsoft\\Netsh|Control Panel\\Desktop|Office\\[^\\]*\\[^\\]*\\Addins\\|W32Time\\TimeProviders\\|Terminal Server\\|shell\\open\\command|FileExts\\)/i },
  // --- Defender tampering (Microsoft-Windows-Windows Defender/Operational) ---
  { category: "Defender Tampering", name: "Defender Protection Disabled", eventIds: ["5001", "5010", "5012", "5101"], channels: ["defender"], severity: "high",
    extractors: { newValue: [P("New Value"), P("NewValue")], oldValue: [P("Old Value"), P("OldValue")], feature: [P("Feature Name"), P("Product Name")] },
    topFields: ["feature", "newValue", "oldValue"], payloadFilter: null },
  { category: "Defender Tampering", name: "Defender Setting Changed", eventIds: ["5007"], channels: ["defender"], severity: "medium",
    extractors: { newValue: [P("New Value"), P("NewValue")], oldValue: [P("Old Value"), P("OldValue")] },
    topFields: ["newValue", "oldValue"],
    // 5007 fires on every signature update — only surface tamper-relevant settings.
    payloadFilter: /Exclusions|DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableArchiveScanning|DisableScanningNetworkFiles|DisableOnAccessProtection|SubmitSamplesConsent|MpEnablePus|TamperProtection|PUAProtection|DisableBlockAtFirstSeen/i },
  // --- Task definition read from disk (Windows\System32\Tasks\<path>) ---
  // Not an event: this is the registered task itself, synthesized into a row by
  // ./collection-analysis.js so the existing task rules, scoring and suppression apply.
  // Unlike 4698/140 it covers EVERY registered task, including ones that never fired
  // inside the log window, and it carries the COMPLETE definition — so Hidden, RunLevel,
  // ComHandler and the trigger set are read rather than inferred from truncated event text.
  // `eventIds` is a sentinel, never a real Windows event id.
  { category: "Scheduled Tasks", name: "Scheduled Task Defined", eventIds: ["TASKXML"], channels: ["taskscheduler"], severity: "medium",
    extractors: { taskName: [P("TaskName"), P("Task")], command: [P("Command")], executable: [P("Path")], userName: [P("UserContext"), P("UserId")] },
    topFields: ["taskName", "command"], payloadFilter: null },
  // --- Remote execution: how the persistence got here ---
  // These are NOT persistence mechanisms. They are the arrival: the remote operation that
  // created the service/task/registry value sitting next to them in time. The analyzer
  // deliberately does not grow a logon engine (that is lateral movement's job) — it owns
  // only the remote-execution events whose payload names the machine on the other end, so
  // a persistence artifact can be tied to the pivot that planted it. See _remoteOrigin.
  { category: "Remote Execution", name: "WMI Remote Operation", eventIds: ["5857", "5858", "5860"], channels: ["wmi-activity"], severity: "medium",
    extractors: {
      clientMachine: [P("ClientMachine"), P("ClientMachineFQDN")],
      remoteUser: [P("User"), P("TargetUserName")],
      operation: [P("Operation"), P("Operationame"), P("operationName")],
      query: [P("Query")],
      namespace: [P("EventNamespace"), P("Namespace")],
      provider: [P("ProviderName")],
    },
    topFields: ["clientMachine", "remoteUser", "operation"],
    // Local WMI activity is constant background noise; only an operation attributed to
    // ANOTHER machine is evidence of remote execution.
    payloadFilter: /ClientMachine(?:FQDN)?:\s*\S/i },
  { category: "Remote Execution", name: "WinRM Remote Session", eventIds: ["145", "161", "169"], channels: ["winrm"], severity: "medium",
    extractors: {
      remoteUser: [P("User"), P("TargetUserName")],
      authMechanism: [P("AuthenticationMechanism")],
      operation: [P("operationName"), P("Operation")],
      resource: [P("resourceUri"), P("connection")],
    },
    topFields: ["remoteUser", "authMechanism", "operation"], payloadFilter: null },
];

const REGISTRY_RULES = [
  { category: "Run Keys", name: "Run/RunOnce Autostart", severity: "high", description: "Standard autorun registry key",
    keyPathPattern: /\\(?:Software|SOFTWARE)\\(?:Microsoft\\Windows\\CurrentVersion|WOW6432Node\\Microsoft\\Windows\\CurrentVersion)\\(?:Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run)(?:\\|$)/i, valueNameFilter: null },
  { category: "Services", name: "Service ImagePath/ServiceDll", severity: "high", description: "Service executable or DLL path",
    keyPathPattern: /\\(?:SYSTEM|System)\\(?:CurrentControlSet|ControlSet\d+)\\Services\\[^\\]+(?:\\Parameters)?$/i,
    valueNameFilter: /^(ImagePath|ServiceDll|FailureCommand)$/i },
  { category: "Winlogon", name: "Winlogon Shell/Userinit", severity: "critical", description: "Login-triggered execution via Winlogon",
    keyPathPattern: /\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon$/i, valueNameFilter: /^(Shell|Userinit|Notify|VmApplet|AppSetup|Taskman)$/i },
  { category: "AppInit DLLs", name: "AppInit_DLLs", severity: "critical", description: "DLL injection on every user-mode process",
    keyPathPattern: /\\Microsoft\\Windows NT\\CurrentVersion\\Windows$/i, valueNameFilter: /^(AppInit_DLLs|LoadAppInit_DLLs)$/i },
  { category: "IFEO", name: "Image File Execution Options Debugger", severity: "critical", description: "Debugger hijacking of executable launch",
    keyPathPattern: /\\Image File Execution Options\\[^\\]+$/i, valueNameFilter: /^(Debugger|GlobalFlag)$/i },
  { category: "COM Hijacking", name: "COM Object Server", severity: "high", description: "COM object DLL/executable hijacking",
    keyPathPattern: /\\(?:InprocServer32|LocalServer32|InprocHandler32)$/i, valueNameFilter: null },
  { category: "Shell Extensions", name: "Shell Extension Handler", severity: "medium", description: "Explorer shell extension persistence",
    keyPathPattern: /\\(?:ShellIconOverlayIdentifiers|ContextMenuHandlers|PropertySheetHandlers|ColumnHandlers|CopyHookHandlers|DragDropHandlers|ShellExecuteHooks)\\[^\\]+$/i, valueNameFilter: null },
  { category: "Boot Execute", name: "Session Manager BootExecute", severity: "critical", description: "Pre-boot execution before Windows starts",
    keyPathPattern: /\\(?:Session Manager)$/i, valueNameFilter: /^(BootExecute|SetupExecute|Execute)$/i },
  { category: "BHO", name: "Browser Helper Object", severity: "medium", description: "Browser helper object (IE/Edge extension)",
    keyPathPattern: /\\Browser Helper Objects\\{[0-9a-fA-F-]+}$/i, valueNameFilter: null },
  { category: "LSA", name: "LSA Security/Auth Packages", severity: "critical", description: "Credential interception via LSA packages",
    keyPathPattern: /\\(?:Control\\)?Lsa(?:\\OSConfig)?$/i, valueNameFilter: /^(Security Packages|Authentication Packages|Notification Packages)$/i },
  { category: "Print Monitors", name: "Print Monitor DLL", severity: "high", description: "Spooler-based persistence via print monitor",
    keyPathPattern: /\\Print\\Monitors\\[^\\]+$/i, valueNameFilter: /^Driver$/i },
  { category: "Active Setup", name: "Active Setup StubPath", severity: "high", description: "Per-user execution on first login",
    keyPathPattern: /\\Active Setup\\Installed Components\\{[0-9a-fA-F-]+}$/i, valueNameFilter: /^StubPath$/i },
  { category: "Startup Folder", name: "Startup Folder Registry Path", severity: "high", description: "Startup folder path redirection",
    keyPathPattern: /\\Explorer\\(?:User Shell Folders|Shell Folders)$/i, valueNameFilter: /Startup/i },
  { category: "Scheduled Tasks (Reg)", name: "Scheduled Task in Registry", severity: "medium", description: "Task definition stored in registry",
    keyPathPattern: /\\Schedule\\TaskCache\\(?:Tasks|Tree)\\?/i, valueNameFilter: null },
  { category: "Network Providers", name: "Network Provider Order", severity: "high", description: "Network login interception via custom provider",
    keyPathPattern: /\\NetworkProvider\\Order$/i, valueNameFilter: /^ProviderOrder$/i },
  { category: "Logon Script", name: "User Logon Script (Environment)", severity: "high", description: "Per-user logon script via Environment key",
    keyPathPattern: /\\Environment$/i, valueNameFilter: /^UserInitMprLogonScript$/i },
  { category: "AppCert DLLs", name: "AppCert DLL", severity: "critical", description: "DLL loaded into every process that calls Win32 API CreateProcess",
    keyPathPattern: /\\Session Manager\\AppCertDlls$/i, valueNameFilter: null },
  { category: "Silent Process Exit", name: "Silent Process Exit Monitor", severity: "critical", description: "Execution triggered by monitored process termination",
    keyPathPattern: /\\SilentProcessExit\\[^\\]+$/i, valueNameFilter: /^(MonitorProcess|ReportingMode|IgnoreSelfExits)$/i },
  { category: "Credential Providers", name: "Credential Provider Registration", severity: "high", description: "Custom credential provider DLL for login interception",
    keyPathPattern: /\\Authentication\\(?:Credential Providers|Credential Provider Filters|PLAP Providers)\\{[0-9a-fA-F-]+}$/i, valueNameFilter: null },
  { category: "Command Processor", name: "Command Processor AutoRun", severity: "high", description: "cmd.exe startup command persistence",
    keyPathPattern: /\\Command Processor$/i, valueNameFilter: /^AutoRun$/i },
  { category: "Explorer Autoruns", name: "ShellServiceObjectDelayLoad", severity: "high", description: "Explorer-triggered DLL persistence via ShellServiceObjectDelayLoad",
    keyPathPattern: /\\ShellServiceObjectDelayLoad$/i, valueNameFilter: null },
  { category: "Netsh Helper DLLs", name: "Netsh Helper DLL", severity: "high", description: "Netsh helper DLL persistence",
    keyPathPattern: /\\Microsoft\\Netsh$/i, valueNameFilter: null },
  // --- New rules: commonly seen in DFIR cases, previously undetected ---
  { category: "Screensaver", name: "Screensaver Hijack", severity: "high", description: "Idle-triggered execution via screensaver registry (T1546.002)",
    keyPathPattern: /\\Control Panel\\Desktop$/i, valueNameFilter: /^SCRNSAVE\.EXE$/i },
  { category: "Office Add-ins", name: "Office Add-in Registration", severity: "high", description: "Persistent Office add-in DLL loaded on application start (T1137.006)",
    keyPathPattern: /\\Microsoft\\Office\\[^\\]+\\[^\\]+\\Addins\\/i, valueNameFilter: null },
  { category: "Time Providers", name: "Time Provider DLL", severity: "critical", description: "W32Time service DLL persistence — runs as SYSTEM (T1547.003)",
    keyPathPattern: /\\Services\\W32Time\\TimeProviders\\[^\\]+$/i, valueNameFilter: /^DllName$/i },
  { category: "Terminal Server", name: "Terminal Server InitialProgram", severity: "critical", description: "RDP session hijacking — runs arbitrary binary on RDP login instead of explorer",
    keyPathPattern: /\\Terminal Server\\(?:WinStations\\[^\\]+|DefaultUserConfiguration)$/i, valueNameFilter: /^(?:InitialProgram|fInheritInitialProgram)$/i },
  { category: "File Association", name: "File Association Hijack", severity: "high", description: "File extension handler hijack — triggers on every file open (T1546.001)",
    keyPathPattern: /(?:\\(?:Classes|Explorer\\FileExts)\\[^\\]+\\(?:shell\\open\\command|OpenWithList|UserChoice)|\\[^\\]*\.[^\\]+\\shell\\open\\command)$/i, valueNameFilter: null },
  // --- Tier-3 coverage additions (2026-05-29 gap analysis) ---
  { category: "Group Policy Scripts", name: "GPO Logon/Startup Script", severity: "high", description: "Logon/Startup/Shutdown script registered via Group Policy (T1037.001)",
    keyPathPattern: /\\(?:Group Policy\\Scripts|Windows\\System\\Scripts)\\(?:Startup|Shutdown|Logon|Logoff)\\/i, valueNameFilter: /^(Script|Parameters)$/i },
  { category: "Security Support Provider", name: "LSA Security Support Provider", severity: "critical", description: "SSP/AP DLL loaded into LSASS — credential interception (T1547.005)",
    keyPathPattern: /\\Control\\SecurityProviders$/i, valueNameFilter: /^SecurityProviders$/i },
  { category: "Environment Hijack", name: "COR_PROFILER .NET Profiler", severity: "high", description: "DLL injected into any CLR process via COR_PROFILER env var (T1574.012)",
    keyPathPattern: /\\Environment$/i, valueNameFilter: /^(COR_PROFILER|COR_ENABLE_PROFILING|COR_PROFILER_PATH(?:_32|_64)?)$/i },
  { category: "Winlogon", name: "Winlogon Notify/GPExtensions DLL", severity: "critical", description: "Logon-triggered DLL via Winlogon Notify or GPExtensions subkey (T1547.004)",
    keyPathPattern: /\\Winlogon\\Notify\\[^\\]+$|\\GPExtensions\\{[0-9a-fA-F-]+}$/i, valueNameFilter: /^DllName$/i },
  { category: "COM Hijacking", name: "COM TreatAs Redirect", severity: "high", description: "COM class redirected to another server via TreatAs (T1546.015)",
    keyPathPattern: /\\CLSID\\{[0-9a-fA-F-]+}\\TreatAs$/i, valueNameFilter: null },
  { category: "Defender Tampering", name: "Defender Exclusion / Protection Disabled", severity: "high", description: "AV exclusion added or protection disabled via registry (T1562.001)",
    keyPathPattern: /\\(?:Windows Defender|Microsoft Antimalware)\\(?:Exclusions\\(?:Paths|Extensions|Processes|TemporaryPaths)|Real-Time Protection|Features)(?:\\|$)/i, valueNameFilter: null },
];

// Positional rule catalog for the renderer (see src/constants/persistenceRuleCatalog.mjs).
// Carries only display metadata — no regexes — so it stays JSON-serializable.
const PERSISTENCE_RULE_CATALOG = {
  evtx: EVTX_RULES.map((r, i) => ({
    id: `evtx-${i}`,
    cat: r.category,
    name: r.name,
    sev: r.severity,
    hint: (r.eventIds || []).join(", "),
  })),
  registry: REGISTRY_RULES.map((r, i) => ({
    id: `reg-${i}`,
    cat: r.category,
    name: r.name,
    sev: r.severity,
  })),
};

module.exports = { P, EVTX_RULES, REGISTRY_RULES, PERSISTENCE_RULE_CATALOG };
