/**
 * Shared DFIR event field schema and alias registry.
 *
 * Analysts think in concepts such as process image, source IP, and target
 * user. Evidence sources expose those concepts with different column names or
 * packed KV keys. This registry is the central place for those mappings.
 */

const FIELD_REGISTRY = {
  "event.timestamp": {
    label: "Timestamp",
    aliases: ["Timestamp", "datetime", "UtcTime", "TimeCreated", "system_time", "timestamp"],
  },
  "event.id": {
    label: "EventID",
    aliases: ["EventID", "EventId", "event_id", "eventid", "id"],
    chainsawAliases: ["id"],
  },
  "event.provider": {
    label: "Provider",
    aliases: ["Provider", "SourceName", "Event.System.Provider", "Event.System.Provider.Name"],
  },
  "event.channel": {
    label: "Channel",
    aliases: ["Channel", "Event.System.Channel"],
  },
  "host.name": {
    label: "Computer",
    aliases: ["Computer", "ComputerName", "Hostname", "MachineName", "computer_name"],
    kvAliases: ["Computer", "Host", "Hostname"],
    chainsawAliases: ["computer_name"],
  },

  "process.id": {
    label: "ProcessId",
    aliases: ["ProcessId", "PID", "pid", "process_id", "NewProcessId"],
    kvAliases: ["PID", "ProcessId", "NewProcessId"],
    compactLabel: "ProcessId",
  },
  "process.parent_id": {
    label: "ParentProcessId",
    aliases: ["ParentProcessId", "ParentPID", "ppid", "parent_process_id", "parent_pid", "CreatorProcessId"],
    kvAliases: ["ParentPID", "ParentProcessId", "CreatorProcessId"],
    compactLabel: "ParentProcessId",
  },
  "process.guid": {
    label: "ProcessGuid",
    aliases: ["ProcessGuid", "ProcessGUID", "process_guid"],
    kvAliases: ["PGUID", "ProcessGuid", "ProcessGUID"],
    compactLabel: "ProcessGuid",
  },
  "process.parent_guid": {
    label: "ParentProcessGuid",
    aliases: ["ParentProcessGuid", "ParentProcessGUID", "parent_process_guid"],
    kvAliases: ["ParentPGUID", "ParentProcessGuid", "ParentProcessGUID"],
    compactLabel: "ParentProcessGuid",
  },
  "process.image": {
    label: "Image",
    aliases: ["Image", "Proc", "NewProcessName", "ProcessName", "process_name", "exe", "FileName", "ImagePath", "Event.EventData.Image"],
    kvAliases: ["Proc", "Image", "NewProcessName", "ProcessName"],
    chainsawAliases: ["process_name", "Event.EventData.Image"],
    compactLabel: "Image",
  },
  "process.parent_image": {
    label: "ParentImage",
    aliases: ["ParentImage", "ParentProcessName", "parent_image", "parent_process_name", "CreatorProcessName", "Event.EventData.ParentImage"],
    kvAliases: ["ParentImage", "ParentProcessName"],
    chainsawAliases: ["parent_process_name", "Event.EventData.ParentImage"],
    compactLabel: "ParentImage",
  },
  "process.command_line": {
    label: "CommandLine",
    aliases: ["CommandLine", "Cmdline", "ProcessCommandLine", "command_line", "cmd", "cmdline", "Event.EventData.CommandLine"],
    kvAliases: ["Cmdline", "CommandLine", "ProcessCommandLine"],
    chainsawAliases: ["command_line", "Event.EventData.CommandLine"],
    compactLabel: "CommandLine",
  },
  "process.parent_command_line": {
    label: "ParentCommandLine",
    aliases: ["ParentCommandLine", "ParentCmdline", "Event.EventData.ParentCommandLine"],
    kvAliases: ["ParentCmdline", "ParentCommandLine"],
    chainsawAliases: ["Event.EventData.ParentCommandLine"],
  },
  "process.integrity": {
    label: "IntegrityLevel",
    aliases: ["IntegrityLevel", "MandatoryLabel", "Mandatory_Label"],
    kvAliases: ["IntegrityLevel"],
  },
  "process.current_directory": {
    label: "CurrentDirectory",
    aliases: ["CurrentDirectory"],
    kvAliases: ["CurrentDirectory"],
  },
  "process.hashes": {
    label: "Hashes",
    aliases: ["Hashes", "Hash"],
    kvAliases: ["Hashes", "Hash"],
    chainsawAliases: ["Event.EventData.Hashes"],
    compactLabel: "Hashes",
  },
  "process.original_file_name": {
    label: "OriginalFileName",
    aliases: ["OriginalFileName", "Original_File_Name"],
    kvAliases: ["OriginalFileName"],
    chainsawAliases: ["Event.EventData.OriginalFileName"],
    compactLabel: "OriginalFileName",
  },
  "process.file_version": {
    label: "FileVersion",
    aliases: ["FileVersion", "Event.EventData.FileVersion"],
    kvAliases: ["FileVersion"],
    chainsawAliases: ["Event.EventData.FileVersion"],
  },
  "process.product": {
    label: "Product",
    aliases: ["Product"],
    kvAliases: ["Product"],
    compactLabel: "Product",
  },
  "process.company": {
    label: "Company",
    aliases: ["Company"],
    kvAliases: ["Company"],
    compactLabel: "Company",
  },
  "process.description": {
    label: "Description",
    aliases: ["Description"],
    kvAliases: ["Description"],
  },

  "identity.user": {
    label: "User",
    aliases: ["User", "UserName", "user_name", "TargetUserName", "SubjectUserName", "target_username", "TgtUser", "SrcUser"],
    kvAliases: ["TgtUser", "TargetUserName", "User", "SubjectUserName"],
    chainsawAliases: ["target_username", "user"],
  },
  "identity.target_user": {
    label: "TargetUserName",
    aliases: ["TargetUserName", "Target_User_Name", "TgtUser", "User", "target_username"],
    kvAliases: ["TgtUser", "TargetUserName", "User"],
    chainsawAliases: ["target_username"],
    compactLabel: "TargetUserName",
  },
  "identity.subject_user": {
    label: "SubjectUserName",
    aliases: ["SubjectUserName", "Subject_User_Name", "SrcUser"],
    kvAliases: ["SubjectUserName", "SrcUser"],
    compactLabel: "SubjectUserName",
  },
  "identity.target_domain": {
    label: "TargetDomainName",
    aliases: ["TargetDomainName", "Target_Domain_Name", "Domain"],
    kvAliases: ["TargetDomainName", "Domain"],
    compactLabel: "TargetDomainName",
  },
  "identity.subject_domain": {
    label: "SubjectDomainName",
    aliases: ["SubjectDomainName", "Subject_Domain_Name"],
    kvAliases: ["SubjectDomainName"],
  },
  "identity.target_sid": {
    label: "TargetUserSid",
    aliases: ["TargetUserSid", "Target_User_Sid", "SID"],
    kvAliases: ["TargetUserSid", "SID"],
  },
  "identity.subject_sid": {
    label: "SubjectUserSid",
    aliases: ["SubjectUserSid", "Subject_User_Sid"],
    kvAliases: ["SubjectUserSid"],
  },
  "identity.logon_type": {
    label: "LogonType",
    aliases: ["LogonType", "Logon_Type", "logon_type", "Type"],
    kvAliases: ["LogonType", "Type"],
    chainsawAliases: ["logon_type"],
    compactLabel: "LogonType",
  },
  "identity.logon_process": {
    label: "LogonProcessName",
    aliases: ["LogonProcessName"],
    kvAliases: ["LogonProcessName"],
  },
  "identity.auth_package": {
    label: "AuthenticationPackageName",
    aliases: ["AuthenticationPackageName"],
    kvAliases: ["AuthenticationPackageName"],
  },
  "identity.subject_logon_id": {
    label: "SubjectLogonId",
    aliases: ["SubjectLogonId", "Subject_Logon_ID", "LID", "LGUID"],
    kvAliases: ["SubjectLogonId", "LID", "LGUID"],
  },
  "identity.target_logon_id": {
    label: "TargetLogonId",
    aliases: ["TargetLogonId", "Target_Logon_ID"],
    kvAliases: ["TargetLogonId"],
  },

  "network.source_ip": {
    label: "IpAddress",
    aliases: ["IpAddress", "SrcIP", "SourceNetworkAddress", "SourceAddress", "Source_Network_Address", "ClientAddress", "RemoteHost", "source_ip"],
    kvAliases: ["SrcIP", "IpAddress", "SourceNetworkAddress", "ClientAddress"],
    chainsawAliases: ["source_ip"],
    compactLabel: "IpAddress",
  },
  "network.source_port": {
    label: "SourcePort",
    aliases: ["SourcePort", "SrcPort", "Event.EventData.SourcePort"],
    kvAliases: ["SrcPort", "SourcePort"],
    chainsawAliases: ["Event.EventData.SourcePort"],
  },
  "network.destination_ip": {
    label: "DestinationIp",
    aliases: ["DestinationIp", "DestinationAddress", "DstIP", "Event.EventData.DestinationIp"],
    kvAliases: ["DstIP", "DestinationIp", "DestinationAddress"],
    chainsawAliases: ["Event.EventData.DestinationIp"],
  },
  "network.destination_port": {
    label: "DestinationPort",
    aliases: ["DestinationPort", "DstPort", "Event.EventData.DestinationPort"],
    kvAliases: ["DstPort", "DestinationPort"],
    chainsawAliases: ["Event.EventData.DestinationPort"],
  },
  "network.workstation": {
    label: "WorkstationName",
    aliases: ["WorkstationName", "Workstation_Name", "SourceHostname", "SourceComputerName", "ClientName", "SrcComp", "SrcHost", "workstation_name"],
    kvAliases: ["SrcComp", "WorkstationName", "ClientName", "SrcHost"],
    chainsawAliases: ["workstation_name"],
    compactLabel: "WorkstationName",
  },
  "network.destination_host": {
    label: "DestinationHostname",
    aliases: ["DestinationHostname", "DstHost", "Event.EventData.DestinationHostname"],
    kvAliases: ["DstHost", "DestinationHostname"],
    chainsawAliases: ["Event.EventData.DestinationHostname"],
  },
  "network.protocol": {
    label: "Protocol",
    aliases: ["Protocol"],
    kvAliases: ["Protocol"],
  },
  "network.remote_host": {
    label: "RemoteHost",
    aliases: ["RemoteHost", "TgtSvr", "TgtHost"],
    kvAliases: ["TgtSvr", "TgtHost", "RemoteHost"],
    compactLabel: "RemoteHost",
  },

  "file.target": {
    label: "TargetFilename",
    aliases: ["TargetFilename", "TgtFile", "FileName", "target_filename", "Event.EventData.TargetFilename"],
    kvAliases: ["TargetFilename", "TgtFile", "FileName"],
    chainsawAliases: ["target_filename", "Event.EventData.TargetFilename"],
    compactLabel: "TargetFilename",
  },
  "file.creation_time": {
    label: "CreationUtcTime",
    aliases: ["CreationUtcTime", "Event.EventData.CreationUtcTime"],
    kvAliases: ["CreationUtcTime"],
    chainsawAliases: ["Event.EventData.CreationUtcTime"],
  },
  // Sysmon EID 2 (FileCreateTime) — the ORIGINAL creation time before a timestomp. The single most
  // valuable datum in a timestomp case: it recovers the pre-stomp $SI Created (CreationUtcTime is the
  // forged value). Consumed by the Timestomping Detector's cross-artifact corroboration.
  "file.creation_previous_time": {
    label: "PreviousCreationUtcTime",
    aliases: ["PreviousCreationUtcTime", "Previous_Creation_Utc_Time", "PrevCreationTime", "Event.EventData.PreviousCreationUtcTime"],
    kvAliases: ["PreviousCreationUtcTime", "PrevCreationTime"],
    chainsawAliases: ["Event.EventData.PreviousCreationUtcTime"],
    compactLabel: "PrevCreationTime",
  },
  "file.relative_target": {
    label: "RelativeTargetName",
    aliases: ["RelativeTargetName", "Relative_Target_Name", "RelTarget"],
    kvAliases: ["RelativeTargetName", "RelTarget"],
    compactLabel: "RelativeTargetName",
  },
  "file.share_name": {
    label: "ShareName",
    aliases: ["ShareName", "Share_Name", "Share"],
    kvAliases: ["ShareName", "Share"],
    compactLabel: "ShareName",
  },
  "file.access_mask": {
    label: "AccessMask",
    aliases: ["AccessMask"],
    kvAliases: ["AccessMask"],
  },
  "file.path": {
    label: "Path",
    aliases: ["Path"],
    kvAliases: ["Path"],
    compactLabel: "Path",
  },

  "registry.key": {
    label: "TargetObject",
    aliases: ["TargetObject", "RegKey", "TgtObj", "ObjectName", "target_object", "Event.EventData.TargetObject"],
    kvAliases: ["RegKey", "TargetObject", "TgtObj", "ObjectName"],
    chainsawAliases: ["target_object", "Event.EventData.TargetObject"],
    compactLabel: "TargetObject",
  },
  "registry.details": {
    label: "Details",
    aliases: ["Details", "details", "Event.EventData.Details"],
    kvAliases: ["Details"],
    chainsawAliases: ["details", "Event.EventData.Details"],
    compactLabel: "Details",
  },
  "registry.new_value": {
    label: "NewValue",
    aliases: ["NewValue"],
    kvAliases: ["NewValue"],
  },
  "registry.old_value": {
    label: "OldValue",
    aliases: ["OldValue"],
    kvAliases: ["OldValue"],
  },

  "service.name": {
    label: "ServiceName",
    aliases: ["ServiceName", "Service_Name", "Svc", "param1", "service_name", "Event.System.ServiceName"],
    kvAliases: ["Svc", "ServiceName", "param1"],
    chainsawAliases: ["service_name", "Event.System.ServiceName"],
    compactLabel: "ServiceName",
  },
  "service.file_name": {
    label: "ServiceFileName",
    aliases: ["ServiceFileName", "ImagePath"],
    kvAliases: ["ServiceFileName", "ImagePath"],
  },
  "service.type": {
    label: "ServiceType",
    aliases: ["ServiceType"],
    kvAliases: ["ServiceType"],
  },
  "service.start_type": {
    label: "StartType",
    aliases: ["StartType", "OldStartType", "NewStartType", "ServiceStartType"],
    kvAliases: ["StartType", "OldStartType", "NewStartType", "ServiceStartType"],
    compactLabel: "StartType",
  },
  "service.account": {
    label: "Account",
    aliases: ["Account", "Acct", "AccountName", "ServiceAccount"],
    kvAliases: ["Acct", "AccountName", "ServiceAccount"],
    compactLabel: "Account",
  },
  "service.image_path": {
    label: "ImagePath",
    aliases: ["ImagePath", "Path", "ServiceFileName"],
    kvAliases: ["Path", "ImagePath", "ServiceFileName"],
    compactLabel: "ImagePath",
  },

  "task.name": {
    label: "TaskName",
    aliases: ["TaskName", "Task", "Name"],
    kvAliases: ["Task", "TaskName", "Name"],
    compactLabel: "Task",
  },
  "task.content": {
    label: "TaskContent",
    aliases: ["TaskContent", "TaskContentNew", "Content"],
    kvAliases: ["TaskContent", "Content"],
    compactLabel: "TaskContent",
  },
  "task.command": {
    label: "Command",
    aliases: ["Command", "Action", "Actions"],
    kvAliases: ["Command", "Action", "Actions"],
    compactLabel: "Command",
  },
  "task.actions": {
    label: "Actions",
    aliases: ["Actions"],
    kvAliases: ["Actions"],
  },

  "dns.query": {
    label: "QueryName",
    aliases: ["QueryName", "Query", "DnsQuery", "Event.EventData.QueryName"],
    kvAliases: ["QueryName", "Query", "DnsQuery"],
    chainsawAliases: ["Event.EventData.QueryName"],
  },
  "dns.results": {
    label: "QueryResults",
    aliases: ["QueryResults", "DnsResults", "Event.EventData.QueryResults"],
    kvAliases: ["QueryResults", "DnsResults"],
    chainsawAliases: ["Event.EventData.QueryResults"],
  },
  "dns.status": {
    label: "QueryStatus",
    aliases: ["QueryStatus", "Event.EventData.QueryStatus"],
    kvAliases: ["QueryStatus"],
    chainsawAliases: ["Event.EventData.QueryStatus"],
  },
  "pipe.name": {
    label: "PipeName",
    aliases: ["PipeName", "Pipe", "Event.EventData.PipeName"],
    kvAliases: ["PipeName", "Pipe"],
    chainsawAliases: ["Event.EventData.PipeName"],
  },
  "powershell.script_block": {
    label: "ScriptBlockText",
    aliases: ["ScriptBlockText", "ScriptBlock"],
    kvAliases: ["ScriptBlock", "ScriptBlockText"],
    compactLabel: "ScriptBlockText",
  },
  "powershell.host_application": {
    label: "HostApplication",
    aliases: ["HostApplication"],
    kvAliases: ["HostApplication"],
    compactLabel: "HostApplication",
  },
  "powershell.message_number": {
    label: "MessageNumber",
    aliases: ["MessageNumber"],
    kvAliases: ["MessageNumber"],
    compactLabel: "MessageNumber",
  },
  "powershell.message_total": {
    label: "MessageTotal",
    aliases: ["MessageTotal"],
    kvAliases: ["MessageTotal"],
    compactLabel: "MessageTotal",
  },
  "powershell.script_block_id": {
    label: "ScriptBlockId",
    aliases: ["ScriptBlockId"],
    kvAliases: ["ScriptBlockId"],
    compactLabel: "ScriptBlockId",
  },

  "sysmon.rule_name": {
    label: "RuleName",
    aliases: ["RuleName", "Event.EventData.RuleName"],
    kvAliases: ["RuleName"],
    chainsawAliases: ["Event.EventData.RuleName"],
  },
  "sysmon.source_image": {
    label: "SourceImage",
    aliases: ["SourceImage", "SrcProc", "SrcImage", "Event.EventData.SourceImage"],
    kvAliases: ["SourceImage", "SrcProc", "SrcImage"],
    chainsawAliases: ["Event.EventData.SourceImage"],
  },
  "sysmon.call_trace": {
    label: "CallTrace",
    aliases: ["CallTrace", "Event.EventData.CallTrace"],
    kvAliases: ["CallTrace"],
    chainsawAliases: ["Event.EventData.CallTrace"],
  },
  "sysmon.granted_access": {
    label: "GrantedAccess",
    aliases: ["GrantedAccess", "Access", "Event.EventData.GrantedAccess"],
    kvAliases: ["GrantedAccess", "Access"],
    chainsawAliases: ["Event.EventData.GrantedAccess"],
  },
  "sysmon.source_process_id": {
    label: "SourceProcessId",
    aliases: ["SourceProcessId", "SrcPID", "Event.EventData.SourceProcessId"],
    kvAliases: ["SourceProcessId", "SrcPID"],
    chainsawAliases: ["Event.EventData.SourceProcessId"],
  },
  "sysmon.target_process_id": {
    label: "TargetProcessId",
    aliases: ["TargetProcessId", "TgtPID", "Event.EventData.TargetProcessId"],
    kvAliases: ["TargetProcessId", "TgtPID"],
    chainsawAliases: ["Event.EventData.TargetProcessId"],
  },
  "sysmon.image_loaded": {
    label: "ImageLoaded",
    aliases: ["ImageLoaded", "Loaded", "Event.EventData.ImageLoaded"],
    kvAliases: ["ImageLoaded", "Loaded"],
    chainsawAliases: ["Event.EventData.ImageLoaded"],
  },
  "sysmon.signed": {
    label: "Signed",
    aliases: ["Signed", "Event.EventData.Signed"],
    kvAliases: ["Signed"],
    chainsawAliases: ["Event.EventData.Signed"],
  },
  "sysmon.signature": {
    label: "Signature",
    aliases: ["Signature", "Signer", "Event.EventData.Signature"],
    kvAliases: ["Signature", "Signer"],
    chainsawAliases: ["Event.EventData.Signature"],
  },
  "sysmon.signature_status": {
    label: "SignatureStatus",
    aliases: ["SignatureStatus", "SigStatus", "Event.EventData.SignatureStatus"],
    kvAliases: ["SignatureStatus", "SigStatus"],
    chainsawAliases: ["Event.EventData.SignatureStatus"],
  },

  "rdp.session_name": {
    label: "SessionName",
    aliases: ["SessionName"],
    kvAliases: ["SessionName"],
    compactLabel: "SessionName",
  },
  "rdp.session_id": {
    label: "SessionId",
    aliases: ["SessionId", "SessionID"],
    kvAliases: ["SessionId", "SessionID"],
  },

  "wmi.consumer": {
    label: "Consumer",
    aliases: ["Consumer"],
    kvAliases: ["Consumer"],
    compactLabel: "Consumer",
  },
  "wmi.filter": {
    label: "Filter",
    aliases: ["Filter"],
    kvAliases: ["Filter"],
    compactLabel: "Filter",
  },
  "wmi.query": {
    label: "Query",
    aliases: ["Query"],
    kvAliases: ["Query"],
    compactLabel: "Query",
  },
  "wmi.operation": {
    label: "Operation",
    aliases: ["Operation"],
    kvAliases: ["Operation"],
    compactLabel: "Operation",
  },
  "wmi.namespace": {
    label: "Namespace",
    aliases: ["Namespace"],
    kvAliases: ["Namespace"],
    compactLabel: "Namespace",
  },

  "ad.object_dn": {
    label: "ObjectDN",
    aliases: ["ObjectDN"],
    kvAliases: ["ObjectDN"],
    compactLabel: "ObjectDN",
  },
  "ad.object_class": {
    label: "ObjectClass",
    aliases: ["ObjectClass"],
    kvAliases: ["ObjectClass"],
    compactLabel: "ObjectClass",
  },
  "ad.object_guid": {
    label: "ObjectGUID",
    aliases: ["ObjectGUID"],
    kvAliases: ["ObjectGUID"],
  },
  "ad.attribute_name": {
    label: "AttributeLDAPDisplayName",
    aliases: ["AttributeLDAPDisplayName"],
    kvAliases: ["AttributeLDAPDisplayName"],
  },
  "ad.attribute_value": {
    label: "AttributeValue",
    aliases: ["AttributeValue"],
    kvAliases: ["AttributeValue"],
  },

  "event.status": {
    label: "Status",
    aliases: ["Status"],
    kvAliases: ["Status"],
  },
  "event.sub_status": {
    label: "SubStatus",
    aliases: ["SubStatus", "Sub_Status"],
    kvAliases: ["SubStatus"],
    compactLabel: "SubStatus",
  },
  "event.failure_reason": {
    label: "FailureReason",
    aliases: ["FailureReason"],
    kvAliases: ["FailureReason"],
  },
  "event.privilege_list": {
    label: "PrivilegeList",
    aliases: ["PrivilegeList", "Privileges", "Privilege_List"],
    kvAliases: ["PrivilegeList", "Privileges"],
  },
  "event.key_length": {
    label: "KeyLength",
    aliases: ["KeyLength"],
    kvAliases: ["KeyLength"],
  },
};

const SIGMA_FIELD_TO_CONCEPT = {
  Image: "process.image",
  CommandLine: "process.command_line",
  ParentImage: "process.parent_image",
  ParentCommandLine: "process.parent_command_line",
  TargetUserName: "identity.target_user",
  SubjectUserName: "identity.subject_user",
  TargetDomainName: "identity.target_domain",
  User: "identity.user",
  Computer: "host.name",
  EventID: "event.id",
  LogonType: "identity.logon_type",
  IpAddress: "network.source_ip",
  WorkstationName: "network.workstation",
  TargetObject: "registry.key",
  Details: "registry.details",
  SourcePort: "network.source_port",
  DestinationPort: "network.destination_port",
  DestinationIp: "network.destination_ip",
  DestinationHostname: "network.destination_host",
  ServiceName: "service.name",
  ShareName: "file.share_name",
  TaskName: "task.name",
  TargetFilename: "file.target",
  CreationUtcTime: "file.creation_time",
  PreviousCreationUtcTime: "file.creation_previous_time",
  SourceImage: "sysmon.source_image",
  CallTrace: "sysmon.call_trace",
  GrantedAccess: "sysmon.granted_access",
  SourceProcessId: "sysmon.source_process_id",
  TargetProcessId: "sysmon.target_process_id",
  QueryName: "dns.query",
  QueryResults: "dns.results",
  QueryStatus: "dns.status",
  PipeName: "pipe.name",
  ImageLoaded: "sysmon.image_loaded",
  Signed: "sysmon.signed",
  Signature: "sysmon.signature",
  SignatureStatus: "sysmon.signature_status",
  FileVersion: "process.file_version",
  RuleName: "sysmon.rule_name",
  Hashes: "process.hashes",
  OriginalFileName: "process.original_file_name",
  Product: "process.product",
  Company: "process.company",
  Description: "process.description",
  IntegrityLevel: "process.integrity",
  CurrentDirectory: "process.current_directory",
  ScriptBlockText: "powershell.script_block",
  TargetProcessGuid: "process.guid",
  ProcessGuid: "process.guid",
  ParentProcessGuid: "process.parent_guid",
  ProcessId: "process.id",
  ParentProcessId: "process.parent_id",
};

const EVTX_MESSAGE_SUMMARY_FIELDS = [
  "TargetUserName", "SubjectUserName", "TargetDomainName", "SubjectDomainName",
  "LogonType", "IpAddress", "WorkstationName", "ProcessName", "NewProcessName",
  "CommandLine", "ParentProcessName", "ServiceName", "ServiceFileName",
  "TaskName", "ShareName", "RelativeTargetName", "Status", "SubStatus",
];

const EVTX_WELL_KNOWN_DATA_FIELDS = [
  "TargetUserName", "TargetDomainName", "TargetUserSid", "TargetLogonId",
  "SubjectUserName", "SubjectDomainName", "SubjectUserSid", "SubjectLogonId",
  "LogonType", "LogonProcessName", "AuthenticationPackageName",
  "WorkstationName", "IpAddress", "IpPort", "Workstation",
  "ProcessId", "ProcessName", "Status", "SubStatus", "FailureReason",
  "ElevatedToken", "ImpersonationLevel", "VirtualAccount",
  "ServiceName", "ServiceSid", "TicketEncryptionType", "TicketOptions",
  "PreAuthType", "TransmittedServices",
  "NewProcessId", "NewProcessName", "ParentProcessName", "CommandLine",
  "TokenElevationType", "MandatoryLabel",
  "ServiceFileName", "ServiceType", "ServiceStartType", "ServiceAccount",
  "TaskName", "TaskContent", "TaskContentNew",
  "ShareName", "ShareLocalPath", "RelativeTargetName", "AccessMask", "AccessList",
  "ClientName", "ClientAddress", "SessionID", "Param1", "Param2", "Param3",
  // TerminalServices-LocalSessionManager UserData leaves. Unlike RemoteConnectionManager
  // (which uses Param1/2/3), LSM names them directly, and EID 39/40 add Reason/Session.
  // Without these, a TerminalServices tab whose first SAMPLE_LIMIT records happen to be
  // some other event type loses its source address entirely.
  "Address", "User", "Reason", "Session", "TargetSession",
];

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function resolveConcept(fieldOrConcept) {
  if (FIELD_REGISTRY[fieldOrConcept]) return fieldOrConcept;
  return SIGMA_FIELD_TO_CONCEPT[fieldOrConcept] || null;
}

function getFieldEntry(fieldOrConcept) {
  const concept = resolveConcept(fieldOrConcept);
  return concept ? FIELD_REGISTRY[concept] : null;
}

function getFieldAliases(fieldOrConcept, options = {}) {
  const { source = "all", includeLabel = true, includeField = true } = options;
  const entry = getFieldEntry(fieldOrConcept);
  const aliases = [];
  if (includeField && !FIELD_REGISTRY[fieldOrConcept]) aliases.push(fieldOrConcept);
  if (!entry) return unique(aliases);
  if (includeLabel) aliases.push(entry.label);
  if (source === "kv") aliases.push(...(entry.kvAliases || entry.aliases || []));
  else if (source === "chainsaw") aliases.push(...(entry.chainsawAliases || []));
  else aliases.push(...(entry.aliases || []), ...(entry.kvAliases || []), ...(entry.chainsawAliases || []));
  return unique(aliases);
}

function buildAliasMap(fields, options = {}) {
  const map = {};
  for (const field of fields) {
    const aliases = getFieldAliases(field, options);
    if (aliases.length > 0) map[field] = aliases;
  }
  return map;
}

function getKvExtractableFields() {
  const fields = [];
  for (const entry of Object.values(FIELD_REGISTRY)) {
    fields.push(entry.label, ...(entry.kvAliases || []));
  }
  return unique(fields);
}

function isDfirKvField(key) {
  return KV_EXTRACTABLE_FIELD_SET.has(key);
}

function getCompactAliasDefinitions() {
  return Object.values(FIELD_REGISTRY)
    .filter((entry) => entry.compactLabel && Array.isArray(entry.kvAliases) && entry.kvAliases.length > 0)
    .map((entry) => ({ label: entry.compactLabel, aliases: unique(entry.kvAliases) }));
}

function getEvtxWellKnownDataFields() {
  return [...EVTX_WELL_KNOWN_DATA_FIELDS];
}

function getEvtxMessageSummaryFields() {
  return [...EVTX_MESSAGE_SUMMARY_FIELDS];
}

const KV_EXTRACTABLE_FIELD_SET = new Set(getKvExtractableFields());

module.exports = {
  FIELD_REGISTRY,
  SIGMA_FIELD_TO_CONCEPT,
  EVTX_MESSAGE_SUMMARY_FIELDS,
  EVTX_WELL_KNOWN_DATA_FIELDS,
  resolveConcept,
  getFieldEntry,
  getFieldAliases,
  buildAliasMap,
  getKvExtractableFields,
  isDfirKvField,
  getCompactAliasDefinitions,
  getEvtxWellKnownDataFields,
  getEvtxMessageSummaryFields,
};
