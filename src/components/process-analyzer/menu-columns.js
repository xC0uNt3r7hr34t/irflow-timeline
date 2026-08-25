export function buildPiCols({ headers, isEvtxECmdPT, isHayabusa, isChainsawProcess, isSec4688 }) {
  if (!Array.isArray(headers) || headers.length === 0) return {};
  const det = (pats) => { for (const p of pats) { const f = headers.find((h) => p.test(h)); if (f) return f; } return null; };
  if (isEvtxECmdPT) return {
    pid: det([/^PayloadData1$/i]), ppid: det([/^PayloadData5$/i]),
    guid: det([/^PayloadData1$/i]), parentGuid: det([/^PayloadData5$/i]),
    image: det([/^ExecutableInfo$/i]), cmdLine: det([/^ExecutableInfo$/i]),
    user: det([/^UserName$/i, /^User$/i]),
    ts: det([/^TimeCreated$/i, /^datetime$/i, /^Timestamp$/i]),
    eventId: det([/^EventId$/i, /^EventID$/i]),
    provider: det([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
  };
  if (isHayabusa) return {
    pid: det([/^Details$/i]), ppid: det([/^ExtraFieldInfo$/i]) || det([/^Details$/i]),
    guid: det([/^Details$/i]), parentGuid: det([/^Details$/i]),
    image: det([/^Details$/i]), parentImage: det([/^ExtraFieldInfo$/i]) || det([/^Details$/i]),
    cmdLine: det([/^Details$/i]),
    user: det([/^ExtraFieldInfo$/i]) || det([/^Details$/i]),
    ts: det([/^Timestamp$/i, /^TimeCreated$/i, /^datetime$/i, /^UtcTime$/i]),
    eventId: det([/^EventID$/i, /^event_id$/i, /^EventId$/]),
    elevation: det([/^ExtraFieldInfo$/i]) || det([/^Details$/i]),
    integrity: det([/^ExtraFieldInfo$/i]) || det([/^Details$/i]),
    provider: det([/^Channel$/i, /^Provider$/i, /^SourceName$/i]),
  };
  if (isChainsawProcess) return {
    pid: det([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
    ppid: det([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^CreatorProcessId$/i]),
    guid: det([/^ProcessGuid$/i, /^process_guid$/i]),
    parentGuid: det([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
    image: det([/^Event\.EventData\.Image$/i, /^process_name$/i, /^Image$/i]),
    parentImage: det([/^ParentImage$/i, /^ParentProcessName$/i]),
    cmdLine: det([/^command_line$/i, /^Event\.EventData\.CommandLine$/i, /^CommandLine$/i]),
    user: det([/^User$/i, /^UserName$/i]),
    ts: det([/^system_time$/i, /^Timestamp$/i, /^TimeCreated$/i, /^datetime$/i]),
    eventId: det([/^id$/i, /^EventID$/i, /^event_id$/i, /^EventId$/]),
    provider: det([/^Channel$/i, /^Provider$/i, /^SourceName$/i]),
  };
  if (isSec4688) {
    const hasNewPid = headers.some((h) => /^NewProcessId$/i.test(h));
    return {
      pid: hasNewPid ? det([/^NewProcessId$/i]) : det([/^ProcessId$/i]),
      ppid: hasNewPid ? det([/^ProcessId$/i, /^CreatorProcessId$/i]) : det([/^CreatorProcessId$/i]),
      guid: det([/^ProcessGuid$/i, /^process_guid$/i]),
      parentGuid: det([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
      image: det([/^NewProcessName$/i, /^Image$/i]),
      parentImage: det([/^ParentProcessName$/i, /^ParentImage$/i]),
      cmdLine: det([/^CommandLine$/i, /^command_line$/i, /^cmdline$/i, /^ProcessCommandLine$/i]),
      user: det([/^SubjectUserName$/i, /^TargetUserName$/i, /^User$/i, /^UserName$/i]),
      ts: det([/^datetime$/i, /^TimeCreated$/i, /^UtcTime$/i, /^Timestamp$/i]),
      eventId: det([/^EventID$/i, /^event_id$/i, /^EventId$/]),
      elevation: det([/^TokenElevationType$/i]),
      integrity: det([/^MandatoryLabel$/i, /^IntegrityLevel$/i]),
      provider: det([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
    };
  }
  return {
    pid: det([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
    ppid: det([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^CreatorProcessId$/i]),
    guid: det([/^ProcessGuid$/i, /^process_guid$/i]),
    parentGuid: det([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
    image: det([/^Image$/i, /^process_name$/i, /^exe$/i, /^NewProcessName$/i]),
    parentImage: det([/^ParentImage$/i, /^ParentProcessName$/i]),
    cmdLine: det([/^CommandLine$/i, /^command_line$/i, /^cmdline$/i, /^ProcessCommandLine$/i]),
    user: det([/^User$/i, /^UserName$/i, /^TargetUserName$/i]),
    ts: det([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^Timestamp$/i]),
    eventId: det([/^EventID$/i, /^event_id$/i, /^EventId$/]),
    elevation: det([/^TokenElevationType$/i]),
    integrity: det([/^MandatoryLabel$/i, /^IntegrityLevel$/i]),
    provider: det([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
  };
}
