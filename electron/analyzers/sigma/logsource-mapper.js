/**
 * sigma/logsource-mapper.js — Sigma Logsource to Channel/EventID Mapping
 *
 * Maps Sigma's abstract logsource (product, category, service) to concrete
 * Windows event log channels and Event IDs for SQL pre-filtering.
 */

// Category-to-EventID mapping (Sigma taxonomy)
const CATEGORY_MAP = {
  // Sysmon categories
  process_creation:     { channels: ["sysmon", "security"], eids: ["1", "4688"] },
  process_termination:  { channels: ["sysmon"], eids: ["5"] },
  image_load:           { channels: ["sysmon"], eids: ["7"] },
  image_loaded:         { channels: ["sysmon"], eids: ["7"] },  // alias used by some repos
  file_event:           { channels: ["sysmon"], eids: ["11"] },
  file_access:          { channels: ["sysmon"], eids: ["11"] },  // alias for file_event
  file_delete:          { channels: ["sysmon"], eids: ["23", "26"] },
  registry_set:         { channels: ["sysmon"], eids: ["13"] },
  registry_add:         { channels: ["sysmon"], eids: ["12"] },
  registry_delete:      { channels: ["sysmon"], eids: ["14"] },
  registry_event:       { channels: ["sysmon"], eids: ["12", "13", "14"] },
  network_connection:   { channels: ["sysmon"], eids: ["3"] },
  dns_query:            { channels: ["sysmon"], eids: ["22"] },
  pipe_created:         { channels: ["sysmon"], eids: ["17"] },
  pipe_connected:       { channels: ["sysmon"], eids: ["18"] },
  create_remote_thread: { channels: ["sysmon"], eids: ["8"] },
  create_stream_hash:   { channels: ["sysmon"], eids: ["15"] },
  driver_loaded:        { channels: ["sysmon"], eids: ["6"] },
  wmi_event:            { channels: ["sysmon"], eids: ["19", "20", "21"] },
  process_access:       { channels: ["sysmon"], eids: ["10"] },
  clipboard_capture:    { channels: ["sysmon"], eids: ["24"] },
  // Sysmon file/misc
  file_change:          { channels: ["sysmon"], eids: ["2"] },
  file_rename:          { channels: ["sysmon"], eids: ["23", "26"] },
  sysmon_error:         { channels: ["sysmon"], eids: ["255"] },
  sysmon_status:        { channels: ["sysmon"], eids: ["16"] },
  // PowerShell
  ps_script:            { channels: ["powershell"], eids: ["4104"] },
  ps_module:            { channels: ["powershell"], eids: ["4103"] },
  ps_classic_start:     { channels: ["powershell"], eids: ["400"] },
};

// Service-to-channel mapping
const SERVICE_MAP = {
  security:       ["security"],
  system:         ["system"],
  sysmon:         ["sysmon"],
  powershell:     ["powershell"],
  taskscheduler:  ["taskscheduler"],
  "powershell-classic": ["powershell"],
  application:    ["application"],
  "dns-server":   ["dns-server"],
  firewall:       ["firewall"],
  "bits-client":  ["bits"],
  wmi:            ["wmi-activity"],
  "windows-defender": ["windows defender"],
  applocker:      ["applocker"],
  codeintegrity:  ["code integrity"],
  printservice:   ["printservice"],
  smbclient:      ["smbclient"],
  ldap:           ["ldap"],
  ntlm:           ["ntlm"],
  windefend:       ["windows defender"],
  "microsoft-windows-windows-defender": ["windows defender"],
  openssh:         ["openssh"],
  shellcore:       ["shellcore"],
  "terminalservices-localsessionmanager": ["localsessionmanager"],
  "terminal-services-local-session-manager": ["localsessionmanager"],
  "terminalservices-remoteconnectionmanager": ["remoteconnectionmanager"],
  certificateservices: ["certificateservices"],
  vhdmp:           ["vhdmp"],
  msexchange:      ["msexchange"],
  "lsa-server":    ["lsa-server"],
};

/**
 * Map a Sigma logsource to SQL filter constraints.
 *
 * @param {object} logsource - { product, category, service }
 * @returns {{ channels: string[], eids: string[], channelSql: string, eidSql: string }}
 */
function mapLogsource(logsource) {
  const { product, category, service } = logsource;

  let channels = [];
  let eids = [];

  // Category takes priority (most specific)
  if (category && CATEGORY_MAP[category]) {
    const mapped = CATEGORY_MAP[category];
    channels = mapped.channels;
    eids = mapped.eids;
  }

  // Service adds channel constraint
  if (service && SERVICE_MAP[service]) {
    const svcChannels = SERVICE_MAP[service];
    if (channels.length === 0) {
      channels = svcChannels;
    } else {
      // Intersect if both category and service specify channels
      channels = channels.filter(c => svcChannels.includes(c));
      if (channels.length === 0) channels = svcChannels; // fallback to service channels
    }
  }

  // Product: windows is the default, no additional filtering needed
  // Non-windows products should be skipped
  if (product && product !== "windows") {
    return { channels: [], eids: [], skip: true };
  }

  return { channels, eids, skip: false };
}

/**
 * Generate a unique logsource key for grouping rules.
 */
function logsourceKey(logsource) {
  return `${logsource.category || ""}|${logsource.service || ""}|${logsource.product || ""}`;
}

module.exports = { mapLogsource, logsourceKey, CATEGORY_MAP, SERVICE_MAP };
