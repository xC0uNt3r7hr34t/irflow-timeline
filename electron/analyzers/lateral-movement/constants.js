/**
 * constants.js — module-scope constants for the lateral-movement analyzer.
 *
 * These were previously declared inline (and lazily) inside the
 * getLateralMovement() closure. They are pure, frozen data / regex literals
 * with no captured state, so hoisting them to module scope is behavior-neutral
 * and removes ~15 inline declarations from the orchestrator. Mirrors the
 * pure-constant pattern already used by the sibling network/ analyzer.
 *
 * Consumers import these and alias them back to their original in-function
 * names (e.g. `DC_PAT: _DC_PAT`) so existing usage sites stay unchanged.
 */

// IPs that are never a meaningful lateral-movement source/target.
const EXCLUDED_IPS = new Set(["-", "::1", "127.0.0.1", "0.0.0.0", ""]);

// Built-in/service principals that are not interactive user accounts.
const SERVICE_RE = /^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON)$/i;

// Events used for RDP session correlation but which do NOT create graph edges.
const SESSION_ONLY_EVENTS = new Set(["20", "23", "24", "32", "33", "34", "35", "39", "40", "4634", "4647", "4672", "4769", "4779"]);

// Events that can participate in an RDP authentication/session reconstruction.
// General authentication events remain in the main logon graph, but only this
// subset is copied into the RDP state machine.
const RDP_CONTEXT_EVENT_IDS = new Set([
  "20", "21", "22", "23", "24", "25", "32", "33", "34", "35", "39", "40",
  "1149", "4624", "4625", "4634", "4647", "4648", "4672", "4776", "4778", "4779",
]);

// Human-readable descriptions for RDP/logon event IDs.
const RDP_EVENT_DESC = {
  "1149": "Network auth succeeded", "4624": "Logon succeeded", "4625": "Logon failed",
  "21": "Session logon succeeded", "22": "Shell start notification", "23": "Session logoff",
  "24": "Session disconnected", "25": "Session reconnected", "39": "Disconnected by another session",
  "40": "Session disconnect (reason code)", "4634": "Account logged off", "4647": "User-initiated logoff",
  "4648": "Explicit credentials used", "4672": "Admin privileges assigned",
  "4776": "NTLM authentication", "4778": "Session reconnected (window station)", "4779": "Session disconnected (window station)",
};

// Hostname pattern → likely Domain Controller.
const DC_PAT = /(?:^|[\-_])(DC|PDC|BDC|ADDS|ADCS|ADFS)\d{0,3}(?:$|[\-_])|^AD\d{0,3}$/i;

// Hostname pattern → likely server role.
const SRV_PAT = /^(SVR|SRV|SERVER|FS|SQL|EXCH|MAIL|WEB|APP|DB|CA|WSUS|SCCM|SCOM|PRINT|FILE|DNS|DHCP|NPS|RADIUS|VPN|RDS|RDSH|RDCB|RDGW)/i;

// Hostname pattern → privileged-access / management workstation (jump/bastion/PAM/orchestration).
const MGMT_SRC_PAT = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|MONITOR|NAGIOS|ZABBIX|ANSIBLE|PUPPET|CHEF|SALT|ORCH)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;

// Severity ordering for sorting findings (lower = more severe).
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// Telemetry coverage categories — which event IDs constitute each detection capability.
const TELEMETRY_CATEGORIES = [
  { id: "auth",     label: "Auth (Logon)",      eids: ["4624", "4625"], critical: true },
  { id: "explicit", label: "Explicit Creds",    eids: ["4648"],         critical: false },
  { id: "process",  label: "Process Creation",  eids: ["4688", "1"],    critical: true },
  { id: "service",  label: "Service Install",   eids: ["7045", "4697"], critical: false },
  { id: "task",     label: "Scheduled Task",    eids: ["4698"],         critical: false },
  { id: "rdp",      label: "RDP Session",       eids: ["1149", "21", "22", "25"], critical: false },
  { id: "share",    label: "Share Access",      eids: ["5140", "5145"], critical: false },
  { id: "kerberos", label: "Kerberos",          eids: ["4769", "4768", "4771"], critical: false },
  { id: "ntlm",     label: "NTLM",              eids: ["4776"],         critical: false },
  { id: "dsaccess", label: "DS Access",         eids: ["4662"],         critical: false },
  { id: "sysmon10", label: "Process Access",    eids: ["10"],           critical: false },
];

// Account-name pattern → privileged identity (administrator/root/domain-admin/etc.).
const PRIVILEGED_NAME_RE = /^(ADMINISTRATOR|ADMIN|ROOT|DA[_-]|DOMAIN ADMIN|ENTERPRISE ADMIN|SCHEMA ADMIN|BACKUP)/i;

module.exports = {
  EXCLUDED_IPS,
  SERVICE_RE,
  SESSION_ONLY_EVENTS,
  RDP_CONTEXT_EVENT_IDS,
  RDP_EVENT_DESC,
  DC_PAT,
  SRV_PAT,
  MGMT_SRC_PAT,
  SEV_ORDER,
  TELEMETRY_CATEGORIES,
  PRIVILEGED_NAME_RE,
};
