// analyzer-launch.js — shared header/format detection + capability launchers.
//
// Single source of truth for resolving analyzer column mappings from a tab's
// headers and for turning a freshly-imported tab into an open analyzer modal.
// Both launch paths consume these helpers, so detection stays identical:
//   • the home-screen capability tiles (src/App.jsx, HOME_CAPABILITY_LAUNCHERS)
//   • the Tools menu (src/components/MenuBar.jsx imports buildProcessInspectorCols /
//     buildLateralMovementCols / buildPersistenceMode from here).

import {
  isChainsawProcessDataset,
  isChainsawLogonDataset,
  isChainsawDataset,
} from "./dataset-detect.js";
import { buildPiCols } from "../components/process-analyzer/menu-columns.js";
import {
  openProcessTreeModal,
  openLateralMovementModal,
  openPersistenceModal,
  openIocLoadModal,
  openRansomwareModal,
  openUsnAnalysisModal,
} from "../modals/modalRegistry.js";

// First header matching any of the patterns, else null.
function det(headers, pats) {
  for (const p of pats) {
    const f = headers.find((h) => p.test(h));
    if (f) return f;
  }
  return null;
}

// Detect the dataset "shape" so column resolvers can pick format-specific aliases.
// Mirrors the booleans computed at the top of MenuBar.buildToolsItems().
export function detectFormats(headers = []) {
  const isEvtxECmdPT =
    headers.some((h) => /^PayloadData1$/i.test(h)) && headers.some((h) => /^ExecutableInfo$/i.test(h));
  const isHayabusa =
    headers.some((h) => /^RuleTitle$/i.test(h)) &&
    headers.some((h) => /^Details$/i.test(h)) &&
    headers.some((h) => /^EventID$/i.test(h));
  const isChainsawProcess = isChainsawProcessDataset(headers);
  const isSec4688 =
    !isEvtxECmdPT && !isHayabusa && !isChainsawProcess && headers.some((h) => /^NewProcess(Name|Id)$/i.test(h));
  const isChainsawLogons = isChainsawLogonDataset(headers);
  const isEvtxECmd =
    headers.some((h) => /^RemoteHost$/i.test(h)) && headers.some((h) => /^PayloadData1$/i.test(h));
  return { isEvtxECmdPT, isHayabusa, isChainsawProcess, isSec4688, isChainsawLogons, isEvtxECmd };
}

// Process Inspector column mapping (delegates to the process-analyzer resolver).
export function buildProcessInspectorCols(headers = []) {
  const { isEvtxECmdPT, isHayabusa, isChainsawProcess, isSec4688 } = detectFormats(headers);
  return buildPiCols({ headers, isEvtxECmdPT, isHayabusa, isChainsawProcess, isSec4688 });
}

// Lateral Movement column mapping + the synthetic-target fallback Chainsaw needs.
export function buildLateralMovementCols(headers = []) {
  const { isHayabusa, isChainsawLogons, isEvtxECmd } = detectFormats(headers);
  const d = (pats) => det(headers, pats);
  const cols = {
    source:
      d([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^RemoteHost$/i, ...(isChainsawLogons ? [/^source_ip$/i] : [])]) ||
      (isHayabusa ? d([/^Details$/i]) : null),
    target: d([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i]),
    // EvtxECmd column priority: PayloadData1 ("Target: DOMAIN\\User") MUST come before
    // UserName (which for EvtxECmd is the Subject/initiator, often "-\\-").
    user:
      d([/^TargetUserName$/i, /^Target_User_Name$/i, ...(isEvtxECmd ? [/^PayloadData1$/i] : []), /^UserName$/i, ...(isChainsawLogons ? [/^target_username$/i] : [])]) ||
      (isHayabusa ? d([/^Details$/i]) : null),
    logonType:
      d([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsawLogons ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]) ||
      (isHayabusa ? d([/^Details$/i]) : null),
    eventId: d([/^EventID$/i, /^event_id$/i, /^EventId$/, ...(isChainsawLogons ? [/^id$/i] : [])]),
    ts: d([/^Timestamp$/i, /^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, ...(isChainsawLogons ? [/^system_time$/i] : [])]),
    domain: d([/^TargetDomainName$/i]) || (isHayabusa ? (d([/^ExtraFieldInfo$/i]) || d([/^Details$/i])) : null),
  };
  const chainsawSyntheticTarget = isChainsawLogons && !cols.target ? "LOCAL_HOST" : "";
  return { cols, chainsawSyntheticTarget };
}

// Persistence auto-mode: registry (hive dump), evtx (event log), or auto.
export function buildPersistenceMode(headers = []) {
  const d = (pats) => det(headers, pats);
  const hasKeyPath = d([/^KeyPath$/i, /^Key ?Path$/i]);
  const hasValueName = d([/^ValueName$/i, /^Value ?Name$/i]);
  const hasEventId = d([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsawDataset(headers) ? [/^id$/i] : [])]);
  return hasKeyPath && hasValueName ? "registry" : hasEventId ? "evtx" : "auto";
}

// Capability key → { compatible(tab), incompatibleHint?, buildModal(tab) }.
// `tab` is a lightweight { id, headers, sourceFormat, dataReady } snapshot taken at
// import-complete. Universal analyzers accept any ready timeline (matching MenuBar's
// dataReady-only gate); format-specific ones declare an incompatibleHint so a wrong
// file lands the user in the grid with a clear explanation instead of an empty modal.
export const HOME_CAPABILITY_LAUNCHERS = {
  processInspector: {
    compatible: (tab) => !!tab?.dataReady,
    buildModal: (tab) => openProcessTreeModal(buildProcessInspectorCols(tab.headers || [])),
  },
  lateralMovement: {
    compatible: (tab) => !!tab?.dataReady,
    buildModal: (tab) => {
      const { cols, chainsawSyntheticTarget } = buildLateralMovementCols(tab.headers || []);
      return openLateralMovementModal(cols, { chainsawSyntheticTarget });
    },
  },
  persistence: {
    compatible: (tab) => !!tab?.dataReady,
    buildModal: (tab) => openPersistenceModal({ mode: buildPersistenceMode(tab.headers || []) }),
  },
  ioc: {
    compatible: (tab) => !!tab?.dataReady,
    buildModal: () => openIocLoadModal(),
  },
  mft: {
    // Master File Table → Ransomware Analysis. Mirrors MenuBar's Ransomware gate:
    // a raw $MFT carrying the columns the analyzer reads. usnTabId defaults to
    // "__none__" (modalRegistry) — the home path imports a single $MFT, so there is
    // rarely a $J tab to auto-pair; the user can select one inside the modal.
    compatible: (tab) =>
      !!tab?.dataReady &&
      tab?.sourceFormat === "raw-mft" &&
      ["Extension", "FileName", "ParentPath", "LastModified0x10"].every((c) => (tab.headers || []).includes(c)),
    incompatibleHint: "Ransomware Analysis needs a raw $MFT — opened it in the grid instead.",
    buildModal: () => openRansomwareModal(),
  },
  usn: {
    compatible: (tab) => !!tab?.dataReady && tab?.sourceFormat === "raw-usnjrnl",
    incompatibleHint: "USN Journal Analysis needs a $J / USN Journal file — opened it in the grid instead.",
    buildModal: () => openUsnAnalysisModal(),
  },
};
