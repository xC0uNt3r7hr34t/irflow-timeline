import { KAPE_PROFILES } from "../constants/kape-profiles.js";

export function detectKapeProfile(headers) {
  const headerSet = new Set((headers || []).map((h) => String(h).toLowerCase()));
  for (const [name, profile] of Object.entries(KAPE_PROFILES)) {
    if (profile.detect.every((col) => headerSet.has(String(col).toLowerCase()))) return { name, ...profile };
  }
  return null;
}

export function isChainsawDataset(headers) {
  const has = (re) => (headers || []).some((h) => re.test(h));
  return has(/^system_time$/i) && has(/^id$/i)
    && (has(/^detection_rules$/i) || has(/^computer_name$/i) || has(/^workstation_name$/i));
}

export function isChainsawProcessDataset(headers) {
  const has = (re) => (headers || []).some((h) => re.test(h));
  return isChainsawDataset(headers)
    && (has(/^process_name$/i) || has(/^Event\.EventData\.Image$/i) || has(/^command_line$/i) || has(/^Event\.EventData\.CommandLine$/i));
}

export function isChainsawLogonDataset(headers) {
  const has = (re) => (headers || []).some((h) => re.test(h));
  return isChainsawDataset(headers)
    && has(/^target_username$/i)
    && has(/^logon_type$/i)
    && (has(/^source_ip$/i) || has(/^workstation_name$/i));
}
