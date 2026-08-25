import { useState, useEffect, useCallback } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { Modal, Button, Input } from "../primitives/index.js";

export default function PresetsModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const ct = useCurrentTab();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const up = useCallback((key, value) => {
    useTabStore.getState().updateActiveTab({ [key]: value });
  }, []);

  const [filterPresets, setFilterPresets] = useState([]);
  useEffect(() => {
    if (tle) tle.loadFilterPresets().then((p) => setFilterPresets(p || [])).catch(() => {});
  }, [tle]);

  if (modal?.type !== "presets" || !ct) return null;

  const BUILTIN_PRESETS = [
    { name: "Lateral Movement", builtin: true, searchTerm: "psexec OR wmi OR schtasks OR winrm OR rdp", searchMode: "or" },
    { name: "Persistence Mechanisms", builtin: true, searchTerm: "Run OR RunOnce OR schtasks OR service OR Startup", searchMode: "or" },
    { name: "Credential Access", builtin: true, searchTerm: "mimikatz OR lsass OR credential OR sekurlsa OR kerberos", searchMode: "or" },
    { name: "Encoded Commands", builtin: true, searchTerm: "-encodedcommand OR -enc OR FromBase64", searchMode: "or" },
    { name: "Suspicious Execution", builtin: true, searchTerm: "powershell OR cmd.exe OR wscript OR cscript OR mshta OR certutil OR bitsadmin", searchMode: "or" },
    { name: "Data Exfiltration", builtin: true, searchTerm: "ftp OR curl OR wget OR Invoke-WebRequest OR compress OR archive OR rar", searchMode: "or" },
    { name: "Defense Evasion", builtin: true, searchTerm: "del OR wevtutil OR Clear-EventLog OR Disable-WindowsOptionalFeature OR Set-MpPreference", searchMode: "or" },
    { name: "Discovery", builtin: true, searchTerm: "whoami OR ipconfig OR net user OR systeminfo OR nltest OR tasklist OR netstat", searchMode: "or" },
  ];
  const NOISE_PRESETS = [
    { name: "Suppress Windows Updates & Servicing", builtin: true, noise: true,
      searchTerm: "", searchMode: "mixed",
      advancedFilters: [
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-WindowsUpdateClient", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Servicing", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-WUSA", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-CBS", logic: "AND" },
        { column: "Channel", operator: "not_contains", value: "Microsoft-Windows-WindowsUpdateClient", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-WindowsUpdateClient", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-Servicing", logic: "AND" },
      ],
    },
    { name: "Suppress Defender & Antimalware", builtin: true, noise: true,
      searchTerm: "", searchMode: "mixed",
      advancedFilters: [
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Windows Defender", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft Antimalware", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-AppLocker", logic: "AND" },
        { column: "Channel", operator: "not_contains", value: "Microsoft-Windows-Windows Defender", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-Windows Defender", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft Antimalware", logic: "AND" },
      ],
    },
    { name: "Suppress BITS & Telemetry", builtin: true, noise: true,
      searchTerm: "", searchMode: "mixed",
      advancedFilters: [
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Bits-Client", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Diagnosis", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Diagnostics-Performance", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-TaskScheduler", logic: "AND" },
        { column: "Channel", operator: "not_contains", value: "Microsoft-Windows-TaskScheduler", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-Bits-Client", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-TaskScheduler", logic: "AND" },
      ],
    },
    { name: "Suppress All Common Noise", builtin: true, noise: true,
      searchTerm: "", searchMode: "mixed",
      advancedFilters: [
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-WindowsUpdateClient", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Servicing", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-CBS", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Windows Defender", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft Antimalware", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Bits-Client", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Diagnosis", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Diagnostics-Performance", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-Kernel-PnP", logic: "AND" },
        { column: "Provider", operator: "not_contains", value: "Microsoft-Windows-FilterManager", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-WindowsUpdateClient", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-Servicing", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-Windows Defender", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-Bits-Client", logic: "AND" },
        { column: "Provider Name", operator: "not_contains", value: "Microsoft-Windows-Kernel-PnP", logic: "AND" },
        { column: "Channel", operator: "not_contains", value: "Microsoft-Windows-WindowsUpdateClient", logic: "AND" },
        { column: "Channel", operator: "not_contains", value: "Microsoft-Windows-Windows Defender", logic: "AND" },
      ],
    },
  ];
  const presetSummary = (p) => {
    const parts = [];
    if (p.searchTerm) parts.push(`search: "${p.searchTerm.length > 40 ? p.searchTerm.slice(0, 40) + "..." : p.searchTerm}"`);
    const cf = Object.keys(p.columnFilters || {}).filter((k) => p.columnFilters[k]);
    if (cf.length) parts.push(`${cf.length} col filter${cf.length > 1 ? "s" : ""}`);
    const cb = Object.keys(p.checkboxFilters || {}).filter((k) => p.checkboxFilters[k]?.length);
    if (cb.length) parts.push(`${cb.length} value filter${cb.length > 1 ? "s" : ""}`);
    const dr = Object.keys(p.dateRangeFilters || {}).length;
    if (dr) parts.push(`${dr} date range${dr > 1 ? "s" : ""}`);
    if (p.showBookmarkedOnly) parts.push("flagged only");
    const af = (p.advancedFilters || []).length;
    if (af) parts.push(`${af} advanced filter${af > 1 ? "s" : ""}`);
    if (p.sortCol) parts.push(`sort: ${p.sortCol} ${p.sortDir || "asc"}`);
    if (p.searchHighlight) parts.push("highlight mode");
    const hc = Array.isArray(p.hiddenColumns) ? p.hiddenColumns.length : 0;
    if (hc) parts.push(`${hc} hidden col${hc > 1 ? "s" : ""}`);
    const pc = Array.isArray(p.pinnedColumns) ? p.pinnedColumns.length : 0;
    if (pc) parts.push(`${pc} pinned`);
    if (p.columnOrder) parts.push("custom order");
    return parts.join(" · ") || "no filters";
  };
  const applyPreset = (preset) => {
    if (preset.searchTerm !== undefined) up("searchTerm", preset.searchTerm);
    if (preset.searchMode) up("searchMode", preset.searchMode);
    if (preset.searchCondition) up("searchCondition", preset.searchCondition);
    if (preset.searchHighlight !== undefined) up("searchHighlight", preset.searchHighlight);
    if (preset.columnFilters) up("columnFilters", preset.columnFilters);
    if (preset.checkboxFilters) up("checkboxFilters", preset.checkboxFilters);
    if (preset.dateRangeFilters) up("dateRangeFilters", preset.dateRangeFilters);
    if (preset.showBookmarkedOnly !== undefined) up("showBookmarkedOnly", preset.showBookmarkedOnly);
    if (preset.sortCol !== undefined) up("sortCol", preset.sortCol);
    if (preset.sortDir) up("sortDir", preset.sortDir);
    if (preset.tagFilter !== undefined) up("tagFilter", preset.tagFilter);
    if (preset.advancedFilters) up("advancedFilters", preset.advancedFilters);
    // Column state (saved view) — only applied if present (backwards-compatible)
    if (Array.isArray(preset.hiddenColumns)) up("hiddenColumns", new Set(preset.hiddenColumns));
    if (preset.columnOrder) up("columnOrder", preset.columnOrder);
    if (preset.columnWidths && Object.keys(preset.columnWidths).length > 0) up("columnWidths", preset.columnWidths);
    if (Array.isArray(preset.pinnedColumns)) up("pinnedColumns", preset.pinnedColumns);
    setModal(null);
  };
  const savePreset = (name) => {
    if (!name.trim()) return;
    const preset = {
      name: name.trim(), savedAt: new Date().toISOString(),
      searchTerm: ct.searchTerm || "", searchMode: ct.searchMode || "mixed",
      searchCondition: ct.searchCondition || "contains", searchHighlight: ct.searchHighlight || false,
      columnFilters: ct.columnFilters || {}, checkboxFilters: ct.checkboxFilters || {},
      dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [], showBookmarkedOnly: ct.showBookmarkedOnly || false,
      sortCol: ct.sortCol || null, sortDir: ct.sortDir || "asc", tagFilter: ct.tagFilter || null,
      // Column state (saved view)
      hiddenColumns: ct.hiddenColumns ? [...ct.hiddenColumns] : [],
      columnOrder: ct.columnOrder || null,
      columnWidths: ct.columnWidths || {},
      pinnedColumns: ct.pinnedColumns ? [...ct.pinnedColumns] : [],
    };
    const updated = [...filterPresets, preset];
    setFilterPresets(updated);
    tle.saveFilterPresets(updated);
  };
  const deletePreset = (idx) => {
    const updated = filterPresets.filter((_, i) => i !== idx);
    setFilterPresets(updated);
    tle.saveFilterPresets(updated);
  };
  const clearFilters = () => {
    up("searchTerm", ""); up("searchMode", "mixed"); up("searchCondition", "contains");
    up("searchHighlight", false); up("columnFilters", {}); up("checkboxFilters", {});
    up("dateRangeFilters", {}); up("showBookmarkedOnly", false);
    up("sortCol", null); up("sortDir", "asc"); up("tagFilter", null);
    up("disabledFilters", new Set()); up("advancedFilters", []);
    setModal(null);
  };

  const headerExtra = (
    <Button
      size="sm"
      variant="dangerSoft"
      onClick={clearFilters}
    >
      Clear All Filters
    </Button>
  );

  const labelStyle = { fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system,sans-serif" };

  return (
    <Modal
      title="Filter Presets"
      width={480}
      maxHeight="80vh"
      onClose={() => setModal(null)}
      bodyPadding="16px 20px"
      headerExtra={headerExtra}
      footer={true}
    >
      {/* Save current */}
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        <Input
          id="preset-name-input"
          placeholder="Save current filters as..."
          onKeyDown={(e) => { if (e.key === "Enter" && e.target.value.trim()) { savePreset(e.target.value); e.target.value = ""; } }}
          style={{ flex: 1 }}
        />
        <Button onClick={() => {
          const inp = document.getElementById("preset-name-input");
          if (inp?.value?.trim()) { savePreset(inp.value); inp.value = ""; }
        }}>Save</Button>
      </div>

      {filterPresets.length > 0 && (
        <>
          <div style={labelStyle}>Saved Presets</div>
          <div style={{ maxHeight: "30vh", overflow: "auto", marginBottom: 14 }}>
            {filterPresets.map((p, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 0", borderBottom: `1px solid ${th.border}33` }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: th.text, fontSize: 12, fontWeight: 500 }}>{p.name}</div>
                  <div style={{ color: th.textMuted, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{presetSummary(p)}</div>
                </div>
                <Button size="sm" variant="accentSoft" onClick={() => applyPreset(p)}>Apply</Button>
                <button onClick={() => deletePreset(i)}
                  style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 12, padding: "0 4px" }}>✕</button>
              </div>
            ))}
          </div>
        </>
      )}

      <div style={labelStyle}>DFIR Quick Filters</div>
      <div style={{ maxHeight: "30vh", overflow: "auto" }}>
        {BUILTIN_PRESETS.map((p, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: th.text, fontSize: 12, fontWeight: 500 }}>{p.name}</div>
              <div style={{ color: th.textMuted, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{presetSummary(p)}</div>
            </div>
            <Button size="sm" variant="accentSoft" onClick={() => applyPreset(p)}>Apply</Button>
          </div>
        ))}
      </div>

      <div style={{ ...labelStyle, marginTop: 14 }}>Noise Suppression</div>
      <div style={{ fontSize: 10, color: th.textMuted, marginBottom: 8, fontFamily: "-apple-system,sans-serif", lineHeight: 1.4 }}>
        Exclude common benign Windows event sources. Targets Provider/Channel columns — filters are ignored if those columns don't exist in your data.
      </div>
      <div style={{ maxHeight: "30vh", overflow: "auto" }}>
        {NOISE_PRESETS.map((p, i) => (
          <div key={`noise-${i}`} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: th.text, fontSize: 12, fontWeight: 500 }}>{p.name}</div>
              <div style={{ color: th.textMuted, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{(p.advancedFilters || []).length} exclusion rules</div>
            </div>
            <button onClick={() => applyPreset(p)}
              style={{ padding: "3px 10px", background: th.warning + "22", border: `1px solid ${th.warning}44`, color: th.warning, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
              Apply
            </button>
          </div>
        ))}
      </div>
    </Modal>
  );
}
