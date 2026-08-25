import { levelsAtOrAboveMinimum } from "../../../utils/sigmaScanPresets.mjs";
import { SEV_ORDER, STATUS_LIST } from "./constants.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";

export default function SigmaPresetStep() {
  const {
    modal,
    setModal,
    th,
    ms,
    scanMode,
    levels,
    statuses,
    hayabusaMinSeverity,
    hayabusaLevelList,
    ruleInfo,
    hasRules,
    renderScanPresetPanel,
    checkbox,
    handleLoadRuleInfo,
  } = useSigmaModalContext();

  const open = !!modal.showProfile;

  // One-line summary shown while the section is collapsed. Mirrors the source the
  // scan actually uses per mode: hayabusaMinSeverity for the EVTX/Hayabusa engine,
  // the explicit severity checkboxes for JS Sigma (tab / EvtxECmd).
  const selLevels = SEV_ORDER.filter((l) => levels[l]);
  const selStatuses = STATUS_LIST.filter((s) => statuses[s]);
  const sevText = scanMode === "evtx-dir"
    ? `${hayabusaMinSeverity}+`
    : selLevels.length === SEV_ORDER.length ? "all severities" : (selLevels.join("/") || "none");
  const statusText = selStatuses.length === STATUS_LIST.length ? "all statuses" : (selStatuses.join("/") || "none");
  const summaryChip = modal.activeScanPresetName || `${sevText} · ${statusText}`;

  return (
    <div style={{ ...ms.fg }}>
      {/* Detection profile — collapsed by default; one click to tune presets/severity/status. */}
      <button
        onClick={() => setModal((p) => p?.type === "sigma" ? { ...p, showProfile: !p.showProfile } : p)}
        style={{ display: "flex", alignItems: "center", gap: 8, background: "none", border: "none", cursor: "pointer", padding: "4px 0", width: "100%", minWidth: 0 }}
      >
        <span style={{ fontSize: 9, color: th.textMuted, transition: "transform var(--m-base)", transform: open ? "rotate(90deg)" : "rotate(0deg)", flexShrink: 0 }}>{"▶"}</span>
        <span style={{ fontSize: 10, color: th.textDim, fontWeight: 700, fontFamily: "-apple-system,sans-serif", textTransform: "uppercase", letterSpacing: "0.06em", flexShrink: 0 }}>Detection profile</span>
        {!open && (
          <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }}>{summaryChip}</span>
        )}
        <span style={{ marginLeft: "auto", fontSize: 9, color: th.textMuted, fontFamily: "-apple-system,sans-serif", flexShrink: 0 }}>{open ? "Hide" : "Presets, severity & status"}</span>
      </button>

      {open && (
        <div style={{ marginTop: 6 }}>
          {renderScanPresetPanel()}

          {scanMode === "evtx-dir" ? (
            <div style={{ ...ms.fg }}>
              <label style={ms.lb}>Minimum Severity</label>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <select
                  value={hayabusaMinSeverity}
                  onChange={(e) => {
                    const minSeverity = e.target.value;
                    const nextLevels = levelsAtOrAboveMinimum(minSeverity);
                    setModal((p) => ({
                      ...p,
                      hayabusaMinSeverity: minSeverity,
                      levels: Object.fromEntries(SEV_ORDER.map((level) => [level, nextLevels.includes(level)])),
                      activeScanPresetId: null,
                      activeScanPresetName: null,
                      scanPreflight: null,
                    }));
                  }}
                  style={{ ...ms.sl, width: "auto", flex: "0 0 180px" }}
                >
                  {[
                    ["critical", "Critical only"],
                    ["high", "High and above"],
                    ["medium", "Medium and above"],
                    ["low", "Low and above"],
                    ["informational", "Informational and above"],
                  ].map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
                <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace" }}>
                  Includes {hayabusaLevelList.join(", ")}
                </span>
              </div>
            </div>
          ) : (
            <div style={{ ...ms.fg }}>
              <label style={ms.lb}>Severity Filter</label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
                {SEV_ORDER.map((l) => checkbox(l.charAt(0).toUpperCase() + l.slice(1), levels[l], () => setModal((p) => ({ ...p, levels: { ...levels, [l]: !levels[l] }, activeScanPresetId: null, activeScanPresetName: null }))))}
              </div>
            </div>
          )}

          <div style={{ ...ms.fg }}>
            <label style={ms.lb}>Status Filter</label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
              {STATUS_LIST.map((s) => checkbox(s.charAt(0).toUpperCase() + s.slice(1), statuses[s], () => setModal((p) => ({ ...p, statuses: { ...statuses, [s]: !statuses[s] }, activeScanPresetId: null, activeScanPresetName: null, scanPreflight: null }))))}
            </div>
          </div>

          {/* Category selector — for JS Sigma compatibility scans */}
          {(modal.scanMode || "evtx-dir") !== "evtx-dir" && ruleInfo?.byCategory && Object.keys(ruleInfo.byCategory).length > 0 && (() => {
            const cats = Object.entries(ruleInfo.byCategory).sort((a, b) => b[1] - a[1]);
            const selectedCats = modal.selectedCategories || null; // null = all selected
            const allSelected = !selectedCats;
            const isCatSelected = (cat) => allSelected || selectedCats?.includes(cat);
            const totalSelected = allSelected ? cats.length : (selectedCats || []).length;
            const toggleCat = (cat) => {
              setModal((p) => {
                const current = p.selectedCategories || cats.map(([c]) => c); // expand "all" to explicit list
                const idx = current.indexOf(cat);
                const next = idx >= 0 ? current.filter(c => c !== cat) : [...current, cat];
                return { ...p, selectedCategories: next.length === cats.length ? null : next }; // null = all
              });
            };
            return (
              <div style={{ ...ms.fg }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                  <label style={{ ...ms.lb, margin: 0 }}>Rule Categories ({totalSelected}/{cats.length})</label>
                  <div style={{ display: "flex", gap: 4 }}>
                    <button onClick={() => setModal((p) => ({ ...p, selectedCategories: null }))} style={{ ...ms.bsm, fontSize: 9, padding: "1px 6px", opacity: allSelected ? 0.5 : 1 }}>Select All</button>
                    <button onClick={() => setModal((p) => ({ ...p, selectedCategories: [] }))} style={{ ...ms.bsm, fontSize: 9, padding: "1px 6px" }}>Clear</button>
                  </div>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 3, maxHeight: 120, overflow: "auto" }}>
                  {cats.map(([cat, count]) => {
                    const sel = isCatSelected(cat);
                    const catColor = th.accent; // selected category chips use the brand accent (was rainbow-by-category)
                    return (
                      <button key={cat} onClick={() => toggleCat(cat)}
                        style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 6, fontSize: 10, cursor: "pointer",
                          background: sel ? `${catColor}15` : "transparent",
                          color: sel ? catColor : th.textMuted,
                          border: `1px solid ${sel ? catColor + "44" : th.border + "33"}`,
                          fontFamily: "-apple-system, sans-serif", fontWeight: sel ? 500 : 400,
                          transition: "all var(--m-base)", opacity: sel ? 1 : 0.6 }}>
                        <span style={{ fontSize: 9 }}>{sel ? "✓" : "○"}</span>
                        {cat}
                        <span style={{ fontWeight: 600, fontSize: 9 }}>{count}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })()}
          {(modal.scanMode || "evtx-dir") !== "evtx-dir" && !ruleInfo && hasRules && (
            <button onClick={handleLoadRuleInfo} style={{ ...ms.bsm, marginBottom: 10 }}>Load category breakdown</button>
          )}
        </div>
      )}
    </div>
  );
}
