import { useMemo } from "react";
import { buildRuleHealthReport, formatRuleHealthReportText } from "../../../utils/process-rule-health.js";
import { PI_TYPOGRAPHY } from "../constants.js";

/**
 * Rule health / coverage report panel for Process Inspector results.
 */
export default function ProcessTreeRuleHealthPanel({
  detMap,
  seqMap,
  disabledRules,
  customRules,
  th,
  onClose,
  onCopy,
  onDownload,
}) {
  const report = useMemo(
    () => buildRuleHealthReport(detMap, {
      disabledRules,
      customRules,
      seqMap,
    }),
    [detMap, disabledRules, customRules, seqMap],
  );

  const s = report.summary;
  const pill = (label, value, color) => (
    <div style={{
      padding: "8px 10px", borderRadius: 8, minWidth: 88,
      background: `${color}12`, border: `1px solid ${color}28`,
    }}>
      <div style={{ fontSize: PI_TYPOGRAPHY.metric, fontWeight: 800, color, fontFamily: "'SF Mono', Menlo, monospace" }}>{value}</div>
      <div style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>{label}</div>
    </div>
  );

  const sevColor = (sev) => {
    if (sev === "critical") return th.sev.critical;
    if (sev === "high") return th.sev.high;
    if (sev === "medium" || sev === "med") return th.sev.med;
    return th.textMuted;
  };

  const text = formatRuleHealthReportText(report);

  return (
    <div style={{
      flex: 1, minHeight: 0, overflow: "auto", padding: "12px 20px 20px",
      background: th.modalBg,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
        <div style={{ fontSize: PI_TYPOGRAPHY.heading, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif" }}>
          Rule Health & Coverage
        </div>
        <span style={{ fontSize: PI_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
          {report.processesScored.toLocaleString()} scored · {report.processesDetected.toLocaleString()} detected
        </span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          <button
            type="button"
            onClick={() => onCopy?.(text)}
            style={{ padding: "4px 8px", fontSize: PI_TYPOGRAPHY.control, borderRadius: 4, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif" }}
          >Copy Report</button>
          <button
            type="button"
            onClick={() => onDownload?.(text)}
            style={{ padding: "4px 8px", fontSize: PI_TYPOGRAPHY.control, borderRadius: 4, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif" }}
          >↓ TXT</button>
          <button
            type="button"
            onClick={onClose}
            style={{ padding: "4px 8px", fontSize: PI_TYPOGRAPHY.control, borderRadius: 4, cursor: "pointer", background: `${th.accent}18`, color: th.accent, border: `1px solid ${th.accent}33`, fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}
          >Close</button>
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
        {pill("Coverage", `${s.coveragePct}%`, th.accent)}
        {pill("Fired", s.fired, th.sev.high)}
        {pill("Silent", s.silent, th.textMuted)}
        {pill("Disabled", s.disabled, th.sev.med)}
        {pill("Custom hit", `${s.customFired}/${s.customTotal}`, th.sev.clean)}
        {pill("Sequences", `${s.sequencesFired}/${s.sequencesTotal}`, th.sev.critical)}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, alignItems: "start" }}>
        <section style={{ padding: 12, borderRadius: 10, border: `1px solid ${th.border}33`, background: `${th.panelBg}66` }}>
          <div style={{ fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>
            Fired rules by severity
          </div>
          {report.topFired.length === 0 ? (
            <div style={{ fontSize: PI_TYPOGRAPHY.body, color: th.textMuted }}>No rule hits yet (still scoring or clean dataset).</div>
          ) : report.topFired.map((r) => (
            <div key={r.id} style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 0", borderBottom: `1px solid ${th.border}18` }}>
              <span style={{ fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, color: sevColor(r.sev), fontFamily: "'SF Mono', Menlo, monospace", minWidth: 36 }}>{r.hits}×</span>
              <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${sevColor(r.sev)}18`, color: sevColor(r.sev), fontFamily: "'SF Mono', Menlo, monospace", textTransform: "uppercase" }}>{r.sev}</span>
              <span style={{ fontSize: PI_TYPOGRAPHY.body, color: th.text, fontFamily: "-apple-system, sans-serif", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                <span style={{ color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginRight: 6 }}>{r.id}</span>
                {r.name}
              </span>
            </div>
          ))}
        </section>

        <section style={{ padding: 12, borderRadius: 10, border: `1px solid ${th.border}33`, background: `${th.panelBg}66` }}>
          <div style={{ fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>
            Silent high-value rules
          </div>
          <div style={{ fontSize: PI_TYPOGRAPHY.control, color: th.textDim, marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>
            Enabled critical/high rules with zero hits on this dataset — useful for tuning and coverage gaps.
          </div>
          {report.silentHighValue.length === 0 ? (
            <div style={{ fontSize: PI_TYPOGRAPHY.body, color: th.textMuted }}>None — all high-value enabled rules fired at least once.</div>
          ) : report.silentHighValue.map((r) => (
            <div key={r.id} style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 0", borderBottom: `1px solid ${th.border}18` }}>
              <span style={{ fontSize: PI_TYPOGRAPHY.badge, padding: "1px 5px", borderRadius: 3, background: `${sevColor(r.sev)}18`, color: sevColor(r.sev), fontFamily: "'SF Mono', Menlo, monospace", textTransform: "uppercase" }}>{r.sev}</span>
              <span style={{ fontSize: PI_TYPOGRAPHY.body, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                <span style={{ color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginRight: 6 }}>{r.id}</span>
                {r.name}
              </span>
            </div>
          ))}
        </section>

        <section style={{ padding: 12, borderRadius: 10, border: `1px solid ${th.border}33`, background: `${th.panelBg}66` }}>
          <div style={{ fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>
            By group
          </div>
          {report.byGroup.map((g) => (
            <div key={g.id} style={{ display: "flex", gap: 8, alignItems: "center", padding: "5px 0", borderBottom: `1px solid ${th.border}18` }}>
              <span style={{ flex: 1, fontSize: PI_TYPOGRAPHY.body, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{g.label}</span>
              <span style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.sev.high, fontFamily: "'SF Mono', Menlo, monospace" }}>{g.fired} fired</span>
              <span style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>{g.silent} silent</span>
              {g.disabled > 0 && <span style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.sev.med, fontFamily: "'SF Mono', Menlo, monospace" }}>{g.disabled} off</span>}
              <span style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.accent, fontFamily: "'SF Mono', Menlo, monospace" }}>{g.hits} hits</span>
            </div>
          ))}
        </section>

        <section style={{ padding: 12, borderRadius: 10, border: `1px solid ${th.border}33`, background: `${th.panelBg}66` }}>
          <div style={{ fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>
            Sequences
          </div>
          {report.sequences.map((seq) => (
            <div key={seq.id} style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 0", borderBottom: `1px solid ${th.border}18` }}>
              <span style={{
                fontSize: PI_TYPOGRAPHY.meta, fontWeight: 700, minWidth: 28, fontFamily: "'SF Mono', Menlo, monospace",
                color: seq.hits > 0 ? th.sev.critical : th.textMuted,
              }}>{seq.hits}×</span>
              <span style={{ fontSize: PI_TYPOGRAPHY.body, color: seq.hits > 0 ? th.text : th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{seq.name}</span>
              <span style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginLeft: "auto" }}>{seq.id}</span>
            </div>
          ))}
          {report.techniques.length > 0 && (
            <>
              <div style={{ fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", margin: "12px 0 6px" }}>
                Techniques seen
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {report.techniques.slice(0, 24).map((t) => (
                  <span key={t.tid} style={{
                    fontSize: PI_TYPOGRAPHY.meta, padding: "2px 6px", borderRadius: 4,
                    background: `${th.accent}14`, color: th.accent, border: `1px solid ${th.accent}28`,
                    fontFamily: "'SF Mono', Menlo, monospace",
                  }}>{t.tid} · {t.count}</span>
                ))}
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
