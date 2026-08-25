import { useMemo } from "react";
import { formatNumber } from "../../../utils/format.js";
import { sevColorsFor } from "./constants.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";
import { buildSigmaTriageSummary } from "./triageSummary.mjs";

function compactTime(value) {
  return value ? String(value).slice(0, 19).replace("T", " ") : "none";
}

function Pill({ children, color, title }) {
  return (
    <span title={title} style={{ display: "inline-flex", alignItems: "center", maxWidth: "100%", padding: "1px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, background: `${color}18`, color, border: `1px solid ${color}33`, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
      {children}
    </span>
  );
}

function MiniList({ title, rows, th, color = th.sev.low, empty = "None in preview" }) {
  return (
    <div style={{ minWidth: 0 }}>
      <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", fontWeight: 800, letterSpacing: "0.05em", marginBottom: 5 }}>{title}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 3, maxHeight: 116, overflow: "auto" }}>
        {rows.length === 0 && <span style={{ color: th.textMuted, fontSize: 10 }}>{empty}</span>}
        {rows.map((row) => (
          <div key={row.value} style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, fontSize: 10, color: th.textDim }}>
            <span title={row.value} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0, fontFamily: "'SF Mono',Menlo,monospace" }}>{row.value}</span>
            <span style={{ marginLeft: "auto", color, fontWeight: 800, fontFamily: "'SF Mono',Menlo,monospace" }}>{formatNumber(row.count)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function SigmaTriageDashboard() {
  const {
    results,
    modal,
    th,
    ms,
    sigmaResultsRef,
    sevBadge,
    mitreBadge,
    handleOpenExactMatchesAsTab,
    handleTagMatches,
    handleBookmarkMatches,
    handleMarkRuleReviewed,
    handleMarkRuleFalsePositive,
  } = useSigmaModalContext();
  const SEV_COLORS = sevColorsFor(th);

  const eventRows = sigmaResultsRef.current?.eventRows || [];
  const aggregates = results?.triageAggregates || sigmaResultsRef.current?.triageAggregates || null;
  const summary = useMemo(() => buildSigmaTriageSummary({
    matches: results?.matches || [],
    eventRows,
    aggregates,
    reviewed: modal.sigmaReviewedRules || {},
    falsePositives: modal.sigmaFalsePositiveRules || {},
  }), [aggregates, eventRows, modal.sigmaFalsePositiveRules, modal.sigmaReviewedRules, results?.matches]);

  const reviewedCount = Object.keys(modal.sigmaReviewedRules || {}).length;
  const falsePositiveCount = Object.keys(modal.sigmaFalsePositiveRules || {}).length;
  const resultOnlyActions = (
    sigmaResultsRef.current?.sourceRowMode === "result" ||
    !!(sigmaResultsRef.current?.isDirScan || sigmaResultsRef.current?.isKapeOutput || sigmaResultsRef.current?.isHistory)
  );
  const sourceMode = resultOnlyActions
    ? "These detections are persisted result rows, not original timeline rows. Open exact hits as a tab, then tag/bookmark rows there."
    : sigmaResultsRef.current?.isHistory
      ? "Open exact hits creates a focused result tab for this rule."
      : "Open, tag, and bookmark act on exact source rows when available.";

  const statCards = [
    { label: "Critical/High", value: formatNumber(summary.criticalHigh.length), color: th.sev.high },
    { label: "Affected Hosts", value: formatNumber(summary.affectedHosts.length), color: th.textDim },
    { label: "First Seen", value: compactTime(summary.firstSeen), color: th.textDim },
    { label: "Last Seen", value: compactTime(summary.lastSeen), color: th.textDim },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 6 }}>
        {statCards.map((card) => (
          <div key={card.label} style={{ border: `1px solid ${th.border}55`, background: `${th.panelBg}55`, borderRadius: 8, padding: "8px 10px", minWidth: 0 }}>
            <div style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", fontWeight: 800, letterSpacing: "0.05em", marginBottom: 3 }}>{card.label}</div>
            <div title={card.value} style={{ fontSize: card.value.length > 18 ? 10 : 14, color: card.color, fontWeight: 900, fontFamily: card.label.includes("Seen") ? "'SF Mono',Menlo,monospace" : "-apple-system,sans-serif", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{card.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1.5fr) minmax(260px, 0.9fr)", gap: 10 }}>
        <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, overflow: "hidden", minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", background: th.panelBg, borderBottom: `1px solid ${th.border}` }}>
            <span style={{ color: th.text, fontWeight: 800, fontSize: 12 }}>Look Here First</span>
            <span style={{ color: th.textMuted, fontSize: 9 }}>{sourceMode}</span>
            {(reviewedCount > 0 || falsePositiveCount > 0) && (
              <span style={{ marginLeft: "auto", color: th.textMuted, fontSize: 9 }}>
                {reviewedCount > 0 ? `${reviewedCount} reviewed` : ""}{reviewedCount > 0 && falsePositiveCount > 0 ? " | " : ""}{falsePositiveCount > 0 ? `${falsePositiveCount} false positive` : ""}
              </span>
            )}
          </div>
          <div style={{ maxHeight: 315, overflow: "auto" }}>
            {summary.priorityFindings.length === 0 && (
              <div style={{ padding: 18, textAlign: "center", color: th.textMuted, fontSize: 12 }}>No detections to triage.</div>
            )}
            {summary.priorityFindings.slice(0, 18).map((match, idx) => {
              const levelColor = SEV_COLORS[match._triageLevel] || th.textMuted;
              const reviewed = !!match._triageReviewed;
              const falsePositive = !!match._triageFalsePositive;
              const tagged = !!modal.sigmaTaggedRules?.[match._triageKey];
              const bookmarked = !!modal.sigmaBookmarkedRules?.[match._triageKey];
              return (
                <div key={match._triageKey || idx} style={{ padding: "9px 10px", borderBottom: `1px solid ${th.border}33`, background: falsePositive ? th.sev.low + "10" : reviewed ? th.sev.clean + "08" : idx % 2 ? `${th.panelBg}33` : "transparent", opacity: falsePositive ? 0.68 : 1 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                    <div style={{ width: 22, color: levelColor, fontWeight: 900, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace", paddingTop: 2 }}>{idx + 1}</div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                        {sevBadge(match._triageLevel)}
                        <span title={match.title} style={{ color: th.text, fontWeight: 800, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{match.title || match.ruleId}</span>
                        {reviewed && <Pill color={th.sev.clean}>reviewed</Pill>}
                        {falsePositive && <Pill color={th.sev.low}>false positive</Pill>}
                        {tagged && <Pill color={th.accent}>tagged</Pill>}
                        {bookmarked && <Pill color={th.sev.med}>bookmarked</Pill>}
                      </div>
                      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 4, fontSize: 10, color: th.textMuted }}>
                        <span><strong style={{ color: th.text }}>{formatNumber(match._triageHitCount)}</strong> hits</span>
                        <span><strong style={{ color: th.text }}>{formatNumber(match.hosts?.length || 0)}</strong> hosts</span>
                        {match.firstSeen && <span>first {compactTime(match.firstSeen)}</span>}
                        {match.lastSeen && <span>last {compactTime(match.lastSeen)}</span>}
                        {(match.mitre || []).slice(0, 3).map(mitreBadge)}
                      </div>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 5, alignItems: "center", flexWrap: "wrap", marginTop: 8, paddingLeft: 30 }}>
                    <button onClick={() => handleOpenExactMatchesAsTab(match)} disabled={!!modal.sourceAction} style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>Open Exact Hits</button>
                    <button onClick={() => handleTagMatches(match)} disabled={!!modal.sourceAction} title={resultOnlyActions ? "Open exact hits as a result tab and tag every imported row automatically." : undefined} style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "tag" ? "Opening + Tagging..." : resultOnlyActions ? "Open + Tag" : "Tag"}</button>
                    <button onClick={() => handleBookmarkMatches(match)} disabled={!!modal.sourceAction} title={resultOnlyActions ? "Open exact hits as a result tab and bookmark every imported row automatically." : undefined} style={{ ...ms.bsm, opacity: modal.sourceAction ? 0.55 : 1 }}>{modal.sourceAction === "bookmark" ? "Opening + Bookmarking..." : resultOnlyActions ? "Open + Bookmark" : "Bookmark"}</button>
                    <button onClick={() => handleMarkRuleReviewed(match, !reviewed)} style={{ ...ms.bsm, color: reviewed ? th.sev.clean : th.textDim, border: `1px solid ${reviewed ? th.sev.clean + "44" : th.border}` }}>{reviewed ? "Reviewed" : "Mark Reviewed"}</button>
                    <button onClick={() => handleMarkRuleFalsePositive(match, !falsePositive)} style={{ ...ms.bsm, color: falsePositive ? th.sev.low : th.textDim, border: `1px solid ${falsePositive ? th.sev.low + "66" : th.border}` }}>{falsePositive ? "False Positive" : "Mark False Positive"}</button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 0 }}>
          <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 9, background: `${th.panelBg}44` }}>
            <MiniList title="Top Rules by Hits" rows={summary.topRules.map((match) => ({ value: match.title || match.ruleId, count: match._triageHitCount }))} th={th} color={th.accent} empty="No rule hits" />
          </div>
          <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 9, background: `${th.panelBg}44` }}>
            <MiniList title="Affected Hosts" rows={summary.affectedHosts} th={th} color={th.textDim} empty="No hosts in results" />
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, minmax(0, 1fr))", gap: 8 }}>
        <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 9, background: `${th.panelBg}33` }}>
          <MiniList title="ATT&CK Techniques" rows={summary.mitreTechniques} th={th} color={th.textDim} empty="No techniques" />
        </div>
        <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 9, background: `${th.panelBg}33` }}>
          <MiniList title="ATT&CK Tactics" rows={summary.mitreTactics} th={th} color={th.textDim} empty="No tactics" />
        </div>
        <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 9, background: `${th.panelBg}33` }}>
          <MiniList title="Rare Hosts" rows={summary.rareHosts} th={th} color={th.textDim} />
        </div>
        <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 9, background: `${th.panelBg}33` }}>
          <MiniList title="Rare Users" rows={summary.rareUsers} th={th} color={th.textDim} />
        </div>
        <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 9, background: `${th.panelBg}33` }}>
          <MiniList title="Rare Processes" rows={summary.rareProcesses} th={th} color={th.textDim} />
        </div>
      </div>
    </div>
  );
}
