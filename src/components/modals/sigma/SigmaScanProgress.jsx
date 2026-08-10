import { formatNumber } from "../../../utils/format.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";

export default function SigmaScanProgress() {
  const {
    phase,
    progress,
    th,
  } = useSigmaModalContext();

  return (
    <>
          {/* ── SCANNING PHASE ────────────────────────────────────── */}
          {phase === "scanning" && (() => {
            const isPreparing = progress?.phase === "discovering" || progress?.phase === "schema" || progress?.phase === "compiling" || progress?.phase === "installing";
            const isHayabusaRunning = progress?.phase === "hayabusa-running";
            const isHayabusaDone = progress?.phase === "hayabusa-done";
            const isParsingResults = progress?.phase === "parsing-results";
            const isScanning = progress?.phase === "scanning";
            // SQL-based tab scan: progress bar based on logsource groups completed
            const isSqlScan = isScanning && progress?.totalGroups > 0;
            const matchCount = progress?.matchesFound || 0;
            const sqlPct = isSqlScan ? Math.round((progress.groupsCompleted || 0) / progress.totalGroups * 100) : 0;
            // Hayabusa scan-stage percentage parsed from stderr progress bar (0..100, may be float)
            const hayabusaPct = isHayabusaRunning && typeof progress?.scanPct === "number" && progress.scanPct > 0
              ? Math.min(100, progress.scanPct) : 0;
            const hasHayabusaPct = hayabusaPct > 0;
            const etaStr = progress?.etaStr || "";

            return (
              <div style={{ padding: "20px 0" }}>
                {/* Progress bar */}
                <div style={{ marginBottom: 14, maxWidth: 480, margin: "0 auto 14px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, gap: 8 }}>
                    <span style={{ fontSize: 11, color: th.text, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                      {isPreparing ? "Preparing..." : isHayabusaRunning ? "Hayabusa scanning EVTX files..." : isHayabusaDone ? "Hayabusa scan complete" : isParsingResults ? "Parsing Hayabusa results..." : isSqlScan ? "Evaluating Sigma rules..." : progress?.phase === "done" ? "Done" : "Scanning..."}
                    </span>
                    <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
                      {isSqlScan && (
                        <span style={{ fontSize: 11, color: th.accent, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace" }}>{sqlPct}%</span>
                      )}
                      {hasHayabusaPct && (
                        <span style={{ fontSize: 11, color: th.accent, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace" }}>{hayabusaPct.toFixed(1)}%</span>
                      )}
                      {etaStr && (isHayabusaRunning || isParsingResults) && (
                        <span style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace" }}>ETA {etaStr}</span>
                      )}
                      {isHayabusaRunning && progress?.timeStr && (
                        <span style={{ fontSize: 11, color: th.textDim, fontWeight: 600, fontFamily: "'SF Mono',Menlo,monospace" }}>{progress.timeStr}</span>
                      )}
                    </span>
                  </div>
                  <div style={{ height: 8, background: th.border + "44", borderRadius: 4, overflow: "hidden" }}>
                    {isSqlScan ? (
                      <div style={{ height: "100%", width: `${sqlPct}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`, borderRadius: 4, transition: "width var(--m-slow) ease-out", boxShadow: `0 0 8px ${th.accent}44` }} />
                    ) : hasHayabusaPct ? (
                      <div style={{ height: "100%", width: `${hayabusaPct}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.accentHover})`, borderRadius: 4, transition: "width var(--m-slow) ease-out", boxShadow: `0 0 8px ${th.accent}44` }} />
                    ) : (
                      <div style={{ height: "100%", background: `linear-gradient(90deg, ${th.accent}, ${th.accentHover})`, borderRadius: 4, width: "100%", animation: "tle-pulse 1.5s ease-in-out infinite" }} />
                    )}
                  </div>
                  {isHayabusaRunning && progress?.currentFile && (
                    <div style={{ marginTop: 4, fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono',Menlo,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {progress.currentFile}
                    </div>
                  )}
                </div>

                {/* Hayabusa running stats */}
                {(isHayabusaRunning || isHayabusaDone) && (() => {
                  const hb = progress || {};
                  const stage = hb.stage || hb.hayabusaStage || "starting";
                  return (
                    <div style={{ marginBottom: 12 }}>
                      {/* Key stats row */}
                      <div style={{ display: "flex", justifyContent: "center", gap: 16, marginBottom: 10 }}>
                        {[
                          { label: "EVTX Files", value: hb.filesAfterFilter ? `${hb.filesAfterFilter} / ${hb.fileCount || 0}` : String(hb.fileCount || 0), color: th.textDim },
                          { label: "Rules", value: hb.rulesAfterFilter ? formatNumber(hb.rulesAfterFilter) : hb.totalRules ? formatNumber(hb.totalRules) : "...", color: th.textDim },
                          ...(hb.totalEvents > 0 ? [{ label: "Events", value: formatNumber(hb.totalEvents), color: th.textDim }] : []),
                          ...(hb.eventsWithHits > 0 ? [{ label: "Hits", value: formatNumber(hb.eventsWithHits), color: th.sev.high }] : []),
                          { label: "Elapsed", value: hb.timeStr || "0s", color: th.accent },
                        ].map((s, i) => (
                          <div key={i} style={{ textAlign: "center" }}>
                            <div style={{ fontSize: 20, fontWeight: 700, color: s.color, fontFamily: "'SF Mono',Menlo,monospace" }}>{s.value}</div>
                            <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>{s.label}</div>
                          </div>
                        ))}
                      </div>

                      {/* Stage indicator */}
                      <div style={{ display: "flex", justifyContent: "center", gap: 6, marginBottom: 6 }}>
                        {[
                          { id: "loading-rules", label: "Load Rules" },
                          { id: "channel-filter", label: "Channel Filter" },
                          { id: "scanning", label: "Scan Events" },
                          { id: "results", label: "Results" },
                        ].map((s) => {
                          const stages = ["starting", "loading-rules", "channel-filter", "scanning", "results"];
                          const currentIdx = stages.indexOf(stage);
                          const stageIdx = stages.indexOf(s.id);
                          const isDone = stageIdx < currentIdx;
                          const isCurrent = stageIdx === currentIdx;
                          return (
                            <span key={s.id} style={{
                              padding: "2px 8px", borderRadius: 4, fontSize: 9, fontWeight: isCurrent ? 700 : 400,
                              fontFamily: "-apple-system, sans-serif",
                              background: isCurrent ? `${th.accent}20` : isDone ? `${th.sev.clean}15` : `${th.border}22`,
                              color: isCurrent ? th.accent : isDone ? th.sev.clean : th.textMuted,
                              border: `1px solid ${isCurrent ? th.accent + "44" : isDone ? th.sev.clean + "33" : th.border + "22"}`,
                            }}>
                              {isDone ? "\u2713 " : ""}{s.label}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  );
                })()}

                {/* SQL-based tab scan stats */}
                {isSqlScan && (
                  <div style={{ display: "flex", justifyContent: "center", gap: 20, marginBottom: 12 }}>
                    {[
                      { label: "Groups", value: `${progress?.groupsCompleted || 0} / ${progress?.totalGroups || 0}`, color: th.textDim },
                      { label: "Rules Evaluated", value: formatNumber(progress?.rulesEvaluated || 0), color: th.textDim },
                      { label: "Matches Found", value: formatNumber(matchCount), color: matchCount > 0 ? th.sev.high : th.textDim },
                      { label: "Rows Scanned", value: formatNumber(progress?.rowsScanned || 0), color: th.textDim },
                    ].map((s, i) => (
                      <div key={i} style={{ textAlign: "center" }}>
                        <div style={{ fontSize: 18, fontWeight: 700, color: s.color, fontFamily: "'SF Mono',Menlo,monospace" }}>{s.value}</div>
                        <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>{s.label}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Status text */}
                <div style={{ textAlign: "center", fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                  {progress?.text || (progress?.phase === "done" ? "Finalizing results..." : isSqlScan ? `Evaluating ${formatNumber(progress?.totalRules || 0)} rules across ${formatNumber(progress?.totalGroups || 0)} logsource groups` : "Initializing...")}
                </div>
              </div>
            );
          })()}


    </>
  );
}
