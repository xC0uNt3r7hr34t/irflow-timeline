/**
 * Process tree build progress UI.
 */
export default function ProcessTreeLoadingPhase({ modal, th, handleCancelBuild }) {
        const prog = modal.ptProgress || 0;
        const pi = modal.ptPhaseIdx || 0;
        const ptPhases = ["Querying database...", "Parsing process events...", "Building parent-child relationships...", "Computing tree depth...", "Finalizing...", "Complete"];
        return (
          <div style={{ padding: "50px 40px 40px", textAlign: "center", flex: 1 }}>
            <style>{`@keyframes ptPulse{0%,100%{opacity:.35}50%{opacity:1}}`}</style>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round" style={{ marginBottom: 16, animation: "ptPulse 1.5s ease-in-out infinite" }}>
              <rect x="3" y="10" width="5" height="5" rx="1" fill={th.accent + "33"} />
              <rect x="14" y="3" width="5" height="5" rx="1" fill={th.accent + "33"} />
              <rect x="14" y="16" width="5" height="5" rx="1" fill={th.accent + "33"} />
              <path d="M8 12.5h3v-7h3M11 12.5v5.5h3" />
            </svg>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", marginBottom: 4 }}>Building Process Tree</div>
              <div style={{ fontSize: 11, color: th.accent, fontFamily: "-apple-system, sans-serif", height: 16 }}>{ptPhases[pi]}</div>
            </div>
            <div style={{ width: 280, margin: "0 auto", height: 6, background: th.border + "33", borderRadius: 3, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${prog}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`, borderRadius: 3, transition: "width var(--m-slow) ease-out" }} />
            </div>
            <div style={{ fontSize: 11, color: th.textMuted, marginTop: 8, fontFamily: "SF Mono, Menlo, monospace" }}>{Math.round(prog)}%</div>
            <div style={{ marginTop: 24 }}>
              <button onClick={handleCancelBuild}
                style={{ padding: "4px 16px", fontSize: 11, background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
            </div>
          </div>
        );

}
