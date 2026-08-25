import { useState, useCallback, Fragment } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { formatNumber } from "../../utils/format.js";
import { parseIocText, escapeIocForRegex } from "../../utils/ioc-parsing.js";
import { clearIpcSubscription, replaceIpcSubscription } from "../../utils/ipc-subscriptions.js";
import { VT_COMPATIBLE_RE } from "../../constants/grid.js";
import { Modal } from "../primitives/index.js";
import useModalChrome from "../../hooks/useModalChrome.js";

export default function IocModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const refreshCallback = useUIStore((s) => s.refreshCallback);
  const ct = useCurrentTab();
  const { th } = useTheme();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const tabs = useTabStore((s) => s.tabs);
  const activeTab = useTabStore((s) => s.activeTab);
  const setTabs = useTabStore((s) => s.setTabs);
  const updateActiveTab = useTabStore((s) => s.updateActiveTab);

  const [copiedMsg, setCopiedMsg] = useState(false);

  const up = useCallback((key, value) => {
    setTabs((prev) => prev.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)));
  }, [activeTab, setTabs]);

  const fetchData = useCallback((tab) => {
    if (refreshCallback) refreshCallback(tab);
  }, [refreshCallback]);

  const ms = useModalChrome();

  if (!modal || modal.type !== "ioc" || !ct) return null;

  const phase = modal.phase || "load";
  const iocText = modal.iocText || "";
  const iocName = modal.iocName || "";
  const parsedIocs = modal.parsedIocs || [];
  const fileName = modal.fileName || null;
  const loading = modal.loading || false;
  const results = modal.results || null;
  const error = modal.error || null;
  const scanProgress = modal.scanProgress || null;
  const vtConfigExpanded = modal.vtConfigExpanded || false;
  const vtKeyStatus = modal.vtKeyStatus || null;
  const vtKeyInput = modal.vtKeyInput || "";
  const vtRateLimit = modal.vtRateLimit ?? 4;
  const vtCacheTtl = modal.vtCacheTtl ?? 24;
  const vtResults = modal.vtResults || null;
  const vtEnriching = modal.vtEnriching || false;
  const vtRequestId = modal.vtRequestId || null;
  const vtProgress = modal.vtProgress || null;
  const vtSortBy = modal.vtSortBy || "hits";
  const vtFilterVerdict = modal.vtFilterVerdict || "all";

  // Load VT key status on mount
  if (vtKeyStatus === null && tle.vtGetApiKey) {
    tle.vtGetApiKey().then((status) => {
      setModal((p) => p?.type === "ioc" ? { ...p, vtKeyStatus: status || { hasKey: false }, vtRateLimit: status?.rateLimit || 4, vtCacheTtl: status?.cacheTtlHours || 24 } : p);
    }).catch(() => {});
  }

  const categories = parsedIocs.reduce((acc, ioc) => { acc[ioc.category] = (acc[ioc.category] || 0) + 1; return acc; }, {});
  const defaultName = fileName ? fileName.replace(/\.(txt|csv|ioc|tsv|xlsx|xls)$/i, "") : "IOC Match";
  const effectiveName = (iocName || defaultName || "IOC Match").trim();
  const tagName = `IOC: ${effectiveName}`;

  const handleLoadFile = async () => {
    const result = await tle.loadIocFile();
    if (!result || result.error) return;
    const parsed = parseIocText(result.content);
    const defangedText = parsed.map((i) => i.raw).join("\n");
    setModal((p) => ({ ...p, iocText: defangedText, fileName: result.fileName,
      iocName: p.iocName || result.fileName.replace(/\.(txt|csv|ioc|tsv|xlsx|xls)$/i, ""), parsedIocs: parsed }));
  };

  const handlePasteChange = (text) => {
    const parsed = parseIocText(text);
    setModal((p) => ({ ...p, iocText: text, parsedIocs: parsed }));
  };

  const handleScan = async () => {
    if (parsedIocs.length === 0 || !ct) return;
    setModal((p) => ({ ...p, loading: true, error: null, scanProgress: { stage: "scan", current: 0, total: parsedIocs.length, label: "Scanning database..." } }));
    try {
      const escapedPatterns = parsedIocs.map((ioc) => escapeIocForRegex(ioc.raw));

      const BATCH = 20;
      const mergedRowIds = new Set();
      const mergedPerIocCounts = {};
      const mergedPerRowIocs = {};
      const totalBatches = Math.ceil(escapedPatterns.length / BATCH);

      for (let b = 0; b < totalBatches; b++) {
        const start = b * BATCH;
        const batchPatterns = escapedPatterns.slice(start, start + BATCH);

        setModal((p) => p?.type === "ioc" ? ({ ...p, scanProgress: { stage: "scan", current: Math.min(start + BATCH, escapedPatterns.length), total: escapedPatterns.length, label: `Scanning IOCs ${start + 1}\u2013${Math.min(start + BATCH, escapedPatterns.length)} of ${escapedPatterns.length}...` } }) : p);

        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

        const { matchedRowIds, perIocCounts, perRowIocs } = await tle.matchIocs(ct.id, batchPatterns, 200);
        for (const id of matchedRowIds) mergedRowIds.add(id);
        for (let i = 0; i < batchPatterns.length; i++) {
          mergedPerIocCounts[escapedPatterns[start + i]] = perIocCounts[batchPatterns[i]] || 0;
        }
        for (const [rowId, indices] of Object.entries(perRowIocs || {})) {
          if (!mergedPerRowIocs[rowId]) mergedPerRowIocs[rowId] = [];
          for (const li of indices) mergedPerRowIocs[rowId].push(start + li);
        }
      }

      const allMatchedRowIds = [...mergedRowIds];

      setModal((p) => p?.type === "ioc" ? ({ ...p, scanProgress: { stage: "tag", current: 0, total: 1, label: `Tagging ${allMatchedRowIds.length} matched rows...` } }) : p);
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

      const allIocTags = new Set();
      if (allMatchedRowIds.length > 0) {
        const tagMap = {};
        const newTagColors = { ...ct.tagColors };
        for (const [rowIdStr, iocIndices] of Object.entries(mergedPerRowIocs || {})) {
          const rowId = Number(rowIdStr);
          tagMap[rowId] = iocIndices.map((i) => {
            const iocTag = `IOC: ${parsedIocs[i].raw}`;
            allIocTags.add(iocTag);
            if (!newTagColors[iocTag]) newTagColors[iocTag] = th.sev.high;
            return iocTag;
          });
        }
        await tle.bulkAddTags(ct.id, tagMap);
        up("tagColors", newTagColors);
      }

      setModal((p) => p?.type === "ioc" ? ({ ...p, scanProgress: { stage: "refresh", current: 0, total: 1, label: "Refreshing data..." } }) : p);
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

      const hitIocs = parsedIocs.filter((ioc, i) => (mergedPerIocCounts[escapedPatterns[i]] || 0) > 0).map((ioc) => ioc.raw);
      if (hitIocs.length > 0) {
        const prev = ct.iocHighlights || [];
        up("iocHighlights", [...new Set([...prev, ...hitIocs])]);
      }

      await fetchData(ct);

      const perIocResults = parsedIocs.map((ioc, i) => ({
        raw: ioc.raw, category: ioc.category, hits: mergedPerIocCounts[escapedPatterns[i]] || 0,
      })).sort((a, b) => b.hits - a.hits);

      setModal((p) => p?.type === "ioc" ? ({ ...p, phase: "results", loading: false, scanProgress: null,
        results: { matchedRowIds: allMatchedRowIds, matchedCount: allMatchedRowIds.length, tagName, allIocTags: [...allIocTags], perIocResults } }) : p);
    } catch (e) {
      setModal((p) => p?.type === "ioc" ? ({ ...p, loading: false, scanProgress: null, error: e.message }) : p);
    }
  };

  const foundCount = results ? results.perIocResults.filter((r) => r.hits > 0).length : 0;
  const missedCount = results ? results.perIocResults.filter((r) => r.hits === 0).length : 0;

  return (
    <Modal bare onClose={() => setModal(null)} closeOnOverlay={false}>
    <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 580, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
        {/* Header */}
        <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Known-Bad IOC Matching</h3>
            <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Load an IOC list and auto-tag every matching row</p>
          </div>
          <button onClick={() => {
            if (vtEnriching && vtRequestId) tle.vtCancel(vtRequestId);
            clearIpcSubscription("vt-progress");
            clearIpcSubscription("vt-complete");
            if (vtResults && Object.keys(vtResults).length > 0 && results) {
              up("vtEnrichment", { results: vtResults, perIocResults: results.perIocResults, parsedIocs, matchedCount: results.matchedCount, allIocTags: results.allIocTags });
            }
            setModal(null);
          }} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>{"\u2715"}</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflow: "auto", padding: "16px 20px", display: "flex", flexDirection: "column", gap: 14 }}>
          {phase === "load" && (<>
            {/* VirusTotal API Key Config */}
            <div style={{ background: th.bgAlt, borderRadius: 6, border: `1px solid ${th.border}`, overflow: "hidden" }}>
              <button onClick={() => setModal((p) => ({ ...p, vtConfigExpanded: !vtConfigExpanded }))}
                style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "8px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: vtKeyStatus?.hasKey ? th.success : th.textMuted, flexShrink: 0 }} />
                <span style={{ fontWeight: 500 }}>VirusTotal</span>
                <span style={{ color: th.textMuted, fontSize: 11, marginLeft: "auto" }}>{vtConfigExpanded ? "Hide" : "Configure"}</span>
                <span style={{ color: th.textMuted, fontSize: 10, transform: vtConfigExpanded ? "rotate(180deg)" : "rotate(0deg)", transition: "transform var(--m-base)" }}>{"\u25BC"}</span>
              </button>
              {vtConfigExpanded && (
                <div style={{ padding: "0 12px 12px", display: "flex", flexDirection: "column", gap: 8, borderTop: `1px solid ${th.border}` }}>
                  <div style={{ marginTop: 8 }}>
                    <label style={{ ...ms.lb, marginBottom: 4, display: "block" }}>API Key {vtKeyStatus?.hasKey && <span style={{ color: th.success, fontWeight: 400 }}>({vtKeyStatus.maskedKey})</span>}</label>
                    <div style={{ display: "flex", gap: 6 }}>
                      <input type="password" value={vtKeyInput} onChange={(e) => setModal((p) => ({ ...p, vtKeyInput: e.target.value }))}
                        placeholder={vtKeyStatus?.hasKey ? "Enter new key to replace" : "Paste your VT API key"}
                        style={{ ...ms.ip, flex: 1, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11 }} />
                      <button onClick={async () => {
                        if (vtKeyInput.trim()) {
                          await tle.vtSetApiKey(vtKeyInput.trim(), vtRateLimit, vtCacheTtl);
                          const status = await tle.vtGetApiKey();
                          setModal((p) => ({ ...p, vtKeyInput: "", vtKeyStatus: status }));
                        }
                      }} style={{ ...ms.bp, fontSize: 11, padding: "4px 10px", whiteSpace: "nowrap" }}>Save</button>
                      {vtKeyStatus?.hasKey && (
                        <button onClick={async () => {
                          await tle.vtClearApiKey();
                          const status = await tle.vtGetApiKey();
                          setModal((p) => ({ ...p, vtKeyInput: "", vtKeyStatus: status }));
                        }} style={{ ...ms.bs, fontSize: 11, padding: "4px 10px", color: th.danger, borderColor: th.danger + "44" }}>Clear</button>
                      )}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 12 }}>
                    <div style={{ flex: 1 }}>
                      <label style={{ ...ms.lb, marginBottom: 4, display: "block" }}>Rate Limit</label>
                      <select value={vtRateLimit} onChange={async (e) => {
                        const val = Number(e.target.value);
                        setModal((p) => ({ ...p, vtRateLimit: val }));
                        if (vtKeyStatus?.hasKey) await tle.vtSetApiKey(undefined, val, vtCacheTtl);
                      }} style={{ ...ms.ip, padding: "4px 6px" }}>
                        <option value={4}>4 req/min</option>
                        <option value={8}>8 req/min</option>
                        <option value={15}>15 req/min</option>
                        <option value={30}>30 req/min</option>
                      </select>
                    </div>
                    <div style={{ flex: 1 }}>
                      <label style={{ ...ms.lb, marginBottom: 4, display: "block" }}>Cache TTL</label>
                      <select value={vtCacheTtl} onChange={async (e) => {
                        const val = Number(e.target.value);
                        setModal((p) => ({ ...p, vtCacheTtl: val }));
                        if (vtKeyStatus?.hasKey) await tle.vtSetApiKey(undefined, vtRateLimit, val);
                      }} style={{ ...ms.ip, padding: "4px 6px" }}>
                        <option value={1}>1 hour</option>
                        <option value={6}>6 hours</option>
                        <option value={24}>24 hours</option>
                        <option value={168}>7 days</option>
                      </select>
                    </div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ color: th.textMuted, fontSize: 10, flex: 1 }}>Free VT API keys allow 4 req/min. Results are cached locally to save quota.</span>
                    <button onClick={async () => {
                      const res = await tle.vtClearCache();
                      setModal((p) => ({ ...p, vtCacheCleared: res?.cleared || 0 }));
                      setTimeout(() => setModal((p) => p ? ({ ...p, vtCacheCleared: undefined }) : p), 3000);
                    }} style={{ ...ms.bs, fontSize: 10, padding: "2px 8px", whiteSpace: "nowrap", color: th.warning, borderColor: th.warning + "44" }}>
                      {modal.vtCacheCleared !== undefined ? `Cleared ${modal.vtCacheCleared} entries` : "Clear Cache"}
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div style={ms.fg}>
              <label style={ms.lb}>IOC Set Name</label>
              <input value={iocName} onChange={(e) => setModal((p) => ({ ...p, iocName: e.target.value }))} placeholder={defaultName} style={ms.ip} />
              <span style={{ color: th.textMuted, fontSize: 10, marginTop: 3, display: "block" }}>Each matched IOC gets its own tag, e.g. <code style={{ color: th.accent }}>IOC: cmd.exe</code></span>
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <button onClick={handleLoadFile} style={ms.bp}>Load File (.txt / .csv / .xlsx / .tsv)</button>
              <span style={{ color: th.textMuted, fontSize: 11 }}>or paste below</span>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>IOC List — one per line, # for comments{parsedIocs.length > 0 && <span style={{ color: th.success, marginLeft: 6 }}>{parsedIocs.length} IOCs parsed</span>}</label>
              <textarea value={iocText} onChange={(e) => handlePasteChange(e.target.value)}
                placeholder={"# Paste IOCs here \u2014 one per line\n192.168.1.1\nevil.example.com\nabc123def456...sha256hash\nC:\\malware\\payload.exe"} rows={10}
                style={{ ...ms.ip, resize: "vertical", fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, lineHeight: 1.5 }} />
            </div>
            {parsedIocs.length > 0 && (
              <div style={{ background: th.bgAlt, borderRadius: 6, padding: "10px 12px" }}>
                <div style={{ ...ms.lb, marginBottom: 6 }}>Category Breakdown ({parsedIocs.length} unique)</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {Object.entries(categories).map(([cat, count]) => {
                    const clr = /^(IPv[46]|Domain|Email|URL|Crypto|User_Agent|Phone|Payment)/.test(cat) ? th.accent : /^(SHA|MD5)/.test(cat) ? th.warning : cat === "Other" ? th.textMuted : th.sev.custom;
                    return <span key={cat} style={{ padding: "2px 8px", background: `${clr}22`, border: `1px solid ${clr}44`, borderRadius: 4, fontSize: 11, color: clr, fontFamily: "-apple-system, sans-serif" }}>{cat.replace(/_/g, " ")}: {count}</span>;
                  })}
                </div>
              </div>
            )}
            {error && <div style={{ padding: "8px 12px", background: `${th.danger}22`, border: `1px solid ${th.danger}44`, borderRadius: 6, color: th.danger, fontSize: 12 }}>Error: {error}</div>}
            {loading && scanProgress && (() => {
              const pct = scanProgress.stage === "scan" ? Math.round((scanProgress.current / scanProgress.total) * 80)
                : scanProgress.stage === "tag" ? 90 : 95;
              return (
              <div style={{ padding: "16px 0 8px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <span style={{ fontSize: 12, color: th.text, fontWeight: 500 }}>{scanProgress.label}</span>
                  <span style={{ fontSize: 11, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
                    {scanProgress.stage === "scan" ? `${scanProgress.current}/${scanProgress.total}` : `${pct}%`}
                  </span>
                </div>
                <div style={{ width: "100%", height: 8, background: th.bgAlt, borderRadius: 4, overflow: "hidden", position: "relative" }}>
                  <div style={{
                    height: "100%", borderRadius: 4, transition: "width var(--m-slow) ease-out",
                    width: `${pct}%`, position: "relative", overflow: "hidden",
                    background: `linear-gradient(90deg, ${th.accent}, ${th.warning})`,
                  }}>
                    <div style={{
                      position: "absolute", inset: 0,
                      background: "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.25) 50%, transparent 100%)",
                      backgroundSize: "200% 100%",
                      animation: "iocShimmer 1.2s ease-in-out infinite",
                    }} />
                  </div>
                </div>
                <style>{`@keyframes iocShimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }`}</style>
                <div style={{ display: "flex", justifyContent: "center", gap: 16, marginTop: 10 }}>
                  {["Scanning", "Tagging", "Refreshing"].map((step, i) => {
                    const stages = ["scan", "tag", "refresh"];
                    const si = stages.indexOf(scanProgress.stage);
                    const done = i < si;
                    const active = i === si;
                    return <span key={step} style={{ fontSize: 10, color: done ? th.success : active ? th.accent : th.textDim, fontWeight: active ? 600 : 400, transition: "color var(--m-slow)" }}>{done ? "\u2713 " : active ? "\u25CF " : "\u25CB "}{step}</span>;
                  })}
                </div>
              </div>);
            })()}
          </>)}

          {phase === "results" && results && (() => {
            const vtVals = vtResults ? Object.values(vtResults) : [];
            const hasVtData = vtVals.length > 0;
            const iocHitsMap = {};
            for (const r of results.perIocResults) iocHitsMap[r.raw] = r.hits;
            const vtMatched = vtVals.filter((v) => (iocHitsMap[v.ioc] || 0) > 0);
            const vtFeedOnly = vtVals.filter((v) => (iocHitsMap[v.ioc] || 0) === 0);
            const vtMalCount = vtMatched.filter((v) => v.verdict === "malicious").length;
            const vtSusCount = vtMatched.filter((v) => v.verdict === "suspicious").length;
            const vtCleanCount = vtMatched.filter((v) => v.verdict === "clean").length;
            const vtNotFoundCount = vtMatched.filter((v) => v.verdict === "not_found" || v.verdict === "private").length;
            const vtErrorCount = vtVals.filter((v) => v.verdict === "error").length;
            const feedMalCount = vtFeedOnly.filter((v) => v.verdict === "malicious").length;
            const feedSusCount = vtFeedOnly.filter((v) => v.verdict === "suspicious").length;
            const feedCleanCount = vtFeedOnly.filter((v) => v.verdict === "clean").length;
            const hasFeedOnly = vtFeedOnly.length > 0 && (feedMalCount + feedSusCount + feedCleanCount) > 0;

            const vtIncludeUnmatched = modal.vtIncludeUnmatched || false;
            const vtCompatible = results.perIocResults.filter((ioc) => VT_COMPATIBLE_RE.test(ioc.category) && (vtIncludeUnmatched || ioc.hits > 0));
            const vtCompCount = vtCompatible.length;

            let displayIocs = [...results.perIocResults];
            if (vtFilterVerdict !== "all" && vtResults) {
              displayIocs = displayIocs.filter((ioc) => {
                const vtr = vtResults[ioc.raw];
                if (vtFilterVerdict === "malicious") return vtr?.verdict === "malicious";
                if (vtFilterVerdict === "suspicious") return vtr?.verdict === "suspicious";
                if (vtFilterVerdict === "clean") return vtr?.verdict === "clean";
                if (vtFilterVerdict === "not_found") return !vtr || vtr.verdict === "not_found" || vtr.verdict === "private" || vtr.verdict === "unsupported";
                return true;
              });
            }
            if (vtSortBy === "score" && vtResults) {
              displayIocs.sort((a, b) => {
                const va = vtResults[a.raw], vb = vtResults[b.raw];
                const sa = va ? (va.malicious || 0) + (va.suspicious || 0) : -1;
                const sb = vb ? (vb.malicious || 0) + (vb.suspicious || 0) : -1;
                return sb - sa;
              });
            } else if (vtSortBy === "name") {
              displayIocs.sort((a, b) => a.raw.localeCompare(b.raw));
            }

            const handleExportCsv = () => {
              const headers = ["IOC", "Category", "Timeline Hits", "VT Score", "VT Verdict", "Threat Label", "Queried At", "VT URL"];
              const rows = results.perIocResults.map((ioc) => {
                const vtr = vtResults?.[ioc.raw];
                const queried = vtr?.queriedAt ? new Date(vtr.queriedAt).toISOString() : "";
                return [ioc.raw, ioc.category, ioc.hits, vtr?.score ?? "", vtr?.verdict ?? "", vtr?.threatLabel ?? "", queried, vtr?.vtUrl ?? ""].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",");
              });
              const csv = [headers.join(","), ...rows].join("\n");
              navigator.clipboard?.writeText(csv);
              setCopiedMsg("CSV copied to clipboard"); setTimeout(() => setCopiedMsg(false), 2000);
            };

            const applyVerdictTags = async (vtRes, iocResults) => {
              if (!vtRes || !ct) return 0;
              const verdictTags = { malicious: "VT: Malicious", suspicious: "VT: Suspicious", clean: "VT: Clean" };
              const verdictColors = { malicious: th.sev.critical, suspicious: th.sev.med, clean: th.sev.clean };
              const iocTagToVerdictTag = {};
              for (const iocResult of iocResults) {
                if (iocResult.hits === 0) continue;
                const vtr = vtRes[iocResult.raw];
                if (!vtr || !verdictTags[vtr.verdict]) continue;
                iocTagToVerdictTag[`IOC: ${iocResult.raw}`] = verdictTags[vtr.verdict];
              }
              if (Object.keys(iocTagToVerdictTag).length === 0) return 0;
              const allTagData = await tle.getAllTagData(ct.id);
              const tagMap = {};
              const newTagColors = { ...ct.tagColors };
              for (const { rowid, tag } of allTagData) {
                const verdictTag = iocTagToVerdictTag[tag];
                if (!verdictTag) continue;
                if (!newTagColors[verdictTag]) newTagColors[verdictTag] = verdictColors[Object.keys(verdictTags).find((k) => verdictTags[k] === verdictTag)];
                if (!tagMap[rowid]) tagMap[rowid] = [];
                if (!tagMap[rowid].includes(verdictTag)) tagMap[rowid].push(verdictTag);
              }
              if (Object.keys(tagMap).length > 0) {
                await tle.bulkAddTags(ct.id, tagMap);
                up("tagColors", newTagColors);
                await fetchData(ct);
                return Object.keys(tagMap).length;
              }
              return 0;
            };

            const handleTagByVerdict = async () => {
              const count = await applyVerdictTags(vtResults, results.perIocResults);
              setCopiedMsg(count > 0 ? `Tagged ${count} rows by VT verdict` : "No rows to tag (no IOC hits with VT verdicts)");
              setTimeout(() => setCopiedMsg(false), 2500);
            };

            const handleVtEnrich = async () => {
              const iocs = vtCompatible.map((ioc) => ({ raw: ioc.raw, category: ioc.category }));
              const vtAccum = { ...(vtResults || {}) };
              const activeRequestId = `vt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
              setModal((p) => ({ ...p, vtEnriching: true, vtRequestId: activeRequestId, vtResults: vtAccum, vtProgress: { completed: 0, total: iocs.length, currentIoc: "" } }));

              clearIpcSubscription("vt-progress");
              clearIpcSubscription("vt-complete");

              const onProgress = (data) => {
                if (!data || data.requestId !== activeRequestId) return;
                if (data.result) vtAccum[data.result.ioc] = data.result;
                setModal((p) => {
                  if (!p || p.type !== "ioc") return p;
                  return { ...p, vtResults: { ...vtAccum }, vtProgress: { completed: data.completed, total: data.total, currentIoc: data.result?.ioc || "" } };
                });
              };
              const onComplete = (data) => {
                if (data?.requestId !== activeRequestId) return;
                setModal((p) => {
                  if (!p || p.type !== "ioc") return p;
                  return { ...p, vtEnriching: false, vtRequestId: null };
                });
                if (Object.keys(vtAccum).length > 0 && results) {
                  up("vtEnrichment", { results: { ...vtAccum }, perIocResults: results.perIocResults, parsedIocs, matchedCount: results.matchedCount, allIocTags: results.allIocTags });
                  applyVerdictTags(vtAccum, results.perIocResults).then((count) => {
                    if (count > 0) { setCopiedMsg(`Auto-tagged ${count} rows by VT verdict`); setTimeout(() => setCopiedMsg(false), 2500); }
                  });
                }
                clearIpcSubscription("vt-progress");
                clearIpcSubscription("vt-complete");
              };

              replaceIpcSubscription("vt-progress", tle.onVtProgress, onProgress);
              replaceIpcSubscription("vt-complete", tle.onVtComplete, onComplete);

              const resp = await tle.vtBulkLookup(iocs, activeRequestId);
              if (resp?.error) {
                setModal((p) => p?.type === "ioc" ? { ...p, vtEnriching: false, vtRequestId: null, error: resp.error } : p);
                clearIpcSubscription("vt-progress");
                clearIpcSubscription("vt-complete");
              }
            };

            const handleVtCancel = () => {
              if (vtRequestId) tle.vtCancel(vtRequestId);
              setModal((p) => p?.type === "ioc" ? { ...p, vtEnriching: false, vtRequestId: null } : p);
              clearIpcSubscription("vt-progress");
              clearIpcSubscription("vt-complete");
            };

            return (<>
            {/* Summary cards */}
            <div style={{ display: "flex", gap: 8 }}>
              <div style={{ flex: 1, padding: "10px 14px", background: results.matchedCount > 0 ? `${th.danger}22` : th.bgAlt, border: `1px solid ${results.matchedCount > 0 ? th.danger + "44" : th.border}`, borderRadius: 8, textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: results.matchedCount > 0 ? th.danger : th.textDim }}>{results.matchedCount != null ? formatNumber(results.matchedCount) : "\u2014"}</div>
                <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{results.matchedCount != null ? "matching rows" : "re-scan for count"}</div>
              </div>
              <div style={{ flex: 1, padding: "10px 14px", background: foundCount > 0 ? `${th.warning}22` : th.bgAlt, border: `1px solid ${foundCount > 0 ? th.warning + "44" : th.border}`, borderRadius: 8, textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: foundCount > 0 ? th.warning : th.textDim }}>{foundCount}</div>
                <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>IOCs hit</div>
              </div>
              <div style={{ flex: 1, padding: "10px 14px", background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: th.textDim }}>{missedCount}</div>
                <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>IOCs not found</div>
              </div>
            </div>

            {/* VT Verdict summary cards */}
            {vtCompCount > 0 && (<>
              <div style={{ display: "flex", gap: 6 }}>
                {[
                  { label: "Malicious", count: vtMalCount, color: th.danger, filter: "malicious" },
                  { label: "Suspicious", count: vtSusCount, color: th.warning, filter: "suspicious" },
                  { label: "Clean", count: vtCleanCount, color: th.success, filter: "clean" },
                  { label: "Not Found", count: vtNotFoundCount, color: th.textMuted, filter: "not_found" },
                ].map((card) => (
                  <button key={card.label} onClick={() => hasVtData && setModal((p) => ({ ...p, vtFilterVerdict: vtFilterVerdict === card.filter ? "all" : card.filter }))}
                    style={{ flex: 1, padding: "6px 8px", background: vtFilterVerdict === card.filter ? `${card.color}22` : th.bgAlt,
                      border: `1px solid ${vtFilterVerdict === card.filter ? card.color + "66" : th.border}`, borderRadius: 6, textAlign: "center",
                      cursor: hasVtData ? "pointer" : "default", transition: "all var(--m-base)", opacity: hasVtData ? 1 : 0.5 }}>
                    <div style={{ fontSize: 18, fontWeight: 700, color: card.count > 0 ? card.color : th.textDim }}>{hasVtData ? card.count : "\u2014"}</div>
                    <div style={{ fontSize: 9, color: card.count > 0 ? card.color : th.textMuted, fontFamily: "-apple-system, sans-serif" }}>VT {card.label}</div>
                  </button>
                ))}
              </div>
              {hasFeedOnly && (
                <div style={{ fontSize: 10, color: th.textMuted, textAlign: "center", padding: "2px 0" }}>
                  Feed only:{" "}
                  {feedMalCount > 0 && <span style={{ color: th.danger }}>{feedMalCount} malicious</span>}
                  {feedMalCount > 0 && (feedSusCount > 0 || feedCleanCount > 0) && " \u00B7 "}
                  {feedSusCount > 0 && <span style={{ color: th.warning }}>{feedSusCount} suspicious</span>}
                  {feedSusCount > 0 && feedCleanCount > 0 && " \u00B7 "}
                  {feedCleanCount > 0 && <span style={{ color: th.success }}>{feedCleanCount} clean</span>}
                  <span style={{ color: th.textDim }}> (no timeline hits)</span>
                </div>
              )}
            </>)}

            {(results.matchedCount > 0 || (results.matchedCount == null && results.allIocTags?.length > 0)) && (
              <div style={{ padding: "8px 12px", background: `${th.success}15`, border: `1px solid ${th.success}33`, borderRadius: 6, fontSize: 12, color: th.success }}>
                {results.matchedCount != null
                  ? <>Tagged {formatNumber(results.matchedCount)} rows with {results.allIocTags?.length || 0} per-IOC tags (e.g. <code style={{ background: `${th.success}22`, padding: "0 5px", borderRadius: 3 }}>IOC: {results.perIocResults?.find(r => r.hits > 0)?.raw || "..."}</code>)</>
                  : <>{results.allIocTags?.length || 0} per-IOC tags applied (e.g. <code style={{ background: `${th.success}22`, padding: "0 5px", borderRadius: 3 }}>IOC: {results.perIocResults?.find(r => r.hits > 0)?.raw || "..."}</code>)</>}
              </div>
            )}

            {/* VT Enrichment controls */}
            <div style={{ padding: "8px 12px", background: th.bgAlt, borderRadius: 6, border: `1px solid ${th.border}` }}>
              {!vtEnriching ? (
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <button disabled={!vtKeyStatus?.hasKey || vtCompCount === 0}
                    onClick={handleVtEnrich}
                    style={{ ...ms.bp, fontSize: 11, padding: "5px 12px", opacity: (!vtKeyStatus?.hasKey || vtCompCount === 0) ? 0.5 : 1, cursor: (!vtKeyStatus?.hasKey || vtCompCount === 0) ? "not-allowed" : "pointer" }}>
                    {hasVtData ? "Re-enrich" : "Enrich"} {vtCompCount} IOCs with VirusTotal
                  </button>
                  {hasVtData && (
                    <button onClick={handleTagByVerdict}
                      style={{ ...ms.bs, fontSize: 11, padding: "5px 12px", color: th.accent, borderColor: th.accent + "44" }}>
                      Tag by Verdict
                    </button>
                  )}
                  {hasVtData && (
                    <button onClick={handleExportCsv}
                      style={{ ...ms.bs, fontSize: 11, padding: "5px 12px" }}>
                      Copy CSV
                    </button>
                  )}
                  {hasVtData && vtErrorCount > 0 && vtKeyStatus?.hasKey && !vtEnriching && (
                    <button onClick={async () => {
                      const errorIocs = vtCompatible.filter((ioc) => vtResults?.[ioc.raw]?.verdict === "error");
                      if (errorIocs.length === 0) return;
                      setModal((p) => p?.type === "ioc" ? { ...p, vtRetrying: true } : p);
                      const updated = { ...(vtResults || {}) };
                      for (const ioc of errorIocs) {
                        try {
                          const result = await tle.vtLookupSingle(ioc.raw, ioc.category);
                          if (result) updated[ioc.raw] = result;
                        } catch {}
                      }
                      setModal((p) => p?.type === "ioc" ? { ...p, vtResults: updated, vtRetrying: false } : p);
                      setCopiedMsg(`Retried ${errorIocs.length} failed IOCs`);
                      setTimeout(() => setCopiedMsg(false), 2500);
                    }}
                      disabled={modal.vtRetrying}
                      style={{ ...ms.bs, fontSize: 11, padding: "5px 12px", color: th.warning, borderColor: th.warning + "44",
                        opacity: modal.vtRetrying ? 0.5 : 1, cursor: modal.vtRetrying ? "not-allowed" : "pointer" }}>
                      {modal.vtRetrying ? "Retrying..." : `Retry ${vtErrorCount} Failed`}
                    </button>
                  )}
                  {vtKeyStatus?.hasKey && vtCompCount > 0 && (
                    <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10, color: th.textMuted, cursor: "pointer" }}>
                      <input type="checkbox" checked={vtIncludeUnmatched}
                        onChange={(e) => setModal((p) => ({ ...p, vtIncludeUnmatched: e.target.checked }))} />
                      Include unmatched IOCs
                    </label>
                  )}
                  {!vtKeyStatus?.hasKey && <span style={{ color: th.textMuted, fontSize: 10 }}>Set VT API key to enable enrichment</span>}
                  {vtKeyStatus?.hasKey && vtCompCount === 0 && <span style={{ color: th.textMuted, fontSize: 10 }}>No VT-compatible IOCs with timeline hits{!vtIncludeUnmatched ? " (toggle 'Include unmatched' to enrich all)" : ""}</span>}
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 12, fontWeight: 500, color: th.text }}>Enriching with VirusTotal...</span>
                    <button onClick={handleVtCancel} style={{ ...ms.bs, fontSize: 10, padding: "2px 8px", color: th.danger, borderColor: th.danger + "44" }}>Cancel</button>
                  </div>
                  <div style={{ width: "100%", height: 6, background: th.bg, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 3, background: th.accent, transition: "width var(--m-slow)", width: `${vtProgress && vtProgress.total > 0 ? Math.round((vtProgress.completed / vtProgress.total) * 100) : 0}%` }} />
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: th.textMuted }}>
                    <span style={{ fontFamily: "'SF Mono', Menlo, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 300 }}>{vtProgress?.currentIoc || ""}</span>
                    <span>{vtProgress?.completed || 0}/{vtProgress?.total || 0}{(() => { const rem = (vtProgress?.total || 0) - (vtProgress?.completed || 0); if (rem <= 0) return ""; const maxMin = Math.ceil(rem / (vtRateLimit || 4)); return ` \u2014 \u2264${maxMin} min remaining`; })()}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Per-IOC results with sort/filter */}
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                <div style={ms.lb}>Per-IOC Results ({displayIocs.length}{displayIocs.length !== results.perIocResults.length ? ` of ${results.perIocResults.length}` : ""} IOCs)</div>
                {hasVtData && (
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ fontSize: 10, color: th.textMuted }}>Sort:</span>
                    {[
                      { key: "hits", label: "Hits" },
                      { key: "score", label: "VT Score" },
                      { key: "name", label: "Name" },
                    ].map((s) => (
                      <button key={s.key} onClick={() => setModal((p) => ({ ...p, vtSortBy: s.key }))}
                        style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, border: `1px solid ${vtSortBy === s.key ? th.accent + "66" : th.border}`,
                          background: vtSortBy === s.key ? `${th.accent}22` : "transparent", color: vtSortBy === s.key ? th.accent : th.textMuted,
                          cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>{s.label}</button>
                    ))}
                  </div>
                )}
              </div>
              <div style={{ maxHeight: 260, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                {displayIocs.map((ioc, i) => {
                  const vtr = vtResults?.[ioc.raw];
                  const vtScoreColor = vtr?.verdict === "malicious" ? th.danger : vtr?.verdict === "suspicious" ? th.warning : vtr?.verdict === "clean" ? th.success : th.textMuted;
                  const isVtCompat = VT_COMPATIBLE_RE.test(ioc.category);
                  const relData = modal.vtRelated?.[ioc.raw];
                  const relExpanded = relData?.expanded;
                  const canPivot = vtr && !vtr.error && (vtr.verdict === "malicious" || vtr.verdict === "suspicious") && isVtCompat && vtKeyStatus?.hasKey;
                  return (
                  <div key={i}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 10px", borderBottom: relExpanded ? "none" : `1px solid ${th.border}22`, background: i % 2 === 0 ? "transparent" : `${th.bgAlt}44` }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: ioc.hits > 0 ? th.danger : th.textMuted, opacity: ioc.hits > 0 ? 1 : 0.4 }} />
                    <span style={{ flex: 1, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, color: ioc.hits > 0 ? th.text : th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ioc.raw}>{ioc.raw}</span>
                    <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, flexShrink: 0, fontFamily: "-apple-system, sans-serif",
                      background: /^(IPv[46]|Domain|Email|URL|Crypto|User_Agent|Phone|Payment)/.test(ioc.category) ? `${th.accent}20` : /^(SHA|MD5)/.test(ioc.category) ? `${th.warning}20` : ioc.category === "Other" ? `${th.textMuted}20` : `${th.sev.custom}20`,
                      color: /^(IPv[46]|Domain|Email|URL|Crypto|User_Agent|Phone|Payment)/.test(ioc.category) ? th.accent : /^(SHA|MD5)/.test(ioc.category) ? th.warning : ioc.category === "Other" ? th.textMuted : th.sev.custom,
                    }}>{ioc.category.replace(/_/g, " ")}</span>
                    {vtr ? (<>
                      <span onClick={() => vtr.vtUrl && window.open(vtr.vtUrl, "_blank")}
                        title={vtr.vtUrl ? `Open on VirusTotal: ${vtr.score}` : vtr.error ? `Error: ${vtr.error}` : vtr.score}
                        style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, flexShrink: 0, fontFamily: "'SF Mono', Menlo, monospace",
                          background: `${vtScoreColor}20`, color: vtScoreColor, cursor: vtr.vtUrl ? "pointer" : "default",
                          border: `1px solid ${vtScoreColor}44`, fontWeight: 600 }}>
                        {vtr.error ? "Err" : vtr.score}
                      </span>
                      {vtr.error && vtKeyStatus?.hasKey && !vtEnriching && (
                        <span title="Retry this IOC" onClick={async () => {
                          const result = await tle.vtLookupSingle(ioc.raw, ioc.category);
                          if (result) setModal((p) => {
                            if (!p || p.type !== "ioc") return p;
                            const updated = { ...(p.vtResults || {}), [ioc.raw]: result };
                            return { ...p, vtResults: updated };
                          });
                        }} style={{ fontSize: 10, padding: "1px 5px", borderRadius: 3, flexShrink: 0, cursor: "pointer",
                          background: `${th.accent}20`, color: th.accent, border: `1px solid ${th.accent}44` }}>{"\u21BB"}</span>
                      )}
                      {vtr.threatLabel && <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, flexShrink: 0, background: `${vtScoreColor}12`, color: vtScoreColor, fontStyle: "italic" }}>{vtr.threatLabel}</span>}
                    </>
                    ) : isVtCompat ? (
                      <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 3, flexShrink: 0, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace" }}>{"\u2014"}</span>
                    ) : null}
                    {canPivot && (
                      <span title="Show related artifacts from VirusTotal" onClick={async () => {
                        if (relExpanded) {
                          setModal((p) => ({ ...p, vtRelated: { ...(p.vtRelated || {}), [ioc.raw]: { ...relData, expanded: false } } }));
                          return;
                        }
                        if (relData?.relationships) {
                          setModal((p) => ({ ...p, vtRelated: { ...(p.vtRelated || {}), [ioc.raw]: { ...relData, expanded: true } } }));
                          return;
                        }
                        setModal((p) => ({ ...p, vtRelated: { ...(p.vtRelated || {}), [ioc.raw]: { expanded: true, loading: true } } }));
                        const res = await tle.vtGetRelated(ioc.raw, ioc.category);
                        setModal((p) => ({ ...p, vtRelated: { ...(p.vtRelated || {}), [ioc.raw]: { expanded: true, loading: false, relationships: res?.relationships || [], error: res?.error } } }));
                      }} style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, flexShrink: 0, cursor: "pointer",
                        background: relExpanded ? `${th.accent}22` : "transparent", color: th.accent, border: `1px solid ${th.accent}33` }}>
                        {relData?.loading ? "..." : relExpanded ? "Hide Related" : "Pivot"}
                      </span>
                    )}
                    <span style={{ fontWeight: 600, fontSize: 12, color: ioc.hits > 0 ? th.danger : th.textMuted, flexShrink: 0, minWidth: 40, textAlign: "right", fontFamily: "'SF Mono', Menlo, monospace" }}>{ioc.hits > 0 ? `+${formatNumber(ioc.hits)}` : "\u2014"}</span>
                  </div>
                  {relExpanded && relData && !relData.loading && (
                    <div style={{ padding: "4px 10px 8px 28px", borderBottom: `1px solid ${th.border}22`, background: `${th.accent}08` }}>
                      {relData.error && <span style={{ fontSize: 10, color: th.danger }}>{relData.error}</span>}
                      {relData.relationships?.length === 0 && !relData.error && <span style={{ fontSize: 10, color: th.textMuted }}>No related artifacts found</span>}
                      {relData.relationships?.map((rel, ri) => (
                        <div key={ri} style={{ marginBottom: ri < relData.relationships.length - 1 ? 6 : 0 }}>
                          <div style={{ fontSize: 9, fontWeight: 600, color: th.textMuted, textTransform: "uppercase", marginBottom: 2 }}>{rel.type} ({rel.items.length})</div>
                          {rel.items.slice(0, 8).map((item, ii) => (
                            <div key={ii} style={{ display: "flex", alignItems: "center", gap: 6, padding: "1px 0", fontSize: 10 }}>
                              <span style={{ fontFamily: "'SF Mono', Menlo, monospace", color: item.malicious > 0 ? th.danger : th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 300 }}
                                title={item.name}>{item.name}</span>
                              {item.score && <span style={{ color: item.malicious > 0 ? th.danger : th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 9, flexShrink: 0 }}>{item.score}</span>}
                              {item.threatLabel && <span style={{ color: th.danger, fontSize: 9, fontStyle: "italic", flexShrink: 0 }}>{item.threatLabel}</span>}
                              {item.date && <span style={{ color: th.textDim, fontSize: 9, flexShrink: 0 }}>{new Date(item.date * 1000).toISOString().slice(0, 10)}</span>}
                              {(item.type === "file" || item.type === "domain" || item.type === "ip") && (
                                <span onClick={() => window.open(`https://www.virustotal.com/gui/${item.type === "ip" ? "ip-address" : item.type}/${item.id}`, "_blank")}
                                  style={{ color: th.accent, fontSize: 9, cursor: "pointer", flexShrink: 0, textDecoration: "underline" }}>VT</span>
                              )}
                            </div>
                          ))}
                          {rel.items.length > 8 && <div style={{ fontSize: 9, color: th.textMuted, fontStyle: "italic" }}>+{rel.items.length - 8} more</div>}
                        </div>
                      ))}
                    </div>
                  )}
                  </div>);
                })}
              </div>
            </div>
          </>);
          })()}
        </div>

        {/* Footer */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
          {phase === "load" && (<>
            <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
            <button disabled={parsedIocs.length === 0 || loading} onClick={handleScan}
              style={{ ...ms.bp, opacity: parsedIocs.length === 0 || loading ? 0.5 : 1, cursor: parsedIocs.length === 0 || loading ? "not-allowed" : "pointer" }}>
              {loading && scanProgress ? `${scanProgress.stage === "scan" ? Math.round((scanProgress.current / scanProgress.total) * 100) : scanProgress.stage === "tag" ? 90 : 95}% \u2014 ${scanProgress.label}` : loading ? `Scanning...` : `Scan ${parsedIocs.length > 0 ? parsedIocs.length + " IOCs" : ""}`}
            </button>
          </>)}
          {phase === "results" && results && (<>
            <button onClick={() => setModal((p) => ({ ...p, phase: "load" }))} style={ms.bs}>Back / Re-scan</button>
            <div style={{ display: "flex", gap: 6 }}>
              {(results.matchedCount > 0 || (results.matchedCount == null && results.allIocTags?.length > 0)) && (
                <button onClick={() => {
                  if (vtEnriching && vtRequestId) tle.vtCancel(vtRequestId);
                  clearIpcSubscription("vt-progress");
                  clearIpcSubscription("vt-complete");
                  if (vtResults && Object.keys(vtResults).length > 0) {
                    up("vtEnrichment", { results: vtResults, perIocResults: results.perIocResults, parsedIocs, matchedCount: results.matchedCount, allIocTags: results.allIocTags });
                  }
                  up("tagFilter", results.allIocTags || []); setModal(null);
                }} style={{ ...ms.bs, color: th.accent, borderColor: th.accent + "66" }}>Show Only IOC Matches</button>
              )}
              <button onClick={() => {
                if (vtEnriching && vtRequestId) tle.vtCancel(vtRequestId);
                clearIpcSubscription("vt-progress");
                clearIpcSubscription("vt-complete");
                if (vtResults && Object.keys(vtResults).length > 0) {
                  up("vtEnrichment", { results: vtResults, perIocResults: results.perIocResults, parsedIocs, matchedCount: results.matchedCount, allIocTags: results.allIocTags });
                }
                setModal(null);
              }} style={ms.bp}>Done</button>
            </div>
          </>)}
        </div>
      </div>
    </div>
    </Modal>
  );
}
