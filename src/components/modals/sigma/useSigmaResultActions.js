import { sevColorsFor } from "./constants.js";
import { sigmaRuleKey } from "./triageSummary.mjs";
import { downloadFile, rowsToCsv } from "./sigmaModalHelpers.js";
import { clearIpcSubscription, replaceIpcSubscription } from "../../../utils/ipc-subscriptions.js";

export default function useSigmaResultActions({
  modal,
  setModal,
  tle,
  ct,
  th,
  up,
  fetchData,
  updateActiveTab,
  sigmaResultsRef,
  results,
}) {
  const SEV_COLORS = sevColorsFor(th);
  const getExactSourceRows = async (match) => {
    const jobId = sigmaResultsRef.current?.jobId || modal?.jobId;
    if (!jobId || !tle?.sigmaGetSourceRows) {
      throw new Error("Scan results expired — please re-run the scan.");
    }
    const rows = await tle.sigmaGetSourceRows(jobId, { ruleId: match.ruleId, title: match.title });
    if (rows?.__ipcError || rows?.error) {
      throw new Error(rows.message || rows.error || "Failed to load exact source rows.");
    }
    return Array.isArray(rows) ? rows : [];
  };

  const currentResultsAreResultOnly = () => (
    sigmaResultsRef.current?.sourceRowMode === "result" ||
    !!(sigmaResultsRef.current?.isDirScan || sigmaResultsRef.current?.isKapeOutput || sigmaResultsRef.current?.isHistory)
  );

  const handleShowInTimeline = async (match) => {
    if (!ct?.dataReady) return;
    setModal((p) => ({ ...p, sourceAction: "show", error: null }));
    try {
      const sourceRows = await getExactSourceRows(match);
      const rowIds = [...new Set(sourceRows
        .filter((r) => String(r.tabId) === String(ct.id) && Number.isSafeInteger(Number(r.rowId)) && Number(r.rowId) > 0)
        .map((r) => Number(r.rowId)))];
      if (rowIds.length === 0) {
        setModal((p) => ({ ...p, sourceAction: null, error: "No exact source rows were found in the current tab for this rule." }));
        return;
      }
      const updates = {
        rowIdFilter: rowIds,
        rowIdFilterLabel: match.title || match.ruleId || "Sigma match",
        searchTerm: "",
        searchHighlight: false,
        showBookmarkedOnly: false,
        tagFilter: null,
        groupByColumns: [],
        groupData: [],
        expandedGroups: {},
      };
      updateActiveTab(updates);
      fetchData({ ...ct, ...updates });
      setModal(null);
    } catch (e) {
      setModal((p) => ({ ...p, sourceAction: null, error: e?.message || "Failed to show exact matches." }));
    }
  };

  const getActiveScanHistoryId = () => (
    modal.historyId
    || results?.historyId
    || results?.historyRecord?.id
    || sigmaResultsRef.current?.historyId
    || null
  );

  const persistTriageState = (nextState) => {
    const historyId = getActiveScanHistoryId();
    if (!historyId || !tle?.sigmaUpdateScanTriage) return;
    tle.sigmaUpdateScanTriage(historyId, nextState).catch((e) => {
      setModal((p) => p?.type === "sigma" ? { ...p, error: e?.message || "Failed to persist scan triage state" } : p);
    });
  };

  const openExactMatchesAsTab = async (match, {
    sourceAction = "open",
    postAction = null,
    progressText = "Starting exact-match tab...",
    onSuccess = null,
  } = {}) => {
    const jobId = sigmaResultsRef.current?.jobId || modal?.jobId;
    if (!jobId || !tle?.sigmaOpenSourceRowsAsTab) {
      setModal((p) => ({ ...p, error: "Scan results expired — please re-run the scan." }));
      return null;
    }
    const nameBase = match.title || match.ruleId || "Sigma exact hits";
    const name = `Sigma Exact Hits - ${nameBase}`.slice(0, 120);
    setModal((p) => ({
      ...p,
      sourceAction,
      importProgress: { phase: "importing-tab", importInserted: 0, importTotal: match.matchCount || match._triageHitCount || 0, importPct: 0, text: progressText },
      error: null,
    }));
    replaceIpcSubscription("sigma-progress", tle.onSigmaProgress, (prog) => {
      if (prog?.phase === "importing-tab" || prog?.phase === "importing-tab-done") {
        setModal((p) => p?.type === "sigma" ? { ...p, importProgress: prog } : p);
      }
    });
    try {
      const r = await tle.sigmaOpenSourceRowsAsTab(jobId, { ruleId: match.ruleId, title: match.title }, name, postAction);
      clearIpcSubscription("sigma-progress");
      if (r?.__ipcError || r?.error) {
        setModal((p) => ({ ...p, sourceAction: null, importProgress: null, error: r.message || r.error || "Failed to open exact matches as a tab" }));
        return null;
      }
      onSuccess?.(r);
      setModal(null);
      return r;
    } catch (e) {
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, sourceAction: null, importProgress: null, error: e?.message || "Failed to open exact matches as a tab" }));
      return null;
    }
  };

  const handleTagMatches = async (match) => {
    if (!match.title) return;
    const key = sigmaRuleKey(match);
    const level = match._triageLevel || match.level || "medium";
    const tag = `sigma:${level}`;
    if (currentResultsAreResultOnly()) {
      await openExactMatchesAsTab(match, {
        sourceAction: "tag",
        progressText: `Opening exact hits and applying tag "${tag}"...`,
        postAction: { tag, tagColor: SEV_COLORS[level] || th.accent },
        onSuccess: () => {
          const nextTagged = { ...(modal.sigmaTaggedRules || {}), [key]: tag };
          persistTriageState({
            reviewedRules: modal.sigmaReviewedRules || {},
            falsePositiveRules: modal.sigmaFalsePositiveRules || {},
            taggedRules: nextTagged,
            bookmarkedRules: modal.sigmaBookmarkedRules || {},
          });
        },
      });
      return;
    }
    setModal((p) => ({ ...p, sourceAction: "tag", error: null }));
    try {
      const jobId = sigmaResultsRef.current?.jobId || modal?.jobId;
      if (jobId && tle?.sigmaTagMatches) {
        const res = await tle.sigmaTagMatches(jobId, { ruleId: match.ruleId, title: match.title }, tag);
        if (res?.__ipcError || res?.error) {
          setModal((p) => ({ ...p, sourceAction: null, error: res.message || res.error || "Failed to tag exact matches" }));
          return;
        }
        if (!res.tagged && !res.sourceRows) {
          const nextTagged = { ...(modal.sigmaTaggedRules || {}), [key]: tag };
          setModal((p) => ({ ...p, sourceAction: null, sigmaTaggedRules: nextTagged }));
          persistTriageState({
            reviewedRules: modal.sigmaReviewedRules || {},
            falsePositiveRules: modal.sigmaFalsePositiveRules || {},
            taggedRules: nextTagged,
            bookmarkedRules: modal.sigmaBookmarkedRules || {},
          });
          return;
        }
      } else {
        if (!ct?.dataReady) {
          const nextTagged = { ...(modal.sigmaTaggedRules || {}), [key]: tag };
          setModal((p) => ({ ...p, sourceAction: null, sigmaTaggedRules: nextTagged }));
          persistTriageState({
            reviewedRules: modal.sigmaReviewedRules || {},
            falsePositiveRules: modal.sigmaFalsePositiveRules || {},
            taggedRules: nextTagged,
            bookmarkedRules: modal.sigmaBookmarkedRules || {},
          });
          return;
        }
        await tle.bulkTagFiltered(ct.id, tag, { searchTerm: match.title, searchMode: "mixed", searchCondition: "contains" });
      }
      if (ct?.dataReady) {
        const td = await tle.getAllTagData(ct.id);
        const nrt = {};
        for (const { rowid, tag: rowTag } of td) {
          if (!nrt[rowid]) nrt[rowid] = [];
          nrt[rowid].push(rowTag);
        }
        up("rowTags", nrt);
        const sevColor = SEV_COLORS[level] || th.accent;
        up("tagColors", { ...(ct.tagColors || {}), [tag]: sevColor });
        fetchData(ct);
      }
      const nextTagged = { ...(modal.sigmaTaggedRules || {}), [key]: tag };
      setModal((p) => ({ ...p, sourceAction: null, sigmaTaggedRules: nextTagged }));
      persistTriageState({
        reviewedRules: modal.sigmaReviewedRules || {},
        falsePositiveRules: modal.sigmaFalsePositiveRules || {},
        taggedRules: nextTagged,
        bookmarkedRules: modal.sigmaBookmarkedRules || {},
      });
    } catch (e) {
      setModal((p) => ({ ...p, sourceAction: null, error: e?.message || "Failed to tag exact matches" }));
    }
  };

  const handleBookmarkMatches = async (match) => {
    const key = sigmaRuleKey(match);
    if (currentResultsAreResultOnly()) {
      await openExactMatchesAsTab(match, {
        sourceAction: "bookmark",
        progressText: "Opening exact hits and bookmarking imported result rows...",
        postAction: { bookmark: true },
        onSuccess: () => {
          const nextBookmarked = { ...(modal.sigmaBookmarkedRules || {}), [key]: true };
          persistTriageState({
            reviewedRules: modal.sigmaReviewedRules || {},
            falsePositiveRules: modal.sigmaFalsePositiveRules || {},
            taggedRules: modal.sigmaTaggedRules || {},
            bookmarkedRules: nextBookmarked,
          });
        },
      });
      return;
    }
    const jobId = sigmaResultsRef.current?.jobId || modal?.jobId;
    if (!jobId || !tle?.sigmaBookmarkMatches) {
      const nextBookmarked = { ...(modal.sigmaBookmarkedRules || {}), [key]: true };
      setModal((p) => ({ ...p, sigmaBookmarkedRules: nextBookmarked }));
      persistTriageState({
        reviewedRules: modal.sigmaReviewedRules || {},
        falsePositiveRules: modal.sigmaFalsePositiveRules || {},
        taggedRules: modal.sigmaTaggedRules || {},
        bookmarkedRules: nextBookmarked,
      });
      return;
    }
    setModal((p) => ({ ...p, sourceAction: "bookmark", error: null }));
    try {
      const res = await tle.sigmaBookmarkMatches(jobId, { ruleId: match.ruleId, title: match.title }, true);
      if (res?.__ipcError || res?.error) {
        setModal((p) => ({ ...p, sourceAction: null, error: res.message || res.error || "Failed to bookmark exact matches" }));
        return;
      }
      if (!res.affected && !res.sourceRows) {
        const nextBookmarked = { ...(modal.sigmaBookmarkedRules || {}), [key]: true };
        setModal((p) => ({ ...p, sourceAction: null, sigmaBookmarkedRules: nextBookmarked }));
        persistTriageState({
          reviewedRules: modal.sigmaReviewedRules || {},
          falsePositiveRules: modal.sigmaFalsePositiveRules || {},
          taggedRules: modal.sigmaTaggedRules || {},
          bookmarkedRules: nextBookmarked,
        });
        return;
      }
      if (ct?.dataReady) fetchData(ct);
      const nextBookmarked = { ...(modal.sigmaBookmarkedRules || {}), [key]: true };
      setModal((p) => ({ ...p, sourceAction: null, sigmaBookmarkedRules: nextBookmarked }));
      persistTriageState({
        reviewedRules: modal.sigmaReviewedRules || {},
        falsePositiveRules: modal.sigmaFalsePositiveRules || {},
        taggedRules: modal.sigmaTaggedRules || {},
        bookmarkedRules: nextBookmarked,
      });
    } catch (e) {
      setModal((p) => ({ ...p, sourceAction: null, error: e?.message || "Failed to bookmark exact matches" }));
    }
  };

  const handleMarkRuleReviewed = (match, reviewed = true) => {
    const key = sigmaRuleKey(match);
    if (!key) return;
    const nextReviewed = { ...(modal.sigmaReviewedRules || {}) };
    if (reviewed) nextReviewed[key] = new Date().toISOString();
    else delete nextReviewed[key];
    const nextState = {
      reviewedRules: nextReviewed,
      falsePositiveRules: modal.sigmaFalsePositiveRules || {},
      taggedRules: modal.sigmaTaggedRules || {},
      bookmarkedRules: modal.sigmaBookmarkedRules || {},
    };
    setModal((p) => ({ ...p, sigmaReviewedRules: nextReviewed }));
    persistTriageState(nextState);
  };

  const handleMarkRuleFalsePositive = (match, falsePositive = true) => {
    const key = sigmaRuleKey(match);
    if (!key) return;
    const now = new Date().toISOString();
    const falsePositives = { ...(modal.sigmaFalsePositiveRules || {}) };
    const reviewed = { ...(modal.sigmaReviewedRules || {}) };
    if (falsePositive) {
      falsePositives[key] = now;
      reviewed[key] = reviewed[key] || now;
    } else {
      delete falsePositives[key];
    }
    const nextState = {
      reviewedRules: reviewed,
      falsePositiveRules: falsePositives,
      taggedRules: modal.sigmaTaggedRules || {},
      bookmarkedRules: modal.sigmaBookmarkedRules || {},
    };
    setModal((p) => ({ ...p, sigmaFalsePositiveRules: falsePositives, sigmaReviewedRules: reviewed }));
    persistTriageState(nextState);
  };

  const handleOpenExactMatchesAsTab = async (match) => {
    await openExactMatchesAsTab(match);
  };

  const handleExportCSV = async () => {
    const jobId = sigmaResultsRef.current?.jobId || modal?.jobId;
    if (jobId && tle?.sigmaExportDirCsv) {
      const r = await tle.sigmaExportDirCsv(jobId);
      if (r?.__ipcError) setModal((p) => ({ ...p, error: r.message || "Export failed" }));
      return;
    }
    if (results?.matches) {
      const rows = results.matches.map((m) => ({
        severity: m.level,
        title: m.title,
        mitre: (m.mitre || []).join("; "),
        matches: m.matchCount,
        hosts: (m.hosts || []).join("; "),
        firstSeen: m.firstSeen || "",
        lastSeen: m.lastSeen || "",
        description: m.description || "",
        author: m.author || "",
      }));
      downloadFile(rowsToCsv(rows), "sigma-rules-summary.csv", "text/csv");
    }
  };

  const handleExportJSON = async () => {
    const jobId = sigmaResultsRef.current?.jobId || modal?.jobId;
    if (jobId && tle?.sigmaExportDirJson) {
      const r = await tle.sigmaExportDirJson(jobId);
      if (r?.__ipcError) setModal((p) => ({ ...p, error: r.message || "Export failed" }));
      return;
    }
    const exportData = {
      summary: results?.stats || {},
      matches: results?.matches || [],
      eventRows: [],
    };
    downloadFile(JSON.stringify(exportData, null, 2), `sigma-results-${new Date().toISOString().slice(0, 10)}.json`, "application/json");
  };

  const handleOpenAsTab = async () => {
    const jobId = sigmaResultsRef.current?.jobId || modal?.jobId;
    const name = `Sigma Timeline — ${new Date().toISOString().slice(0, 10)}`;
    if (!jobId || !tle?.sigmaOpenAsTab) {
      setModal((p) => ({ ...p, error: "Scan results expired — please re-run the scan." }));
      return;
    }
    setModal((p) => ({ ...p, openingTab: true, importProgress: { phase: "importing-tab", importInserted: 0, importTotal: results?.eventRowCount || 0, importPct: 0, text: "Starting import..." }, error: null }));
    replaceIpcSubscription("sigma-progress", tle.onSigmaProgress, (prog) => {
      if (prog?.phase === "importing-tab" || prog?.phase === "importing-tab-done") {
        setModal((p) => p?.type === "sigma" ? { ...p, importProgress: prog } : p);
      }
    });
    try {
      const r = await tle.sigmaOpenAsTab(null, name, jobId);
      clearIpcSubscription("sigma-progress");
      if (r?.__ipcError) {
        setModal((p) => ({ ...p, openingTab: false, importProgress: null, error: r.message || "Failed to open as tab" }));
        return;
      }
      if (r?.error) {
        setModal((p) => ({ ...p, openingTab: false, importProgress: null, error: r.error }));
        return;
      }
    } catch (e) {
      clearIpcSubscription("sigma-progress");
      setModal((p) => ({ ...p, openingTab: false, importProgress: null, error: e?.message || "Failed to open as tab" }));
      return;
    }
    setModal(null);
  };

  return {
    handleShowInTimeline,
    handleTagMatches,
    handleBookmarkMatches,
    handleMarkRuleReviewed,
    handleMarkRuleFalsePositive,
    handleOpenExactMatchesAsTab,
    handleExportCSV,
    handleExportJSON,
    handleOpenAsTab,
  };
}
