import { useCallback } from "react";
import useUIStore from "../../../store/useUIStore.js";

export default function useProcessAnalystEntries() {
  const setPiAnalystProfile = useUIStore((s) => s.setPiAnalystProfile);

  const upsertPiAnalystEntry = useCallback((bucket, entry) => {
    if (!bucket || !entry) return;
    setPiAnalystProfile((prev) => {
      const current = Array.isArray(prev?.[bucket]) ? prev[bucket] : [];
      const exists = current.some((item) =>
        item.reason === entry.reason &&
        item.processName === entry.processName &&
        item.parentProcessName === entry.parentProcessName &&
        item.hostname === entry.hostname &&
        item.user === entry.user &&
        item.image === entry.image &&
        item.cmdContains === entry.cmdContains
      );
      if (exists) return prev;
      return { ...prev, [bucket]: [...current, entry] };
    });
  }, [setPiAnalystProfile]);

  const removePiAnalystEntry = useCallback((bucket, entryId) => {
    if (!bucket || !entryId) return;
    setPiAnalystProfile((prev) => ({
      ...prev,
      [bucket]: (prev?.[bucket] || []).filter((item) => item.id !== entryId),
    }));
  }, [setPiAnalystProfile]);

  const makePiAnalystEntry = useCallback((bucket, node, parentNode, susInfo) => {
    if (!node || !susInfo?.reason) return null;
    const primary = (susInfo.evidence || []).find((e) => e.reason === susInfo.reason) || null;
    const isChain = primary?.cat === "chain";
    return {
      id: `${bucket}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt: new Date().toISOString(),
      reason: susInfo.reason,
      processName: node.processName || "",
      parentProcessName: isChain ? (parentNode?.processName || "") : "",
      hostname: bucket === "baselines" ? (node.hostname || "") : "",
      user: "",
      image: bucket === "baselines" ? (node.image || "") : "",
      cmdContains: "",
    };
  }, []);

  return { upsertPiAnalystEntry, removePiAnalystEntry, makePiAnalystEntry };
}
