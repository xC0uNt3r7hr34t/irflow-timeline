import { useCallback } from "react";
import useUIStore from "../../../store/useUIStore.js";

export default function useProcessSourceEvent(ctId) {
  const setModal = useUIStore((s) => s.setModal);
  const tle = typeof window !== "undefined" ? window.tle : null;

  return useCallback(async (target) => {
    const rowId = typeof target === "object" ? target?.rowId : target;
    const tabId = typeof target === "object" ? (target?.tabId || ctId) : ctId;
    if (!tle?.getRowsByIds || !tabId || !rowId) return;
    setModal((p) => p?.type === "processTree" ? { ...p, ptSourceEventLoading: true, ptSourceEvent: null } : p);
    try {
      const rows = await tle.getRowsByIds(tabId, [rowId]);
      const row = rows?.[0] || null;
      setModal((p) => p?.type === "processTree"
        ? { ...p, ptSourceEventLoading: false, ptSourceEvent: row ? { tabId, rowId, row } : null }
        : p);
    } catch {
      setModal((p) => p?.type === "processTree" ? { ...p, ptSourceEventLoading: false, ptSourceEvent: null } : p);
    }
  }, [ctId, tle, setModal]);
}
