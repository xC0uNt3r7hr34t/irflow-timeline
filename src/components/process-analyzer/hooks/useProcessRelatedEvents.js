import { useEffect } from "react";
import useUIStore from "../../../store/useUIStore.js";

export default function useProcessRelatedEvents(ctId) {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const tle = typeof window !== "undefined" ? window.tle : null;

  useEffect(() => {
    if (modal?.type !== "processTree" || modal.phase !== "results" || !tle?.getProcessInspectorContext || !ctId) return;
    if (!modal.selectedKey || !Array.isArray(modal.data?.processes) || modal.data.processes.length === 0) {
      if (modal.ptRelatedEvents || modal.ptRelatedEventsLoading || modal.ptRelatedEventsError) {
        setModal((p) => p?.type === "processTree"
          ? { ...p, ptRelatedEvents: null, ptRelatedEventsLoading: false, ptRelatedEventsError: null, ptRelatedEventsKey: null, ptRelatedEventsReqKey: null }
          : p);
      }
      return;
    }

    const selNode = modal.data.processes.find((p) => p.key === modal.selectedKey);
    if (!selNode?.rowid) return;
    const reqKey = `${ctId}:${selNode.rowid}:${selNode.key}`;
    if (modal.ptRelatedEventsKey === reqKey || modal.ptRelatedEventsReqKey === reqKey) return;

    let cancelled = false;
    setModal((p) => p?.type === "processTree" && p.selectedKey === selNode.key
      ? { ...p, ptRelatedEventsLoading: true, ptRelatedEventsError: null, ptRelatedEventsReqKey: reqKey }
      : p);

    tle.getProcessInspectorContext(ctId, {
      rowId: selNode.rowid,
      selected: {
        rowid: selNode.rowid,
        key: selNode.key,
        ts: selNode.ts || "",
        hostname: selNode.hostname || "",
        user: selNode.user || "",
        pid: selNode.pid || "",
        ppid: selNode.ppid || "",
        guid: selNode.guid || "",
        parentGuid: selNode.parentGuid || "",
        processName: selNode.processName || "",
        parentProcessName: selNode.parentProcessName || "",
        image: selNode.image || "",
        parentImage: selNode.parentImage || "",
        cmdLine: selNode.cmdLine || "",
        eventId: selNode.eventId || "",
        provider: selNode.provider || "",
      },
    }).then((result) => {
      if (cancelled) return;
      setModal((p) => p?.type === "processTree" && p.selectedKey === selNode.key && p.ptRelatedEventsReqKey === reqKey
        ? {
            ...p,
            ptRelatedEventsLoading: false,
            ptRelatedEvents: result || null,
            ptRelatedEventsError: result?.error || null,
            ptRelatedEventsKey: reqKey,
          }
        : p);
    }).catch((err) => {
      if (cancelled) return;
      setModal((p) => p?.type === "processTree" && p.selectedKey === selNode.key && p.ptRelatedEventsReqKey === reqKey
        ? {
            ...p,
            ptRelatedEventsLoading: false,
            ptRelatedEvents: null,
            ptRelatedEventsError: err?.message || "Related event lookup failed",
            ptRelatedEventsKey: reqKey,
          }
        : p);
    });

    return () => { cancelled = true; };
  }, [ctId, modal?.type, modal?.phase, modal?.selectedKey, modal?.data, modal?.ptRelatedEventsKey, modal?.ptRelatedEventsReqKey, tle]);
}
