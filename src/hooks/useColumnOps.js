import { useCallback } from "react";
import useTabStore from "../store/useTabStore.js";
import useGridInteractionStore from "../store/useGridInteractionStore.js";

/**
 * Column management operations: pin/unpin, group by, reorder, auto-fit, reset widths.
 *
 * Extracted from App.jsx to reduce its line count and keep column logic co-located.
 * All operations update tab state via useTabStore — the grid re-renders automatically
 * via Zustand subscriptions.
 */
export default function useColumnOps() {
  const activeTab = useTabStore((s) => s.activeTab);
  const setTabs = useTabStore((s) => s.setTabs);
  const setTagColWidth = useGridInteractionStore((s) => s.setTagColWidth);

  const pinColumn = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const pinned = t.pinnedColumns || [];
      if (pinned.includes(colName)) return t;
      return { ...t, pinnedColumns: [...pinned, colName] };
    }));
  }, [activeTab]);

  const unpinColumn = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      return { ...t, pinnedColumns: (t.pinnedColumns || []).filter((c) => c !== colName) };
    }));
  }, [activeTab]);

  const addGroupBy = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const groups = t.groupByColumns || [];
      if (groups.includes(colName) || groups.length >= 5) return t;
      return { ...t, groupByColumns: [...groups, colName], expandedGroups: {}, groupData: [] };
    }));
  }, [activeTab]);

  const removeGroupBy = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      return { ...t, groupByColumns: (t.groupByColumns || []).filter((c) => c !== colName), expandedGroups: {}, groupData: [] };
    }));
  }, [activeTab]);

  const resetColumnWidths = useCallback(() => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const cw = {};
      t.headers.forEach((h) => {
        const hLen = h.length * 8 + 36;
        const sample = (t.rows || []).slice(0, 50).map((r) => ((r[h] || "").length * 6.5 + 16));
        cw[h] = Math.max(80, Math.min(Math.max(hLen, ...sample), 450));
      });
      return { ...t, columnWidths: cw };
    }));
  }, [activeTab]);

  const autoFitColumn = useCallback((colName) => {
    if (colName === "__tags__") {
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        const hLen = 4 * 8 + 36;
        const sample = (t.rows || []).slice(0, 200).map((r) => {
          const tags = (t.rowTags || {})[r.__idx] || [];
          return tags.reduce((w, tag) => w + tag.length * 6.5 + 14, 8);
        });
        const best = Math.max(80, Math.min(Math.max(hLen, ...sample), 800));
        setTagColWidth(best);
        return t;
      }));
      return;
    }
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const hLen = colName.length * 8 + 36;
      const sample = (t.rows || []).slice(0, 200).map((r) => ((r[colName] || "").length * 6.5 + 16));
      const best = Math.max(80, Math.min(Math.max(hLen, ...sample), 800));
      return { ...t, columnWidths: { ...t.columnWidths, [colName]: best } };
    }));
  }, [activeTab]);

  const autoFitAllColumns = useCallback(() => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const visH = t.headers.filter((h) => !t.hiddenColumns?.has(h));
      const newWidths = { ...t.columnWidths };
      for (const h of visH) {
        const hLen = h.length * 8 + 36;
        const sample = (t.rows || []).slice(0, 200).map((r) => ((r[h] || "").length * 6.5 + 16));
        newWidths[h] = Math.max(80, Math.min(Math.max(hLen, ...sample), 800));
      }
      return { ...t, columnWidths: newWidths };
    }));
  }, [activeTab]);

  const reorderColumn = useCallback((dragCol, dropCol) => {
    if (dragCol === dropCol) return;
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const order = t.columnOrder?.length > 0
        ? [...t.columnOrder]
        : [...t.headers];
      const fromIdx = order.indexOf(dragCol);
      const toIdx = order.indexOf(dropCol);
      if (fromIdx === -1 || toIdx === -1) return t;
      order.splice(fromIdx, 1);
      order.splice(toIdx, 0, dragCol);
      return { ...t, columnOrder: order };
    }));
  }, [activeTab]);

  return {
    pinColumn, unpinColumn,
    addGroupBy, removeGroupBy,
    resetColumnWidths, autoFitColumn, autoFitAllColumns,
    reorderColumn,
  };
}
