import { useCallback } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { formatNumber } from "../../utils/format.js";
import { Modal, Button, Input, Card } from "../primitives/index.js";

export default function BulkActionsModal({
  fetchData,
  selectionFilterOptions = null,
  selectionCount = 0,
}) {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const ct = useCurrentTab();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const up = useCallback((key, value) => {
    useTabStore.getState().updateActiveTab({ [key]: value });
  }, []);

  // Inline activeFilters helper
  const activeFilters = (tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  };

  if (modal?.type !== "bulkActions" || !ct) return null;

  const af = activeFilters(ct);
  const filteredViewOpts = {
    searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
    searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
    columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
    bookmarkedOnly: ct.showBookmarkedOnly, tagFilter: ct.tagFilter || null,
    rowIdFilter: ct.rowIdFilter || null,
    dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
  };
  const modalSelectionOptions = modal.selectionFilterOptions || selectionFilterOptions;
  const appliesToSelection = modal.scope === "selection" && modalSelectionOptions;
  const filterOpts = appliesToSelection ? modalSelectionOptions : filteredViewOpts;
  const tagName = modal.tagName || "";
  const tagColor = modal.tagColor || th.accent;
  const result = modal.result;
  const busy = modal.busy || false;
  const existingTags = Object.keys(ct.tagColors || {});

  const handleTag = async () => {
    if (!tagName.trim() || busy) return;
    setModal((p) => p?.type === "bulkActions" ? { ...p, busy: true, result: null } : p);
    try {
      const res = await tle.bulkTagFiltered(ct.id, tagName.trim(), filterOpts);
      if (res?.error) throw new Error(res.error);
      up("tagColors", { ...(ct.tagColors || {}), [tagName.trim()]: tagColor });
      await fetchData(ct);
      setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "success", msg: `Tagged ${formatNumber(res.tagged)} rows as "${tagName.trim()}"` } } : p);
    } catch (e) {
      setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "error", msg: e.message } } : p);
    }
  };
  const handleBookmark = async (add) => {
    if (busy) return;
    setModal((p) => p?.type === "bulkActions" ? { ...p, busy: true, result: null } : p);
    try {
      const res = await tle.bulkBookmarkFiltered(ct.id, add, filterOpts);
      if (res?.error) throw new Error(res.error);
      await fetchData(ct);
      const msg = add ? `Bookmarked ${formatNumber(res.affected)} rows` : `Removed bookmarks from ${formatNumber(res.affected)} rows`;
      setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "success", msg } } : p);
    } catch (e) {
      setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "error", msg: e.message } } : p);
    }
  };

  const targetCount = appliesToSelection
    ? (modal.selectionCount || selectionCount)
    : ct.totalFiltered;
  const subtitle = (
    <>
      Applies to{" "}
      <b style={{ color: targetCount < ct.totalRows ? th.warning : th.text }}>
        {formatNumber(targetCount)}
      </b>{" "}
      {appliesToSelection ? "selected rows" : "filtered rows"}
    </>
  );

  return (
    <Modal
      title="Bulk Actions"
      subtitle={subtitle}
      width={480}
      onClose={() => setModal(null)}
      bodyPadding="16px 20px"
      footer={true}
    >
      {/* Tag section */}
      <Card label={appliesToSelection ? "Tag Selected Rows" : "Tag Filtered Rows"} style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <Input
            type="text"
            value={tagName}
            onChange={(e) => setModal((p) => p?.type === "bulkActions" ? { ...p, tagName: e.target.value } : p)}
            onKeyDown={(e) => { if (e.key === "Enter") handleTag(); }}
            placeholder="Tag name..."
            list="bulk-tag-suggestions"
            style={{ flex: 1, background: th.modalBg }}
          />
          <datalist id="bulk-tag-suggestions">
            {existingTags.map((t) => <option key={t} value={t} />)}
          </datalist>
          <input
            type="color"
            value={tagColor}
            onChange={(e) => setModal((p) => p?.type === "bulkActions" ? { ...p, tagColor: e.target.value } : p)}
            title="Tag color"
            style={{ width: 30, height: 30, border: `1px solid ${th.border}`, borderRadius: 4, padding: 0, cursor: "pointer", background: "none", flexShrink: 0 }}
          />
          <Button onClick={handleTag} disabled={!tagName.trim()} loading={busy}>
            Apply Tag
          </Button>
        </div>
      </Card>

      {/* Bookmark section */}
      <Card label={appliesToSelection ? "Bookmark Selected Rows" : "Bookmark Filtered Rows"} style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", gap: 8 }}>
          <Button variant="accentSoft" onClick={() => handleBookmark(true)} disabled={busy} fullWidth>
            ★ Bookmark All
          </Button>
          <Button variant="dangerSoft" onClick={() => handleBookmark(false)} disabled={busy} fullWidth>
            ☆ Remove Bookmarks
          </Button>
        </div>
      </Card>

      {/* Result message */}
      {result && (
        <div style={{
          padding: "8px 12px", borderRadius: 6, fontSize: 12,
          fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
          background: result.type === "success" ? (th.success + "18") : ((th.danger) + "18"),
          color: result.type === "success" ? th.success : (th.danger),
          border: `1px solid ${result.type === "success" ? th.success : (th.danger)}44`,
        }}>
          {result.type === "success" ? "✓ " : "✗ "}{result.msg}
        </div>
      )}
    </Modal>
  );
}
