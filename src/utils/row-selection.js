export function isRowSelected(selectedRowIds, allRowsSelected, rowId) {
  if (!Number.isInteger(Number(rowId)) || Number(rowId) <= 0) return false;
  return allRowsSelected
    ? !selectedRowIds.has(Number(rowId))
    : selectedRowIds.has(Number(rowId));
}

export function toggleRowSelection(selectedRowIds, allRowsSelected, rowId) {
  const id = Number(rowId);
  if (!Number.isInteger(id) || id <= 0) return new Set(selectedRowIds);
  const next = new Set(selectedRowIds);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

export function selectRowIds(selectedRowIds, allRowsSelected, rowIds) {
  const next = new Set(selectedRowIds);
  for (const value of rowIds) {
    const id = Number(value);
    if (!Number.isInteger(id) || id <= 0) continue;
    // In select-all mode the Set stores exceptions, so selecting a row removes it.
    if (allRowsSelected) next.delete(id);
    else next.add(id);
  }
  return next;
}

export function getSelectedRowCount(selectedRowIds, allRowsSelected, totalRows) {
  if (!allRowsSelected) return selectedRowIds.size;
  return Math.max(0, Number(totalRows || 0) - selectedRowIds.size);
}

export function getHeaderSelectionState(selectedRowIds, allRowsSelected, totalRows) {
  const normalizedTotal = Math.max(0, Number(totalRows || 0));
  const selectedCount = getSelectedRowCount(
    selectedRowIds,
    allRowsSelected,
    normalizedTotal,
  );
  return {
    selectedCount,
    checked: normalizedTotal > 0 && selectedCount === normalizedTotal,
    indeterminate: selectedCount > 0 && selectedCount < normalizedTotal,
  };
}
