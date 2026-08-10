/**
 * Renderer-only grid geometry helpers.
 *
 * Keep these calculations outside React so column-width and keyboard-scroll
 * regressions can be covered by the Node test suite.
 */

export function getGridContentWidth({
  visibleColumns = [],
  columnWidths = {},
  defaultColumnWidth = 150,
  leadingWidth = 0,
  tagWidth = 0,
  vtWidth = 0,
  evidenceWidth = 0,
} = {}) {
  const dataWidth = visibleColumns.reduce(
    (sum, column) => sum + (columnWidths[column] || defaultColumnWidth),
    0,
  );
  return dataWidth + leadingWidth + tagWidth + vtWidth + evidenceWidth;
}

export function getGridBodyViewportHeight(
  viewportHeight,
  stickyHeight,
  minimumHeight = 1,
) {
  return Math.max(minimumHeight, viewportHeight - stickyHeight);
}

export function getVisibleRowRange({
  totalCount,
  logicalScrollTop,
  viewportHeight,
  rowHeight,
} = {}) {
  const count = Math.max(0, Number(totalCount) || 0);
  if (count === 0) return { start: 0, end: 0 };

  const height = Math.max(1, Number(rowHeight) || 1);
  const scrollTop = Math.max(0, Number(logicalScrollTop) || 0);
  const visibleHeight = Math.max(height, Number(viewportHeight) || height);
  const start = Math.min(count, Math.floor(scrollTop / height) + 1);
  const end = Math.min(count, Math.max(start, Math.ceil((scrollTop + visibleHeight) / height)));
  return { start, end };
}

export function getRowScrollTarget({
  rowIndex,
  rowHeight,
  logicalScrollTop,
  viewportHeight,
  stickyHeight,
} = {}) {
  const bodyHeight = getGridBodyViewportHeight(
    viewportHeight,
    stickyHeight,
    rowHeight,
  );
  const rowTop = rowIndex * rowHeight;
  const rowBottom = rowTop + rowHeight;

  if (rowTop < logicalScrollTop) return rowTop;
  if (rowBottom > logicalScrollTop + bodyHeight) {
    return Math.max(0, rowBottom - bodyHeight);
  }
  return null;
}
