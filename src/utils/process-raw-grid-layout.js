// Responsive sizing for the Process Inspector Raw grid.
// Header and body consumers must use the same returned map.

export const PI_RAW_COLUMN_MIN_WIDTHS = Object.freeze({
  Timestamp: 140,
  Detection: 140,
  Prevalence: 80,
  "Parent Process": 120,
  Process: 190,
  "Command Line": 210,
  PID: 50,
  PPID: 50,
  User: 100,
  Provider: 70,
  "Event ID": 52,
  Integrity: 60,
});

export const PI_RAW_TREE_LAYOUT = Object.freeze({
  leftPad: 16,
  indent: 20,
  controlWidth: 14,
  iconWidth: 14,
  gap: 4,
  // Align the Process header with a root process name after the tree spacer,
  // expander, icon, and the three flex gaps between those elements.
  headerInset: 56,
});

export function processRawGridWidth(widths, headers, fixedWidth = 82) {
  return Math.round(fixedWidth + headers.reduce((sum, header) => sum + (Number(widths?.[header]) || 0), 0));
}

/**
 * Fit preferred column widths into the available grid viewport.
 * Below the readable minimum, retain minimums and allow horizontal scrolling.
 */
export function fitProcessRawColumnWidths(preferredWidths, headers, availableWidth, fixedWidth = 82) {
  const orderedHeaders = Array.isArray(headers) ? headers : Object.keys(preferredWidths || {});
  const target = Math.max(0, Math.floor(Number(availableWidth) || 0) - fixedWidth);
  const result = {};

  for (const header of orderedHeaders) {
    const preferred = Math.max(40, Number(preferredWidths?.[header]) || 0);
    result[header] = Math.min(preferred, PI_RAW_COLUMN_MIN_WIDTHS[header] || 60);
  }

  const minTotal = orderedHeaders.reduce((sum, header) => sum + result[header], 0);
  if (target <= minTotal) return result;

  let remaining = target - minTotal;
  const headroom = orderedHeaders.map((header) => ({
    header,
    amount: Math.max(0, (Number(preferredWidths?.[header]) || result[header]) - result[header]),
  }));
  const totalHeadroom = headroom.reduce((sum, entry) => sum + entry.amount, 0);

  if (totalHeadroom > 0) {
    for (const entry of headroom) {
      if (!entry.amount) continue;
      const addition = Math.min(entry.amount, Math.floor((remaining * entry.amount) / totalHeadroom));
      result[entry.header] += addition;
    }
    remaining = target - orderedHeaders.reduce((sum, header) => sum + result[header], 0);

    // Resolve rounding while respecting preferred widths.
    while (remaining > 0) {
      let changed = false;
      for (const entry of headroom) {
        const preferred = Number(preferredWidths?.[entry.header]) || result[entry.header];
        if (remaining > 0 && result[entry.header] < preferred) {
          result[entry.header]++;
          remaining--;
          changed = true;
        }
      }
      if (!changed) break;
    }
  }

  // Extra room belongs to the two fields analysts read most.
  if (remaining > 0) {
    const commandExtra = Math.ceil(remaining * 0.6);
    result["Command Line"] = (result["Command Line"] || 0) + commandExtra;
    result.Process = (result.Process || 0) + remaining - commandExtra;
  }

  return result;
}
