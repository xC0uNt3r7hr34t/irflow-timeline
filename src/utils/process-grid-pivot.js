// Build a main-grid filter pivot from a Process Inspector node.
//
// Goal: one click from a process should show all timeline rows related to that
// process identity around its create time — not just the single create event.
//
// Strategy (best available evidence first):
//   1. ProcessGuid (+ ParentProcessGuid for children) when a GUID column exists
//   2. Else PID (+ PPID for children) scoped by hostname when available
//   3. Always pair identity filters with a ±N minute time window when a
//      timestamp column and parseable timestamp exist
//
// Pure: no DOM, no store, no Electron APIs. Callers apply the returned tab patch.

import { normalizeGuid, normalizePid, normalizeTimestamp } from "./forensic-normalize.js";

export const PI_GRID_PIVOT_WINDOWS = [
  { minutes: 5, label: "±5m" },
  { minutes: 15, label: "±15m" },
  { minutes: 60, label: "±1h" },
  { minutes: 360, label: "±6h" },
];

const _detectHeader = (headers, patterns) => {
  if (!Array.isArray(headers)) return null;
  for (const pat of patterns) {
    const found = headers.find((h) => pat.test(h));
    if (found) return found;
  }
  return null;
};

export const detectTimestampColumn = (columns = {}, headers = []) =>
  columns.ts
  || _detectHeader(headers, [/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, /^Timestamp$/i, /^system_time$/i]);

export const detectHostnameColumn = (columns = {}, headers = []) =>
  columns.hostname
  || _detectHeader(headers, [/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i, /^computer_name$/i]);

/** Format epoch-ms as the app's canonical naive UTC display form. */
export const formatPivotTimestamp = (ms) => {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
};

/**
 * Resolve the process create timestamp to epoch ms.
 * Prefers the analyzer's canonical tsMs; falls back to normalizeTimestamp(ts).
 */
export const resolveProcessPivotMs = (node) => {
  if (!node) return NaN;
  if (Number.isFinite(node.tsMs)) return node.tsMs;
  return normalizeTimestamp(node.ts || "");
};

/**
 * Build advanced-filter identity clauses for a process node.
 *
 * Advanced-filter SQL groups as: (A AND B) OR (C AND D) when OR appears between
 * clauses. We use that to emit:
 *   (identityMatch AND host?) OR (childMatch AND host?)
 * so host scope never accidentally attaches to only one branch.
 *
 * Returns { filters, strategy, identityValue, notes }.
 */
export const buildProcessIdentityFilters = (node, columns = {}, headers = [], opts = {}) => {
  const includeChildren = opts.includeChildren !== false;
  const filters = [];
  const notes = [];
  if (!node) return { filters, strategy: "none", identityValue: "", notes: ["No process selected"] };

  const bareGuid = normalizeGuid(node.guid);
  const pid = normalizePid(node.pid);
  const host = String(node.hostname || node.normHost || "").trim();
  const guidCol = columns.guid || null;
  const parentGuidCol = columns.parentGuid || null;
  const pidCol = columns.pid || null;
  const ppidCol = columns.ppid || null;
  const hostCol = detectHostnameColumn(columns, headers);

  const pushBranch = (column, operator, value, { or = false } = {}) => {
    filters.push({
      column,
      operator,
      value,
      logic: or ? "OR" : "AND",
    });
    if (host && hostCol) {
      filters.push({
        column: hostCol,
        operator: "contains",
        value: host,
        logic: "AND",
      });
    }
  };

  // GUID path — preferred (survives PID reuse).
  // EvtxECmd/Hayabusa often store GUID inside a payload/details blob; `contains`
  // matches brace-wrapped and bare forms. When parentGuid shares the same column
  // as guid (common in compact formats), a single contains clause covers both
  // the process create and its children's parent reference.
  if (bareGuid && guidCol) {
    pushBranch(guidCol, "contains", bareGuid, { or: false });
    if (includeChildren && parentGuidCol && parentGuidCol !== guidCol) {
      pushBranch(parentGuidCol, "contains", bareGuid, { or: true });
    }
    return {
      filters,
      strategy: includeChildren && parentGuidCol && parentGuidCol !== guidCol ? "guid+children" : "guid",
      identityValue: bareGuid,
      notes,
    };
  }

  // PID fallback — match decimal and hex forms (Security 4688 often stores 0xPID).
  if (pid && pidCol) {
    const pidForms = [String(pid)];
    const asNum = Number.parseInt(pid, 10);
    if (Number.isFinite(asNum) && asNum >= 0) {
      const hex = `0x${asNum.toString(16)}`;
      if (!pidForms.includes(hex)) pidForms.push(hex);
    }
    let first = true;
    for (const form of pidForms) {
      pushBranch(pidCol, "contains", form, { or: !first });
      first = false;
    }
    if (includeChildren && ppidCol && ppidCol !== pidCol) {
      for (const form of pidForms) {
        pushBranch(ppidCol, "contains", form, { or: true });
      }
    }
    if (!host) notes.push("No hostname — PID filter may match other hosts");
    return {
      filters,
      strategy: includeChildren && ppidCol && ppidCol !== pidCol ? "pid+children" : "pid",
      identityValue: String(pid),
      notes,
    };
  }

  // Last resort: process name (noisy — still better than nothing).
  const name = String(node.processName || "").trim();
  const imageCol = columns.image || _detectHeader(headers, [/^Image$/i, /^NewProcessName$/i, /^process_name$/i, /^ExecutableInfo$/i]);
  if (name && imageCol) {
    pushBranch(imageCol, "contains", name, { or: false });
    notes.push("Falling back to process-name filter (no GUID/PID column mapping)");
    return { filters, strategy: "name", identityValue: name, notes };
  }

  return { filters, strategy: "none", identityValue: "", notes: ["Cannot map process identity to grid columns"] };
};

/**
 * Build the full tab-state patch that applies a process pivot to the main grid.
 *
 * @param {object} node - process tree node
 * @param {object} columns - PI column map (header names)
 * @param {string[]} headers - tab headers
 * @param {{ windowMinutes?: number, includeChildren?: boolean, closeModal?: boolean }} opts
 * @returns {{ ok: boolean, error?: string, label: string, strategy: string, windowMinutes: number, tabPatch: object, notes: string[] }}
 */
export const buildProcessGridPivot = (node, columns = {}, headers = [], opts = {}) => {
  const windowMinutes = Math.max(1, Number(opts.windowMinutes) || 15);
  const includeChildren = opts.includeChildren !== false;
  const identity = buildProcessIdentityFilters(node, columns, headers, { includeChildren });

  if (!identity.filters.length || identity.strategy === "none") {
    return {
      ok: false,
      error: identity.notes[0] || "Cannot build grid filter for this process",
      label: "",
      strategy: identity.strategy,
      windowMinutes,
      tabPatch: null,
      notes: identity.notes,
    };
  }

  const tsCol = detectTimestampColumn(columns, headers);
  const pivotMs = resolveProcessPivotMs(node);
  const dateRangeFilters = {};
  const notes = [...identity.notes];

  if (tsCol && Number.isFinite(pivotMs)) {
    const windowMs = windowMinutes * 60 * 1000;
    dateRangeFilters[tsCol] = {
      from: formatPivotTimestamp(pivotMs - windowMs),
      to: formatPivotTimestamp(pivotMs + windowMs),
    };
  } else if (!tsCol) {
    notes.push("No timestamp column — identity filter applied without time window");
  } else {
    notes.push("Unparseable process timestamp — identity filter applied without time window");
  }

  const procLabel = node.processName || node.image || "process";
  const idShort = identity.identityValue.length > 20
    ? `${identity.identityValue.slice(0, 8)}…${identity.identityValue.slice(-4)}`
    : identity.identityValue;
  const windowLabel = Object.keys(dateRangeFilters).length
    ? ` ±${windowMinutes}m`
    : "";
  const childLabel = /children/.test(identity.strategy) ? " +children" : "";
  const label = `PI: ${procLabel} (${identity.strategy.startsWith("guid") ? "GUID" : identity.strategy.startsWith("pid") ? "PID" : "name"} ${idShort})${childLabel}${windowLabel}`;

  const focusRowId = Number.isInteger(Number(node.rowid)) && Number(node.rowid) > 0
    ? Number(node.rowid)
    : null;

  const tabPatch = {
    // Replace — don't stack on unrelated filters so the pivot is predictable.
    searchTerm: "",
    searchHighlight: false,
    searchMode: "mixed",
    searchCondition: "contains",
    columnFilters: {},
    checkboxFilters: {},
    advancedFilters: identity.filters,
    dateRangeFilters,
    rowIdFilter: null,
    rowIdFilterLabel: null,
    showBookmarkedOnly: false,
    tagFilter: null,
    groupByColumns: [],
    groupData: [],
    expandedGroups: {},
    // App.jsx scrolls to this row once it lands in the filtered window.
    pendingFocusRowId: focusRowId,
  };

  return {
    ok: true,
    label,
    strategy: identity.strategy,
    windowMinutes,
    tabPatch,
    notes,
    identityValue: identity.identityValue,
    hasTimeWindow: Object.keys(dateRangeFilters).length > 0,
    focusRowId,
  };
};
