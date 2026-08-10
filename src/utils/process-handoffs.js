// Cross-feature handoffs from Process Inspector → LM / Persistence / Sigma / grid.
// Pure builders: tab filter patches + modal open payloads. No React / IPC.

import {
  buildProcessGridPivot,
  detectHostnameColumn,
  detectTimestampColumn,
  formatPivotTimestamp,
  resolveProcessPivotMs,
} from "./process-grid-pivot.js";
import { normalizeGuid, processIdentityFromNode } from "./process-identity.js";
import {
  buildLateralMovementCols,
  buildPersistenceMode,
} from "./analyzer-launch.js";
import {
  openLateralMovementModal,
  openPersistenceModal,
  openSigmaModal,
} from "../modals/modalRegistry.js";

const DEFAULT_WINDOW_MINUTES = 30;

/**
 * Time-window + host scope suitable for LM / Persistence / Sigma handoffs.
 * Unlike the grid pivot, we do NOT pin to a single ProcessGuid — those features
 * need ambient telemetry (logons, registry, other EIDs) in the same window.
 */
export const buildProcessContextWindow = (node, columns = {}, headers = [], opts = {}) => {
  const windowMinutes = Math.max(1, Number(opts.windowMinutes) || DEFAULT_WINDOW_MINUTES);
  const notes = [];
  if (!node) {
    return { ok: false, error: "No process selected", tabPatch: null, notes, windowMinutes };
  }

  const tsCol = detectTimestampColumn(columns, headers);
  const hostCol = detectHostnameColumn(columns, headers);
  const host = String(node.hostname || node.normHost || "").trim();
  const pivotMs = resolveProcessPivotMs(node);
  const dateRangeFilters = {};
  const advancedFilters = [];

  if (tsCol && Number.isFinite(pivotMs)) {
    const windowMs = windowMinutes * 60 * 1000;
    dateRangeFilters[tsCol] = {
      from: formatPivotTimestamp(pivotMs - windowMs),
      to: formatPivotTimestamp(pivotMs + windowMs),
    };
  } else if (!tsCol) {
    notes.push("No timestamp column — handoff without time window");
  } else {
    notes.push("Unparseable process timestamp — handoff without time window");
  }

  if (host && hostCol) {
    advancedFilters.push({
      column: hostCol,
      operator: "contains",
      value: host,
      logic: "AND",
    });
  } else if (host) {
    notes.push("Hostname present but no host column mapped — time window only");
  }

  const procLabel = node.processName || "process";
  const label = `PI handoff: ${procLabel}${host ? ` @ ${host}` : ""}${Object.keys(dateRangeFilters).length ? ` ±${windowMinutes}m` : ""}`;

  return {
    ok: true,
    label,
    windowMinutes,
    notes,
    host,
    pivotMs: Number.isFinite(pivotMs) ? pivotMs : null,
    tsCol: tsCol || null,
    tabPatch: {
      searchTerm: "",
      searchHighlight: false,
      columnFilters: {},
      checkboxFilters: {},
      advancedFilters,
      dateRangeFilters,
      rowIdFilter: null,
      rowIdFilterLabel: null,
      showBookmarkedOnly: false,
      tagFilter: null,
      groupByColumns: [],
      groupData: [],
      expandedGroups: {},
    },
  };
};

/**
 * Build a full handoff package for a target feature.
 * @param {"lateral"|"persistence"|"sigma"|"grid"} target
 */
export const buildProcessHandoff = (node, columns = {}, headers = [], target, opts = {}) => {
  if (target === "grid") {
    const pivot = buildProcessGridPivot(node, columns, headers, {
      windowMinutes: opts.windowMinutes || 15,
      includeChildren: opts.includeChildren !== false,
    });
    return {
      ok: pivot.ok,
      error: pivot.error,
      label: pivot.label,
      notes: pivot.notes || [],
      tabPatch: pivot.tabPatch,
      modal: null,
      proximity: pivot.hasTimeWindow && pivot.tabPatch
        ? {
            tsCol: Object.keys(pivot.tabPatch.dateRangeFilters || {})[0],
            pivotRaw: node?.ts || "",
            windowMs: (pivot.windowMinutes || 15) * 60 * 1000,
            label: `${pivot.windowMinutes || 15}m`,
          }
        : null,
      focusRowId: node?.rowid || null,
      strategy: pivot.strategy,
    };
  }

  const ctx = buildProcessContextWindow(node, columns, headers, {
    windowMinutes: opts.windowMinutes || DEFAULT_WINDOW_MINUTES,
  });
  if (!ctx.ok) {
    return { ok: false, error: ctx.error, tabPatch: null, modal: null, notes: ctx.notes };
  }

  let modal = null;
  const identity = processIdentityFromNode(node);
  if (target === "lateral") {
    const { cols, chainsawSyntheticTarget } = buildLateralMovementCols(headers);
    modal = openLateralMovementModal(cols, {
      chainsawSyntheticTarget,
      _lmAutoRun: opts.autoRun !== false,
      _piHandoff: {
        host: identity.hostname || ctx.host,
        user: identity.user || node.user || "",
        processName: identity.processName || node.processName || "",
        ts: identity.ts || node.ts || "",
        entityKey: identity.entityKey,
        windowMinutes: ctx.windowMinutes,
      },
    });
  } else if (target === "persistence") {
    modal = openPersistenceModal({
      mode: buildPersistenceMode(headers),
      _paAutoRun: opts.autoRun !== false,
      _piHandoff: {
        host: identity.hostname || ctx.host,
        processName: identity.processName || node.processName || "",
        image: identity.image || node.image || "",
        ts: identity.ts || node.ts || "",
        entityKey: identity.entityKey,
        windowMinutes: ctx.windowMinutes,
      },
    });
  } else if (target === "sigma") {
    const hash = opts.hash || "";
    modal = openSigmaModal({
      scanMode: "tab",
      _piHandoff: {
        host: identity.hostname || ctx.host,
        processName: identity.processName || node.processName || "",
        image: identity.image || node.image || "",
        hash,
        ts: identity.ts || node.ts || "",
        windowMinutes: ctx.windowMinutes,
        guid: identity.guid || normalizeGuid(node.guid) || "",
        entityKey: identity.entityKey,
      },
    });
  } else {
    return { ok: false, error: `Unknown handoff target: ${target}`, tabPatch: null, modal: null, notes: [] };
  }

  return {
    ok: true,
    label: ctx.label,
    notes: ctx.notes,
    tabPatch: ctx.tabPatch,
    modal,
    proximity: ctx.tsCol && ctx.pivotMs != null
      ? {
          tsCol: ctx.tsCol,
          pivotRaw: node.ts || "",
          windowMs: ctx.windowMinutes * 60 * 1000,
          label: `${ctx.windowMinutes}m`,
        }
      : null,
    focusRowId: null,
    windowMinutes: ctx.windowMinutes,
  };
};

/** Map a hex hash string to the VT IOC category used by vtLookupSingle. */
export const vtCategoryForHash = (hash) => {
  const h = String(hash || "").trim();
  if (/^[a-fA-F0-9]{64}$/.test(h)) return "SHA256_Hash";
  if (/^[a-fA-F0-9]{40}$/.test(h)) return "SHA1_Hash";
  if (/^[a-fA-F0-9]{32}$/.test(h)) return "MD5_Hash";
  return null;
};

export const publicVtUrlForHash = (hash) =>
  `https://www.virustotal.com/gui/file/${String(hash || "").trim()}`;
