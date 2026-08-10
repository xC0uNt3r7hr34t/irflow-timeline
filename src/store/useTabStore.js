import { create } from "zustand";

/**
 * useTabStore — Tab management and per-tab state.
 *
 * Design: `setTabs` accepts both direct values and updater functions,
 * matching React's useState API. This allows incremental migration —
 * existing `setTabs(prev => prev.map(...))` calls work unchanged.
 *
 * Convenience actions (addTab, removeTab, updateTab, updateActiveTab)
 * are provided for new code that wants cleaner semantics.
 */
const useTabStore = create((set, get) => ({
  // ── Core tab state ───────────────────────────────────────────────
  tabs: [],
  activeTab: null,
  tabFilter: "",

  // ── Import tracking ──────────────────────────────────────────────
  importingTabs: {},    // { tabId: { fileName, progress, ... } }
  importQueue: [],      // [{ fileName, fileSize }]

  // ── useState-compatible setter ───────────────────────────────────
  // Accepts a value OR an updater function: setTabs(newTabs) or setTabs(prev => ...)
  setTabs: (valueOrUpdater) => set((state) => ({
    tabs: typeof valueOrUpdater === "function"
      ? valueOrUpdater(state.tabs)
      : valueOrUpdater,
  })),

  setActiveTab: (v) => set({ activeTab: v }),
  setTabFilter: (v) => set({ tabFilter: v }),
  setImportingTabs: (v) => set(typeof v === "function" ? (s) => ({ importingTabs: v(s.importingTabs) }) : { importingTabs: v }),
  setImportQueue: (v) => set(typeof v === "function" ? (s) => ({ importQueue: v(s.importQueue) }) : { importQueue: v }),

  // ── Convenience actions for new code ─────────────────────────────

  /** Add a new tab to the list */
  addTab: (tab) => set((state) => ({
    tabs: [...state.tabs, tab],
  })),

  /** Remove a tab by ID */
  removeTab: (tabId) => set((state) => ({
    tabs: state.tabs.filter((t) => t.id !== tabId),
    // If the removed tab was active, switch to the nearest remaining tab
    activeTab: state.activeTab === tabId
      ? (state.tabs[state.tabs.findIndex((t) => t.id === tabId) - 1]?.id
         || state.tabs[state.tabs.findIndex((t) => t.id === tabId) + 1]?.id
         || null)
      : state.activeTab,
  })),

  /** Update a specific tab by ID with a partial object */
  updateTab: (tabId, partial) => set((state) => ({
    tabs: state.tabs.map((t) => (t.id === tabId ? { ...t, ...partial } : t)),
  })),

  /** Update the currently active tab with a partial object */
  updateActiveTab: (partial) => {
    const { activeTab } = get();
    if (!activeTab) return;
    set((state) => ({
      tabs: state.tabs.map((t) => (t.id === activeTab ? { ...t, ...partial } : t)),
    }));
  },

  /** Get current tab (derived — call inside component or selector) */
  getCurrentTab: () => {
    const { tabs, activeTab } = get();
    return tabs.find((t) => t.id === activeTab) || null;
  },

  /** Update a single field on the active tab: up("sortCol", "TimeCreated") */
  up: (key, value) => {
    const { activeTab } = get();
    if (!activeTab) return;
    set((state) => ({
      tabs: state.tabs.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)),
    }));
  },
}));

export default useTabStore;
