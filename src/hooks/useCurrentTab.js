import useTabStore from "../store/useTabStore.js";

/**
 * Returns the current tab object (reactive — re-renders when tabs or activeTab change).
 * Equivalent to the old `const ct = tabs.find(t => t.id === activeTab)`.
 */
export default function useCurrentTab() {
  const tabs = useTabStore((s) => s.tabs);
  const activeTab = useTabStore((s) => s.activeTab);
  return tabs.find((t) => t.id === activeTab) || null;
}
