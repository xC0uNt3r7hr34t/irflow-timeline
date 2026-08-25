import { create } from "zustand";

/**
 * Global confirmation dialog state. Replaces the OS-native window.confirm()
 * calls that bypass the theme entirely.
 *
 * Usage from anywhere (drop-in replacement for window.confirm):
 *
 *   import { confirm } from "../store/useConfirmStore.js";
 *   const ok = await confirm({ title, message, destructive: true });
 *   if (ok) { ... }
 *
 * The <ConfirmDialog /> primitive must be mounted once at the app root for
 * this to work — see App.jsx where it's rendered alongside the modal portals.
 */
const useConfirmStore = create((set, get) => ({
  // null when no dialog is open; otherwise the active prompt's options + resolver
  prompt: null,

  open: ({ title, message, confirmLabel = "Confirm", cancelLabel = "Cancel", destructive = false } = {}) =>
    new Promise((resolve) => {
      set({
        prompt: { title, message, confirmLabel, cancelLabel, destructive, resolve },
      });
    }),

  resolve: (result) => {
    const p = get().prompt;
    if (p) {
      p.resolve(result);
      set({ prompt: null });
    }
  },
}));

export default useConfirmStore;

// Convenience function — `await confirm({...})` returns true if user confirmed.
export const confirm = (opts) => useConfirmStore.getState().open(opts);
