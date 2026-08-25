const activeSubscriptions = new Map();

export function replaceIpcSubscription(key, subscribe, cb) {
  clearIpcSubscription(key);
  const unsub = subscribe?.(cb);
  if (typeof unsub === "function") activeSubscriptions.set(key, unsub);
  return unsub;
}

export function clearIpcSubscription(key) {
  const unsub = activeSubscriptions.get(key);
  if (!unsub) return;
  activeSubscriptions.delete(key);
  try { unsub(); } catch {}
}
