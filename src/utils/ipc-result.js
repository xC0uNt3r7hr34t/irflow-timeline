// Helpers for handling IPC results from the main process uniformly.
//
// `safeHandle` (electron/main.js) wraps a thrown handler error as
//   { __ipcError: true, message }
// and analyzers return domain failures as { error: "..." }. Critically, a worker
// crash / OOM on a 30–50GB file RESOLVES the invoke() with an __ipcError object — it is
// NOT a promise rejection — so a `.then` that stores the result as success `data` will
// render an empty/garbage panel and swallow the message. Route every analysis result
// through these helpers so both failure shapes surface as a real error.

export function isIpcError(result) {
  if (!result || typeof result !== "object") return false;
  if (result.__ipcError) return true;
  return typeof result.error === "string" && result.error.length > 0;
}

export function ipcErrorMessage(result, fallback = "Analysis failed") {
  if (!result || typeof result !== "object") return fallback;
  const msg = result.message || result.error;
  return msg ? String(msg) : fallback;
}

export function isIpcCancelled(result) {
  if (!isIpcError(result)) return false;
  return /cancelled|canceled/i.test(ipcErrorMessage(result, ""));
}
