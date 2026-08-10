module.exports = function registerJobHandlers(safeHandle, safeSend, { jobManager }) {
  safeHandle("jobs-list", () => {
    return jobManager ? jobManager.list() : [];
  });

  safeHandle("jobs-cancel", (event, { jobId }) => {
    if (!jobManager) return { ok: false, error: "Job manager unavailable" };
    return jobManager.cancel(jobId);
  });
};
