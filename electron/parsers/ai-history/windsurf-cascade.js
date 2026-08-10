/**
 * windsurf-cascade.js — detect Windsurf Cascade protobuf (.pb) artifacts (metadata only).
 */

const fs = require("fs");
const path = require("path");

const { TOOL_WINDSURF } = require("./schema");
const { formatTimestampUtc, makeRow } = require("./row-utils");

const CASCADE_PB_RE = /\.pb$/i;

function listCascadePbFiles(userDir, opts = {}) {
  const maxDepth = opts.maxDepth ?? 14;
  const maxFiles = opts.maxFiles ?? 48;
  const hits = [];
  if (!userDir || !fs.existsSync(userDir)) return hits;

  const stack = [{ d: userDir, depth: 0 }];
  while (stack.length && hits.length < maxFiles) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth && !e.isSymbolicLink()) stack.push({ d: full, depth: depth + 1 });
        continue;
      }
      if (!e.isFile()) continue;
      if (!CASCADE_PB_RE.test(e.name)) continue;
      if (!/cascade/i.test(full)) continue;
      let mtime = "";
      let sizeBytes = 0;
      try {
        const st = fs.statSync(full);
        mtime = formatTimestampUtc(st.mtimeMs);
        sizeBytes = st.size;
      } catch { /* ignore */ }
      hits.push({ path: full, mtime, sizeBytes });
    }
  }
  return hits;
}

/**
 * @returns {{ rows: object[], stats: { pbCount: number, sample: string[] }|null }}
 */
function supplementWindsurfCascadePb(userDir, attribution = {}, options = {}) {
  const hits = listCascadePbFiles(userDir, options);
  if (!hits.length) return { rows: [], stats: null };

  const rows = hits.map((h) => makeRow({
    timestamp: h.mtime || "",
    role: "system",
    recordType: "cascade_pb",
    summary: `Windsurf Cascade artifact: ${path.basename(h.path)} (${h.sizeBytes} bytes, protobuf not decoded)`,
    sessionId: "",
    messageId: "",
    parentId: "",
    workspace: path.dirname(h.path),
    toolName: "",
    sourceFile: h.path,
    user: attribution.user || "",
    host: attribution.host || "",
    description: "Cascade .pb chat bundles are detected but not parsed (schema proprietary)",
  }, TOOL_WINDSURF));

  return {
    rows,
    stats: {
      pbCount: hits.length,
      sample: hits.slice(0, 5).map((h) => h.path),
    },
  };
}

function buildWindsurfCascadeNotice(stats) {
  if (!stats?.pbCount) return "";
  return `Windsurf: ${stats.pbCount} Cascade .pb file(s) on disk (protobuf bodies not decoded — use transcripts/state.vscdb rows when present).`;
}

module.exports = {
  listCascadePbFiles,
  supplementWindsurfCascadePb,
  buildWindsurfCascadeNotice,
};
