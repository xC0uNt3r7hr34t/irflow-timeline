/**
 * browser-agents.js — detect browser profiles that may hold web-only AI usage (hints only).
 */

const fs = require("fs");
const path = require("path");

const BROWSER_AI_HINTS = [
  {
    id: "chrome-claude",
    label: "Google Chrome — Claude extension / web app",
    pathSuffixes: [
      "Google/Chrome/Default/Local Extension Settings",
      "Google/Chrome/Profile 1/Local Extension Settings",
      "Google/Chrome/Default/IndexedDB",
    ],
    keywords: ["claude", "anthropic"],
  },
  {
    id: "edge-copilot",
    label: "Microsoft Edge — Copilot / Bing Chat",
    pathSuffixes: [
      "Microsoft/Edge/Default/IndexedDB",
      "Microsoft/Edge/Default/Local Storage",
    ],
    keywords: ["copilot", "bing", "edge copilot"],
  },
  {
    id: "firefox-ai",
    label: "Firefox — web AI storage",
    pathSuffixes: [
      "Mozilla/Firefox/Profiles",
    ],
    keywords: ["openai", "chatgpt", "claude", "gemini"],
  },
  {
    id: "safari-ai",
    label: "Safari — web AI (macOS triage)",
    pathSuffixes: [
      "Library/Safari/LocalStorage",
      "Library/Containers/com.apple.Safari/Data/Library",
    ],
    keywords: ["openai", "chatgpt", "claude"],
  },
];

function pathHasKeyword(full, keywords) {
  const lower = full.toLowerCase();
  return keywords.some((k) => lower.includes(k));
}

/**
 * Record browser AI hint paths during a directory walk (shared with scanAiArtifacts).
 * @param {string} full — absolute directory path
 * @param {string} relNorm — path relative to scan root, forward slashes
 * @param {number} depth
 * @param {{ id: string, label: string, path: string }[]} hits
 * @param {Set<string>} seen
 * @param {number} maxHits
 */
function collectBrowserHintAtDir(full, relNorm, depth, hits, seen, maxHits) {
  if (hits.length >= maxHits) return;
  for (const hint of BROWSER_AI_HINTS) {
    if (hits.length >= maxHits) break;
    const suffixMatch = hint.pathSuffixes.some((s) => relNorm.includes(s.replace(/\\/g, "/")));
    if (!suffixMatch && depth > 4) continue;
    if (suffixMatch || pathHasKeyword(full, hint.keywords)) {
      const key = `${hint.id}:${full}`;
      if (!seen.has(key)) {
        seen.add(key);
        hits.push({ id: hint.id, label: hint.label, path: full });
      }
    }
  }
}

/**
 * Shallow scan under a collection for browser paths that might contain web-only AI artifacts.
 * @returns {{ id: string, label: string, path: string }[]}
 */
function scanBrowserAgentHints(scanRoot, opts = {}) {
  const { scanAiArtifacts } = require("../ai-artifacts");
  const scan = scanAiArtifacts(scanRoot, {
    maxDepth: opts.maxDepth ?? 12,
    maxPerKind: 1,
    collectBrowserHints: true,
    maxBrowserHits: opts.maxHits ?? 24,
  });
  return scan.browserAgentHints || [];
}

function buildBrowserAgentReportLines(hits) {
  if (!hits?.length) return [];
  const lines = [
    "Browser-side AI usage may not appear in desktop/CLI stores:",
  ];
  for (const h of hits.slice(0, 8)) {
    lines.push(`  • ${h.label}: ${h.path}`);
  }
  if (hits.length > 8) lines.push(`  • …and ${hits.length - 8} more path(s)`);
  lines.push("Collect browser profiles separately or export chat history from the vendor web UI.");
  return lines;
}

module.exports = {
  BROWSER_AI_HINTS,
  collectBrowserHintAtDir,
  scanBrowserAgentHints,
  buildBrowserAgentReportLines,
};
