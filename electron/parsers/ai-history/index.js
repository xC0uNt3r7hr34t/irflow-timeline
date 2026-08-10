/**
 * parsers/ai-history — AI assistant query history extraction (IRFlow-native).
 */

const {
  AI_HISTORY_COLUMNS,
  SUMMARY_MAX_LEN,
  TOOL_CLAUDE_CODE,
  TOOL_CHATGPT,
  TOOL_GEMINI_CLI,
  TOOL_CODEX,
  TOOL_GROK_BUILD,
  TOOL_CURSOR,
  TOOL_COPILOT,
  AI_HISTORY_TOOLS,
} = require("./schema");
const rowUtils = require("./row-utils");
const claudeCode = require("./claude-code");
const chatgpt = require("./chatgpt");
const geminiCli = require("./gemini-cli");
const codex = require("./codex");
const grokBuild = require("./grok-build");
const cursor = require("./cursor");
const copilot = require("./copilot");
const windsurf = require("./windsurf");
const continueCli = require("./continue");

const EXTRACTORS = {
  "claude-code": claudeCode.extractClaudeCodePath,
  chatgpt: chatgpt.extractChatgptPath,
  "gemini-cli": geminiCli.extractGeminiCliPath,
  codex: codex.extractCodexPath,
  "grok-build": grokBuild.extractGrokBuildPath,
  cursor: cursor.extractCursorPath,
  copilot: copilot.extractCopilotPath,
  windsurf: windsurf.extractWindsurfPath,
  continue: continueCli.extractContinuePath,
};

async function extractAiHistory(tool, targetPath, attribution = {}, options = {}) {
  const fn = EXTRACTORS[tool];
  if (!fn) throw new Error(`Unknown AI history tool: ${tool}`);
  return fn(targetPath, attribution, options);
}

module.exports = {
  AI_HISTORY_COLUMNS,
  SUMMARY_MAX_LEN,
  TOOL_CLAUDE_CODE,
  TOOL_CHATGPT,
  TOOL_GEMINI_CLI,
  TOOL_CODEX,
  TOOL_GROK_BUILD,
  TOOL_CURSOR,
  TOOL_COPILOT,
  AI_HISTORY_TOOLS,
  extractAiHistory,
  ...rowUtils,
  ...claudeCode,
  ...chatgpt,
  ...geminiCli,
  ...codex,
  ...grokBuild,
  ...cursor,
  ...copilot,
  ...windsurf,
  ...continueCli,
};
