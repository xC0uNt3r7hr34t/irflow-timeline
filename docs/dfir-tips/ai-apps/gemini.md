---
description: Gemini CLI forensic artifacts — JSONL chats, shell history, checkpoints, nested subagents, and what IRFlow does not parse.
---

# Gemini

IRFlow parses the **Gemini CLI** (the npm/agentic CLI), not the official Gemini macOS desktop app. Desktop history is mostly cloud-synced and is not decoded.

Back to [AI Query History](/dfir-tips/ai-query-history).

## Canonical paths

| Platform | Path |
|----------|------|
| macOS / Linux | `~/.gemini/tmp/<project_hash>/chats/**/*.jsonl`, `~/.gemini/shell_history` |
| Windows | `C:\Users\<user>\.gemini\tmp\<hash>\chats\**\*.jsonl`, `C:\Users\<user>\.gemini\shell_history` |

Also parsed when present: legacy `session-*.json`, `logs.json`, and checkpoints under `~/.gemini`.

## What IRFlow extracts

| Artifact | Status | Why it matters |
|----------|--------|----------------|
| `~/.gemini/tmp/<hash>/chats/**/*.jsonl` | Parsed | Current append-only sessions, including nested subagent chats. |
| `~/.gemini/shell_history` | Parsed | Exact shell-history entries, including continued multiline commands. |
| Legacy `session-*.json`, checkpoints, `logs.json` | Parsed | Older Gemini CLI layouts. |

Current sessions are append-only JSONL. IRFlow replays message records, `$set` checkpoints, and `$rewindTo` operations to reconstruct the retained session state. It emits separate tool-call and tool-result rows, preserves the exact `run_shell_command` command in **ToolCommand**, and marks nested chat directories as subagent evidence.

## How to import

1. **File → Open…** and select the `.gemini` folder, or **Tools → Analysis → AI Artifacts → AI Apps → Gemini CLI…**
2. Current `chats/**/*.jsonl`, `shell_history`, and legacy JSON artifacts from the same `.gemini` tree consolidate into **one** tab.

**Collect AI Artifacts** also finds Gemini CLI roots on This Mac or inside a KAPE/triage folder.

## Investigation tips

- **ToolCommand** holds the exact `run_shell_command` string — treat it as evidence, the same as a shell history hit.
- Nested chat directories are subagent evidence. Start with main sessions on a large project tree.
- `$rewindTo` / `$set` mean the retained session is not a simple append-only log. IRFlow replays those markers so the grid reflects what the CLI still had, not every line that was ever written.

## Limitations

- Official **Gemini macOS desktop** app history is not parsed.
- Browser-only Gemini usage is hint-only; collect the browser profile separately.

## See also

- [AI Query History overview](/dfir-tips/ai-query-history)
- [Cursor](/dfir-tips/ai-apps/cursor)
- [AI Artifacts](/features/ai-artifacts)
