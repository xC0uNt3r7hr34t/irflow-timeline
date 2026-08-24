---
description: Grok Build (Grok AI) forensic artifacts — session transcripts, tool commands, search index, app log, and stores that outlive a deleted conversation.
---

# Grok AI

[Grok Build](https://github.com/xai-org/grok-build) is the terminal coding agent distributed as the `grok` CLI. Its default data root is `~/.grok` (`GROK_HOME` can override it). IRFlow parses workspace prompt history, session transcripts, file-hunk records, and three stores that sit **outside** the session tree.

The consumer Grok product (`grok.com` / X) is separate — there is no native parser for web or mobile chats. Collect browser origin data or a vendor export.

Back to [AI Query History](/dfir-tips/ai-query-history).

## Canonical paths

| Platform | Path |
|----------|------|
| all | `$GROK_HOME` or `~/.grok/` — `sessions/`, plus `sessions/session_search.sqlite`, `logs/unified.jsonl`, `active_sessions.json` |

The upstream [authentication guide](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md) documents `~/.grok/auth.json` and `~/.grok/mcp_credentials.json`. Treat both as credential-bearing evidence. IRFlow **never** copies those values into timeline rows.

## Session artifacts

| Artifact | Forensic value |
|----------|----------------|
| `sessions/<encoded-cwd>/prompt_history.jsonl` | Timestamp, session ID, prompt, and `is_bash`; direct bash entries populate **ToolCommand** exactly. |
| `<session-id>/summary.json` | Session ID/title, created/updated time, cwd, model, Git branch/commit, agent mode, sandbox profile, reasoning effort. |
| `<session-id>/updates.jsonl` | Timestamped user/assistant/reasoning chunks, tool calls (`rawInput`), completion output (`rawOutput`), stop reason, token usage. |
| `<session-id>/chat_history.jsonl` | Normalized conversation fallback when timestamped updates are absent. |
| `<session-id>/hunk_records.jsonl` | File path, added/removed lines, prompt index, hunk ID, author, event timestamp. |
| `<session-id>/terminal/call-*.log` | Captured output for terminal commands; the related updates record can reference the log through `output_file`. |
| `<session-id>/events.jsonl`, `signals.json`, `prompt_context.json` | Lifecycle, performance, environment, and context — preserve even when not every record becomes a timeline row. |
| `trusted_folders.toml`, `slash-mru.json`, `version.json`, `agent_id` | Trust decisions, recent slash-command state, installed version, installation identity. |

For a `run_terminal_command` event, IRFlow places the exact recorded `rawInput.command` in **ToolCommand**, retains structured input in **ToolInput**, and creates a related `tool_result` row with cwd, exit code, timeout/truncation flags, captured output, and terminal-log path. Failed calls use `tool_result_failed`.

## Stores that outlive the conversation {#runtime-stores-outside-the-session-tree}

Three stores live outside `sessions/<encoded-cwd>/<session-id>/` and are written independently of it. Deleting a session directory does not delete them.

| Artifact | What it gives you |
|----------|-------------------|
| `sessions/session_search.sqlite` | `session_docs` holds `session_id`, `cwd`, `title`, `updated_at` (epoch **seconds**) and the indexed transcript body, with an FTS5 index over it. It **mirrors the transcript and survives deleting the session directory**. **RecordType** = `session_search`. `last_indexed_offset` well below the body length means a partial view. |
| `logs/unified.jsonl` | `shell.tool.exec_done` records give tool name, success/failure, and duration per `sid`; turn boundaries bracket model calls. There is **no command string** here — that only lives in the session’s `updates.jsonl`. **RecordType** = `log_tool_exec`. Correlate `MessageId` (the tool call id) back to `updates.jsonl`. |
| `active_sessions.json` | `session_id` → `pid`, `cwd`, `opened_at` for sessions open at acquisition. |

::: warning `memtrace/` is not what the name suggests
`~/.grok/memtrace/*.jsonl` looks like agent memory and is not. Every record is a **memory profiler** sample (`rss_bytes`, `alloc`) — tens of megabytes with no conversation content. IRFlow does not parse it. Process-lifetime value is already covered by `active_sessions.json` and the unified log.
:::

## How to import

1. **File → Open…** and select `$GROK_HOME` or `~/.grok`, or **Tools → Analysis → AI Artifacts → AI Apps → Grok Build…**
2. IRFlow imports workspace prompt histories and session `summary.json`, `updates.jsonl` (or `chat_history.jsonl` fallback), and `hunk_records.jsonl`, plus the three out-of-tree stores above.
3. Subagent session folders are skipped by default unless you choose **Include subagents**.

**Collect AI Artifacts** also finds Grok roots on This Mac or inside a KAPE/triage folder.

## Limitations

- Consumer Grok web/mobile chats are not decoded as a native app store. Collect browser history/cache for `grok.com` or X/Grok separately — do not attribute a generic browser profile to Grok without origin-level evidence.
- `auth.json`, `mcp_credentials.json`, `config.toml`, and `trusted_folders.toml` are deliberately not parsed. Preserve them under evidence controls when authorization material is in scope.
- `events.jsonl`, `signals.json`, and `prompt_context.json` remain preservation targets even when the first parser slice does not project every record.
- `session_search.sqlite` requires SQLite support.
- `log_tool_exec` records *that* a tool ran, never the command. Do not present them as evidence of what was executed.
- `memtrace/` is a profiler trace and is deliberately not parsed.

## See also

- [AI Query History overview](/dfir-tips/ai-query-history)
- [Claude Desktop](/dfir-tips/ai-apps/claude-desktop)
- [AI Artifacts](/features/ai-artifacts)
