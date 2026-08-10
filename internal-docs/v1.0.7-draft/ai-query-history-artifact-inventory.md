# AI Query History Artifact Inventory and Data Quality

Prepared for docs and website copy. This is grounded in the current parser implementation, focused parser tests, and a live AI Query History tab containing 142,052 rows.

## Scope

IRFlow currently treats AI assistant evidence in three layers:

| Layer | Meaning |
| --- | --- |
| Parsed AI app history | Message/session rows are extracted into the AI Query History schema. |
| Inventory-only evidence | The artifact is detected and reported, but message bodies are not decoded. |
| Browser hints | Browser profile paths are flagged as likely AI usage locations, but IRFlow does not parse web chat contents from them yet. |

Canonical output columns include `Timestamp`, `Role`, `RecordType`, `Summary`, `FullText`, `InvokedTool`, `SessionId`, `Workspace`, `SourceFile`, `Tool`, `Model`, token counts, user/host attribution, and `Description`.

`Tool` is the AI application or provider family. `InvokedTool` is only the invoked function/tool inside that application. Provider names should not appear in `InvokedTool` on new imports. Older saved tabs can still show the legacy `ToolName` header.

## Data Quality Summary

Validation performed:

| Check | Result |
| --- | --- |
| Provider-valued invoked-tool assignments in parser source | Clean after fixes in ChatGPT encrypted-bundle rows and Windsurf Cascade inventory rows. |
| Syntax check | `chatgpt.js` and `windsurf-cascade.js` pass `node --check`. |
| Focused AI parser tests | 60 tests run, 56 pass, 4 skipped. Skips are SQLite paths because this shell's `better-sqlite3` binary is built for a different Node ABI. |
| Wider AI history test run | 204 tests observed earlier in this pass: 198 passed, 4 skipped, 2 failed due the same `better-sqlite3` ABI mismatch, not parser assertions. |
| Live tab DQ | Required fields are clean for Codex, Claude Code, Cursor, and Gemini CLI. Cursor has expected blank timestamps on some `state.vscdb` rows where the source has no reliable per-message timestamp. |

Current live tab counts:

| Tool | Rows | Source files | Sessions | Workspaces | Missing timestamp | Missing summary | Missing FullText | Raw legacy provider `ToolName` | Real `InvokedTool` rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OpenAI Codex | 97,465 | 84 | 84 | 25 | 0 | 0 | 0 | 74,028 | 23,437 |
| Claude Code | 40,800 | 209 | 208 | 73 | 0 | 0 | 0 | 28,953 | 11,847 |
| Cursor | 3,748 | 13 | 17 | 3 | 799 | 0 | 0 | 1,264 | 2,484 |
| Gemini CLI | 39 | 3 | 3 | 3 | 0 | 0 | 0 | 39 | 0 |

The live SQLite table was imported before the latest `InvokedTool` rename, so raw rows may still contain legacy provider names in `ToolName`. The current query layer masks `ToolName == Tool` values for UI reads, grouping, sorting, filters, and selected column output. Reimporting the AI history tab will emit the clearer `InvokedTool` column.

`Summary` and `FullText` relationship in the live tab:

| Tool | Rows where FullText is longer | Rows where Summary equals FullText | Average Summary length | Average FullText length | Max FullText length |
| --- | ---: | ---: | ---: | ---: | ---: |
| OpenAI Codex | 1,535 | 95,655 | 109.8 | 165.3 | 461,627 |
| Claude Code | 1,293 | 39,101 | 51.2 | 111.9 | 20,453 |
| Cursor | 565 | 2,559 | 152.3 | 989.1 | 198,596 |
| Gemini CLI | 0 | 35 | 83.8 | 83.8 | 458 |

Interpretation: `Summary` and `FullText` often match because many messages are short. This is expected. `FullText` is the investigative field for long prompts, responses, tool output, and secret scanning. `Summary` is the grid preview.

## Application Coverage Matrix

### Claude Code and Claude Desktop

Status: parsed. Current Claude Code and Cowork schemas are supported, including untimed state records. Live Cowork validation produced 52,164 streamed rows; one malformed source JSON record was reported and skipped.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| `~/.claude/history.jsonl` | Parsed | User prompt history, timestamps, session IDs, project hints. | Lightweight prompt log maintained by Claude Code. | Quickly establishes user intent, suspicious questions, data exfiltration prompts, credential pasting, and session pivots. |
| `~/.claude/projects/**/*.jsonl` | Parsed | User/assistant messages, bounded tool inputs/results, media/document descriptors, state/permission/title records, attachments, queue operations, and file-history records. | Main Claude Code transcript store. | Highest-value Claude evidence: prompts, answers, tool names and results, workspace/project paths, model usage, sidechain indicators, token counts, and possible pasted secrets. |
| Claude Desktop `claude-code-sessions/**/local_*.json` | Parsed as metadata and linked to CLI JSONL where available. | Desktop session titles, local IDs, models, cwd/project metadata, and linked transcript rows from `.claude/projects`. | Claude Desktop "Code" session index; transcripts still live under `.claude/projects`. | Proves Desktop usage and helps recover context even when a CLI transcript is missing. Also tells collectors to acquire `.claude/projects`. |
| Claude Desktop/Cowork `local-agent-mode-sessions/` | Recursively parsed. | `local_*.json` metadata, isolated `.claude/projects/**/*.jsonl` transcripts, `audit*.jsonl` audit events, and `.audit-key` presence. | Modern Cowork sessions are self-contained; audit and transcript timestamps may differ and provide independent chronology. | Recovers prompts/tool activity that never appears in host `~/.claude/projects` and preserves audit provenance for future integrity validation. |

Notes:

- History rows are deduped against richer session JSONL rows when both contain the same prompt.
- Subagent/sidechain handling is configurable during profile scans.

### OpenAI Codex

Status: parsed. Live dataset validated with 97,465 rows and no missing timestamp, summary, or FullText values.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| `$CODEX_HOME/history.jsonl` or `~/.codex/history.jsonl` | Parsed | Prompt log with session ID, timestamp, and user text. | Lightweight Codex prompt history. | Fast triage of user requests and starting points for session review. |
| `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` | Parsed | Messages, reasoning summaries, function/custom-tool calls and bounded outputs, patches, web/MCP/tool-search events, image descriptors, subagent activity, compacted context, token counts, errors, and thread/turn metadata. | Primary Codex transcript format. | High-value evidence for AI-assisted actions, shell command intent, file edits, tool use, workspace paths, and possible data disclosure to the model. |
| `~/.codex/archived_sessions/**/rollout-*.jsonl` | Parsed | Same as rollout sessions. | Archived Codex threads. | Extends timeline coverage beyond active sessions. |
| `~/.codex/session_index.jsonl` | Parsed as enrichment metadata. | Thread titles and session index context. | Session title/index file. | Helps analysts identify relevant threads quickly and improves session labeling. |
| `~/.codex/state*.sqlite` plus `-wal`/`-shm` | Snapshot and parsed as enrichment metadata. | Thread index rows, workspace/model/git context, parent-child spawn edges, and per-thread dynamic tools. | Version-aware supplemental Codex state; IRFlow selects the highest schema suffix and snapshots SQLite companions before reading. | Recovers current thread/subagent topology and registered tools, including records that may still reside only in WAL. |
| VS Code-family `state.vscdb` agent session cache for Codex provider | Parsed as supplemental fallback when `.codex` has very few rows. | Codex-labeled VS Code agent session rows from `agentSessions.model.cache`. | Codex provider usage inside VS Code-family storage. | Captures embedded Codex usage that may not appear in `~/.codex`. |

Notes:

- `InvokedTool` is populated for invoked tools/functions such as `exec_command`, `apply_patch`, web search, or MCP calls. It should not contain `OpenAI Codex` on new imports.
- Forked threads and sidechains are marked where metadata supports it.

### ChatGPT Desktop and Atlas

Status: partially parsed. LevelDB and SQLite message paths are covered by tests. Encrypted `conversations-v2-*` bundles are inventory-only.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| macOS `~/Library/Application Support/com.openai.chat/` | Parsed when LevelDB or SQLite stores are present. | Conversation metadata from LevelDB and message rows from SQLite when locally available. | Native ChatGPT Desktop app data root. | Shows local ChatGPT use, conversation titles, timestamps, and sometimes full prompt/response bodies. |
| macOS `~/Library/Application Support/OpenAI/Atlas/` | Scanned with ChatGPT logic. | Same store classes when present. | Atlas/OpenAI app data path. | Keeps coverage aligned with newer OpenAI desktop/browser app storage. |
| Windows `%APPDATA%/OpenAI/ChatGPT/` and MS Store package paths | Parsed when LevelDB or SQLite stores are present. | Same as above. | Windows ChatGPT app stores. | Useful in endpoint triage packages and KAPE-style collections. |
| Linux `~/.config/com.openai.chat/`, `~/.config/ChatGPT/`, `~/.config/OpenAI/ChatGPT/` | Parsed when LevelDB or SQLite stores are present. | Same as above. | Linux app data variants. | Extends support to developer workstations. |
| `Local Storage/leveldb/*.ldb` and `*.log` | Parsed. | Conversation titles, timestamps, and metadata objects found in raw LevelDB bytes. | Electron LevelDB local storage. | Good for proving use and locating relevant conversations, but may be metadata-only. |
| SQLite DBs such as `messages.db` or app-specific conversation DBs | Parsed when `better-sqlite3` is available. | Role, content, created time, conversation ID, model. | Message body storage used by some app versions. | Highest-value ChatGPT Desktop evidence when available. |
| `conversations-v2-*` | Inventory-only. | Metadata row noting encrypted bundle presence. | Newer encrypted ChatGPT conversation bundles, Keychain-gated on macOS. | Important collection/legal notice: proves relevant local artifacts exist, but IRFlow does not decrypt them. |

Notes:

- Test coverage for SQLite paths is currently skipped in this shell due a local `better-sqlite3` ABI mismatch. The LevelDB and encrypted-bundle paths pass.
- If only LevelDB metadata is available, docs should avoid promising full message body recovery.

### Gemini CLI

Status: parsed. Live dataset validated with 39 rows and no missing timestamp, summary, or FullText values.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| `~/.gemini/tmp/<project_hash>/chats/session-*.json` | Parsed. | User, gemini, system, error, session ID, message ID, timestamp, and content. | Gemini CLI session transcript. | Captures local CLI prompts/responses and project-specific usage. |
| `~/.gemini/tmp/<project_hash>/chats/checkpoint-*.json` | Parsed when it follows the session message schema. | Same message schema as session files. | Gemini CLI checkpoint-style data. | Can preserve intermediate context not visible in final session files. |
| `~/.gemini/tmp/<project_hash>/logs.json` | Parsed. | Legacy log array entries with type, message/content, timestamp, session ID, and message ID. | Legacy Gemini CLI log format. | Keeps coverage for older Gemini CLI installations. |

Notes:

- `thoughts` are represented as `[Reasoning present]` or `[Reasoning only]` rather than dumping hidden reasoning text into the grid.
- This parser covers Gemini CLI, not cloud-only Gemini web chats.

### Cursor

Status: parsed. Live dataset validated with 3,748 rows. 799 rows have blank timestamps because the source is `state.vscdb` data without reliable per-message timestamps.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| `~/.cursor/projects/<slug>/agent-transcripts/<session>/<session>.jsonl` | Parsed. | User/assistant messages, structured content blocks, tool-use text, session ID, workspace decoded from slug, sidechain flags, and timestamps when present. | Cursor agent transcript store. | High-value evidence for Cursor agent instructions, codebase actions, command/tool requests, and workspace attribution. |
| Cursor transcript `.txt` logs | Parsed where supported by importer routing. | Transcript text fallback. | Alternate Cursor transcript format. | Helps when JSONL is absent but text export/cache exists. |
| Cursor `User/globalStorage/state.vscdb` | Parsed when SQLite support is available. | Composer/chat bubble messages and timestamps when present. | VS Code-family global state DB for Cursor. | Captures composer/global chats not stored in agent-transcripts. |
| Cursor `User/workspaceStorage/*/state.vscdb` | Parsed when SQLite support is available. | Workspace-scoped chat/composer messages. | Workspace state DB. | Links AI activity to a specific project/workspace. |
| `~/.cursor/chats/**/store.db` | Parsed when SQLite support is available. | Cursor composer store bubble messages. | Alternate Cursor composer SQLite store. | Recovers chat history missed by transcript-only collection. |

Notes:

- Cursor transcript rows prefer embedded `timestamp` or `createdAt` values. File mtime spreading is only a fallback for transcript rows.
- For SQLite rows with no timestamp, IRFlow intentionally leaves `Timestamp` blank rather than fabricating one.

### GitHub Copilot in VS Code-family Editors

Status: parsed by tests. No Copilot rows were present in the live tab.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| `Code/User/workspaceStorage/<hash>/chatSessions/*.json` | Parsed. | User requests, assistant responses, session ID, request ID, model when present, and workspace from `workspace.json`. | VS Code Copilot Chat snapshot files. | Shows Copilot usage tied to opened workspace folders. |
| `Code/User/workspaceStorage/<hash>/chatSessions/*.jsonl` | Parsed and preferred over sibling JSON for same session. | Replayed `kind: 0`, `kind: 2`, and `kind: 1` operations. | Incremental Copilot Chat session log. | More complete than final snapshots; preserves chat evolution. |
| `Code/User/workspaceStorage/<hash>/workspace.json` | Parsed as workspace mapping. | Workspace path/URI. | VS Code workspace metadata. | Provides project attribution for chat sessions. |
| `Code/User/globalStorage/emptyWindowChatSessions/*.json` and `*.jsonl` | Parsed. | Chats created with no folder open. | Global Copilot chat storage. | Prevents missed evidence when users asked Copilot questions outside a workspace. |
| VS Code-family `state.vscdb` chat/session keys | Parsed as supplement when SQLite support is available. | `agentSessions.model.cache`, `chat.ChatSessionStore.index`, prompt arrays, chat data. | VS Code-family state database. | Recovers session titles, cache entries, or messages when chat session files are sparse or empty. |

Notes:

- Product coverage includes Code, Code Insiders, VSCodium, and VSCodium Insiders user data roots.
- Public docs should say "VS Code-family Copilot Chat", not just "GitHub Copilot cloud".

### Windsurf

Status: partially parsed. VS Code-family `state.vscdb` messages are parsed when SQLite support is available. Cascade `.pb` files are inventory-only.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| `Windsurf/User/globalStorage/state.vscdb` | Parsed when SQLite support is available. | Global chat/session rows from VS Code-family keys. | Windsurf global user state database. | Captures global AI chat context and agent session metadata. |
| `Windsurf/User/workspaceStorage/*/state.vscdb` | Parsed when SQLite support is available. | Workspace chat/session rows. | Windsurf workspace state database. | Ties Windsurf activity to a workspace/project hash. |
| `Windsurf/User/globalStorage/windsurf.cascade/**/*.pb` | Inventory-only. | File name, size, source path, and notice that protobuf is not decoded. | Windsurf Cascade proprietary protobuf bundles. | Important preservation signal. It tells investigators the endpoint has Cascade artifacts even when message contents are not decoded. |

Notes:

- Public claims should be careful: IRFlow detects Cascade `.pb` files but does not decode proprietary protobuf bodies.
- The parser now leaves `InvokedTool` blank on Cascade inventory rows because `Tool` already says `Windsurf`.

### Continue

Status: parsed by tests. No Continue rows were present in the live tab.

| Artifact | Parse status | What IRFlow extracts | Description | IR relevance |
| --- | --- | --- | --- | --- |
| `~/.continue/sessions/*.json` | Parsed. | History entries, role, content, session ID, message index, workspace directory, model where present. | Continue.dev local session history. | Captures prompts/responses from a common developer assistant and maps them to a project path. |
| `~/.continue/sessions/sessions.json` | Ignored as an index file. | None. | Session index, not message history. | Avoids false positive rows from non-message metadata. |

Notes:

- Current support is focused on session JSON bodies.

### Browser AI Hints

Status: hints only, not parsed into AI Query History message rows.

| Artifact family | Parse status | What IRFlow reports | Description | IR relevance |
| --- | --- | --- | --- | --- |
| Chrome profile AI paths | Hint only. | Paths under Chrome extension/local storage/IndexedDB that may contain Claude, ChatGPT, or similar web artifacts. | Browser storage for web AI apps/extensions. | Tells collectors to acquire browser profiles or vendor exports. |
| Edge Copilot/Bing paths | Hint only. | Edge IndexedDB/local storage path hints. | Browser storage for Copilot/Bing Chat. | Helps find web-only Copilot use. |
| Firefox profiles | Hint only. | Firefox profile paths with AI-related keywords. | Browser profile storage. | Helps scope browser forensic collection. |
| Safari local storage/container paths | Hint only. | Safari local storage and container path hints. | macOS Safari storage. | Helps scope browser forensic collection on macOS. |

Notes:

- These are collection hints. They should not be described as decoded web chat history.

## Parser Correctness Assessment

| App | Current assessment | Evidence |
| --- | --- | --- |
| Claude Code/Desktop | Correct for supported artifacts. | Live rows have complete core fields; parser tests cover history, sessions, desktop metadata, attachments, sidechains, dedupe, and tool names. |
| OpenAI Codex | Correct for supported artifacts. | Live rows have complete core fields; tests cover history, rollout envelopes, forked sessions, and Codex state metadata. |
| ChatGPT Desktop/Atlas | Correct for LevelDB metadata and encrypted-bundle inventory; SQLite message-body path needs runtime ABI verification. | LevelDB and encrypted-bundle tests pass; SQLite tests skip in this shell because `better-sqlite3` is not ABI-compatible. |
| Gemini CLI | Correct for supported artifacts. | Live rows are clean; tests cover session JSON, legacy logs, system/error messages, and reasoning markers. |
| Cursor | Correct with timestamp caveat. | Live rows have complete summary/full text; blank timestamps are isolated to source records without reliable per-message time. Tests cover transcript timestamps and composer DB paths, with SQLite paths skipped in this shell. |
| GitHub Copilot | Correct by fixture tests; not present in live dataset. | Tests cover workspace chat sessions, JSONL replay, JSONL-over-JSON preference, and empty-window routing. |
| Windsurf | Correct for state.vscdb path by shared VS Code parser; Cascade `.pb` is inventory-only. | Cascade inventory test passes; SQLite-backed state DB parsing needs runtime ABI verification in this shell. |
| Continue | Correct by fixture tests; not present in live dataset. | Tests cover root detection and session JSON extraction. |

## Documentation and Website Copy Recommendations

Use these statements publicly:

- "IRFlow parses local AI assistant histories from Claude Code/Desktop, OpenAI Codex, ChatGPT Desktop, Gemini CLI, Cursor, GitHub Copilot in VS Code-family editors, Windsurf, and Continue."
- "IRFlow preserves both a grid-friendly `Summary` and richer `FullText` for long prompts/responses and secret scanning."
- "IRFlow distinguishes the AI application (`Tool`) from invoked tools/functions (`InvokedTool`)."
- "Encrypted or proprietary stores are reported as inventory when IRFlow cannot decode message bodies, including ChatGPT `conversations-v2-*` and Windsurf Cascade `.pb`."
- "Browser-only AI use is surfaced as collection hints, not decoded browser chat history."

Avoid these claims until implemented:

- "IRFlow decrypts ChatGPT `conversations-v2-*`."
- "IRFlow decodes Windsurf Cascade protobuf bodies."
- "IRFlow parses all web ChatGPT/Claude/Copilot browser chats."
- "All AI history rows always have timestamps." Some SQLite/cache sources lack reliable per-message timestamps.

## Follow-up Engineering Items

| Priority | Item | Why |
| --- | --- | --- |
| High | Rebuild/test `better-sqlite3` in the same Node/Electron runtime used for parser tests. | SQLite-backed ChatGPT, Cursor, Copilot/Windsurf state DB coverage is important, and current shell tests skip/fail on ABI mismatch. |
| High | Reimport or backfill legacy AI Query History tabs that have provider names stored in raw `ToolName`. | Query normalization hides this in the UI/export path, but raw DQ still flags stale rows. |
| Medium | Add a public docs section explaining `Tool` versus `InvokedTool`. | Prevents analyst confusion when grouping by tool usage. |
| Medium | Add a docs matrix separating parsed, metadata-only, inventory-only, and browser-hint artifacts. | Sets accurate expectations for DFIR users and public website copy. |
| Medium | Add explicit runtime coverage for Windsurf `state.vscdb` and ChatGPT SQLite fixtures once SQLite ABI is fixed. | Confirms the most DFIR-relevant SQLite paths under automated tests. |
