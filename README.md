# IRFlow Timeline (Windows)

A high-performance native Windows application for DFIR timeline analysis. Built on Electron + SQLite to handle large forensic files (CSV, TSV, XLSX, EVTX, Plaso, raw $MFT, $J) without breaking a sweat.

This fork tracks [r3nzsec/irflow-timeline](https://github.com/r3nzsec/irflow-timeline) and adapts it for native Windows builds. Inspired by Eric Zimmerman's Timeline Explorer for Windows.

**Current version: v1.0.9** — merged from upstream with Windows packaging and platform-specific UI/runtime changes.

---

## What's New (merged from upstream v1.0.6–v1.0.9)

| Version | Highlights |
|---|---|
| **v1.0.9** | Large EVTX import fix — bounded 64 KiB chunk parsing supports ~4 GiB logs without Node Buffer limits |
| **v1.0.8** | AI Application Forensics expansion (Grok Build, Claude/Codex improvements), Open Triage Collection, Process Inspector overhaul, multi-source Persistence/Lateral Movement analyzers |
| **v1.0.7** | AI Artifacts / AI Query History, AI Secret Hunt |
| **v1.0.6** | Sigma Detection (Hayabusa + in-app JS engine), RDP Bitmap Cache (bmc-tools), Lateral Movement expansion, modular codebase refactor |

---

## Download & Install

1. Download the latest installer from [Releases](https://github.com/xC0uNt3r7hr34t/irflow-timeline/releases)
2. Run the NSIS installer (`IRFlow-Timeline-Setup-x.x.x.exe`) and follow the prompts
3. Launch **IRFlow Timeline** from the Start Menu or Desktop shortcut

A portable build (`IRFlow-Timeline-Portable-x.x.x.exe`) is also available — no installation required.

**Requirements:** Windows 10 64-bit or later. No other dependencies needed for end users.

---

## Building from Source

### Prerequisites

- **Node.js v20** (required — v21+ is not compatible with the native module build)
- **Python 3.x** — required for compiling `better-sqlite3` and bundling `bmc-tools`
- **Visual Studio Build Tools** — workload: **Desktop development with C++**
- **Git Bash** (or WSL) — required for `bundle:hayabusa` and `bundle:bmc-tools` scripts

### Steps

```bash
git clone https://github.com/xC0uNt3r7hr34t/irflow-timeline.git
cd irflow-timeline
npm install
npm run rebuild
```

#### Development (hot-reload)

```bash
npm run dev
```

#### Build + launch (production renderer, no packaging)

```bash
npm run start
```

#### Package as Windows installer

```bash
# NSIS installer + portable exe (x64) — same as original fork workflow
npm run dist:win

# Full build with bundled Hayabusa + bmc-tools (Sigma Scan, RDP Bitmap Cache)
# Requires Git Bash on Windows
npm run dist:win:full

# NSIS installer only
npm run dist:win:nsis

# Portable exe only
npm run dist:win:portable
```

Or use the all-in-one PowerShell script:

```powershell
.\scripts\build-win.ps1
```

Output in `release/`.

### Troubleshooting the build

| Problem | Fix |
|---|---|
| `Cannot find module '@electron/rebuild/lib/cli.js'` | Run `npm install` first, then `npm run rebuild` |
| `node --version` shows wrong version | Use nvm-windows to switch: `nvm use 20` |
| Python not found during rebuild | Install Python 3.x and add to PATH |
| `MSBuild` or `VCBuild` error | Install Visual Studio Build Tools with "Desktop development with C++" |
| `NODE_MODULE_VERSION mismatch` | Wrong Node version during rebuild — switch to v20 and run `npm run rebuild` again |
| App loads blank screen | Run `npm run build:renderer` — `vite.config.js` `base: "./"` is required |
| Hayabusa bundle fails | Run via Git Bash: `bash scripts/bundle-hayabusa.sh` |

---

## Supported Formats

| Format | Description |
|---|---|
| **CSV / TSV** | Comma, tab, pipe delimited (auto-detected) |
| **XLSX / XLS / XLSM** | Excel files with multi-sheet picker |
| **EVTX** | Windows Event Logs (native parsing, supports multi-GB files in v1.0.9+) |
| **Plaso** | Plaso SQLite databases |
| **Raw $MFT** | NTFS Master File Table — direct binary parsing |
| **Raw $J / UsnJrnl** | NTFS USN Change Journal |

---

## Key Features

### Investigation Tools

- **AI Artifacts** — Collect and timeline AI assistant history (ChatGPT, Claude, Cursor, Copilot, Gemini, Grok, etc.)
- **AI Secret Hunt** — Detect exposed credentials in AI history with redacted export
- **Sigma Detection** — Hayabusa EVTX scanning + in-app JS Sigma engine
- **Open Triage Collection** — KAPE/triage folder inventory and selective import
- **Process Inspector** — Verdict-first process analysis with graph and hunt modes
- **Lateral Movement Tracker** — Multi-source detection with network graphs and campaign triage
- **Persistence Analyzer** — Multi-source persistence hunting with KAPE collection support
- **RDP Bitmap Cache** — Recover tiles from Windows RDP cache artifacts
- **VirusTotal Enrichment**, **IOC Matching**, **Gap/Burst Analysis**, **Ransomware Analyzer**, and more

### Data & Search

- Multi-file import with tab merging and session save/restore (`.tle`)
- SQLite FTS5 search across millions of rows
- Virtual grid, histogram, filter presets, bookmarks/tags, HTML/PDF reports

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| Ctrl+O | Open file |
| Ctrl+F | Focus search |
| Ctrl+E | Export filtered view |
| Ctrl+B | Toggle bookmarked-only |
| Ctrl+S | Save session |
| Ctrl+Shift+O | Load session |
| Ctrl+W | Close current tab |
| Ctrl+K | Command palette |
| Ctrl+/ | Keyboard shortcuts |

---

## Architecture

```
React UI (renderer)  →  IPC  →  Electron Main Process
                                      ↓
                              SQLite (better-sqlite3)
                                      ↓
                         Streaming Parsers (CSV/XLSX/EVTX/Plaso/$MFT/$J)
                                      ↓
                         Worker Threads (import, analyzers, index builds)
```

The v1.0.6+ refactor split the monolithic codebase into focused modules under `electron/parsers/`, `electron/ipc/`, `electron/jobs/`, `electron/analyzers/`, and `src/components/`.

---

## Windows-Specific Adaptations

This fork applies the following changes on top of upstream:

- **Window chrome** — standard Windows frame (no macOS traffic lights / vibrancy)
- **Single-instance lock** — file associations open in the running instance via `second-instance`
- **Native menus** — Windows-style File/Help menus (no macOS App menu)
- **Keyboard shortcuts** — UI displays `Ctrl+` instead of `⌘` on Windows
- **electron-builder** — NSIS installer + portable targets
- **Hayabusa bundling** — `bundle-hayabusa.sh` downloads the Windows x64 binary

---

## Open Source Credits

| Project | Usage |
|---|---|
| [r3nzsec/irflow-timeline](https://github.com/r3nzsec/irflow-timeline) | Original macOS IRFlow Timeline |
| [Eric Zimmerman's Timeline Explorer](https://ericzimmerman.github.io/) | Original Windows DFIR timeline inspiration |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Sigma EVTX scanning engine |
| [Electron](https://github.com/electron/electron) | Application framework |
| [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) | SQLite with WAL + FTS5 |

## License

Apache-2.0
