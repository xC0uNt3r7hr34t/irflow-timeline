# IRFlow Timeline (Windows)

A high-performance native Windows application for DFIR timeline analysis. Built on Electron + SQLite to handle large forensic files (CSV, TSV, XLSX, EVTX, Plaso, raw $MFT, $J) without breaking a sweat.

Inspired by Eric Zimmerman's Timeline Explorer for Windows.

---

## Download & Install

1. Download the latest installer from [Releases](https://github.com/xC0uNt3r7hr34t/irflow-timeline/releases)
2. Run the NSIS installer (`IRFlow-Timeline-Setup-x.x.x.exe`) and follow the prompts
3. Launch **IRFlow Timeline** from the Start Menu or Desktop shortcut

A portable build (`IRFlow-Timeline-Portable-x.x.x.exe`) is also available — no installation required, runs from any folder including USB drives.

**Requirements:** Windows 10 64-bit or later. No other dependencies needed.

---

## Building from Source

### Prerequisites

- **Node.js v20** (required — v21+ is not compatible with the native module build)
  - Download: https://nodejs.org/en/download (select LTS v20)
  - If you have multiple Node versions, use [nvm-windows](https://github.com/coreybutler/nvm-windows) to switch:
    ```
    nvm install 20
    nvm use 20
    node --version   # must show v20.x.x
    ```
- **Python 3.x** — required for compiling `better-sqlite3`
  - Download: https://python.org — check **"Add Python to PATH"** during install
- **Visual Studio Build Tools** — required for compiling `better-sqlite3`
  - Download: https://visualstudio.microsoft.com/visual-cpp-build-tools/
  - Select workload: **"Desktop development with C++"**
  - Alternatively, install via npm in an elevated PowerShell:
    ```
    npm install --global --production windows-build-tools
    ```
- **Git** — https://git-scm.com/download/win

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
# NSIS installer + portable exe (x64)
npm run dist:win

# NSIS installer only
npm run dist:win:nsis

# Portable exe only
npm run dist:win:portable
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
| App loads blank screen | Run `npm run build:renderer` to regenerate `dist/` — the `vite.config.js` `base: "./"` setting is required |
| File dialog doesn't open | Check DevTools console (`Ctrl+Shift+I`) for errors — usually a preload script path issue |

---

## Supported Formats

| Format | Description |
|---|---|
| **CSV / TSV** | Comma, tab, pipe delimited (auto-detected) |
| **XLSX / XLS / XLSM** | Excel files with multi-sheet picker |
| **EVTX** | Windows Event Logs (native parsing via `@ts-evtx/core`) |
| **Plaso** | Plaso SQLite databases (auto-detects schema version, handles zlib-compressed event data) |
| **Raw $MFT** | NTFS Master File Table — direct binary parsing, no tools required |
| **Raw $J / UsnJrnl** | NTFS USN Change Journal — parent path resolved from $MFT if loaded |

---

## Features

### Data Import

- **Multi-file import** — drag multiple files onto the window or select via File → Open; files queue and import sequentially to prevent memory exhaustion
- **Multi-tab workspace** — each file gets its own tab with independent state
- **Tab merging** — combine 2+ tabs into a single chronological timeline with a `_Source` column
- **Large file warning** — files over 10 GB prompt before import; XLSX files over 10 GB are blocked with a CSV conversion suggestion

### Search

Powered by SQLite FTS5 for near-instant search across millions of rows:

| Syntax | Behavior |
|---|---|
| `word1 word2` | OR — matches either term |
| `+word` | AND — must include |
| `-word` | Exclude |
| `"exact phrase"` | Phrase match |
| `Column:value` | Column-specific filter |

**Search modes:** Mixed, OR, AND, Exact, Regex, Fuzzy

**Search conditions:** Contains, Starts With, Like, Equals

**Cross-tab search** — search across all open tabs simultaneously with per-tab match counts

**Regex Pattern Palette** — built-in quick-insert buttons for common forensic patterns (IPv4/v6, domains, email, MD5/SHA1/SHA256, Base64, Windows SIDs, UNC paths, file paths, URLs, registry keys, MAC addresses)

### Column Management

- **Show/hide columns** — auto-detects and hides empty columns on import
- **Pin columns** — keep important columns visible while scrolling
- **Reorder columns** — drag headers to rearrange
- **Resize columns** — drag column borders; double-click to auto-fit
- **Group by** — drag column headers to the group bar for hierarchical views
- **Column Quick Stats** — right-click a header for value distribution, fill rate, timestamp range, numeric stats, top 25 values bar chart

### Filtering

- **Per-column text filters** with SQL LIKE queries
- **Checkbox filters** — select specific values from a dropdown
- **Date range filters** — constrain any timestamp column to a time window
- **Advanced Edit Filter** — multi-condition builder with AND/OR logic and 11 operators
- **Filter presets** — save and load named filter configurations
- **Bookmarked-only view** — show only flagged rows
- **Clear All Filters** — one-click reset for all active filters with active filter count badge

### Timeline Visualization

- **Interactive histogram** — event density over time with heatmap coloring
- **Click-and-drag** — select a time range on the histogram to filter
- **Resizable** — drag the bottom edge to adjust height
- **Per-tab caching** — instant histogram display when switching tabs

### Investigation Tools

| Tool | Description |
|---|---|
| **Stack Values** | Frequency distribution of any column's values with counts, percentages, and bar chart |
| **IOC Matching** | Load IOC lists (IPs, domains, hashes, URLs) and highlight matches across all columns |
| **VirusTotal Enrichment** | Bulk VT lookup with rate limiting, caching, relationship pivoting |
| **Gap Analysis** | Detect activity sessions and quiet periods in the timeline. Auto-tag sessions |
| **Log Source Coverage Map** | Gantt-style visualization of which log sources are present, their time span, and event counts |
| **Burst Detection** | Find windows with abnormally high event density |
| **Process Tree** | Reconstruct parent-child process relationships from Sysmon EventID 1. GUID-preferred linking, suspicious pattern detection |
| **Lateral Movement Tracker** | Force-directed network graph of host-to-host logons (EventID 4624/4625/4648) |
| **Ransomware Analyzer** | MFT-based encrypted file detection, ransom note pattern matching, anti-forensic detection |
| **Timestomping Detector** | Identifies $SI vs $FN timestamp discrepancies in MFT data |
| **ADS Analyzer** | Detects Alternate Data Streams in MFT imports |

### Tagging & Bookmarking

- **Row bookmarking** — flag important events with Ctrl+B or the star icon
- **Custom tags** — apply named, color-coded tags to rows
- **Bulk tagging** — tag all filtered rows or events by time range
- **Tag management** — view, rename, recolor tags

### Export & Reporting

- **Export filtered view** — stream filtered/sorted data to CSV, TSV, or XLSX
- **HTML Report** — self-contained report with bookmarked events, tagged groups, VT enrichment summary, and summary cards
- **PDF Export** — ransomware analysis reports exported directly to PDF
- **Session save/restore** — persist bookmarks, tags, filters, column layout across sessions (`.tle` files)

### Display

- **Dark/Light theme** — Unit 42-inspired dark theme (default)
- **Timezone selector** — UTC, major US/EU/Asia zones, or local
- **Datetime format** — configurable display format
- **Adjustable font size** — Ctrl+Plus / Ctrl+Minus

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
| Ctrl+Shift+Q | Close all tabs |
| Ctrl+R | Reset column widths |
| Ctrl+Shift+C | Column Manager |
| Ctrl+Shift+L | Conditional Formatting |
| Ctrl+Shift+F | Find in All Tabs |
| Ctrl+Shift+R | Generate Report |
| Ctrl+/ | Keyboard Shortcuts |
| Ctrl+Plus / Ctrl+Minus | Increase / decrease font size |
| Esc | Close modal / clear search |

---

## KAPE / EZ Tools Auto-Profiles

IRFlow Timeline automatically detects output from common DFIR tools and applies optimised column layouts, pinned columns, and color rules:

MFTECmd · EvtxECmd · PECmd · LECmd · AmcacheParser · RECmd · SBECmd · SrumECmd · AppCompatcache · JLECmd · Hayabusa · Chainsaw · Forensic Timeline · SuperTimeline (Plaso) · MacTime · KapeMiniTimeline · BrowsingHistoryView · KAPE Copy Log

---

## Performance

- **Import speed:** ~500K rows/sec (CSV), ~200K rows/sec (XLSX), ~150K rows/sec (Plaso)
- **Query speed:** <100ms for filtered queries on 10M+ row datasets
- **Memory usage:** ~200–500 MB regardless of file size (SQLite handles the rest)
- **Disk usage:** SQLite temp DB is roughly 2–3× the original file size (stored in `%TEMP%`)

---

## Architecture

```
+----------------------------------------------------+
|  React UI (renderer process)                       |
|  - Virtual scroll (only renders visible rows)      |
|  - Requests 5,000-row windows via IPC              |
|  - Inline SVG histogram, modals, context menus     |
+------------------------+---------------------------+
                         | IPC (contextBridge)
+------------------------v---------------------------+
|  Electron Main Process                             |
|  - File dialog, native menus, export streaming     |
|  - HTML/PDF report generation                      |
|  - Coordinates parser <-> DB <-> renderer          |
|  - Single-instance lock + argv file open           |
|  - window.open(_blank) → shell.openExternal        |
+------------------------+---------------------------+
                         |
+------------------------v---------------------------+
|  SQLite Engine (better-sqlite3)                    |
|  - WAL mode, 500 MB cache, 2 GB mmap               |
|  - FTS5 full-text search index                     |
|  - B-tree indexes on timestamp/numeric columns     |
|  - SQL filtering, sorting, pagination              |
|  - Temp DB in %TEMP%, auto-cleaned on close        |
+------------------------+---------------------------+
                         |
+------------------------v---------------------------+
|  Streaming Parsers                                 |
|  - CSV: readline stream, 50K-row batch inserts     |
|  - XLSX: ExcelJS streaming + unzipper              |
|  - EVTX: @ts-evtx/core async generator            |
|  - Plaso: SQLite ATTACH + zlib decompress          |
|  - $MFT: two-pass binary parser                    |
|  - $J / UsnJrnl: binary record parser             |
|  - Never loads full file into memory               |
+----------------------------------------------------+
```

---

## Open Source Credits

| Project | Usage |
|---|---|
| [Electron](https://github.com/electron/electron) | Application framework |
| [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) | High-performance SQLite with WAL mode and FTS5 |
| [@ts-evtx/core](https://github.com/nicholasgasior/ts-evtx) | Windows EVTX event log parsing |
| [ExcelJS](https://github.com/exceljs/exceljs) | XLSX streaming reader |
| [unzipper](https://github.com/ZJONSSON/node-unzipper) | XLSX zip extraction |
| [csv-parser](https://github.com/mafintosh/csv-parser) | CSV/TSV streaming parser |
| [React](https://github.com/facebook/react) | UI rendering |
| [Vite](https://github.com/vitejs/vite) | Build tooling and hot-reload |
| [electron-builder](https://github.com/electron-userland/electron-builder) | Windows NSIS/portable packaging |
| [electron-updater](https://github.com/electron-userland/electron-builder/tree/master/packages/electron-updater) | Auto-update support |

Inspired by [Eric Zimmerman's Timeline Explorer](https://ericzimmerman.github.io/) — the original Windows DFIR timeline tool.

---

### DFIR Community

- [Renzon Cruz](https://github.com/r3nzsec/irflow-timeline) -- Original macos build of IRFlow Timeline
- [Eric Zimmerman](https://ericzimmerman.github.io/) -- Timeline Explorer for Windows, the original inspiration for this project
- [log2timeline/Plaso](https://github.com/log2timeline/plaso) -- Super timeline generation framework by Kristinn Gudjonsson and contributors
- [SANS DFIR](https://www.sans.org/digital-forensics-incident-response/) -- DFIR training and community resources
- [The DFIR Report](https://thedfirreport.com/) -- Real-world intrusion analysis reports that informed threat detection patterns
- [CyberCX](https://cybercx.com.au/blog/ntfs-usnjrnl-rewind/) -- NTFS $UsnJrnl research that informed $J parsing implementation

## License

Apache-2.0
