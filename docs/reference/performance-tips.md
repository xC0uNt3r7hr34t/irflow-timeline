---
description: Performance optimization tips for IRFlow Timeline — streaming architecture, memory management, and large file handling.
---

# Performance Tips

IRFlow Timeline is engineered for large datasets, but these tips will help you get the best performance.

## Import Performance

### Streaming Architecture

Files are imported in streaming chunks — the full file is never loaded into memory:

| Format | Chunk Size | Batch Size |
|--------|-----------|------------|
| **CSV/TSV** | 128 MB | Adaptive (up to 100,000 rows) |
| **XLSX** | Streaming (ExcelJS) | Adaptive (up to 100,000 rows) |
| **XLS** | Full file (SheetJS) | Adaptive (up to 100,000 rows) |
| **EVTX** | Full file (binary) | Adaptive (up to 100,000 rows) |
| **Plaso** | Single SQLite query | All rows |

### Expected Import Times

These are approximate times on an Apple Silicon Mac:

| File Size | Rows | Import Time |
|-----------|------|-------------|
| 100 MB | ~500K | 5-10 seconds |
| 1 GB | ~5M | 30-60 seconds |
| 10 GB | ~50M | 5-8 minutes |
| 30 GB+ | ~150M+ | 15-25 minutes |

### Benchmarks

The following benchmarks were measured on an **Apple M1 Pro (16 GB RAM, NVMe SSD)** using EvtxECmd CSV output. Times may vary based on column count, data complexity, and system load.

#### Import + Indexing

| Dataset | Rows | Columns | Import | Column Indexes | FTS5 Build | Total |
|---------|------|---------|--------|---------------|------------|-------|
| Small (KAPE single host) | 500K | 22 | ~6s | ~3s | ~4s | ~13s |
| Medium (multi-host merge) | 5M | 22 | ~45s | ~25s | ~35s | ~2 min |
| Large (enterprise triage) | 50M | 22 | ~7 min | ~4 min | ~6 min | ~17 min |
| Very large (full super-timeline) | 150M+ | 22 | ~22 min | ~12 min | ~18 min | ~52 min |

#### Query Response Times (after indexing)

| Operation | 500K rows | 5M rows | 50M rows |
|-----------|----------|---------|----------|
| FTS keyword search | <10ms | <30ms | <80ms |
| Regex search | ~20ms | ~150ms | ~1.5s |
| Fuzzy search | ~50ms | ~400ms | ~4s |
| Column sort (indexed) | <10ms | <20ms | <50ms |
| Checkbox filter | <10ms | <15ms | <40ms |
| Scroll to new page | <5ms | <10ms | <15ms |

#### Analytics Tools

| Tool | 500K rows | 5M rows | 50M rows |
|------|----------|---------|----------|
| Histogram build | <100ms | ~300ms | ~2s |
| Stacking (single column) | ~50ms | ~200ms | ~1.5s |
| Gap Analysis | ~30ms | ~150ms | ~1s |
| Burst Detection | ~40ms | ~200ms | ~1.5s |
| Log Source Coverage | ~20ms | ~100ms | ~800ms |
| Process Inspector build | ~100ms | ~500ms | ~3s |
| Lateral Movement scan | ~80ms | ~400ms | ~2.5s |
| Persistence Analyzer | ~60ms | ~300ms | ~2s |
| IOC Match (1,000 IOCs) | ~200ms | ~1s | ~8s |

::: tip
Analytics tools run against the currently filtered dataset. Applying date range or column filters before running analytics significantly reduces processing time on large datasets.
:::

### Tips for Faster Import

- **Restart IRFlow** before importing multi-GB files if the app has been open for hours — a high main-process memory footprint before import is a common crash trigger
- **Close unused tabs** before importing large files to free memory
- **Wait for "indexes ready"** before opening column filter dropdowns on files over 5 GB (filter value lists may be sampled until indexes finish). Large imports index timestamps plus EventID/Channel for Sigma pre-filters, not every column.
- **Use CSV over XLSX** for very large datasets — CSV streaming is faster than Excel parsing
- **Pre-filter with external tools** if you only need a subset of the data

Files over **5 GB** skip the trigram FTS index (search uses LIKE). You need roughly **2–3× the file size** of free space on your temp volume for the SQLite database and indexes.

## AI History Performance

**Collect AI Artifacts** and large folder imports run in a worker thread so the UI stays responsive.

| Tip | Why |
|-----|-----|
| **Main sessions only** on first pass | Skips `subagents/` and sidechain rows — much faster on hosts with 80k+ JSONL lines |
| **Browse folder scope** | Point at the KAPE/triage root so discovery does not also read unrelated local Mac paths |
| **Filter before export** | **Export AI History Package** respects active filters — narrow to tagged secret findings or a date window before writing the CSV |
| **Scroll large AI tabs** | AI Query History tabs with 100k+ rows use the same virtual scroll window as EVTX timelines; avoid keeping many huge AI tabs open at once |

Merged AI timelines stop at **3,000,000** rows and report truncation in the import notice. Malformed JSONL lines are skipped and counted so you know when a source may be incomplete.

## Search Performance

### Background Indexing

After import, two background build phases run automatically:

1. **Column indexes** — one B-tree index per column, built sequentially (yields to event loop between each)
2. **FTS5 search index** — full-text search index built in 200,000-row chunks

Both phases run asynchronously so the UI remains interactive. A status indicator in the toolbar shows progress. If you search before the FTS index is ready, LIKE mode is used as a fallback.

### Search Mode Performance

| Mode | Speed | Best For |
|------|-------|---------|
| **FTS** | Fastest | Keyword searches |
| **LIKE** | Fast | Substring matching |
| **Mixed** | Fast | General use (runs both) |
| **Regex** | Moderate | Pattern matching |
| **Fuzzy** | Slowest | Typo-tolerant search |

### Debouncing

Search queries are debounced at 500ms — the query only executes after you stop typing for half a second. This prevents unnecessary queries while typing.

## Scrolling Performance

### Virtual Scrolling

The grid maintains a window of ~10,000 rows:

- Only visible rows (~50) are rendered in the DOM
- 20-row overscan above and below for smooth scrolling
- New data is fetched via SQLite `LIMIT`/`OFFSET` as you scroll

### Sorting

Column indexes are built automatically in the background after import:

- Sorting is fast once background indexing completes
- A status indicator shows indexing progress in the toolbar
- All columns are indexed (not just timestamp columns)

## Memory Management

### SQLite Configuration

IRFlow Timeline uses aggressive SQLite tuning for performance:

SQLite pragmas are tuned per-phase for maximum throughput:

**During import:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Journal mode** | OFF | No journal overhead for temp databases |
| **Synchronous** | OFF | Fast async writes |
| **Cache size** | 1 GB | Keep entire B-tree in memory |
| **MMAP size** | 0 | Disabled during writes |
| **Page size** | 64 KB | Fewer B-tree nodes, faster bulk writes |
| **Threads** | 4 | Parallel sort for internal operations |

**During background index/FTS build:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Journal mode** | OFF | No journal overhead |
| **Cache size** | 1 GB | Keep data + index pages in memory |
| **Threads** | 8 | Parallel sort/merge for CREATE INDEX |

**During query mode:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Journal mode** | WAL | Concurrent reads |
| **Synchronous** | NORMAL | Safe for queries |
| **Cache size** | 256 MB | Query cache |
| **MMAP size** | 512 MB | Memory-mapped reads |

### Temp storage folder

Each tab creates a temporary SQLite database plus column indexes and (after import) an FTS5 index. By default these files live under the macOS system temp directory. For large cases, point temp storage at an external or scratch volume so imports do not fill your boot disk.

**macOS menu bar → Tools → Set Temp Storage Folder…**

- Applies to **new imports only** (existing tabs keep their current database path)
- **Tools → Use Default Temp Folder** clears a custom path
- The read-only **Temp Storage:** label shows the active setting

IRFlow estimates required free space before import (roughly a few times the source file size) and blocks the import with a clear error if the temp volume is too full.

See [Preferences — Temp storage folder](/reference/preferences#temp-storage-folder) for full details and the optional `TLE_TEMP_DIR` environment variable.

#### Approximate on-disk size per tab

| Dataset Size | Approximate DB + indexes |
|-------------|-------------------------|
| 1 GB CSV | ~1.5 GB |
| 10 GB CSV | ~15 GB |
| 30 GB+ CSV | ~45 GB+ |

Temp databases are removed when you close the tab or quit the app.

### Search Result Caching

The 4 most recent search queries per tab are cached in memory. This provides instant results when toggling between searches or switching tabs.

## JS Sigma scan (imported tab / EvtxECmd CSV)

The in-app **JS Sigma** engine scans rows already loaded into SQLite. On multi-million-row timelines it is CPU-heavy because each candidate row is checked against every rule in its logsource group.

### Faster JS scans

1. **Use the “Fast high-confidence only” preset** — fewer rules (`core` set, critical/high, stable/test) cuts evaluation time sharply versus “Full hunt” (~3,800+ rules).
2. **Wait for indexes ready** — large imports now build **EventID** and **Channel** indexes (with timestamps) so logsource SQL pre-filters use indexes instead of full table scans.
3. **Prefer Hayabusa on raw EVTX** when you have `.evtx` folders — the bundled Hayabusa binary is optimized for EVTX and usually beats re-scanning a giant EvtxECmd CSV inside the app.
4. **Narrow the timeline first** — apply a date range filter on the tab before scanning so fewer rows match broad channel queries.
5. **First scan after import** — if EventID/Channel indexes were not built at import time, the scan may spend a few minutes building them once; later scans on the same tab are faster.

::: warning
An 8 GB EvtxECmd CSV (~6M rows) with **all** severity levels and **all** rules can take a long time even after these optimizations. Treat full-rule JS scans as batch jobs; use presets or Hayabusa for interactive triage.
:::

## Recommendations for Large Investigations

1. **Start with targeted files** — open the most relevant logs first, add more as needed
2. **Use date range filters early** — narrow to the investigation window before running analytics
3. **Merge selectively** — merge only the tabs relevant to your current question
4. **Save sessions frequently** — protect your work against unexpected issues
5. **Export subsets** — when sharing or reporting, export filtered data rather than full datasets
6. **Close completed tabs** — free memory by closing tabs you're done analyzing

## Hardware Recommendations

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 8 GB | 16-32 GB |
| **Storage** | SSD (any) | NVMe SSD |
| **CPU** | Any 64-bit | Apple Silicon (M1+) |
| **Free disk** | 2x largest file on temp volume | 3x total evidence size (use **Set Temp Storage Folder…** if needed) |
