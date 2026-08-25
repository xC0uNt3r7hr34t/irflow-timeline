---
description: Export timeline data to CSV, XLSX, TSV, and XLS formats, or generate HTML investigation reports.
---

# Export & Reports

IRFlow Timeline supports exporting filtered data and generating investigation reports.

## Data Export

### Export to CSV

1. **Menu:** File → Export (`Cmd+E`)
2. Select **CSV** format
3. Choose a save location
4. Exported data respects all active filters — only visible rows are exported

### Export to TSV

1. **Menu:** File → Export (`Cmd+E`)
2. Select **TSV** format
3. Choose a save location
4. Tab-separated output with the same filtering as CSV

### Export to XLSX

1. **Menu:** File → Export (`Cmd+E`)
2. Select **XLSX** format
3. Choose a save location
4. Excel files include:
   - Auto-fit column widths
   - Styled header row (bold, colored)
   - All filtered data

### Export to XLS

1. **Menu:** File → Export (`Cmd+E`)
2. Select **XLS** format
3. Choose a save location
4. Writes OOXML format with a `.xls` extension for compatibility with tools that expect the `.xls` extension

### Export Selected Rows

1. Select rows using checkboxes in the data grid
2. **Menu:** Actions → Export Selected Rows
3. Choose a save location
4. Exports only the selected rows as CSV

### What Gets Exported

Full export (File → Export) includes:

- All visible columns (hidden columns are excluded)
- Only rows matching current filters, search, and date range
- Bookmarked/tagged rows if those filters are active
- Data in the current sort order

Selected export (Actions → Export Selected Rows) includes only the checked rows regardless of filters.

::: tip Export Bookmarked Only
Enable the bookmark filter (`Cmd+B`) before exporting to create a file containing only your flagged rows.
:::

## AI History Package

On an **AI Query History** tab, use **Tools → Export → Export AI History Package…** to write a case-ready folder:

| File | Purpose |
|------|---------|
| `<tab>_timeline.csv` | Grid rows (respects filters, sort, and visible columns; **FullText** is always included) |
| `manifest.json` | Each **SourceFile** path with row count, size, mtime, and SHA-256 (first 250 files hashed) |
| `README.txt` | Short bundle description |

Use **Tools → Export → Export Source Manifest…** when you only need the source inventory without the filtered timeline CSV. See [AI Query History](/dfir-tips/ai-query-history#export-for-reporting) for investigation context.

## HTML Reports

Generate a formatted investigation report from your bookmarks and tags.

### Generate a Report

1. **In-app menu:** **Tools → Export → Generate Report**
2. **macOS menu bar:** **File → Generate Report…** (`Cmd+Shift+R`)
3. Choose a save location
4. The HTML report opens in your default browser

### Report Contents

The generated report includes:

#### Summary Cards

- Total rows in the dataset
- Number of bookmarked rows
- Number of tagged rows
- Count of unique tags

#### Timeline Span

- Earliest timestamp in the data
- Latest timestamp in the data
- Total time span covered

#### Tag Breakdown

- Colored chips showing each tag and its count
- Colors match your in-app tag palette

#### Bookmarked Events Table

- Full data for every bookmarked row
- All columns included
- Sortable in the browser

#### Tagged Events (Grouped)

- Separate tables for each tag
- Rows grouped under their tag heading
- Shows all columns with full data

#### VirusTotal IOC Enrichment

When you have run [IOC Matching](/features/ioc-matching) with [VirusTotal](/features/virustotal) enrichment on the same tab, the report adds a **VirusTotal IOC Enrichment** section (saved with the tab in sessions). If no VT lookups were performed, this section is omitted.

The enrichment block includes:

- **Verdict summary cards** — counts of timeline-matched IOCs rated malicious, suspicious, clean, and not found / private
- **Feed-only note** — optional line for enriched IOCs that did not hit any timeline rows (when you chose to enrich the full feed)
- **IOC details table** — one row per enriched indicator with:
  - Raw IOC value and category (IPv4, domain, SHA256, etc.)
  - VT detection score and color-coded verdict badge
  - Threat label (when returned by VirusTotal)
  - Query timestamp (UTC)
  - **Timeline hits** — how many rows matched that IOC in the tab (or — if feed-only)

Rows are sorted with malicious and suspicious verdicts first so executives and peer reviewers see the highest-risk indicators at the top.

::: tip Workflow
Run IOC scan → enrich hits with VirusTotal → bookmark/tag key rows → **Generate Report**. The HTML file then doubles as a lightweight intel summary for stakeholders who do not have IRFlow installed.
:::

### Report Styling

Reports are self-contained HTML with embedded CSS:

- Clean, professional layout
- Print-friendly formatting
- Works in light and dark browser themes
- No external dependencies — can be shared as a single file

## Export Workflow Example

A typical investigation export workflow:

1. **Analyze** — use search, filters, and analytics to investigate
2. **Bookmark** — star important rows as you find them
3. **Tag** — categorize findings (Suspicious, Lateral Movement, etc.)
4. **Generate Report** — create the HTML summary
5. **Export Data** — export filtered CSV/XLSX for further analysis or archival
6. **Share** — send the report to your team or include in your case file

## See Also

- [VirusTotal Integration](/features/virustotal) — configure API key and bulk enrichment before reporting
- [IOC Matching](/features/ioc-matching) — scan and tag indicators that feed the VT report section
- [Bookmarks & Tags](/features/bookmarks-tags) — tagged rows appear grouped in HTML reports
- [Sessions](/workflows/sessions) — save investigation state (including VT enrichment) before exporting
- [Multi-Tab Analysis](/workflows/multi-tab) — export from individual tabs or merged timelines
- [Merging Timelines](/workflows/merge-tabs) — create a unified timeline before final export
