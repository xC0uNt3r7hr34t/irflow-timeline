---
description: Bookmark important rows and tag evidence with DFIR categories to build your investigation narrative.
---

# Bookmarks & Tags

Bookmarks and tags are the core annotation tools for building your investigation narrative within IRFlow Timeline.

![Bookmarks and Tags showing tagged rows with context menu for applying DFIR tags like Suspicious, Lateral Movement, and C2](/dfir-tips/Bookmarks-Tags.png)

Bulk annotation: **Actions → Bulk Tag / Bookmark**. Per-row tags also appear in the right-click / `Cmd+Click` context menu.

## Bookmarks

Bookmarks let you flag individual rows as important for later review and reporting.

### Adding Bookmarks

- Click the **star icon** on any row to toggle its bookmark
- `Cmd+Click` a row and select **Bookmark**
- Bookmarks are stored per-tab in the SQLite database

### Bulk Bookmarking

- Open **Actions → Bulk Tag / Bookmark** to bookmark or tag rows by time range
- Or `Cmd+Click` a row and use the bookmark option in the context menu

### Viewing Bookmarks

- Toggle `Cmd+B` to show only bookmarked rows
- The tab badge shows the bookmarked row count
- Bookmarked rows display a filled star icon in the grid

### In Reports

Bookmarked rows are included in HTML reports with their full data. They appear in a dedicated "Bookmarked Events" section.

## Tags

Tags are free-form labels you attach to rows for categorization. Each row can have multiple tags, and tags are color-coded for visual distinction. The Tags column is a full first-class grid column — you can sort, filter, and stack by tags just like any other column.

### Adding Tags

1. Right-click a row to open the context menu
2. Hover over **Tags ▸** to expand the tag submenu
3. Click a tag to toggle it on or off
4. The tag appears as a colored chip in the Tags column

### Multi-Row Tagging

Select multiple rows using checkboxes, then right-click to apply a tag to all selected rows at once. The context menu shows the count (e.g., "Tags (4 rows)") to confirm how many rows will be affected.

### Tag Presets

IRFlow Timeline includes common DFIR investigation tags:

| Tag | Use Case |
|-----|----------|
| **Suspicious** | General suspicious activity |
| **Lateral Movement** | Evidence of movement between hosts |
| **Exfiltration** | Data exfiltration indicators |
| **Persistence** | Persistence mechanism installation |
| **C2** | Command and control communication |
| **Initial Access** | Entry point indicators |
| **Execution** | Malicious execution events |
| **Credential Access** | Credential harvesting/dumping |

You can also create custom tags — just type any name. IOC Matching automatically creates per-indicator tags (e.g., `IOC: cmd.exe`, `IOC: 185.220.101.34`) with orange coloring.

### Bulk Actions

Open **Actions → Bulk Tag / Bookmark** for bulk operations on filtered rows:

**Bulk Tagging:**

1. Enter a tag name (with autocomplete from existing tags)
2. Pick a tag color
3. Click **Apply Tag** to tag all rows matching the current filter
4. Shows "Applies to N filtered rows" count and confirmation ("Tagged N rows as X")

**Bulk Bookmarking:**

1. Click **Bookmark All** to bookmark all filtered rows, or **Remove Bookmarks** to clear bookmarks from filtered rows
2. Shows result count confirmation

**By Time Range:**

Tags can also be applied by time range from other tools:
- **Histogram sessions** — tag all rows in a detected session window
- **Burst detection** — tag rows in identified burst periods
- **Heatmap windows** — tag rows from file activity heatmap time ranges

This is useful for marking an entire activity window (e.g., "Attacker Active 14:30-15:45").

**Auto-Tags from Analysis Tools:**

Several analysis tools automatically create bulk tags:
- `Timestomp Indicator` — from timestomping detection
- `Downloaded` — from ADS Zone.Identifier analysis
- `Encrypted`, `Ransom Note`, `Payload` — from ransomware analysis
- `Modified Burst`, `Created Burst` — from burst detection
- `IOC: {value}` — from IOC matching
- `VT: Malicious`, `VT: Suspicious`, `VT: Clean` — from VirusTotal enrichment

### Removing Tags

- `Cmd+Click` a tagged row and select **Remove Tag**
- Choose which tag to remove (if multiple)

### Tag Colors

Each unique tag is assigned a color from the palette. Colors are consistent within a session and persist when saving/loading sessions.

### Tags Column Features

The Tags column behaves as a full grid column with:

- **Sorting** — click the Tags column header to sort rows by their tag values
- **Text filtering** — type in the Tags filter cell to search for specific tags using SQL `LIKE` matching
- **Checkbox filtering** — click the dropdown button in the Tags filter cell to select specific tags from a checkbox list
- **Stacking** — `Cmd+Click` the Tags header and select Stack Values to see tag frequency distribution
- **Column Stats** — view tag statistics including total tagged rows, unique tags, and top values
- **Disable/enable** — toggle the tag filter on/off without removing it (shown with strikethrough when disabled)

### Filtering by Tag

- Type in the Tags filter cell to filter by tag name
- Use the dropdown checkbox filter to select one or more specific tags
- Click a tag chip in a row to filter to rows with that tag
- Combine tag filters with other filter types

### In Reports

HTML reports include:

- Summary count of tagged rows
- Tag breakdown chips showing each tag and its count
- Grouped tables showing rows organized by tag
- Color-coded tag indicators matching the in-app palette

## See Also

- [Color Rules](/features/color-rules) — conditional formatting to visually highlight patterns
- [IOC Matching](/features/ioc-matching) — auto-creates per-IOC tags on matched rows
- [NTFS Analysis](/features/ntfs-analysis) — auto-tags timestomped files, ADS entries, and ransomware indicators
- [Export & Reports](/workflows/export-reports) — tagged rows appear grouped in HTML reports
- [Sessions](/workflows/sessions) — bookmarks and tags persist across session save/restore
