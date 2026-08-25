---
description: Save and reload frequently used filter configurations as named presets that persist across sessions.
---

# Filter Presets

Filter presets let you save complex filter configurations and reload them instantly. Presets persist to disk and are available across app restarts and sessions.

## Creating a Preset

1. Build your filter using any combination of:
   - [Column filters](/features/search-filtering#column-filters) (text, checkbox, or date range)
   - [Advanced filter editor](/features/search-filtering#advanced-filter-editor) conditions
   - [Tag filters](/features/search-filtering#tag-filters)
2. Open **View → Filter Presets**
3. Enter a descriptive name for the preset
4. Click **Save**

The preset captures your complete filter state — all column filters, advanced conditions, and tag selections.

## Loading a Preset

1. Open **View → Filter Presets**
2. Select a saved preset from the list
3. The filter is applied immediately to the current tab

::: tip KAPE-Aware Presets
When working with KAPE tool output, IRFlow Timeline auto-detects the tool format and applies optimized column layouts. Combine this with filter presets to create tool-specific investigation workflows — for example, a "Suspicious Logons" preset for EvtxECmd Security log output that filters to Event IDs 4624/4625 with specific logon types.
:::

## Managing Presets

- Presets are stored in `filter-presets.json` in the app's user data directory
- All presets are available globally — they are not tied to a specific file or tab
- Delete presets you no longer need from the preset list

## Use Cases

| Preset Example | Filters |
|---------------|---------|
| **Suspicious Logons** | Event ID = 4624/4625, Logon Type = 3/10, exclude SYSTEM |
| **PowerShell Activity** | Source contains "PowerShell", Event ID = 4104/4103 |
| **Lateral Movement** | Event ID = 4624, Logon Type = 3, filter by target hostname |
| **File Execution** | Source = Sysmon, Event ID = 1, path contains `\Temp\` or `\AppData\` |
| **Persistence** | Event ID = 7045 (service install) or 4698 (scheduled task create) |

## See Also

- [Search & Filtering](/features/search-filtering) — full guide to all filter types
- [Color Rules](/features/color-rules) — visually highlight rows matching filter criteria
- [KAPE Integration](/workflows/kape-integration) — auto-detected formats pair well with saved presets
- [Sessions](/workflows/sessions) — session save/restore captures the active filter state separately from presets
