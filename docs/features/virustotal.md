---
description: VirusTotal integration — API setup, single and bulk IOC lookups, persistent cache, verdict badges, and auto-tagging for threat intel enrichment.
---

# VirusTotal Integration

IRFlow Timeline integrates with VirusTotal to enrich matched IOCs with reputation data. After running an [IOC scan](/features/ioc-matching), you can look up individual indicators or enrich all matched IOCs in bulk.

## API Key Setup

1. In the IOC Matching modal, expand the **VirusTotal** section
2. Enter your VirusTotal API key (free or premium)
3. Configure rate limiting and cache settings:

| Setting | Options | Default |
|---------|---------|---------|
| **Rate limit** | 4, 8, 12, 16 requests/minute | 4 req/min (free tier) |
| **Cache TTL** | 1 hour, 6 hours, 12 hours, 24 hours, 48 hours, 7 days | 24 hours |

Your API key is stored locally and never transmitted except to the VirusTotal API.

::: tip Free vs Premium
The free VirusTotal API allows 4 requests per minute and 500 per day. If you have a premium key, increase the rate limit to 8–16 req/min for faster bulk enrichment.
:::

## Single Lookup

Right-click any cell and select **Lookup on VirusTotal** to query a single indicator. Results open in your browser on virustotal.com.

| Indicator Type | VirusTotal URL |
|---------------|----------------|
| SHA256 / SHA1 / MD5 | `virustotal.com/gui/file/{hash}` |
| Domain | `virustotal.com/gui/domain/{domain}` |
| IPv4 / IPv6 | `virustotal.com/gui/ip-address/{ip}` |

## Bulk Lookup

After an IOC scan, click **Enrich N IOCs with VirusTotal** to look up all VT-compatible indicators that matched timeline rows.

- By default, only IOCs with timeline hits are enriched to conserve API quota
- Enable **Include unmatched IOCs** to enrich all compatible indicators regardless of hit count
- Equivalent IOCs (e.g., `1.2.3.4:80` and `1.2.3.4:443`) are deduplicated so only one API call is made per unique object

### Progress and Cancellation

Progress is shown inline as each IOC is processed. A **Cancel** button stops in-flight lookups immediately. If the application window closes during a bulk lookup, the operation stops automatically without errors.

When the VirusTotal API returns a rate-limit response, IRFlow Timeline waits with a cancellable retry — polling every 2 seconds so you can cancel at any time rather than waiting for the full retry period.

## Persistent Cache

Results are cached in a local SQLite database (`vt-cache.db`) to avoid redundant API calls:

- Hash values are normalized to lowercase
- Domains are normalized to lowercase
- Ports are stripped from IP:Port values (e.g., `1.2.3.4:80` → `1.2.3.4`)
- Cached results are returned instantly on subsequent lookups until the configured TTL expires

## Verdict Badges

After enrichment, a **VT** column appears in the data grid showing color-coded verdict badges:

| Verdict | Color | Meaning |
|---------|-------|---------|
| **Malicious** | Red | Flagged as malicious by multiple engines |
| **Suspicious** | Yellow | Flagged as suspicious by some engines |
| **Clean** | Green | No detections |

- Click a badge to open the indicator's VirusTotal page
- Hover to see all matched IOCs and their individual verdicts
- The VT column supports sorting (malicious first) and filtering via the column dropdown

## Auto-Tagging

After enrichment completes, rows are automatically tagged with their VT verdict:

- `VT: Malicious`
- `VT: Suspicious`
- `VT: Clean`

This enables immediate filtering via the tag system and ensures sort-by-verdict works without manual steps. The **Tag by Verdict** button is also available for manual re-tagging if needed.

## See Also

- [IOC Matching](/features/ioc-matching) — scan timelines against threat intel indicator lists before enriching with VT
- [Bookmarks & Tags](/features/bookmarks-tags) — VT verdicts auto-create tags for filtering and reporting
- [Process Inspector](/features/process-tree) — trace processes associated with matched indicators
- [Export & Reports](/workflows/export-reports#virustotal-ioc-enrichment) — HTML reports include a VT verdict summary and per-IOC table when enrichment was run on the tab
