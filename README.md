# SharePoint CSP Violation Analyzer

A PowerShell script for SharePoint Administrators that parses large Microsoft Purview audit log exports, extracts Content Security Policy (CSP) violation data, and generates a standalone interactive HTML report — helping admins understand and act on upcoming CSP enforcement before pages break.

> **Related Message Center notification:** [MC1193419](https://admin.microsoft.com/Adminportal/Home#/MessageCenter) — SharePoint Online Content Security Policy enforcement changes.

---

## Background

Microsoft is enforcing Content Security Policy (CSP) across SharePoint Online (MC1193419). Once enforced, any external script source not on the tenant allow-list will be **blocked by the browser**, potentially breaking customizations, analytics, WalkMe guides, Clarity telemetry, and more.

Microsoft Purview captures every CSP violation as a `ContentSecurityPolicyViolated` audit event. This script processes those events — even exports with **100,000+ rows** — and produces a clear, actionable report so admins know exactly what to allow-list, remove, or investigate before enforcement begins.

---

## Features

- **High-performance CSV parsing** — uses fast regex-based JSON extraction instead of `ConvertFrom-Json` per row, handling 100k+ row exports efficiently with live progress reporting
- **Smart allow-list minimization** — computes the longest common URL path prefix per hostname so one entry covers many versioned files (no hostname wildcards, which SharePoint CSP does not support)
- **Interactive HTML report** — fully standalone (no internet required), with:
  - Summary cards: total violations, unique blocked domains, affected sites, date range, allow-list count vs. 300-entry limit
  - Script Source Allow-List section with usage bar, copy-to-clipboard, and chip/plain-text toggle
  - Top Blocked Domains table with visual violation bars and expandable affected-site lists
  - Most Affected Sites table
  - **Domains to Allow checklist** — per-entry Allow / Remove / Review decision buttons with live progress tally
  - Sortable and searchable tables throughout
- Requires only **PowerShell 5.1+** — no additional modules needed

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later (PowerShell 7+ recommended for large files) |
| Input | CSV exported from Microsoft Purview Audit Log Search |
| Permissions | Read access to the exported CSV file |

---

## Exporting the Audit Data from Purview

1. Go to the [Microsoft Purview compliance portal](https://compliance.microsoft.com) → **Audit**
2. Set the date range you want to analyze
3. Under **Activities – friendly names** (or **Record types**), filter for **ContentSecurityPolicyViolated** (Record Type `336`)
4. Run the search and export results as CSV
5. Extract the downloaded `.zip` — the `.csv` file inside is your input

> **Tip:** For a baseline before MC1193419 enforcement, export 30–90 days of data to capture the full breadth of external sources your users are loading.

---

## Usage

```powershell
# Basic — report saved alongside the CSV with a timestamp
.\Analyze-CSPViolations.ps1 -CsvPath "C:\Exports\purview_audit.csv"

# Specify output path and show top 30 blocked domains
.\Analyze-CSPViolations.ps1 -CsvPath ".\audit.csv" -OutputPath ".\CSP_Report.html" -TopDomains 30

# Also include every individual DocumentUrl / BlockedUrl pair in the report
.\Analyze-CSPViolations.ps1 -CsvPath ".\audit.csv" -IncludeFullUrls
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-CsvPath` | String | *(required)* | Path to the Purview audit log CSV export |
| `-OutputPath` | String | Auto-timestamped filename next to the CSV | Path for the generated HTML report |
| `-TopDomains` | Int (1–200) | `20` | Number of top blocked domains to show in the domain summary table |
| `-IncludeFullUrls` | Switch | Off | Adds a full DocumentUrl→BlockedUrl pairs table to the report. Warning: increases report file size significantly on large datasets |

---

## Understanding the Report

### Summary Cards

| Card | What it means |
|---|---|
| Total CSP Violations | Total rows matched in the audit export |
| Unique Blocked Domains | Number of distinct external hostnames blocked |
| SharePoint Sites Affected | Number of distinct site collections that triggered violations |
| Violation Date Range | Earliest and latest event timestamps in the export |
| Allow-List Entries Needed | Number of URL prefix entries required, against the 300-entry tenant limit |

### Script Source Allow-List

The key output of the report. Each entry is the **minimal URL prefix** that covers all blocked resources seen from that hostname:

| Seen in data | Allow-list entry generated | Rationale |
|---|---|---|
| `https://www.clarity.ms/tag/abc123` | `https://www.clarity.ms/` | Single URL from host → origin only |
| `https://cdn.walkme.com/player/lib/v1/a.js` `https://cdn.walkme.com/player/lib/v1/b.js` | `https://cdn.walkme.com/player/lib/v1/` | Multiple files, common path → shared folder prefix |
| `https://cdn.example.com/v1/a.js` `https://cdn.example.com/v2/b.js` | `https://cdn.example.com/` | No common deep path → origin only |

> Entries are automatically deduplicated: if a broader prefix already covers a more specific one, the more specific entry is dropped.

Use the **Copy all domains** button to copy the plain-text list, then paste it into your tenant CSP policy submission.

### Domains to Allow Checklist

A per-entry decision table sorted by violation count. For each URL prefix:

| Decision | When to use |
|---|---|
| ✓ **Allow** | The resource is legitimate — add this prefix to the tenant allow-list |
| ✗ **Remove** | The resource should not be loading in SharePoint — remove the script from the affected pages |
| ? **Review** | Ownership or intent is unclear — needs further investigation before enforcement |

A live progress tally tracks how many entries are in each state.

---

## How the Allow-List is Minimized

The script groups all `BlockedUrl` values by hostname, then for each hostname computes the **longest common URL path prefix** across all unique blocked URLs from that host:

```
All URLs from cdn.walkme.com:
  /player/lib/20260114-155748-1bcf23ac/9.f53a4f92.walkme_lib.js
  /player/lib/20260114-155748-1bcf23ac/bundle.walkme.min.js
  /player/lib/20260114-155748-1bcf23ac/walkme_player.min.js

Common prefix: /player/lib/20260114-155748-1bcf23ac/
Allow-list entry: https://cdn.walkme.com/player/lib/20260114-155748-1bcf23ac/
```

This avoids unnecessarily broad origins when a vendor consistently serves from versioned paths. If URLs are spread across many paths, it falls back to the origin (`https://cdn.walkme.com/`).

> **No hostname wildcards** (e.g. `*.clarity.ms`) are generated. SharePoint Online's CSP allow-list does not support hostname wildcards — only URL prefixes.

---

## Output

The script generates a single **self-contained HTML file** with no external dependencies. It can be:

- Opened directly in any browser
- Emailed to stakeholders
- Printed to PDF
- Committed to a repo or SharePoint document library as a point-in-time snapshot

Console output on completion:

```
=== SharePoint CSP Violation Analyzer ===
Input  : C:\Exports\purview_audit.csv
Output : C:\Exports\CSP_Report_20260223_143012.html
MC Ref : MC1193419

Counting rows in CSV...
Total data rows: 87,423

Processing CSV and extracting CSP violation data...
  Columns detected:
    Top-level DocumentUrl : False
    Top-level BlockedUrl  : False
    AuditData JSON column : True  [AuditData]

Processing complete.
  Rows processed : 87,423
  Rows matched   : 87,423
  Rows skipped   : 0

  Allow-list entries   : 14 (of 300 tenant limit)

Report written successfully!
  Path : C:\Exports\CSP_Report_20260223_143012.html
  Size : 248.7 KB
```

---

## Input CSV Format

The script expects the standard Purview audit log CSV export format. Required columns:

| Column | Description |
|---|---|
| `AuditData` | JSON blob containing the event details, including `DocumentUrl` and `BlockedUrl` |
| `CreationDate` | Event timestamp (used for date range cards) |

All other columns (`RecordId`, `RecordType`, `Operation`, `UserId`, etc.) are ignored.

The `AuditData` JSON blob format for CSP violations looks like:

```json
{
  "Operation": "ContentSecurityPolicyViolated",
  "DocumentUrl": "https://tenant.sharepoint.com/sites/MySite/SitePages/Home.aspx",
  "BlockedUrl": "https://scripts.clarity.ms/0.8.49/clarity.js",
  ...
}
```

---

## Remediation Steps

Once you have your allow-list from the report:

1. **Review** each entry in the "Domains to Allow" checklist — confirm ownership before allowing
2. **Submit approved entries** to your SharePoint tenant CSP policy via the SharePoint admin center or PowerShell
3. **Remove** any Script Editor web parts or inline scripts loading from domains that should not be trusted
4. **Re-run** this script after the MC1193419 enforcement date to confirm violation counts drop to zero for allow-listed domains
5. **Monitor** Purview audit logs on an ongoing basis for new violations as content evolves

---

## Performance Notes

| Export size | Approx. processing time |
|---|---|
| 10,000 rows | < 5 seconds |
| 50,000 rows | ~15–25 seconds |
| 100,000 rows | ~30–60 seconds |

*Times vary by machine. PowerShell 7+ is noticeably faster than Windows PowerShell 5.1 for large files.*

The script uses regex-based field extraction from the `AuditData` JSON string rather than calling `ConvertFrom-Json` on every row, which eliminates the primary bottleneck for large exports.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Mike Lee**  
Version 1.0.0 — February 2026
