# Analyze-CSPInlineViolations.ps1

A PowerShell script that parses Microsoft Purview audit log exports and generates a standalone interactive HTML report identifying every SharePoint page that has triggered a **CSP inline script violation**.

Companion to [`Analyze-CSPViolations.ps1`](./Analyze-CSPViolations.ps1) (external-resource violations).  
Related Message Center notification: **MC1193419** — SharePoint Online Content Security Policy enforcement changes.

---

## Background

### What is an inline CSP violation?

When SharePoint enforces its Content Security Policy, the browser blocks:

- Inline `<script>` blocks (code written directly in the HTML, not in an external `.js` file)
- Inline event handlers such as `onclick="..."`, `onload="..."`, etc.
- Inline `<style>` blocks

In the Purview audit log, these violations appear as rows where the **BlockedUrl** column contains `inline` or `unsafe-inline` instead of an external domain name.

### Why inline violations are different

Unlike external-resource violations, **inline violations cannot be resolved by adding a domain to the CSP allow-list**. The offending code must be identified and refactored — moved to an external file or rewritten to use `addEventListener` calls.

This script focuses on identifying **which pages** are affected so site owners can open each page in a browser, use Developer Tools, and locate the exact inline code causing the violation.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell | 5.1 or PowerShell 7+ |
| Purview audit export | CSV exported from Microsoft Purview (Audit → Search) |
| Audit operations | Filter for `ContentSecurityPolicyViolationDetected` |

---

## Getting the audit data

1. Sign in to the [Microsoft Purview compliance portal](https://compliance.microsoft.com).
2. Go to **Audit** → **New Search**.
3. Set the date range and filter **Activities** to `ContentSecurityPolicyViolationDetected`.
4. Run the search and **Export** the results as a CSV.
5. Use the exported CSV as the `-CsvPath` input.

---

## Usage

```powershell
# Basic — report saved next to the CSV with a timestamped filename
.\Analyze-CSPInlineViolations.ps1 -CsvPath "C:\Exports\purview_audit.csv"

# Specify output path
.\Analyze-CSPInlineViolations.ps1 -CsvPath ".\audit.csv" -OutputPath ".\inline_report.html"

# Show top 50 pages instead of the default 100
.\Analyze-CSPInlineViolations.ps1 -CsvPath ".\audit.csv" -TopPages 50
```

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-CsvPath` | Yes | — | Path to the Purview audit log CSV export |
| `-OutputPath` | No | `<csv_dir>\CSP_Inline_Report_<timestamp>.html` | Path for the generated HTML report |
| `-TopPages` | No | `100` | Number of top affected pages to show in the report (max 500) |

---

## What the script matches

Rows are included when the `BlockedUrl` value (case-insensitive) is one of:

| Value | Description |
|---|---|
| `inline` | Bare inline indicator |
| `'inline'` | Quoted inline indicator |
| `unsafe-inline` | Bare unsafe-inline |
| `'unsafe-inline'` | Quoted unsafe-inline |
| `blob` / `'blob:'` | Blob URI scheme |
| `data` / `'data:'` | Data URI scheme |

All rows with an external domain in `BlockedUrl` are counted but excluded from this report (use `Analyze-CSPViolations.ps1` for those).

---

## HTML Report

The generated report is a **single self-contained HTML file** — no server, no dependencies, works offline.

### Report sections

| Section | Description |
|---|---|
| **Summary cards** | Total inline violations · Unique pages · Site collections · Date range |
| **What is an inline violation?** | Plain-language explanation of inline CSP violations |
| **DevTools guidance** | Step-by-step instructions for using browser Developer Tools to find the offending script on each page |
| **Affected Pages table** | Every DocumentUrl ranked by violation count — sortable, searchable, with site collection column |
| **Site Collections table** | Site collections ranked by total violations with expandable page lists |

### Interactive features

- Sort any table column by clicking the header
- Search/filter both tables in real time
- Expand site collections to see their individual affected pages
- **Export as CSV** button to download the affected pages table

---

## How to investigate each violation

The audit log tells you *which page* has an inline violation but not *which script* caused it. For each affected `DocumentUrl`:

1. Open the page URL in **Microsoft Edge** or **Chrome**.
2. Press **F12** to open Developer Tools.
3. Go to the **Console** tab and press **F5** to reload.
4. Look for red error messages containing **"Content Security Policy"** and **"inline"**.
5. The console entry includes a clickable link that jumps to the **Sources** panel at the exact offending line.
6. Refactor the inline code:
   - Move `<script>` blocks to an external `.js` file
   - Replace inline event handlers (`onclick="..."`) with `addEventListener` calls
   - Move `<style>` blocks to an external `.css` file

---

## Output

```
=== SharePoint CSP Inline Violation Analyzer ===
Input  : C:\Exports\purview_audit.csv
Output : C:\Exports\CSP_Inline_Report_20260224_143012.html
MC Ref : MC1193419

Counting rows in CSV...
Total data rows: 125,430

Processing CSV and extracting inline CSP violation data...
  Columns detected:
    Top-level DocumentUrl : False
    Top-level BlockedUrl  : False
    AuditData JSON column : True  [AuditData]

Processing complete.
  Rows processed      : 125,430
  Inline violations   : 8,214
  Non-inline rows     : 117,021
  Rows skipped        : 195 (missing DocumentUrl/BlockedUrl)

Report written successfully!
  Path : C:\Exports\CSP_Inline_Report_20260224_143012.html
  Size : 342.7 KB
```

---

## Related scripts

| Script | Purpose |
|---|---|
| [`Analyze-CSPViolations.ps1`](./Analyze-CSPViolations.ps1) | External-resource violations — identifies blocked domains and builds a tenant CSP allow-list |
| [`Analyze-CSPInlineViolations.ps1`](./Analyze-CSPInlineViolations.ps1) | Inline violations — identifies affected pages for Developer Tools investigation |

---

## Notes

- Tested on PowerShell 5.1 and PowerShell 7+
- Uses regex-based JSON field extraction (not `ConvertFrom-Json`) for performance on large exports
- Column names are detected automatically and support both camelCase and PascalCase variants in the `AuditData` JSON blob

---

## Author

Mike Lee  
Version 1.0.0 — February 24, 2026
