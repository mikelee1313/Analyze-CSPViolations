<#
.SYNOPSIS
    Analyzes SharePoint CSP inline-script violation audit data exported from Microsoft Purview.

.DESCRIPTION
    Parses large CSV audit log exports from Microsoft Purview, extracts CSP violation rows
    where the BlockedUrl is an inline indicator ('inline', 'unsafe-inline', etc.), and
    generates a standalone interactive HTML report listing every DocumentUrl (SharePoint page)
    that triggered an inline script violation.

    Because inline violations cannot be resolved by adding an allow-list entry, the report
    focuses on identifying WHICH PAGES are affected so owners can inspect each page's inline
    scripts using browser Developer Tools.

    Guidance for remediation:
      1. Open each affected DocumentUrl in a browser.
      2. Open Developer Tools (F12) → Console tab.
      3. Look for Content Security Policy violation messages that reference 'inline'.
      4. Identify the offending script/style block or event handler and refactor it to use
         an external file or a nonce-based approach.

    Relevant Message Center notification: MC1193419
    (SharePoint Online Content Security Policy enforcement changes)

.PARAMETER CsvPath
    Path to the Purview audit log CSV export file (.csv).

.PARAMETER OutputPath
    Path for the generated HTML report file.
    Defaults to the same directory as the CSV with a timestamped filename.

.PARAMETER TopPages
    Number of top affected pages to feature in the summary table. Default: 100.

.EXAMPLE
    .\Analyze-CSPInlineViolations.ps1 -CsvPath "C:\Exports\purview_audit.csv"

.EXAMPLE
    .\Analyze-CSPInlineViolations.ps1 -CsvPath ".\audit.csv" -OutputPath ".\inline_report.html" -TopPages 50

.NOTES
    Author  : Mike Lee
    Version : 1.0.0
    Date    : 2/24/2026
    Tested  : PowerShell 5.1, PowerShell 7+

    Inline BlockedUrl indicators matched (case-insensitive):
      inline, 'inline', unsafe-inline, 'unsafe-inline', blob, 'blob:', data, 'data:'

    The script resolves DocumentUrl / BlockedUrl from:
      1. Top-level CSV columns (if present)
      2. The AuditData JSON blob column (handles both camelCase and PascalCase)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = 'Path to the Purview audit CSV export.')]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(HelpMessage = 'Output HTML report path. Defaults to CSV directory with timestamp.')]
    [string]$OutputPath,

    [Parameter(HelpMessage = 'Number of top affected pages to show in the report.')]
    [ValidateRange(1, 500)]
    [int]$TopPages = 100
)

# The Purview audit export always uses 'AuditData' as the JSON column name.
$AuditDataColumn = 'AuditData'

# Inline violation BlockedUrl patterns (trimmed, lowercased values to match against)
$InlineIndicators = @(
    'inline',
    "'inline'",
    'unsafe-inline',
    "'unsafe-inline'",
    'blob',
    "'blob:'",
    'data',
    "'data:'"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helper Functions ────────────────────────────────────────────────────

function Test-IsInlineViolation {
    <#
    .SYNOPSIS Returns $true if the BlockedUrl string is an inline CSP indicator.
    #>
    param([string]$BlockedUrl)

    if ([string]::IsNullOrWhiteSpace($BlockedUrl)) { return $false }

    $normalized = $BlockedUrl.Trim().ToLowerInvariant()
    return $normalized -in $script:InlineIndicators
}

function Get-JsonStringValue {
    <#
    .SYNOPSIS
        Extracts a named string field value from a JSON string using regex.
        Much faster than ConvertFrom-Json for high-volume processing.
    #>
    param(
        [string]$Json,
        [string[]]$FieldNames
    )

    foreach ($name in $FieldNames) {
        $pattern = '"' + [regex]::Escape($name) + '"\s*:\s*"((?:[^"\\]|\\.)*)"'
        if ($Json -match $pattern) {
            return $matches[1] `
                -replace '\\/', '/' `
                -replace '\\"', '"' `
                -replace '\\\\', '\' `
                -replace '\\n', ' ' `
                -replace '\\r', ''
        }
    }
    return $null
}

function Format-Number {
    param([long]$n)
    return $n.ToString('N0')
}

function Get-HtmlEscaped {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return '' }
    return $s `
        -replace '&', '&amp;' `
        -replace '<', '&lt;' `
        -replace '>', '&gt;' `
        -replace '"', '&quot;'
}

#endregion

#region ── Output Path Resolution ──────────────────────────────────────────────

$csvFullPath = (Resolve-Path $CsvPath).Path
$csvDir      = Split-Path $csvFullPath -Parent
$stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not $OutputPath) {
    $OutputPath = Join-Path $csvDir "CSP_Inline_Report_$stamp.html"
}

Write-Host "`n=== SharePoint CSP Inline Violation Analyzer ===" -ForegroundColor Cyan
Write-Host "Input  : $csvFullPath"
Write-Host "Output : $OutputPath"
Write-Host "MC Ref : MC1193419`n"

#endregion

#region ── Row Counting ────────────────────────────────────────────────────────

Write-Host "Counting rows in CSV..." -ForegroundColor Yellow

$totalRows = 0
try {
    $reader = [System.IO.File]::OpenText($csvFullPath)
    $null = $reader.ReadLine()   # skip header
    while ($null -ne $reader.ReadLine()) { $totalRows++ }
    $reader.Close()
}
catch {
    Write-Warning "Could not pre-count rows: $_. Progress % will not display."
    $totalRows = 0
}

Write-Host "Total data rows: $(Format-Number $totalRows)`n" -ForegroundColor Green

#endregion

#region ── CSV Processing ──────────────────────────────────────────────────────

Write-Host "Processing CSV and extracting inline CSP violation data..." -ForegroundColor Yellow

# Data structures
# pageStats    : documentUrl  → @{ Count; Site }
# siteStats    : siteUrl      → @{ Count; Pages (HashSet) }
$pageStats     = [System.Collections.Generic.Dictionary[string, hashtable]]::new()
$siteStats     = [System.Collections.Generic.Dictionary[string, hashtable]]::new()
$dateList      = [System.Collections.Generic.List[datetime]]::new()

$processedRows   = 0
$matchedRows     = 0   # inline violations found
$skippedRows     = 0   # missing DocumentUrl or BlockedUrl
$nonInlineRows   = 0   # rows with a BlockedUrl that is not inline
$progressStep    = [Math]::Max(1, [Math]::Floor($totalRows / 100))

$hasTopLevelDocUrl    = $false
$hasTopLevelBlockUrl  = $false
$hasAuditDataCol      = $false
$columnsInspected     = $false

try {
    $csvData = Import-Csv -Path $csvFullPath -Encoding UTF8 -ErrorAction Stop
}
catch {
    Write-Error "Failed to read CSV: $_"
    exit 1
}

foreach ($row in $csvData) {

    $processedRows++

    # ── Detect columns on first row ────────────────────────────────────────
    if (-not $columnsInspected) {
        $colNames = $row.PSObject.Properties.Name

        $docUrlCol   = $colNames | Where-Object { $_ -in @('DocumentUrl','DocumentURL','documentUrl','documentURL') } | Select-Object -First 1
        $blockUrlCol = $colNames | Where-Object { $_ -in @('BlockedUrl','BlockedURL','blockedUrl','blockedURL') }     | Select-Object -First 1

        $hasTopLevelDocUrl   = $null -ne $docUrlCol
        $hasTopLevelBlockUrl = $null -ne $blockUrlCol
        $hasAuditDataCol     = $colNames -contains $AuditDataColumn

        Write-Host "  Columns detected:" -ForegroundColor DarkCyan
        Write-Host "    Top-level DocumentUrl : $hasTopLevelDocUrl  $(if($docUrlCol){"[$docUrlCol]"})"
        Write-Host "    Top-level BlockedUrl  : $hasTopLevelBlockUrl  $(if($blockUrlCol){"[$blockUrlCol]"})"
        Write-Host "    AuditData JSON column : $hasAuditDataCol  $(if($hasAuditDataCol){"[$AuditDataColumn]"})"
        Write-Host ""

        if (-not $hasTopLevelDocUrl -and -not $hasTopLevelBlockUrl -and -not $hasAuditDataCol) {
            Write-Warning "Neither top-level URL columns nor '$AuditDataColumn' column found."
            Write-Warning "Available columns: $($colNames -join ', ')"
        }

        $columnsInspected = $true
    }

    # ── Extract DocumentUrl & BlockedUrl ──────────────────────────────────
    $docUrl   = $null
    $blockUrl = $null

    if ($hasTopLevelDocUrl)   { $docUrl   = $row.$docUrlCol }
    if ($hasTopLevelBlockUrl) { $blockUrl = $row.$blockUrlCol }

    if ((-not $docUrl -or -not $blockUrl) -and $hasAuditDataCol) {
        $json = $row.$AuditDataColumn
        if (-not [string]::IsNullOrWhiteSpace($json)) {
            if (-not $docUrl) {
                $docUrl = Get-JsonStringValue -Json $json -FieldNames @(
                    'DocumentURL', 'DocumentUrl', 'documentUrl', 'documentURL',
                    'PageUrl', 'pageUrl', 'Url', 'url'
                )
            }
            if (-not $blockUrl) {
                $blockUrl = Get-JsonStringValue -Json $json -FieldNames @(
                    'BlockedURL', 'BlockedUrl', 'blockedUrl', 'blockedURL',
                    'BlockedUri', 'blockedUri', 'ViolatedSource', 'violatedSource'
                )
            }
        }
    }

    # ── Skip rows missing either value ────────────────────────────────────
    if ([string]::IsNullOrWhiteSpace($docUrl) -or [string]::IsNullOrWhiteSpace($blockUrl)) {
        $skippedRows++
        if ($processedRows % $progressStep -eq 0 -and $totalRows -gt 0) {
            $pct = [Math]::Round(($processedRows / $totalRows) * 100)
            Write-Progress -Activity "Processing inline CSP violations" `
                -Status "$pct% — Inline matches: $(Format-Number $matchedRows) | Skipped: $(Format-Number $skippedRows)" `
                -PercentComplete $pct
        }
        continue
    }

    # ── Only process inline violations ────────────────────────────────────
    if (-not (Test-IsInlineViolation -BlockedUrl $blockUrl)) {
        $nonInlineRows++
        if ($processedRows % $progressStep -eq 0 -and $totalRows -gt 0) {
            $pct = [Math]::Round(($processedRows / $totalRows) * 100)
            Write-Progress -Activity "Processing inline CSP violations" `
                -Status "$pct% — Inline matches: $(Format-Number $matchedRows) | Non-inline: $(Format-Number $nonInlineRows)" `
                -PercentComplete $pct
        }
        continue
    }

    $matchedRows++

    # ── Resolve site collection URL ────────────────────────────────────────
    $site = $docUrl
    try {
        $uri = [System.Uri]$docUrl
        $spManagedPaths = @('sites','teams','portals','personal','search','hub')
        if ($uri.Segments.Count -ge 3 -and
            ($uri.Segments[1].TrimEnd('/') -in $spManagedPaths)) {
            $site = "$($uri.Scheme)://$($uri.Host)$($uri.Segments[0])$($uri.Segments[1])$($uri.Segments[2])"
        } else {
            $site = "$($uri.Scheme)://$($uri.Host)"
        }
        $site = $site.TrimEnd('/')
    }
    catch { <# use raw docUrl #> }

    # ── Capture date ──────────────────────────────────────────────────────
    $dateStr = $null
    if ($row.PSObject.Properties['CreationDate'])  { $dateStr = $row.CreationDate }
    if (-not $dateStr -and $row.PSObject.Properties['CreationTime']) { $dateStr = $row.CreationTime }
    if (-not $dateStr -and $hasAuditDataCol) {
        $dateStr = Get-JsonStringValue -Json $row.$AuditDataColumn -FieldNames @('CreationTime','creationTime')
    }
    if ($dateStr) {
        try { $dateList.Add([datetime]::Parse($dateStr)) } catch {}
    }

    # ── Aggregate page stats ──────────────────────────────────────────────
    if (-not $pageStats.ContainsKey($docUrl)) {
        $pageStats[$docUrl] = @{ Count = 0; Site = $site }
    }
    $pageStats[$docUrl].Count++

    # ── Aggregate site stats ──────────────────────────────────────────────
    if (-not $siteStats.ContainsKey($site)) {
        $siteStats[$site] = @{
            Count = 0
            Pages = [System.Collections.Generic.HashSet[string]]::new()
        }
    }
    $siteStats[$site].Count++
    $null = $siteStats[$site].Pages.Add($docUrl)

    # ── Progress update ───────────────────────────────────────────────────
    if ($processedRows % $progressStep -eq 0 -and $totalRows -gt 0) {
        $pct = [Math]::Round(($processedRows / $totalRows) * 100)
        Write-Progress -Activity "Processing inline CSP violations" `
            -Status "$pct% — Inline matches: $(Format-Number $matchedRows) | Non-inline: $(Format-Number $nonInlineRows)" `
            -PercentComplete $pct
    }
}

Write-Progress -Activity "Processing inline CSP violations" -Completed
Write-Host "Processing complete." -ForegroundColor Green
Write-Host "  Rows processed      : $(Format-Number $processedRows)"
Write-Host "  Inline violations   : $(Format-Number $matchedRows)"
Write-Host "  Non-inline rows     : $(Format-Number $nonInlineRows)"
Write-Host "  Rows skipped        : $(Format-Number $skippedRows) (missing DocumentUrl/BlockedUrl)"
Write-Host ""

if ($matchedRows -eq 0) {
    Write-Warning "No inline CSP violation rows were found. Verify the CSV contains rows where BlockedUrl is 'inline' or 'unsafe-inline'."
    exit 0
}

#endregion

#region ── Aggregate Statistics ───────────────────────────────────────────────

$uniquePageCount = $pageStats.Count
$uniqueSiteCount = $siteStats.Count

$dateMin = if ($dateList.Count -gt 0) { ($dateList | Measure-Object -Minimum).Minimum } else { $null }
$dateMax = if ($dateList.Count -gt 0) { ($dateList | Measure-Object -Maximum).Maximum } else { $null }

$dateRangeStr = if ($dateMin -and $dateMax) {
    "$($dateMin.ToString('yyyy-MM-dd')) → $($dateMax.ToString('yyyy-MM-dd'))"
} else { 'Unknown' }

# Sort pages by violation count descending, take top N
$sortedPages = $pageStats.GetEnumerator() |
    Sort-Object { $_.Value.Count } -Descending |
    Select-Object -First $TopPages

# Sort sites by violation count descending
$sortedSites = $siteStats.GetEnumerator() |
    Sort-Object { $_.Value.Count } -Descending |
    Select-Object -First 50

#endregion

#region ── HTML Report Generation ─────────────────────────────────────────────

Write-Host "Generating HTML report..." -ForegroundColor Yellow

#── Page Table Rows ────────────────────────────────────────────────────────────
$pageTableRows = [System.Text.StringBuilder]::new()
$rank = 0
foreach ($entry in $sortedPages) {
    $rank++
    $url   = $entry.Key
    $count = $entry.Value.Count
    $site  = $entry.Value.Site

    $null = $pageTableRows.AppendLine(@"
<tr>
  <td class='rank'>$rank</td>
  <td class='url-cell'><a href='$(Get-HtmlEscaped $url)' target='_blank' rel='noopener'>$(Get-HtmlEscaped $url)</a></td>
  <td class='count-cell'>$(Format-Number $count)</td>
  <td class='site-col'><a href='$(Get-HtmlEscaped $site)' target='_blank' rel='noopener'>$(Get-HtmlEscaped $site)</a></td>
</tr>
"@)
}

#── Site Table Rows ────────────────────────────────────────────────────────────
$siteTableRows = [System.Text.StringBuilder]::new()
foreach ($entry in $sortedSites) {
    $s         = $entry.Key
    $count     = $entry.Value.Count
    $pageCount = $entry.Value.Pages.Count
    $expandId  = "siteexp_$([Math]::Abs($s.GetHashCode()))"

    $pageLinksHtml = ($entry.Value.Pages | Sort-Object | ForEach-Object {
        "<div class='site-item'><a href='$(Get-HtmlEscaped $_)' target='_blank' rel='noopener'>$(Get-HtmlEscaped $_)</a></div>"
    }) -join ''

    $null = $siteTableRows.AppendLine(@"
<tr>
  <td class='url-cell'><a href='$(Get-HtmlEscaped $s)' target='_blank' rel='noopener'>$(Get-HtmlEscaped $s)</a></td>
  <td class='count-cell'>$(Format-Number $count)</td>
  <td class='sites-cell'>
    <button class='expand-btn' onclick="toggleExpand('$expandId')">$pageCount page$(if($pageCount -ne 1){'s'}) &#9660;</button>
    <div id='$expandId' class='site-list hidden'>$pageLinksHtml</div>
  </td>
</tr>
"@)
}

#── Assemble Full HTML ─────────────────────────────────────────────────────────
$reportDate  = Get-Date -Format 'dddd, MMMM d, yyyy  HH:mm'
$csvBaseName = Split-Path $csvFullPath -Leaf

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SharePoint CSP Inline Violation Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      font-size: 14px;
      background: #f3f2f1;
      color: #323130;
      line-height: 1.5;
    }
    a { color: #0078d4; text-decoration: none; }
    a:hover { text-decoration: underline; }

    /* ── Layout ── */
    .page-header {
      background: linear-gradient(135deg, #691c32 0%, #a80000 100%);
      color: #fff;
      padding: 28px 40px 24px;
    }
    .page-header h1 { font-size: 24px; font-weight: 600; margin-bottom: 4px; }
    .page-header .subtitle { opacity: 0.85; font-size: 13px; }
    .mc-badge {
      display: inline-block;
      background: rgba(255,255,255,0.2);
      border: 1px solid rgba(255,255,255,0.4);
      border-radius: 12px;
      padding: 2px 10px;
      font-size: 12px;
      margin-left: 10px;
      vertical-align: middle;
    }
    .main { max-width: 1400px; margin: 0 auto; padding: 28px 24px 60px; }

    /* ── Summary Cards ── */
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .card {
      background: #fff;
      border-radius: 8px;
      padding: 20px 24px;
      box-shadow: 0 1px 4px rgba(0,0,0,.08);
      border-top: 4px solid #a80000;
    }
    .card.warn    { border-top-color: #d83b01; }
    .card.info    { border-top-color: #008272; }
    .card.neutral { border-top-color: #8764b8; }
    .card-value { font-size: 32px; font-weight: 700; color: #a80000; line-height: 1; margin-bottom: 4px; }
    .card.warn    .card-value { color: #d83b01; }
    .card.info    .card-value { color: #008272; }
    .card.neutral .card-value { color: #8764b8; font-size:18px; padding-top:6px; }
    .card-label { font-size: 12px; color: #605e5c; text-transform: uppercase; letter-spacing: .5px; }

    /* ── Guidance Box ── */
    .guidance-box {
      background: #fff4ce;
      border-left: 4px solid #c19c00;
      border-radius: 4px;
      padding: 16px 20px;
      margin-bottom: 28px;
      font-size: 13px;
      color: #323130;
    }
    .guidance-box h3 { font-size: 14px; font-weight: 600; color: #7d6608; margin-bottom: 10px; }
    .guidance-box ol { margin-left: 20px; margin-top: 6px; }
    .guidance-box ol li { margin-bottom: 6px; }
    .guidance-box code { background: #f3f2f1; padding: 1px 5px; border-radius: 3px; font-size: 12px; }

    /* ── Info Box ── */
    .info-box {
      background: #eff6fc;
      border-left: 4px solid #0078d4;
      border-radius: 4px;
      padding: 14px 18px;
      margin-bottom: 28px;
      font-size: 13px;
      color: #004578;
    }
    .info-box strong { font-weight: 600; }

    /* ── Section Headings ── */
    section { margin-bottom: 40px; }
    section h2 {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 4px;
      padding-bottom: 10px;
      border-bottom: 2px solid #edebe9;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .badge {
      display: inline-block;
      background: #a80000;
      color: #fff;
      border-radius: 10px;
      padding: 1px 9px;
      font-size: 11px;
      font-weight: 500;
    }
    .section-note { font-size: 12px; color: #605e5c; margin-bottom: 12px; }

    /* ── Table ── */
    .table-wrap { overflow-x: auto; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      font-size: 13px;
    }
    .data-table thead tr { background: #f3f2f1; }
    .data-table th {
      text-align: left;
      padding: 11px 14px;
      font-weight: 600;
      color: #323130;
      border-bottom: 2px solid #edebe9;
      white-space: nowrap;
      cursor: pointer;
      user-select: none;
    }
    .data-table th:hover { background: #edebe9; }
    .data-table th.sorted-asc::after  { content: ' ▲'; font-size: 10px; color: #a80000; }
    .data-table th.sorted-desc::after { content: ' ▼'; font-size: 10px; color: #a80000; }
    .data-table td {
      padding: 9px 14px;
      border-bottom: 1px solid #f3f2f1;
      vertical-align: top;
    }
    .data-table tbody tr:hover { background: #f3f2f1; }

    .rank { color: #605e5c; font-size: 12px; width: 36px; text-align: center; }
    .count-cell { font-weight: 600; text-align: right; white-space: nowrap; }
    .url-cell { word-break: break-all; }
    .site-col { font-size: 12px; word-break: break-all; color: #605e5c; }
    .sites-cell { min-width: 160px; }

    /* ── Expand Button ── */
    .expand-btn {
      background: #fff4ce;
      border: 1px solid #e8d870;
      border-radius: 4px;
      padding: 3px 10px;
      font-size: 12px;
      color: #7d6608;
      cursor: pointer;
      white-space: nowrap;
    }
    .expand-btn:hover { background: #fef0b3; }
    .site-list { margin-top: 8px; }
    .site-list.hidden { display: none; }
    .site-item { font-size: 11px; padding: 2px 0; border-bottom: 1px solid #f3f2f1; word-break: break-all; }
    .site-item:last-child { border-bottom: none; }

    /* ── Search / Filter ── */
    .table-controls { display: flex; gap: 10px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; }
    .search-box {
      border: 1px solid #c8c6c4;
      border-radius: 4px;
      padding: 6px 12px;
      font-size: 13px;
      width: 320px;
      outline: none;
    }
    .search-box:focus { border-color: #a80000; box-shadow: 0 0 0 2px rgba(168,0,0,.12); }
    .control-label { font-size: 12px; color: #605e5c; }

    /* ── Export Button ── */
    .export-btn {
      background: #a80000; color: #fff; border: none; border-radius: 4px;
      padding: 7px 18px; font-size: 13px; cursor: pointer; font-family: inherit;
    }
    .export-btn:hover { background: #691c32; }

    /* ── Footer ── */
    .report-footer {
      text-align: center;
      font-size: 11px;
      color: #a19f9d;
      padding: 20px;
      border-top: 1px solid #edebe9;
      margin-top: 40px;
    }

    @media print {
      .page-header { background: #a80000 !important; -webkit-print-color-adjust: exact; }
    }
  </style>
</head>
<body>

<header class="page-header">
  <h1>SharePoint CSP Inline Violation Report
    <span class="mc-badge">MC1193419</span>
  </h1>
  <div class="subtitle">
    Generated: $reportDate &nbsp;|&nbsp; Source: $csvBaseName
  </div>
</header>

<main class="main">

  <!-- What is inline? -->
  <div class="info-box">
    <strong>What is an inline violation?</strong>
    An inline CSP violation occurs when a SharePoint page contains an inline <code>&lt;script&gt;</code> block,
    an inline event handler (e.g. <code>onclick="..."</code>), or an inline <code>&lt;style&gt;</code> block that is
    blocked by the browser's Content Security Policy. In the Purview audit log these rows appear with
    a <strong>BlockedUrl</strong> value of <code>inline</code> or <code>unsafe-inline</code> rather than an external domain.
    Unlike external-resource violations, inline violations <strong>cannot be resolved by adding an allow-list entry</strong>
    — the offending inline code must be refactored.
  </div>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card">
      <div class="card-value">$(Format-Number $matchedRows)</div>
      <div class="card-label">Total Inline Violations</div>
    </div>
    <div class="card warn">
      <div class="card-value">$(Format-Number $uniquePageCount)</div>
      <div class="card-label">Unique Pages Affected</div>
    </div>
    <div class="card info">
      <div class="card-value">$(Format-Number $uniqueSiteCount)</div>
      <div class="card-label">Site Collections Affected</div>
    </div>
    <div class="card neutral">
      <div class="card-value">$dateRangeStr</div>
      <div class="card-label">Violation Date Range</div>
    </div>
  </div>

  <!-- DevTools Guidance -->
  <div class="guidance-box">
    <h3>&#128270; How to identify the offending inline script on each page</h3>
    <p>
      The audit log tells you <em>which page</em> has an inline violation but not <em>which script</em>
      caused it. To pinpoint the exact inline code, follow these steps for each affected DocumentUrl:
    </p>
    <ol>
      <li>Open the page URL in your browser (Chrome, Edge, or Firefox).</li>
      <li>Open <strong>Developer Tools</strong> with <code>F12</code> or <code>Ctrl+Shift+I</code>.</li>
      <li>Go to the <strong>Console</strong> tab and reload the page (<code>F5</code>).</li>
      <li>Look for red error messages containing <strong>"Content Security Policy"</strong> and <strong>"inline"</strong>.
          The console entry will show the <strong>source file and line number</strong> of the offending code.</li>
      <li>Refactor the inline code to an external <code>.js</code> / <code>.css</code> file, or remove
          inline event handlers and replace with <code>addEventListener</code> calls.</li>
    </ol>
    <p style="margin-top:10px;">
      <strong>Tip:</strong> In Edge/Chrome, the Console message includes a link — clicking it jumps directly
      to the <strong>Sources</strong> panel at the exact violating line.
    </p>
  </div>

  <!-- Top Affected Pages -->
  <section id="pages">
    <h2>Affected Pages <span class="badge">Top $TopPages of $(Format-Number $uniquePageCount) unique pages</span></h2>
    <p class="section-note">
      Each row is a SharePoint page (DocumentUrl) that generated at least one inline CSP violation.
      Pages with the highest violation count should be prioritized. Click any link to open the page
      and use browser Developer Tools to identify the offending script.
    </p>
    <div class="table-controls">
      <input type="text" class="search-box" id="pageSearch" placeholder="&#128269;  Search pages or sites..." oninput="filterTable('pageTable','pageSearch')">
      <span class="control-label">$(Format-Number $matchedRows) total inline violations across $(Format-Number $uniquePageCount) pages</span>
      <button class="export-btn" onclick="exportCsv()">&#128229; Export as CSV</button>
    </div>
    <div class="table-wrap">
      <table id="pageTable" class="data-table">
        <thead>
          <tr>
            <th class="rank" onclick="sortTable('pageTable',0)">#</th>
            <th onclick="sortTable('pageTable',1)">DocumentUrl (Affected Page)</th>
            <th onclick="sortTable('pageTable',2)" class="sorted-desc">Inline Violations</th>
            <th onclick="sortTable('pageTable',3)">Site Collection</th>
          </tr>
        </thead>
        <tbody>
          $($pageTableRows.ToString())
        </tbody>
      </table>
    </div>
  </section>

  <!-- Site Collections Summary -->
  <section id="sites">
    <h2>Site Collections Affected <span class="badge">Top 50 of $(Format-Number $uniqueSiteCount)</span></h2>
    <p class="section-note">
      Site collections ranked by total inline violations. Click the page count button to see
      which specific pages within that site collection are affected.
    </p>
    <div class="table-controls">
      <input type="text" class="search-box" id="siteSearch" placeholder="&#128269;  Search sites..." oninput="filterTable('siteTable','siteSearch')">
    </div>
    <div class="table-wrap">
      <table id="siteTable" class="data-table">
        <thead>
          <tr>
            <th onclick="sortTable('siteTable',0)">Site Collection URL</th>
            <th onclick="sortTable('siteTable',1)" class="sorted-desc">Total Inline Violations</th>
            <th>Affected Pages</th>
          </tr>
        </thead>
        <tbody>
          $($siteTableRows.ToString())
        </tbody>
      </table>
    </div>
  </section>

</main>

<footer class="report-footer">
  SharePoint CSP Inline Violation Report &nbsp;|&nbsp; Source: $csvBaseName &nbsp;|&nbsp;
  Generated on $reportDate &nbsp;|&nbsp; MC1193419
</footer>

<script>
  /* ── Table Sort ── */
  function sortTable(tableId, colIndex) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const rows  = Array.from(tbody.querySelectorAll('tr'));
    const th    = table.querySelectorAll('thead th')[colIndex];
    const asc   = !th.classList.contains('sorted-asc');

    table.querySelectorAll('thead th').forEach(h => {
      h.classList.remove('sorted-asc', 'sorted-desc');
    });
    th.classList.add(asc ? 'sorted-asc' : 'sorted-desc');

    rows.sort((a, b) => {
      const aText = a.cells[colIndex] ? a.cells[colIndex].innerText.trim() : '';
      const bText = b.cells[colIndex] ? b.cells[colIndex].innerText.trim() : '';
      const aNum  = parseFloat(aText.replace(/[,%]/g, ''));
      const bNum  = parseFloat(bText.replace(/[,%]/g, ''));
      if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
      return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
    });

    rows.forEach(r => tbody.appendChild(r));
  }

  /* ── Search Filter ── */
  function filterTable(tableId, inputId) {
    const filter = document.getElementById(inputId).value.toLowerCase();
    const rows   = document.getElementById(tableId).querySelectorAll('tbody tr');
    rows.forEach(r => {
      r.style.display = r.innerText.toLowerCase().includes(filter) ? '' : 'none';
    });
  }

  /* ── Expand/Collapse ── */
  function toggleExpand(id) {
    const el  = document.getElementById(id);
    const btn = el.previousElementSibling;
    if (el.classList.toggle('hidden')) {
      btn.innerHTML = btn.innerHTML.replace('&#9650;', '&#9660;');
    } else {
      btn.innerHTML = btn.innerHTML.replace('&#9660;', '&#9650;');
    }
  }

  /* ── Export page table as CSV ── */
  function exportCsv() {
    const rows  = document.querySelectorAll('#pageTable tbody tr');
    const lines = ['Rank,DocumentUrl,InlineViolations,SiteCollection'];
    rows.forEach(r => {
      const cells = r.querySelectorAll('td');
      if (cells.length < 4) return;
      const rank   = cells[0].innerText.trim();
      const url    = cells[1].innerText.trim().replace(/,/g,'%2C');
      const count  = cells[2].innerText.trim().replace(/,/g,'');
      const site   = cells[3].innerText.trim().replace(/,/g,'%2C');
      lines.push([rank, url, count, site].join(','));
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = 'csp_inline_violations.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }
</script>
</body>
</html>
"@

#endregion

#region ── Write Report ────────────────────────────────────────────────────────

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

$reportSize = (Get-Item $OutputPath).Length / 1KB

Write-Host "`nReport written successfully!" -ForegroundColor Green
Write-Host "  Path : $OutputPath"
Write-Host "  Size : $([Math]::Round($reportSize, 1)) KB"
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Total inline violations  : $(Format-Number $matchedRows)"
Write-Host "  Unique pages affected    : $(Format-Number $uniquePageCount)"
Write-Host "  Site collections affected: $(Format-Number $uniqueSiteCount)"
Write-Host "  Date range               : $dateRangeStr"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open the HTML report and review each affected DocumentUrl."
Write-Host "  2. For each page, open it in a browser with Developer Tools (F12) → Console."
Write-Host "  3. Reload the page and look for CSP 'inline' violation messages."
Write-Host "  4. Refactor the identified inline scripts/styles to external files."
Write-Host ""

try {
    Start-Process $OutputPath
    Write-Host "Report opened in your default browser." -ForegroundColor Green
}
catch {
    Write-Host "Open the report manually: $OutputPath" -ForegroundColor Yellow
}

#endregion
