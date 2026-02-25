<#
.SYNOPSIS
    Analyzes SharePoint CSP violation audit data exported from Microsoft Purview.

.DESCRIPTION
    Parses large CSV audit log exports from Microsoft Purview, extracts CSP
    violation data (DocumentUrl / BlockedUrl), aggregates violations by blocked
    domain, and generates a standalone interactive HTML report for SharePoint
    Administrators.

    Designed to handle exports with 100,000+ rows efficiently by using fast
    regex-based JSON field extraction rather than per-row ConvertFrom-Json calls.

    Relevant Message Center notification: MC1193419
    (SharePoint Online Content Security Policy enforcement changes)

.PARAMETER CsvPath
    Path to the Purview audit log CSV export file (.csv).

.PARAMETER OutputPath
    Path for the generated HTML report file.
    Defaults to the same directory as the CSV with a timestamped filename.

.PARAMETER TopDomains
    Number of top blocked domains to feature in the summary table. Default: 20.

.PARAMETER IncludeFullUrls
    Include full BlockedUrl values in the report in addition to domain grouping.
    WARNING: May significantly increase report file size on large datasets.

.EXAMPLE
    .\Analyze-CSPViolations.ps1 -CsvPath "C:\Exports\purview_audit.csv"

.EXAMPLE
    .\Analyze-CSPViolations.ps1 -CsvPath ".\audit.csv" -OutputPath ".\report.html" -TopDomains 30

.EXAMPLE
    .\Analyze-CSPViolations.ps1 -CsvPath ".\audit.csv" -IncludeFullUrls

.NOTES
    Author  : Mike Lee
    Version : 1.4.0 Minor updates for better JSON parsing and additional stats, add well-known CDN path overrides, 
                                added option to copy full URLs to allow-list details for manual review.
    Date    : 2/23/2026
    Updated : 2/25/2026
    Tested  : PowerShell 5.1, PowerShell 7+

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

    [Parameter(HelpMessage = 'Number of top blocked domains to show in the summary.')]
    [ValidateRange(1, 200)]
    [int]$TopDomains = 20,

    [Parameter(HelpMessage = 'Include full BlockedUrl values in the report (increases file size).')]
    [switch]$IncludeFullUrls
)

# The Purview audit export always uses 'AuditData' as the JSON column name.
$AuditDataColumn = 'AuditData'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helper Functions ────────────────────────────────────────────────────

function Get-UrlDomain {
    <#
    .SYNOPSIS Extracts the hostname from a URL string. Returns $null on failure.
    #>
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }

    # Remove CSP source expressions that are not real URLs
    if ($Url -match "^'|^data:|^blob:|^about:|^\*") { return $Url.Trim("'") }

    try {
        $uri = [System.Uri]$Url
        if ($uri.Host) { return $uri.Host.ToLowerInvariant() }
    }
    catch {
        # Fallback: try to extract domain with regex
        if ($Url -match '(?:https?://)?([^/:?#]+)') {
            return $matches[1].ToLowerInvariant()
        }
    }
    return $Url
}

function Get-JsonStringValue {
    <#
    .SYNOPSIS
        Extracts a named string field value from a JSON string using regex.
        Much faster than ConvertFrom-Json for high-volume processing.
        Handles both "fieldName" and case-insensitive variants.
    #>
    param(
        [string]$Json,
        [string[]]$FieldNames   # Try each name in order; return first match
    )

    foreach ($name in $FieldNames) {
        # Match: "FieldName"  :  "value"  (handles escaped chars in value)
        $pattern = '"' + [regex]::Escape($name) + '"\s*:\s*"((?:[^"\\]|\\.)*)"'
        if ($Json -match $pattern) {
            # Unescape common JSON escape sequences
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
$csvDir = Split-Path $csvFullPath -Parent
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not $OutputPath) {
    $OutputPath = Join-Path $csvDir "CSP_Report_$stamp.html"
}

Write-Host "`n=== SharePoint CSP Violation Analyzer ===" -ForegroundColor Cyan
Write-Host "Input  : $csvFullPath"
Write-Host "Output : $OutputPath"
Write-Host "MC Ref : MC1193419`n"

#endregion

#region ── Row Counting (progress denominator) ────────────────────────────────

Write-Host "Counting rows in CSV (this may take a moment for large files)..." -ForegroundColor Yellow

$totalRows = 0
try {
    $reader = [System.IO.File]::OpenText($csvFullPath)
    # Skip header
    $null = $reader.ReadLine()
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

Write-Host "Processing CSV and extracting CSP violation data..." -ForegroundColor Yellow

# Data structures
$domainStats = [System.Collections.Generic.Dictionary[string, hashtable]]::new()
$siteDomainMap = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]]::new()
$blockedUrlsByHost = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]]::new()
$fullUrlPairs = [System.Collections.Generic.List[hashtable]]::new()   # Only if -IncludeFullUrls
$dateList = [System.Collections.Generic.List[datetime]]::new()
$spTenantHostCount = [System.Collections.Generic.Dictionary[string, int]]::new()  # tracks DocumentUrl *.sharepoint.com hosts

$processedRows = 0
$matchedRows = 0
$skippedRows = 0
$cspKeywordRows = 0
$progressStep = [Math]::Max(1, [Math]::Floor($totalRows / 100))  # Update every 1%

# CSP special keywords / pseudo-domains that are NOT real external hostnames.
# BlockedUrl values like 'inline', 'eval', about:blank, or Microsoft's
# 'relative-path.invalid' sentinel appear as domain names if not filtered out.
# They inflate the unique-domain count and can crowd real domains out of the
# TopDomains summary table or the allow-list.
$cspPseudoDomains = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('inline', 'eval', 'unsafe-inline', 'unsafe-eval', 'self', 'none',
        'wasm-unsafe-eval', 'strict-dynamic', 'report-sample',
        'data', 'blob', 'about', 'about:blank',
        'localhost', 'relative-path.invalid',
        '(unknown)'),
    [System.StringComparer]::OrdinalIgnoreCase)

# Column presence flags (determined on first row)
$hasTopLevelDocUrl = $false
$hasTopLevelBlockUrl = $false
$hasAuditDataCol = $false
$columnsInspected = $false

try {
    $csvData = Import-Csv -Path $csvFullPath -Encoding UTF8 -ErrorAction Stop
}
catch {
    Write-Error "Failed to read CSV: $_"
    exit 1
}

foreach ($row in $csvData) {

    $processedRows++

    # ── Detect available columns on first row ──────────────────────────────
    if (-not $columnsInspected) {
        $colNames = $row.PSObject.Properties.Name

        # Check for top-level URL columns (various casings)
        $docUrlCol = $colNames | Where-Object { $_ -in @('DocumentUrl', 'DocumentURL', 'documentUrl', 'documentURL') } | Select-Object -First 1
        $blockUrlCol = $colNames | Where-Object { $_ -in @('BlockedUrl', 'BlockedURL', 'blockedUrl', 'blockedURL') }     | Select-Object -First 1

        $hasTopLevelDocUrl = $null -ne $docUrlCol
        $hasTopLevelBlockUrl = $null -ne $blockUrlCol
        $hasAuditDataCol = $colNames -contains $AuditDataColumn

        Write-Host "  Columns detected:" -ForegroundColor DarkCyan
        Write-Host "    Top-level DocumentUrl : $hasTopLevelDocUrl  $(if($docUrlCol){"[$docUrlCol]"})"
        Write-Host "    Top-level BlockedUrl  : $hasTopLevelBlockUrl  $(if($blockUrlCol){"[$blockUrlCol]"})"
        Write-Host "    AuditData JSON column : $hasAuditDataCol  $(if($hasAuditDataCol){"[$AuditDataColumn]"})"
        Write-Host ""

        if (-not $hasTopLevelDocUrl -and -not $hasTopLevelBlockUrl -and -not $hasAuditDataCol) {
            Write-Warning "Neither top-level URL columns nor '$AuditDataColumn' column found in this CSV."
            Write-Warning "Available columns: $($colNames -join ', ')"
        }

        $columnsInspected = $true
    }

    # ── Extract DocumentUrl & BlockedUrl ──────────────────────────────────
    $docUrl = $null
    $blockUrl = $null

    if ($hasTopLevelDocUrl) { $docUrl = $row.$docUrlCol }
    if ($hasTopLevelBlockUrl) { $blockUrl = $row.$blockUrlCol }

    # Fall back to / supplement from AuditData JSON if needed
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

    # ── Skip rows without both values ─────────────────────────────────────
    if ([string]::IsNullOrWhiteSpace($docUrl) -or [string]::IsNullOrWhiteSpace($blockUrl)) {
        $skippedRows++
        if ($processedRows % $progressStep -eq 0 -and $totalRows -gt 0) {
            $pct = [Math]::Round(($processedRows / $totalRows) * 100)
            Write-Progress -Activity "Processing CSP violations" `
                -Status "$pct% complete — Matched: $(Format-Number $matchedRows) | Skipped: $(Format-Number $skippedRows)" `
                -PercentComplete $pct
        }
        continue
    }

    $matchedRows++

    # ── Extract domain from BlockedUrl ────────────────────────────────────
    $domain = Get-UrlDomain -Url $blockUrl
    if (-not $domain) { $domain = '(unknown)' }

    # ── Skip CSP special keywords & pseudo-domains ───────────────────────
    # Values like 'inline', 'eval', about:blank, relative-path.invalid, and
    # localhost are CSP directive keywords or Microsoft sentinels – not real
    # external hostnames.  Counting them as domains inflates ranking and can
    # push legitimate blocked domains out of the TopDomains summary table.
    if ($cspPseudoDomains.Contains($domain) -or $domain -match '^nonce-|^sha256-|^sha384-|^sha512-') {
        $cspKeywordRows++
        continue
    }

    # ── Extract SP site collection URL ────────────────────────────────────
    # SharePoint managed paths (/sites/, /teams/, etc.) are 2 segments deep,
    # so the site collection is always: scheme://host/managedpath/sitename
    # Root sites live at scheme://host with no managed path.
    $site = $docUrl
    try {
        $uri = [System.Uri]$docUrl
        $spManagedPaths = @('sites', 'teams', 'portals', 'personal', 'search', 'hub')
        if ($uri.Segments.Count -ge 3 -and
            ($uri.Segments[1].TrimEnd('/') -in $spManagedPaths)) {
            # Named site collection: take scheme://host/managedpath/sitename
            $site = "$($uri.Scheme)://$($uri.Host)$($uri.Segments[0])$($uri.Segments[1])$($uri.Segments[2])"
        }
        else {
            # Root site collection
            $site = "$($uri.Scheme)://$($uri.Host)"
        }
        $site = $site.TrimEnd('/')

        # Track the tenant hostname for CDN scoping (public-cdn / publiccdn)
        $th = $uri.Host.ToLowerInvariant()
        if ($th -like '*.sharepoint.com') {
            if ($spTenantHostCount.ContainsKey($th)) { $spTenantHostCount[$th]++ }
            else { $spTenantHostCount[$th] = 1 }
        }
    }
    catch { <# use raw docUrl #> }

    # ── Capture date ──────────────────────────────────────────────────────
    $dateStr = $null
    if ($row.PSObject.Properties['CreationDate']) { $dateStr = $row.CreationDate }
    if (-not $dateStr -and $row.PSObject.Properties['CreationTime']) { $dateStr = $row.CreationTime }
    if (-not $dateStr -and $hasAuditDataCol) {
        $dateStr = Get-JsonStringValue -Json $row.$AuditDataColumn -FieldNames @('CreationTime', 'creationTime')
    }
    if ($dateStr) {
        try { $dateList.Add([datetime]::Parse($dateStr)) } catch {}
    }

    # ── Aggregate domain stats ────────────────────────────────────────────
    if (-not $domainStats.ContainsKey($domain)) {
        $domainStats[$domain] = @{ Count = 0; Sites = [System.Collections.Generic.HashSet[string]]::new() }
    }
    $domainStats[$domain].Count++
    $null = $domainStats[$domain].Sites.Add($site)

    # ── Track full BlockedUrls per host (for path-prefix allow-list) ──────
    if (-not $blockedUrlsByHost.ContainsKey($domain)) {
        $blockedUrlsByHost[$domain] = [System.Collections.Generic.HashSet[string]]::new()
    }
    $null = $blockedUrlsByHost[$domain].Add($blockUrl)

    # ── Track site→domain mapping ─────────────────────────────────────────
    if (-not $siteDomainMap.ContainsKey($site)) {
        $siteDomainMap[$site] = [System.Collections.Generic.HashSet[string]]::new()
    }
    $null = $siteDomainMap[$site].Add($domain)

    # ── Optionally store full URL pairs ───────────────────────────────────
    if ($IncludeFullUrls) {
        $fullUrlPairs.Add(@{ DocumentUrl = $docUrl; BlockedUrl = $blockUrl; Domain = $domain; Site = $site })
    }

    # ── Progress update ───────────────────────────────────────────────────
    if ($processedRows % $progressStep -eq 0 -and $totalRows -gt 0) {
        $pct = [Math]::Round(($processedRows / $totalRows) * 100)
        Write-Progress -Activity "Processing CSP violations" `
            -Status "$pct% complete — Matched: $(Format-Number $matchedRows) | Skipped: $(Format-Number $skippedRows)" `
            -PercentComplete $pct
    }
}

Write-Progress -Activity "Processing CSP violations" -Completed
Write-Host "Processing complete." -ForegroundColor Green
Write-Host "  Rows processed : $(Format-Number $processedRows)"
Write-Host "  Rows matched   : $(Format-Number $matchedRows)"
Write-Host "  Rows skipped   : $(Format-Number $skippedRows) (no DocumentUrl/BlockedUrl found)"
Write-Host "  CSP keywords   : $(Format-Number $cspKeywordRows) (inline/eval/blob/relative-path etc. — not real domains, excluded from stats)"
Write-Host ""

if ($matchedRows -eq 0) {
    Write-Warning "No CSP violation rows were matched. Verify that the CSV was exported from Purview with the AuditData column present."
    exit 0
}

#endregion

#region ── Aggregate Statistics ───────────────────────────────────────────────

$sortedDomains = $domainStats.GetEnumerator() |
Sort-Object { $_.Value.Count } -Descending |
Select-Object -First $TopDomains

$uniqueDomainCount = $domainStats.Count
$uniqueSiteCount = $siteDomainMap.Count

$dateMin = if ($dateList.Count -gt 0) { ($dateList | Measure-Object -Minimum).Minimum } else { $null }
$dateMax = if ($dateList.Count -gt 0) { ($dateList | Measure-Object -Maximum).Maximum } else { $null }

$dateRangeStr = if ($dateMin -and $dateMax) {
    "$($dateMin.ToString('yyyy-MM-dd')) → $($dateMax.ToString('yyyy-MM-dd'))"
}
else { 'Unknown' }

#── Build Minimized Script-Source Allow-List ───────────────────────────────────
# Strategy (no wildcards in hostnames — not supported by SharePoint CSP policy):
#   1. Group all unique BlockedUrls by hostname.
#   2. Single URL from a host → entry is just the origin  (scheme://host/)
#      This is sufficient and avoids exposing unnecessary path specifics.
#   3. Multiple URLs from a host → compute the longest common path prefix
#      shared by all of them, truncated to the last /.
#      e.g. 10 files all under /player/lib/v1.2.3/ → https://cdn.example.com/player/lib/v1.2.3/
#      e.g. files spread across many paths    → falls back to https://cdn.example.com/
#   4. Deduplicate final entries (one prefix may cover another).
# Result: a minimal, ordered list of CSP script-src URL prefixes.

function Get-CspAllowEntry {
    <#
    .SYNOPSIS
        Returns the minimal CSP script-src URL prefix for a set of BlockedUrls
        that all share the same hostname.
    #>
    param([string[]]$Urls)

    # Strip query strings and fragments; deduplicate
    # @() forces array so $clean[0] is always an element, never a character
    $clean = @($Urls |
        ForEach-Object { ($_ -split '[?#]')[0].TrimEnd('/') } |
        Sort-Object -Unique)

    # Parse first URL to establish the origin
    try { $first = [System.Uri]$clean[0] }
    catch { return $clean[0] }               # unparseable – return as-is

    $origin = "$($first.Scheme)://$($first.Host)"

    # Single distinct URL → origin only
    if ($clean.Count -eq 1) { return "$origin/" }

    # Multiple URLs → find longest common path prefix
    # @() forces array so $paths[0] is always an element, never a character
    $paths = @($clean | ForEach-Object {
            try { ([System.Uri]$_).AbsolutePath } catch { '/' }
        })

    $commonPath = $paths[0]
    foreach ($p in $paths[1..($paths.Count - 1)]) {
        $maxLen = [Math]::Min($commonPath.Length, $p.Length)
        $commonLen = 0
        for ($i = 0; $i -lt $maxLen; $i++) {
            if ($commonPath[$i] -eq $p[$i]) { $commonLen++ } else { break }
        }
        $commonPath = $commonPath.Substring(0, $commonLen)
    }

    # Truncate to folder boundary (last /)
    $lastSlash = $commonPath.LastIndexOf('/')
    $folderPath = if ($lastSlash -le 0) { '/' } else { $commonPath.Substring(0, $lastSlash + 1) }

    return "$origin$folderPath"
}

# Determine the primary SP tenant hostname from DocumentUrl values.
# The most-seen *.sharepoint.com host is used to scope public-cdn and publiccdn
# allow-list entries to this tenant rather than trusting the full CDN domain.
$spTenantHost = if ($spTenantHostCount.Count -gt 0) {
    ($spTenantHostCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
}
else { $null }
if ($spTenantHost) {
    Write-Host "  SP tenant host       : $spTenantHost (used to scope SharePoint CDN entries)" -ForegroundColor DarkCyan
}

$allowList = [System.Collections.Generic.List[string]]::new()
$allowListDetails = [System.Collections.Generic.List[hashtable]]::new()

# Well-known domain path overrides.
# For certain hostnames the automatic common-path computation produces entries
# that are either too broad (origin-only when there is only one tag/asset URL)
# or unnecessarily deep (locking in a specific asset version or tag ID).
# Each entry maps a hostname → the fixed CSP URL prefix that should always be
# used for that host, regardless of the specific URLs seen in the audit data.
#
# Add new entries here as more well-known CDNs are identified.
$wellKnownPathOverrides = @{
    # Clarity tag IDs are unique per site/customer (e.g. /tag/jxmt8etn16).
    # Trusting the full domain is intentional: it covers all current and future
    # managed paths without tying the entry to a specific tag ID or path segment.
    'www.clarity.ms' = 'https://www.clarity.ms/'
}

foreach ($hostname in ($blockedUrlsByHost.Keys | Sort-Object)) {
    $urls = @($blockedUrlsByHost[$hostname])

    # Well-known overrides take highest priority.
    if ($wellKnownPathOverrides.ContainsKey($hostname)) {
        $entry = $wellKnownPathOverrides[$hostname]
    }
    # public-cdn.sharepointonline.com and publiccdn.sharepointonline.com serve
    # tenant-specific cached assets under a path matching the tenant hostname.
    # Scope the allow-list entry to that path rather than allowing the whole CDN
    # (which would cover every other tenant's assets too).
    elseif ($hostname -in @('public-cdn.sharepointonline.com', 'publiccdn.sharepointonline.com') -and $spTenantHost) {
        $entry = "https://$hostname/$spTenantHost/"
    }
    else {
        $entry = Get-CspAllowEntry -Urls $urls
    }
    $allowList.Add($entry)
    $allowListDetails.Add(@{
            UrlPrefix  = $entry
            Hostname   = $hostname
            Violations = $domainStats[$hostname].Count
            SiteCount  = $domainStats[$hostname].Sites.Count
            Sites      = $domainStats[$hostname].Sites
            UrlCount   = $urls.Count
        })
}

# Deduplicate: remove any entry that is a prefix of another entry
# (e.g. if https://cdn.example.com/ and https://cdn.example.com/v2/ are both present,
#  the more specific one is redundant — the shorter prefix already covers it)
# @() ensures this is always an array even when only one entry survives
$allowList = @($allowList | Sort-Object | Where-Object {
        $candidate = $_
        -not ($allowList | Where-Object { $_ -ne $candidate -and $candidate.StartsWith($_) })
    } | Sort-Object)

# Filter details to match surviving entries; sort by violation count descending
$allowListDetails = @($allowListDetails |
    Where-Object { $allowList -contains $_.UrlPrefix } |
    Sort-Object { $_.Violations } -Descending)

$allowListCount = @($allowList).Count
$allowListPct = [Math]::Round(($allowListCount / 300) * 100, 1)
$allowListStatus = if ($allowListCount -le 20) { 'good' } elseif ($allowListCount -le 100) { 'warn' } else { 'bad' }

Write-Host "  Allow-list entries   : $allowListCount (of 300 tenant limit)" -ForegroundColor $(
    if ($allowListStatus -eq 'good') { 'Green' } elseif ($allowListStatus -eq 'warn') { 'Yellow' } else { 'Red' }
)

#endregion

#region ── HTML Report Generation ─────────────────────────────────────────────

Write-Host "Generating HTML report..." -ForegroundColor Yellow

#── Remediation Checklist Rows ────────────────────────────────────────────────
$remediationRows = [System.Text.StringBuilder]::new()
$remRank = 0
foreach ($detail in $allowListDetails) {
    $remRank++
    $rowId = "rem_$remRank"
    $prefix = $detail.UrlPrefix
    $hostname = $detail.Hostname
    $viol = Format-Number $detail.Violations
    $siteCnt = $detail.SiteCount
    $urlCnt = $detail.UrlCount

    $siteLinksHtml = ($detail.Sites | Sort-Object | ForEach-Object {
            "<div class='site-item'><a href='$(Get-HtmlEscaped $_)' target='_blank' rel='noopener'>$(Get-HtmlEscaped $_)</a></div>"
        }) -join ''
    $expandId = "remexp_$remRank"

    $null = $remediationRows.AppendLine(@"
<tr id="$rowId" class="rem-row">
  <td class="chk-cell"><input type="checkbox" class="rem-chk" onchange="markDone('$rowId',this)" title="Mark as reviewed"></td>
  <td class="prefix-cell"><code>$(Get-HtmlEscaped $prefix)</code></td>
  <td class="count-cell">$viol</td>
  <td class="sites-cell">
    <button class="expand-btn" onclick="toggleSites('$expandId')">$siteCnt site$(if($siteCnt -ne 1){'s'}) &#9660;</button>
    <div id="$expandId" class="site-list hidden">$siteLinksHtml</div>
  </td>
  <td class="urlcount-cell">$urlCnt</td>
  <td class="dec-cell">
    <div class="dec-btns">
      <button class="dec-btn dec-allow"       onclick="setDecision('$rowId','allow')">&#10003;&nbsp;Allow</button>
      <button class="dec-btn dec-remove"      onclick="setDecision('$rowId','remove')">&#10007;&nbsp;Remove</button>
      <button class="dec-btn dec-investigate" onclick="setDecision('$rowId','investigate')">&#63;&nbsp;Review</button>
    </div>
    <span class="dec-label" id="${rowId}_label"></span>
  </td>
</tr>
"@)
}

$domainTableRows = [System.Text.StringBuilder]::new()
$rank = 0
foreach ($entry in $sortedDomains) {
    $rank++
    $d = $entry.Key
    $count = $entry.Value.Count
    $sitesSet = $entry.Value.Sites
    $pct = [Math]::Round(($count / $matchedRows) * 100, 1)
    $barWidth = [Math]::Max(1, [Math]::Round($pct))

    $siteListHtml = ($sitesSet | Sort-Object | ForEach-Object {
            "<div class='site-item'><a href='$(Get-HtmlEscaped $_)' target='_blank' rel='noopener'>$(Get-HtmlEscaped $_)</a></div>"
        }) -join ''

    $expandId = "expand_$rank"

    $null = $domainTableRows.AppendLine(@"
<tr>
  <td class='rank'>$rank</td>
  <td class='domain-cell'>
    <span class='domain-name'>$(Get-HtmlEscaped $d)</span>
  </td>
  <td class='count-cell'>$(Format-Number $count)</td>
  <td class='pct-cell'>
    <div class='bar-wrap'>
      <div class='bar' style='width:$($barWidth)%'></div>
      <span class='pct-label'>$pct%</span>
    </div>
  </td>
  <td class='sites-cell'>
    <button class='expand-btn' onclick="toggleSites('$expandId')">
      $($sitesSet.Count) site$(if($sitesSet.Count -ne 1){'s'}) &#9660;
    </button>
    <div id='$expandId' class='site-list hidden'>$siteListHtml</div>
  </td>
</tr>
"@)
}

#── Site Summary Table Rows ────────────────────────────────────────────────────
$siteTableRows = [System.Text.StringBuilder]::new()
$siteDomainMap.GetEnumerator() |
Sort-Object { $_.Value.Count } -Descending |
Select-Object -First 50 |
ForEach-Object {
    $s = $_.Key
    $domainList = ($_.Value | Sort-Object) -join ', '
    $null = $siteTableRows.AppendLine(@"
<tr>
  <td><a href='$(Get-HtmlEscaped $s)' target='_blank' rel='noopener'>$(Get-HtmlEscaped $s)</a></td>
  <td class='count-cell'>$($_.Value.Count)</td>
  <td class='domain-list-cell'>$(Get-HtmlEscaped $domainList)</td>
</tr>
"@)
}

#── Full URL Pairs Table (optional) ───────────────────────────────────────────
$fullUrlSection = ''
if ($IncludeFullUrls -and $fullUrlPairs.Count -gt 0) {
    $fullRows = [System.Text.StringBuilder]::new()
    $fullUrlPairs |
    Sort-Object { $_['Domain'] } |
    ForEach-Object {
        $null = $fullRows.AppendLine(@"
<tr>
  <td class='url-cell'><a href='$(Get-HtmlEscaped $_["DocumentUrl"])' target='_blank' rel='noopener'>$(Get-HtmlEscaped $_["DocumentUrl"])</a></td>
  <td class='url-cell'><a href='$(Get-HtmlEscaped $_["BlockedUrl"])' target='_blank' rel='noopener'>$(Get-HtmlEscaped $_["BlockedUrl"])</a></td>
  <td>$(Get-HtmlEscaped $_["Domain"])</td>
</tr>
"@)
    }

    $fullUrlSection = @"
<section id='full-urls'>
  <h2>Full URL Pair Details <span class='badge'>$(Format-Number $fullUrlPairs.Count) rows</span></h2>
  <p class='section-note'>All DocumentUrl → BlockedUrl pairs extracted from the audit data.</p>
  <div class='table-wrap'>
    <table id='fullUrlTable' class='data-table sortable'>
      <thead>
        <tr>
          <th>DocumentUrl (SharePoint Page)</th>
          <th>BlockedUrl (Blocked Resource)</th>
          <th>Blocked Domain</th>
        </tr>
      </thead>
      <tbody>
        $($fullRows.ToString())
      </tbody>
    </table>
  </div>
</section>
"@
}

#── Assemble Full HTML ─────────────────────────────────────────────────────────
$reportDate = Get-Date -Format 'dddd, MMMM d, yyyy  HH:mm'
$csvBaseName = Split-Path $csvFullPath -Leaf

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SharePoint CSP Violation Report</title>
  <style>
    /* ── Reset & Base ── */
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
      background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
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
      border-top: 4px solid #0078d4;
    }
    .card.warn  { border-top-color: #d83b01; }
    .card.info  { border-top-color: #008272; }
    .card.neutral { border-top-color: #8764b8; }
    .card-value { font-size: 32px; font-weight: 700; color: #0078d4; line-height: 1; margin-bottom: 4px; }
    .card.warn  .card-value { color: #d83b01; }
    .card.info  .card-value { color: #008272; }
    .card.neutral .card-value { color: #8764b8; }
    .card-label { font-size: 12px; color: #605e5c; text-transform: uppercase; letter-spacing: .5px; }

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
      background: #0078d4;
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
    .data-table th.sorted-asc::after  { content: ' ▲'; font-size: 10px; color: #0078d4; }
    .data-table th.sorted-desc::after { content: ' ▼'; font-size: 10px; color: #0078d4; }
    .data-table td {
      padding: 9px 14px;
      border-bottom: 1px solid #f3f2f1;
      vertical-align: top;
    }
    .data-table tbody tr:hover { background: #f3f2f1; }

    /* ── Domain Table Specifics ── */
    .rank { color: #605e5c; font-size: 12px; width: 36px; text-align: center; }
    .domain-name { font-weight: 600; font-size: 13px; }
    .count-cell { font-weight: 600; text-align: right; white-space: nowrap; }
    .pct-cell { min-width: 140px; }
    .bar-wrap { display: flex; align-items: center; gap: 8px; }
    .bar { height: 8px; background: #0078d4; border-radius: 4px; min-width: 2px; flex-shrink: 0; }
    .pct-label { font-size: 12px; color: #605e5c; white-space: nowrap; }
    .sites-cell { min-width: 160px; }

    /* ── Expand Button ── */
    .expand-btn {
      background: #eff6fc;
      border: 1px solid #c7e0f4;
      border-radius: 4px;
      padding: 3px 10px;
      font-size: 12px;
      color: #0078d4;
      cursor: pointer;
      white-space: nowrap;
    }
    .expand-btn:hover { background: #deecf9; }
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
      width: 280px;
      outline: none;
    }
    .search-box:focus { border-color: #0078d4; box-shadow: 0 0 0 2px rgba(0,120,212,.15); }
    .control-label { font-size: 12px; color: #605e5c; }

    /* ── Allow-List ── */
    .allowlist-wrap { background:#fff; border-radius:8px; box-shadow:0 1px 4px rgba(0,0,0,.08); padding:20px 24px; }
    .allowlist-header { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; margin-bottom:14px; }
    .copy-btn { background:#0078d4; color:#fff; border:none; border-radius:4px; padding:7px 18px; font-size:13px; cursor:pointer; font-family:inherit; display:flex; align-items:center; gap:6px; }
    .copy-btn:hover { background:#005a9e; }
    .copy-btn.copied { background:#107c10; }
    .usage-bar-wrap { display:flex; align-items:center; gap:10px; margin-bottom:16px; }
    .usage-bar-track { flex:1; height:10px; background:#edebe9; border-radius:5px; overflow:hidden; }
    .usage-bar-fill { height:100%; border-radius:5px; }
    .usage-bar-fill.good { background:#107c10; }
    .usage-bar-fill.warn { background:#c19c00; }
    .usage-bar-fill.bad  { background:#d83b01; }
    .usage-note { font-size:12px; white-space:nowrap; }
    .usage-note.good { color:#107c10; font-weight:600; }
    .usage-note.warn { color:#c19c00; font-weight:600; }
    .usage-note.bad  { color:#d83b01; font-weight:600; }
    .chips { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; }
    .chip { background:#eff6fc; border:1px solid #c7e0f4; border-radius:14px; padding:4px 13px; font-size:12px; font-family:'Consolas','Courier New',monospace; color:#004578; }
    .chip.deep-path { background:#f3f2f1; border-color:#8a8886; color:#323130; }
    .allowlist-raw { background:#1e1e1e; color:#d4d4d4; border-radius:6px; padding:14px 16px; font-family:'Consolas','Courier New',monospace; font-size:12px; line-height:1.7; white-space:pre; overflow-x:auto; display:none; margin-top:10px; }
    .toggle-raw-btn { background:none; border:1px solid #c8c6c4; border-radius:4px; padding:4px 12px; font-size:12px; cursor:pointer; color:#605e5c; }
    .toggle-raw-btn:hover { background:#f3f2f1; }
    .card.allow { border-top-color:#107c10; }
    .card.allow .card-value { color:#107c10; }

    /* ── Remediation Checklist ── */
    .rem-row { transition: background .2s; }
    .rem-row.done { opacity: .55; }
    .rem-row.dec-allow         { background: #dff6dd !important; }
    .rem-row.dec-remove        { background: #fde7e9 !important; }
    .rem-row.dec-investigate   { background: #fff4ce !important; }
    .chk-cell { text-align:center; width:36px; }
    .chk-cell input[type=checkbox] { width:16px; height:16px; cursor:pointer; }
    .prefix-cell code { font-size:11.5px; word-break:break-all; color:#0078d4; background:#f3f9ff; padding:2px 6px; border-radius:3px; }
    .urlcount-cell { text-align:right; color:#605e5c; font-size:12px; }
    .dec-cell { min-width:220px; }
    .dec-btns { display:flex; gap:5px; flex-wrap:wrap; }
    .dec-btn { border:none; border-radius:4px; padding:4px 10px; font-size:11px; cursor:pointer; font-family:inherit; font-weight:600; white-space:nowrap; }
    .dec-btn.dec-allow       { background:#dff6dd; color:#107c10; border:1px solid #a8d8a8; }
    .dec-btn.dec-remove      { background:#fde7e9; color:#a4262c; border:1px solid #f0b0b3; }
    .dec-btn.dec-investigate { background:#fff4ce; color:#7d6608; border:1px solid #e8d870; }
    .dec-btn:hover { filter:brightness(.93); }
    .dec-label { display:inline-block; margin-top:4px; font-size:11px; font-weight:600; }
    .rem-row.dec-allow       .dec-label { color:#107c10; }
    .rem-row.dec-remove      .dec-label { color:#a4262c; }
    .rem-row.dec-investigate .dec-label { color:#7d6608; }
    .progress-summary { display:flex; gap:20px; flex-wrap:wrap; margin-bottom:14px; font-size:12px; }
    .progress-pill { background:#f3f2f1; border-radius:12px; padding:4px 12px; }
    .progress-pill.green { background:#dff6dd; color:#107c10; font-weight:600; }
    .progress-pill.red   { background:#fde7e9; color:#a4262c; font-weight:600; }
    .progress-pill.amber { background:#fff4ce; color:#7d6608; font-weight:600; }
    .rem-toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:16px; padding:12px 16px; background:#f3f2f1; border-radius:6px; border:1px solid #edebe9; }
    .rem-export-btn { border:none; border-radius:4px; padding:7px 16px; font-size:13px; cursor:pointer; font-family:inherit; display:flex; align-items:center; gap:6px; font-weight:500; white-space:nowrap; }
    .rem-export-btn.btn-copy-allowed { background:#dff6dd; color:#107c10; border:1px solid #a8d8a8; }
    .rem-export-btn.btn-copy-allowed:hover { background:#c8edc8; }
    .rem-export-btn.btn-copy-allowed.copied { background:#107c10; color:#fff; border-color:#107c10; }
    .rem-export-btn.btn-export-csv { background:#fff; color:#323130; border:1px solid #c8c6c4; }
    .rem-export-btn.btn-export-csv:hover { background:#edebe9; }
    .rem-toolbar-note { font-size:12px; color:#605e5c; margin-left:4px; }


    /* ── URL cell ── */
    .url-cell { max-width: 420px; word-break: break-all; font-size: 11px; }
    .domain-list-cell { font-size: 11px; word-break: break-all; }

    /* ── Footer ── */
    .report-footer {
      text-align: center;
      font-size: 11px;
      color: #a19f9d;
      padding: 20px;
      border-top: 1px solid #edebe9;
      margin-top: 40px;
    }

    /* ── Print ── */
    @media print {
      .page-header { background: #0078d4 !important; -webkit-print-color-adjust: exact; }
      .bar { background: #0078d4 !important; -webkit-print-color-adjust: exact; }
      .expand-btn { display: none; }
      .site-list { display: block !important; }
    }
  </style>
</head>
<body>

<header class="page-header">
  <h1>SharePoint CSP Violation Report
    <span class="mc-badge">MC1193419</span>
  </h1>
  <div class="subtitle">
    Generated: $reportDate &nbsp;|&nbsp; Source: $csvBaseName
  </div>
</header>

<main class="main">

  <!-- Info Banner -->
  <div class="info-box">
    <strong>What is this report?</strong>
    Microsoft Message Center notification <strong>MC1193419</strong> announces upcoming
    Content Security Policy (CSP) enforcement for SharePoint Online. Once enforced, external
    resources loaded from the domains below will be <strong>blocked by the browser</strong>
    unless those domains are explicitly allow-listed via an
    <a href="https://learn.microsoft.com/en-us/sharepoint/dev/spfx/use-aadhttpclient" target="_blank" rel="noopener">
    HTML Field Security policy or CDN allow-list</a>.
    Use this report to identify which external domains need to be reviewed before enforcement begins.
  </div>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card">
      <div class="card-value">$(Format-Number $matchedRows)</div>
      <div class="card-label">Total CSP Violations</div>
    </div>
    <div class="card warn">
      <div class="card-value">$(Format-Number $uniqueDomainCount)</div>
      <div class="card-label">Unique Blocked Domains</div>
    </div>
    <div class="card info">
      <div class="card-value">$(Format-Number $uniqueSiteCount)</div>
      <div class="card-label">SharePoint Sites Affected</div>
    </div>
    <div class="card neutral">
      <div class="card-value" style="font-size:18px; padding-top:6px;">$dateRangeStr</div>
      <div class="card-label">Violation Date Range</div>
    </div>
    <div class="card allow">
      <div class="card-value">$allowListCount <span style="font-size:16px;font-weight:400;color:#605e5c;">/ 300</span></div>
      <div class="card-label">Allow-List Entries Needed</div>
    </div>
  </div>

  <!-- Script Source Allow-List -->
  <section id="allowlist">
    <h2>Script Source Allow-List <span class="badge">$allowListCount of 300 limit</span></h2>
    <p class="section-note">
      Minimized list of script-source URL prefixes that must be trusted before CSP enforcement
      begins. Where a single URL was seen from a host, the entry is trimmed to the origin
      (<code>https://host/</code>). Where multiple URLs share a common path, the deepest shared
      folder prefix is used — keeping the allow-list as specific (and as short) as possible.
      No hostname wildcards are used. Review each entry before submitting to your tenant policy.
    </p>
    <div class="allowlist-wrap">
      <div class="allowlist-header">
        <div>
          <strong>$allowListCount unique entr$(if($allowListCount -eq 1){'y'}else{'ies'})</strong>
          &nbsp;&middot;&nbsp;
          <span class="usage-note $allowListStatus">$(
            if ($allowListStatus -eq 'good') { "Well within the 300-entry limit" }
            elseif ($allowListStatus -eq 'warn') { "Review recommended before submitting" }
            else { "Approaching limit — consolidate further before submitting" }
          )</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center;">
          <button class="toggle-raw-btn" id="rawToggleBtn" onclick="toggleRaw()">&#128196; Show as plain text</button>
          <button class="copy-btn" id="copyBtn" onclick="copyAllowList()">&#128203; Copy all domains</button>
        </div>
      </div>
      <div class="usage-bar-wrap">
        <div class="usage-bar-track">
          <div class="usage-bar-fill $allowListStatus" style="width:$([Math]::Min(100,$allowListPct))%"></div>
        </div>
        <span class="usage-note $allowListStatus">$allowListCount / 300 &nbsp;($allowListPct%)</span>
      </div>
      <div class="chips" id="allowChips">
$(($allowList | Sort-Object | ForEach-Object {
    # Chips that go deeper than just the origin get a distinct style
    $cls = if ($_ -match '^https?://[^/]+/[^/]+') { 'chip deep-path' } else { 'chip' }
    "        <span class='$cls'>$(Get-HtmlEscaped $_)</span>"
}) -join "`n")
      </div>
      <pre class="allowlist-raw" id="allowRaw">$(($allowList | Sort-Object) -join "`n")</pre>
    </div>
  </section>

  <!-- Top Blocked Domains -->
  <section id="domains">
    <h2>Top Blocked Domains <span class="badge">Top $TopDomains of $(Format-Number $uniqueDomainCount)</span></h2>
    <p class="section-note">
      Domains are extracted from the BlockedUrl field. Click a site count button to see which
      SharePoint pages loaded resources from that domain. Sort any column by clicking the header.
    </p>
    <div class="table-controls">
      <input type="text" class="search-box" id="domainSearch" placeholder="&#128269;  Search domains..." oninput="filterTable('domainTable','domainSearch')">
      <span class="control-label">Showing top $TopDomains domains (sorted by violation count)</span>
    </div>
    <div class="table-wrap">
      <table id="domainTable" class="data-table sortable">
        <thead>
          <tr>
            <th class="rank">#</th>
            <th onclick="sortTable('domainTable',1)">Blocked Domain</th>
            <th onclick="sortTable('domainTable',2)" class="sorted-desc">Violations</th>
            <th onclick="sortTable('domainTable',3)">% of Total</th>
            <th>Affected Sites</th>
          </tr>
        </thead>
        <tbody>
          $($domainTableRows.ToString())
        </tbody>
      </table>
    </div>
  </section>

  <!-- Sites Most Affected -->
  <section id="sites">
    <h2>Most Affected SharePoint Sites <span class="badge">Top 50 of $(Format-Number $uniqueSiteCount)</span></h2>
    <p class="section-note">
      SharePoint sites ranked by the number of distinct blocked domains they attempted to load.
      Sites loading resources from many external domains carry the highest risk once CSP is enforced.
    </p>
    <div class="table-controls">
      <input type="text" class="search-box" id="siteSearch" placeholder="&#128269;  Search sites..." oninput="filterTable('siteTable','siteSearch')">
    </div>
    <div class="table-wrap">
      <table id="siteTable" class="data-table sortable">
        <thead>
          <tr>
            <th onclick="sortTable('siteTable',0)">SharePoint Site</th>
            <th onclick="sortTable('siteTable',1)" class="sorted-desc">Distinct Blocked Domains</th>
            <th>Blocked Domains</th>
          </tr>
        </thead>
        <tbody>
          $($siteTableRows.ToString())
        </tbody>
      </table>
    </div>
  </section>

  $fullUrlSection

  <!-- Remediation Checklist -->
  <section id="remediation">
    <h2>Domains to Allow <span class="badge">$allowListCount to review</span></h2>
    <p class="section-note">
      For each URL prefix below, decide whether the resource is legitimate (allow it in the tenant CSP policy),
      unwanted (remove the script from the page), or needs further review.
      Once decisions are made, use <strong>Copy Allowed URLs</strong> to copy just the approved prefixes,
      or <strong>Export CSV</strong> to download the full decision table for sharing or review in Excel.
    </p>
    <div class="progress-summary" id="progressSummary">
      <span class="progress-pill" id="pill_pending">$allowListCount pending</span>
      <span class="progress-pill green" id="pill_allow" style="display:none">0 to allow</span>
      <span class="progress-pill red"   id="pill_remove" style="display:none">0 to remove</span>
      <span class="progress-pill amber" id="pill_review" style="display:none">0 to review</span>
    </div>
    <div class="rem-toolbar">
      <button class="rem-export-btn btn-copy-allowed" id="copyAllowedBtn" onclick="copyAllowed()">&#128203; Copy Allowed URLs</button>
      <button class="rem-export-btn btn-export-csv"  onclick="exportRemediationCsv()">&#8659; Export to CSV</button>
      <span class="rem-toolbar-note" id="remToolbarNote">Mark decisions using the row buttons, then export.</span>
    </div>
    <div class="table-wrap">
      <table id="remediationTable" class="data-table">
        <thead>
          <tr>
            <th class="chk-cell" title="Mark reviewed">&#10003;</th>
            <th onclick="sortTable('remediationTable',1)">URL Prefix (add to tenant allow-list)</th>
            <th onclick="sortTable('remediationTable',2)" class="sorted-desc">Violations</th>
            <th>Affected Sites</th>
            <th onclick="sortTable('remediationTable',4)">Unique&nbsp;URLs&nbsp;Seen</th>
            <th>Decision</th>
          </tr>
        </thead>
        <tbody>
          $($remediationRows.ToString())
        </tbody>
      </table>
    </div>
  </section>

</main>

<footer class="report-footer">
  SharePoint CSP Violation Report &nbsp;|&nbsp; Source: $csvBaseName &nbsp;|&nbsp;
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

    // Clear all sort indicators
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

  /* ── Remediation: Mark row as reviewed ── */
  function markDone(rowId, cb) {
    document.getElementById(rowId).classList.toggle('done', cb.checked);
  }

  /* ── Remediation: Set Allow / Remove / Review decision ── */
  const decLabels = { allow: '✓ Allowed', remove: '✗ Remove script', investigate: '? Needs review' };

  function setDecision(rowId, decision) {
    const row = document.getElementById(rowId);
    row.classList.remove('dec-allow', 'dec-remove', 'dec-investigate');
    row.classList.add('dec-' + decision);
    const lbl = document.getElementById(rowId + '_label');
    if (lbl) lbl.textContent = decLabels[decision] || '';
    updateProgress();
  }

  function updateProgress() {
    const rows    = document.querySelectorAll('#remediationTable tbody tr.rem-row');
    let allow = 0, remove = 0, review = 0, pending = 0;
    rows.forEach(r => {
      if (r.classList.contains('dec-allow'))       allow++;
      else if (r.classList.contains('dec-remove')) remove++;
      else if (r.classList.contains('dec-investigate')) review++;
      else pending++;
    });
    const set = (id, val, show) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = val;
      el.style.display = show ? '' : 'none';
    };
    set('pill_pending', pending + ' pending',    pending > 0);
    set('pill_allow',   allow   + ' to allow',   allow   > 0);
    set('pill_remove',  remove  + ' to remove',  remove  > 0);
    set('pill_review',  review  + ' to review',  review  > 0);
    if (pending === 0 && document.getElementById('pill_pending'))
      document.getElementById('pill_pending').style.display = 'none';
    // Update toolbar note
    const note = document.getElementById('remToolbarNote');
    if (note) {
      const total = allow + remove + review + pending;
      if (allow > 0 && pending === 0 && remove === 0 && review === 0) {
        note.textContent = '\u2713 All ' + allow + ' entr' + (allow === 1 ? 'y' : 'ies') + ' marked as Allow \u2014 ready to copy.';
      } else if (allow > 0) {
        note.textContent = allow + ' of ' + total + ' marked as Allow \u2014 ' + pending + ' still pending.';
      } else {
        note.textContent = 'Mark decisions using the row buttons, then export.';
      }
    }
  }

  /* ── Expand/Collapse Sites ── */
  function toggleSites(id) {
    const el  = document.getElementById(id);
    const btn = el.previousElementSibling;
    if (el.classList.toggle('hidden')) {
      btn.innerHTML = btn.innerHTML.replace('&#9650;', '&#9660;');
    } else {
      btn.innerHTML = btn.innerHTML.replace('&#9660;', '&#9650;');
    }
  }

  /* ── Allow-List: Toggle Plain Text ── */
  function toggleRaw() {
    const raw = document.getElementById('allowRaw');
    const chips = document.getElementById('allowChips');
    const btn = document.getElementById('rawToggleBtn');
    const isHidden = raw.style.display === 'none' || raw.style.display === '';
    raw.style.display   = isHidden ? 'block' : 'none';
    chips.style.display = isHidden ? 'none'  : 'flex';
    btn.textContent     = isHidden ? '\uD83D\uDCC4 Show as chips' : '\uD83D\uDCC4 Show as plain text';
  }

  /* ── Remediation: Copy only Allowed entries ── */
  function copyAllowed() {
    const rows  = document.querySelectorAll('#remediationTable tbody tr.rem-row.dec-allow');
    const lines = Array.from(rows).map(r => {
      const code = r.querySelector('.prefix-cell code');
      return code ? code.textContent.trim() : '';
    }).filter(Boolean);
    if (!lines.length) {
      alert('No entries are marked as Allowed yet.\nUse the \u2713 Allow button on each row first.');
      return;
    }
    const text = lines.join('\n');
    const btn  = document.getElementById('copyAllowedBtn');
    const orig = btn.innerHTML;
    const finish = () => {
      btn.innerHTML = '\u2713 Copied ' + lines.length + ' entr' + (lines.length === 1 ? 'y' : 'ies') + '!';
      btn.classList.add('copied');
      setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2500);
    };
    navigator.clipboard.writeText(text).then(finish).catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy');
      document.body.removeChild(ta); finish();
    });
  }

  /* ── Remediation: Export full decision table to CSV ── */
  function exportRemediationCsv() {
    const rows   = document.querySelectorAll('#remediationTable tbody tr.rem-row');
    const decMap = { 'dec-allow': 'Allow', 'dec-remove': 'Remove', 'dec-investigate': 'Review' };
    const esc    = v => '"' + String(v).trim().replace(/"/g, '""') + '"';
    const csvRows = [['URL Prefix', 'Violations', 'Affected Sites', 'Unique URLs Seen', 'Decision'].map(esc)];
    rows.forEach(r => {
      const prefix  = (r.querySelector('.prefix-cell code') || {}).textContent || '';
      const viol    = (r.querySelector('.count-cell')       || {}).textContent || '';
      const siteBtn = r.querySelector('.sites-cell .expand-btn');
      const sites   = siteBtn ? siteBtn.textContent.replace(/\s*\u25bc\s*$/,'').trim() : '';
      const urlcnt  = (r.querySelector('.urlcount-cell')    || {}).textContent || '';
      let decision  = 'Pending';
      for (const [cls, label] of Object.entries(decMap)) {
        if (r.classList.contains(cls)) { decision = label; break; }
      }
      csvRows.push([prefix, viol, sites, urlcnt, decision].map(esc));
    });
    const csv  = csvRows.map(r => r.join(',')).join('\r\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'CSP_Domains_Decisions.csv';
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
  }

  /* ── Allow-List: Copy to Clipboard ── */
  function copyAllowList() {
    const text = document.getElementById('allowRaw').textContent.trim();
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById('copyBtn');
      const orig = btn.innerHTML;
      btn.innerHTML = '&#10003; Copied!';
      btn.classList.add('copied');
      setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2500);
    }).catch(() => {
      // Fallback for older browsers
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity  = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    });
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
Write-Host "  Total violations     : $(Format-Number $matchedRows)"
Write-Host "  Unique blocked domains: $(Format-Number $uniqueDomainCount)"
Write-Host "  Affected SP sites    : $(Format-Number $uniqueSiteCount)"
Write-Host "  Date range           : $dateRangeStr"
Write-Host ""

# Open the report in the default browser
try {
    Start-Process $OutputPath
    Write-Host "Report opened in your default browser." -ForegroundColor Green
}
catch {
    Write-Host "Open the report manually: $OutputPath" -ForegroundColor Yellow
}

#endregion
