param(
    [string]$Baseline = "signatures",
    [Parameter(Mandatory = $true)]
    [string]$Candidate,
    [string]$OutputReport = "",
    [int]$MaxDropPercent = 80,
    [int]$MinTotalSignatures = 1
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Resolve-InputPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path $Root $Path
}

function Read-SignatureFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $Entries = @{}
    foreach ($Property in $Json.PSObject.Properties) {
        if ($Property.Name -eq "_metadata") {
            continue
        }

        $Value = $Property.Value
        $Entries[$Property.Name] = [pscustomobject]@{
            pattern = [string]$Value.pattern
            rva = [string]$Value.rva
            category = [string]$Value.category
            quality = [string]$Value.quality
        }
    }

    return $Entries
}

function Compare-EntryMap {
    param($BaselineEntries, $CandidateEntries)

    $Added = @()
    $Removed = @()
    $PatternChanged = @()
    $RvaChanged = @()

    foreach ($Name in $CandidateEntries.Keys) {
        if (-not $BaselineEntries.ContainsKey($Name)) {
            $Added += $Name
            continue
        }

        if ($BaselineEntries[$Name].pattern -ne $CandidateEntries[$Name].pattern) {
            $PatternChanged += $Name
        }
        if ($BaselineEntries[$Name].rva -ne $CandidateEntries[$Name].rva) {
            $RvaChanged += $Name
        }
    }

    foreach ($Name in $BaselineEntries.Keys) {
        if (-not $CandidateEntries.ContainsKey($Name)) {
            $Removed += $Name
        }
    }

    return [pscustomobject]@{
        added = @($Added | Sort-Object)
        removed = @($Removed | Sort-Object)
        pattern_changed = @($PatternChanged | Sort-Object)
        rva_changed = @($RvaChanged | Sort-Object)
    }
}

$BaselinePath = Resolve-InputPath $Baseline
$CandidatePath = Resolve-InputPath $Candidate

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    throw "Baseline directory was not found: $BaselinePath"
}
if (-not (Test-Path -LiteralPath $CandidatePath)) {
    throw "Candidate directory was not found: $CandidatePath"
}

$BaselineFiles = Get-ChildItem -LiteralPath $BaselinePath -Filter "*_signatures.json" |
    Where-Object { $_.Name -ne "cs2_signatures.json" } |
    Sort-Object Name
$CandidateFiles = Get-ChildItem -LiteralPath $CandidatePath -Filter "*_signatures.json" |
    Where-Object { $_.Name -ne "cs2_signatures.json" } |
    Sort-Object Name

if (-not $CandidateFiles) {
    throw "No candidate signature files found: $CandidatePath"
}

$BaselineByName = @{}
foreach ($File in $BaselineFiles) {
    $BaselineByName[$File.Name] = $File.FullName
}

$ReportModules = @()
$Failures = @()
$BaselineTotal = 0
$CandidateTotal = 0

foreach ($CandidateFile in $CandidateFiles) {
    if (-not $BaselineByName.ContainsKey($CandidateFile.Name)) {
        $Failures += "New signature file has no baseline: $($CandidateFile.Name)"
        continue
    }

    $BaselineEntries = Read-SignatureFile $BaselineByName[$CandidateFile.Name]
    $CandidateEntries = Read-SignatureFile $CandidateFile.FullName
    $Diff = Compare-EntryMap $BaselineEntries $CandidateEntries

    $BaselineCount = $BaselineEntries.Count
    $CandidateCount = $CandidateEntries.Count
    $BaselineTotal += $BaselineCount
    $CandidateTotal += $CandidateCount

    $DropPercent = if ($BaselineCount -gt 0) {
        [math]::Round((($BaselineCount - $CandidateCount) * 100.0) / $BaselineCount, 2)
    } else {
        0
    }

    if ($DropPercent -gt $MaxDropPercent) {
        $Failures += "$($CandidateFile.Name) dropped by $DropPercent percent"
    }

    $ReportModules += [pscustomobject]@{
        file = $CandidateFile.Name
        baseline_count = $BaselineCount
        candidate_count = $CandidateCount
        drop_percent = $DropPercent
        added_count = $Diff.added.Count
        removed_count = $Diff.removed.Count
        pattern_changed_count = $Diff.pattern_changed.Count
        rva_changed_count = $Diff.rva_changed.Count
        added = $Diff.added
        removed = $Diff.removed
        pattern_changed = $Diff.pattern_changed
        rva_changed = $Diff.rva_changed
    }
}

foreach ($BaselineFile in $BaselineFiles) {
    if (-not ($CandidateFiles | Where-Object { $_.Name -eq $BaselineFile.Name })) {
        $Failures += "Candidate is missing signature file: $($BaselineFile.Name)"
    }
}

if ($CandidateTotal -lt $MinTotalSignatures) {
    $Failures += "Candidate total signatures is below minimum: $CandidateTotal < $MinTotalSignatures"
}

$TotalDropPercent = if ($BaselineTotal -gt 0) {
    [math]::Round((($BaselineTotal - $CandidateTotal) * 100.0) / $BaselineTotal, 2)
} else {
    0
}

if ($TotalDropPercent -gt $MaxDropPercent) {
    $Failures += "Total signatures dropped by $TotalDropPercent percent"
}

$Report = [ordered]@{
    baseline = $BaselinePath
    candidate = $CandidatePath
    baseline_total = $BaselineTotal
    candidate_total = $CandidateTotal
    total_drop_percent = $TotalDropPercent
    max_drop_percent = $MaxDropPercent
    success = ($Failures.Count -eq 0)
    failures = @($Failures)
    modules = @($ReportModules)
}

if ($OutputReport) {
    $ReportPath = Resolve-InputPath $OutputReport
    $ReportDir = Split-Path -Parent $ReportPath
    if ($ReportDir -and -not (Test-Path -LiteralPath $ReportDir)) {
        New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
    }
    $Text = $Report | ConvertTo-Json -Depth 16
    [System.IO.File]::WriteAllText($ReportPath, ($Text -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
}

Write-Host "Baseline: $BaselineTotal signature(s)"
Write-Host "Candidate: $CandidateTotal signature(s)"
Write-Host "Drop: $TotalDropPercent percent"

if ($Failures.Count -gt 0) {
    foreach ($Failure in $Failures) {
        Write-Host "ERROR: $Failure"
    }
    exit 1
}

exit 0
