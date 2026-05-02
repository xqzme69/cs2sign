param(
    [Parameter(Mandatory = $true)]
    [string]$Baseline,
    [Parameter(Mandatory = $true)]
    [string]$Candidate,
    [string]$OutputReport = ""
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

function Read-ScanResult {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $Entries = @{}

    foreach ($Entry in @($Json.signatures)) {
        $Module = if ($Entry.module) { [string]$Entry.module } else { "" }
        $Name = [string]$Entry.name
        if (-not $Name) {
            continue
        }

        $Key = "$($Module.ToLowerInvariant())|$Name"
        $Entries[$Key] = [pscustomobject]@{
            name = $Name
            module = $Module
            status = [string]$Entry.status
            found = [bool]$Entry.found
            address = [string]$Entry.address
            module_rva = [string]$Entry.module_rva
            field_offset = [string]$Entry.field_offset
            ida_pattern = [string]$Entry.ida_pattern
            pattern_synth = [string]$Entry.pattern_synth
            result_type = [string]$Entry.result_type
            resolver_status = [string]$Entry.resolver_status
            required = [bool]$Entry.required
        }
    }

    return $Entries
}

function New-DiffItem {
    param($Entry)
    return [ordered]@{
        module = $Entry.module
        name = $Entry.name
        status = $Entry.status
        address = $Entry.address
        module_rva = $Entry.module_rva
        field_offset = $Entry.field_offset
        resolver_status = $Entry.resolver_status
        required = $Entry.required
    }
}

$BaselinePath = Resolve-InputPath $Baseline
$CandidatePath = Resolve-InputPath $Candidate

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    throw "Baseline file was not found: $BaselinePath"
}
if (-not (Test-Path -LiteralPath $CandidatePath)) {
    throw "Candidate file was not found: $CandidatePath"
}

$Base = Read-ScanResult $BaselinePath
$Next = Read-ScanResult $CandidatePath

$Added = @()
$Removed = @()
$StatusChanged = @()
$AddressChanged = @()
$PatternChanged = @()
$ResolverChanged = @()

foreach ($Key in $Next.Keys) {
    if (-not $Base.ContainsKey($Key)) {
        $Added += New-DiffItem $Next[$Key]
        continue
    }

    $Old = $Base[$Key]
    $New = $Next[$Key]

    if ($Old.status -ne $New.status -or $Old.found -ne $New.found) {
        $StatusChanged += [ordered]@{
            module = $New.module
            name = $New.name
            previous = $Old.status
            current = $New.status
        }
    }

    if ($Old.address -ne $New.address -or
        $Old.module_rva -ne $New.module_rva -or
        $Old.field_offset -ne $New.field_offset) {
        $AddressChanged += [ordered]@{
            module = $New.module
            name = $New.name
            previous_address = $Old.address
            current_address = $New.address
            previous_module_rva = $Old.module_rva
            current_module_rva = $New.module_rva
            previous_field_offset = $Old.field_offset
            current_field_offset = $New.field_offset
        }
    }

    if ($Old.ida_pattern -ne $New.ida_pattern -or $Old.pattern_synth -ne $New.pattern_synth) {
        $PatternChanged += [ordered]@{
            module = $New.module
            name = $New.name
            previous_ida_pattern = $Old.ida_pattern
            current_ida_pattern = $New.ida_pattern
            previous_pattern_synth = $Old.pattern_synth
            current_pattern_synth = $New.pattern_synth
        }
    }

    if ($Old.resolver_status -ne $New.resolver_status -or $Old.result_type -ne $New.result_type) {
        $ResolverChanged += [ordered]@{
            module = $New.module
            name = $New.name
            previous_result_type = $Old.result_type
            current_result_type = $New.result_type
            previous_resolver_status = $Old.resolver_status
            current_resolver_status = $New.resolver_status
        }
    }
}

foreach ($Key in $Base.Keys) {
    if (-not $Next.ContainsKey($Key)) {
        $Removed += New-DiffItem $Base[$Key]
    }
}

$Report = [ordered]@{
    baseline = $BaselinePath
    candidate = $CandidatePath
    baseline_total = $Base.Count
    candidate_total = $Next.Count
    added = @($Added | Sort-Object module, name)
    removed = @($Removed | Sort-Object module, name)
    status_changed = @($StatusChanged | Sort-Object module, name)
    address_changed = @($AddressChanged | Sort-Object module, name)
    pattern_changed = @($PatternChanged | Sort-Object module, name)
    resolver_changed = @($ResolverChanged | Sort-Object module, name)
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

Write-Host "Baseline: $($Base.Count) signature(s)"
Write-Host "Candidate: $($Next.Count) signature(s)"
Write-Host "Added: $($Added.Count), removed: $($Removed.Count), status changed: $($StatusChanged.Count), address changed: $($AddressChanged.Count)"
