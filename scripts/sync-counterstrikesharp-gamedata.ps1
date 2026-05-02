param(
    [string]$Uri = "https://raw.githubusercontent.com/roflmuffin/CS2-Gamedata/main/data/latest.json",
    [string]$Output = "signatures\server_signatures.json",
    [string]$SignatureDirectory = "signatures",
    [string]$BaseUrl = "https://raw.githubusercontent.com/xqzme69/cs2sign/main/signatures/",
    [string]$Build = "cs2-current"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path $Root $Path
}

function Write-Utf8NoBomLf {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $Text = $Text -replace "`r`n", "`n" -replace "`r", "`n"
    if (-not $Text.EndsWith("`n")) {
        $Text += "`n"
    }

    [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom)
}

function Get-TextField {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or $null -eq $Property.Value) {
        return ""
    }

    return ([string]$Property.Value).Trim()
}

$OutputPath = Resolve-RepoPath $Output
$SignaturePath = Resolve-RepoPath $SignatureDirectory

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null

$Gamedata = Invoke-RestMethod -Uri $Uri
$Metadata = [ordered]@{
    generator = "sync-counterstrikesharp-gamedata.ps1"
    source_project = "roflmuffin/CS2-Gamedata"
    source_url = $Uri
    module = "server"
    runtime = "windows"
    generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    signatures_generated = 0
    offsets_skipped = 0
}

$Converted = [ordered]@{
    _metadata = $Metadata
}

$Generated = 0
$OffsetsSkipped = 0

foreach ($Property in $Gamedata.PSObject.Properties) {
    $Entry = $Property.Value
    $SignaturesProperty = $Entry.PSObject.Properties["signatures"]
    if ($null -eq $SignaturesProperty -or $null -eq $SignaturesProperty.Value) {
        if ($null -ne $Entry.PSObject.Properties["offsets"]) {
            ++$OffsetsSkipped
        }
        continue
    }

    $Signatures = $SignaturesProperty.Value
    $Pattern = Get-TextField -Object $Signatures -Name "windows"
    if ($Pattern -eq "") {
        continue
    }

    $Library = Get-TextField -Object $Signatures -Name "library"
    if ($Library -eq "") {
        $Library = "server"
    }

    $Converted[$Property.Name] = [ordered]@{
        pattern = $Pattern
        ida_pattern = $Pattern
        module = $Library
        category = "counterstrikesharp"
        importance = "optional"
        required = $false
        result_type = "function_address"
        source = "counterstrikesharp_gamedata"
        source_project = "roflmuffin/CS2-Gamedata"
        source_url = $Uri
        quality = "external"
    }
    ++$Generated
}

if ($Generated -eq 0) {
    throw "No Windows signatures were found in CounterStrikeSharp gamedata."
}

$Metadata.signatures_generated = $Generated
$Metadata.offsets_skipped = $OffsetsSkipped

$Json = $Converted | ConvertTo-Json -Depth 8
Write-Utf8NoBomLf -Path $OutputPath -Text $Json

& (Join-Path $PSScriptRoot "update-signatures.ps1") `
    -Source $SignaturePath `
    -Output $SignaturePath `
    -BaseUrl $BaseUrl `
    -Build $Build

Write-Host "Synced $Generated CounterStrikeSharp signature(s) to $OutputPath"
if ($OffsetsSkipped -gt 0) {
    Write-Host "Skipped $OffsetsSkipped offset-only entr$(if ($OffsetsSkipped -eq 1) { 'y' } else { 'ies' })."
}
