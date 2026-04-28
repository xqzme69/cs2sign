param(
    [string]$Source = "cs2sign\x64\Release\cs2sign",
    [string]$Output = "signatures",
    [string]$BaseUrl = "https://raw.githubusercontent.com/xqzme69/cs2sign/main/signatures/",
    [string]$Build = "cs2-current"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$SourcePath = Join-Path $Root $Source
$OutputPath = Join-Path $Root $Output

if (-not (Test-Path -LiteralPath $SourcePath)) {
    throw "Signature source directory was not found: $SourcePath"
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$SourceFiles = Get-ChildItem -LiteralPath $SourcePath -Filter "*_signatures.json" |
    Where-Object { $_.Name -ne "cs2_signatures.json" } |
    Sort-Object Name

if (-not $SourceFiles) {
    throw "No *_signatures.json files found in $SourcePath"
}

foreach ($File in $SourceFiles) {
    Copy-Item -LiteralPath $File.FullName -Destination (Join-Path $OutputPath $File.Name) -Force
}

$Entries = foreach ($File in Get-ChildItem -LiteralPath $OutputPath -Filter "*_signatures.json" | Sort-Object Name) {
    [ordered]@{
        name = $File.Name
        sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $File.Length
    }
}

$Index = [ordered]@{
    schema_version = 1
    project = "cs2sign"
    source = "github"
    build = $Build
    generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    base_url = $BaseUrl
    files = @($Entries)
}

$IndexPath = Join-Path $OutputPath "index.json"
$IndexJson = $Index | ConvertTo-Json -Depth 8
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($IndexPath, $IndexJson + [Environment]::NewLine, $Utf8NoBom)

Write-Host "Updated $($Entries.Count) signature file(s) in $OutputPath"
