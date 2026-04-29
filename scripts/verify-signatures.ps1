param(
    [string]$SignatureDirectory = "signatures"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$SignaturePath = Join-Path $Root $SignatureDirectory
$IndexPath = Join-Path $SignaturePath "index.json"

if (-not (Test-Path -LiteralPath $IndexPath)) {
    throw "Signature index was not found: $IndexPath"
}

function Test-TextFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        throw "UTF-8 BOM is not allowed: $Path"
    }

    if ($Bytes -contains 13) {
        throw "CRLF is not allowed in published signatures: $Path"
    }
}

Test-TextFile -Path $IndexPath

$Index = Get-Content -LiteralPath $IndexPath -Raw | ConvertFrom-Json
if (-not $Index.files -or $Index.files.Count -eq 0) {
    throw "Signature index does not contain files."
}

foreach ($Entry in $Index.files) {
    $FilePath = Join-Path $SignaturePath $Entry.name
    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Signature file is missing: $($Entry.name)"
    }

    Test-TextFile -Path $FilePath

    $Item = Get-Item -LiteralPath $FilePath
    if ($Item.Length -ne [int64]$Entry.size) {
        throw "Size mismatch for $($Entry.name): index=$($Entry.size), file=$($Item.Length)"
    }

    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FilePath).Hash.ToLowerInvariant()
    if ($Hash -ne [string]$Entry.sha256) {
        throw "sha256 mismatch for $($Entry.name): index=$($Entry.sha256), file=$Hash"
    }
}

Write-Output "Verified $($Index.files.Count) signature file(s)."
