param(
    [string]$ExePath = "",

    [string]$FixtureDirectory = "tests/sdk",

    [switch]$RequireZig
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
if (-not $ExePath) {
    $ExePath = Join-Path $Root "cs2sign/x64/Release/cs2sign.exe"
}

if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "cs2sign.exe was not found: $ExePath"
}

$FixturePath = Join-Path $Root $FixtureDirectory
$FixtureSchemas = Join-Path $FixturePath "schemas"
if (-not (Test-Path -LiteralPath $FixtureSchemas)) {
    throw "SDK fixture schemas were not found: $FixtureSchemas"
}

$WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("cs2sign-sdkcheck-" + [System.Guid]::NewGuid().ToString("N"))
$WorkSchemas = Join-Path $WorkRoot "schemas"
New-Item -ItemType Directory -Force -Path $WorkSchemas | Out-Null
Get-ChildItem -LiteralPath $FixtureSchemas -Filter "*.json" | Copy-Item -Destination $WorkSchemas

& $ExePath --no-signatures --emit-sdk --output $WorkRoot --no-pause
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$SdkRoot = Join-Path $WorkRoot "sdk"
$ExpectedFiles = @(
    "cpp/sdk_test_dll.hpp",
    "csharp/sdk_test_dll.cs",
    "rust/sdk_test_dll.rs",
    "zig/sdk_test_dll.zig",
    "ida.h"
)

foreach ($RelativePath in $ExpectedFiles) {
    $Path = Join-Path $SdkRoot $RelativePath
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Expected SDK output was not generated: $RelativePath"
    }
}

$Shell = (Get-Process -Id $PID).Path
$CSharpFiles = (Get-ChildItem (Join-Path $SdkRoot "csharp") -Filter "*.cs").FullName
& $Shell -NoProfile -Command {
    param([string[]]$Files)
    $ErrorActionPreference = "Stop"
    Add-Type -Path $Files
} -args $CSharpFiles
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$Rust = Get-Command rustc -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $Rust) {
    throw "rustc was not found."
}

foreach ($RustFile in Get-ChildItem (Join-Path $SdkRoot "rust") -Filter "*.rs") {
    & $Rust.Source --crate-type lib --edition 2021 --emit metadata $RustFile.FullName -o "$($RustFile.FullName).rmeta"
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$Zig = Get-Command zig -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Zig) {
    foreach ($ZigFile in Get-ChildItem (Join-Path $SdkRoot "zig") -Filter "*.zig") {
        & $Zig.Source test $ZigFile.FullName
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
} elseif ($RequireZig) {
    throw "zig was not found."
} else {
    Write-Warning "zig was not found; skipped Zig SDK compile check."
}

Write-Output "SDK output verified."
