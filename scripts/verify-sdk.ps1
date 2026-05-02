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

function Invoke-CSharpSdkCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SdkRoot,

        [Parameter(Mandatory = $true)]
        [string]$WorkRoot
    )

    $CSharpFiles = @(Get-ChildItem (Join-Path $SdkRoot "csharp") -Filter "*.cs")
    if ($CSharpFiles.Count -eq 0) {
        throw "No C# SDK files were generated."
    }

    $Dotnet = Get-Command dotnet -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Dotnet) {
        $VersionText = (& $Dotnet.Source --version).Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($VersionText)) {
            throw "dotnet --version failed."
        }

        $MajorText = ($VersionText -split '\.')[0]
        $Major = 0
        if (-not [int]::TryParse($MajorText, [ref]$Major) -or $Major -lt 5) {
            throw "dotnet SDK version is too old for generated C# SDK syntax: $VersionText"
        }

        $CheckRoot = Join-Path $WorkRoot "csharp-check"
        New-Item -ItemType Directory -Force -Path $CheckRoot | Out-Null
        foreach ($File in $CSharpFiles) {
            Copy-Item -LiteralPath $File.FullName -Destination $CheckRoot
        }

        $ProjectPath = Join-Path $CheckRoot "cs2sign-sdk-check.csproj"
        $TargetFramework = "net$Major.0"
        @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>$TargetFramework</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="*.cs" />
  </ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $ProjectPath -Encoding utf8

        & $Dotnet.Source build $ProjectPath --nologo --verbosity quiet
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
        return
    }

    $Shell = (Get-Process -Id $PID).Path
    & $Shell -NoProfile -Command {
        param([string[]]$Files)
        $ErrorActionPreference = "Stop"
        Add-Type -Path $Files
    } -args $CSharpFiles.FullName
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

function Test-ExecutableCommand {
    param(
        [Parameter(Mandatory = $true)]
        $Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    try {
        & $Command.Source @Arguments *> $null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
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

Invoke-CSharpSdkCheck -SdkRoot $SdkRoot -WorkRoot $WorkRoot

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
if ($Zig -and (Test-ExecutableCommand -Command $Zig -Arguments @("version"))) {
    foreach ($ZigFile in Get-ChildItem (Join-Path $SdkRoot "zig") -Filter "*.zig") {
        & $Zig.Source test $ZigFile.FullName
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
} elseif ($RequireZig) {
    if ($Zig) {
        throw "zig was found but could not be executed: $($Zig.Source)"
    }
    throw "zig was not found."
} else {
    if ($Zig) {
        Write-Warning "zig was found but could not be executed; skipped Zig SDK compile check: $($Zig.Source)"
    } else {
        Write-Warning "zig was not found; skipped Zig SDK compile check."
    }
}

Write-Output "SDK output verified."
