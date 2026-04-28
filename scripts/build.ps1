param(
    [ValidateSet("Debug", "Release", "Production")]
    [string]$Configuration = "Release",

    [ValidateSet("x64", "Win32")]
    [string]$Platform = "x64",

    [ValidateSet("scanner")]
    [string]$Target = "scanner"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot

$Command = Get-Command msbuild.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Command) {
    $MSBuild = $Command.Source
} else {
    $Candidates = @(
        "C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"
    )

    $MSBuild = $Candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if (-not $MSBuild) {
    throw "MSBuild.exe was not found. Install Visual Studio or run this from a Developer PowerShell."
}

$Projects = @()
if ($Target -eq "scanner") {
    $Projects += Join-Path $Root "cs2sign\cs2sign.vcxproj"
}

foreach ($Project in $Projects) {
    & $MSBuild $Project /p:Configuration=$Configuration /p:Platform=$Platform /m
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
