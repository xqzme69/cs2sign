param(
    [ValidateSet("Debug", "Release", "Production")]
    [string]$Configuration = "Release",

    [ValidateSet("x64", "Win32")]
    [string]$Platform = "x64",

    [ValidateSet("scanner")]
    [string]$Target = "scanner",

    [string]$PlatformToolset = ""
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot

function Resolve-MSBuild {
    param(
        [string]$PreferredVersionRange = ""
    )

    $Command = Get-Command msbuild.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Command -and -not $PreferredVersionRange) {
        return $Command.Source
    }

    $VsWhereCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($VsWhere in $VsWhereCandidates) {
        $VsWhereArgs = @("-latest", "-products", "*", "-requires", "Microsoft.Component.MSBuild")
        if ($PreferredVersionRange) {
            $VsWhereArgs += @("-all", "-version", $PreferredVersionRange)
        }

        $Found = & $VsWhere @VsWhereArgs -find "MSBuild\**\Bin\amd64\MSBuild.exe" |
            Select-Object -First 1
        if ($Found -and (Test-Path -LiteralPath $Found)) {
            return $Found
        }

        $Found = & $VsWhere @VsWhereArgs -find "MSBuild\**\Bin\MSBuild.exe" |
            Select-Object -First 1
        if ($Found -and (Test-Path -LiteralPath $Found)) {
            return $Found
        }
    }

    $VS2022Candidates = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    )

    $VSCurrentCandidates = @(
        "C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe"
    )

    $Candidates = @()
    if ($PreferredVersionRange) {
        $Candidates += $VS2022Candidates
        $Candidates += $VSCurrentCandidates
    } else {
        $Candidates += $VSCurrentCandidates
        $Candidates += $VS2022Candidates
    }

    return $Candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

$PreferredMSBuildVersionRange = ""
if ($PlatformToolset -eq "v143") {
    $PreferredMSBuildVersionRange = "[17.0,18.0)"
}

$MSBuild = Resolve-MSBuild -PreferredVersionRange $PreferredMSBuildVersionRange
if (-not $MSBuild) {
    throw "MSBuild.exe was not found. Install Visual Studio or run this from a Developer PowerShell."
}

$Projects = @()
if ($Target -eq "scanner") {
    $Projects += Join-Path $Root "cs2sign\cs2sign.vcxproj"
}

foreach ($Project in $Projects) {
    $Arguments = @($Project, "/p:Configuration=$Configuration", "/p:Platform=$Platform", "/m")
    if ($PlatformToolset) {
        $Arguments += "/p:PlatformToolset=$PlatformToolset"
    }

    & $MSBuild @Arguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
