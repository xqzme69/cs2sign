param(
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Targets = @(
    "x64",
    "Win32",
    "compiled",
    "cs2sign\x64",
    "cs2sign\Win32",
    "cs2sign\cs2sign",
    "tools\ida\__pycache__",
    "tools\ida\backups"
)

foreach ($Relative in $Targets) {
    $Path = Join-Path $Root $Relative
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force -WhatIf:$WhatIf
    }
}

$GeneratedFiles = @(
    "cs2_signatures.json",
    "cs2sign\cs2_signatures.json",
    "cs2sign\cs2sign.vcxproj.user",
    "cs2sign\NUL.obj"
)

foreach ($Relative in $GeneratedFiles) {
    $Path = Join-Path $Root $Relative
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force -WhatIf:$WhatIf
    }
}
