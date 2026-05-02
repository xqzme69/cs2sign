param(
    [string]$Uri = "https://raw.githubusercontent.com/scros22/cs2-universal-offsets/main/src/signatures/database.rs",
    [string]$Output = "signatures\universal_signatures.json",
    [string]$ExistingSignatureDirectory = "signatures",
    [string]$BaseUrl = "https://raw.githubusercontent.com/xqzme69/cs2sign/main/signatures/",
    [string]$Build = "cs2-current",
    [switch]$IncludeExisting,
    [switch]$NoUpdateIndex
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

function Normalize-ModuleName {
    param([string]$Module)
    $Value = ([string]$Module).Trim().ToLowerInvariant()
    if ($Value -eq "") {
        return ""
    }
    if (-not $Value.EndsWith(".dll")) {
        $Value += ".dll"
    }
    return $Value
}

function Get-JsonTextValue {
    param($Object, [string]$Name)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or $null -eq $Property.Value) {
        return ""
    }
    return ([string]$Property.Value).Trim()
}

function Read-ExistingSignatureKeys {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [string]$ExcludePath = ""
    )

    $Keys = New-Object 'System.Collections.Generic.HashSet[string]'
    if (-not (Test-Path -LiteralPath $Directory)) {
        return $Keys
    }

    $ResolvedExcludePath = ""
    if ($ExcludePath -and (Test-Path -LiteralPath $ExcludePath)) {
        $ResolvedExcludePath = (Resolve-Path -LiteralPath $ExcludePath).Path
    }

    Get-ChildItem -LiteralPath $Directory -Filter "*_signatures.json" |
        Where-Object { $_.Name -ne "cs2_signatures.json" } |
        ForEach-Object {
            if ($ResolvedExcludePath -and $_.FullName -eq $ResolvedExcludePath) {
                return
            }

            $Json = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
            foreach ($Property in $Json.PSObject.Properties) {
                if ($Property.Name -eq "_metadata") {
                    continue
                }

                $Module = Normalize-ModuleName (Get-JsonTextValue -Object $Property.Value -Name "module")
                if ($Module -eq "") {
                    continue
                }

                [void]$Keys.Add("$Module|$($Property.Name)")
            }
        }

    return $Keys
}

function Get-ResolveKind {
    param([string]$ResolveText, [hashtable]$ResolveAliases)

    $Text = $ResolveText.Trim()
    if ($ResolveAliases.ContainsKey($Text)) {
        return $ResolveAliases[$Text]
    }

    if ($Text -match 'ResolveKind::(?<kind>Rel32|RipRel)\s*\{\s*rel_off:\s*(?<off>\d+)\s*\}') {
        return [pscustomobject]@{
            kind = $Matches.kind
            rel_off = [int]$Matches.off
        }
    }

    if ($Text -match 'ResolveKind::(?<kind>None|StringRef)') {
        return [pscustomobject]@{
            kind = $Matches.kind
            rel_off = 0
        }
    }

    throw "Unsupported ResolveKind expression: $Text"
}

function Add-UniqueEntry {
    param(
        [Parameter(Mandatory = $true)]$Map,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Entry
    )

    $Key = $Name
    $Suffix = 2
    while ($Map.Contains($Key)) {
        $Key = "$Name`_$Suffix"
        ++$Suffix
    }

    $Map[$Key] = $Entry
}

function Get-SignatureBlocks {
    param([Parameter(Mandatory = $true)][string]$Text)

    $Blocks = New-Object System.Collections.Generic.List[string]
    $Pattern = [regex]'Signature\s*\{'
    $Offset = 0

    while ($Offset -lt $Text.Length) {
        $Match = $Pattern.Match($Text, $Offset)
        if (-not $Match.Success) {
            break
        }

        $BraceStart = $Text.IndexOf('{', $Match.Index)
        if ($BraceStart -lt 0) {
            break
        }

        $Depth = 0
        $InString = $false
        $Escaped = $false
        for ($Index = $BraceStart; $Index -lt $Text.Length; ++$Index) {
            $Character = $Text[$Index]

            if ($InString) {
                if ($Escaped) {
                    $Escaped = $false
                    continue
                }
                if ($Character -eq '\') {
                    $Escaped = $true
                    continue
                }
                if ($Character -eq '"') {
                    $InString = $false
                }
                continue
            }

            if ($Character -eq '"') {
                $InString = $true
                continue
            }
            if ($Character -eq '{') {
                ++$Depth
                continue
            }
            if ($Character -eq '}') {
                --$Depth
                if ($Depth -eq 0) {
                    $Blocks.Add($Text.Substring($Match.Index, $Index - $Match.Index + 1))
                    $Offset = $Index + 1
                    break
                }
            }
        }

        if ($Depth -ne 0) {
            throw "Unterminated Signature block near offset $($Match.Index)"
        }
    }

    return $Blocks
}

function Read-RustStringField {
    param(
        [Parameter(Mandatory = $true)][string]$Block,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $Match = [regex]::Match($Block, "$Field\s*:\s*`"(?<value>(?:\\.|[^`"])*)`"", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $Match.Success) {
        throw "Signature block is missing string field '$Field': $Block"
    }
    return [regex]::Unescape($Match.Groups["value"].Value)
}

function Read-RustIntegerField {
    param(
        [Parameter(Mandatory = $true)][string]$Block,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $Match = [regex]::Match($Block, "$Field\s*:\s*(?<value>-?\d+)", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $Match.Success) {
        throw "Signature block is missing integer field '$Field': $Block"
    }
    return [int64]$Match.Groups["value"].Value
}

function Read-RustResolveField {
    param([Parameter(Mandatory = $true)][string]$Block)

    $Match = [regex]::Match($Block, 'resolve\s*:\s*(?<value>.*?)\s*,\s*extra_off\s*:', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $Match.Success) {
        throw "Signature block is missing resolve field: $Block"
    }
    return $Match.Groups["value"].Value.Trim()
}

$OutputPath = Resolve-RepoPath $Output
$ExistingPath = Resolve-RepoPath $ExistingSignatureDirectory

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null

$Source = (Invoke-WebRequest -UseBasicParsing -Uri $Uri).Content
if ([string]::IsNullOrWhiteSpace($Source)) {
    throw "Downloaded signature database is empty: $Uri"
}

$ResolveAliases = @{}
foreach ($Match in [regex]::Matches($Source, 'const\s+(?<name>[A-Z0-9_]+)\s*:\s*ResolveKind\s*=\s*(?<expr>.*?);')) {
    $Name = $Match.Groups["name"].Value
    $Expr = $Match.Groups["expr"].Value.Trim()
    if ($Expr -match 'ResolveKind::(?<kind>Rel32|RipRel)\s*\{\s*rel_off:\s*(?<off>\d+)\s*\}') {
        $ResolveAliases[$Name] = [pscustomobject]@{
            kind = $Matches.kind
            rel_off = [int]$Matches.off
        }
    } elseif ($Expr -match 'ResolveKind::(?<kind>None|StringRef)') {
        $ResolveAliases[$Name] = [pscustomobject]@{
            kind = $Matches.kind
            rel_off = 0
        }
    }
}

$ExistingKeys = Read-ExistingSignatureKeys -Directory $ExistingPath -ExcludePath $OutputPath
$Converted = [ordered]@{
    _metadata = [ordered]@{
        generator = "import-cs2-universal-offsets.ps1"
        source_project = "scros22/cs2-universal-offsets"
        source_url = $Uri
        module = "multi"
        runtime = "windows"
        generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        signatures_generated = 0
        signatures_skipped_existing = 0
    }
}

$SignatureBlocks = Get-SignatureBlocks -Text $Source
if ($SignatureBlocks.Count -eq 0) {
    throw "No Signature entries were parsed from $Uri"
}

$Generated = 0
$SkippedExisting = 0

foreach ($Block in $SignatureBlocks) {
    $Name = Read-RustStringField -Block $Block -Field "name"
    $Module = Normalize-ModuleName (Read-RustStringField -Block $Block -Field "module")
    $Needle = Read-RustStringField -Block $Block -Field "needle"
    $ExtraOffset = Read-RustIntegerField -Block $Block -Field "extra_off"
    $Resolve = Get-ResolveKind -ResolveText (Read-RustResolveField -Block $Block) -ResolveAliases $ResolveAliases

    $ExistingKey = "$Module|$Name"
    if (-not $IncludeExisting -and $ExistingKeys.Contains($ExistingKey)) {
        ++$SkippedExisting
        continue
    }

    $Entry = [ordered]@{
        pattern = $Needle
        ida_pattern = $Needle
        module = $Module
        category = "cs2_universal_offsets"
        importance = "optional"
        required = $false
        result_type = "absolute_address"
        source = "cs2_universal_offsets"
        source_project = "scros22/cs2-universal-offsets"
        source_url = $Uri
        quality = "external"
    }

    if ($ExtraOffset -ne 0) {
        $Entry.address_offset = $ExtraOffset
    }

    switch ($Resolve.kind) {
        "StringRef" {
            $Entry.string_ref = $Needle
            $Entry.result_type = "function_address"
            $Entry.resolver = [ordered]@{
                type = "string_ref"
                result_type = "function_address"
            }
        }
        "Rel32" {
            $InstructionSize = [int]$Resolve.rel_off + 4
            $Entry.result_type = "function_address"
            $Entry.resolver = [ordered]@{
                type = "rip_relative"
                result_type = "function_address"
                operand_offset = [int]$Resolve.rel_off
                operand_size = 4
                instruction_offset = 0
                instruction_size = $InstructionSize
            }
        }
        "RipRel" {
            $InstructionSize = [int]$Resolve.rel_off + 4
            $Entry.result_type = "module_rva"
            $Entry.resolver = [ordered]@{
                type = "rip_relative"
                result_type = "module_rva"
                operand_offset = [int]$Resolve.rel_off
                operand_size = 4
                instruction_offset = 0
                instruction_size = $InstructionSize
            }
        }
        "None" {}
        default {
            throw "Unsupported parsed ResolveKind: $($Resolve.kind)"
        }
    }

    Add-UniqueEntry -Map $Converted -Name $Name -Entry $Entry
    ++$Generated
}

if ($Generated -eq 0) {
    throw "No new signatures were generated. Use -IncludeExisting to include entries already present locally."
}

$Converted._metadata.signatures_generated = $Generated
$Converted._metadata.signatures_skipped_existing = $SkippedExisting

$Json = $Converted | ConvertTo-Json -Depth 16
Write-Utf8NoBomLf -Path $OutputPath -Text $Json

if (-not $NoUpdateIndex) {
    & (Join-Path $PSScriptRoot "update-signatures.ps1") `
        -Source $ExistingPath `
        -Output $ExistingPath `
        -BaseUrl $BaseUrl `
        -Build $Build
}

Write-Host "Imported $Generated cs2-universal-offsets signature(s) to $OutputPath"
if ($SkippedExisting -gt 0) {
    Write-Host "Skipped $SkippedExisting existing entr$(if ($SkippedExisting -eq 1) { 'y' } else { 'ies' }). Use -IncludeExisting to keep duplicates."
}
