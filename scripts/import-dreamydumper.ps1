param(
    [string]$ManualUri = "https://raw.githubusercontent.com/CBXPL/DreamyDumper/main/Manual/Patterns.list",
    [string[]]$FieldUris = @(
        "https://raw.githubusercontent.com/CBXPL/DreamyDumper/main/2_0_dumps/player.json",
        "https://raw.githubusercontent.com/CBXPL/DreamyDumper/main/2_0_dumps/weaponbase.json",
        "https://raw.githubusercontent.com/CBXPL/DreamyDumper/main/2_0_dumps/cameraservices.json"
    ),
    [string]$Output = "signatures\dreamy_signatures.json",
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

function Resolve-OutputPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Resolved = Resolve-RepoPath $Path
    if ([System.IO.Path]::GetExtension($Resolved).ToLowerInvariant() -eq ".json") {
        return $Resolved
    }

    return Join-Path $Resolved "dreamy_signatures.json"
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

function Normalize-IdaPattern {
    param([Parameter(Mandatory = $true)][string]$Pattern)

    $Tokens = New-Object System.Collections.Generic.List[string]
    foreach ($Token in ($Pattern.Trim() -split '\s+')) {
        if ($Token -eq "") {
            continue
        }

        if ($Token -match '^\?+$') {
            $Tokens.Add("?")
            continue
        }

        if ($Token -match '^[0-9A-Fa-f]{2}$') {
            $Tokens.Add($Token.ToUpperInvariant())
            continue
        }

        throw "Unsupported IDA pattern token '$Token' in pattern: $Pattern"
    }

    if ($Tokens.Count -eq 0) {
        throw "Pattern is empty."
    }

    return ($Tokens -join " ")
}

function Get-JsonTextValue {
    param($Object, [string]$Name)
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or $null -eq $Property.Value) {
        return ""
    }
    return ([string]$Property.Value).Trim()
}

function ConvertTo-Int64OrNull {
    param($Value)
    if ($null -eq $Value) {
        return $null
    }

    $Text = ([string]$Value).Trim()
    if ($Text -eq "") {
        return $null
    }

    if ($Text -match '^0x[0-9A-Fa-f]+$') {
        return [Convert]::ToInt64($Text.Substring(2), 16)
    }

    return [int64]$Text
}

function Read-ExistingSignatureIndex {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [string]$ExcludePath = ""
    )

    $NameKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $PatternKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    if (-not (Test-Path -LiteralPath $Directory)) {
        return [pscustomobject]@{
            NameKeys = $NameKeys
            PatternKeys = $PatternKeys
        }
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

                [void]$NameKeys.Add("$Module|$($Property.Name)")

                $Pattern = Get-JsonTextValue -Object $Property.Value -Name "ida_pattern"
                if ($Pattern -eq "") {
                    $Pattern = Get-JsonTextValue -Object $Property.Value -Name "pattern"
                }
                if ($Pattern -ne "") {
                    try {
                        [void]$PatternKeys.Add("$Module|$(Normalize-IdaPattern $Pattern)")
                    } catch {
                        # Existing packs may contain string-ref entries where the pattern field is not byte-style.
                    }
                }
            }
        }

    return [pscustomobject]@{
        NameKeys = $NameKeys
        PatternKeys = $PatternKeys
    }
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

function Get-DreamyDisplayName {
    param([Parameter(Mandatory = $true)][string]$RawName)

    $Name = $RawName.Trim()
    if ($Name.Contains("/")) {
        $Parts = $Name -split "/"
        $Name = $Parts[$Parts.Length - 1]
    }
    return $Name
}

function Get-WildcardOperand {
    param([Parameter(Mandatory = $true)][string]$Pattern)

    $Tokens = @((Normalize-IdaPattern $Pattern) -split " ")
    for ($Index = 0; $Index -le $Tokens.Count - 4; ++$Index) {
        if ($Tokens[$Index] -eq "?" -and
            $Tokens[$Index + 1] -eq "?" -and
            $Tokens[$Index + 2] -eq "?" -and
            $Tokens[$Index + 3] -eq "?") {
            return [pscustomobject]@{
                Offset = $Index
                Size = 4
            }
        }
    }

    for ($Index = 0; $Index -lt $Tokens.Count; ++$Index) {
        if ($Tokens[$Index] -eq "?") {
            return [pscustomobject]@{
                Offset = $Index
                Size = 1
            }
        }
    }

    return $null
}

function Get-FieldGroupFromUri {
    param([Parameter(Mandatory = $true)][string]$Uri)

    $Path = ([System.Uri]$Uri).AbsolutePath
    return [System.IO.Path]::GetFileNameWithoutExtension($Path)
}

$OutputPath = Resolve-OutputPath $Output
$ExistingPath = Resolve-RepoPath $ExistingSignatureDirectory

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null

$ExistingIndex = Read-ExistingSignatureIndex -Directory $ExistingPath -ExcludePath $OutputPath
$Converted = [ordered]@{
    _metadata = [ordered]@{
        generator = "import-dreamydumper.ps1"
        source_project = "CBXPL/DreamyDumper"
        source_url = "https://github.com/CBXPL/DreamyDumper"
        module = "multi"
        runtime = "windows"
        generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        source_license = "none-declared-upstream"
        manual_uri = $ManualUri
        field_uris = @($FieldUris)
        manual_signatures_generated = 0
        field_offset_signatures_generated = 0
        signatures_skipped_existing = 0
        field_offsets_skipped = 0
        ambiguous_field_patterns_skipped = 0
        static_data_table_skipped = 0
    }
}

$GeneratedManual = 0
$GeneratedFields = 0
$SkippedExisting = 0
$SkippedFields = 0
$SkippedAmbiguous = 0
$SkippedStatic = 0

$ManualText = (Invoke-WebRequest -UseBasicParsing -Uri $ManualUri).Content
if ([string]::IsNullOrWhiteSpace($ManualText)) {
    throw "Downloaded manual pattern list is empty: $ManualUri"
}

$ManualRegex = [regex]'(?<name>[A-Za-z0-9_:<>~\/.\-]+)\s*=\s*(?<pattern>.*?)\s*\|\s*(?<module>[A-Za-z0-9_.\-]+\.dll)(?=\s+[A-Za-z0-9_:<>~\/.\-]+\s*=|$)'
$ManualMatches = $ManualRegex.Matches($ManualText)
if ($ManualMatches.Count -eq 0) {
    throw "No manual DreamyDumper patterns were parsed from $ManualUri"
}

foreach ($Match in $ManualMatches) {
    $RawName = $Match.Groups["name"].Value.Trim()
    $Name = Get-DreamyDisplayName -RawName $RawName
    $Pattern = Normalize-IdaPattern $Match.Groups["pattern"].Value
    $Module = Normalize-ModuleName $Match.Groups["module"].Value

    $ExistingNameKey = "$Module|$Name"
    $ExistingPatternKey = "$Module|$Pattern"
    if (-not $IncludeExisting -and
        ($ExistingIndex.NameKeys.Contains($ExistingNameKey) -or $ExistingIndex.PatternKeys.Contains($ExistingPatternKey))) {
        ++$SkippedExisting
        continue
    }

    $Entry = [ordered]@{
        pattern = $Pattern
        ida_pattern = $Pattern
        module = $Module
        category = "dreamydumper_manual"
        importance = "optional"
        required = $false
        result_type = "function_address"
        source = "dreamydumper_manual"
        source_project = "CBXPL/DreamyDumper"
        source_url = $ManualUri
        upstream_name = $RawName
        quality = "external"
    }

    if ($Name -eq "GlobalVars" -or $RawName -eq "GlobalVars") {
        $Entry.result_type = "module_rva"
        $Entry.resolver = [ordered]@{
            type = "rip_relative"
            result_type = "module_rva"
            operand_offset = 3
            operand_size = 4
            instruction_offset = 0
            instruction_size = 7
        }
    }

    Add-UniqueEntry -Map $Converted -Name $Name -Entry $Entry
    ++$GeneratedManual
}

$FieldCandidates = New-Object System.Collections.Generic.List[object]
$FieldPatternCounts = @{}

foreach ($FieldUri in $FieldUris) {
    $FieldText = (Invoke-WebRequest -UseBasicParsing -Uri $FieldUri).Content
    if ([string]::IsNullOrWhiteSpace($FieldText)) {
        throw "Downloaded field-offset JSON is empty: $FieldUri"
    }

    $FieldJson = $FieldText | ConvertFrom-Json
    $FieldGroup = Get-FieldGroupFromUri -Uri $FieldUri

    foreach ($Property in $FieldJson.PSObject.Properties) {
        if ($Property.Name -eq "metadata") {
            continue
        }

        $FieldName = $Property.Name
        $Pattern = Get-JsonTextValue -Object $Property.Value -Name "pattern"
        if ($Pattern -eq "" -or $Pattern -eq "STATIC_DATA_TABLE") {
            ++$SkippedStatic
            continue
        }

        $Operand = Get-WildcardOperand -Pattern $Pattern
        if ($null -eq $Operand) {
            ++$SkippedFields
            continue
        }

        $Pattern = Normalize-IdaPattern $Pattern
        $Module = "client.dll"
        $Expected = ConvertTo-Int64OrNull (Get-JsonTextValue -Object $Property.Value -Name "offset")
        if ($null -eq $Expected) {
            $Expected = ConvertTo-Int64OrNull (Get-JsonTextValue -Object $Property.Value -Name "hex_offset")
        }

        $FieldPatternKey = "$Module|$Pattern"
        if (-not $FieldPatternCounts.ContainsKey($FieldPatternKey)) {
            $FieldPatternCounts[$FieldPatternKey] = 0
        }
        ++$FieldPatternCounts[$FieldPatternKey]

        $FieldCandidates.Add([pscustomobject]@{
            Name = $FieldName
            Pattern = $Pattern
            Module = $Module
            FieldGroup = $FieldGroup
            Location = (Get-JsonTextValue -Object $Property.Value -Name "location")
            SourceUrl = $FieldUri
            OperandOffset = [int]$Operand.Offset
            OperandSize = [int]$Operand.Size
            Expected = $Expected
        })
    }
}

foreach ($Candidate in $FieldCandidates) {
    $FieldPatternKey = "$($Candidate.Module)|$($Candidate.Pattern)"
    if ($FieldPatternCounts[$FieldPatternKey] -gt 1) {
        ++$SkippedAmbiguous
        continue
    }

    $ExistingNameKey = "$($Candidate.Module)|$($Candidate.Name)"
    if (-not $IncludeExisting -and
        ($ExistingIndex.NameKeys.Contains($ExistingNameKey) -or $ExistingIndex.PatternKeys.Contains($FieldPatternKey))) {
        ++$SkippedExisting
        continue
    }

        $Resolver = [ordered]@{
            type = "instruction_displacement"
            result_type = "field_offset"
            operand_offset = [int]$Candidate.OperandOffset
            operand_size = [int]$Candidate.OperandSize
            instruction_offset = 0
        }

        if ($null -ne $Candidate.Expected) {
            $Resolver.expected = [int64]$Candidate.Expected
        }

        $Entry = [ordered]@{
            pattern = $Candidate.Pattern
            ida_pattern = $Candidate.Pattern
            module = $Candidate.Module
            category = "dreamydumper_field_offset"
            importance = "optional"
            required = $false
            result_type = "field_offset"
            source = "dreamydumper_field_offset"
            source_project = "CBXPL/DreamyDumper"
            source_url = $Candidate.SourceUrl
            field_group = $Candidate.FieldGroup
            location = $Candidate.Location
            quality = "external"
            resolver = $Resolver
        }

        Add-UniqueEntry -Map $Converted -Name $Candidate.Name -Entry $Entry
        ++$GeneratedFields
}

if (($GeneratedManual + $GeneratedFields) -eq 0) {
    throw "No new DreamyDumper signatures were generated. Use -IncludeExisting to include entries already present locally."
}

$Converted._metadata.manual_signatures_generated = $GeneratedManual
$Converted._metadata.field_offset_signatures_generated = $GeneratedFields
$Converted._metadata.signatures_skipped_existing = $SkippedExisting
$Converted._metadata.field_offsets_skipped = $SkippedFields
$Converted._metadata.ambiguous_field_patterns_skipped = $SkippedAmbiguous
$Converted._metadata.static_data_table_skipped = $SkippedStatic

$Json = $Converted | ConvertTo-Json -Depth 16
Write-Utf8NoBomLf -Path $OutputPath -Text $Json

if (-not $NoUpdateIndex) {
    & (Join-Path $PSScriptRoot "update-signatures.ps1") `
        -Source $ExistingPath `
        -Output $ExistingPath `
        -BaseUrl $BaseUrl `
        -Build $Build
}

Write-Host "Imported $GeneratedManual DreamyDumper manual signature(s) and $GeneratedFields field-offset signature(s) to $OutputPath"
if ($SkippedExisting -gt 0) {
    Write-Host "Skipped $SkippedExisting existing entr$(if ($SkippedExisting -eq 1) { 'y' } else { 'ies' }). Use -IncludeExisting to keep duplicates."
}
if ($SkippedStatic -gt 0 -or $SkippedFields -gt 0 -or $SkippedAmbiguous -gt 0) {
    Write-Host "Skipped $SkippedStatic static data-table field(s), $SkippedFields field(s) without a usable wildcard operand, and $SkippedAmbiguous ambiguous field pattern(s)."
}
