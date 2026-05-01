param(
    [string]$TargetFile = "tools/targets/cs2_targets.json",
    [string]$KnownOffsetFile = "tools/targets/known_offsets.json",
    [string]$SignatureDirectory = "signatures"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Errors = @()
$Warnings = @()
$SignatureCache = @{}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path $Root $Path
}

function Add-ValidationError {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:Errors += $Message
}

function Add-ValidationWarning {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:Warnings += $Message
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "File was not found: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
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

function Get-BoolField {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [bool]$Default = $false
    )
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property -or $null -eq $Property.Value) {
        return $Default
    }
    return [bool]$Property.Value
}

function Normalize-ModuleName {
    param([string]$Value)
    $Name = ([string]$Value).Trim().ToLowerInvariant()
    if ($Name.EndsWith(".dll")) {
        $Name = [System.IO.Path]::GetFileNameWithoutExtension($Name)
    }
    if ($Name.StartsWith("lib") -and $Name.EndsWith(".so")) {
        $Name = $Name.Substring(3, $Name.Length - 6)
    }
    return $Name
}

function Get-SignatureFile {
    param([Parameter(Mandatory = $true)][string]$Module)

    $ModuleKey = Normalize-ModuleName $Module
    if ($script:SignatureCache.ContainsKey($ModuleKey)) {
        return $script:SignatureCache[$ModuleKey]
    }

    $SignaturePath = Join-Path (Resolve-RepoPath $SignatureDirectory) ($ModuleKey + "_signatures.json")
    if (-not (Test-Path -LiteralPath $SignaturePath)) {
        $script:SignatureCache[$ModuleKey] = $null
        return $null
    }

    $Json = Read-JsonFile $SignaturePath
    $script:SignatureCache[$ModuleKey] = $Json
    return $Json
}

function Get-SignatureEntry {
    param(
        [Parameter(Mandatory = $true)]$SignatureFile,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $Property = $SignatureFile.PSObject.Properties[$Name]
    if ($null -eq $Property) {
        return $null
    }
    return $Property.Value
}

function Get-NumericField {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $Value = Get-TextField $Object $Name
    if ($Value -eq "") {
        return $null
    }
    $Number = 0.0
    if ([double]::TryParse($Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$Number)) {
        return $Number
    }
    return $null
}

function Validate-SignatureTarget {
    param(
        [Parameter(Mandatory = $true)]$Target,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Module,
        [bool]$Required
    )

    $SignatureFile = Get-SignatureFile $Module
    if ($null -eq $SignatureFile) {
        if ($Required) {
            Add-ValidationError "Signature file missing for required target $Module/$Name"
        } else {
            Add-ValidationWarning "Signature file missing for optional target $Module/$Name"
        }
        return
    }

    $Entry = Get-SignatureEntry $SignatureFile $Name
    if ($null -eq $Entry) {
        if ($Required) {
            Add-ValidationError "Signature target missing: $Module/$Name"
        } else {
            Add-ValidationWarning "Optional signature target missing: $Module/$Name"
        }
        return
    }

    $Pattern = Get-TextField $Entry "pattern"
    $IdaPattern = Get-TextField $Entry "ida_pattern"
    $CodePattern = Get-TextField $Entry "code_style_pattern"
    if ($Pattern -eq "" -and $IdaPattern -eq "" -and $CodePattern -eq "") {
        Add-ValidationError "Signature target has no pattern: $Module/$Name"
    }

    $EntryModule = Get-TextField $Entry "module"
    if ($EntryModule -ne "" -and (Normalize-ModuleName $EntryModule) -ne (Normalize-ModuleName $Module)) {
        Add-ValidationError "Signature module mismatch for $Module/$Name`: entry module is $EntryModule"
    }

    $ExpectedResultType = Get-TextField $Target "result_type"
    $ActualResultType = Get-TextField $Entry "result_type"
    if ($ExpectedResultType -ne "" -and $ActualResultType -ne "" -and $ExpectedResultType -ne $ActualResultType) {
        Add-ValidationError "result_type mismatch for $Module/$Name`: expected $ExpectedResultType, got $ActualResultType"
    }

    $MinConfidence = Get-NumericField $Target "min_confidence"
    if ($null -ne $MinConfidence) {
        $Confidence = Get-NumericField $Entry "confidence"
        if ($null -eq $Confidence) {
            $Confidence = Get-NumericField $Entry "quality_score"
        }
        if ($null -eq $Confidence -or $Confidence -lt $MinConfidence) {
            Add-ValidationError "Confidence below target for $Module/$Name`: expected at least $MinConfidence"
        }
    }
}

function Validate-KnownOffsetTarget {
    param(
        [Parameter(Mandatory = $true)]$Target,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Module
    )

    $ResultType = Get-TextField $Target "result_type"
    if ($ResultType -eq "") {
        Add-ValidationError "Known offset target has no result_type: $Module/$Name"
    }

    $Resolver = Get-TextField $Target "resolver"
    if ($Resolver -eq "") {
        Add-ValidationError "Known offset target has no resolver: $Module/$Name"
    }
}

$AllowedKinds = @("signature", "known_offset", "vtable", "vfunc", "schema_field", "interface")
$AllowedResultTypes = @("absolute_address", "module_rva", "field_offset", "function_address", "")
$AllowedResolvers = @("direct_match", "rip_relative", "instruction_displacement", "schema_field", "vtable_index", "none", "")
$AllowedStability = @("stable", "good", "volatile", "experimental", "")

$TargetPath = Resolve-RepoPath $TargetFile
$RootObject = Read-JsonFile $TargetPath

if ([int]$RootObject.schema_version -ne 1) {
    Add-ValidationError "Unsupported target schema_version: $($RootObject.schema_version)"
}

if ($null -eq $RootObject.targets) {
    Add-ValidationError "Target registry has no targets array."
}

$Seen = @{}
$KnownOffsetRegistry = @{}
$Targets = @($RootObject.targets)
$SignatureCount = 0
$KnownOffsetCount = 0

foreach ($Target in $Targets) {
    $Name = Get-TextField $Target "name"
    $Module = Normalize-ModuleName (Get-TextField $Target "module")
    $Kind = (Get-TextField $Target "kind").ToLowerInvariant()
    $ResultType = (Get-TextField $Target "result_type").ToLowerInvariant()
    $Resolver = (Get-TextField $Target "resolver").ToLowerInvariant()
    $Stability = (Get-TextField $Target "stability").ToLowerInvariant()
    $Required = Get-BoolField $Target "required" $true

    if ($Name -eq "") {
        Add-ValidationError "Target has no name."
        continue
    }
    if ($Module -eq "") {
        Add-ValidationError "Target has no module: $Name"
        continue
    }
    if ($Kind -eq "") {
        Add-ValidationError "Target has no kind: $Module/$Name"
        continue
    }

    $Key = "$Module|$Kind|$Name"
    if ($Seen.ContainsKey($Key)) {
        Add-ValidationError "Duplicate target: $Module/$Kind/$Name"
        continue
    }
    $Seen[$Key] = $true

    if ($AllowedKinds -notcontains $Kind) {
        Add-ValidationError "Unsupported target kind for $Module/$Name`: $Kind"
    }
    if ($AllowedResultTypes -notcontains $ResultType) {
        Add-ValidationError "Unsupported result_type for $Module/$Name`: $ResultType"
    }
    if ($AllowedResolvers -notcontains $Resolver) {
        Add-ValidationError "Unsupported resolver for $Module/$Name`: $Resolver"
    }
    if ($AllowedStability -notcontains $Stability) {
        Add-ValidationError "Unsupported stability for $Module/$Name`: $Stability"
    }

    if ($Kind -eq "signature") {
        ++$SignatureCount
        Validate-SignatureTarget -Target $Target -Name $Name -Module $Module -Required $Required
    } elseif ($Kind -eq "known_offset") {
        ++$KnownOffsetCount
        $KnownOffsetRegistry["$Module|$Name"] = $Target
        Validate-KnownOffsetTarget -Target $Target -Name $Name -Module $Module
    }
}

$KnownOffsetPath = Resolve-RepoPath $KnownOffsetFile
$KnownOffsetRoot = Read-JsonFile $KnownOffsetPath
if ([int]$KnownOffsetRoot.schema_version -ne 1) {
    Add-ValidationError "Unsupported known offset schema_version: $($KnownOffsetRoot.schema_version)"
}
if ($null -eq $KnownOffsetRoot.patterns) {
    Add-ValidationError "known_offsets.json has no patterns array."
}

$KnownOffsetPatterns = @($KnownOffsetRoot.patterns)
$KnownOffsetPatternKeys = @{}
$AllowedCaptureModes = @("rip_relative", "u8_immediate", "u32_immediate")

foreach ($Pattern in $KnownOffsetPatterns) {
    $Name = Get-TextField $Pattern "name"
    $Module = Normalize-ModuleName (Get-TextField $Pattern "module")
    $PatternText = Get-TextField $Pattern "pattern"
    $ResultType = (Get-TextField $Pattern "result_type").ToLowerInvariant()
    $CaptureProperty = $Pattern.PSObject.Properties["capture"]
    $Capture = if ($null -eq $CaptureProperty) { $null } else { $CaptureProperty.Value }

    if ($Name -eq "") {
        Add-ValidationError "Known offset pattern has no name."
        continue
    }
    if ($Module -eq "") {
        Add-ValidationError "Known offset pattern has no module: $Name"
        continue
    }
    if ($PatternText -eq "") {
        Add-ValidationError "Known offset pattern has no pattern: $Module/$Name"
    }
    if ($AllowedResultTypes -notcontains $ResultType) {
        Add-ValidationError "Unsupported known offset result_type for $Module/$Name`: $ResultType"
    }

    $Key = "$Module|$Name"
    if ($KnownOffsetPatternKeys.ContainsKey($Key)) {
        Add-ValidationError "Duplicate known offset pattern: $Module/$Name"
    }
    $KnownOffsetPatternKeys[$Key] = $Pattern

    if (-not $KnownOffsetRegistry.ContainsKey($Key)) {
        Add-ValidationError "Known offset pattern is not listed in target registry: $Module/$Name"
    }

    if ($null -eq $Capture) {
        Add-ValidationError "Known offset pattern has no capture object: $Module/$Name"
        continue
    }

    $Mode = (Get-TextField $Capture "mode").ToLowerInvariant()
    $Offset = Get-TextField $Capture "offset"
    if ($AllowedCaptureModes -notcontains $Mode) {
        Add-ValidationError "Unsupported capture mode for $Module/$Name`: $Mode"
    }
    if ($Offset -eq "") {
        Add-ValidationError "Known offset capture has no offset: $Module/$Name"
    }
    if ($Mode -eq "rip_relative") {
        $InstructionLength = Get-TextField $Capture "instruction_length"
        if ($InstructionLength -eq "") {
            Add-ValidationError "RIP-relative known offset has no instruction_length: $Module/$Name"
        }
    }
}

foreach ($Key in $KnownOffsetRegistry.Keys) {
    if (-not $KnownOffsetPatternKeys.ContainsKey($Key)) {
        Add-ValidationError "Target registry known offset has no pattern: $Key"
    }
}

if ($KnownOffsetRoot.build_overrides) {
    foreach ($Override in @($KnownOffsetRoot.build_overrides)) {
        $Name = Get-TextField $Override "name"
        $Module = Normalize-ModuleName (Get-TextField $Override "module")
        $Build = Get-TextField $Override "build"
        $Rva = Get-TextField $Override "rva"
        if ($Name -eq "" -or $Module -eq "" -or $Build -eq "" -or $Rva -eq "") {
            Add-ValidationError "Build override is missing build/module/name/rva."
            continue
        }

        $Key = "$Module|$Name"
        if (-not $KnownOffsetPatternKeys.ContainsKey($Key)) {
            Add-ValidationError "Build override target has no known offset pattern: $Module/$Name"
        }
    }
}

foreach ($Warning in $Warnings) {
    Write-Warning $Warning
}

if ($Errors.Count -gt 0) {
    foreach ($Failure in $Errors) {
        Write-Host "ERROR: $Failure"
    }
    exit 1
}

Write-Output "Verified $($Targets.Count) target(s)."
Write-Output "Signature targets: $SignatureCount"
Write-Output "Known offset targets: $KnownOffsetCount"
Write-Output "Known offset patterns: $($KnownOffsetPatterns.Count)"
exit 0
