<#
.SYNOPSIS
    Automated CS2 signature update pipeline.
    Detects CS2 updates, runs IDA headless analysis, and pushes new signatures to GitHub.

.DESCRIPTION
    Designed to run as a Windows Scheduled Task every 5-10 minutes.
    When a CS2 update is detected:
      1. Waits for CDN propagation
      2. Locates updated DLLs (local Steam or SteamCMD)
      3. Runs IDA 9.2 headless on each module
      4. Updates signatures/index.json
      5. Commits and pushes to GitHub
      6. Creates a GitHub release
      7. Sends Discord notification

.PARAMETER ConfigPath
    Path to the JSON config file. Default: auto-update-config.json next to this script.

.PARAMETER Force
    Skip build ID check and run the pipeline regardless.

.PARAMETER DryRun
    Run all steps except git push, release creation, and Discord notification.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$Force,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve paths

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $ScriptDir "auto-update-config.json"
}

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config not found: $ConfigPath. Copy auto-update-config.example.json and fill in your paths."
    exit 1
}

$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# Defaults

function Cfg([string]$Key, $Default) {
    $val = $Config.PSObject.Properties[$Key]
    if ($null -eq $val -or $null -eq $val.Value -or $val.Value -eq "") { return $Default }
    return $val.Value
}

$IdaPath = Cfg "ida_path"            "C:\Program Files\IDA Professional 9.2"
$IdaExe = Cfg "ida_executable"      "idat.exe"
$IdaScript = Cfg "ida_script"          (Join-Path $ScriptDir "..\tools\ida\cs2_sig_dumper.py")
$DllSource = Cfg "dll_source"          "local_steam"
$SteamLibrary = Cfg "steam_library"       ""
$SteamcmdPath = Cfg "steamcmd_path"       ""
$SteamcmdLogin = Cfg "steamcmd_login"      "anonymous"
$SteamcmdAppId = Cfg "steamcmd_app_id"     730
$DepotPath = Cfg "depot_path"          ""
$RepoPath = Cfg "repo_path"           (Resolve-Path (Join-Path $ScriptDir "..")).Path
$WorkDir = Cfg "work_dir"            (Join-Path $env:LOCALAPPDATA "cs2sign-auto")
$UpdateWaitSec = Cfg "update_wait_seconds" 900
$IdaTimeoutSec = Cfg "ida_timeout_seconds" 1800
$DownloadAttempts = Cfg "download_attempts"   3
$PushAttempts = Cfg "push_attempts"       3
$MaxFailures = Cfg "max_consecutive_failures" 5
$RequireAllModules = Cfg "require_all_modules" $true
$CreateGitHubRelease = Cfg "create_github_release" $false
$MaxSignatureDropPercent = Cfg "max_signature_drop_percent" 80
$CleanupIdb = Cfg "cleanup_idb"         $true
$LogRetentionDays = Cfg "log_retention_days"  30
$IdaPriority = Cfg "ida_priority"        "BelowNormal"
$DiscordWebhook = Cfg "discord_webhook"     ""

$Modules = @()
foreach ($m in $Config.modules) {
    $Modules += @{ name = $m.name; dll_rel = $m.dll_rel }
}

$StatePath = Join-Path $WorkDir "state.json"
$LockPath = Join-Path $WorkDir "lockfile"
$LogDir = Join-Path $WorkDir "logs"
$IdaOutDir = Join-Path $WorkDir "ida_output"
$IdbDir = Join-Path $WorkDir "idb"
$SignatureStageDir = Join-Path $WorkDir "signature_stage"

$IdaFullPath = Join-Path $IdaPath $IdaExe
$IdaScriptFull = Resolve-Path $IdaScript -ErrorAction SilentlyContinue
if (-not $IdaScriptFull) { $IdaScriptFull = $IdaScript }

$SteamApiUrl = "https://api.steampowered.com/ISteamApps/UpToDateCheck/v1/?appid=730&version=0"

# Ensure directories

foreach ($dir in @($WorkDir, $LogDir, $IdaOutDir, $IdbDir, $SignatureStageDir)) {
    if (-not (Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
}

# Logging

$LogFile = Join-Path $LogDir "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$LogStream = $null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    if ($null -ne $LogStream) {
        $LogStream.WriteLine($line)
        $LogStream.Flush()
    }
}

function Start-Logging {
    $script:LogStream = [System.IO.StreamWriter]::new($LogFile, $true, [System.Text.Encoding]::UTF8)
    Write-Log "=== cs2sign auto-update started ==="
    Write-Log "Config: $ConfigPath"
    Write-Log "WorkDir: $WorkDir"
    Write-Log "RepoPath: $RepoPath"
    Write-Log "DryRun: $DryRun"
}

function Stop-Logging {
    if ($null -ne $script:LogStream) {
        Write-Log "=== cs2sign auto-update finished ==="
        $script:LogStream.Close()
        $script:LogStream = $null
    }
}

# Lock file

function Test-Lock {
    if (-not (Test-Path $LockPath)) { return $false }
    $lockAge = (Get-Date) - (Get-Item $LockPath).LastWriteTime
    if ($lockAge.TotalHours -ge 2) {
        Write-Log "Stale lock found ($([int]$lockAge.TotalMinutes) min old), removing." "WARN"
        Remove-Item $LockPath -Force
        return $false
    }
    return $true
}

function Set-Lock { Set-Content $LockPath "$$" -Force }
function Clear-Lock { Remove-Item $LockPath -Force -ErrorAction SilentlyContinue }

# State

function Read-State {
    if (Test-Path $StatePath) {
        return Get-Content $StatePath -Raw | ConvertFrom-Json
    }
    return [PSCustomObject]@{
        last_buildid         = 0
        last_update_utc      = ""
        last_status          = ""
        consecutive_failures = 0
        history              = @()
    }
}

function Save-State($state) {
    $state | ConvertTo-Json -Depth 4 | Set-Content $StatePath -Encoding UTF8
}

# Steam API

function Get-CurrentBuildId {
    try {
        $resp = Invoke-RestMethod -Uri $SteamApiUrl -TimeoutSec 15
        $ver = $resp.response.required_version
        if ($ver -and $ver -gt 0) {
            Write-Log "Steam API returned build $ver"
            return [int]$ver
        }
        Write-Log "Steam API returned unexpected response" "WARN"
    }
    catch {
        Write-Log "Steam API request failed: $_" "WARN"
    }

    # Fallback: read steam.inf from local install
    if ($SteamLibrary -and (Test-Path $SteamLibrary)) {
        $steamInf = Join-Path $SteamLibrary "game\csgo\steam.inf"
        if (Test-Path $steamInf) {
            $content = Get-Content $steamInf -Raw
            if ($content -match "ServerVersion=(\d+)") {
                $ver = [int]$Matches[1]
                Write-Log "Fallback: steam.inf build $ver"
                return $ver
            }
        }
    }

    return 0
}

function Get-LocalSteamBuildId {
    if (-not $SteamLibrary -or -not (Test-Path $SteamLibrary)) {
        return 0
    }

    $steamInf = Join-Path $SteamLibrary "game\csgo\steam.inf"
    if (-not (Test-Path $steamInf)) {
        return 0
    }

    $content = Get-Content $steamInf -Raw
    if ($content -match "ServerVersion=(\d+)") {
        return [int]$Matches[1]
    }

    return 0
}

function Invoke-GitChecked {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $oldGitPrompt = $env:GIT_TERMINAL_PROMPT
    $oldGcmInteractive = $env:GCM_INTERACTIVE

    try {
        $env:GIT_TERMINAL_PROMPT = "0"
        $env:GCM_INTERACTIVE = "never"

        & git @Arguments 2>&1 | ForEach-Object { Write-Log "git: $_" }
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        if ($null -eq $oldGitPrompt) {
            Remove-Item Env:GIT_TERMINAL_PROMPT -ErrorAction SilentlyContinue
        }
        else {
            $env:GIT_TERMINAL_PROMPT = $oldGitPrompt
        }

        if ($null -eq $oldGcmInteractive) {
            Remove-Item Env:GCM_INTERACTIVE -ErrorAction SilentlyContinue
        }
        else {
            $env:GCM_INTERACTIVE = $oldGcmInteractive
        }
    }
}

# DLL source

function Get-DllPath([string]$DllRel) {
    if ($DllSource -eq "local_steam") {
        return Join-Path $SteamLibrary $DllRel
    }
    else {
        $root = if ($DepotPath) { $DepotPath } else { Join-Path $WorkDir "depot" }
        return Join-Path $root $DllRel
    }
}

function Invoke-SteamCmdDownload {
    if ($DllSource -ne "steamcmd") { return $true }

    $depotDir = if ($DepotPath) { $DepotPath } else { Join-Path $WorkDir "depot" }

    for ($attempt = 1; $attempt -le $DownloadAttempts; $attempt++) {
        Write-Log "SteamCMD download attempt $attempt/$DownloadAttempts"
        $proc = Start-Process -FilePath $SteamcmdPath -ArgumentList @(
            "+force_install_dir", "`"$depotDir`"",
            "+login", $SteamcmdLogin,
            "+app_update", $SteamcmdAppId, "validate",
            "+quit"
        ) -PassThru -NoNewWindow -Wait

        if ($proc.ExitCode -eq 0) {
            Write-Log "SteamCMD download completed"
            return $true
        }

        Write-Log "SteamCMD exit code $($proc.ExitCode)" "WARN"
        if ($attempt -lt $DownloadAttempts) {
            $wait = $attempt * 60
            Write-Log "Retrying in $wait seconds..."
            Start-Sleep -Seconds $wait
        }
    }

    Write-Log "SteamCMD download failed after $DownloadAttempts attempts" "ERROR"
    return $false
}

function Test-DllsAvailable {
    $allOk = $true
    foreach ($mod in $Modules) {
        $path = Get-DllPath $mod.dll_rel
        if (-not (Test-Path $path)) {
            Write-Log "DLL not found: $($mod.name) at $path" "ERROR"
            $allOk = $false
            continue
        }
        $size = (Get-Item $path).Length
        if ($size -lt 50KB) {
            Write-Log "DLL too small: $($mod.name) = $size bytes" "ERROR"
            $allOk = $false
            continue
        }
        Write-Log "DLL OK: $($mod.name) ($([math]::Round($size / 1MB, 1)) MB)"
    }
    return $allOk
}

# IDA batch

function Invoke-IdaBatch {
    if (-not (Test-Path $IdaFullPath)) {
        Write-Log "IDA not found at $IdaFullPath" "ERROR"
        return @()
    }

    Get-ChildItem $IdaOutDir -Filter "*_signatures.json" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

    $results = @()

    $env:CS2SIG_OUTPUT_DIR = $IdaOutDir
    $env:CS2SIG_HEADLESS = "1"
    $env:CS2SIG_NO_CPP = "1"
    $env:CS2SIG_NO_REPORT = "1"
    $env:CS2SIG_NO_MANIFEST = "1"

    foreach ($mod in $Modules) {
        $dllPath = Get-DllPath $mod.dll_rel
        if (-not (Test-Path $dllPath)) {
            Write-Log "Skipping $($mod.name): DLL not found" "WARN"
            $results += @{ name = $mod.name; success = $false; error = "dll_not_found"; sigs = 0 }
            continue
        }

        $idbPath = Join-Path $IdbDir "$($mod.name).idb"
        Write-Log "IDA analyzing $($mod.name)..."

        $startTime = Get-Date
        $argStr = "-c -A -S`"$IdaScriptFull`" -o`"$idbPath`" `"$dllPath`""
        Write-Log "CMD: $IdaFullPath $argStr"
        $proc = Start-Process -FilePath $IdaFullPath -ArgumentList $argStr -PassThru -NoNewWindow

        try {
            if ($IdaPriority -ne "Normal") {
                $proc.PriorityClass = $IdaPriority
            }
        }
        catch {}

        $exited = $proc.WaitForExit($IdaTimeoutSec * 1000)
        $elapsed = ((Get-Date) - $startTime).TotalSeconds

        if (-not $exited) {
            Write-Log "$($mod.name): IDA timed out after $IdaTimeoutSec sec, killing" "ERROR"
            $proc.Kill()
            $results += @{ name = $mod.name; success = $false; error = "timeout"; sigs = 0 }
            continue
        }

        Write-Log "$($mod.name): IDA finished in $([int]$elapsed)s (exit code $($proc.ExitCode))"

        $jsonPath = Join-Path $IdaOutDir "$($mod.name)_signatures.json"
        if (-not (Test-Path $jsonPath)) {
            Write-Log "$($mod.name): IDA completed but no JSON output" "ERROR"
            $results += @{ name = $mod.name; success = $false; error = "no_output"; sigs = 0 }
            continue
        }

        if ((Get-Item $jsonPath).LastWriteTime -lt $startTime.AddSeconds(-5)) {
            Write-Log "$($mod.name): JSON output is stale" "ERROR"
            $results += @{ name = $mod.name; success = $false; error = "stale_output"; sigs = 0 }
            continue
        }

        $jsonContent = Get-Content $jsonPath -Raw | ConvertFrom-Json
        if ($jsonContent._metadata.module -and $jsonContent._metadata.module -ne $mod.name) {
            Write-Log "$($mod.name): JSON module mismatch: $($jsonContent._metadata.module)" "ERROR"
            $results += @{ name = $mod.name; success = $false; error = "module_mismatch"; sigs = 0 }
            continue
        }

        $sigCount = ($jsonContent.PSObject.Properties | Where-Object { $_.Name -ne "_metadata" }).Count
        if ($sigCount -lt 10) {
            Write-Log "$($mod.name): only $sigCount signatures (suspicious)" "WARN"
        }

        Write-Log "$($mod.name): $sigCount signatures in $([int]$elapsed)s"
        $results += @{ name = $mod.name; success = $true; error = ""; sigs = $sigCount }

        # Brief pause to release IDA license before next module
        Start-Sleep -Seconds 5
    }

    Remove-Item Env:CS2SIG_OUTPUT_DIR  -ErrorAction SilentlyContinue
    Remove-Item Env:CS2SIG_HEADLESS    -ErrorAction SilentlyContinue
    Remove-Item Env:CS2SIG_NO_CPP      -ErrorAction SilentlyContinue
    Remove-Item Env:CS2SIG_NO_REPORT   -ErrorAction SilentlyContinue
    Remove-Item Env:CS2SIG_NO_MANIFEST -ErrorAction SilentlyContinue

    return $results
}

# Repository update

function Update-Signatures([int]$BuildId, [hashtable[]]$Results) {
    Remove-Item $SignatureStageDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $SignatureStageDir | Out-Null

    $copiedCount = 0
    foreach ($mod in $Modules) {
        $src = Join-Path $IdaOutDir "$($mod.name)_signatures.json"
        $dst = Join-Path $SignatureStageDir "$($mod.name)_signatures.json"
        if (-not (Test-Path $src)) {
            Write-Log "Missing generated signature file for $($mod.name)" "ERROR"
            return $false
        }

        Copy-Item $src $dst -Force
        $copiedCount++
        Write-Log "Staged $($mod.name)_signatures.json"
    }

    if ($copiedCount -ne $Modules.Count) {
        Write-Log "Expected $($Modules.Count) signature files, staged $copiedCount" "ERROR"
        return $false
    }

    $compareScript = Join-Path $RepoPath "scripts\compare-signatures.ps1"
    if (Test-Path $compareScript) {
        $compareReport = Join-Path $WorkDir "signature_compare.json"
        Write-Log "Running compare-signatures.ps1..."
        & pwsh -NoProfile -File $compareScript `
            -Baseline (Join-Path $RepoPath "signatures") `
            -Candidate $SignatureStageDir `
            -OutputReport $compareReport `
            -MaxDropPercent $MaxSignatureDropPercent `
            -MinTotalSignatures 1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "compare-signatures.ps1 failed with exit code $LASTEXITCODE" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "compare-signatures.ps1 not found" "ERROR"
        return $false
    }

    $updateScript = Join-Path $RepoPath "scripts\update-signatures.ps1"
    if (Test-Path $updateScript) {
        Write-Log "Running update-signatures.ps1..."
        & pwsh -NoProfile -File $updateScript -Source $SignatureStageDir -Output "signatures" -Build $BuildId
        if ($LASTEXITCODE -ne 0) {
            Write-Log "update-signatures.ps1 failed with exit code $LASTEXITCODE" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "update-signatures.ps1 not found" "ERROR"
        return $false
    }

    $verifyScript = Join-Path $RepoPath "scripts\verify-signatures.ps1"
    if (Test-Path $verifyScript) {
        Write-Log "Running verify-signatures.ps1..."
        & pwsh -NoProfile -File $verifyScript
        if ($LASTEXITCODE -ne 0) {
            Write-Log "verify-signatures.ps1 failed with exit code $LASTEXITCODE" "ERROR"
            return $false
        }
    }
    else {
        Write-Log "verify-signatures.ps1 not found" "ERROR"
        return $false
    }

    if ($DryRun) {
        Write-Log "[DRY RUN] Skipping git push"
        return $true
    }

    Push-Location $RepoPath
    try {
        $dirtyOutsideSignatures = git status --porcelain --untracked-files=no -- . ":(exclude)signatures"
        if ($dirtyOutsideSignatures) {
            Write-Log "Repository has tracked changes outside signatures/. Refusing to auto-commit." "ERROR"
            $dirtyOutsideSignatures | ForEach-Object { Write-Log "dirty: $_" "ERROR" }
            return $false
        }

        if (-not (Invoke-GitChecked @("pull", "--rebase", "origin", "main"))) {
            Write-Log "git pull --rebase failed" "ERROR"
            return $false
        }

        if (-not (Invoke-GitChecked @("add", "signatures/"))) {
            Write-Log "git add failed" "ERROR"
            return $false
        }

        $status = git status --porcelain signatures/
        if (-not $status) {
            Write-Log "No changes in signatures/ after update"
            return $true
        }

        $msg = "update signatures for build $BuildId"
        if (-not (Invoke-GitChecked @("commit", "-m", $msg))) {
            Write-Log "git commit failed" "ERROR"
            return $false
        }

        for ($attempt = 1; $attempt -le $PushAttempts; $attempt++) {
            if (Invoke-GitChecked @("push", "origin", "main")) {
                Write-Log "Git push successful"
                return $true
            }
            Write-Log "Git push failed (attempt $attempt/$PushAttempts)" "WARN"
            if ($attempt -lt $PushAttempts) {
                Start-Sleep -Seconds 10
                if (-not (Invoke-GitChecked @("pull", "--rebase", "origin", "main"))) {
                    Write-Log "git pull --rebase failed during retry" "ERROR"
                    return $false
                }
            }
        }

        Write-Log "Git push failed after $PushAttempts attempts" "ERROR"
        return $false
    }
    finally {
        Pop-Location
    }
}

function New-GitHubRelease([int]$BuildId, [hashtable[]]$Results) {
    if (-not $CreateGitHubRelease) {
        Write-Log "GitHub release creation disabled"
        return
    }

    if ($DryRun) {
        Write-Log "[DRY RUN] Skipping GitHub release"
        return
    }

    $successModules = ($Results | Where-Object { $_.success }).Count
    $totalSigs = ($Results | Where-Object { $_.success } | ForEach-Object { $_.sigs } | Measure-Object -Sum).Sum

    $tag = "auto-build$BuildId"
    $title = "Auto-update: CS2 build $BuildId"
    $notes = "Automated signature update for CS2 build $BuildId.`n"
    $notes += "Modules: $successModules/$($Results.Count) successful, $totalSigs total signatures.`n"
    $notes += "Generated at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)."

    $oldGhPrompt = $env:GH_PROMPT_DISABLED
    try {
        $env:GH_PROMPT_DISABLED = "1"

        gh release create $tag --title $title --notes $notes --latest 2>&1 | ForEach-Object { Write-Log "gh: $_" }
        if ($LASTEXITCODE -eq 0) {
            Write-Log "GitHub release $tag created"
        }
        else {
            Write-Log "GitHub release creation failed with exit code $LASTEXITCODE" "WARN"
        }
    }
    catch {
        Write-Log "GitHub release creation failed: $_" "WARN"
    }
    finally {
        if ($null -eq $oldGhPrompt) {
            Remove-Item Env:GH_PROMPT_DISABLED -ErrorAction SilentlyContinue
        }
        else {
            $env:GH_PROMPT_DISABLED = $oldGhPrompt
        }
    }
}

# Discord notification

function Send-DiscordNotification([string]$Message, [int]$Color = 3066993) {
    if (-not $DiscordWebhook -or $DryRun) { return }

    $body = @{
        embeds = @(@{
                title       = "cs2sign auto-update"
                description = $Message
                color       = $Color
                timestamp   = (Get-Date).ToUniversalTime().ToString("o")
            })
    } | ConvertTo-Json -Depth 4

    try {
        Invoke-RestMethod -Uri $DiscordWebhook -Method Post -ContentType "application/json" -Body $body -TimeoutSec 10 | Out-Null
    }
    catch {
        Write-Log "Discord notification failed: $_" "WARN"
    }
}

# Cleanup

function Invoke-Cleanup {
    if ($CleanupIdb) {
        Get-ChildItem $IdbDir -Include *.idb, *.i64, *.id0, *.id1, *.id2, *.nam, *.til -Recurse -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "IDB files cleaned"
    }

    # Clean old IDA output (keep latest)
    Get-ChildItem $IdaOutDir -Filter "*_signatures.json" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

    # Rotate logs
    Get-ChildItem $LogDir -Filter "*.log" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
    Remove-Item -Force -ErrorAction SilentlyContinue
}

# Main pipeline

function Invoke-Pipeline {
    Start-Logging

    # Pre-flight checks
    if (-not (Test-Path $IdaFullPath)) {
        Write-Log "IDA not found: $IdaFullPath" "ERROR"
        return 1
    }

    if (-not (Test-Path $IdaScriptFull)) {
        Write-Log "IDA script not found: $IdaScriptFull" "ERROR"
        return 1
    }

    if (-not (Test-Path $RepoPath)) {
        Write-Log "Repository not found: $RepoPath" "ERROR"
        return 1
    }

    # Lock
    if (Test-Lock) {
        Write-Log "Another instance is running, exiting."
        return 0
    }
    Set-Lock

    try {
        $state = Read-State

        # Consecutive failure check
        if ($state.consecutive_failures -ge $MaxFailures) {
            Write-Log "Pipeline disabled after $($state.consecutive_failures) consecutive failures. Reset state.json to re-enable." "ERROR"
            Send-DiscordNotification "Pipeline disabled after $($state.consecutive_failures) consecutive failures. Manual intervention required." 15158332
            return 1
        }

        # Check for update
        $currentBuild = Get-CurrentBuildId
        if ($currentBuild -eq 0) {
            Write-Log "Could not determine current build ID" "WARN"
            return 0
        }

        if (-not $Force -and $currentBuild -le $state.last_buildid) {
            Write-Log "Build $currentBuild is current (last: $($state.last_buildid)), nothing to do."
            return 0
        }

        Write-Log "New build detected: $currentBuild (previous: $($state.last_buildid))"

        # Wait for CDN propagation
        if (-not $Force -and $UpdateWaitSec -gt 0) {
            Write-Log "Waiting $UpdateWaitSec seconds for CDN propagation..."
            Start-Sleep -Seconds $UpdateWaitSec
        }

        if ($DllSource -eq "local_steam") {
            $localBuild = Get-LocalSteamBuildId
            if ($localBuild -eq 0) {
                Write-Log "Could not read local steam.inf build ID" "ERROR"
                $state.consecutive_failures++
                Save-State $state
                Send-DiscordNotification "Build $currentBuild`: local CS2 build could not be verified." 15158332
                return 1
            }

            if (-not $Force -and $localBuild -lt $currentBuild) {
                Write-Log "Local CS2 build $localBuild is older than Steam API build $currentBuild" "ERROR"
                $state.consecutive_failures++
                Save-State $state
                Send-DiscordNotification "Build $currentBuild`: local CS2 is still at build $localBuild." 16776960
                return 1
            }

            Write-Log "Local CS2 build verified: $localBuild"
        }

        # Download DLLs if using SteamCMD
        if ($DllSource -eq "steamcmd") {
            if (-not (Invoke-SteamCmdDownload)) {
                $state.consecutive_failures++
                Save-State $state
                Send-DiscordNotification "Build $currentBuild`: SteamCMD download failed after $DownloadAttempts attempts." 15158332
                return 1
            }
        }

        # Verify DLLs exist
        if (-not (Test-DllsAvailable)) {
            Write-Log "Not all DLLs available. If using local_steam, make sure CS2 has finished updating." "ERROR"
            $state.consecutive_failures++
            Save-State $state
            Send-DiscordNotification "Build $currentBuild`: DLLs not available. CS2 may not have finished updating." 16776960
            return 1
        }

        # IDA analysis
        $results = @(Invoke-IdaBatch)
        $successList = @($results | Where-Object { $_.success })
        $failList = @($results | Where-Object { -not $_.success })
        $successCount = $successList.Count
        $failCount = $failList.Count
        $totalSigs = 0
        foreach ($r in $successList) { $totalSigs += $r.sigs }

        Write-Log "IDA results: $successCount OK, $failCount failed, $totalSigs total signatures"

        if ($successCount -eq 0) {
            Write-Log "All modules failed" "ERROR"
            $state.consecutive_failures++
            Save-State $state
            $failDetails = ($results | ForEach-Object { "$($_.name): $($_.error)" }) -join ", "
            Send-DiscordNotification "Build $currentBuild`: all modules failed.`n$failDetails" 15158332
            return 1
        }

        if ($RequireAllModules -and $failCount -gt 0) {
            Write-Log "Partial signature update refused because require_all_modules is enabled" "ERROR"
            $state.consecutive_failures++
            Save-State $state
            $failDetails = ($failList | ForEach-Object { "$($_.name): $($_.error)" }) -join ", "
            Send-DiscordNotification "Build $currentBuild`: partial signature update refused.`n$failDetails" 15158332
            return 1
        }

        # Update repo
        $pushOk = Update-Signatures $currentBuild $results
        if (-not $pushOk) {
            $state.consecutive_failures++
            Save-State $state
            Send-DiscordNotification "Build $currentBuild`: signature update failed (git)." 15158332
            return 1
        }

        # Release
        New-GitHubRelease $currentBuild $results

        # Success state
        $sigDetails = @{}
        foreach ($r in $results) { if ($r.success) { $sigDetails[$r.name] = $r.sigs } }

        $historyEntry = [PSCustomObject]@{
            buildid        = $currentBuild
            updated_utc    = (Get-Date).ToUniversalTime().ToString("o")
            status         = if ($failCount -eq 0) { "success" } else { "partial" }
            modules_ok     = $successCount
            modules_failed = $failCount
            signatures     = $sigDetails
        }

        $history = @($state.history)
        $history += $historyEntry
        if ($history.Count -gt 50) { $history = $history[-50..-1] }

        $state.last_buildid = $currentBuild
        $state.last_update_utc = (Get-Date).ToUniversalTime().ToString("o")
        $state.last_status = $historyEntry.status
        $state.consecutive_failures = 0
        $state.history = $history
        Save-State $state

        # Notify
        $color = if ($failCount -eq 0) { 3066993 } else { 16776960 }
        $statusText = if ($failCount -eq 0) { "updated" } else { "updated with warnings" }
        $msgLines = @(
            "**Build $currentBuild** $statusText"
            "Modules: $successCount/$($results.Count) OK"
            "Signatures: $totalSigs total"
        )
        if ($failCount -gt 0) {
            $failedNames = ($results | Where-Object { -not $_.success } | ForEach-Object { $_.name }) -join ", "
            $msgLines += "Failed: $failedNames"
        }
        Send-DiscordNotification ($msgLines -join "`n") $color

        # Cleanup
        Invoke-Cleanup

        Write-Log "Pipeline completed successfully"
        return 0
    }
    catch {
        Write-Log "Unhandled error: $_" "ERROR"
        Write-Log $_.ScriptStackTrace "ERROR"

        try {
            $st = Read-State
            $st.consecutive_failures++
            Save-State $st
            Send-DiscordNotification "Build update failed with unhandled error:`n``$_``" 15158332
        }
        catch {}

        return 1
    }
    finally {
        Clear-Lock
        Stop-Logging
    }
}

# Entry point

$exitCode = Invoke-Pipeline
exit $exitCode
