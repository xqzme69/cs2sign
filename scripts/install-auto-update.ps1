<#
.SYNOPSIS
    Register or unregister the cs2sign auto-update scheduled task.

.PARAMETER Unregister
    Remove the scheduled task instead of creating it.

.PARAMETER IntervalMinutes
    How often to check for updates. Default: 10.
#>

[CmdletBinding()]
param(
    [switch]$Unregister,
    [int]$IntervalMinutes = 10
)

$TaskName = "cs2sign-auto-update"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ScriptPath = Join-Path $ScriptDir "auto-update.ps1"

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Task '$TaskName' removed."
    exit 0
}

if (-not (Test-Path $ScriptPath)) {
    Write-Error "auto-update.ps1 not found at $ScriptPath"
    exit 1
}

$configPath = Join-Path $ScriptDir "auto-update-config.json"
if (-not (Test-Path $configPath)) {
    Write-Error "auto-update-config.json not found. Copy the example and fill in your paths first."
    exit 1
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json
$workDir = if ($config.work_dir) { $config.work_dir } else { Join-Path $env:LOCALAPPDATA "cs2sign-auto" }
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null
}

$pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $pwshPath) {
    $pwshPath = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
}
if (-not $pwshPath) {
    Write-Error "PowerShell executable not found."
    exit 1
}

$wrapperPath = Join-Path $workDir "run-auto-update-hidden.vbs"
$escapedScriptDir = $ScriptDir.Replace('"', '""')
$escapedScriptPath = $ScriptPath.Replace('"', '""')
$escapedPwshPath = $pwshPath.Replace('"', '""')
$wrapper = @"
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = "$escapedScriptDir"
command = """$escapedPwshPath"" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""$escapedScriptPath"""
WScript.Quit shell.Run(command, 0, True)
"@
Set-Content -Path $wrapperPath -Value $wrapper -Encoding ASCII

$action = New-ScheduledTaskAction `
    -Execute "wscript.exe" `
    -Argument "`"$wrapperPath`"" `
    -WorkingDirectory $ScriptDir

$triggerInterval = New-ScheduledTaskTrigger `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration ([TimeSpan]::FromDays(3650)) `
    -Once -At (Get-Date)

$triggerBoot = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -Hidden `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 0 `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -RunLevel Highest `
    -LogonType Interactive

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger @($triggerInterval, $triggerBoot) `
    -Settings $settings `
    -Principal $principal `
    -Force

Write-Host ""
Write-Host "Scheduled task '$TaskName' registered."
Write-Host "  Interval: every $IntervalMinutes minutes"
Write-Host "  Script:   $ScriptPath"
Write-Host "  Config:   $configPath"
Write-Host "  Wrapper:  $wrapperPath"
Write-Host ""
Write-Host "To test manually:"
Write-Host "  pwsh -File `"$ScriptPath`" -Force -DryRun"
Write-Host ""
Write-Host "To remove:"
Write-Host "  pwsh -File `"$($MyInvocation.MyCommand.Definition)`" -Unregister"
