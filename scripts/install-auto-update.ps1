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

$action = New-ScheduledTaskAction `
    -Execute "pwsh.exe" `
    -Argument "-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`"" `
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
Write-Host ""
Write-Host "To test manually:"
Write-Host "  pwsh -File `"$ScriptPath`" -Force -DryRun"
Write-Host ""
Write-Host "To remove:"
Write-Host "  pwsh -File `"$($MyInvocation.MyCommand.Definition)`" -Unregister"
