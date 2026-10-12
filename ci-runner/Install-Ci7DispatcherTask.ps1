[CmdletBinding()]
param(
    [string]$TaskName = 'LDW-Ci7Dispatcher',
    [string[]]$ApprovedRepositories = @('LowcountryDigitalWorks/business-operations'),
    [string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'),
    [switch]$AllowPublicSyntheticProof,
    [int]$PollIntervalSeconds = 30
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force

Assert-Ci7Elevated

$scriptPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Invoke-Ci7Dispatcher.ps1'))
if (-not (Test-Path -LiteralPath $scriptPath)) { throw 'DISPATCHER_SCRIPT_NOT_FOUND' }

$pwsh = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
if (-not $pwsh) { $pwsh = (Get-Command powershell.exe -ErrorAction Stop).Source }

$argList = [Collections.Generic.List[string]]::new()
$argList.Add('-NonInteractive')
$argList.Add('-NoProfile')
$argList.Add('-ExecutionPolicy')
$argList.Add('Bypass')
$argList.Add('-File')
$argList.Add('"' + $scriptPath + '"')
$argList.Add('-Mode')
$argList.Add('Loop')
$argList.Add('-PollIntervalSeconds')
$argList.Add($PollIntervalSeconds.ToString())
$argList.Add('-Root')
$argList.Add('"' + $Root + '"')

if ($AllowPublicSyntheticProof) {
    $argList.Add('-AllowPublicSyntheticProof')
}
if ($ApprovedRepositories.Count -gt 0) {
    $argList.Add('-ApprovedRepositories')
    $argList.Add(($ApprovedRepositories -join ','))
}

$action = New-ScheduledTaskAction -Execute $pwsh -Argument ($argList -join ' ')
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

'SCHEDULED_TASK_INSTALLED=PASS'
'TASK_NAME=' + $TaskName
