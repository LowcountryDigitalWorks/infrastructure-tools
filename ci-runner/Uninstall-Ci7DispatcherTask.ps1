[CmdletBinding()]
param(
    [string]$TaskName = 'LDW-Ci7Dispatcher'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force

Assert-Ci7Elevated

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    if ($task.State -ne 'Disabled') {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    'SCHEDULED_TASK_UNINSTALLED=PASS'
} else {
    'SCHEDULED_TASK_NOT_FOUND=IDEMPOTENT_PASS'
}
