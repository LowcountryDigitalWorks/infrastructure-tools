[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'HyperVObserverDeployment.psm1') -Force
Assert-HyperVObserverElevated
$context = Get-HyperVObserverValidatedContext
$constants = $context.Constants

$wasDisabled = [string]$context.Task.State -eq 'Disabled'
if ($wasDisabled) {
    Enable-ScheduledTask -TaskPath $constants.TaskPath -TaskName $constants.TaskName | Out-Null
}

$task = Get-HyperVObserverScheduledTask
Assert-HyperVObserverTaskIdentity -Task $task -Spec $context.Spec
if ([string]$task.State -ne 'Running') {
    Start-ScheduledTask -TaskPath $constants.TaskPath -TaskName $constants.TaskName
}

$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    Start-Sleep -Milliseconds 500
    $task = Get-HyperVObserverScheduledTask
    Assert-HyperVObserverTaskIdentity -Task $task -Spec $context.Spec
    if ([string]$task.State -eq 'Running') { break }
} while ([DateTime]::UtcNow -lt $deadline)

if ([string]$task.State -ne 'Running') {
    throw 'Managed Scheduled Task did not remain Running after enable/start. Inspect Task Scheduler/App Control logs; do not weaken security policy.'
}

[pscustomobject]@{
    Enabled = $true
    WasDisabled = $wasDisabled
    TaskRunning = $true
    TaskIdentityValidatedBeforeMutation = $true
    TaskIdentityValidatedAfterMutation = $true
    TaskName = $constants.TaskName
    TaskPath = $constants.TaskPath
}
