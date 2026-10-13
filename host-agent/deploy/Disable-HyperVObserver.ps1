[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'HyperVObserverDeployment.psm1') -Force
Assert-HyperVObserverElevated
$context = Get-HyperVObserverValidatedContext
$constants = $context.Constants

if ([string]$context.Task.State -eq 'Disabled') {
    [pscustomobject]@{
        Disabled = $true
        AlreadyDisabled = $true
        TaskIdentityValidatedBeforeMutation = $true
        TaskName = $constants.TaskName
        TaskPath = $constants.TaskPath
    }
    return
}

if ([string]$context.Task.State -eq 'Running') {
    Stop-ScheduledTask -TaskPath $constants.TaskPath -TaskName $constants.TaskName
}
Disable-ScheduledTask -TaskPath $constants.TaskPath -TaskName $constants.TaskName | Out-Null

$task = Get-HyperVObserverScheduledTask
Assert-HyperVObserverTaskIdentity -Task $task -Spec $context.Spec
if ([string]$task.State -ne 'Disabled') {
    throw 'Managed Scheduled Task did not enter Disabled state.'
}

[pscustomobject]@{
    Disabled = $true
    AlreadyDisabled = $false
    TaskIdentityValidatedBeforeMutation = $true
    TaskIdentityValidatedAfterMutation = $true
    TaskName = $constants.TaskName
    TaskPath = $constants.TaskPath
}
