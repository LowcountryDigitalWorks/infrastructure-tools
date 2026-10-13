[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'HyperVObserverDeployment.psm1') -Force
Assert-HyperVObserverElevated
$constants = Get-HyperVObserverDeploymentConstants
$state = Read-HyperVObserverDeploymentState
$task = Get-HyperVObserverScheduledTask

if ($null -eq $state -and $null -eq $task -and
    -not (Test-Path -LiteralPath $constants.InstallRoot) -and
    -not (Test-Path -LiteralPath $constants.ConfigRoot)) {
    [pscustomobject]@{
        Installed = $false
        DriftDetected = $false
        TaskName = $constants.TaskName
        TaskPath = $constants.TaskPath
        IncrementalRuntimeCostUsd = 0
    }
    return
}

$context = Get-HyperVObserverValidatedContext
$taskInfo = Get-ScheduledTaskInfo -TaskPath $constants.TaskPath -TaskName $constants.TaskName -ErrorAction Stop

[pscustomobject]@{
    Installed = $true
    DriftDetected = $false
    ReleaseId = [string]$context.State.releaseId
    TaskName = $constants.TaskName
    TaskPath = $constants.TaskPath
    TaskState = [string]$context.Task.State
    TaskEnabled = ([string]$context.Task.State -ne 'Disabled')
    LastTaskResult = [int]$taskInfo.LastTaskResult
    TaskIdentityValidated = $true
    ReleaseManifestValidated = $true
    ProtectedStateValidated = $true
    ConfigValidatedWithoutDisclosure = $true
    IncrementalRuntimeCostUsd = 0
}
