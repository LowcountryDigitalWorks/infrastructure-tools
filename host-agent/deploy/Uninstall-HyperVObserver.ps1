[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'HyperVObserverDeployment.psm1') -Force
Assert-HyperVObserverElevated
$constants = Get-HyperVObserverDeploymentConstants
$state = Read-HyperVObserverDeploymentState
$task = Get-HyperVObserverScheduledTask

$installExists = Test-Path -LiteralPath $constants.InstallRoot
$configExists = Test-Path -LiteralPath $constants.ConfigRoot
if ($null -eq $state -and $null -eq $task -and -not $installExists -and -not $configExists) {
    [pscustomobject]@{
        Uninstalled = $true
        AlreadyAbsent = $true
        TaskRemoved = $true
        HelperInstallRootRemoved = $true
        HelperConfigRootRemoved = $true
        NormalizedSshTrustTouched = $false
    }
    return
}

if ($null -eq $state) {
    throw 'Deployment state is missing while managed artifacts remain. Fail closed rather than guessing ownership during rollback.'
}

$context = Get-HyperVObserverValidatedContext
if ([string]$context.Task.State -eq 'Running') {
    Stop-ScheduledTask -TaskPath $constants.TaskPath -TaskName $constants.TaskName -ErrorAction Stop
}

# Exact task identity has been proven above. No task mutation occurs before that proof.
Unregister-ScheduledTask -TaskPath $constants.TaskPath -TaskName $constants.TaskName -Confirm:$false
if ($null -ne (Get-HyperVObserverScheduledTask)) {
    throw 'Managed Scheduled Task still exists after unregister; protected files were not removed.'
}

if (Test-Path -LiteralPath $constants.ConfigRoot -PathType Container) {
    Remove-Item -LiteralPath $constants.ConfigRoot -Recurse -Force
}
if (Test-Path -LiteralPath $constants.InstallRoot -PathType Container) {
    Remove-Item -LiteralPath $constants.InstallRoot -Recurse -Force
}

[pscustomobject]@{
    Uninstalled = $true
    AlreadyAbsent = $false
    TaskIdentityValidatedBeforeMutation = $true
    TaskRemoved = ($null -eq (Get-HyperVObserverScheduledTask))
    HelperInstallRootRemoved = -not (Test-Path -LiteralPath $constants.InstallRoot)
    HelperConfigRootRemoved = -not (Test-Path -LiteralPath $constants.ConfigRoot)
    NormalizedSshTrustTouched = $false
}
