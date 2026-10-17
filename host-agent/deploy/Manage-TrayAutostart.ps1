#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Plan','Install','Status','Disable','Enable','Uninstall')][string]$Action,
    [Parameter(Mandatory)][string]$OwnerSid
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TrayAutostartDeployment.psm1') -Force

$spec = Get-TrayAutostartSpec -OwnerSid $OwnerSid
$task = Get-TrayAutostartTask

if ($Action -eq 'Plan') {
    $drift = @()
    if ($null -ne $task) { $drift = @(Get-TrayAutostartIdentityProblems -Task $task -Spec $spec) }
    [pscustomobject]@{
        Action = 'Plan'
        MutationPerformed = $false
        ExistingTask = ($null -ne $task)
        DriftDetected = ($drift.Count -gt 0)
        Drift = $drift
        TaskName = $spec.TaskName
        TaskPath = $spec.TaskPath
        Trigger = 'AtLogOn'
        OwnerSid = $spec.OwnerSid
        LogonType = $spec.LogonType
        RunLevel = $spec.RunLevel
        ExecutablePath = $spec.ExecutablePath
        MultipleInstances = $spec.MultipleInstances
        IncrementalRuntimeCostUsd = 0
    }
    return
}

if ($Action -eq 'Status') {
    if ($null -eq $task) {
        [pscustomobject]@{ Installed = $false; Enabled = $false; DriftDetected = $false; State = 'Absent'; MutationPerformed = $false; IncrementalRuntimeCostUsd = 0 }
        return
    }
    $drift = @(Get-TrayAutostartIdentityProblems -Task $task -Spec $spec)
    $info = if ($drift.Count -eq 0) { Get-ScheduledTaskInfo -TaskPath $spec.TaskPath -TaskName $spec.TaskName -ErrorAction Stop } else { $null }
    [pscustomobject]@{
        Installed = $true
        Enabled = (Test-TrayAutostartEnabled -Task $task)
        DriftDetected = ($drift.Count -gt 0)
        Drift = $drift
        State = [string]$task.State
        LastRunTime = if ($null -ne $info) { $info.LastRunTime } else { $null }
        LastTaskResult = if ($null -ne $info) { $info.LastTaskResult } else { $null }
        MutationPerformed = $false
        IncrementalRuntimeCostUsd = 0
    }
    return
}

Assert-TrayAutostartCurrentOwner -OwnerSid $spec.OwnerSid
Assert-TrayAutostartAdministrator

if ($Action -eq 'Install') {
    $installDisposition = Get-TrayAutostartInstallDisposition -Task $task -Spec $spec
    if ($installDisposition -ne 'Register') {
        $null = Assert-TrayAutostartTask -Spec $spec
        if ($installDisposition -eq 'Enable') { Enable-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName | Out-Null }
        $verified = Assert-TrayAutostartTask -Spec $spec
        if (-not (Test-TrayAutostartEnabled -Task $verified)) { throw 'Idempotent install could not verify the existing task is enabled.' }
        [pscustomobject]@{ Installed = $true; AlreadyInstalled = $true; Enabled = $true; MutationPerformed = ($installDisposition -eq 'Enable'); TaskName = $spec.TaskName; TaskPath = $spec.TaskPath; RunLevel = $spec.RunLevel; IncrementalRuntimeCostUsd = 0 }
        return
    }

    $registered = $false
    try {
        $definition = New-TrayAutostartTaskDefinition -Spec $spec
        Register-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName -InputObject $definition -ErrorAction Stop | Out-Null
        $registered = $true
        $verified = Assert-TrayAutostartTask -Spec $spec
        if (-not (Test-TrayAutostartEnabled -Task $verified)) { throw 'Registered tray task did not read back as enabled.' }
        [pscustomobject]@{ Installed = $true; AlreadyInstalled = $false; Enabled = $true; MutationPerformed = $true; TaskName = $spec.TaskName; TaskPath = $spec.TaskPath; RunLevel = $spec.RunLevel; IncrementalRuntimeCostUsd = 0 }
        return
    } catch {
        $installError = $_
        if ($registered) {
            $rollbackTask = Get-TrayAutostartTask
            if ($null -eq $rollbackTask -or @(Get-TrayAutostartIdentityProblems -Task $rollbackTask -Spec $spec).Count -ne 0) {
                throw "Install failed and exact task ownership could not be proven; task was left untouched for manual reconciliation. Original error: $($installError.Exception.Message)"
            }
            Unregister-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName -Confirm:$false -ErrorAction Stop
        }
        throw $installError
    }
}

$task = Assert-TrayAutostartTask -Spec $spec
switch ($Action) {
    'Disable' {
        if ([string]$task.State -eq 'Running') { Stop-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName -ErrorAction Stop }
        if (Test-TrayAutostartEnabled -Task $task) { Disable-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName | Out-Null }
        $verified = Assert-TrayAutostartTask -Spec $spec
        if (Test-TrayAutostartEnabled -Task $verified) { throw 'Disable readback failed; managed task remains enabled.' }
    }
    'Enable' {
        if (-not (Test-TrayAutostartEnabled -Task $task)) { Enable-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName | Out-Null }
        $verified = Assert-TrayAutostartTask -Spec $spec
        if (-not (Test-TrayAutostartEnabled -Task $verified)) { throw 'Enable readback failed; managed task remains disabled.' }
    }
    'Uninstall' {
        if ([string]$task.State -eq 'Running') { Stop-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName -ErrorAction Stop }
        Unregister-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName -Confirm:$false -ErrorAction Stop
        if ($null -ne (Get-TrayAutostartTask)) { throw 'Uninstall readback failed; managed task still exists.' }
    }
}

[pscustomobject]@{
    Action = $Action
    MutationPerformed = $true
    TaskRemoved = ($Action -eq 'Uninstall')
    Enabled = if ($Action -eq 'Disable') { $false } elseif ($Action -eq 'Uninstall') { $false } else { $true }
    TaskName = $spec.TaskName
    TaskPath = $spec.TaskPath
    IncrementalRuntimeCostUsd = 0
}
