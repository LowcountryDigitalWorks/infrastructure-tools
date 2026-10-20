#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Plan','Install','Status','Disable','Enable','Uninstall')][string]$Action)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TrayAutostartDeployment.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'TrayRunKeyDeployment.psm1') -Force

$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$spec = Get-TrayAutostartSpec -OwnerSid $currentSid

# The accepted task path always wins if it already exists. Never create a second registration.
$acceptedTask = Get-TrayAutostartTask
if ($null -ne $acceptedTask) {
    throw 'The accepted Host Agent tray Scheduled Task exists. Use Manage-TrayAutostart.ps1 to inspect or operate that exact registration.'
}

$entry = Get-TrayAutostartRunEntry
$expected = Get-TrayAutostartRunCommand -ExecutablePath $spec.ExecutablePath
if ($entry.Present -and -not (Test-TrayAutostartRunEntryMatches -Value $entry.Value -ExpectedValue $expected)) {
    throw 'Existing per-user Host Agent startup value drifted; no mutation was performed.'
}

if ($Action -eq 'Plan') {
    [pscustomobject]@{
        Action = $Action
        Mechanism = 'HKCU Run'
        MutationPerformed = $false
        ExistingAcceptedTask = $false
        RegistrationPresent = $entry.Present
        DriftDetected = $false
        ValueName = $entry.Name
        ExecutablePath = $spec.ExecutablePath
        Arguments = ''
        IncrementalRuntimeCostUsd = 0
    }
    return
}

if ($Action -eq 'Status') {
    [pscustomobject]@{
        Action = $Action
        Mechanism = 'HKCU Run'
        Installed = $entry.Present
        Enabled = $entry.Present
        DriftDetected = $false
        State = if ($entry.Present) { 'Registered' } else { 'Absent' }
        MutationPerformed = $false
        IncrementalRuntimeCostUsd = 0
    }
    return
}

switch ($Action) {
    { $_ -in 'Install','Enable' } {
        $result = Set-TrayAutostartRunEntry -ExecutablePath $spec.ExecutablePath
        [pscustomobject]@{
            Action = $Action
            Mechanism = 'HKCU Run'
            Installed = $true
            Enabled = $true
            MutationPerformed = $result.Changed
            ValueName = $result.Name
            IncrementalRuntimeCostUsd = 0
        }
    }
    { $_ -in 'Disable','Uninstall' } {
        $result = Remove-TrayAutostartRunEntry -ExecutablePath $spec.ExecutablePath
        [pscustomobject]@{
            Action = $Action
            Mechanism = 'HKCU Run'
            Installed = ($Action -eq 'Disable' -and $result.Present)
            Enabled = $false
            MutationPerformed = $result.Changed
            ValueName = $result.Name
            IncrementalRuntimeCostUsd = 0
        }
    }
}
