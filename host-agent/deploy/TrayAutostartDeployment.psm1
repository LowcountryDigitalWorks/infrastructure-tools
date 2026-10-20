#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TaskName = 'Tray'
$script:TaskPath = '\LowcountryDigitalWorks\HostAgent\'
$script:TaskDescription = 'LDW Host Agent normal-user tray at logon.'
$script:ExecutableRelativePath = 'LowcountryDigitalWorks\HostAgent\Windows\LDW.HostAgent.Windows.exe'

function Get-TrayAutostartSpec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OwnerSid,
        [string]$ExecutablePath = (Join-Path $env:ProgramFiles $script:ExecutableRelativePath)
    )

    try { $sid = [Security.Principal.SecurityIdentifier]::new($OwnerSid) }
    catch { throw 'OwnerSid must be a valid machine-local user SID.' }
    if (-not ($OwnerSid -match '^S-1-(5-21|12-1)-')) {
        throw 'OwnerSid must identify a user account; well-known service/group SIDs are not accepted.'
    }
    if ([string]::IsNullOrWhiteSpace($env:ProgramFiles)) { throw 'ProgramFiles is unavailable.' }
    $expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles $script:ExecutableRelativePath))
    $resolved = [IO.Path]::GetFullPath($ExecutablePath)
    if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Tray executable must use the exact protected Program Files installation path.'
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw 'Tray executable is missing from the protected installation path.' }

    [pscustomobject]@{
        TaskName = $script:TaskName
        TaskPath = $script:TaskPath
        TaskDescription = $script:TaskDescription
        OwnerSid = $sid.Value
        ExecutablePath = $resolved
        Arguments = ''
        TriggerClass = 'MSFT_TaskLogonTrigger'
        LogonType = 'Interactive'
        RunLevel = 'Limited'
        MultipleInstances = 'IgnoreNew'
        StartWhenAvailable = $true
        ExecutionTimeLimit = 'PT0S'
        DisallowStartIfOnBatteries = $false
        StopIfGoingOnBatteries = $false
    }
}

function Test-TrayAutostartUserIdMatchesSid {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$UserId,
        [Parameter(Mandatory)][string]$OwnerSid
    )

    if ([string]::IsNullOrWhiteSpace($UserId)) { return $false }
    if ([string]::Equals($UserId, $OwnerSid, [StringComparison]::OrdinalIgnoreCase)) { return $true }

    try {
        $account = [Security.Principal.NTAccount]::new($UserId)
        $resolvedSid = $account.Translate([Security.Principal.SecurityIdentifier])
        return [string]::Equals($resolvedSid.Value, $OwnerSid, [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Get-TrayAutostartIdentityProblems {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Task, [Parameter(Mandatory)]$Spec)

    $problems = [Collections.Generic.List[string]]::new()
    if ($null -eq $Task -or $Task.TaskName -cne $Spec.TaskName -or $Task.TaskPath -cne $Spec.TaskPath) { $problems.Add('task-name-or-path') }
    if (@($Task.Actions).Count -ne 1) { $problems.Add('action-count') }
    else {
        if (-not [string]::Equals([string]$Task.Actions[0].Execute, $Spec.ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('action-executable') }
        if (-not [string]::IsNullOrEmpty([string]$Task.Actions[0].Arguments)) { $problems.Add('action-arguments') }
    }
    if (@($Task.Triggers).Count -ne 1) { $problems.Add('trigger-count') }
    else {
        $trigger = $Task.Triggers[0]
        if ([string]$trigger.CimClass.CimClassName -cne $Spec.TriggerClass) { $problems.Add('trigger-type') }
        if (-not (Test-TrayAutostartUserIdMatchesSid -UserId ([string]$trigger.UserId) -OwnerSid $Spec.OwnerSid)) { $problems.Add('trigger-user') }
    }
    if (-not (Test-TrayAutostartUserIdMatchesSid -UserId ([string]$Task.Principal.UserId) -OwnerSid $Spec.OwnerSid)) { $problems.Add('principal-user') }
    if ([string]$Task.Principal.LogonType -cne $Spec.LogonType) { $problems.Add('principal-logon-type') }
    if ([string]$Task.Principal.RunLevel -cne $Spec.RunLevel) { $problems.Add('principal-run-level') }
    if ([string]$Task.Settings.MultipleInstances -cne $Spec.MultipleInstances) { $problems.Add('multiple-instances') }
    if (-not [bool]$Task.Settings.StartWhenAvailable) { $problems.Add('start-when-available') }
    if ([string]$Task.Settings.ExecutionTimeLimit -cne $Spec.ExecutionTimeLimit) { $problems.Add('execution-time-limit') }
    if ([bool]$Task.Settings.DisallowStartIfOnBatteries -ne $Spec.DisallowStartIfOnBatteries) { $problems.Add('battery-start') }
    if ([bool]$Task.Settings.StopIfGoingOnBatteries -ne $Spec.StopIfGoingOnBatteries) { $problems.Add('battery-stop') }
    return $problems.ToArray()
}

function Get-TrayAutostartTask {
    try {
        return Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:TaskName -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -eq 'CmdletizationQuery_NotFound,Get-ScheduledTask') { return $null }
        throw
    }
}

function Assert-TrayAutostartTask {
    param([Parameter(Mandatory)]$Spec)
    $task = Get-TrayAutostartTask
    if ($null -eq $task) { throw 'Managed Host Agent tray logon task is not installed.' }
    $problems = @(Get-TrayAutostartIdentityProblems -Task $task -Spec $Spec)
    if ($problems.Count -gt 0) { throw "Managed task identity drifted ($($problems -join ', ')); no mutation was performed." }
    return $task
}

function New-TrayAutostartTaskDefinition {
    param([Parameter(Mandatory)]$Spec)
    $actionParameters = @{
        Execute = $Spec.ExecutablePath
        WorkingDirectory = (Split-Path -Parent $Spec.ExecutablePath)
    }
    if (-not [string]::IsNullOrEmpty([string]$Spec.Arguments)) {
        $actionParameters.Argument = [string]$Spec.Arguments
    }
    $action = New-ScheduledTaskAction @actionParameters
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $Spec.OwnerSid
    $principal = New-ScheduledTaskPrincipal -UserId $Spec.OwnerSid -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $Spec.TaskDescription
}

function Assert-TrayAutostartAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Registration management requires an elevated installer session; the scheduled tray itself remains normal-user and unelevated.' }
}

function Assert-TrayAutostartCurrentOwner {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OwnerSid)
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if (-not [string]::Equals($currentSid, $OwnerSid, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The target SID must be the same owner account running this lifecycle operation; cross-user task changes are not supported.'
    }
}

function Test-TrayAutostartEnabled {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Task)
    switch -CaseSensitive ([string]$Task.State) {
        'Disabled' { return $false }
        'Ready' { return $true }
        'Running' { return $true }
        'Queued' { return $true }
        default { throw 'Managed task enabled state is unknown; lifecycle must fail closed.' }
    }
}

function Get-TrayAutostartInstallDisposition {
    [CmdletBinding()]
    param($Task, [Parameter(Mandatory)]$Spec)
    if ($null -eq $Task) { return 'Register' }
    $problems = @(Get-TrayAutostartIdentityProblems -Task $Task -Spec $Spec)
    if ($problems.Count -gt 0) { throw "Existing task identity drifted ($($problems -join ', ')); install must not overwrite it." }
    if (-not (Test-TrayAutostartEnabled -Task $Task)) { return 'Enable' }
    return 'NoOp'
}

Export-ModuleMember -Function Get-TrayAutostartSpec, Test-TrayAutostartUserIdMatchesSid, Get-TrayAutostartIdentityProblems, Get-TrayAutostartTask, Assert-TrayAutostartTask, New-TrayAutostartTaskDefinition, Assert-TrayAutostartAdministrator, Assert-TrayAutostartCurrentOwner, Test-TrayAutostartEnabled, Get-TrayAutostartInstallDisposition
