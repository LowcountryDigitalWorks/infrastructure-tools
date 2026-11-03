#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deploymentModule = Join-Path $PSScriptRoot 'HostAgentWindowsDeployment.psm1'
Import-Module $deploymentModule -Force

$script:ProcessName = 'LDW.HostAgent.Windows'
$script:PollAttempts = 50
$script:PollMilliseconds = 200

function Get-HostAgentWindowsTrayLaunchConstants {
    $deployment = Get-HostAgentWindowsDeploymentConstants
    [pscustomobject]@{
        ProcessName = $script:ProcessName
        ExecutablePath = $deployment.ExecutablePath
        ExplorerPath = Join-Path $env:WINDIR 'explorer.exe'
        PollAttempts = $script:PollAttempts
        PollMilliseconds = $script:PollMilliseconds
    }
}

function Initialize-HostAgentWindowsTokenProbe {
    if ('LDWHostAgentWindowsTokenProbe' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class LDWHostAgentWindowsTokenProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_ELEVATION { public int TokenIsElevated; }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, out TOKEN_ELEVATION tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static bool IsElevated(int processId)
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        const uint TOKEN_QUERY = 0x0008;
        const int TokenElevation = 20;

        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed.");
        try
        {
            if (!OpenProcessToken(process, TOKEN_QUERY, out IntPtr token))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed.");
            try
            {
                TOKEN_ELEVATION elevation;
                if (!GetTokenInformation(token, TokenElevation, out elevation, Marshal.SizeOf<TOKEN_ELEVATION>(), out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation failed.");
                return elevation.TokenIsElevated != 0;
            }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(process); }
    }
}
'@
}

function Test-HostAgentWindowsProcessElevated {
    param([Parameter(Mandatory)][int]$ProcessId)
    Initialize-HostAgentWindowsTokenProbe
    return [LDWHostAgentWindowsTokenProbe]::IsElevated($ProcessId)
}

function Get-HostAgentWindowsTrayProcesses {
    $items = @(Get-Process -Name $script:ProcessName -ErrorAction SilentlyContinue)
    foreach ($item in $items) {
        $path = $null
        try { $path = [IO.Path]::GetFullPath([string]$item.Path) } catch { }
        [pscustomobject]@{
            Id = [int]$item.Id
            SessionId = [int]$item.SessionId
            Path = $path
        }
    }
}

function Get-HostAgentWindowsExplorerCandidates {
    param([Parameter(Mandatory)][int]$SessionId)
    $constants = Get-HostAgentWindowsTrayLaunchConstants
    $expected = [IO.Path]::GetFullPath($constants.ExplorerPath)
    foreach ($item in @(Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) {
        if ([int]$item.SessionId -ne $SessionId) { continue }
        $path = $null
        try { $path = [IO.Path]::GetFullPath([string]$item.Path) } catch { continue }
        if (-not [string]::Equals($path, $expected, [StringComparison]::OrdinalIgnoreCase)) { continue }
        try {
            if (Test-HostAgentWindowsProcessElevated -ProcessId ([int]$item.Id)) { continue }
        } catch {
            continue
        }
        [pscustomobject]@{ Id=[int]$item.Id; SessionId=[int]$item.SessionId; Path=$path; Elevated=$false }
    }
}

function Assert-HostAgentWindowsTrayLaunchState {
    param(
        [Parameter(Mandatory)][string]$InstalledState,
        [Parameter(Mandatory)][int]$RunningCount,
        [Parameter(Mandatory)][int]$SessionId,
        [Parameter(Mandatory)][int]$ExplorerCandidateCount
    )
    if ($InstalledState -cne 'Managed') { throw 'HOST_AGENT_WINDOWS_TRAY_MANAGED_INSTALL_REQUIRED' }
    if ($RunningCount -ne 0) { throw 'HOST_AGENT_WINDOWS_TRAY_ALREADY_RUNNING' }
    if ($SessionId -le 0) { throw 'HOST_AGENT_WINDOWS_TRAY_INTERACTIVE_SESSION_REQUIRED' }
    if ($ExplorerCandidateCount -le 0) { throw 'HOST_AGENT_WINDOWS_TRAY_EXPLORER_SESSION_REQUIRED' }
}

function Stop-HostAgentWindowsNewTrayCandidates {
    param(
        [Parameter(Mandatory)][object[]]$Candidates,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$BeforeProcessIds,
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter(Mandatory)][int]$SessionId,
        [Parameter(Mandatory)][scriptblock]$StopAction
    )
    $expected = [IO.Path]::GetFullPath($ExecutablePath)
    $failures = [Collections.Generic.List[int]]::new()
    foreach ($candidate in $Candidates) {
        $processId = [int]$candidate.Id
        if ($BeforeProcessIds -contains $processId) { continue }
        if ([int]$candidate.SessionId -ne $SessionId) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$candidate.Path)) { continue }
        $actual = [IO.Path]::GetFullPath([string]$candidate.Path)
        if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) { continue }
        try { & $StopAction $processId } catch { $failures.Add($processId) }
    }
    if ($failures.Count -gt 0) { throw 'HOST_AGENT_WINDOWS_TRAY_CLEANUP_REFUSED' }
}

function Invoke-HostAgentWindowsTrayLaunchCore {
    param(
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter(Mandatory)][int]$SessionId,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$BeforeProcessIds,
        [Parameter(Mandatory)][scriptblock]$LaunchAction,
        [Parameter(Mandatory)][scriptblock]$ObserveAction,
        [Parameter(Mandatory)][scriptblock]$ElevationProbe,
        [Parameter(Mandatory)][scriptblock]$StopAction,
        [Parameter(Mandatory)][scriptblock]$SleepAction,
        [int]$PollAttempts = $script:PollAttempts
    )
    if ($PollAttempts -lt 1 -or $PollAttempts -gt 300) { throw 'HOST_AGENT_WINDOWS_TRAY_POLL_BOUND_REFUSED' }
    $expected = [IO.Path]::GetFullPath($ExecutablePath)
    & $LaunchAction $expected $SessionId

    for ($attempt = 0; $attempt -lt $PollAttempts; $attempt++) {
        $observed = @(& $ObserveAction)
        $new = @($observed | Where-Object { $BeforeProcessIds -notcontains [int]$_.Id })
        if ($new.Count -gt 1) {
            Stop-HostAgentWindowsNewTrayCandidates -Candidates $new -BeforeProcessIds $BeforeProcessIds -ExecutablePath $expected -SessionId $SessionId -StopAction $StopAction
            throw 'HOST_AGENT_WINDOWS_TRAY_AMBIGUOUS_RESULT'
        }
        if ($new.Count -eq 1) {
            $candidate = $new[0]
            $candidatePath = if ([string]::IsNullOrWhiteSpace([string]$candidate.Path)) { $null } else { [IO.Path]::GetFullPath([string]$candidate.Path) }
            if ([int]$candidate.SessionId -ne $SessionId -or $null -eq $candidatePath -or -not [string]::Equals($candidatePath, $expected, [StringComparison]::OrdinalIgnoreCase)) {
                Stop-HostAgentWindowsNewTrayCandidates -Candidates $new -BeforeProcessIds $BeforeProcessIds -ExecutablePath $expected -SessionId $SessionId -StopAction $StopAction
                throw 'HOST_AGENT_WINDOWS_TRAY_RESULT_IDENTITY_REFUSED'
            }
            try {
                $elevated = [bool](& $ElevationProbe ([int]$candidate.Id))
            } catch {
                Stop-HostAgentWindowsNewTrayCandidates -Candidates $new -BeforeProcessIds $BeforeProcessIds -ExecutablePath $expected -SessionId $SessionId -StopAction $StopAction
                throw 'HOST_AGENT_WINDOWS_TRAY_TOKEN_PROBE_REFUSED'
            }
            if ($elevated) {
                Stop-HostAgentWindowsNewTrayCandidates -Candidates $new -BeforeProcessIds $BeforeProcessIds -ExecutablePath $expected -SessionId $SessionId -StopAction $StopAction
                throw 'HOST_AGENT_WINDOWS_TRAY_ELEVATED_RESULT_REFUSED'
            }
            return [pscustomobject]@{
                Started = $true
                ProcessId = [int]$candidate.Id
                SessionId = [int]$candidate.SessionId
                Elevated = $false
            }
        }
        & $SleepAction $script:PollMilliseconds
    }
    # Final readback closes the last-poll race without accepting a late result.
    # Cleanup is limited to new fixed-path processes in the expected session.
    $finalObserved = @(& $ObserveAction)
    $finalNew = @($finalObserved | Where-Object { $BeforeProcessIds -notcontains [int]$_.Id })
    if ($finalNew.Count -gt 0) {
        Stop-HostAgentWindowsNewTrayCandidates -Candidates $finalNew -BeforeProcessIds $BeforeProcessIds -ExecutablePath $expected -SessionId $SessionId -StopAction $StopAction
    }
    throw 'HOST_AGENT_WINDOWS_TRAY_LAUNCH_TIMEOUT'
}

function Get-HostAgentWindowsTrayLaunchPlan {
    $constants = Get-HostAgentWindowsTrayLaunchConstants
    $installed = Get-HostAgentWindowsInstalledObservation
    if ($installed.State -cne 'Managed' -or $null -eq $installed.Context) { throw 'HOST_AGENT_WINDOWS_TRAY_MANAGED_INSTALL_REQUIRED' }
    Assert-HostAgentWindowsSafeFile -Path $constants.ExecutablePath

    $running = @(Get-HostAgentWindowsTrayProcesses)
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $explorers = if ($sessionId -gt 0) { @(Get-HostAgentWindowsExplorerCandidates -SessionId $sessionId) } else { @() }
    Assert-HostAgentWindowsTrayLaunchState -InstalledState $installed.State -RunningCount $running.Count -SessionId $sessionId -ExplorerCandidateCount $explorers.Count

    [pscustomobject]@{
        Action = 'Plan'
        MutationPerformed = $false
        ExecutablePath = $constants.ExecutablePath
        ManagedSourceCommit = $installed.Context.SourceCommit
        ManagedSourceTree = $installed.Context.SourceTree
        SessionId = $sessionId
        ExplorerCandidateCount = $explorers.Count
        ExplorerPid = [int]$explorers[0].Id
        RunningCount = 0
        RequiresExistingExplorer = $true
        ResultMustBeUnelevated = $true
        StartupRegistrationMutation = $false
        IncrementalRuntimeCostUsd = 0
    }
}

function Start-HostAgentWindowsTray {
    $plan = Get-HostAgentWindowsTrayLaunchPlan
    $constants = Get-HostAgentWindowsTrayLaunchConstants
    $before = @(Get-HostAgentWindowsTrayProcesses | ForEach-Object { [int]$_.Id })
    if ($before.Count -ne 0) { throw 'HOST_AGENT_WINDOWS_TRAY_ALREADY_RUNNING' }

    $launchAction = {
        param([string]$ExecutablePath,[int]$SessionId)
        $null = $SessionId
        Start-Process -FilePath $constants.ExplorerPath -ArgumentList ('"' + $ExecutablePath + '"') -ErrorAction Stop
    }.GetNewClosure()
    $observeAction = { @(Get-HostAgentWindowsTrayProcesses) }
    $elevationProbe = { param([int]$ProcessId) Test-HostAgentWindowsProcessElevated -ProcessId $ProcessId }
    $stopAction = {
        param([int]$ProcessId)
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Wait-Process -Id $ProcessId -Timeout 5 -ErrorAction SilentlyContinue
        if ($null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { throw 'tray-cleanup-timeout' }
    }
    $sleepAction = { param([int]$Milliseconds) Start-Sleep -Milliseconds $Milliseconds }

    $result = Invoke-HostAgentWindowsTrayLaunchCore -ExecutablePath $constants.ExecutablePath -SessionId $plan.SessionId -BeforeProcessIds $before -LaunchAction $launchAction -ObserveAction $observeAction -ElevationProbe $elevationProbe -StopAction $stopAction -SleepAction $sleepAction
    [pscustomobject]@{
        Action = 'Start'
        Started = $result.Started
        MutationPerformed = $true
        ProcessId = $result.ProcessId
        SessionId = $result.SessionId
        Elevated = $result.Elevated
        ManagedSourceCommit = $plan.ManagedSourceCommit
        ManagedSourceTree = $plan.ManagedSourceTree
        StartupRegistrationMutation = $false
        IncrementalRuntimeCostUsd = 0
    }
}

Export-ModuleMember -Function Get-HostAgentWindowsTrayLaunchConstants, Get-HostAgentWindowsTrayLaunchPlan, Start-HostAgentWindowsTray
