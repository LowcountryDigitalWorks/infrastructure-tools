[CmdletBinding()]
param(
    [ValidateSet('PollOnce', 'Loop', 'InstallTask', 'UninstallTask', 'Status', 'Reap')][string]$Mode = 'PollOnce',
    [string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'),
    [string[]]$ApprovedRepositories = @('LowcountryDigitalWorks/business-operations'),
    [int]$PollIntervalSeconds = 15,
    [switch]$AllowPublicSyntheticProof
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force

$TaskName = 'LDW-CiRunner-Dispatcher'

try {
    Assert-Ci7Elevated

    if ($Mode -eq 'InstallTask') {
        Assert-Ci7ControllerProvenance
        $exe = (Get-Command pwsh -ErrorAction SilentlyContinue)
        $exePath = if ($exe) { $exe.Source } else { 'powershell.exe' }
        $scriptPath = Join-Path $PSScriptRoot 'Invoke-Ci7Dispatcher.ps1'
        $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode Loop -Root `"$Root`""
        if ($AllowPublicSyntheticProof) { $argList += ' -AllowPublicSyntheticProof' }

        $action = New-ScheduledTaskAction -Execute $exePath -Argument $argList
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365)

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        'DISPATCHER_TASK_INSTALLED=PASS'
        exit 0
    }

    if ($Mode -eq 'UninstallTask') {
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
        try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        'DISPATCHER_TASK_UNINSTALLED=PASS'
        exit 0
    }

    if ($Mode -eq 'Status') {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        $taskState = if ($task) { [string]$task.State } else { 'NotInstalled' }
        $lockPath = Join-Path $Root 'control.lock'
        $busy = (Test-Path -LiteralPath $lockPath)
        'DISPATCHER_TASK_STATUS=' + $taskState
        'DISPATCHER_BUSY_STATE=' + (if ($busy) { 'BUSY' } else { 'IDLE' })
        exit 0
    }

    if ($Mode -eq 'Reap') {
        Assert-Ci7ControllerProvenance
        & (Join-Path $PSScriptRoot 'Invoke-IsolatedRunner.ps1') -Mode Reap -Root $Root -ApprovedRepositories $ApprovedRepositories
        'DISPATCHER_REAP=PASS'
        exit 0
    }

    # Modes PollOnce and Loop require provenance and root initialization
    Assert-Ci7ControllerProvenance
    Initialize-Ci7Root $Root
    Write-Ci7DispatcherEvidence -Root $Root -Event 'DISPATCHER_STARTED' -Status 'PASS'

    function Invoke-DispatcherCycle {
        try {
            # Stale / interrupted resource check
            $runsDir = Join-Path $Root 'runs'
            if (Test-Path -LiteralPath $runsDir) {
                $staleDirs = @(Get-ChildItem -LiteralPath $runsDir -Directory)
                if ($staleDirs.Count -gt 0) {
                    Write-Ci7DispatcherEvidence -Root $Root -Event 'REAP_ATTEMPT' -Status 'INFO'
                    & (Join-Path $PSScriptRoot 'Invoke-IsolatedRunner.ps1') -Mode Reap -Root $Root -ApprovedRepositories $ApprovedRepositories
                }
            }

            # Capacity / active controller lock check
            $lockPath = Join-Path $Root 'control.lock'
            if (Test-Path -LiteralPath $lockPath) {
                try {
                    $testLock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
                    $testLock.Dispose()
                } catch {
                    Write-Ci7DispatcherEvidence -Root $Root -Event 'CAPACITY_BUSY' -Status 'INFO'
                    'DISPATCHER_CAPACITY_BUSY=YES'
                    return
                }
            }

            # Queue discovery
            $profiles = Get-Ci7DispatcherAllowlist -AllowPublicSyntheticProof:$AllowPublicSyntheticProof -ApprovedRepositories $ApprovedRepositories
            $candidates = Get-Ci7QueuedJobs -Profiles $profiles
            $selected = Select-Ci7EligibleJob -CandidateJobs $candidates

            if (-not $selected) {
                Write-Ci7DispatcherEvidence -Root $Root -Event 'POLL_IDLE' -Status 'INFO'
                'DISPATCHER_POLL_RESULT=IDLE'
                return
            }

            Write-Ci7DispatcherEvidence -Root $Root -Event 'ELIGIBLE_JOB_DETECTED' -ProfileId $selected.Profile.ProfileId -WorkflowRunId $selected.WorkflowRunId -Status 'PASS'
            'DISPATCHER_ELIGIBLE_JOB=' + $selected.WorkflowRunId

            # Invoke isolated runner controller
            & (Join-Path $PSScriptRoot 'Invoke-IsolatedRunner.ps1') -Mode Run `
                -Repository $selected.Repository `
                -WorkflowRunId $selected.WorkflowRunId `
                -ExpectedSha $selected.ExpectedSha `
                -Root $Root `
                -ApprovedRepositories $ApprovedRepositories `
                -AllowPublicSyntheticProof:$AllowPublicSyntheticProof `
                -MemoryMiB $selected.Profile.MemoryMiB `
                -CpuCount $selected.Profile.CpuCount `
                -TimeoutMinutes $selected.Profile.TimeoutMinutes

            if ($LASTEXITCODE -eq 0) {
                Write-Ci7DispatcherEvidence -Root $Root -Event 'CONTROLLER_COMPLETED' -ProfileId $selected.Profile.ProfileId -WorkflowRunId $selected.WorkflowRunId -Status 'PASS'
                'DISPATCHER_CONTROLLER_RESULT=PASS'
            } else {
                Write-Ci7DispatcherEvidence -Root $Root -Event 'CONTROLLER_FAILED' -ProfileId $selected.Profile.ProfileId -WorkflowRunId $selected.WorkflowRunId -Status 'FAIL'
                'DISPATCHER_CONTROLLER_RESULT=FAIL'
            }
        } catch {
            $msg = [string]$_.Exception.Message
            if ($msg -cnotmatch '^[A-Z][A-Z0-9_]+$') { $msg = 'DISPATCHER_CYCLE_FAILED' }
            Write-Ci7DispatcherEvidence -Root $Root -Event 'DISPATCHER_ERROR' -Status $msg
            'DISPATCHER_ERROR=' + $msg
        }
    }

    if ($Mode -eq 'PollOnce') {
        Invoke-DispatcherCycle
    } else {
        while ($true) {
            Invoke-DispatcherCycle
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }
} catch {
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z0-9_]+$') { $code = 'DISPATCHER_OPERATION_FAILED' }
    'DISPATCHER_RESULT=FAIL'
    'CLASSIFICATION=' + $code
    exit 1
}
