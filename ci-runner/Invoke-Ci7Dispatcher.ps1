[CmdletBinding()]
param(
    [ValidateSet('Verify','PollOnce','Service','RegisterTask','UnregisterTask')][string]$Mode = 'PollOnce',
    [string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'),
    [int]$PollIntervalSeconds = 30,
    [switch]$AllowPublicSyntheticProof
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force

$dispatchLock = $null
try {
    Assert-Ci7Elevated
    Assert-Ci7Provenance $PSScriptRoot

    if ($Mode -eq 'Verify') {
        & gh auth status 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'GH_AUTH_UNAVAILABLE' }
        $allowlist = Get-Ci7DispatcherAllowlist -AllowPublicSyntheticProof:$AllowPublicSyntheticProof
        if (-not $allowlist -or $allowlist.Count -eq 0) { throw 'ALLOWLIST_EMPTY' }
        Initialize-Ci7Root $Root
        'DISPATCHER_VERIFY=PASS'
        exit 0
    }

    if ($Mode -eq 'RegisterTask') {
        $taskName = 'LDW-CiRunner-Dispatcher'
        $scriptPath = Join-Path $PSScriptRoot 'Invoke-Ci7Dispatcher.ps1'
        Assert-Ci7Path $PSScriptRoot $scriptPath
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument ('-ExecutionPolicy Bypass -NoProfile -File "' + $scriptPath + '" -Mode Service' + $(if ($AllowPublicSyntheticProof) { ' -AllowPublicSyntheticProof' } else { '' }))
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId $currentUser -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        'SCHEDULED_TASK_REGISTERED=PASS'
        exit 0
    }

    if ($Mode -eq 'UnregisterTask') {
        $taskName = 'LDW-CiRunner-Dispatcher'
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
        }
        'SCHEDULED_TASK_UNREGISTERED=PASS'
        exit 0
    }

    Initialize-Ci7Root $Root
    $dispatchLock = Enter-Ci7DispatcherLock $Root
    Write-Ci7DispatcherLog $Root 'dispatcher-started'

    script:PollQueueOnce -Root $Root -AllowPublicSyntheticProof:$AllowPublicSyntheticProof

    if ($Mode -eq 'Service') {
        while ($true) {
            Start-Sleep -Seconds $PollIntervalSeconds
            script:PollQueueOnce -Root $Root -AllowPublicSyntheticProof:$AllowPublicSyntheticProof
        }
    }

    Write-Ci7DispatcherLog $Root 'dispatcher-completed'
    'DISPATCHER_RESULT=PASS'
    exit 0

} catch {
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z0-9_]+$') { $code = 'DISPATCHER_OPERATION_FAILED' }
    try { Write-Ci7DispatcherLog $Root ('dispatcher-failed-' + $code.ToLowerInvariant()) } catch {}
    'DISPATCHER_RESULT=FAIL'
    'CLASSIFICATION=' + $code
    exit 1
} finally {
    if ($dispatchLock) { $dispatchLock.Dispose(); $dispatchLock = $null }
}

function script:PollQueueOnce {
    param([string]$Root, [switch]$AllowPublicSyntheticProof)

    # Reconcile any stale/interrupted local resources before discovering new jobs
    $reapOutput = & (Join-Path $PSScriptRoot 'Invoke-IsolatedRunner.ps1') -Mode Reap -Root $Root 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'REAP_RECONCILIATION_FAILED' }

    $allowlist = Get-Ci7DispatcherAllowlist -AllowPublicSyntheticProof:$AllowPublicSyntheticProof
    $candidates = Get-Ci7QueuedCandidates $allowlist -AllowPublicSyntheticProof:$AllowPublicSyntheticProof

    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Ci7DispatcherLog $Root 'queue-idle'
        'DISPATCHER_POLL=IDLE'
        return
    }

    $selected = $candidates[0]
    Write-Ci7DispatcherLog $Root 'eligible-job-detected' $selected.Profile.ProfileId $selected.WorkflowRunId

    # Defense in depth: re-read job status immediately prior to controller invocation
    $config = New-Ci7Configuration -Repository $selected.Repository -WorkflowRunId $selected.WorkflowRunId `
        -ExpectedSha $selected.ExpectedSha -Root $Root -AllowPublicSyntheticProof:$selected.Profile.AllowPublicSyntheticProof `
        -MemoryMiB $selected.Profile.MemoryMiB -CpuCount $selected.Profile.CpuCount -TimeoutMinutes $selected.Profile.TimeoutMinutes

    $job = Get-Ci7ExpectedJob $config -RequireQueued
    if ($job.status -cne 'queued' -or $job.runner_id) {
        Write-Ci7DispatcherLog $Root 'job-status-changed-before-provisioning' $selected.Profile.ProfileId $selected.WorkflowRunId
        throw 'JOB_NOT_QUEUED_BEFORE_PROVISIONING'
    }

    Write-Ci7DispatcherLog $Root 'controller-started' $selected.Profile.ProfileId $selected.WorkflowRunId

    $runnerParams = @(
        '-Mode', 'Run',
        '-Repository', $selected.Repository,
        '-WorkflowRunId', [string]$selected.WorkflowRunId,
        '-ExpectedSha', $selected.ExpectedSha,
        '-Root', $Root,
        '-MemoryMiB', [string]$selected.Profile.MemoryMiB,
        '-CpuCount', [string]$selected.Profile.CpuCount,
        '-TimeoutMinutes', [string]$selected.Profile.TimeoutMinutes
    )
    if ($selected.Profile.AllowPublicSyntheticProof) { $runnerParams += '-AllowPublicSyntheticProof' }

    $runnerScript = Join-Path $PSScriptRoot 'Invoke-IsolatedRunner.ps1'
    & $runnerScript @runnerParams
    if ($LASTEXITCODE -ne 0) {
        Write-Ci7DispatcherLog $Root 'controller-failed' $selected.Profile.ProfileId $selected.WorkflowRunId
        throw 'CONTROLLER_INVOCATION_FAILED'
    }

    Write-Ci7DispatcherLog $Root 'controller-completed' $selected.Profile.ProfileId $selected.WorkflowRunId
    'DISPATCHER_POLL=PROVISIONED'
}
