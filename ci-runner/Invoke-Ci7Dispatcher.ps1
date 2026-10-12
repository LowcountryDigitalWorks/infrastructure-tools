[CmdletBinding()]
param(
    [ValidateSet('PollOnce','Loop')][string]$Mode = 'PollOnce',
    [string[]]$ApprovedRepositories = @('LowcountryDigitalWorks/business-operations'),
    [string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'),
    [switch]$AllowPublicSyntheticProof,
    [int]$PollIntervalSeconds = 30,
    [int]$MaxLoops = 0,
    [switch]$SkipProvenanceCheck
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force

Assert-Ci7Elevated
Initialize-Ci7Root $Root

if (-not $SkipProvenanceCheck) {
    Assert-Ci7ArtifactProvenance -Path $PSScriptRoot
}

Write-Ci7DispatcherEvidence $Root 'started' @{ mode = $Mode }

$loopCount = 0

try {
    do {
        $loopCount++
        $rootLock = $null
        try {
            $rootLock = Enter-Ci7ControllerLock $Root

            # Reconcile/reap stale or interrupted runs first
            try {
                & (Join-Path $PSScriptRoot 'Invoke-IsolatedRunner.ps1') -Mode Reap -Root $Root -ApprovedRepositories $ApprovedRepositories
            } catch {
                Write-Ci7DispatcherEvidence $Root 'reap-failure'
            }

            # Discover eligible queued jobs matching strict allowlist profiles
            $profiles = Get-Ci7DispatcherProfiles -ApprovedRepositories $ApprovedRepositories -AllowPublicSyntheticProof:$AllowPublicSyntheticProof
            $candidates = Get-Ci7EligibleJobs -Profiles $profiles

            if ($candidates.Count -gt 0) {
                $selected = $candidates[0]
                Write-Ci7DispatcherEvidence $Root 'candidate-selected' @{
                    repo = $selected.Repository
                    profile = $selected.Profile.Name
                    run_id = $selected.WorkflowRunId
                }

                # Release the lock before launching Invoke-IsolatedRunner which manages its own root lock and lifecycle
                if ($rootLock) { $rootLock.Dispose(); $rootLock = $null }

                $runnerArgs = @{
                    Mode = 'Run'
                    Repository = $selected.Repository
                    ApprovedRepositories = $ApprovedRepositories
                    WorkflowRunId = $selected.WorkflowRunId
                    ExpectedSha = $selected.ExpectedSha
                    Root = $Root
                    AllowPublicSyntheticProof = $selected.Profile.PublicSyntheticProof
                    MemoryMiB = $selected.Profile.MemoryMiB
                    CpuCount = $selected.Profile.CpuCount
                    TimeoutMinutes = $selected.Profile.TimeoutMinutes
                }

                try {
                    & (Join-Path $PSScriptRoot 'Invoke-IsolatedRunner.ps1') @runnerArgs
                    Write-Ci7DispatcherEvidence $Root 'runner-success' @{ run_id = $selected.WorkflowRunId }
                } catch {
                    Write-Ci7DispatcherEvidence $Root 'runner-failure' @{ run_id = $selected.WorkflowRunId }
                }
            } else {
                Write-Ci7DispatcherEvidence $Root 'poll-idle'
            }
        } catch {
            $msg = [string]$_.Exception.Message
            if ($msg -cnotmatch '^[A-Z][A-Z0-9_]+$') { $msg = 'DISPATCHER_POLL_FAILED' }
            Write-Ci7DispatcherEvidence $Root 'poll-error' @{ error = $msg }
        } finally {
            if ($rootLock) { $rootLock.Dispose(); $rootLock = $null }
        }

        if ($Mode -eq 'Loop') {
            if ($MaxLoops -gt 0 -and $loopCount -ge $MaxLoops) { break }
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    } while ($Mode -eq 'Loop')
} finally {
    Write-Ci7DispatcherEvidence $Root 'stopped' @{ mode = $Mode; loops = $loopCount }
}
