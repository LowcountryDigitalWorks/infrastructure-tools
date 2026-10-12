[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$module = Import-Module (Join-Path $PSScriptRoot '../CiRunner.psm1') -Force -PassThru
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + '/CiRunnerEphemeral')
$total = 0

function Check([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:total++
    'PASS ' + $Name
}

function Assert([bool]$Condition) { if (-not $Condition) { throw 'TEST_ASSERTION_FAILED' } }

function Refuses([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert $rejected
}

try {
    [void](New-Item -ItemType Directory -Path (Join-Path $root 'runs') -Force)
    [void](New-Item -ItemType Directory -Path (Join-Path $root 'evidence') -Force)

    Check 'dispatcher profiles filter correctly based on repository allowlist and synthetic proof flag' {
        $profilesDefault = Get-Ci7DispatcherProfiles -ApprovedRepositories @('LowcountryDigitalWorks/business-operations')
        Assert ($profilesDefault.Count -eq 1)
        Assert ($profilesDefault[0].Repository -ceq 'LowcountryDigitalWorks/business-operations')
        Assert ($profilesDefault[0].WorkflowPath -ceq '.github/workflows/security-secrets.yml')

        $profilesProof = Get-Ci7DispatcherProfiles -ApprovedRepositories @('LowcountryDigitalWorks/business-operations') -AllowPublicSyntheticProof
        Assert ($profilesProof.Count -eq 2)
        Assert ($profilesProof[0].Repository -ceq 'LowcountryDigitalWorks/infrastructure-tools')
        Assert ($profilesProof[0].PublicSyntheticProof)
    }

    Check 'artifact provenance check verifies exact file hashes' {
        Assert-Ci7ArtifactProvenance -Path (Join-Path $PSScriptRoot '..')
        Refuses { Assert-Ci7ArtifactProvenance -Path $root }
    }

    Check 'queue discovery filters candidate runs, checks labels and sorts oldest first' {
        & $module {
            $script:MockApiRuns = [pscustomobject]@{
                workflow_runs = @(
                    [pscustomobject]@{
                        id = 101
                        path = '.github/workflows/security-secrets.yml'
                        event = 'push'
                        head_branch = 'main'
                        head_sha = 'a' * 40
                        created_at = '2026-10-15T12:00:00Z'
                        head_repository = [pscustomobject]@{ full_name = 'LowcountryDigitalWorks/business-operations' }
                    },
                    [pscustomobject]@{
                        id = 100
                        path = '.github/workflows/security-secrets.yml'
                        event = 'push'
                        head_branch = 'main'
                        head_sha = 'b' * 40
                        created_at = '2026-10-15T11:00:00Z'
                        head_repository = [pscustomobject]@{ full_name = 'LowcountryDigitalWorks/business-operations' }
                    },
                    [pscustomobject]@{
                        id = 102
                        path = '.github/workflows/unrelated.yml'
                        event = 'push'
                        head_branch = 'main'
                        head_sha = 'c' * 40
                        created_at = '2026-10-15T10:00:00Z'
                        head_repository = [pscustomobject]@{ full_name = 'LowcountryDigitalWorks/business-operations' }
                    }
                )
            }
            $script:MockApiJobs = @{
                100 = [pscustomobject]@{
                    total_count = 1
                    jobs = @(
                        [pscustomobject]@{
                            id = 1001
                            status = 'queued'
                            runner_id = 0
                            labels = @(Get-Ci7Labels 100)
                        }
                    )
                }
                101 = [pscustomobject]@{
                    total_count = 1
                    jobs = @(
                        [pscustomobject]@{
                            id = 1002
                            status = 'queued'
                            runner_id = 0
                            labels = @(Get-Ci7Labels 101)
                        }
                    )
                }
            }

            function script:Invoke-Ci7Api {
                param($Path, $Method = 'GET', $Body)
                if ($Path -match '/actions/runs\?status=queued') {
                    return $script:MockApiRuns
                } elseif ($Path -match '/actions/runs/(\d+)/jobs') {
                    $runId = [long]$Matches[1]
                    return $script:MockApiJobs[$runId]
                }
                throw "UNMOCKED_PATH: $Path"
            }
        }

        $profiles = Get-Ci7DispatcherProfiles -ApprovedRepositories @('LowcountryDigitalWorks/business-operations')
        $candidates = Get-Ci7EligibleJobs -Profiles $profiles

        Assert ($candidates.Count -eq 2)
        Assert ($candidates[0].WorkflowRunId -eq 100) # Oldest first (11:00 before 12:00)
        Assert ($candidates[1].WorkflowRunId -eq 101)
        Assert ($candidates[0].ExpectedSha -ceq ('b' * 40))
    }

    Check 'dispatcher evidence logging writes sanitized JSONL' {
        Write-Ci7DispatcherEvidence $root 'started' @{ mode = 'PollOnce' }
        Write-Ci7DispatcherEvidence $root 'candidate-selected' @{ repo = 'LowcountryDigitalWorks/business-operations'; run_id = 100 }

        $logPath = Join-Path $root 'evidence/dispatcher.jsonl'
        Assert (Test-Path -LiteralPath $logPath)
        $lines = Get-Content -LiteralPath $logPath
        Assert ($lines.Count -eq 2)

        $entry1 = $lines[0] | ConvertFrom-Json
        Assert ($entry1.event -ceq 'started')
        Assert ($entry1.mode -ceq 'PollOnce')

        $entry2 = $lines[1] | ConvertFrom-Json
        Assert ($entry2.event -ceq 'candidate-selected')
        Assert ($entry2.run_id -eq 100)
    }

    'DETERMINISTIC_DISPATCHER_TESTS=PASS'
    'TEST_COUNT=' + $total
} finally {
    Remove-Module $module -Force
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $full = [IO.Path]::GetFullPath($root)
    if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -cne 'CiRunnerEphemeral') { throw 'TEST_CLEANUP_ROOT_INVALID' }
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force }
}
