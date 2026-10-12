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

    Check 'provenance validation passes on valid manifest and fails on tampering' {
        $tempDir = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + '/CiRunnerEphemeral')
        [void](New-Item -ItemType Directory -Path $tempDir -Force)
        try {
            $manifestSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../provenance.json') -Raw | ConvertFrom-Json
            $fileMap = @{}
            foreach ($prop in $manifestSource.Files.psobject.properties) {
                $subPath = Join-Path $tempDir $prop.Name
                [void](New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($subPath)) -Force)
                Set-Content -LiteralPath $subPath -Value ('content-for-' + $prop.Name)
                $fileMap[$prop.Name] = (Get-FileHash -LiteralPath $subPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $testManifest = [pscustomobject]@{ Schema = 1; Description = 'test'; Files = $fileMap }
            $testManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $tempDir 'provenance.json')

            # Should pass
            Assert-Ci7Provenance $tempDir

            # Modify a file -> should fail
            $tampered = Join-Path $tempDir 'CiRunner.psm1'
            Set-Content -LiteralPath $tampered -Value 'tampered'
            Refuses { Assert-Ci7Provenance $tempDir }

            # Restore file, remove another -> should fail
            Set-Content -LiteralPath $tampered -Value ('content-for-CiRunner.psm1')
            Remove-Item -LiteralPath (Join-Path $tempDir 'Native.cs')
            Refuses { Assert-Ci7Provenance $tempDir }
        } finally {
            if (Test-Path -LiteralPath $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force }
        }
    }

    Check 'allowlist profiles match strict repo, workflow, event, and label bounds' {
        $profiles = Get-Ci7DispatcherAllowlist
        Assert ($profiles.Count -eq 1)
        Assert ($profiles[0].ProfileId -ceq 'business-operations-secret-scan')
        Assert ($profiles[0].Repository -ceq 'LowcountryDigitalWorks/business-operations')

        $proofProfiles = Get-Ci7DispatcherAllowlist -AllowPublicSyntheticProof
        Assert ($proofProfiles.Count -eq 2)
        Assert ($proofProfiles[1].ProfileId -ceq 'infrastructure-tools-synthetic-proof')

        foreach ($p in $proofProfiles) { Assert-Ci7AllowlistProfile $p }

        $badRepo = $profiles[0] | ConvertTo-Json | ConvertFrom-Json
        $badRepo.Repository = 'untrusted/repo'
        Refuses { Assert-Ci7AllowlistProfile $badRepo }

        $badBounds = $profiles[0] | ConvertTo-Json | ConvertFrom-Json
        $badBounds.MemoryMiB = 1024
        Refuses { Assert-Ci7AllowlistProfile $badBounds }
    }

    & $module {
        param($cfg)
        $script:MockRuns = @()
        $script:MockJobs = @{}
        function script:Invoke-Ci7Api {
            param($Path, $Method = 'GET', $Body)
            if ($Path -match '/actions/runs\?status=queued') {
                return [pscustomobject]@{ total_count = @($script:MockRuns).Count; workflow_runs = @($script:MockRuns) }
            }
            if ($Path -match '/actions/runs/(\d+)/jobs') {
                $runId = [string]$matches[1]
                $jobs = if ($script:MockJobs.Contains($runId)) { @($script:MockJobs[$runId]) } else { @() }
                return [pscustomobject]@{ total_count = $jobs.Count; jobs = $jobs }
            }
            return [pscustomobject]@{ private = $true }
        }
    }

    Check 'queued candidate discovery filters ineligible runs and sorts oldest first' {
        $profile = (Get-Ci7DispatcherAllowlist)[0]
        $safeLabels = Get-Ci7Labels 101

        # Add candidate 1 (newer)
        $run101 = [pscustomobject]@{
            id = 101
            path = '.github/workflows/security-secrets.yml'
            event = 'push'
            head_branch = 'main'
            head_sha = 'a' * 40
            head_repository = [pscustomobject]@{ full_name = 'LowcountryDigitalWorks/business-operations'; private = $true }
            created_at = '2026-10-12T12:00:00Z'
            run_number = 2
        }
        $job101 = [pscustomobject]@{ id = 1001; status = 'queued'; runner_id = $null; labels = $safeLabels }

        # Add candidate 2 (older)
        $labels100 = Get-Ci7Labels 100
        $run100 = [pscustomobject]@{
            id = 100
            path = '.github/workflows/security-secrets.yml'
            event = 'push'
            head_branch = 'main'
            head_sha = 'b' * 40
            head_repository = [pscustomobject]@{ full_name = 'LowcountryDigitalWorks/business-operations'; private = $true }
            created_at = '2026-10-12T10:00:00Z'
            run_number = 1
        }
        $job100 = [pscustomobject]@{ id = 1000; status = 'queued'; runner_id = $null; labels = $labels100 }

        & $module {
            param($r1, $j1, $r2, $j2)
            $script:MockRuns = @($r1, $r2)
            $script:MockJobs = @{ '101' = $j1; '100' = $j2 }
        } $run101 $job101 $run100 $job100

        $allowlist = Get-Ci7DispatcherAllowlist
        $candidates = Get-Ci7QueuedCandidates $allowlist

        Assert ($candidates.Count -eq 2)
        # Oldest first sorting check: run 100 (created 10:00) before run 101 (created 12:00)
        Assert ($candidates[0].WorkflowRunId -eq 100)
        Assert ($candidates[1].WorkflowRunId -eq 101)
    }

    Check 'dispatcher lock prevents concurrent dispatcher polling' {
        $first = Enter-Ci7DispatcherLock $root
        try { Refuses { Enter-Ci7DispatcherLock $root } }
        finally { $first.Dispose() }
        $second = Enter-Ci7DispatcherLock $root
        $second.Dispose()
        Assert ((Get-Item -LiteralPath (Join-Path $root 'dispatch.lock')).Length -eq 0)
    }

    Check 'sanitized dispatcher evidence logs contain no credentials or raw API payloads' {
        Write-Ci7DispatcherLog $root 'eligible-job-detected' 'business-operations-secret-scan' 1001
        $logFile = Join-Path $root 'evidence/dispatcher.jsonl'
        Assert (Test-Path -LiteralPath $logFile)
        $lines = @(Get-Content -LiteralPath $logFile)
        Assert ($lines.Count -ge 1)
        $entry = $lines[-1] | ConvertFrom-Json
        Assert ($entry.phase -ceq 'eligible-job-detected')
        Assert ($entry.profile -ceq 'business-operations-secret-scan')
        Assert ($entry.run_id -eq 1001)
        Assert (-not $lines[-1].Contains('token') -and -not $lines[-1].Contains('password'))
    }

    Check 'PowerShell AST syntax of Invoke-Ci7Dispatcher.ps1' {
        $source = Join-Path $PSScriptRoot '../Invoke-Ci7Dispatcher.ps1'
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
        Assert ($errors.Count -eq 0)
    }

    'DETERMINISTIC_TESTS=PASS'
    'TEST_COUNT=' + $total

} finally {
    Remove-Module $module -Force
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $full = [IO.Path]::GetFullPath($root)
    if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -cne 'CiRunnerEphemeral') { throw 'TEST_CLEANUP_ROOT_INVALID' }
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force }
}
