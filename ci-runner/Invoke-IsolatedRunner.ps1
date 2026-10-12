[CmdletBinding()]
param(
    [ValidateSet('Plan','Run','Cleanup','Reap')][string]$Mode = 'Plan',
    [string]$Repository = 'LowcountryDigitalWorks/business-operations',
    [string[]]$ApprovedRepositories = @('LowcountryDigitalWorks/business-operations', 'LowcountryDigitalWorks/wqt-operations'),
    [long]$WorkflowRunId, [string]$ExpectedSha,
    [string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'),
    [string]$LocalRunId,
    [switch]$AllowPublicSyntheticProof,
    [int]$MemoryMiB = 2048, [int]$CpuCount = 2, [int]$TimeoutMinutes = 20,
    [string]$WorkflowPath, [string]$TargetJob, [string]$ExpectedEvent, [int]$Attempt = 1
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force
$state = $null
$lock = $null
$rootLock = $null
$diagnostics = $null
$cleanupComplete = $false
try {
    Assert-Ci7Elevated
    if ($Mode -in @('Cleanup','Reap')) {
        $rootLock = Enter-Ci7ControllerLock $Root
        if ($Mode -eq 'Cleanup' -and $LocalRunId -cnotmatch '^[0-9a-f]{32}$') { throw 'LOCAL_RUN_ID_REQUIRED' }
        if ($Mode -eq 'Cleanup' -and -not (Test-Path -LiteralPath (Join-Path $Root ('runs/' + $LocalRunId)))) {
            Assert-Ci7AlreadyClean $Root $LocalRunId $ApprovedRepositories
            'CLEANUP_IDEMPOTENT=PASS'
            exit 0
        }
        $directories = if ($Mode -eq 'Cleanup') { @(Join-Path $Root ('runs/' + $LocalRunId)) } else {
            @(Get-ChildItem -LiteralPath (Join-Path $Root 'runs') -Directory -ErrorAction Stop | ForEach-Object FullName)
        }
        foreach ($directory in $directories) {
            Assert-Ci7Path $Root $directory
            if ([IO.Path]::GetFileName($directory) -cnotmatch '^[0-9a-f]{32}$') { throw 'STALE_DIRECTORY_OWNERSHIP_AMBIGUOUS' }
            $file = Join-Path $directory 'state.json'
            if (-not (Test-Path -LiteralPath $file)) { throw 'STALE_STATE_MISSING' }
            $state = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            Assert-Ci7State $state $Root
            # A live controller owns an exclusive lock. Reap never races it.
            try { $lock = [IO.File]::Open((Join-Path $directory 'controller.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
            catch { throw 'ACTIVE_CONTROLLER_OR_LOCK_UNCERTAIN' }
            try {
                Remove-Ci7LocalResources $state
                $job = Get-Ci7ExpectedJob $state.Configuration
                if ($state.JobId -and $job.id -ne $state.JobId) { throw 'INTERRUPTED_JOB_IDENTITY_CHANGED' }
                if ($job.status -ne 'completed') { Invoke-Ci7Api ('repos/' + $state.Configuration.Repository + '/actions/runs/' + $state.Configuration.WorkflowRunId + '/cancel') POST }
                Remove-Ci7Runner $state -Interrupted
                $lock.Dispose(); $lock = $null
                Clear-Ci7TransientState $state
                'INTERRUPTED_CLEANUP=PASS'
            } finally { if ($lock) { $lock.Dispose(); $lock = $null } }
        }
        # Prefix alone is never enough authority to destroy an orphan VM.
        $orphans = @(Get-VM | Where-Object { $_.Name -cmatch '^ci7-' })
        if ($orphans.Count) { throw 'ORPHAN_VM_REQUIRES_CONCLUSIVE_STATE' }
        exit 0
    }

    $configuration = New-Ci7Configuration -Repository $Repository -ApprovedRepositories $ApprovedRepositories -WorkflowRunId $WorkflowRunId -ExpectedSha $ExpectedSha -Root $Root -AllowPublicSyntheticProof:$AllowPublicSyntheticProof -MemoryMiB $MemoryMiB -CpuCount $CpuCount -TimeoutMinutes $TimeoutMinutes -WorkflowPath $WorkflowPath -TargetJob $TargetJob -ExpectedEvent $ExpectedEvent -Attempt $Attempt
    Assert-Ci7Capacity $configuration
    Assert-Ci7Base $Root
    $job = Get-Ci7ExpectedJob $configuration -RequireQueued
    if ($Mode -eq 'Plan') { 'PROVISIONING_PLAN=PASS'; exit 0 }
    Initialize-Ci7Root $Root
    $rootLock = Enter-Ci7ControllerLock $Root
    Assert-Ci7Capacity $configuration
    $job = Get-Ci7ExpectedJob $configuration -RequireQueued
    if (@(Get-VM | Where-Object { $_.Name -cmatch '^ci7-' }).Count -or @(Get-ChildItem -LiteralPath (Join-Path $Root 'runs') -Directory).Count) { throw 'STALE_RUN_MUST_BE_RECONCILED_FIRST' }
    $state = New-Ci7State $configuration
    $state.JobId = $job.id
    $state.PersistentBaseline = Get-Ci7PersistentBaseline $configuration
    [void](New-Item -ItemType Directory -Path $state.Directory)
    $lock = [IO.File]::Open((Join-Path $state.Directory 'controller.lock'), 'CreateNew', 'ReadWrite', 'None')
    Save-Ci7State $state
    Write-Ci7Evidence $state 'planned'
    try {
        $jit = Invoke-Ci7Api ('repos/' + $Repository + '/actions/runners/generate-jitconfig') POST @{
            name = $state.Name; runner_group_id = 1; labels = @(Get-Ci7Labels $WorkflowRunId); work_folder = '_work'
        }
        if ($jit.runner.name -cne $state.Name -or $jit.runner.id -le 0) { throw 'JIT_REGISTRATION_IDENTITY_AMBIGUOUS' }
        $state.RunnerId = [long]$jit.runner.id
        Save-Ci7State $state
        Move-Ci7Phase $state Registered
        Save-Ci7State $state
        Write-Ci7Evidence $state 'registered'
        Assert-Ci7JitContract $state $jit
        New-Ci7Seed $state $jit.encoded_jit_config
        $jit.encoded_jit_config = $null; $jit = $null
        New-Ci7Guest $state
        Move-Ci7Phase $state Provisioned; Save-Ci7State $state
        Write-Ci7Evidence $state 'provisioned'
        Start-VM -VM (Get-VM -Id $state.VMId -ErrorAction Stop) -ErrorAction Stop
        $diagnostics = [LDW.CiRunner.GuestDiagnostics]::new($state.Name)
        Move-Ci7Phase $state Running; Save-Ci7State $state
        Write-Ci7Evidence $state 'running'
        'SYNTHETIC_CONTROLLER_STARTED=YES'
        $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
        $lastProgress = [DateTime]::UtcNow
        do {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'BOUNDED_JOB_TIMEOUT' }
            foreach ($stage in $diagnostics.Poll()) {
                Write-Ci7GuestEvidence $state $stage; 'GUEST_BOOT_PHASE=' + $stage
                if ($stage -like '*FAILED') { throw 'BOOTSTRAP_FAILURE_REPORTED' }
            }
            $job = Get-Ci7ExpectedJob $configuration
            if ($job.id -ne $state.JobId -or ($job.runner_id -and $job.runner_id -ne $state.RunnerId)) { throw 'UNEXPECTED_JOB_ASSIGNMENT' }
            if ([DateTime]::UtcNow - $lastProgress -ge [TimeSpan]::FromSeconds(45)) { 'LIFECYCLE_WAIT=BOUNDED'; $lastProgress = [DateTime]::UtcNow }
            if ($job.status -ne 'completed') {
                $vm = Get-VM -Id $state.VMId -ErrorAction Stop
                Assert-Ci7OwnedVm $state $vm
                if ($vm.State -eq 'Off') {
                    foreach ($stage in $diagnostics.Poll()) { Write-Ci7GuestEvidence $state $stage; 'GUEST_BOOT_PHASE=' + $stage }
                    throw 'GUEST_STOPPED_BEFORE_JOB_COMPLETION'
                }
                Start-Sleep -Seconds 10
            }
        } while ($job.status -ne 'completed')
        if ($job.runner_id -ne $state.RunnerId -or $job.runner_name -cne $state.Name) { throw 'JOB_RUNNER_EVIDENCE_MISMATCH' }
        Move-Ci7Phase $state JobCompleted; Save-Ci7State $state
        Write-Ci7Evidence $state $(if ($job.conclusion -ceq 'success') { 'job-success' } else { 'job-failure' })
        Remove-Ci7Runner $state
        Move-Ci7Phase $state RunnerAbsent; Save-Ci7State $state
        Remove-Ci7LocalResources $state
        Move-Ci7Phase $state GuestRemoved
        Move-Ci7Phase $state ArtifactsRemoved; Save-Ci7State $state
        $lock.Dispose(); $lock = $null
        Clear-Ci7TransientState $state
        Move-Ci7Phase $state Complete
        $cleanupComplete = $true
        if ($job.conclusion -cne 'success') { throw 'INTENDED_JOB_FAILED' }
        'SYNTHETIC_EXACTLY_ONE_JOB=PASS'
        'SYNTHETIC_EXPECTED_LABELS=PASS'
        'SYNTHETIC_RUNNER_DEREGISTERED=PASS'
        'SYNTHETIC_GUEST_REMOVED=PASS'
        'SYNTHETIC_DISK_REMOVED=PASS'
        'SYNTHETIC_BOOTSTRAP_JIT_MATERIAL_REMOVED=PASS'
        'PERSISTENT_LDW01_CI_01_UNCHANGED=PASS'
    } catch {
        Write-Ci7Evidence $state 'failed'
        if (-not $cleanupComplete) {
            try {
                Remove-Ci7LocalResources $state
                $current = Get-Ci7ExpectedJob $configuration
                if ($current.status -ne 'completed') { Invoke-Ci7Api ('repos/' + $Repository + '/actions/runs/' + $WorkflowRunId + '/cancel') POST }
                Remove-Ci7Runner $state -Interrupted
                if ($lock) { $lock.Dispose(); $lock = $null }
                Clear-Ci7TransientState $state
                $cleanupComplete = $true
            } catch { Write-Ci7Evidence $state 'cleanup-failed'; throw 'CLEANUP_UNCERTAIN_MANIFEST_RETAINED' }
        }
        throw
    }
} catch {
    # No native exception text: it may include private paths or API response data.
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z0-9_]+$') { $code = 'CONTROLLER_OPERATION_FAILED' }
    'CONTROLLER_RESULT=FAIL'
    'CLASSIFICATION=' + $code
    exit 1
} finally { if ($diagnostics) { $diagnostics.Dispose() }; if ($lock) { $lock.Dispose() }; if ($rootLock) { $rootLock.Dispose() } }
