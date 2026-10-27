[CmdletBinding()]
param(
    [ValidateSet('Plan','Run','Cleanup','Reap')][string]$Mode = 'Plan',
    [string]$Repository = 'LowcountryDigitalWorks/business-operations',
    [string[]]$ApprovedRepositories = @('LowcountryDigitalWorks/business-operations', 'LowcountryDigitalWorks/royal-cruise-tracker'),
    [long]$WorkflowRunId, [string]$ExpectedSha,
    [string]$WorkflowPath, [string]$WorkflowBlobSha, [string]$ExpectedJobName, [string[]]$StaticLabels,
    [string]$ProfileId, [int]$RunAttempt, [long]$ExpectedJobId,
    [string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'),
    [string]$LocalRunId,
    [switch]$AllowPublicSyntheticProof,
    [int]$MemoryMiB = 2048, [int]$CpuCount = 2, [int]$TimeoutMinutes = 20
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force
$approvedList = @($ApprovedRepositories | ForEach-Object { $_ -split ',' })
$staticLabelsList = if ($StaticLabels) { @($StaticLabels | ForEach-Object { $_ -split ',' }) } else { $null }

$statusRoot = Join-Path $env:ProgramData 'LDW/CiJitStatus'
$statusPath = Join-Path $statusRoot 'status.json'
$statusLockPath = Join-Path $statusRoot 'status.lock'
$statusActivePhases = @('Planned','Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved')

function Get-Ci7StatusBootStartedUtc {
    [DateTimeOffset]::UtcNow.AddMilliseconds(-[Environment]::TickCount64).ToUniversalTime()
}

function Assert-Ci7StatusPath([string]$Path) {
    $root = [IO.Path]::GetFullPath($statusRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -cne $root -and -not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'STATUS_PATH_OUTSIDE_OWNED_ROOT'
    }
    $cursor = $full
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'STATUS_REPARSE_PATH_REFUSED'
        }
        if ($cursor -ceq $root) { break }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}

function Protect-Ci7StatusRoot {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        [void](New-Item -ItemType Directory -Path $statusRoot -Force)
        return
    }
    if (-not (Test-Path -LiteralPath $statusRoot)) {
        [void](New-Item -ItemType Directory -Path $statusRoot -Force)
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),
                'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $statusRoot -AclObject $acl
    }
    Assert-Ci7StatusPath $statusRoot
    $acl = Get-Acl -LiteralPath $statusRoot
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'STATUS_ROOT_OWNER_UNTRUSTED'
    }
    $write = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'STATUS_ROOT_UNTRUSTED_WRITE'
        }
    }
}

function Get-Ci7StatusDefault {
    [ordered]@{
        schema=1; source_version='ci-jit-v1'; boot_started_utc=(Get-Ci7StatusBootStartedUtc).ToString('O')
        local_observed_at_utc=[DateTimeOffset]::UtcNow.ToUniversalTime().ToString('O')
        provenance_valid=$false; proven_failure=$false; controller_phase=$null; capacity='UNKNOWN'; reason_code='LOCAL_STATE_UNAVAILABLE'
        queue_observed_at_utc=$null; queue_state='UNAVAILABLE'; eligible_queued_count=$null; held_queued_count=$null
        selected_profile=$null; selected_run_id=$null; selected_job_id=$null
    }
}

function Read-Ci7StatusUnsafe {
    if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) { return Get-Ci7StatusDefault }
    try { $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json }
    catch { return Get-Ci7StatusDefault }
    $required = @('schema','source_version','boot_started_utc','local_observed_at_utc','provenance_valid','proven_failure','controller_phase','capacity','reason_code','queue_observed_at_utc','queue_state','eligible_queued_count','held_queued_count','selected_profile','selected_run_id','selected_job_id')
    try { $sameBoot = (([DateTimeOffset]::Parse([string]$status.boot_started_utc).ToUniversalTime() - (Get-Ci7StatusBootStartedUtc)).Duration() -le [TimeSpan]::FromMinutes(2)) }
    catch { $sameBoot = $false }
    if ($status.schema -ne 1 -or $status.source_version -cne 'ci-jit-v1' -or
        @(Compare-Object $required @($status.PSObject.Properties.Name) -CaseSensitive).Count -or -not $sameBoot) {
        return Get-Ci7StatusDefault
    }
    $status
}

function Write-Ci7StatusUnsafe([object]$Status) {
    $temp = Join-Path $statusRoot ('status.' + [guid]::NewGuid().ToString('N') + '.pending')
    Assert-Ci7StatusPath $temp
    try {
        $Status | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temp -Encoding utf8NoBOM
        if (Test-Path -LiteralPath $statusPath) { [IO.File]::Replace($temp,$statusPath,$null,$true) }
        else { Move-Item -LiteralPath $temp -Destination $statusPath }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Test-Ci7PublishedBundle {
    try {
        $bundle = Split-Path $PSScriptRoot -Parent
        $manifestPath = Join-Path $bundle 'manifest.json'
        $dispatchPath = Join-Path $bundle 'ci-dispatch/Dispatch.psm1'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $dispatchPath -PathType Leaf)) { return $false }
        Import-Module $dispatchPath -Force
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $null = Assert-Ci10Bundle $bundle $manifestSha ([string]$manifest.commit) ([string]$manifest.tree)
        return $true
    } catch { return $false }
}

function Set-Ci7StatusPhase {
    param(
        [ValidateSet('Planned','Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved','Complete')][string]$Phase,
        [switch]$ProvenanceValid,
        [switch]$ProvenFailure,
        [ValidateSet('STALE_RESIDUE')][string]$FailureReason
    )
    Protect-Ci7StatusRoot
    Assert-Ci7StatusPath $statusLockPath
    $statusLock = $null
    try {
        $statusLock = [IO.File]::Open($statusLockPath,'OpenOrCreate','ReadWrite','None')
        $prior = Read-Ci7StatusUnsafe
        $next = [ordered]@{
            schema=1; source_version='ci-jit-v1'; boot_started_utc=(Get-Ci7StatusBootStartedUtc).ToString('O')
            local_observed_at_utc=[DateTimeOffset]::UtcNow.ToUniversalTime().ToString('O')
            provenance_valid=[bool]$ProvenanceValid; proven_failure=[bool]$ProvenFailure; controller_phase=$Phase
            capacity=if ($Phase -in $statusActivePhases) { 'BUSY' } else { 'READY' }
            reason_code=if ($ProvenFailure) { $FailureReason } elseif ($Phase -in $statusActivePhases) { 'BUSY' } else { $null }
            queue_observed_at_utc=$prior.queue_observed_at_utc; queue_state=$prior.queue_state
            eligible_queued_count=$prior.eligible_queued_count; held_queued_count=$prior.held_queued_count
            selected_profile=$prior.selected_profile; selected_run_id=$prior.selected_run_id; selected_job_id=$prior.selected_job_id
        }
        Write-Ci7StatusUnsafe $next
    } finally { if ($statusLock) { $statusLock.Dispose() } }
}

$state = $null
$lock = $null
$rootLock = $null
$diagnostics = $null
$cleanupComplete = $false
$statusProvenanceValid = Test-Ci7PublishedBundle
try {
    Assert-Ci7Elevated
    if ($Mode -in @('Cleanup','Reap')) {
        $rootLock = Enter-Ci7ControllerLock $Root
        if ($Mode -eq 'Cleanup' -and $LocalRunId -cnotmatch '^[0-9a-f]{32}$') { throw 'LOCAL_RUN_ID_REQUIRED' }
        if ($Mode -eq 'Cleanup' -and -not (Test-Path -LiteralPath (Join-Path $Root ('runs/' + $LocalRunId)))) {
            Assert-Ci7AlreadyClean $Root $LocalRunId $approvedList
            if ($statusProvenanceValid) { Set-Ci7StatusPhase Complete -ProvenanceValid }
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
            try { $lock = [IO.File]::Open((Join-Path $directory 'controller.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
            catch { throw 'ACTIVE_CONTROLLER_OR_LOCK_UNCERTAIN' }
            try {
                Remove-Ci7LocalResources $state
                $job = Get-Ci7CleanupJob $state
                if ($job.status -ne 'completed') { Invoke-Ci7Api ('repos/' + $state.Configuration.Repository + '/actions/runs/' + $state.Configuration.WorkflowRunId + '/cancel') POST }
                Remove-Ci7Runner $state -Interrupted
                $lock.Dispose(); $lock = $null
                Clear-Ci7TransientState $state
                'INTERRUPTED_CLEANUP=PASS'
            } finally { if ($lock) { $lock.Dispose(); $lock = $null } }
        }
        $orphans = @(Get-VM | Where-Object { $_.Name -cmatch '^ci7-' })
        if ($orphans.Count) { throw 'ORPHAN_VM_REQUIRES_CONCLUSIVE_STATE' }
        if ($statusProvenanceValid) { Set-Ci7StatusPhase Complete -ProvenanceValid }
        exit 0
    }

    $configuration = New-Ci7Configuration -Repository $Repository -ApprovedRepositories $approvedList -WorkflowRunId $WorkflowRunId -ExpectedSha $ExpectedSha -WorkflowPath $WorkflowPath -WorkflowBlobSha $WorkflowBlobSha -ExpectedJobName $ExpectedJobName -StaticLabels $staticLabelsList -ProfileId $ProfileId -RunAttempt $RunAttempt -ExpectedJobId $ExpectedJobId -Root $Root -AllowPublicSyntheticProof:$AllowPublicSyntheticProof -MemoryMiB $MemoryMiB -CpuCount $CpuCount -TimeoutMinutes $TimeoutMinutes
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
    if ($statusProvenanceValid) { Set-Ci7StatusPhase Planned -ProvenanceValid }
    try {
        $jit = Invoke-Ci7Api ('repos/' + $Repository + '/actions/runners/generate-jitconfig') POST @{
            name = $state.Name; runner_group_id = 1; labels = @(Get-Ci7Labels $WorkflowRunId $configuration); work_folder = '_work'
        }
        if ($jit.runner.name -cne $state.Name -or $jit.runner.id -le 0) { throw 'JIT_REGISTRATION_IDENTITY_AMBIGUOUS' }
        $state.RunnerId = [long]$jit.runner.id
        Save-Ci7State $state
        Move-Ci7Phase $state Registered
        Save-Ci7State $state
        Write-Ci7Evidence $state 'registered'
        if ($statusProvenanceValid) { Set-Ci7StatusPhase Registered -ProvenanceValid }
        Assert-Ci7JitContract $state $jit
        New-Ci7Seed $state $jit.encoded_jit_config
        $jit.encoded_jit_config = $null; $jit = $null
        New-Ci7Guest $state
        Move-Ci7Phase $state Provisioned; Save-Ci7State $state
        Write-Ci7Evidence $state 'provisioned'
        if ($statusProvenanceValid) { Set-Ci7StatusPhase Provisioned -ProvenanceValid }
        Start-VM -VM (Get-VM -Id $state.VMId -ErrorAction Stop) -ErrorAction Stop
        $diagnostics = [LDW.CiRunner.GuestDiagnostics]::new($state.Name)
        Move-Ci7Phase $state Running; Save-Ci7State $state
        Write-Ci7Evidence $state 'running'
        if ($statusProvenanceValid) { Set-Ci7StatusPhase Running -ProvenanceValid }
        'SYNTHETIC_CONTROLLER_STARTED=YES'
        $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
        $lastProgress = [DateTime]::UtcNow
        do {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'BOUNDED_JOB_TIMEOUT' }
            foreach ($stage in $diagnostics.Poll()) {
                Write-Ci7GuestEvidence $state $stage; 'GUEST_BOOT_PHASE=' + $stage
                if ($stage -like '*FAILED') { throw 'BOOTSTRAP_FAILURE_REPORTED' }
            }
            $job = Get-Ci7MonitoredJob $state
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
        if ($statusProvenanceValid) { Set-Ci7StatusPhase JobCompleted -ProvenanceValid }
        Remove-Ci7Runner $state
        Move-Ci7Phase $state RunnerAbsent; Save-Ci7State $state
        if ($statusProvenanceValid) { Set-Ci7StatusPhase RunnerAbsent -ProvenanceValid }
        Remove-Ci7LocalResources $state
        Move-Ci7Phase $state GuestRemoved
        if ($statusProvenanceValid) { Set-Ci7StatusPhase GuestRemoved -ProvenanceValid }
        Move-Ci7Phase $state ArtifactsRemoved; Save-Ci7State $state
        if ($statusProvenanceValid) { Set-Ci7StatusPhase ArtifactsRemoved -ProvenanceValid }
        $lock.Dispose(); $lock = $null
        Clear-Ci7TransientState $state
        Move-Ci7Phase $state Complete
        $cleanupComplete = $true
        if ($statusProvenanceValid) { Set-Ci7StatusPhase Complete -ProvenanceValid }
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
                $current = Get-Ci7CleanupJob $state
                if ($current.status -ne 'completed') { Invoke-Ci7Api ('repos/' + $Repository + '/actions/runs/' + $WorkflowRunId + '/cancel') POST }
                Remove-Ci7Runner $state -Interrupted
                if ($lock) { $lock.Dispose(); $lock = $null }
                Clear-Ci7TransientState $state
                $cleanupComplete = $true
                if ($statusProvenanceValid) { Set-Ci7StatusPhase Complete -ProvenanceValid }
            } catch {
                if ($statusProvenanceValid -and $state) {
                    $failurePhase = if ([string]$state.Phase -in $statusActivePhases) { [string]$state.Phase } else { 'ArtifactsRemoved' }
                    Set-Ci7StatusPhase $failurePhase -ProvenanceValid -ProvenFailure -FailureReason STALE_RESIDUE
                }
                Write-Ci7Evidence $state 'cleanup-failed'; throw 'CLEANUP_UNCERTAIN_MANIFEST_RETAINED'
            }
        }
        throw
    }
} catch {
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z0-9_]+$') { $code = 'CONTROLLER_OPERATION_FAILED' }
    'CONTROLLER_RESULT=FAIL'
    'CLASSIFICATION=' + $code
    exit 1
} finally { if ($diagnostics) { $diagnostics.Dispose() }; if ($lock) { $lock.Dispose() }; if ($rootLock) { $rootLock.Dispose() } }
