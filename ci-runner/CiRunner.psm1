Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:SafeLabels = @('self-hosted', 'Linux', 'X64', 'ldw01', 'ldw-ephemeral', 'ldw-isolated', 'security-isolated')
$script:Marker = 'CI-RUNNER-EPHEMERAL-001'

function Assert-Ci7Elevated {
    if ($env:OS -ne 'Windows_NT') { return }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ELEVATED_CONTROLLER_REQUIRED' }
}

function Assert-Ci7Path {
    param([string]$Root, [string]$Path)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($fullRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'PATH_OUTSIDE_OWNED_ROOT' }
    $cursor = $fullPath
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'REPARSE_PATH_REFUSED' }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Initialize-Ci7Root {
    param([string]$Root)
    # Dedicated storage only, never a drive root or an existing VM/workspace directory.
    if ([IO.Path]::GetFileName($Root.TrimEnd('\', '/')) -cne 'CiRunnerEphemeral') { throw 'DEDICATED_ROOT_REQUIRED' }
    Assert-Ci7Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Root))) $Root
    [void](New-Item -ItemType Directory -Path $Root -Force)
    if ($env:OS -eq 'Windows_NT') {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $Root -AclObject $acl
    }
    foreach ($child in @('runs', 'evidence')) { [void](New-Item -ItemType Directory -Path (Join-Path $Root $child) -Force) }
}

function Assert-Ci7Base {
    param([string]$Root)
    $base = Join-Path $Root 'base/ubuntu-noble-20260926.vhdx'
    $manifest = Join-Path $Root 'base/provenance.json'
    Assert-Ci7Path $Root $base
    Assert-Ci7Path $Root $manifest
    if (-not (Test-Path -LiteralPath $base) -or -not (Test-Path -LiteralPath $manifest)) { throw 'VERIFIED_BASE_REQUIRED' }
    $contract = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    if ($contract.Schema -ne 1 -or $contract.Release -cne 'noble-20260926' -or
        $contract.SourceSha256 -cne '6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2' -or
        $contract.BaseSha256 -notmatch '^[0-9a-f]{64}$' -or $contract.VirtualSize -lt 3GB -or $contract.VirtualSize -gt 16GB -or
        -not (Get-Item -LiteralPath $base).IsReadOnly) { throw 'BASE_CONTRACT_INVALID' }
    if ((Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant() -cne $contract.BaseSha256) { throw 'BASE_DISK_HASH_MISMATCH' }
    $info = Get-VHD -Path $base -ErrorAction Stop
    if ($info.VhdType -ne 'Dynamic' -or $info.ParentPath -or $info.Size -ne $contract.VirtualSize) { throw 'BASE_DISK_CONTRACT_MISMATCH' }
}

function Enter-Ci7ControllerLock {
    param([string]$Root)
    $path = Join-Path $Root 'control.lock'
    Assert-Ci7Path $Root $path
    try { [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'ANOTHER_CONTROLLER_ACTIVE_OR_LOCK_UNCERTAIN' }
}

function New-Ci7Configuration {
    param([string]$Repository, [long]$WorkflowRunId, [string]$ExpectedSha, [string]$Root,
        [string[]]$ApprovedRepositories = @('LowcountryDigitalWorks/business-operations', 'LowcountryDigitalWorks/royal-cruise-tracker'),
        [switch]$AllowPublicSyntheticProof, [int]$MemoryMiB = 2048, [int]$CpuCount = 2, [int]$TimeoutMinutes = 20,
        [string]$WorkflowPath, [string]$WorkflowBlobSha, [string]$ExpectedJobName, [string[]]$StaticLabels,
        [string]$ProfileId, [int]$RunAttempt = 0, [long]$ExpectedJobId = 0)
    if ($ExpectedSha -notmatch '^[0-9a-f]{40}$' -or $WorkflowRunId -le 0) { throw 'EXACT_JOB_REFERENCE_REQUIRED' }
    if ($MemoryMiB -lt 2048 -or $MemoryMiB -gt 4096 -or $CpuCount -lt 1 -or $CpuCount -gt 2 -or $TimeoutMinutes -lt 5 -or $TimeoutMinutes -gt 30) { throw 'RESOURCE_BOUNDS_INVALID' }
    $proof = $AllowPublicSyntheticProof -and $Repository -ceq 'LowcountryDigitalWorks/infrastructure-tools'
    if (-not $proof -and ($Repository -cnotin $ApprovedRepositories -or $Repository -cnotmatch '^LowcountryDigitalWorks/[a-z0-9-]+$')) { throw 'REPOSITORY_NOT_APPROVED' }
    if ($AllowPublicSyntheticProof -and -not $proof) { throw 'PUBLIC_PROOF_EXCEPTION_INVALID' }

    $resolvedWorkflowPath = if ($WorkflowPath) {
        $WorkflowPath
    } elseif ($proof) {
        '.github/workflows/ci-runner-isolation-proof.yml'
    } elseif ($Repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker') {
        '.github/workflows/deploy-dashboard-pr379.yml'
    } else {
        '.github/workflows/security-secrets.yml'
    }

    $profile = $null
    if ($Repository -ceq 'LowcountryDigitalWorks/wqt-operations') {
        $profiles = @(Get-Ci7ClosedProfiles)
        $profile = @($profiles | Where-Object ProfileId -CEQ $ProfileId)
        if ($profile.Count -ne 1) { throw 'WQT_CLOSED_PROFILE_REQUIRED' }
        $profile = $profile[0]
        if ($WorkflowPath -cne $profile.WorkflowPath -or $ExpectedJobName -cne $profile.JobName) { throw 'WQT_PROFILE_IDENTITY_REFUSED' }
        if ($RunAttempt -lt 1 -or $ExpectedJobId -lt 1 -or $WorkflowBlobSha -cnotmatch '^[a-f0-9]{40}$') { throw 'WQT_FROZEN_RUN_AND_WORKFLOW_REQUIRED' }
        $wqtLabels = @('self-hosted','Linux','X64','ldw01','ldw-ephemeral','ldw-isolated','security-isolated',$profile.RoutingLabel)
        if ($StaticLabels -and @(Compare-Object $wqtLabels @($StaticLabels) -CaseSensitive).Count) { throw 'WQT_STATIC_LABELS_REFUSED' }
        $resolvedStaticLabels = $wqtLabels
    } elseif ($ProfileId -or $RunAttempt -or $ExpectedJobId) { throw 'PROFILE_NOT_AUTHORIZED_FOR_REPOSITORY' }

    if ($Repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker') {
        $royalLabels = @('self-hosted', 'Linux', 'X64', 'ldw01', 'ldw-ephemeral', 'ldw-isolated', 'royal-isolated')
        if ($resolvedWorkflowPath -ceq '.github/workflows/deploy-dashboard-pr379.yml') {
            if ($WorkflowBlobSha -cnotmatch '^[a-f0-9]{40}$') { throw 'FROZEN_ROYAL_WORKFLOW_BLOB_REQUIRED' }
            if ($ExpectedJobName -cne 'Manual exact-SHA') { throw 'ROYAL_JOB_NAME_REFUSED' }
            if ($ExpectedSha -ceq 'd77a0e01f42b7ecddd6bce0f7f226288dcc0b11e' -and
                $WorkflowBlobSha -ceq '3bfe9fec5fa4ebc10db17d41594ded8878b37064') { throw 'PRE_ROUTING_ROYAL_PAIR_REFUSED' }
        } elseif ($resolvedWorkflowPath -ceq '.github/workflows/dashboard-release-gate.yml') {
            if ($WorkflowBlobSha) { throw 'ROYAL_PR_WORKFLOW_BLOB_PIN_REFUSED' }
            if ($ExpectedJobName -cne 'Zero-side-effect full repository release validation') { throw 'ROYAL_PR_JOB_NAME_REFUSED' }
        } else { throw 'ROYAL_WORKFLOW_PATH_INVALID' }
        if ($StaticLabels -and @(Compare-Object $royalLabels @($StaticLabels) -CaseSensitive).Count) { throw 'ROYAL_STATIC_LABELS_REFUSED' }
        $resolvedStaticLabels = $royalLabels
    } elseif (-not $profile) { $resolvedStaticLabels = if ($StaticLabels) { @($StaticLabels) } else { @($script:SafeLabels) } }
    [pscustomobject]@{ Repository = $Repository; WorkflowRunId = $WorkflowRunId; ExpectedSha = $ExpectedSha;
        Root = [IO.Path]::GetFullPath($Root); ApprovedRepositories = @($ApprovedRepositories); PublicSyntheticProof = [bool]$proof; MemoryMiB = $MemoryMiB; CpuCount = $CpuCount;
        TimeoutMinutes = $TimeoutMinutes; WorkflowPath = $resolvedWorkflowPath; WorkflowBlobSha = $WorkflowBlobSha; ExpectedJobName = $ExpectedJobName; StaticLabels = @($resolvedStaticLabels);
        ProfileId = if ($profile) { $profile.ProfileId } else { $null }; RunAttempt = $RunAttempt; ExpectedJobId = $ExpectedJobId; ProfileRoutingLabel = if ($profile) { $profile.RoutingLabel } else { $null };
        ReadPermissions = if ($profile) { @($profile.ReadPermissions) } else { @() }; WorkflowSecrets = if ($profile) { $profile.WorkflowSecrets } else { $false };
        PrivateProductionState = if ($profile) { $profile.PrivateProductionState } else { $false }; Docker = if ($profile) { $profile.Docker } else { $false } }
}

function Get-Ci7ClosedProfiles {
    @(
        [pscustomobject]@{ ProfileId='wqt-validation'; Repository='LowcountryDigitalWorks/wqt-operations'; WorkflowPath='.github/workflows/wqt.yml'; Event='pull_request'; JobName='validate-pr'; RoutingLabel='wqt-validation'; AllowedJobs=@('validate-pr','validate-hosted','scan'); ReadPermissions=@('contents:read'); WorkflowSecrets=$false; PrivateProductionState=$false; Docker=$false },
        [pscustomobject]@{ ProfileId='wqt-semantic-validate'; Repository='LowcountryDigitalWorks/wqt-operations'; WorkflowPath='.github/workflows/wqt-semantic-consumer.yml'; Event='pull_request'; JobName='validate-pr'; RoutingLabel='wqt-semantic-validate'; AllowedJobs=@('validate-pr','validate-hosted','retention-probe-pr','retention-probe-hosted','consume-real'); ReadPermissions=@('contents:read'); WorkflowSecrets=$false; PrivateProductionState=$false; Docker=$false },
        [pscustomobject]@{ ProfileId='wqt-semantic-retention-probe'; Repository='LowcountryDigitalWorks/wqt-operations'; WorkflowPath='.github/workflows/wqt-semantic-consumer.yml'; Event='pull_request'; JobName='retention-probe-pr'; RoutingLabel='wqt-semantic-retention-probe'; AllowedJobs=@('validate-pr','validate-hosted','retention-probe-pr','retention-probe-hosted','consume-real'); ReadPermissions=@('contents:read','actions:read'); WorkflowSecrets=$false; PrivateProductionState=$false; Docker=$false }
    )
}

function Get-Ci7Labels {
    param([long]$WorkflowRunId, [object]$Configuration)
    if ($WorkflowRunId -le 0) { throw 'WORKFLOW_RUN_ID_INVALID' }
    $static = if ($Configuration -and $Configuration.StaticLabels) {
        @($Configuration.StaticLabels)
    } else {
        @($script:SafeLabels)
    }
    @($static) + @('ci7-run-' + $WorkflowRunId)
}

function Get-Ci7JobField {
    param([object]$Job, [string]$Name)
    $property = $Job.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-Ci7JobUnassigned {
    param([object]$Job)
    $runnerId = Get-Ci7JobField $Job 'runner_id'
    $runnerName = Get-Ci7JobField $Job 'runner_name'
    $runnerGroupId = Get-Ci7JobField $Job 'runner_group_id'
    if ($null -ne $runnerId -and [string]$runnerId -notin @('', '0')) { return $false }
    if (-not [string]::IsNullOrEmpty([string]$runnerName)) { return $false }
    if ($null -ne $runnerGroupId -and [string]$runnerGroupId -notin @('', '0')) { return $false }
    return $true
}

function Invoke-Ci7Api {
    param([string]$Path, [ValidateSet('GET', 'POST', 'DELETE')][string]$Method = 'GET', [object]$Body)
    if ($Path -notmatch '^repos/LowcountryDigitalWorks/[a-z0-9-]+(/|$)') { throw 'API_TARGET_NOT_APPROVED' }
    $raw = if ($null -ne $Body) {
        $Body | ConvertTo-Json -Depth 12 -Compress | & gh api --method $Method $Path --input - 2>$null
    } else { & gh api --method $Method $Path 2>$null }
    if ($LASTEXITCODE -ne 0) { throw ('GITHUB_API_' + $Method + '_FAILED') }
    if ($Method -ne 'DELETE' -and $raw) { $raw | ConvertFrom-Json }
}

function Get-Ci7ExpectedJob {
    param([object]$Configuration, [switch]$RequireQueued)
    $repo = Invoke-Ci7Api ('repos/' + $Configuration.Repository)
    if (-not $repo.private -and -not $Configuration.PublicSyntheticProof) { throw 'PRIVATE_REPOSITORY_REQUIRED' }
    $run = Invoke-Ci7Api ('repos/' + $Configuration.Repository + '/actions/runs/' + $Configuration.WorkflowRunId)
    if ($run.head_sha -cne $Configuration.ExpectedSha -or $run.path -cne $Configuration.WorkflowPath -or
        $run.head_repository.full_name -cne $Configuration.Repository) { throw 'WORKFLOW_IDENTITY_MISMATCH' }

    if ($Configuration.ProfileId) {
        $profile = @((Get-Ci7ClosedProfiles) | Where-Object ProfileId -CEQ $Configuration.ProfileId)
        if ($profile.Count -ne 1) { throw 'WQT_CLOSED_PROFILE_REQUIRED' }
        $profile = $profile[0]
        if ($profile.Repository -cne $Configuration.Repository -or $profile.WorkflowPath -cne $Configuration.WorkflowPath -or
            $profile.JobName -cne $Configuration.ExpectedJobName -or $profile.RoutingLabel -cne $Configuration.ProfileRoutingLabel) { throw 'WQT_PROFILE_IDENTITY_REFUSED' }
        if ($run.id -ne $Configuration.WorkflowRunId -or $run.repository.full_name -cne $Configuration.Repository -or $run.event -cne 'pull_request' -or
            $run.run_attempt -ne $Configuration.RunAttempt -or $run.run_attempt -lt 1 -or
            @($run.pull_requests).Count -ne 1 -or $run.pull_requests[0].head.sha -cne $Configuration.ExpectedSha) { throw 'WQT_RUN_IDENTITY_MISMATCH' }
        if ($run.status -notin @('queued','in_progress') -or $null -ne $run.conclusion) { throw 'WQT_RUN_NOT_ACTIVE' }
        $blob = Invoke-Ci7Api ('repos/' + $Configuration.Repository + '/contents/' + $Configuration.WorkflowPath + '?ref=' + $Configuration.ExpectedSha)
        if ($blob.sha -cne $Configuration.WorkflowBlobSha) { throw 'WORKFLOW_BLOB_SHA_MISMATCH' }

        $allJobs = @()
        $expectedCount = $null
        for ($page = 1; $page -le 10; $page++) {
            $pageData = Invoke-Ci7Api ('repos/' + $Configuration.Repository + '/actions/runs/' + $Configuration.WorkflowRunId + '/jobs?filter=latest&per_page=100&page=' + $page)
            if ($null -eq $expectedCount) { $expectedCount = [int]$pageData.total_count }
            if ($pageData.total_count -ne $expectedCount) { throw 'WQT_JOB_GRAPH_CHANGED' }
            $allJobs += @($pageData.jobs)
            if ($allJobs.Count -ge $expectedCount) { break }
        }
        if ($null -eq $expectedCount -or $expectedCount -lt 1 -or $expectedCount -gt 1000 -or $allJobs.Count -ne $expectedCount) { throw 'WQT_JOB_GRAPH_INCOMPLETE' }
        $jobIds = @($allJobs | ForEach-Object { $_.id })
        if (@($jobIds | Where-Object { $_ -isnot [ValueType] -or $_ -le 0 }).Count -or @($jobIds | Sort-Object -Unique).Count -ne $jobIds.Count) { throw 'WQT_JOB_GRAPH_IDENTITY_INVALID' }
        if (@($allJobs | Where-Object { $_.name -cnotin $profile.AllowedJobs }).Count) { throw 'WQT_UNKNOWN_GRAPH_JOB' }
        $targets = @($allJobs | Where-Object { $_.name -ceq $profile.JobName })
        if ($targets.Count -ne 1) { throw 'WQT_TARGET_JOB_COUNT_MISMATCH' }
        $validateJobs = @($allJobs | Where-Object { $_.name -ceq 'validate-pr' })
        if ($validateJobs.Count -ne 1) { throw 'WQT_VALIDATE_JOB_COUNT_MISMATCH' }
        if ($Configuration.ProfileId -ceq 'wqt-semantic-validate' -and
            @($allJobs | Where-Object { $_.name -ceq 'retention-probe-pr' }).Count -ne 0) {
            # The Jobs API has no dependency-reason field. Until validation succeeds,
            # accept only the API representation where the `needs: validate-pr`
            # dependent job is not yet present. Any exposed non-target state (queued,
            # waiting, pending, requested, or otherwise) is ambiguous and fails closed.
            throw 'WQT_RETENTION_NOT_DEPENDENCY_BLOCKED'
        }
        foreach ($other in @($allJobs | Where-Object { $_.id -ne $targets[0].id })) {
            $isExactSkipped = $other.status -ceq 'completed' -and $other.conclusion -ceq 'skipped'
            $isExactValidationDependency = $Configuration.ProfileId -ceq 'wqt-semantic-retention-probe' -and $other.name -ceq 'validate-pr' -and
                $other.status -ceq 'completed' -and $other.conclusion -ceq 'success' -and
                $other.run_id -eq $run.id -and $other.run_attempt -eq $run.run_attempt -and $other.head_sha -ceq $Configuration.ExpectedSha
            if (-not ($isExactValidationDependency -or $isExactSkipped)) { throw 'WQT_NON_TARGET_JOB_RUNNABLE' }
        }
        $job = $targets[0]
        if ($job.id -ne $Configuration.ExpectedJobId -or $job.run_id -ne $run.id -or $job.run_attempt -ne $run.run_attempt -or $job.head_sha -cne $Configuration.ExpectedSha) { throw 'JOB_IDENTITY_MISMATCH' }
        $expectedLabels = @(Get-Ci7Labels $Configuration.WorkflowRunId $Configuration)
        if (@($job.labels).Count -ne $expectedLabels.Count -or @(Compare-Object $expectedLabels @($job.labels) -CaseSensitive).Count) { throw 'ISOLATED_JOB_LABELS_REQUIRED' }
        if ($Configuration.ProfileId -ceq 'wqt-semantic-retention-probe') {
            if ($validateJobs[0].status -cne 'completed' -or $validateJobs[0].conclusion -cne 'success' -or
                $validateJobs[0].run_id -ne $run.id -or $validateJobs[0].run_attempt -ne $run.run_attempt -or $validateJobs[0].head_sha -cne $Configuration.ExpectedSha) { throw 'WQT_RETENTION_DEPENDENCY_REQUIRED' }
        }
        if ($RequireQueued -and ($job.status -cne 'queued' -or -not (Test-Ci7JobUnassigned $job))) { throw 'UNASSIGNED_QUEUED_JOB_REQUIRED' }
        return $job
    }

    if ($Configuration.Repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker') {
        if ($run.repository.full_name -cne $Configuration.Repository) { throw 'ROYAL_REPOSITORY_REFUSED' }
        if ($Configuration.WorkflowPath -ceq '.github/workflows/deploy-dashboard-pr379.yml') {
            if ($run.event -cne 'workflow_dispatch') { throw 'ROYAL_EVENT_REFUSED' }
            if ($run.head_branch -cne 'main') { throw 'ROYAL_REF_REFUSED' }
            if ($run.id -ne $Configuration.WorkflowRunId -or $run.status -cne 'queued' -or $null -ne $run.conclusion -or $run.run_attempt -le 0) { throw 'ROYAL_RUN_NOT_QUEUED' }
            if ($Configuration.ExpectedSha -cnotmatch '^[a-f0-9]{40}$' -or $run.head_sha -cne $Configuration.ExpectedSha) { throw 'ROYAL_HEAD_SHA_REFUSED' }
            if ($Configuration.WorkflowBlobSha) {
                $blob = Invoke-Ci7Api ('repos/' + $Configuration.Repository + '/contents/' + $Configuration.WorkflowPath + '?ref=' + $run.head_sha)
                if ($blob.sha -cne $Configuration.WorkflowBlobSha) { throw 'WORKFLOW_BLOB_SHA_MISMATCH' }
            }
        } elseif ($Configuration.WorkflowPath -ceq '.github/workflows/dashboard-release-gate.yml') {
            if ($run.event -cne 'pull_request') { throw 'ROYAL_PR_EVENT_REFUSED' }
            if ($run.id -ne $Configuration.WorkflowRunId -or $run.status -cne 'queued' -or $null -ne $run.conclusion -or $run.run_attempt -le 0) { throw 'ROYAL_RUN_NOT_QUEUED' }
            if ($Configuration.ExpectedJobName -cne 'Zero-side-effect full repository release validation') { throw 'ROYAL_PR_JOB_NAME_REFUSED' }
        } else { throw 'ROYAL_WORKFLOW_PATH_INVALID' }
    } else {
        if ($run.event -cnotin @('push', 'pull_request', 'workflow_dispatch')) { throw 'WORKFLOW_IDENTITY_MISMATCH' }
    }

    if ($Configuration.PublicSyntheticProof -and ($run.head_branch -cne 'feat/ci-runner-ephemeral-001' -or $run.event -cne 'push')) { throw 'PUBLIC_PROOF_TRIGGER_REFUSED' }
    $response = Invoke-Ci7Api ('repos/' + $Configuration.Repository + '/actions/runs/' + $Configuration.WorkflowRunId + '/jobs?filter=latest&per_page=100')
    if ($response.total_count -ne 1 -or @($response.jobs).Count -ne 1) { throw 'EXACTLY_ONE_JOB_REQUIRED' }
    $job = $response.jobs[0]
    if ($Configuration.Repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker' -and
        ($job.name -cne $Configuration.ExpectedJobName -or $job.run_id -ne $Configuration.WorkflowRunId -or
         $job.run_attempt -ne $run.run_attempt -or $job.head_sha -cne $run.head_sha)) { throw 'JOB_IDENTITY_MISMATCH' }
    $expected = @(Get-Ci7Labels $Configuration.WorkflowRunId $Configuration)
    if (@($job.labels).Count -ne $expected.Count -or @(Compare-Object $expected @($job.labels) -CaseSensitive).Count -ne 0) { throw 'ISOLATED_JOB_LABELS_REQUIRED' }
    if ($RequireQueued -and ($job.status -cne 'queued' -or -not (Test-Ci7JobUnassigned $job))) { throw 'UNASSIGNED_QUEUED_JOB_REQUIRED' }
    $job
}

function Get-Ci7PersistedCleanupJob {
    param([object]$State)
    Assert-Ci7State $State $State.Configuration.Root
    $configuration = $State.Configuration
    if (-not $State.JobId -or [long]$State.JobId -le 0 -or $configuration.ExpectedJobId -ne $State.JobId -or
        [string]::IsNullOrWhiteSpace($configuration.ExpectedJobName) -or $configuration.WorkflowRunId -le 0 -or
        $configuration.RunAttempt -lt 1 -or $configuration.ExpectedSha -cnotmatch '^[a-f0-9]{40}$') { throw 'PERSISTED_JOB_IDENTITY_MISSING' }
    $job = Invoke-Ci7Api ('repos/' + $configuration.Repository + '/actions/jobs/' + $State.JobId)
    if ($job.id -ne $State.JobId -or $job.name -cne $configuration.ExpectedJobName -or
        $job.run_id -ne $configuration.WorkflowRunId -or $job.run_attempt -ne $configuration.RunAttempt -or
        $job.head_sha -cne $configuration.ExpectedSha) { throw 'PERSISTED_JOB_IDENTITY_MISMATCH' }
    return $job
}

function Get-Ci7CleanupJob {
    param([object]$State)
    if ($State.Configuration.ProfileId) { return Get-Ci7PersistedCleanupJob $State }
    $job = Get-Ci7ExpectedJob $State.Configuration
    if ($State.JobId -and $job.id -ne $State.JobId) { throw 'INTERRUPTED_JOB_IDENTITY_CHANGED' }
    return $job
}

function Assert-Ci7Capacity {
    param([object]$Configuration)
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor
    if ($os.FreePhysicalMemory * 1024 -lt ($Configuration.MemoryMiB * 1MB + 4GB)) { throw 'CAPACITY_RAM_RESERVE_4GIB_REQUIRED' }
    if (($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum -lt $Configuration.CpuCount + 2) { throw 'CAPACITY_CPU_RESERVE_REQUIRED' }
    if (($cpu | Measure-Object LoadPercentage -Average).Average -gt 70) { throw 'CAPACITY_CPU_LOAD_TOO_HIGH' }
    $driveRoot = [IO.Path]::GetPathRoot($Configuration.Root)
    $drive = [IO.DriveInfo]::new($driveRoot)
    if ($drive.AvailableFreeSpace -lt 40GB) { throw 'CAPACITY_DISK_RESERVE_40GIB_REQUIRED' }
    $switch = @(Get-VMSwitch | Where-Object { $_.Name -ceq 'Default Switch' -and $_.SwitchType -eq 'Internal' })
    if ($switch.Count -ne 1) { throw 'DEFAULT_NAT_SWITCH_REQUIRED' }
}

function New-Ci7State {
    param([object]$Configuration, [string]$RunId = ([guid]::NewGuid().ToString('N')))
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') { throw 'LOCAL_RUN_ID_INVALID' }
    $runDirectory = Join-Path $Configuration.Root ('runs/' + $RunId)
    [pscustomobject]@{ Schema = 1; Marker = $script:Marker; RunId = $RunId; Name = 'ci7-' + $RunId;
        Phase = 'Planned'; CreatedUtc = [DateTime]::UtcNow.ToString('o'); Configuration = $Configuration;
        Directory = $runDirectory; Disk = Join-Path $runDirectory 'disk.vhdx'; Seed = Join-Path $runDirectory 'seed.iso';
        VMId = $null; RunnerId = $null; JobId = $null; PersistentBaseline = $null }
}

function Assert-Ci7State {
    param([object]$State, [string]$Root)
    if ($State.Schema -ne 1 -or $State.Marker -cne $script:Marker -or $State.RunId -cnotmatch '^[0-9a-f]{32}$' -or
        $State.Name -cne ('ci7-' + $State.RunId) -or $State.Configuration.Root -cne [IO.Path]::GetFullPath($Root)) { throw 'RESOURCE_OWNERSHIP_AMBIGUOUS' }
    $expected = Join-Path ([IO.Path]::GetFullPath($Root)) ('runs/' + $State.RunId)
    foreach ($pair in @(@($State.Directory, $expected), @($State.Disk, (Join-Path $expected 'disk.vhdx')), @($State.Seed, (Join-Path $expected 'seed.iso')))) {
        if ([IO.Path]::GetFullPath($pair[0]) -cne [IO.Path]::GetFullPath($pair[1])) { throw 'RESOURCE_PATH_OWNERSHIP_MISMATCH' }
        Assert-Ci7Path $Root $pair[0]
    }
    if ($State.RunnerId -and [long]$State.RunnerId -le 0) { throw 'RUNNER_ID_INVALID' }
    if ($State.Configuration.PublicSyntheticProof) {
        if ($State.Configuration.Repository -cne 'LowcountryDigitalWorks/infrastructure-tools') { throw 'PUBLIC_PROOF_EXCEPTION_INVALID' }
    } elseif ($State.Configuration.Repository -cnotin $State.Configuration.ApprovedRepositories -or
        $State.Configuration.Repository -cnotmatch '^LowcountryDigitalWorks/[a-z0-9-]+$') { throw 'STALE_REPOSITORY_NOT_APPROVED' }
}

function Assert-Ci7OwnedVm {
    param([object]$State, [object]$VM)
    Assert-Ci7State $State $State.Configuration.Root
    if (-not $State.VMId -or [string]$VM.VMId -cne [string]$State.VMId -or $VM.Name -cne $State.Name -or
        $VM.Notes -cne ($script:Marker + ':' + $State.RunId)) { throw 'VM_NOT_CONCLUSIVELY_OWNED' }
}

function Save-Ci7State {
    param([object]$State)
    Assert-Ci7State $State $State.Configuration.Root
    $temp = Join-Path $State.Directory 'state.pending'
    $State | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temp -Encoding utf8NoBOM
    Move-Item -LiteralPath $temp -Destination (Join-Path $State.Directory 'state.json') -Force
}

function Write-Ci7Evidence {
    param([object]$State, [ValidateSet('planned','registered','provisioned','running','job-success','job-failure','runner-absent','guest-removed','artifacts-removed','complete','failed','cleanup-failed')][string]$Classification)
    Assert-Ci7State $State $State.Configuration.Root
    $file = Join-Path $State.Configuration.Root ('evidence/' + $State.RunId + '.jsonl')
    Assert-Ci7Path $State.Configuration.Root $file
    [ordered]@{ run = $State.RunId; phase = $Classification; utc = [DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath $file -Encoding utf8NoBOM
}

function Move-Ci7Phase {
    param([object]$State, [string]$Next)
    $order = @('Planned','Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved','Complete')
    $current = [array]::IndexOf($order, [string]$State.Phase)
    $target = [array]::IndexOf($order, $Next)
    if ($current -lt 0 -or $target -ne $current + 1) { throw 'ONE_JOB_LIFECYCLE_TRANSITION_REFUSED' }
    $State.Phase = $Next
}

function New-Ci7Seed {
    param([object]$State, [string]$Jit)
    Assert-Ci7State $State $State.Configuration.Root
    if ([string]::IsNullOrWhiteSpace($Jit) -or $Jit -notmatch '^[A-Za-z0-9+/=]+$') { throw 'JIT_MATERIAL_INVALID' }
    $seed = Join-Path $State.Directory 'seed'
    [void](New-Item -ItemType Directory -Path $seed)
    $files = @(
        @{ Path = '/run/ci7/jit'; Mode = '0600'; Data = $Jit },
        @{ Path = '/run/ci7/run-id'; Mode = '0444'; Data = $State.RunId },
        @{ Path = '/usr/local/lib/ci7/bootstrap.sh'; Mode = '0700'; Data = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'guest/bootstrap.sh')) },
        @{ Path = '/usr/local/lib/ci7/run-one.sh'; Mode = '0755'; Data = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'guest/run-one.sh')) },
        @{ Path = '/etc/systemd/system/ci7-runner.service'; Mode = '0644'; Data = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'guest/ci7-runner.service')) }
    )
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($line in @('#cloud-config','users:','  - name: ldw-runner','    lock_passwd: true','    shell: /bin/bash','    sudo: false','    groups: []','ssh_pwauth: false','disable_root: true','write_files:')) { $lines.Add($line) }
    foreach ($file in $files) {
        $lines.Add('  - path: ' + $file.Path); $lines.Add("    permissions: '" + $file.Mode + "'"); $lines.Add('    encoding: b64')
        $lines.Add('    content: ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($file.Data.Replace("`r`n", "`n"))))
    }
    $lines.Add('runcmd:'); $lines.Add('  - [bash, /usr/local/lib/ci7/bootstrap.sh]')
    [IO.File]::WriteAllText((Join-Path $seed 'user-data'), ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $seed 'meta-data'), ('instance-id: ' + $State.Name + "`nlocal-hostname: ci7-guest`n"), [Text.UTF8Encoding]::new($false))
    if (-not ('LDW.CiRunner.Native' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'Native.cs') }
    $iso = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    try {
        $iso.FileSystemsToCreate = 3; $iso.VolumeName = 'cidata'
        $iso.Root.AddTree($seed, $false)
        $image = $iso.CreateResultImage()
        [LDW.CiRunner.Native]::SaveIso($image.ImageStream, $State.Seed)
    } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($iso) }
    Remove-Item -LiteralPath (Join-Path $seed 'user-data'), (Join-Path $seed 'meta-data')
    Remove-Item -LiteralPath $seed
}

function Assert-Ci7JitContract {
    param([object]$State, [object]$Jit)
    # Inspect only in memory. Never emit or persist the decoded registration files.
    try {
        $files = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Jit.encoded_jit_config)) | ConvertFrom-Json
        $settings = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($files.'.runner')) | ConvertFrom-Json
        if ($settings.agentName -cne $State.Name -or $settings.agentId -ne $State.RunnerId -or
            $settings.gitHubUrl.TrimEnd('/') -cne ('https://github.com/' + $State.Configuration.Repository) -or
            -not $settings.ephemeral -or -not $settings.disableUpdate) { throw 'JIT_ONE_JOB_PINNING_CONTRACT_INVALID' }
    } catch { throw 'JIT_ONE_JOB_PINNING_CONTRACT_INVALID' }
}

function Get-Ci7PersistentBaseline {
    param([object]$Configuration)
    # Keep the reference baseline local and protected; never output fingerprints.
    $all = Invoke-Ci7Api 'repos/LowcountryDigitalWorks/business-operations/actions/runners?per_page=100'
    $persistent = @($all.runners | Where-Object name -CEQ 'ldw01-ci-01')
    if ($persistent.Count -ne 1 -or $persistent[0].status -cne 'online') { throw 'PERSISTENT_RUNNER_BASELINE_UNAVAILABLE' }
    $vms = @(Get-VM)
    $summary = @($vms | Sort-Object VMId | ForEach-Object {
        @{ Id = [string]$_.VMId; Name = $_.Name; Cpu = $_.ProcessorCount; Startup = $_.MemoryStartup;
            Dynamic = $_.DynamicMemoryEnabled; State = [string]$_.State;
            Disks = @(Get-VMHardDiskDrive -VM $_ | Select-Object ControllerType,ControllerNumber,ControllerLocation,Path);
            Network = @(Get-VMNetworkAdapter -VM $_ | Select-Object SwitchId,MacAddress) }
    })
    [pscustomobject]@{ Runner = ($persistent[0] | Select-Object id,name,os,labels | ConvertTo-Json -Depth 6 -Compress);
        VMs = ($summary | ConvertTo-Json -Depth 8 -Compress) }
}

function Assert-Ci7PersistentUnchanged {
    param([object]$State)
    $current = Get-Ci7PersistentBaseline $State.Configuration
    if (-not (Test-Ci7EquivalentData ($current.Runner | ConvertFrom-Json -AsHashtable) ($State.PersistentBaseline.Runner | ConvertFrom-Json -AsHashtable)) -or
        -not (Test-Ci7EquivalentData ($current.VMs | ConvertFrom-Json -AsHashtable) ($State.PersistentBaseline.VMs | ConvertFrom-Json -AsHashtable))) { throw 'PERSISTENT_REFERENCE_CHANGED' }
}

function Test-Ci7EquivalentData {
    param($Left, $Right)
    # JSON object key ordering is not a configuration change, especially after
    # recovery in another PowerShell process. Array ordering remains significant.
    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    if ($Left -is [Collections.IDictionary]) {
        if ($Right -isnot [Collections.IDictionary] -or $Left.Count -ne $Right.Count) { return $false }
        foreach ($key in $Left.Keys) { if (-not $Right.Contains($key) -or -not (Test-Ci7EquivalentData $Left[$key] $Right[$key])) { return $false } }
        return $true
    }
    if ($Left -is [Collections.IList]) {
        if ($Right -isnot [Collections.IList] -or $Left.Count -ne $Right.Count) { return $false }
        for ($index = 0; $index -lt $Left.Count; $index++) { if (-not (Test-Ci7EquivalentData $Left[$index] $Right[$index])) { return $false } }
        return $true
    }
    return ($Left -ceq $Right)
}

function New-Ci7Guest {
    param([object]$State)
    Assert-Ci7State $State $State.Configuration.Root
    Assert-Ci7Capacity $State.Configuration
    Assert-Ci7Base $State.Configuration.Root
    if (@(Get-VM | Where-Object Name -CEQ $State.Name).Count) { throw 'FRESH_VM_NAME_REQUIRED' }
    New-VHD -Path $State.Disk -ParentPath (Join-Path $State.Configuration.Root 'base/ubuntu-noble-20260926.vhdx') -Differencing -ErrorAction Stop | Out-Null
    $vm = New-VM -Name $State.Name -Path (Join-Path $State.Directory 'vm') -Generation 2 -MemoryStartupBytes ($State.Configuration.MemoryMiB * 1MB) -VHDPath $State.Disk -SwitchName 'Default Switch' -ErrorAction Stop
    $State.VMId = [string]$vm.VMId
    Save-Ci7State $State
    Set-VM -VM $vm -Notes ($script:Marker + ':' + $State.RunId) -AutomaticStartAction Nothing -AutomaticStopAction TurnOff -AutomaticCheckpointsEnabled $false -ErrorAction Stop
    Set-VMProcessor -VM $vm -Count $State.Configuration.CpuCount
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Get-VMIntegrationService -VM $vm | Where-Object Name -NE 'Heartbeat' | Disable-VMIntegrationService
    Add-VMDvdDrive -VM $vm -Path $State.Seed
    # Local named-pipe diagnostics is not an inbound network administration path.
    Set-VMComPort -VM $vm -Number 1 -Path ('\\.\pipe\' + $State.Name)
    Set-VMNetworkAdapter -VM $vm -MacAddressSpoofing Off -DhcpGuard Off -RouterGuard On
    $disk = @(Get-VMHardDiskDrive -VM $vm)
    if ($disk.Count -ne 1 -or $disk[0].Path -cne $State.Disk) { throw 'VM_DISK_BOUNDARY_INVALID' }
    Assert-Ci7OwnedVm $State (Get-VM -Id $State.VMId)
}

function Write-Ci7GuestEvidence {
    param([object]$State, [ValidateSet('BOOTSTRAP','NETWORK','DEPENDENCIES','FIREWALL','IDENTITY','DOWNLOAD','HASH','SERVICE','FAILED',
        'DOWNLOAD_DNS_FAILED','DOWNLOAD_CONNECT_FAILED','DOWNLOAD_HTTP_FAILED','DOWNLOAD_WRITE_FAILED','DOWNLOAD_TLS_FAILED','DOWNLOAD_OTHER_FAILED')][string]$Stage)
    Assert-Ci7State $State $State.Configuration.Root
    $file = Join-Path $State.Configuration.Root ('evidence/' + $State.RunId + '.jsonl')
    Assert-Ci7Path $State.Configuration.Root $file
    [ordered]@{ run = $State.RunId; phase = 'guest-' + $Stage.ToLowerInvariant(); utc = [DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath $file -Encoding utf8NoBOM
}

function Remove-Ci7LocalResources {
    param([object]$State)
    Assert-Ci7State $State $State.Configuration.Root
    $matches = @(Get-VM | Where-Object { $_.Name -ceq $State.Name -or ($State.VMId -and [string]$_.VMId -ceq $State.VMId) })
    if ($matches.Count -gt 1) { throw 'VM_OWNERSHIP_AMBIGUOUS' }
    if ($matches.Count -eq 1) {
        $vm = $matches[0]
        Assert-Ci7OwnedVm $State $vm
        $disk = @(Get-VMHardDiskDrive -VM $vm)
        if ($disk.Count -ne 1 -or $disk[0].Path -cne $State.Disk) { throw 'VM_ATTACHED_DISK_AMBIGUOUS' }
        $dvd = @(Get-VMDvdDrive -VM $vm)
        if ($dvd.Count -ne 1 -or $dvd[0].Path -cne $State.Seed) { throw 'VM_BOOTSTRAP_MEDIA_AMBIGUOUS' }
        if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force -Confirm:$false }
        Remove-VM -VM $vm -Force -Confirm:$false
        if (@(Get-VM | Where-Object { [string]$_.VMId -ceq $State.VMId -or $_.Name -ceq $State.Name }).Count) { throw 'VM_REMOVAL_UNCONFIRMED' }
    }
    Write-Ci7Evidence $State 'guest-removed'
    foreach ($file in @($State.Disk, $State.Seed)) {
        Assert-Ci7Path $State.Configuration.Root $file
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
        if (Test-Path -LiteralPath $file) { throw 'LOCAL_ARTIFACT_REMOVAL_UNCONFIRMED' }
    }
    Write-Ci7Evidence $State 'artifacts-removed'
}

function Remove-Ci7Runner {
    param([object]$State, [switch]$Interrupted)
    Assert-Ci7State $State $State.Configuration.Root
    $repo = $State.Configuration.Repository
    $all = Invoke-Ci7Api ('repos/' + $repo + '/actions/runners?per_page=100')
    if ($all.total_count -gt 100) { throw 'RUNNER_INVENTORY_TRUNCATED' }
    $matches = @($all.runners | Where-Object { $_.name -ceq $State.Name -or ($State.RunnerId -and $_.id -eq $State.RunnerId) })
    if ($matches.Count -gt 1) { throw 'RUNNER_OWNERSHIP_AMBIGUOUS' }
    if ($matches.Count -eq 1) {
        $runner = $matches[0]
        if (-not $State.RunnerId -or $runner.id -ne $State.RunnerId -or $runner.name -cne $State.Name -or $runner.name -ceq 'ldw01-ci-01') { throw 'RUNNER_NOT_CONCLUSIVELY_OWNED' }
        $expected = @(Get-Ci7Labels $State.Configuration.WorkflowRunId $State.Configuration)
        if (@($runner.labels.name).Count -ne $expected.Count -or @(Compare-Object $expected @($runner.labels.name) -CaseSensitive).Count) { throw 'RUNNER_LABEL_OWNERSHIP_AMBIGUOUS' }
        if ($runner.busy -and -not $Interrupted) { throw 'JOB_STILL_ACTIVE' }
        Invoke-Ci7Api ('repos/' + $repo + '/actions/runners/' + $State.RunnerId) DELETE
    }
    $check = Invoke-Ci7Api ('repos/' + $repo + '/actions/runners?per_page=100')
    if ($check.total_count -gt 100 -or @($check.runners | Where-Object { $_.name -ceq $State.Name -or ($State.RunnerId -and $_.id -eq $State.RunnerId) }).Count) { throw 'RUNNER_ABSENCE_UNCONFIRMED' }
    Write-Ci7Evidence $State 'runner-absent'
}

function Clear-Ci7TransientState {
    param([object]$State)
    Assert-Ci7State $State $State.Configuration.Root
    Assert-Ci7PersistentUnchanged $State
    if (Test-Path -LiteralPath $State.Directory) {
        $children = @(Get-ChildItem -LiteralPath $State.Directory -Force)
        if (@($children | Where-Object Name -CNotIn @('state.json','state.pending','controller.lock','seed','vm')).Count) { throw 'TRANSIENT_DIRECTORY_HAS_UNKNOWN_CONTENT' }
        $descendants = @(Get-ChildItem -LiteralPath $State.Directory -Recurse -Force)
        foreach ($child in $descendants) { Assert-Ci7Path $State.Configuration.Root $child.FullName }
        Remove-Item -LiteralPath $State.Directory -Recurse -Force
    }
    if (Test-Path -LiteralPath $State.Directory) { throw 'TRANSIENT_STATE_REMOVAL_UNCONFIRMED' }
    Write-Ci7Evidence $State 'complete'
}

function Assert-Ci7AlreadyClean {
    param([string]$Root, [string]$RunId, [string[]]$ApprovedRepositories = @('LowcountryDigitalWorks/business-operations', 'LowcountryDigitalWorks/royal-cruise-tracker'))
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') { throw 'LOCAL_RUN_ID_INVALID' }
    $directory = Join-Path $Root ('runs/' + $RunId)
    $log = Join-Path $Root ('evidence/' + $RunId + '.jsonl')
    Assert-Ci7Path $Root $directory; Assert-Ci7Path $Root $log
    if ((Test-Path -LiteralPath $directory) -or -not (Test-Path -LiteralPath $log)) { throw 'PRIOR_CLEANUP_NOT_CONFIRMED' }
    $last = Get-Content -LiteralPath $log | Select-Object -Last 1 | ConvertFrom-Json
    if ($last.run -cne $RunId -or $last.phase -cne 'complete') { throw 'PRIOR_CLEANUP_NOT_CONFIRMED' }
    $name = 'ci7-' + $RunId
    if (@(Get-VM | Where-Object Name -CEQ $name).Count) { throw 'VM_REAPPEARED_WITHOUT_CONCLUSIVE_STATE' }
    foreach ($repo in @(@($ApprovedRepositories) + @('LowcountryDigitalWorks/infrastructure-tools') | Sort-Object -Unique)) {
        if ($repo -cnotmatch '^LowcountryDigitalWorks/[a-z0-9-]+$') { throw 'REPOSITORY_NOT_APPROVED' }
        $all = Invoke-Ci7Api ('repos/' + $repo + '/actions/runners?per_page=100')
        if ($all.total_count -gt 100 -or @($all.runners | Where-Object name -CEQ $name).Count) { throw 'RUNNER_ABSENCE_UNCONFIRMED' }
    }
}

Export-ModuleMember -Function *-Ci7*
