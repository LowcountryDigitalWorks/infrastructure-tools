Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:AcceptedControllerSnapshots = @(
    [pscustomobject]@{ commit='49f39f5d3a66251ed18c2e776d843feb25f65fe1'; tree='4d241fe9bc0fbf190daf2e36be0e9c52966c5a7b'; files=@{
        'ci-runner/CiRunner.psm1'='74d1b588a2280a2e8516bbd25465202ebbae155e29271fc3159be17dc9501770'
        'ci-runner/Invoke-IsolatedRunner.ps1'='cd7907f9f8584aa00dc81a39672f347795b58fceecec1ec170f179e9145c8d62'
        'ci-runner/Native.cs'='f5af15fdcd477574114885635870049b199f992a997f061057c547a98b407261'
        'ci-runner/guest/bootstrap.sh'='9eba5d80e12336fcb45841cb495260121197a69c0819508b46599b720bc58f55'
        'ci-runner/guest/ci7-runner.service'='3f87a4de95d07bcf75719b728240ffbb9471f64b4b5fab938184bfe46e653104'
        'ci-runner/guest/run-one.sh'='a6f69f5605aa2a78f42fb32234ff91a097bf1683b7a7ef6e5ec910625ec864b1'
    } },
    [pscustomobject]@{ commit='54b9343af44c70db1d1403cf7f45cfc11e8bf167'; tree='beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec'; files=@{
        'ci-runner/CiRunner.psm1'='023fc793634173463907594503965524ede16f2188050e711f5c284dca42ce66'
        'ci-runner/Invoke-IsolatedRunner.ps1'='b2c08d63865c8ac0801be3afb18fd8f5d1892927398838fadc132541361d06b4'
        'ci-runner/Native.cs'='f5af15fdcd477574114885635870049b199f992a997f061057c547a98b407261'
        'ci-runner/guest/bootstrap.sh'='9eba5d80e12336fcb45841cb495260121197a69c0819508b46599b720bc58f55'
        'ci-runner/guest/ci7-runner.service'='3f87a4de95d07bcf75719b728240ffbb9471f64b4b5fab938184bfe46e653104'
        'ci-runner/guest/run-one.sh'='a6f69f5605aa2a78f42fb32234ff91a097bf1683b7a7ef6e5ec910625ec864b1'
    } }
)
$script:RuntimeFiles = @(
    'ci-dispatch/Dispatch.psm1', 'ci-dispatch/Invoke-Dispatcher.ps1', 'ci-dispatch/profiles.json',
    'ci-dispatch/verifier-provenance.json', 'ci-dispatch/StatusProjection.psm1',
    'ci-runner/CiRunner.psm1', 'ci-runner/Invoke-IsolatedRunner.ps1', 'ci-runner/Native.cs',
    'ci-runner/guest/bootstrap.sh', 'ci-runner/guest/ci7-runner.service', 'ci-runner/guest/run-one.sh'
)

function Get-Ci10RuntimeFiles { @($script:RuntimeFiles) }
function Get-Ci10AcceptedControllerSnapshots { @($script:AcceptedControllerSnapshots) }

function Get-Ci10ManifestControllerSnapshot {
    param([Parameter(Mandatory)][object]$Manifest)
    $snapshot = @($script:AcceptedControllerSnapshots | Where-Object {
        $_.commit -ceq $Manifest.controllerCommit -and $_.tree -ceq $Manifest.controllerTree
    })
    if ($snapshot.Count -ne 1) { throw 'BUNDLE_PROVENANCE_MISMATCH' }
    $controllerPaths = @($script:RuntimeFiles | Where-Object { $_.StartsWith('ci-runner/') })
    if (@(Compare-Object $controllerPaths @($snapshot[0].files.Keys) -CaseSensitive).Count) {
        throw 'BUNDLE_CONTROLLER_SNAPSHOT_MISMATCH'
    }
    foreach ($path in $controllerPaths) {
        $entry = @($Manifest.files | Where-Object path -CEQ $path)
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cne $snapshot[0].files[$path]) {
            throw 'BUNDLE_CONTROLLER_SNAPSHOT_MISMATCH'
        }
    }
    $snapshot[0]
}

function Get-Ci10ManifestDispatcherProvenance {
    param([Parameter(Mandatory)][string]$BundleRoot, [Parameter(Mandatory)][object]$Manifest)
    $provenancePath = Join-Path $BundleRoot 'ci-dispatch/verifier-provenance.json'
    $dispatcherPath = Join-Path $BundleRoot 'ci-dispatch/Dispatch.psm1'
    if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) { throw 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH' }
    try { $accepted = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json }
    catch { throw 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH' }
    $dispatcherProperty = $Manifest.PSObject.Properties['dispatcher']
    $actual = if ($dispatcherProperty) { $dispatcherProperty.Value } else { $null }
    if (-not $actual -or $accepted.schema -ne 1 -or
        $accepted.commit -cnotmatch '^[a-f0-9]{40}$' -or $accepted.tree -cnotmatch '^[a-f0-9]{40}$' -or
        $accepted.blob -cnotmatch '^[a-f0-9]{40}$' -or $accepted.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $actual.commit -cne $accepted.commit -or $actual.tree -cne $accepted.tree -or
        $actual.blob -cne $accepted.blob -or $actual.sha256 -cne $accepted.sha256) {
        throw 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH'
    }
    $entry = @($Manifest.files | Where-Object path -CEQ 'ci-dispatch/Dispatch.psm1')
    if ($entry.Count -ne 1 -or $entry[0].sha256 -cne $accepted.sha256) { throw 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH' }
    if ((Get-FileHash -LiteralPath $dispatcherPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $accepted.sha256) {
        throw 'BUNDLE_VERIFIER_HASH_DRIFT'
    }
    [pscustomobject]@{ commit=$accepted.commit; tree=$accepted.tree; blob=$accepted.blob; sha256=$accepted.sha256 }
}

function Get-Ci10MatchedControllerSnapshot {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$ControllerRoot,
        [Parameter(Mandatory)][string[]]$ControllerFiles,
        [Parameter(Mandatory)][string]$StagingRoot
    )
    $matches = @()
    foreach ($snapshot in $script:AcceptedControllerSnapshots) {
        $actualTree = & git -C $RepositoryRoot rev-parse ($snapshot.commit + '^{tree}') 2>$null
        if ($LASTEXITCODE -ne 0 -or ([string]$actualTree).Trim() -cne $snapshot.tree) { throw 'ACCEPTED_CONTROLLER_UNAVAILABLE' }
        $snapshotRoot = Join-Path $StagingRoot ('controller-' + $snapshot.commit)
        $archive = Join-Path $StagingRoot ('controller-' + $snapshot.commit + '.zip')
        & git -C $RepositoryRoot archive --format=zip ('--output=' + $archive) $snapshot.commit -- @ControllerFiles 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'ACCEPTED_CONTROLLER_UNAVAILABLE' }
        $null = New-Item -ItemType Directory -Path $snapshotRoot
        [IO.Compression.ZipFile]::ExtractToDirectory($archive, $snapshotRoot)
        $same = $true
        foreach ($path in $ControllerFiles) {
            $candidate = Join-Path $ControllerRoot $path
            $accepted = Join-Path $snapshotRoot $path
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
                -not (Test-Path -LiteralPath $accepted -PathType Leaf) -or
                (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -cne
                    (Get-FileHash -LiteralPath $accepted -Algorithm SHA256).Hash) {
                $same = $false
                break
            }
        }
        if ($same) { $matches += $snapshot }
        Remove-Item -LiteralPath $snapshotRoot -Recurse -Force
        Remove-Item -LiteralPath $archive -Force
    }
    if ($matches.Count -eq 0) { throw 'ACCEPTED_CONTROLLER_CHANGED' }
    if ($matches.Count -ne 1) { throw 'ACCEPTED_CONTROLLER_MATCH_AMBIGUOUS' }
    $matches[0]
}

function Assert-Ci10ParentBoundary {
    param([string]$Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'BUNDLE_PARENT_OWNER_UNTRUSTED' }
    $replace = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $replace) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'BUNDLE_PARENT_REPLACEMENT_UNTRUSTED' }
    }
}

function Assert-Ci10ProtectedPath {
    param([string]$Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE_PATH_REFUSED' }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    $acl = Get-Acl -LiteralPath $full
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'BUNDLE_OWNER_UNTRUSTED'
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $write = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'BUNDLE_ACL_UNTRUSTED_WRITE' }
    }
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        if (-not @($rules | Where-Object { $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' -and
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl }).Count) {
            throw 'BUNDLE_ACL_REQUIRED_PRINCIPAL_MISSING'
        }
    }
}

function Assert-Ci10Bundle {
    param([string]$BundleRoot, [string]$ManifestSha, [string]$Commit, [string]$Tree)
    if ($ManifestSha -cnotmatch '^[a-f0-9]{64}$' -or $Commit -cnotmatch '^[a-f0-9]{40}$' -or $Tree -cnotmatch '^[a-f0-9]{40}$') {
        throw 'EXACT_BUNDLE_REFERENCE_REQUIRED'
    }
    Assert-Ci10ProtectedPath $BundleRoot
    # Validate the release parent as well: deleting/replacing a protected child must be impossible for an unelevated account.
    Assert-Ci10ProtectedPath ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($BundleRoot)))
    $releaseRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($BundleRoot)))
    Assert-Ci10ProtectedPath $releaseRoot
    $parent = [IO.Path]::GetDirectoryName($releaseRoot)
    Assert-Ci10ParentBoundary $parent
    Assert-Ci10ParentBoundary ([IO.Path]::GetDirectoryName($parent))
    $manifestPath = Join-Path $BundleRoot 'manifest.json'
    Assert-Ci10ProtectedPath $manifestPath
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha) { throw 'MANIFEST_HASH_DRIFT' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $acceptedSnapshot = Get-Ci10ManifestControllerSnapshot $manifest
    Assert-Ci10ProtectedPath (Join-Path $BundleRoot 'ci-dispatch/verifier-provenance.json')
    Assert-Ci10ProtectedPath (Join-Path $BundleRoot 'ci-dispatch/Dispatch.psm1')
    $acceptedDispatcher = Get-Ci10ManifestDispatcherProvenance -BundleRoot $BundleRoot -Manifest $manifest
    if ($manifest.schema -ne 1 -or $manifest.commit -cne $Commit -or $manifest.tree -cne $Tree -or
        -not $acceptedSnapshot -or -not $acceptedDispatcher) {
        throw 'BUNDLE_PROVENANCE_MISMATCH'
    }
    $expected = @($script:RuntimeFiles) + @('manifest.json')
    $actual = @(Get-ChildItem -LiteralPath $BundleRoot -Recurse -Force -File | ForEach-Object {
        [IO.Path]::GetRelativePath($BundleRoot, $_.FullName).Replace('\','/')
    })
    if ($actual.Count -ne $expected.Count -or @(Compare-Object $expected $actual -CaseSensitive).Count -or
        @($manifest.files).Count -ne $script:RuntimeFiles.Count -or
        @(Compare-Object $script:RuntimeFiles @($manifest.files.path) -CaseSensitive).Count) { throw 'BUNDLE_FILE_SET_DRIFT' }
    foreach ($directory in @(Get-ChildItem -LiteralPath $BundleRoot -Recurse -Force -Directory)) {
        Assert-Ci10ProtectedPath $directory.FullName
    }
    foreach ($entry in $manifest.files) {
        if ($entry.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'BUNDLE_MANIFEST_INVALID' }
        $file = Join-Path $BundleRoot $entry.path
        Assert-Ci10ProtectedPath $file
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'BUNDLE_FILE_HASH_DRIFT' }
    }
    $manifest
}

function Read-Ci10Profiles {
    param([string]$Path)
    $registry = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($registry.schema -ne 1 -or @($registry.profiles).Count -ne 4) { throw 'PROFILE_REGISTRY_REFUSED' }
    $profiles = @($registry.profiles)
    $required = @('id','repository','workflowPath','events','branch','headSha','workflowBlobSha','jobName','labels','dynamicLabel','jobCount',
        'cpu','memoryMiB','timeoutMinutes','docker','workflowSecrets','privateProductionState','egress','controllerProfile')
    foreach ($profile in $profiles) {
        if (@(Compare-Object $required @($profile.PSObject.Properties.Name) -CaseSensitive).Count -or
            $profile.dynamicLabel -cne 'ci7-run-<run-id>' -or $profile.jobCount -ne 1 -or $profile.cpu -ne 2 -or
            $profile.memoryMiB -ne 2048 -or $profile.timeoutMinutes -ne 20 -or
            $profile.docker -isnot [bool] -or $profile.docker -or $profile.workflowSecrets -isnot [bool] -or
            $profile.privateProductionState -isnot [bool] -or $profile.privateProductionState -or
            $profile.egress -cne 'accepted-ci7-public-ipv4-private-deny') { throw 'PROFILE_CONTRACT_REFUSED' }
        if ($profile.id -ceq 'ci10-royal-dashboard-deploy') {
            if (-not $profile.workflowSecrets) { throw 'PROFILE_CONTRACT_REFUSED' }
        } else {
            if ($profile.workflowSecrets) { throw 'PROFILE_CONTRACT_REFUSED' }
        }
        $labels = if ($profile.id -cin @('ci10-royal-dashboard-deploy','ci10-royal-dashboard-release-gate-pr')) {
            @('self-hosted','Linux','X64','ldw01','ldw-ephemeral','ldw-isolated','royal-isolated')
        } else {
            @('self-hosted','Linux','X64','ldw01','ldw-ephemeral','ldw-isolated','security-isolated')
        }
        if (@($profile.labels).Count -ne 7 -or @(Compare-Object $labels @($profile.labels) -CaseSensitive).Count) { throw 'PROFILE_LABELS_REFUSED' }
    }
    $synthetic = $profiles | Where-Object id -CEQ 'ci10-accepted-synthetic'
    $production = $profiles | Where-Object id -CEQ 'ci10-bo-secret-scan'
    $royal = $profiles | Where-Object id -CEQ 'ci10-royal-dashboard-deploy'
    $royalPr = $profiles | Where-Object id -CEQ 'ci10-royal-dashboard-release-gate-pr'
    if ($synthetic.Count -ne 1 -or $production.Count -ne 1 -or $royal.Count -ne 1 -or $royalPr.Count -ne 1 -or
        $synthetic.repository -cne 'LowcountryDigitalWorks/infrastructure-tools' -or
        $synthetic.workflowPath -cne '.github/workflows/ci-runner-isolation-proof.yml' -or
        @($synthetic.events).Count -ne 1 -or $synthetic.events[0] -cne 'push' -or
        $synthetic.branch -cne 'feat/ci-runner-ephemeral-001' -or
        $synthetic.headSha -cne '6bf0fc0de72c7cef3cea7c3c054ba2326fdbfe26' -or
        $synthetic.jobName -cne 'synthetic' -or $synthetic.controllerProfile -cne 'accepted-ci7-public-synthetic' -or
        $production.repository -cne 'LowcountryDigitalWorks/business-operations' -or
        $production.workflowPath -cne '.github/workflows/security-secrets.yml' -or
        @($production.events).Count -ne 2 -or
        @(Compare-Object @('pull_request','push') @($production.events) -CaseSensitive).Count -or
        $null -ne $production.branch -or $null -ne $production.headSha -or
        $production.jobName -cne 'secret-scan / secret-scan' -or
        $production.controllerProfile -cne 'accepted-ci7-private-secret-scan' -or
        $royal.repository -cne 'LowcountryDigitalWorks/royal-cruise-tracker' -or
        $royal.workflowPath -cne '.github/workflows/deploy-dashboard-pr379.yml' -or
        @($royal.events).Count -ne 1 -or $royal.events[0] -cne 'workflow_dispatch' -or
        $royal.branch -cne 'main' -or
        $null -ne $royal.headSha -or $null -ne $royal.workflowBlobSha -or
        $royal.jobName -cne 'Manual exact-SHA' -or
        -not $royal.workflowSecrets -or
        $royal.controllerProfile -cne 'accepted-ci7-royal-dashboard-deploy' -or
        $royalPr.repository -cne 'LowcountryDigitalWorks/royal-cruise-tracker' -or
        $royalPr.workflowPath -cne '.github/workflows/dashboard-release-gate.yml' -or
        @($royalPr.events).Count -ne 1 -or $royalPr.events[0] -cne 'pull_request' -or
        $null -ne $royalPr.branch -or $null -ne $royalPr.headSha -or $null -ne $royalPr.workflowBlobSha -or
        $royalPr.jobName -cne 'Zero-side-effect full repository release validation' -or
        $royalPr.workflowSecrets -or $royalPr.privateProductionState -or $royalPr.docker -or
        $royalPr.controllerProfile -cne 'accepted-ci7-royal-dashboard-release-gate-pr') { throw 'PROFILE_CONTRACT_REFUSED' }
    $profiles
}

function Invoke-Ci10Read {
    param([string]$Path)
    if ($Path -cnotmatch '^repos/LowcountryDigitalWorks/(infrastructure-tools|business-operations|royal-cruise-tracker)/(actions/(runs|workflows|runners)|contents(/|$))(/|\?|$)') { throw 'API_SCOPE_REFUSED' }
    $raw = & gh api --method GET $Path 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'API_READ_FAILED' }
    try { $raw | ConvertFrom-Json -DateKind String -ErrorAction Stop } catch { throw 'API_RESPONSE_INVALID' }
}

function Get-Ci10Candidate {
    param([object]$Profile, [object]$Run, [object]$Jobs,
        [string]$RoyalExpectedSha, [string]$RoyalWorkflowBlobSha)
    # API objects never enter the log. Noneligible jobs are not cancelled or modified.
    if ($Run.repository.full_name -cne $Profile.repository -or $Run.head_repository.full_name -cne $Profile.repository) { throw 'WRONG_REPOSITORY' }
    if ($Run.path -cne $Profile.workflowPath) { throw 'WRONG_WORKFLOW' }
    $expectedSha = $Profile.headSha
    $workflowBlobSha = $Profile.workflowBlobSha
    if ($Profile.id -ceq 'ci10-royal-dashboard-deploy') {
        if ($RoyalExpectedSha -cnotmatch '^[a-f0-9]{40}$') { throw 'FROZEN_ROYAL_HEAD_REQUIRED' }
        if ($RoyalWorkflowBlobSha -cnotmatch '^[a-f0-9]{40}$') { throw 'FROZEN_ROYAL_WORKFLOW_BLOB_REQUIRED' }
        if ($RoyalExpectedSha -ceq 'd77a0e01f42b7ecddd6bce0f7f226288dcc0b11e' -and
            $RoyalWorkflowBlobSha -ceq '3bfe9fec5fa4ebc10db17d41594ded8878b37064') { throw 'PRE_ROUTING_ROYAL_PAIR_REFUSED' }
        $expectedSha = $RoyalExpectedSha
        $workflowBlobSha = $RoyalWorkflowBlobSha
    }
    if ($Run.event -cnotin $Profile.events -or ($null -ne $Profile.branch -and $Run.head_branch -cne $Profile.branch) -or
        $Run.head_sha -notmatch '^[a-f0-9]{40}$' -or ($null -ne $expectedSha -and $Run.head_sha -cne $expectedSha)) { throw 'WRONG_EVENT_REF_SOURCE' }
    if ($Run.id -le 0 -or $Run.run_attempt -le 0 -or $Run.status -cne 'queued' -or $null -ne $Run.conclusion) { throw 'RUN_NOT_QUEUED' }
    if ($Jobs.total_count -ne 1 -or @($Jobs.jobs).Count -ne 1) { throw 'EXACTLY_ONE_JOB_REQUIRED' }
    $job = $Jobs.jobs[0]
    if ($job.id -le 0 -or $job.run_id -ne $Run.id -or $job.run_attempt -ne $Run.run_attempt -or
        $job.head_sha -cne $Run.head_sha -or $job.name -cne $Profile.jobName) { throw 'JOB_IDENTITY_MISMATCH' }
    # GitHub supplies started_at even on an unassigned queued job. Assignment is established by runner identity fields.
    if ($job.status -cne 'queued' -or $null -ne $job.conclusion -or $job.runner_id -or $job.runner_name -or $job.runner_group_id) { throw 'JOB_NOT_UNASSIGNED_QUEUED' }
    $labels = @($Profile.labels) + @('ci7-run-' + $Run.id)
    if (@($job.labels).Count -ne $labels.Count -or @(Compare-Object $labels @($job.labels) -CaseSensitive).Count) { throw 'WRONG_LABELS' }
    $created = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Run.created_at, [ref]$created)) { throw 'RUN_TIME_INVALID' }
    [pscustomobject]@{ Profile = $Profile; RunId = [long]$Run.id; Sha = $Run.head_sha; Attempt = [int]$Run.run_attempt;
        FrozenHeadSha = $expectedSha; FrozenWorkflowBlobSha = $workflowBlobSha;
        JobId = [long]$job.id; CreatedUtc = $created.UtcDateTime }
}

function Select-Ci10Oldest {
    param([object[]]$Candidates)
    if (@($Candidates | Group-Object RunId | Where-Object Count -ne 1).Count) { throw 'DUPLICATE_CANDIDATE_REFUSED' }
    @($Candidates | Sort-Object CreatedUtc, RunId, JobId | Select-Object -First 1)
}

function Get-QueueSnapshotCore {
    param([object[]]$Profiles, [string]$RoyalExpectedSha, [string]$RoyalWorkflowBlobSha)
    $acceptedProfiles = @(Read-Ci10Profiles (Join-Path $PSScriptRoot 'profiles.json'))
    if (@($Profiles).Count -lt 1 -or @($Profiles).Count -gt $acceptedProfiles.Count -or
        @($Profiles | Group-Object id | Where-Object Count -ne 1).Count) { throw 'PROFILE_SCOPE_REFUSED' }
    foreach ($profile in $Profiles) {
        $accepted = @($acceptedProfiles | Where-Object id -CEQ $profile.id)
        if ($accepted.Count -ne 1 -or
            ($accepted[0] | ConvertTo-Json -Depth 10 -Compress) -cne ($profile | ConvertTo-Json -Depth 10 -Compress)) {
            throw 'PROFILE_SCOPE_REFUSED'
        }
    }
    $candidates = [Collections.Generic.List[object]]::new()
    $heldReasons = [Collections.Generic.SortedDictionary[string,int]]::new([StringComparer]::Ordinal)
    $heldClass = @{
        WRONG_REPOSITORY='IDENTITY_MISMATCH'; WRONG_WORKFLOW='IDENTITY_MISMATCH'; WRONG_EVENT_REF_SOURCE='IDENTITY_MISMATCH'
        RUN_NOT_QUEUED='STATE_MISMATCH'; JOB_NOT_UNASSIGNED_QUEUED='STATE_MISMATCH'; JOB_IDENTITY_MISMATCH='STATE_MISMATCH'
        EXACTLY_ONE_JOB_REQUIRED='JOB_SHAPE'; WRONG_LABELS='CAPABILITY_MISMATCH'; RUN_TIME_INVALID='INVALID_METADATA'
        FROZEN_ROYAL_HEAD_REQUIRED='FROZEN_POLICY'; FROZEN_ROYAL_WORKFLOW_BLOB_REQUIRED='FROZEN_POLICY'
        PRE_ROUTING_ROYAL_PAIR_REFUSED='FROZEN_POLICY'
    }
    foreach ($profile in $Profiles) {
        $workflow = [Uri]::EscapeDataString([IO.Path]::GetFileName($profile.workflowPath))
        $seen = [Collections.Generic.HashSet[long]]::new()
        foreach ($event in @($profile.events)) {
            for ($page = 1; $page -le 3; $page++) {
                $query = 'status=queued&event=' + [Uri]::EscapeDataString($event)
                if ($null -ne $profile.branch) { $query += '&branch=' + [Uri]::EscapeDataString($profile.branch) }
                $response = Invoke-Ci10Read ('repos/' + $profile.repository + '/actions/workflows/' + $workflow +
                    '/runs?' + $query + '&per_page=100&page=' + $page)
            if ($response.total_count -gt 300) { throw 'QUEUE_BOUND_EXCEEDED' }
            foreach ($run in @($response.workflow_runs)) {
                if (-not $seen.Add([long]$run.id)) { throw 'QUEUE_PAGE_RACE_REFUSED' }
                $jobs = Invoke-Ci10Read ('repos/' + $profile.repository + '/actions/runs/' + $run.id + '/jobs?filter=latest&per_page=100')
                try { $candidate = Get-Ci10Candidate $profile $run $jobs $RoyalExpectedSha $RoyalWorkflowBlobSha; $candidates.Add($candidate) }
                catch {
                    $reason = $_.Exception.Message
                    if (-not $heldClass.ContainsKey($reason)) { throw }
                    $class = $heldClass[$reason]
                    if (-not $heldReasons.ContainsKey($class)) { $heldReasons[$class] = 0 }
                    $heldReasons[$class]++
                }
            }
            if (@($response.workflow_runs).Count -lt 100) { break }
            if ($page -eq 3) { throw 'QUEUE_BOUND_EXCEEDED' }
            }
        }
    }
    $selected = @(Select-Ci10Oldest @($candidates))
    [pscustomobject]@{
        Candidates = @($candidates)
        Selected = if ($selected.Count) { $selected[0] } else { $null }
        EligibleQueuedCount = $candidates.Count
        HeldQueuedCount = [int](($heldReasons.Values | Measure-Object -Sum).Sum)
        HeldReasonCounts = $heldReasons
    }
}

function Get-Ci10QueueSnapshot {
    param([object[]]$Profiles, [string]$RoyalExpectedSha, [string]$RoyalWorkflowBlobSha)
    try { $core = Get-QueueSnapshotCore $Profiles $RoyalExpectedSha $RoyalWorkflowBlobSha }
    catch {
        if ($_.Exception.Message -notin @('API_READ_FAILED','API_RESPONSE_INVALID')) { throw }
        return [pscustomobject]@{
            Schema='ci10-queue-v1'; QueueState='UNAVAILABLE'; EligibleQueuedCount=$null; HeldQueuedCount=$null
            HeldReasonCounts=@(); Selected=$null
        }
    }
    $selected = $core.Selected
    [pscustomobject]@{
        Schema='ci10-queue-v1'; QueueState='FRESH'; EligibleQueuedCount=[int]$core.EligibleQueuedCount
        HeldQueuedCount=[int]$core.HeldQueuedCount
        HeldReasonCounts=@($core.HeldReasonCounts.GetEnumerator() | ForEach-Object {
            [pscustomobject]@{ReasonCode=[string]$_.Key; Count=[int]$_.Value}
        })
        Selected=if ($null -eq $selected) { $null } else {
            [pscustomobject]@{ProfileId=[string]$selected.Profile.id; RunId=[long]$selected.RunId; JobId=[long]$selected.JobId}
        }
    }
}

function Find-Ci10QueuedJob {
    param([object[]]$Profiles, [string]$RoyalExpectedSha, [string]$RoyalWorkflowBlobSha)
    # Compatibility surface for the dispatcher: it consumes the same validated
    # queue snapshot core while retaining the rich trusted candidate internally.
    $snapshot = Get-QueueSnapshotCore $Profiles $RoyalExpectedSha $RoyalWorkflowBlobSha
    if ($null -eq $snapshot.Selected) { return }
    $snapshot.Selected
}

function Confirm-Ci10Candidate {
    param([object]$Selected)
    $base = 'repos/' + $Selected.Profile.repository + '/actions/runs/' + $Selected.RunId
    $current = Get-Ci10Candidate $Selected.Profile (Invoke-Ci10Read $base) (Invoke-Ci10Read ($base + '/jobs?filter=latest&per_page=100')) $Selected.FrozenHeadSha $Selected.FrozenWorkflowBlobSha
    if ($current.RunId -ne $Selected.RunId -or $current.Sha -cne $Selected.Sha -or $current.JobId -ne $Selected.JobId -or
        $current.Attempt -ne $Selected.Attempt -or $current.CreatedUtc -ne $Selected.CreatedUtc) { throw 'SELECTED_JOB_DRIFT' }
    $current
}

function Enter-Ci10DispatcherLock {
    param([string]$Root)
    Assert-Ci10ProtectedPath $Root
    try { [IO.File]::Open((Join-Path $Root 'dispatcher.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'DISPATCHER_BUSY_OR_LOCK_UNCERTAIN' }
}

function Get-Ci10ControllerGate {
    param([string]$ControllerRoot, [object]$Profile)
    $lock = $null
    try {
        try { $lock = Enter-Ci7ControllerLock $ControllerRoot }
        catch { if ($_.Exception.Message -ceq 'ANOTHER_CONTROLLER_ACTIVE_OR_LOCK_UNCERTAIN') { return 'BUSY' }; throw }
        $directories = @(Get-ChildItem -LiteralPath (Join-Path $ControllerRoot 'runs') -Directory -Force)
        $ownedNames = @()
        foreach ($directory in $directories) {
            Assert-Ci7Path $ControllerRoot $directory.FullName
            $state = Get-Content -LiteralPath (Join-Path $directory.FullName 'state.json') -Raw | ConvertFrom-Json
            Assert-Ci7State $state $ControllerRoot
            $matchesProfile = $state.Configuration.Repository -ceq $Profile.repository -and
                $state.Configuration.WorkflowPath -ceq $Profile.workflowPath
            $matchesKnownOther = ($state.Configuration.Repository -ceq 'LowcountryDigitalWorks/infrastructure-tools' -and
                $state.Configuration.WorkflowPath -ceq '.github/workflows/ci-runner-isolation-proof.yml') -or
                ($state.Configuration.Repository -ceq 'LowcountryDigitalWorks/business-operations' -and
                $state.Configuration.WorkflowPath -ceq '.github/workflows/security-secrets.yml') -or
                ($state.Configuration.Repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker' -and
                $state.Configuration.WorkflowPath -ceq '.github/workflows/deploy-dashboard-pr379.yml') -or
            ($Profile.id -ceq 'ci10-royal-dashboard-release-gate-pr' -and
                $state.Configuration.Repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker' -and
                $state.Configuration.WorkflowPath -ceq '.github/workflows/dashboard-release-gate.yml')
            if (-not $matchesProfile -and -not $matchesKnownOther) { throw 'STALE_PROFILE_OWNERSHIP_REFUSED' }
            if (-not $matchesProfile) {
                $otherRunLock = $null
                try { $otherRunLock = [IO.File]::Open((Join-Path $directory.FullName 'controller.lock'),'OpenOrCreate','ReadWrite','None') }
                catch { return 'BUSY' }
                finally { if ($otherRunLock) { $otherRunLock.Dispose() } }
                $otherVm = @(Get-VM | Where-Object { $_.Name -ceq $state.Name -or ($state.VMId -and [string]$_.VMId -ceq [string]$state.VMId) })
                if ($otherVm.Count -gt 1) { throw 'STALE_VM_OWNERSHIP_AMBIGUOUS' }
                if ($otherVm.Count -eq 1) { Assert-Ci7OwnedVm $state $otherVm[0] }
                $ownedNames += $state.Name
                continue
            }
            if ($directory.Name -cne $state.RunId -or $state.Configuration.Repository -cne $Profile.repository -or
                $state.Configuration.WorkflowPath -cne $Profile.workflowPath -or
                ($Profile.id -ceq 'ci10-accepted-synthetic' -and
                    ($state.Configuration.ExpectedSha -cne $Profile.headSha -or -not $state.Configuration.PublicSyntheticProof)) -or
                ($Profile.id -ceq 'ci10-bo-secret-scan' -and $state.Configuration.PublicSyntheticProof) -or
                ($Profile.id -cin @('ci10-royal-dashboard-deploy','ci10-royal-dashboard-release-gate-pr') -and $state.Configuration.PublicSyntheticProof)) { throw 'STALE_PROFILE_OWNERSHIP_REFUSED' }
            $runLock = $null
            try { $runLock = [IO.File]::Open((Join-Path $directory.FullName 'controller.lock'),'OpenOrCreate','ReadWrite','None') }
            catch { return 'BUSY' }
            finally { if ($runLock) { $runLock.Dispose() } }
            $vm = @(Get-VM | Where-Object { $_.Name -ceq $state.Name -or ($state.VMId -and [string]$_.VMId -ceq [string]$state.VMId) })
            if ($vm.Count -gt 1) { throw 'STALE_VM_OWNERSHIP_AMBIGUOUS' }
            if ($vm.Count -eq 1) { Assert-Ci7OwnedVm $state $vm[0] }
            $ownedNames += $state.Name
        }
        if (@(Get-VM | Where-Object { $_.Name -cmatch '^ci7-' -and $_.Name -cnotin $ownedNames }).Count) { throw 'ORPHAN_VM_REQUIRES_CONCLUSIVE_STATE' }
        if ($directories.Count) { return 'STALE' }
        $runners = Invoke-Ci10Read ('repos/' + $Profile.repository + '/actions/runners?per_page=100')
        if ($runners.total_count -gt 100 -or @($runners.runners | Where-Object name -cmatch '^ci7-').Count) { throw 'RUNNER_OWNERSHIP_UNCERTAIN' }
        $approved = @('LowcountryDigitalWorks/business-operations', 'LowcountryDigitalWorks/royal-cruise-tracker')
        # This check measures local capacity only; these placeholder refs never enter candidate verification or launch.
        $capacityBlobSha = if ($Profile.id -ceq 'ci10-royal-dashboard-deploy') { '0000000000000000000000000000000000000000' } else { $Profile.workflowBlobSha }
        $configuration = New-Ci7Configuration -Repository $Profile.repository -WorkflowRunId 1 -ExpectedSha ('0' * 40) -Root $ControllerRoot -ApprovedRepositories $approved -AllowPublicSyntheticProof:($Profile.id -ceq 'ci10-accepted-synthetic') -WorkflowPath $Profile.workflowPath -WorkflowBlobSha $capacityBlobSha -ExpectedJobName $Profile.jobName -StaticLabels $Profile.labels
        try { Assert-Ci7Capacity $configuration }
        catch { if ($_.Exception.Message -cmatch '^CAPACITY_' -or $_.Exception.Message -ceq 'DEFAULT_NAT_SWITCH_REQUIRED') { return 'CAPACITY' }; throw }
        'READY'
    } finally { if ($lock) { $lock.Dispose() } }
}

function Get-Ci10StaleRunIds {
    param([string]$ControllerRoot, [object]$Profile)
    $lock = Enter-Ci7ControllerLock $ControllerRoot
    try {
        foreach ($directory in @(Get-ChildItem -LiteralPath (Join-Path $ControllerRoot 'runs') -Directory -Force | Sort-Object Name)) {
            Assert-Ci7Path $ControllerRoot $directory.FullName
            $state = Get-Content -LiteralPath (Join-Path $directory.FullName 'state.json') -Raw | ConvertFrom-Json
            Assert-Ci7State $state $ControllerRoot
            if ($state.Configuration.Repository -cne $Profile.repository -or
                $state.Configuration.WorkflowPath -cne $Profile.workflowPath) {
                $knownOther = ($state.Configuration.Repository -ceq 'LowcountryDigitalWorks/infrastructure-tools' -and
                    $state.Configuration.WorkflowPath -ceq '.github/workflows/ci-runner-isolation-proof.yml') -or
                    ($state.Configuration.Repository -ceq 'LowcountryDigitalWorks/business-operations' -and
                    $state.Configuration.WorkflowPath -ceq '.github/workflows/security-secrets.yml') -or
                    ($state.Configuration.Repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker' -and
                    $state.Configuration.WorkflowPath -ceq '.github/workflows/deploy-dashboard-pr379.yml')
                if (-not $knownOther) { throw 'STALE_PROFILE_OWNERSHIP_REFUSED' }
                continue
            }
            if ($directory.Name -cne $state.RunId -or $state.Configuration.Repository -cne $Profile.repository -or
                $state.Configuration.WorkflowPath -cne $Profile.workflowPath -or
                ($Profile.id -ceq 'ci10-accepted-synthetic' -and
                    ($state.Configuration.ExpectedSha -cne $Profile.headSha -or -not $state.Configuration.PublicSyntheticProof)) -or
                ($Profile.id -ceq 'ci10-bo-secret-scan' -and $state.Configuration.PublicSyntheticProof) -or
                ($Profile.id -cin @('ci10-royal-dashboard-deploy','ci10-royal-dashboard-release-gate-pr') -and $state.Configuration.PublicSyntheticProof)) { throw 'STALE_PROFILE_OWNERSHIP_REFUSED' }
            $state.RunId
        }
    } finally { $lock.Dispose() }
}

function Write-Ci10Log {
    param([string]$Root, [ValidateSet('start','stop','poll-pass','poll-fail','busy','capacity','idle','selected','discovery-only',
        'controller-start','controller-pass','controller-fail','reap-pass','reap-fail')][string]$Classification,
        [ValidateSet('ci10-accepted-synthetic','ci10-bo-secret-scan','ci10-royal-dashboard-deploy','ci10-royal-dashboard-release-gate-pr')][string]$ProfileId = 'ci10-accepted-synthetic', [long]$RunId = 0)
    if ($RunId -lt 0) { throw 'LOG_RUN_ID_INVALID' }
    Assert-Ci10ProtectedPath $Root
    $file = Join-Path $Root 'dispatcher.jsonl'
    foreach ($candidate in @($file, ($file+'.1'), ($file+'.2'))) {
        if (Test-Path -LiteralPath $candidate) { Assert-Ci10ProtectedPath $candidate }
    }
    if ((Test-Path -LiteralPath $file) -and (Get-Item -LiteralPath $file).Length -ge 256KB) {
        if (Test-Path -LiteralPath ($file+'.2')) { Remove-Item -LiteralPath ($file+'.2') -Force }
        if (Test-Path -LiteralPath ($file+'.1')) { Move-Item -LiteralPath ($file+'.1') -Destination ($file+'.2') }
        Move-Item -LiteralPath $file -Destination ($file+'.1')
    }
    [ordered]@{ utc=[DateTime]::UtcNow.ToString('o'); phase=$Classification; profile=$ProfileId; run=$RunId } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath $file -Encoding utf8NoBOM
}

function Start-Ci10Controller {
    param([string]$BundleRoot, [string]$ControllerRoot, [object]$Candidate,
        [ValidatePattern('^[a-f0-9]{32}$')][string]$CleanupRunId)
    # A child survives dispatcher interruption. Never terminate it from dispatcher finally.
    # Controller owns its global/per-run locks, exact API checks, cleanup and sanitized evidence.
    $info = [Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    foreach ($arg in @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $BundleRoot 'ci-runner/Invoke-IsolatedRunner.ps1'),
        '-Mode',$(if ($CleanupRunId) { 'Cleanup' } else { 'Run' }),'-Root',$ControllerRoot)) { $info.ArgumentList.Add($arg) }
    if ($CleanupRunId) { $info.ArgumentList.Add('-LocalRunId'); $info.ArgumentList.Add($CleanupRunId) }
    else {
        $args = @('-Repository',$Candidate.Profile.repository,'-WorkflowRunId',[string]$Candidate.RunId,
            '-ExpectedSha',$(if ($Candidate.Profile.id -ceq 'ci10-royal-dashboard-deploy') { $Candidate.FrozenHeadSha } elseif ($Candidate.Profile.id -ceq 'ci10-royal-dashboard-release-gate-pr') { $Candidate.Sha } else { $Candidate.Sha }),'-MemoryMiB',[string]$Candidate.Profile.memoryMiB,
            '-CpuCount',[string]$Candidate.Profile.cpu,'-TimeoutMinutes',[string]$Candidate.Profile.timeoutMinutes)
        if ($Candidate.Profile.id -ceq 'ci10-accepted-synthetic') { $args += '-AllowPublicSyntheticProof' }
        else { $args += @('-ApprovedRepositories','LowcountryDigitalWorks/business-operations,LowcountryDigitalWorks/royal-cruise-tracker') }
        if ($Candidate.Profile.workflowPath) { $args += @('-WorkflowPath', $Candidate.Profile.workflowPath) }
        if ($Candidate.FrozenWorkflowBlobSha) { $args += @('-WorkflowBlobSha', $Candidate.FrozenWorkflowBlobSha) }
        if ($Candidate.Profile.jobName) { $args += @('-ExpectedJobName', $Candidate.Profile.jobName) }
        if ($Candidate.Profile.labels) { $args += @('-StaticLabels', ($Candidate.Profile.labels -join ',')) }
        foreach ($arg in $args) { $info.ArgumentList.Add($arg) }
    }
    $process = [Diagnostics.Process]::Start($info)
    # Drain streams asynchronously and discard every line; no raw diagnostics retained, even in memory buffers.
    $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null) | Out-Null
    $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null) | Out-Null
    try {
        while (-not $process.WaitForExit(1000)) { }
        if ($process.ExitCode -ne 0) { throw 'CONTROLLER_FAILED_OR_CLEANUP_UNCERTAIN' }
    } finally { $process.Dispose() }
}

Export-ModuleMember -Function *-Ci10*
