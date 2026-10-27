Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:StatusSchema = 1
$script:StatusSourceVersion = 'ci-jit-v1'
$script:StatusRoot = Join-Path $env:ProgramData 'LDW/CiJitStatus'
$script:StatusPath = Join-Path $script:StatusRoot 'status.json'
$script:StatusLockPath = Join-Path $script:StatusRoot 'status.lock'
$script:ActivePhases = @('Planned','Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved')
$script:AllowedReasons = @(
    'BUSY','CAPACITY','LOCAL_STATE_STALE','LOCAL_STATE_UNAVAILABLE','MALFORMED_STATE',
    'MULTIPLE_ACTIVE_RUNS','OWNED_RESOURCE_CONTRADICTION','POLICY_HOLD','PROVENANCE_MISMATCH',
    'QUEUE_STALE','QUEUE_UNAVAILABLE','SOURCE_UNAVAILABLE','STALE_RESIDUE','UNKNOWN'
)

function Get-Ci10StatusProjectionPath { $script:StatusPath }

function Get-Ci10StatusBootStartedUtc {
    [DateTimeOffset]::UtcNow.AddMilliseconds(-[Environment]::TickCount64).ToUniversalTime()
}

function Assert-Ci10StatusProjectionPath {
    param([Parameter(Mandatory)][string]$Path)
    $root = [IO.Path]::GetFullPath($script:StatusRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
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

function Assert-Ci10StatusParentBoundary {
    param([Parameter(Mandatory)][string]$Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw 'STATUS_PARENT_REQUIRED' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'STATUS_PARENT_OWNER_UNTRUSTED'
    }
    $replace = [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $replace) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'STATUS_PARENT_REPLACEMENT_UNTRUSTED'
        }
    }
}

function Protect-Ci10StatusRoot {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $null = New-Item -ItemType Directory -Path $script:StatusRoot -Force
        return
    }
    $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($script:StatusRoot))
    Assert-Ci10StatusParentBoundary $parent
    if (-not (Test-Path -LiteralPath $script:StatusRoot)) {
        $null = New-Item -ItemType Directory -Path $script:StatusRoot -Force
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),
                'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $script:StatusRoot -AclObject $acl
    }
    Assert-Ci10StatusProjectionPath $script:StatusRoot
    $acl = Get-Acl -LiteralPath $script:StatusRoot
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
    Assert-Ci10StatusParentBoundary $parent
}
function Set-Ci10StatusReaderAcl {
    param([Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')][string]$ReaderSid)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'STATUS_READER_ACL_WINDOWS_ONLY' }
    Protect-Ci10StatusRoot
    $acl = Get-Acl -LiteralPath $script:StatusRoot
    $sid = [Security.Principal.SecurityIdentifier]::new($ReaderSid)
    foreach ($existing in @($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference.Value -eq $ReaderSid
    })) {
        $null = $acl.RemoveAccessRuleSpecific($existing)
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize,
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $script:StatusRoot -AclObject $acl
    Protect-Ci10StatusRoot
}

function New-Ci10StatusProjectionDefault {
    $boot = Get-Ci10StatusBootStartedUtc
    [ordered]@{
        schema = $script:StatusSchema
        source_version = $script:StatusSourceVersion
        boot_started_utc = $boot.ToString('O')
        local_observed_at_utc = [DateTimeOffset]::UtcNow.ToUniversalTime().ToString('O')
        provenance_valid = $false
        proven_failure = $false
        controller_phase = $null
        capacity = 'UNKNOWN'
        reason_code = 'LOCAL_STATE_UNAVAILABLE'
        queue_observed_at_utc = $null
        queue_state = 'UNAVAILABLE'
        eligible_queued_count = $null
        held_queued_count = $null
        selected_profile = $null
        selected_run_id = $null
        selected_job_id = $null
    }
}

function Test-Ci10StatusSameBoot {
    param([object]$Status)
    try {
        $stored = [DateTimeOffset]::Parse([string]$Status.boot_started_utc).ToUniversalTime()
        $current = Get-Ci10StatusBootStartedUtc
        return (($stored - $current).Duration() -le [TimeSpan]::FromMinutes(2))
    } catch { return $false }
}

function Read-Ci10StatusProjectionUnsafe {
    if (-not (Test-Path -LiteralPath $script:StatusPath -PathType Leaf)) { return New-Ci10StatusProjectionDefault }
    Assert-Ci10StatusProjectionPath $script:StatusPath
    try { $status = Get-Content -LiteralPath $script:StatusPath -Raw | ConvertFrom-Json }
    catch { return New-Ci10StatusProjectionDefault }
    $required = @(
        'schema','source_version','boot_started_utc','local_observed_at_utc','provenance_valid','proven_failure',
        'controller_phase','capacity','reason_code','queue_observed_at_utc','queue_state','eligible_queued_count',
        'held_queued_count','selected_profile','selected_run_id','selected_job_id'
    )
    if ($status.schema -ne $script:StatusSchema -or $status.source_version -cne $script:StatusSourceVersion -or
        @(Compare-Object $required @($status.PSObject.Properties.Name) -CaseSensitive).Count -or -not (Test-Ci10StatusSameBoot $status)) {
        return New-Ci10StatusProjectionDefault
    }
    $status
}

function Enter-Ci10StatusProjectionLock {
    Protect-Ci10StatusRoot
    Assert-Ci10StatusProjectionPath $script:StatusLockPath
    try { [IO.File]::Open($script:StatusLockPath,'OpenOrCreate','ReadWrite','None') }
    catch { throw 'STATUS_PROJECTION_LOCK_UNAVAILABLE' }
}

function Write-Ci10StatusProjectionUnsafe {
    param([Parameter(Mandatory)][object]$Status)
    $required = @(
        'schema','source_version','boot_started_utc','local_observed_at_utc','provenance_valid','proven_failure',
        'controller_phase','capacity','reason_code','queue_observed_at_utc','queue_state','eligible_queued_count',
        'held_queued_count','selected_profile','selected_run_id','selected_job_id'
    )
    if ($Status.schema -ne $script:StatusSchema -or $Status.source_version -cne $script:StatusSourceVersion -or
        @(Compare-Object $required @($Status.Keys) -CaseSensitive).Count) { throw 'STATUS_PROJECTION_SCHEMA_REFUSED' }
    if ($Status.capacity -cnotin @('READY','BUSY','CAPACITY','UNKNOWN')) { throw 'STATUS_CAPACITY_REFUSED' }
    if ($Status.queue_state -cnotin @('FRESH','UNAVAILABLE')) { throw 'STATUS_QUEUE_STATE_REFUSED' }
    if ($null -ne $Status.controller_phase -and $Status.controller_phase -cnotin @($script:ActivePhases + 'Complete')) { throw 'STATUS_PHASE_REFUSED' }
    if ($null -ne $Status.reason_code -and $Status.reason_code -cnotin $script:AllowedReasons) { throw 'STATUS_REASON_REFUSED' }
    if ($Status.queue_state -ceq 'FRESH') {
        if ($null -eq $Status.queue_observed_at_utc -or $null -eq $Status.eligible_queued_count -or $null -eq $Status.held_queued_count -or
            [int]$Status.eligible_queued_count -lt 0 -or [int]$Status.held_queued_count -lt 0) { throw 'STATUS_QUEUE_DETAIL_REFUSED' }
    } elseif ($null -ne $Status.queue_observed_at_utc -or $null -ne $Status.eligible_queued_count -or $null -ne $Status.held_queued_count -or
        $null -ne $Status.selected_profile -or $null -ne $Status.selected_run_id -or $null -ne $Status.selected_job_id) {
        throw 'STATUS_QUEUE_DETAIL_REFUSED'
    }
    $selected = @($Status.selected_profile,$Status.selected_run_id,$Status.selected_job_id | Where-Object { $null -ne $_ }).Count
    if ($selected -notin @(0,3)) { throw 'STATUS_SELECTED_IDENTITY_REFUSED' }
    if ($selected -eq 3 -and ([string]$Status.selected_profile -cnotmatch '^[a-z0-9._-]{1,64}$' -or
        [long]$Status.selected_run_id -le 0 -or [long]$Status.selected_job_id -le 0)) { throw 'STATUS_SELECTED_IDENTITY_REFUSED' }

    $temp = Join-Path $script:StatusRoot ('status.' + [guid]::NewGuid().ToString('N') + '.pending')
    Assert-Ci10StatusProjectionPath $temp
    try {
        $Status | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temp -Encoding utf8NoBOM
        if (Test-Path -LiteralPath $script:StatusPath) {
            [IO.File]::Replace($temp,$script:StatusPath,$null,$true)
        } else {
            Move-Item -LiteralPath $temp -Destination $script:StatusPath
        }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Set-Ci10StatusQueueProjection {
    param(
        [Parameter(Mandatory)][object]$QueueSnapshot,
        [ValidateSet('READY','BUSY','CAPACITY','UNKNOWN')][string]$Capacity,
        [ValidateSet('BUSY','CAPACITY','POLICY_HOLD','QUEUE_UNAVAILABLE','UNKNOWN')][string]$ReasonCode,
        [switch]$ProvenanceValid
    )
    if (-not $QueueSnapshot -or $QueueSnapshot.Schema -cne 'ci10-queue-v1' -or
        $QueueSnapshot.QueueState -cnotin @('FRESH','UNAVAILABLE')) { throw 'STATUS_QUEUE_SNAPSHOT_REFUSED' }
    $lock = Enter-Ci10StatusProjectionLock
    try {
        $prior = Read-Ci10StatusProjectionUnsafe
        $queueState = [string]$QueueSnapshot.QueueState
        $eligible = if ($queueState -ceq 'FRESH') { [int]$QueueSnapshot.EligibleQueuedCount } else { $null }
        $held = if ($queueState -ceq 'FRESH') { [int]$QueueSnapshot.HeldQueuedCount } else { $null }
        $selectedProfile = if ($queueState -ceq 'FRESH' -and $QueueSnapshot.Selected) { [string]$QueueSnapshot.Selected.ProfileId } else { $null }
        $selectedRunId = if ($queueState -ceq 'FRESH' -and $QueueSnapshot.Selected) { [long]$QueueSnapshot.Selected.RunId } else { $null }
        $selectedJobId = if ($queueState -ceq 'FRESH' -and $QueueSnapshot.Selected) { [long]$QueueSnapshot.Selected.JobId } else { $null }
        $activePhase = [string]$prior.controller_phase -in $script:ActivePhases
        $effectiveCapacity = if ($activePhase) { 'BUSY' } elseif ($Capacity -ceq 'BUSY') { 'UNKNOWN' } else { $Capacity }
        $hasQueuedWork = $queueState -ceq 'FRESH' -and (($eligible -gt 0) -or ($held -gt 0))
        if ($ReasonCode -eq 'POLICY_HOLD' -and -not $hasQueuedWork) { throw 'STATUS_REASON_REFUSED' }
        $effectiveReason = if ([bool]$prior.proven_failure) { [string]$prior.reason_code }
            elseif ($activePhase) { 'BUSY' }
            elseif ($queueState -ceq 'UNAVAILABLE') { 'QUEUE_UNAVAILABLE' }
            elseif ($effectiveCapacity -ceq 'CAPACITY' -and $hasQueuedWork) { 'CAPACITY' }
            elseif ($Capacity -ceq 'BUSY') { 'UNKNOWN' }
            elseif ($ReasonCode -eq 'POLICY_HOLD') { 'POLICY_HOLD' }
            elseif ($ReasonCode -eq 'UNKNOWN') { 'UNKNOWN' }
            else { $null }
        $status = [ordered]@{
            schema = $script:StatusSchema
            source_version = $script:StatusSourceVersion
            boot_started_utc = (Get-Ci10StatusBootStartedUtc).ToString('O')
            local_observed_at_utc = [DateTimeOffset]::UtcNow.ToUniversalTime().ToString('O')
            provenance_valid = [bool]$ProvenanceValid
            proven_failure = [bool]$prior.proven_failure
            controller_phase = $prior.controller_phase
            capacity = $effectiveCapacity
            reason_code = $effectiveReason
            queue_observed_at_utc = if ($queueState -ceq 'FRESH') { [DateTimeOffset]::UtcNow.ToUniversalTime().ToString('O') } else { $null }
            queue_state = $queueState
            eligible_queued_count = $eligible
            held_queued_count = $held
            selected_profile = $selectedProfile
            selected_run_id = $selectedRunId
            selected_job_id = $selectedJobId
        }
        Write-Ci10StatusProjectionUnsafe $status
    } finally { $lock.Dispose() }
}
function Set-Ci10StatusControllerPhase {
    param(
        [ValidateSet('Planned','Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved','Complete')][string]$Phase,
        [switch]$ProvenanceValid,
        [switch]$ProvenFailure,
        [ValidateSet('MULTIPLE_ACTIVE_RUNS','OWNED_RESOURCE_CONTRADICTION','STALE_RESIDUE')][string]$FailureReason
    )
    $lock = Enter-Ci10StatusProjectionLock
    try {
        $status = Read-Ci10StatusProjectionUnsafe
        $status = [ordered]@{
            schema = $script:StatusSchema
            source_version = $script:StatusSourceVersion
            boot_started_utc = (Get-Ci10StatusBootStartedUtc).ToString('O')
            local_observed_at_utc = [DateTimeOffset]::UtcNow.ToUniversalTime().ToString('O')
            provenance_valid = [bool]$ProvenanceValid
            proven_failure = [bool]$ProvenFailure
            controller_phase = $Phase
            capacity = if ($Phase -in $script:ActivePhases) { 'BUSY' } else { 'READY' }
            reason_code = if ($ProvenFailure) { $FailureReason } elseif ($Phase -in $script:ActivePhases) { 'BUSY' } else { $null }
            queue_observed_at_utc = $status.queue_observed_at_utc
            queue_state = $status.queue_state
            eligible_queued_count = $status.eligible_queued_count
            held_queued_count = $status.held_queued_count
            selected_profile = $status.selected_profile
            selected_run_id = $status.selected_run_id
            selected_job_id = $status.selected_job_id
        }
        Write-Ci10StatusProjectionUnsafe $status
    } finally { $lock.Dispose() }
}

Export-ModuleMember -Function *-Ci10Status*
