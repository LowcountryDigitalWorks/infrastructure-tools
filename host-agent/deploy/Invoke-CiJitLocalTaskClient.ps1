[CmdletBinding()]
param(
    [ValidateSet('STATUS','DISCOVER','RUN_ONCE','RECOVER','ABORT_ACTIVE','LIST_STALE','RETIRE_STALE','GET_OPERATION_RESULT')]
    [string]$Operation,
    [long]$RunId = 0,
    [guid]$OperationId = [guid]::Empty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ControlRoot = Join-Path $env:ProgramData 'LDW/CiJitControl'
$script:RequestRoot = Join-Path $script:ControlRoot 'requests'
$script:ResultRoot = Join-Path $script:ControlRoot 'results'
$script:StatusPath = Join-Path $env:ProgramData 'LDW/CiJitStatus/status.json'
$script:MaximumEnvelopeBytes = 16384
$script:MaximumStatusBytes = 65536
$script:TaskNames = @{
    DISCOVER='\LDW-CI-JIT-DISCOVER'; RUN_ONCE='\LDW-CI-JIT-RUN-ONCE'; RECOVER='\LDW-CI-JIT-RECOVER'
    ABORT_ACTIVE='\LDW-CI-JIT-ABORT-ACTIVE'; LIST_STALE='\LDW-CI-JIT-LIST-STALE'; RETIRE_STALE='\LDW-CI-JIT-RETIRE-STALE'
}
$script:SlotNames = @{
    DISCOVER='discover.json'; RUN_ONCE='run-once.json'; RECOVER='recover.json'
    ABORT_ACTIVE='abort-active.json'; LIST_STALE='list-stale.json'; RETIRE_STALE='retire-stale.json'
}
$script:ResultStates = @('QUEUED','STARTED','PASS','BLOCKED','FAILED','STALE','AMBIGUOUS')
$script:ReasonCodes = @(
    'NONE','ADAPTER_UNAVAILABLE','INVALID_ADAPTER_RESULT','TARGET_REFUSED','QUEUE_UNAVAILABLE','QUEUE_STALE',
    'NO_ELIGIBLE_JOB','BUSY','CAPACITY','POLICY_HOLD','PROVENANCE_MISMATCH','LOCK_OR_RESIDUE_UNCERTAIN',
    'IDENTITY_MISMATCH','NO_ACTIVE_JOB','CURRENT_CANDIDATE','NOT_STALE','PR_CLOSED','PR_MERGED',
    'PR_HEAD_MOVED','SUPERSEDED','PROFILE_MISMATCH','OPERATION_NOT_FOUND','FAILED'
)
$script:StatusReasonCodes = @(
    'BUSY','CAPACITY','LOCAL_STATE_STALE','LOCAL_STATE_UNAVAILABLE','MALFORMED_STATE','MULTIPLE_ACTIVE_RUNS',
    'OWNED_RESOURCE_CONTRADICTION','POLICY_HOLD','PROVENANCE_MISMATCH','QUEUE_STALE','QUEUE_UNAVAILABLE',
    'SOURCE_UNAVAILABLE','STALE_RESIDUE','UNKNOWN'
)

function Assert-CiJitLocalTaskClientNormalUser {
    if ($env:OS -cne 'Windows_NT') { throw 'LOCAL_CLIENT_WINDOWS_REQUIRED' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $identity.User -or $identity.User.Value -cnotmatch '^S-1-5-21-(\d+-){3}\d+$' -or
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'LOCAL_CLIENT_NORMAL_USER_REQUIRED'
    }
}

function Assert-CiJitNoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'LOCAL_CLIENT_REPARSE_REFUSED' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Test-CiJitSafeIdentifier([string]$Value,[int]$MaximumLength,[bool]$AllowUppercase) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt $MaximumLength) { return $false }
    $pattern = if ($AllowUppercase) { '^[A-Za-z0-9._:-]+$' } else { '^[a-z0-9._-]+$' }
    if ($Value -cnotmatch $pattern) { return $false }
    if ($Value.Length -in @(40,64) -and $Value -match '^[0-9a-fA-F]+$') { return $false }
    $true
}

function New-CiJitLocalResult([bool]$Success,[string]$State,[string]$Reason,[System.Collections.IDictionary]$Details) {
    if ($State -cnotin $script:ResultStates -or $Reason -cnotin $script:ReasonCodes) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
    if (($Success -and $State -in @('BLOCKED','FAILED','AMBIGUOUS')) -or
        (-not $Success -and $State -in @('QUEUED','STARTED','PASS'))) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
    [ordered]@{ success=$Success; resultState=$State; errorCode=$null; details=$Details }
}

function New-CiJitUnavailableStatus([string]$Reason) {
    $details = [ordered]@{
        reasonCode='NONE'; observedAtUtc=[DateTimeOffset]::UtcNow.ToString('O')
        sourceVersion='ci-jit-v1'; ownerState='UNKNOWN'; statusReasonCode=$Reason
        localStateFresh='false'; queueState='UNAVAILABLE'; capacity='UNKNOWN'
    }
    New-CiJitLocalResult $true 'PASS' 'NONE' $details
}

function Assert-CiJitTrustedStatusBoundary {
    if (-not (Test-Path -LiteralPath $script:StatusPath -PathType Leaf)) { return $false }
    Assert-CiJitNoReparse $script:StatusPath
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $readerSid = $identity.User.Value
    $trusted = @('S-1-5-18','S-1-5-32-544')
    $write = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership

    $statusRoot=Split-Path -Parent $script:StatusPath
    foreach ($entry in @(
        [pscustomobject]@{Path=$statusRoot; Required=[Security.AccessControl.FileSystemRights]::ReadAndExecute; Protected=$true},
        [pscustomobject]@{Path=$script:StatusPath; Required=[Security.AccessControl.FileSystemRights]::Read; Protected=$false}
    )) {
        $acl = Get-Acl -LiteralPath $entry.Path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or ($entry.Protected -and -not $acl.AreAccessRulesProtected)) { return $false }
        $readerRights=[Security.AccessControl.FileSystemRights]0
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = $rule.IdentityReference.Value
            if ($sid -in $trusted) { continue }
            if (($rule.FileSystemRights -band $write) -ne 0) { return $false }
            if ($sid -ceq $readerSid) { $readerRights = $readerRights -bor $rule.FileSystemRights }
        }
        if (($readerRights -band $entry.Required) -ne $entry.Required) { return $false }
    }
    $true
}

function ConvertFrom-CiJitStatusProjection([string]$Json,[DateTimeOffset]$NowUtc,[DateTimeOffset]$BootUtc) {
    $document = $null
    try {
        $document = [Text.Json.JsonDocument]::Parse($Json)
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'STATUS_MALFORMED' }
        $required = @(
            'schema','source_version','boot_started_utc','local_observed_at_utc','provenance_valid','proven_failure',
            'controller_phase','capacity','reason_code','queue_observed_at_utc','queue_state','eligible_queued_count',
            'held_queued_count','selected_profile','selected_run_id','selected_job_id'
        )
        $names = @($root.EnumerateObject() | ForEach-Object Name)
        if ($names.Count -ne $required.Count -or @($names | Group-Object | Where-Object Count -ne 1).Count -or
            @(Compare-Object $required $names -CaseSensitive).Count) { throw 'STATUS_MALFORMED' }
        if ($root.GetProperty('schema').GetInt32() -ne 1 -or $root.GetProperty('source_version').GetString() -cne 'ci-jit-v1') {
            throw 'STATUS_MALFORMED'
        }

        $bootText = $root.GetProperty('boot_started_utc').GetString()
        $localText = $root.GetProperty('local_observed_at_utc').GetString()
        [DateTimeOffset]$projectedBoot = [DateTimeOffset]::MinValue
        [DateTimeOffset]$localObserved = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse($bootText,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$projectedBoot) -or
            -not [DateTimeOffset]::TryParse($localText,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$localObserved)) {
            throw 'STATUS_MALFORMED'
        }
        $projectedBoot=$projectedBoot.ToUniversalTime(); $localObserved=$localObserved.ToUniversalTime()
        if ($localObserved -gt $NowUtc.AddMinutes(1)) { throw 'STATUS_MALFORMED' }

        $provenance = $root.GetProperty('provenance_valid')
        $failure = $root.GetProperty('proven_failure')
        if ($provenance.ValueKind -notin @([Text.Json.JsonValueKind]::True,[Text.Json.JsonValueKind]::False) -or
            $failure.ValueKind -notin @([Text.Json.JsonValueKind]::True,[Text.Json.JsonValueKind]::False)) { throw 'STATUS_MALFORMED' }
        $provenanceValid=$provenance.GetBoolean(); $provenFailure=$failure.GetBoolean()

        $capacity = $root.GetProperty('capacity').GetString().ToUpperInvariant()
        $queueState = $root.GetProperty('queue_state').GetString().ToUpperInvariant()
        if ($capacity -notin @('READY','BUSY','CAPACITY','UNKNOWN') -or $queueState -notin @('FRESH','UNAVAILABLE')) { throw 'STATUS_MALFORMED' }

        $phaseElement=$root.GetProperty('controller_phase')
        $phase=$null
        if ($phaseElement.ValueKind -ne [Text.Json.JsonValueKind]::Null) {
            if ($phaseElement.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw 'STATUS_MALFORMED' }
            $phase=$phaseElement.GetString().ToUpperInvariant()
            if ($phase -notin @('PLANNED','REGISTERED','PROVISIONED','RUNNING','JOBCOMPLETED','RUNNERABSENT','GUESTREMOVED','ARTIFACTSREMOVED','COMPLETE')) { throw 'STATUS_MALFORMED' }
        }

        $reasonElement=$root.GetProperty('reason_code')
        $reason=$null
        if ($reasonElement.ValueKind -ne [Text.Json.JsonValueKind]::Null) {
            if ($reasonElement.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw 'STATUS_MALFORMED' }
            $reason=$reasonElement.GetString()
            if ($reason -cnotin $script:StatusReasonCodes) { throw 'STATUS_MALFORMED' }
        }

        $queueObserved=$null
        $queueTimeElement=$root.GetProperty('queue_observed_at_utc')
        if ($queueTimeElement.ValueKind -ne [Text.Json.JsonValueKind]::Null) {
            if ($queueTimeElement.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw 'STATUS_MALFORMED' }
            [DateTimeOffset]$q=[DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse($queueTimeElement.GetString(),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$q)) { throw 'STATUS_MALFORMED' }
            $queueObserved=$q.ToUniversalTime()
            if ($queueObserved -gt $NowUtc.AddMinutes(1)) { throw 'STATUS_MALFORMED' }
        }

        function Read-NullableNonNegativeInt([Text.Json.JsonElement]$Element) {
            if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Null) { return $null }
            [int]$value=0
            if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $Element.TryGetInt32([ref]$value) -or $value -lt 0) { throw 'STATUS_MALFORMED' }
            $value
        }
        function Read-NullablePositiveLong([Text.Json.JsonElement]$Element) {
            if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Null) { return $null }
            [long]$value=0
            if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $Element.TryGetInt64([ref]$value) -or $value -le 0) { throw 'STATUS_MALFORMED' }
            $value
        }
        $eligible=Read-NullableNonNegativeInt $root.GetProperty('eligible_queued_count')
        $held=Read-NullableNonNegativeInt $root.GetProperty('held_queued_count')
        $selectedRun=Read-NullablePositiveLong $root.GetProperty('selected_run_id')
        $selectedJob=Read-NullablePositiveLong $root.GetProperty('selected_job_id')
        $profileElement=$root.GetProperty('selected_profile')
        $selectedProfile=$null
        if ($profileElement.ValueKind -ne [Text.Json.JsonValueKind]::Null) {
            if ($profileElement.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw 'STATUS_MALFORMED' }
            $selectedProfile=$profileElement.GetString()
            if (-not (Test-CiJitSafeIdentifier $selectedProfile 64 $false)) { throw 'STATUS_MALFORMED' }
        }

        if ($queueState -ceq 'FRESH') {
            if ($null -eq $queueObserved -or $null -eq $eligible -or $null -eq $held) { throw 'STATUS_MALFORMED' }
        } elseif ($null -ne $queueObserved -or $null -ne $eligible -or $null -ne $held -or
            $null -ne $selectedProfile -or $null -ne $selectedRun -or $null -ne $selectedJob) { throw 'STATUS_MALFORMED' }
        $selectedParts=@(@($selectedProfile;$selectedRun;$selectedJob) | Where-Object { $null -ne $_ }).Count
        if ($selectedParts -notin @(0,3)) { throw 'STATUS_MALFORMED' }

        $active = $phase -in @('PLANNED','REGISTERED','PROVISIONED','RUNNING','JOBCOMPLETED','RUNNERABSENT','GUESTREMOVED','ARTIFACTSREMOVED')
        if (($capacity -ceq 'BUSY') -ne $active) { throw 'STATUS_MALFORMED' }
        $sameBoot=[Math]::Abs(($projectedBoot-$BootUtc).TotalMinutes) -le 2
        $localFresh=$sameBoot -and (-not $active -or ($NowUtc-$localObserved).TotalMinutes -le 2)
        if ($queueState -ceq 'FRESH' -and ($NowUtc-$queueObserved).TotalMinutes -gt 2) {
            $queueState='STALE'; $eligible=$null; $held=$null; $selectedProfile=$null; $selectedRun=$null; $selectedJob=$null
        }

        if ($provenFailure) {
            if ($reason -notin @('MULTIPLE_ACTIVE_RUNS','OWNED_RESOURCE_CONTRADICTION','STALE_RESIDUE')) { throw 'STATUS_MALFORMED' }
        } elseif ($reason -in @('MULTIPLE_ACTIVE_RUNS','OWNED_RESOURCE_CONTRADICTION','STALE_RESIDUE')) { throw 'STATUS_MALFORMED' }
        if (-not $provenFailure) {
            if (-not $localFresh) { $reason='LOCAL_STATE_STALE' }
            elseif (-not $provenanceValid) { $reason='PROVENANCE_MISMATCH' }
            elseif ($queueState -ceq 'STALE') { $reason='QUEUE_STALE' }
            elseif ($queueState -ceq 'UNAVAILABLE' -and $null -eq $reason) { $reason='QUEUE_UNAVAILABLE' }
        }
        if ($reason -and $reason -cnotin $script:StatusReasonCodes) { throw 'STATUS_MALFORMED' }

        if ($provenFailure) { $ownerState='FAILED' }
        elseif ($reason -in @('UNKNOWN','MALFORMED_STATE','SOURCE_UNAVAILABLE') -or -not $localFresh -or -not $provenanceValid) { $ownerState='UNKNOWN' }
        elseif ($phase -in @('JOBCOMPLETED','RUNNERABSENT','GUESTREMOVED','ARTIFACTSREMOVED')) { $ownerState='CLEANING' }
        elseif ($phase -ceq 'RUNNING') { $ownerState='RUNNING' }
        elseif ($phase -in @('PLANNED','REGISTERED','PROVISIONED')) { $ownerState='DISPATCHING' }
        elseif ($queueState -cne 'FRESH' -or $null -eq $eligible -or $null -eq $held) { $ownerState='UNKNOWN' }
        elseif ($eligible -gt 0) {
            if ($reason -ceq 'POLICY_HOLD') { $ownerState='HOLD' }
            elseif ($capacity -ceq 'READY') { $ownerState='QUEUED' }
            elseif ($capacity -in @('BUSY','CAPACITY')) { $ownerState='HOLD' }
            else { $ownerState='UNKNOWN' }
        } elseif ($held -gt 0) { $ownerState='HOLD' }
        else { $ownerState='IDLE' }

        $observed=$localObserved
        if ($null -ne $queueObserved -and $queueObserved -gt $observed) { $observed=$queueObserved }
        $details=[ordered]@{
            reasonCode='NONE'; observedAtUtc=$observed.ToString('O'); sourceVersion='ci-jit-v1'; ownerState=$ownerState
            localStateFresh=($(if($localFresh){'true'}else{'false'})); queueState=$queueState; capacity=$capacity
        }
        if ($reason) { $details.statusReasonCode=$reason }
        if ($null -ne $eligible) { $details.eligibleQueuedCount=[string]$eligible }
        if ($null -ne $held) { $details.heldQueuedCount=[string]$held }
        if ($selectedProfile) { $details.selectedProfile=$selectedProfile }
        if ($null -ne $selectedRun) { $details.selectedRunId=[string]$selectedRun }
        if ($null -ne $selectedJob) { $details.selectedJobId=[string]$selectedJob }
        if ($phase) { $details.controllerPhase=$phase }
        New-CiJitLocalResult $true 'PASS' 'NONE' $details
    } finally {
        if ($null -ne $document) { $document.Dispose() }
    }
}

function Get-CiJitLocalStatus {
    if (-not (Test-Path -LiteralPath $script:StatusPath -PathType Leaf)) { return (New-CiJitUnavailableStatus 'LOCAL_STATE_UNAVAILABLE') }
    try {
        if (-not (Assert-CiJitTrustedStatusBoundary)) { return (New-CiJitUnavailableStatus 'SOURCE_UNAVAILABLE') }
        $info=Get-Item -LiteralPath $script:StatusPath -Force
        if ($info.Length -le 0 -or $info.Length -gt $script:MaximumStatusBytes) { return (New-CiJitUnavailableStatus 'MALFORMED_STATE') }
        $json=[IO.File]::ReadAllText($script:StatusPath,[Text.Encoding]::UTF8)
        $now=[DateTimeOffset]::UtcNow
        $boot=$now.AddMilliseconds(-[Environment]::TickCount64)
        ConvertFrom-CiJitStatusProjection $json $now $boot
    } catch {
        New-CiJitUnavailableStatus 'MALFORMED_STATE'
    }
}

function Assert-CiJitControlBoundary {
    foreach ($path in @($script:ControlRoot,$script:RequestRoot,$script:ResultRoot)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw 'LOCAL_CLIENT_BOUNDARY_UNAVAILABLE' }
        Assert-CiJitNoReparse $path
    }
}

function Test-CiJitDirectChild([string]$Parent,[string]$Child) {
    $parentFull=[IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    $childFull=[IO.Path]::GetFullPath($Child)
    $childFull.StartsWith($parentFull,[StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([IO.Path]::GetDirectoryName($childFull),$parentFull.TrimEnd([IO.Path]::DirectorySeparatorChar),[StringComparison]::OrdinalIgnoreCase)
}

function ConvertFrom-CiJitTaskResult([guid]$ExpectedOperationId) {
    Assert-CiJitControlBoundary
    $path=Join-Path $script:ResultRoot ($ExpectedOperationId.ToString('D')+'.json')
    if (-not (Test-CiJitDirectChild $script:ResultRoot $path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return New-CiJitLocalResult $false 'BLOCKED' 'OPERATION_NOT_FOUND' ([ordered]@{reasonCode='OPERATION_NOT_FOUND'})
    }
    Assert-CiJitNoReparse $path
    $bytes=[IO.File]::ReadAllBytes($path)
    if ($bytes.Length -le 0 -or $bytes.Length -gt $script:MaximumEnvelopeBytes) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
    $document=$null
    try {
        $document=[Text.Json.JsonDocument]::Parse([System.ReadOnlyMemory[byte]]$bytes)
        $root=$document.RootElement
        $required=@('schema','operationId','success','resultState','reasonCode','profileId','runId','jobId','staleItems')
        $names=@($root.EnumerateObject() | ForEach-Object Name)
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object -or $names.Count -ne $required.Count -or
            @($names | Group-Object | Where-Object Count -ne 1).Count -or @(Compare-Object $required $names -CaseSensitive).Count) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
        if ($root.GetProperty('schema').GetInt32() -ne 1 -or $root.GetProperty('operationId').GetString() -cne $ExpectedOperationId.ToString('D')) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
        $successElement=$root.GetProperty('success')
        if ($successElement.ValueKind -notin @([Text.Json.JsonValueKind]::True,[Text.Json.JsonValueKind]::False)) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
        $success=$successElement.GetBoolean()
        $state=$root.GetProperty('resultState').GetString()
        $reason=$root.GetProperty('reasonCode').GetString()
        if ($state -cnotin $script:ResultStates -or $reason -cnotin $script:ReasonCodes -or
            ($success -and $state -in @('BLOCKED','FAILED','AMBIGUOUS')) -or (-not $success -and $state -in @('QUEUED','STARTED','PASS'))) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
        $details=[ordered]@{reasonCode=$reason; operationId=$ExpectedOperationId.ToString('D')}
        foreach ($pair in @(@('profileId','profileId'),@('runId','runId'),@('jobId','jobId'),@('staleItems','staleItems'))) {
            $element=$root.GetProperty($pair[0])
            if ($element.ValueKind -eq [Text.Json.JsonValueKind]::Null) { continue }
            if ($pair[0] -eq 'profileId') {
                if ($element.ValueKind -ne [Text.Json.JsonValueKind]::String -or -not (Test-CiJitSafeIdentifier $element.GetString() 64 $false)) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
                $details[$pair[1]]=$element.GetString()
            } elseif ($pair[0] -in @('runId','jobId')) {
                [long]$id=0
                if ($element.ValueKind -ne [Text.Json.JsonValueKind]::Number -or -not $element.TryGetInt64([ref]$id) -or $id -le 0) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
                $details[$pair[1]]=[string]$id
            } else {
                if ($element.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
                $value=$element.GetString()
                if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 1024 -or $value -cnotmatch '^(\d+:(PR_CLOSED|PR_MERGED|PR_HEAD_MOVED|SUPERSEDED|PROFILE_MISMATCH))(,\d+:(PR_CLOSED|PR_MERGED|PR_HEAD_MOVED|SUPERSEDED|PROFILE_MISMATCH))*$') { throw 'LOCAL_CLIENT_RESULT_REFUSED' }
                $details[$pair[1]]=$value
            }
        }
        New-CiJitLocalResult $success $state $reason $details
    } finally { if ($null -ne $document) { $document.Dispose() } }
}

function Invoke-CiJitTaskOperation([string]$RequestedOperation,[long]$RequestedRunId) {
    if ($RequestedOperation -cnotin $script:TaskNames.Keys) { throw 'LOCAL_CLIENT_OPERATION_REFUSED' }
    if (($RequestedOperation -ceq 'RETIRE_STALE') -ne ($RequestedRunId -gt 0)) { throw 'LOCAL_CLIENT_ARGUMENT_REFUSED' }
    Assert-CiJitControlBoundary
    $operationId=[guid]::NewGuid()
    $slot=Join-Path $script:RequestRoot $script:SlotNames[$RequestedOperation]
    if (-not (Test-CiJitDirectChild $script:RequestRoot $slot) -or (Test-Path -LiteralPath $slot)) {
        return New-CiJitLocalResult $false 'BLOCKED' 'BUSY' ([ordered]@{reasonCode='BUSY'})
    }
    $payload=[ordered]@{schema=1;operationId=$operationId.ToString('D');operation=$RequestedOperation;runId=$(if($RequestedRunId -gt 0){$RequestedRunId}else{$null})}
    $json=$payload | ConvertTo-Json -Compress
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json)
    if ($bytes.Length -le 0 -or $bytes.Length -gt $script:MaximumEnvelopeBytes) { throw 'LOCAL_CLIENT_REQUEST_REFUSED' }
    $temp=Join-Path $script:RequestRoot ('.pending-'+$operationId.ToString('N')+'.json')
    try {
        $options=[IO.FileOptions]::WriteThrough
        $stream=[IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,$options)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        [IO.File]::Move($temp,$slot,$false)
        $schtasks=Join-Path $env:SystemRoot 'System32/schtasks.exe'
        $start=[Diagnostics.ProcessStartInfo]::new($schtasks)
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        $null=$start.ArgumentList.Add('/Run'); $null=$start.ArgumentList.Add('/TN'); $null=$start.ArgumentList.Add($script:TaskNames[$RequestedOperation])
        $process=[Diagnostics.Process]::Start($start)
        try {
            $null=$process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
            $null=$process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
            $process.WaitForExit()
            if ($process.ExitCode -ne 0) {
                if (Test-Path -LiteralPath $slot) { Remove-Item -LiteralPath $slot -Force }
                return New-CiJitLocalResult $false 'BLOCKED' 'ADAPTER_UNAVAILABLE' ([ordered]@{reasonCode='ADAPTER_UNAVAILABLE'})
            }
        } finally { $process.Dispose() }
        New-CiJitLocalResult $true 'QUEUED' 'NONE' ([ordered]@{reasonCode='NONE';operationId=$operationId.ToString('D')})
    } catch {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
        throw
    }
}

function Invoke-CiJitLocalTaskClient {
    param(
        [Parameter(Mandatory)][ValidateSet('STATUS','DISCOVER','RUN_ONCE','RECOVER','ABORT_ACTIVE','LIST_STALE','RETIRE_STALE','GET_OPERATION_RESULT')][string]$RequestedOperation,
        [long]$RequestedRunId = 0,
        [guid]$RequestedOperationId = [guid]::Empty
    )
    Assert-CiJitLocalTaskClientNormalUser
    if ($RequestedOperation -ceq 'STATUS') {
        if ($RequestedRunId -ne 0 -or $RequestedOperationId -ne [guid]::Empty) { throw 'LOCAL_CLIENT_ARGUMENT_REFUSED' }
        return (Get-CiJitLocalStatus)
    }
    if ($RequestedOperation -ceq 'GET_OPERATION_RESULT') {
        if ($RequestedRunId -ne 0 -or $RequestedOperationId -eq [guid]::Empty) { throw 'LOCAL_CLIENT_ARGUMENT_REFUSED' }
        return (ConvertFrom-CiJitTaskResult $RequestedOperationId)
    }
    if ($RequestedOperation -ceq 'RETIRE_STALE') {
        if ($RequestedRunId -le 0 -or $RequestedOperationId -ne [guid]::Empty) { throw 'LOCAL_CLIENT_ARGUMENT_REFUSED' }
    } elseif ($RequestedRunId -ne 0 -or $RequestedOperationId -ne [guid]::Empty) { throw 'LOCAL_CLIENT_ARGUMENT_REFUSED' }
    Invoke-CiJitTaskOperation $RequestedOperation $RequestedRunId
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($Operation)) { throw 'LOCAL_CLIENT_OPERATION_REQUIRED' }
    $result=Invoke-CiJitLocalTaskClient -RequestedOperation $Operation -RequestedRunId $RunId -RequestedOperationId $OperationId
    'CI_JIT_LOCAL_TASK_CLIENT_RESULT=' + ($result | ConvertTo-Json -Compress -Depth 4)
}
