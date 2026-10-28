[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('DISCOVER','RUN_ONCE','RECOVER','ABORT_ACTIVE','LIST_STALE','RETIRE_STALE')][string]$Operation,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$WorkerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$controlRoot = Join-Path $env:ProgramData 'LDW/CiJitControl'
$requestRoot = Join-Path $controlRoot 'requests'
$resultRoot = Join-Path $controlRoot 'results'
$binRoot = Join-Path $controlRoot 'bin'
$expectedWorker = Join-Path $binRoot 'Invoke-CiJitControlTask.ps1'
$bundle = Join-Path (Join-Path $env:ProgramData 'LDW/CiRunnerDispatch/releases') $Commit
$dispatcher = Join-Path $bundle 'ci-dispatch/Invoke-Dispatcher.ps1'
$dispatchModule = Join-Path $bundle 'ci-dispatch/Dispatch.psm1'
$runnerEntry = Join-Path $bundle 'ci-runner/Invoke-IsolatedRunner.ps1'
$runnerModule = Join-Path $bundle 'ci-runner/CiRunner.psm1'
$controllerRoot = Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'
$slotNames = @{
    DISCOVER='discover.json'; RUN_ONCE='run-once.json'; RECOVER='recover.json';
    ABORT_ACTIVE='abort-active.json'; LIST_STALE='list-stale.json'; RETIRE_STALE='retire-stale.json'
}
$requestPath = Join-Path $requestRoot $slotNames[$Operation]
$operationId = $null

function Assert-ElevatedOwnerTask {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        -not $identity.User -or $identity.User.Value -cnotmatch '^S-1-5-21-(\d+-){3}\d+$') {
        throw 'ELEVATED_OWNER_TASK_REQUIRED'
    }
}

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE_PATH_REFUSED' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-ProtectedPath([string]$Path) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath ([IO.Path]::GetFullPath($Path))
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'PROTECTED_OWNER_REFUSED'
    }
    $write = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'PROTECTED_WRITE_REFUSED'
        }
    }
}

function Assert-WorkerAndBundle {
    Assert-ElevatedOwnerTask
    $actualWorker = [IO.Path]::GetFullPath($PSCommandPath)
    if (-not [string]::Equals($actualWorker,[IO.Path]::GetFullPath($expectedWorker),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'WORKER_PATH_REFUSED'
    }
    Assert-ProtectedPath $binRoot
    Assert-ProtectedPath $actualWorker
    if ((Get-FileHash -LiteralPath $actualWorker -Algorithm SHA256).Hash.ToLowerInvariant() -cne $WorkerSha256) {
        throw 'WORKER_HASH_DRIFT'
    }
    $expectedBundle = [IO.Path]::GetFullPath((Join-Path (Join-Path $env:ProgramData 'LDW/CiRunnerDispatch/releases') $Commit))
    if (-not [string]::Equals([IO.Path]::GetFullPath($bundle),$expectedBundle,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'BUNDLE_PATH_REFUSED'
    }
    foreach ($path in @($bundle,(Join-Path $bundle 'manifest.json'),$dispatcher,$dispatchModule,$runnerEntry,$runnerModule)) {
        Assert-ProtectedPath $path
    }
    $manifestPath = Join-Path $bundle 'manifest.json'
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha) {
        throw 'MANIFEST_HASH_DRIFT'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or $manifest.commit -cne $Commit -or $manifest.tree -cne $Tree) {
        throw 'BUNDLE_PROVENANCE_MISMATCH'
    }
    foreach ($relative in @('ci-dispatch/Invoke-Dispatcher.ps1','ci-dispatch/Dispatch.psm1','ci-runner/Invoke-IsolatedRunner.ps1','ci-runner/CiRunner.psm1')) {
        $entry = @($manifest.files | Where-Object path -CEQ $relative)
        $file = Join-Path $bundle $relative
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[0].sha256) {
            throw 'BUNDLE_FILE_HASH_DRIFT'
        }
    }
    Import-Module $dispatchModule -Force
    $null = Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
}

function Read-Request {
    Assert-NoReparse $requestRoot
    Assert-NoReparse $requestPath
    if (-not (Test-Path -LiteralPath $requestPath -PathType Leaf)) { throw 'REQUEST_REQUIRED' }
    $bytes = [IO.File]::ReadAllBytes($requestPath)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 16384) { throw 'REQUEST_REFUSED' }
    $document = [Text.Json.JsonDocument]::Parse($bytes)
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'REQUEST_REFUSED' }
        $names = @($root.EnumerateObject() | ForEach-Object Name)
        if ($names.Count -ne 4 -or @($names | Group-Object | Where-Object Count -ne 1).Count -or
            @(Compare-Object @('schema','operationId','operation','runId') $names -CaseSensitive).Count) { throw 'REQUEST_REFUSED' }
        if ($root.GetProperty('schema').GetInt32() -ne 1) { throw 'REQUEST_REFUSED' }
        $id = $root.GetProperty('operationId').GetString()
        if (-not [Guid]::TryParseExact($id,'D',[ref]([Guid]$null))) { throw 'REQUEST_REFUSED' }
        if ($root.GetProperty('operation').GetString() -cne $Operation) { throw 'REQUEST_OPERATION_MISMATCH' }
        $runElement = $root.GetProperty('runId')
        $runId = if ($runElement.ValueKind -eq [Text.Json.JsonValueKind]::Null) { $null } else { $runElement.GetInt64() }
        if ($Operation -ceq 'RETIRE_STALE') {
            if ($null -eq $runId -or $runId -le 0) { throw 'REQUEST_RUN_ID_REFUSED' }
        } elseif ($null -ne $runId) { throw 'REQUEST_RUN_ID_REFUSED' }
        [pscustomobject]@{ OperationId=$id; RunId=$runId }
    } finally { $document.Dispose() }
}

function Write-Result([bool]$Success,[string]$State,[string]$Reason,[string]$ProfileId=$null,[long]$RunId=0,[long]$JobId=0,[string]$StaleItems=$null) {
    if ($operationId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return }
    if ($State -cnotin @('QUEUED','STARTED','PASS','BLOCKED','FAILED','STALE','AMBIGUOUS')) { $State='FAILED' }
    if ($Reason -cnotin @('NONE','ADAPTER_UNAVAILABLE','INVALID_ADAPTER_RESULT','TARGET_REFUSED','QUEUE_UNAVAILABLE','QUEUE_STALE','NO_ELIGIBLE_JOB','BUSY','CAPACITY','POLICY_HOLD','PROVENANCE_MISMATCH','LOCK_OR_RESIDUE_UNCERTAIN','IDENTITY_MISMATCH','NO_ACTIVE_JOB','CURRENT_CANDIDATE','NOT_STALE','PR_CLOSED','PR_MERGED','PR_HEAD_MOVED','SUPERSEDED','PROFILE_MISMATCH','OPERATION_NOT_FOUND','FAILED')) { $Reason='FAILED' }
    if ($ProfileId -and $ProfileId -cnotmatch '^[a-z0-9._-]{1,64}$') { $ProfileId=$null }
    $payload = [ordered]@{
        schema=1; operationId=$operationId; success=$Success; resultState=$State; reasonCode=$Reason;
        profileId=$(if ($ProfileId) {$ProfileId} else {$null}); runId=$(if ($RunId -gt 0) {$RunId} else {$null});
        jobId=$(if ($JobId -gt 0) {$JobId} else {$null}); staleItems=$(if ($StaleItems) {$StaleItems} else {$null})
    }
    Assert-NoReparse $resultRoot
    $path = Join-Path $resultRoot ($operationId + '.json')
    $temp = Join-Path $resultRoot ('.pending-' + $operationId + '.json')
    $json = $payload | ConvertTo-Json -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 16384) { throw 'RESULT_TOO_LARGE' }
    try {
        [IO.File]::WriteAllText($temp,$json,[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temp -Destination $path -Force
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Invoke-Child([string]$Path,[string[]]$Arguments) {
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $info = [Diagnostics.ProcessStartInfo]::new($pwsh)
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    foreach ($arg in @('-NoLogo','-NoProfile','-NonInteractive','-File',$Path)+$Arguments) { $info.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::Start($info)
    $null = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
    $safe = [Collections.Generic.List[string]]::new()
    while (-not $process.StandardOutput.EndOfStream) {
        $line = $process.StandardOutput.ReadLine()
        if ($line -cmatch '^(DISPATCHER_RESULT|DISCOVERED_RUN_ID|DISCOVERED_JOB_ID|INTERRUPTED_CLEANUP|CLEANUP_IDEMPOTENT)=([A-Z_]+|[0-9]+|PASS)$') { $safe.Add($line) }
    }
    $process.WaitForExit()
    $code=$process.ExitCode; $process.Dispose()
    [pscustomobject]@{ ExitCode=$code; Lines=@($safe) }
}

function Get-OutputValue([string[]]$Lines,[string]$Name) {
    $match = @($Lines | Where-Object { $_ -cmatch ('^'+[regex]::Escape($Name)+'=') })
    if ($match.Count -ne 1) { return $null }
    $match[0].Substring($Name.Length+1)
}

function Invoke-DispatcherMode([ValidateSet('Discover','Once','Recover')][string]$Mode) {
    $args = @('-ManifestSha',$ManifestSha,'-Commit',$Commit,'-Tree',$Tree,'-Mode',$Mode)
    $result = Invoke-Child $dispatcher $args
    $code = Get-OutputValue $result.Lines 'DISPATCHER_RESULT'
    if ($result.ExitCode -ne 0 -or $code -ceq 'FAIL' -or -not $code) { return [pscustomobject]@{Success=$false;State='FAILED';Reason='FAILED';RunId=0;JobId=0;ProfileId=$null} }
    if ($code -ceq 'BUSY') { return [pscustomobject]@{Success=$false;State='BLOCKED';Reason='BUSY';RunId=0;JobId=0;ProfileId=$null} }
    if ($code -ceq 'CAPACITY') { return [pscustomobject]@{Success=$false;State='BLOCKED';Reason='CAPACITY';RunId=0;JobId=0;ProfileId=$null} }
    if ($code -ceq 'IDLE') { return [pscustomobject]@{Success=($Mode -ceq 'Discover');State=$(if($Mode -ceq 'Discover'){'PASS'}else{'BLOCKED'});Reason=$(if($Mode -ceq 'Discover'){'NONE'}else{'NO_ELIGIBLE_JOB'});RunId=0;JobId=0;ProfileId=$null} }
    if ($code -notin @('DISCOVERED','PASS','RECOVERED')) { return [pscustomobject]@{Success=$false;State='FAILED';Reason='FAILED';RunId=0;JobId=0;ProfileId=$null} }
    $run = Get-OutputValue $result.Lines 'DISCOVERED_RUN_ID'; $job = Get-OutputValue $result.Lines 'DISCOVERED_JOB_ID'
    $statusPath = Join-Path $env:ProgramData 'LDW/CiJitStatus/status.json'
    $profile = $null
    try { if (Test-Path -LiteralPath $statusPath) { $profile=(Get-Content -LiteralPath $statusPath -Raw|ConvertFrom-Json).selected_profile } } catch { $profile=$null }
    [pscustomobject]@{Success=$true;State='PASS';Reason='NONE';RunId=$(if($run){[long]$run}else{0});JobId=$(if($job){[long]$job}else{0});ProfileId=$profile}
}

function Invoke-ControlGhRead([string]$Path) {
    if ($Path -cnotmatch '^repos/LowcountryDigitalWorks/(infrastructure-tools|business-operations|royal-cruise-tracker)/(actions/(runs|workflows)|pulls)(/|\?|$)') { throw 'API_SCOPE_REFUSED' }
    $raw = & gh api --method GET $Path 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'API_READ_FAILED' }
    try { $raw | ConvertFrom-Json -DateKind String -ErrorAction Stop } catch { throw 'API_RESPONSE_INVALID' }
}

function Test-UnassignedQueued([object]$Run,[object]$Jobs) {
    if ($Run.status -cne 'queued' -or $null -ne $Run.conclusion -or $Jobs.total_count -ne 1 -or @($Jobs.jobs).Count -ne 1) { return $false }
    $job=$Jobs.jobs[0]
    return $job.status -ceq 'queued' -and $null -eq $job.conclusion -and -not $job.runner_id -and -not $job.runner_name -and -not $job.runner_group_id
}

function Get-PrStaleReason([object]$Profile,[object]$Run) {
    $prs=@($Run.pull_requests)
    if ($prs.Count -eq 0) { return $null }
    if ($prs.Count -ne 1 -or $prs[0].number -le 0) { throw 'API_RESPONSE_INVALID' }
    $pr=Invoke-ControlGhRead ('repos/'+$Profile.repository+'/pulls/'+$prs[0].number)
    if ($pr.merged_at) { return 'PR_MERGED' }
    if ($pr.state -ceq 'closed') { return 'PR_CLOSED' }
    if (-not $pr.head -or $pr.head.sha -cnotmatch '^[a-f0-9]{40}$') { throw 'API_RESPONSE_INVALID' }
    if ($pr.head.sha -cne $Run.head_sha) { return 'PR_HEAD_MOVED' }
    return $null
}

function Get-ProvenStaleEntries([long]$TargetRunId=0) {
    $profiles=@(Read-Ci10Profiles (Join-Path $bundle 'ci-dispatch/profiles.json'))
    $queue=Get-Ci10QueueSnapshot $profiles
    if ($queue.QueueState -cne 'FRESH') { throw 'QUEUE_UNAVAILABLE' }
    $entries=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[long]]::new()
    $profileMismatch=@('WRONG_REPOSITORY','WRONG_WORKFLOW','WRONG_EVENT_REF_SOURCE','JOB_IDENTITY_MISMATCH','WRONG_LABELS')
    foreach($profile in $profiles){
        $workflow=[Uri]::EscapeDataString([IO.Path]::GetFileName($profile.workflowPath))
        foreach($event in @($profile.events)){
            for($page=1;$page -le 3;$page++){
                $query='status=queued&event='+[Uri]::EscapeDataString($event)
                if($null -ne $profile.branch){$query+='&branch='+[Uri]::EscapeDataString($profile.branch)}
                $response=Invoke-ControlGhRead ('repos/'+$profile.repository+'/actions/workflows/'+$workflow+'/runs?'+$query+'&per_page=100&page='+$page)
                if($response.total_count -gt 300){throw 'QUEUE_BOUND_EXCEEDED'}
                foreach($run in @($response.workflow_runs)){
                    $runId=[long]$run.id
                    if($TargetRunId -gt 0 -and $runId -ne $TargetRunId){continue}
                    if(-not $seen.Add($runId)){throw 'QUEUE_PAGE_RACE_REFUSED'}
                    $jobs=Invoke-ControlGhRead ('repos/'+$profile.repository+'/actions/runs/'+$runId+'/jobs?filter=latest&per_page=100')
                    if(-not (Test-UnassignedQueued $run $jobs)){continue}
                    $reason=Get-PrStaleReason $profile $run
                    if(-not $reason){
                        try { $null=Get-Ci10Candidate $profile $run $jobs }
                        catch { if($_.Exception.Message -in $profileMismatch){$reason='PROFILE_MISMATCH'} else { continue } }
                    }
                    if($reason){$entries.Add([pscustomobject]@{Repository=$profile.repository;ProfileId=$profile.id;RunId=$runId;JobId=[long]$jobs.jobs[0].id;Reason=$reason;HeadSha=$run.head_sha})}
                }
                if(@($response.workflow_runs).Count -lt 100){break}
                if($page -eq 3){throw 'QUEUE_BOUND_EXCEEDED'}
            }
        }
    }
    if($entries.Count -gt 16){throw 'STALE_LIST_BOUND_EXCEEDED'}
    @($entries|Sort-Object RunId)
}

function Retire-ProvenStale([long]$RunId) {
    $first=@(Get-ProvenStaleEntries -TargetRunId $RunId)
    if($first.Count -eq 0){return [pscustomobject]@{Success=$false;State='BLOCKED';Reason='NOT_STALE';RunId=$RunId;JobId=0;ProfileId=$null}}
    if($first.Count -ne 1){return [pscustomobject]@{Success=$false;State='AMBIGUOUS';Reason='IDENTITY_MISMATCH';RunId=$RunId;JobId=0;ProfileId=$null}}
    $second=@(Get-ProvenStaleEntries -TargetRunId $RunId)
    if($second.Count -ne 1 -or $second[0].Repository -cne $first[0].Repository -or $second[0].Reason -cne $first[0].Reason -or
        $second[0].JobId -ne $first[0].JobId -or $second[0].HeadSha -cne $first[0].HeadSha){
        return [pscustomobject]@{Success=$false;State='AMBIGUOUS';Reason='IDENTITY_MISMATCH';RunId=$RunId;JobId=0;ProfileId=$null}
    }
    $null=& gh api --method POST ('repos/'+$second[0].Repository+'/actions/runs/'+$RunId+'/cancel') 2>$null
    if($LASTEXITCODE -ne 0){return [pscustomobject]@{Success=$false;State='FAILED';Reason='FAILED';RunId=$RunId;JobId=$second[0].JobId;ProfileId=$second[0].ProfileId}}
    [pscustomobject]@{Success=$true;State='PASS';Reason=$second[0].Reason;RunId=$RunId;JobId=$second[0].JobId;ProfileId=$second[0].ProfileId}
}

try {
    Assert-WorkerAndBundle
    Assert-NoReparse $requestRoot; Assert-NoReparse $resultRoot
    $request=Read-Request; $operationId=[string]$request.OperationId
    switch($Operation){
        'DISCOVER' { $r=Invoke-DispatcherMode Discover; Write-Result $r.Success $r.State $r.Reason $r.ProfileId $r.RunId $r.JobId }
        'RUN_ONCE' { $r=Invoke-DispatcherMode Once; Write-Result $r.Success $r.State $r.Reason $r.ProfileId $r.RunId $r.JobId }
        'RECOVER' { $r=Invoke-DispatcherMode Recover; Write-Result $r.Success $r.State $r.Reason $r.ProfileId $r.RunId $r.JobId }
        'ABORT_ACTIVE' {
            $runs=if(Test-Path -LiteralPath (Join-Path $controllerRoot 'runs')){@(Get-ChildItem -LiteralPath (Join-Path $controllerRoot 'runs') -Directory -Force)}else{@()}
            if($runs.Count -eq 0){Write-Result $false 'BLOCKED' 'NO_ACTIVE_JOB';break}
            if($runs.Count -ne 1 -or $runs[0].Name -cnotmatch '^[a-f0-9]{32}$'){Write-Result $false 'AMBIGUOUS' 'IDENTITY_MISMATCH';break}
            $child=Invoke-Child $runnerEntry @('-Mode','Cleanup','-LocalRunId',$runs[0].Name)
            $ok=$child.ExitCode -eq 0 -and @($child.Lines|Where-Object{$_ -cin @('INTERRUPTED_CLEANUP=PASS','CLEANUP_IDEMPOTENT=PASS')}).Count -eq 1
            Write-Result $ok $(if($ok){'PASS'}else{'FAILED'}) $(if($ok){'NONE'}else{'FAILED'})
        }
        'LIST_STALE' {
            $items=@(Get-ProvenStaleEntries)
            $encoded=if($items.Count){($items|ForEach-Object{[string]$_.RunId+':'+$_.Reason}) -join ','}else{$null}
            Write-Result $true 'PASS' 'NONE' -StaleItems $encoded
        }
        'RETIRE_STALE' {
            $r=Retire-ProvenStale ([long]$request.RunId)
            Write-Result $r.Success $r.State $r.Reason $r.ProfileId $r.RunId $r.JobId
        }
    }
} catch {
    if($operationId){
        $reason=switch -Regex ([string]$_.Exception.Message){
            '^QUEUE_UNAVAILABLE$|^API_READ_FAILED$|^API_RESPONSE_INVALID$' {'QUEUE_UNAVAILABLE';break}
            'PROVENANCE|MANIFEST|BUNDLE|WORKER_HASH|PROTECTED_' {'PROVENANCE_MISMATCH';break}
            'BUSY|LOCK|RESIDUE|ACTIVE_CONTROLLER' {'LOCK_OR_RESIDUE_UNCERTAIN';break}
            default {'FAILED'}
        }
        Write-Result $false 'FAILED' $reason
    }
    exit 1
} finally {
    try { if(Test-Path -LiteralPath $requestPath){Remove-Item -LiteralPath $requestPath -Force} } catch { }
}