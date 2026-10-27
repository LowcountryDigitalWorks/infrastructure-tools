[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repo 'ci-runner/CiRunner.psm1') -Force
$module=Import-Module (Join-Path $PSScriptRoot '../Dispatch.psm1') -Force -PassThru
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ci10-test-'+[guid]::NewGuid().ToString('N'))
$total=0
function Check([string]$Name,[scriptblock]$Body){ $script:case=$Name; & $Body; $script:total++; 'PASS '+$Name }
function Assert([bool]$Condition){if(-not $Condition){throw 'TEST_ASSERTION_FAILED'}}
function Refuses([scriptblock]$Action,[string]$Expected){
    $code=$null
    try {& $Action | Out-Null} catch {$code=$_.Exception.Message}
    Assert ($null -ne $code)
    if($Expected){Assert ($code -ceq $Expected)}
}
function Clone($Object){$Object|ConvertTo-Json -Depth 15|ConvertFrom-Json}
function New-ControllerFixture([string]$Commit,[string]$Destination){
    $paths=@(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')})
    $zip=$Destination+'.zip'
    & git -C $repo archive --format=zip ('--output='+$zip) $Commit -- @paths 2>$null
    if($LASTEXITCODE -ne 0){throw 'TEST_SNAPSHOT_ARCHIVE_FAILED'}
    [IO.Compression.ZipFile]::ExtractToDirectory($zip,$Destination)
    Remove-Item -LiteralPath $zip -Force
}
function Copy-AcceptedDispatcherFixture([string]$Destination){
    $commit='4faab579250ad7aaeeb13ae91708973b49bf9d10'
    $stage=Join-Path $fixture ('accepted-dispatcher-'+[guid]::NewGuid().ToString('N'))
    $zip=$stage+'.zip'
    $null=New-Item -ItemType Directory -Path $stage
    & git -C $repo archive --format=zip ('--output='+$zip) $commit -- 'ci-dispatch/Dispatch.psm1' 2>$null
    if($LASTEXITCODE -ne 0){throw 'TEST_DISPATCHER_ARCHIVE_FAILED'}
    [IO.Compression.ZipFile]::ExtractToDirectory($zip,$stage)
    $acceptedPath=Join-Path $stage 'ci-dispatch/Dispatch.psm1'
    $source=[IO.File]::ReadAllText($acceptedPath)
    [IO.File]::WriteAllText($Destination,$source.Replace("`r`n","`n").Replace("`n","`r`n"),[Text.UTF8Encoding]::new($false))
    Remove-Item -LiteralPath $stage -Recurse -Force
    Remove-Item -LiteralPath $zip -Force
}
function Protect([string]$Path){
    $null=New-Item -ItemType Directory -Path $Path -Force
    if ($env:OS -eq 'Windows_NT') {
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach($sid in @('S-1-5-18','S-1-5-32-544')){
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}
try {
    Protect $fixture
    $profilePath=Join-Path $fixture 'profiles.json'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../profiles.json') -Destination $profilePath
    $profiles=@(Read-Ci10Profiles $profilePath); $profile=$profiles[0]
    $production=$profiles | Where-Object id -CEQ 'ci10-bo-secret-scan'
    $royalProfile=$profiles | Where-Object id -CEQ 'ci10-royal-dashboard-deploy'

    Check 'accepted production profile is exact and source-dynamic' {
        Assert ($production.repository -ceq 'LowcountryDigitalWorks/business-operations')
        Assert ($production.workflowPath -ceq '.github/workflows/security-secrets.yml')
        Assert (@(Compare-Object @('pull_request','push') @($production.events) -CaseSensitive).Count -eq 0)
        Assert ($null -eq $production.branch -and $null -eq $production.headSha)
        Assert ($production.jobName -ceq 'secret-scan / secret-scan')
    }


    Check 'Royal PR release-gate profile accepts only its closed queued job identity' {
        $prProfile=$profiles | Where-Object id -CEQ 'ci10-royal-dashboard-release-gate-pr'
        Assert ($null -ne $prProfile)
        Assert ($prProfile.repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker')
        Assert ($prProfile.workflowPath -ceq '.github/workflows/dashboard-release-gate.yml')
        Assert (@($prProfile.events).Count -eq 1 -and $prProfile.events[0] -ceq 'pull_request')
        Assert ($prProfile.jobName -ceq 'Zero-side-effect full repository release validation')
        Assert ($prProfile.workflowSecrets -eq $false -and $prProfile.privateProductionState -eq $false -and $prProfile.docker -eq $false)
        Assert ($prProfile.cpu -eq 2 -and $prProfile.memoryMiB -eq 2048 -and $prProfile.timeoutMinutes -eq 20)
        $prRun=[pscustomobject]@{id=99886;run_attempt=1;status='queued';conclusion=$null;created_at='2026-10-18T12:00:00Z';head_sha=('e'*40);head_branch='feature/release-gate';event='pull_request';path=$prProfile.workflowPath;repository=@{full_name=$prProfile.repository};head_repository=@{full_name=$prProfile.repository}}
        $prJobs=[pscustomobject]@{total_count=1;jobs=@([pscustomobject]@{id=77665;run_id=99886;run_attempt=1;head_sha=('e'*40);name=$prProfile.jobName;status='queued';conclusion=$null;runner_id=0;runner_name=$null;runner_group_id=0;started_at=$null;labels=@($prProfile.labels)+@('ci7-run-99886')})}
        Assert ((Get-Ci10Candidate $prProfile $prRun $prJobs).JobId -eq 77665)
        $bad=Clone $prRun; $bad.repository.full_name='LowcountryDigitalWorks/other'; Refuses { Get-Ci10Candidate $prProfile $bad $prJobs } 'WRONG_REPOSITORY'
        $bad=Clone $prRun; $bad.path='.github/workflows/other.yml'; Refuses { Get-Ci10Candidate $prProfile $bad $prJobs } 'WRONG_WORKFLOW'
        $bad=Clone $prRun; $bad.event='workflow_dispatch'; Refuses { Get-Ci10Candidate $prProfile $bad $prJobs } 'WRONG_EVENT_REF_SOURCE'
        $bad=Clone $prJobs; $bad.jobs[0].name='Manual exact-SHA'; Refuses { Get-Ci10Candidate $prProfile $prRun $bad } 'JOB_IDENTITY_MISMATCH'
        $bad=Clone $prJobs; $bad.jobs[0].labels[6]='security-isolated'; Refuses { Get-Ci10Candidate $prProfile $prRun $bad } 'WRONG_LABELS'
        $deployProfile=$profiles | Where-Object id -CEQ 'ci10-royal-dashboard-deploy'
        Refuses { Get-Ci10Candidate $deployProfile $prRun $prJobs ('e'*40) ('d'*40) } 'WRONG_WORKFLOW'
    }
    Check 'accepted Royal deployment profile is exact and pinned' {
        Assert ($royalProfile.repository -ceq 'LowcountryDigitalWorks/royal-cruise-tracker')
        Assert ($royalProfile.workflowPath -ceq '.github/workflows/deploy-dashboard-pr379.yml')
        Assert (@($royalProfile.events).Count -eq 1 -and $royalProfile.events[0] -ceq 'workflow_dispatch')
        Assert ($royalProfile.branch -ceq 'main')
        Assert ($null -eq $royalProfile.headSha)
        Assert ($null -eq $royalProfile.workflowBlobSha)
        Assert ($royalProfile.jobName -ceq 'Manual exact-SHA')
        Assert ($royalProfile.workflowSecrets -eq $true)
        Assert ($royalProfile.docker -eq $false)
        Assert ('royal-isolated' -cin $royalProfile.labels)
    }

    $productionRun=[pscustomobject]@{id=223344; run_attempt=1; status='queued'; conclusion=$null; created_at='2026-10-11T20:00:00Z';
        repository=@{full_name=$production.repository}; head_repository=@{full_name=$production.repository}; path=$production.workflowPath;
        event='pull_request'; head_branch='feature/example'; head_sha=('a'*40)}
    $productionJobs=[pscustomobject]@{total_count=1; jobs=@([pscustomobject]@{id=667788;run_id=223344;run_attempt=1;head_sha=('a'*40);
        name=$production.jobName;status='queued';conclusion=$null;runner_id=0;runner_name=$null;runner_group_id=0;started_at=$null;
        labels=@($production.labels)+@('ci7-run-223344')})}
    Check 'production profile accepts immutable run head' {
        Assert ((Get-Ci10Candidate $production $productionRun $productionJobs).Sha -ceq ('a'*40))
    }

    $royalRun=[pscustomobject]@{id=98765; run_attempt=1; status='queued'; conclusion=$null; created_at='2026-10-11T20:00:00Z';
        repository=@{full_name=$royalProfile.repository}; head_repository=@{full_name=$royalProfile.repository}; path=$royalProfile.workflowPath;
        event='workflow_dispatch'; head_branch='main'; head_sha=('c'*40)}
    $royalJobs=[pscustomobject]@{total_count=1; jobs=@([pscustomobject]@{id=112233;run_id=98765;run_attempt=1;head_sha=('c'*40);
        name='Manual exact-SHA';status='queued';conclusion=$null;runner_id=0;runner_name=$null;runner_group_id=0;started_at=$null;
        labels=@($royalProfile.labels)+@('ci7-run-98765')})}
    Check 'Royal deployment profile accepts exact pinned queued job' {
        Assert ((Get-Ci10Candidate $royalProfile $royalRun $royalJobs ('c'*40) ('d'*40)).JobId -eq 112233)
    }
    Check 'Royal job event mismatch refused' {
        $bad=Clone $royalRun; Check 'missing frozen Royal head refused' { Refuses { Get-Ci10Candidate $royalProfile $royalRun $royalJobs $null ('d'*40) } 'FROZEN_ROYAL_HEAD_REQUIRED' }
Check 'missing frozen Royal blob refused' { Refuses { Get-Ci10Candidate $royalProfile $royalRun $royalJobs ('c'*40) $null } 'FROZEN_ROYAL_WORKFLOW_BLOB_REQUIRED' }
Check 'malformed frozen Royal head refused' { Refuses { Get-Ci10Candidate $royalProfile $royalRun $royalJobs 'bad' ('d'*40) } 'FROZEN_ROYAL_HEAD_REQUIRED' }
Check 'malformed frozen Royal blob refused' { Refuses { Get-Ci10Candidate $royalProfile $royalRun $royalJobs ('c'*40) 'bad' } 'FROZEN_ROYAL_WORKFLOW_BLOB_REQUIRED' }
Check 'known pre-routing Royal pair refused' { Refuses { Get-Ci10Candidate $royalProfile $royalRun $royalJobs 'd77a0e01f42b7ecddd6bce0f7f226288dcc0b11e' '3bfe9fec5fa4ebc10db17d41594ded8878b37064' } 'PRE_ROUTING_ROYAL_PAIR_REFUSED' }
Check 'frozen Royal head mismatch refused' { $bad=Clone $royalRun; $bad.head_sha='e'*40; Refuses { Get-Ci10Candidate $royalProfile $bad $royalJobs ('c'*40) ('d'*40) } 'WRONG_EVENT_REF_SOURCE' }
Check 'Royal profile does not block other queued profiles without invocation pins' { Assert ($null -eq $royalProfile.headSha -and $null -eq $royalProfile.workflowBlobSha) }
Check 'wrong Royal static label refused' { $bad=Clone $royalJobs; $bad.jobs[0].labels[3]='ldw-light'; Refuses { Get-Ci10Candidate $royalProfile $royalRun $bad ('c'*40) ('d'*40) } 'WRONG_LABELS' }
Check 'Royal YAML job id is not the Jobs API name' { $bad=Clone $royalJobs; $bad.jobs[0].name='deploy'; Refuses { Get-Ci10Candidate $royalProfile $royalRun $bad ('c'*40) ('d'*40) } 'JOB_IDENTITY_MISMATCH' }
Check 'wrong Royal job name refused' { $bad=Clone $royalJobs; $bad.jobs[0].name='other'; Refuses { Get-Ci10Candidate $royalProfile $royalRun $bad ('c'*40) ('d'*40) } 'JOB_IDENTITY_MISMATCH' }
$bad.event='push'
        Refuses { Get-Ci10Candidate $royalProfile $bad $royalJobs ('c'*40) ('d'*40) } 'WRONG_EVENT_REF_SOURCE'
    }
    Check 'Royal job branch mismatch refused' {
        $bad=Clone $royalRun; $bad.head_branch='feature/test'
        Refuses { Get-Ci10Candidate $royalProfile $bad $royalJobs ('c'*40) ('d'*40) } 'WRONG_EVENT_REF_SOURCE'
    }
    Check 'Royal job head SHA mismatch refused' {
        $bad=Clone $royalRun; $bad.head_sha='e'*40
        Refuses { Get-Ci10Candidate $royalProfile $bad $royalJobs ('c'*40) ('d'*40) } 'WRONG_EVENT_REF_SOURCE'
    }

    Check 'fork production PR refused' {
        $bad=Clone $productionRun; $bad.head_repository.full_name='LowcountryDigitalWorks/fork'
        Refuses { Get-Ci10Candidate $production $bad $productionJobs } 'WRONG_REPOSITORY'
    }
    Check 'production job commit mismatch refused' {
        $bad=Clone $productionJobs; $bad.jobs[0].head_sha='b'*40
        Refuses { Get-Ci10Candidate $production $productionRun $bad } 'JOB_IDENTITY_MISMATCH'
    }
    Check 'unknown profile is refused' {
        $registry=Get-Content -LiteralPath $profilePath -Raw|ConvertFrom-Json
        $registry.profiles[1].id='ci10-unknown'
        $registry|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $profilePath
        Refuses { Read-Ci10Profiles $profilePath }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../profiles.json') -Destination $profilePath -Force
    }
    $run=[pscustomobject]@{id=12345; run_attempt=2; status='queued'; conclusion=$null; created_at='2026-10-11T20:00:00Z';
        repository=@{full_name=$profile.repository}; head_repository=@{full_name=$profile.repository}; path=$profile.workflowPath;
        event='push'; head_branch=$profile.branch; head_sha=$profile.headSha}
    $jobs=[pscustomobject]@{total_count=1; jobs=@([pscustomobject]@{id=56789;run_id=12345;run_attempt=2;head_sha=$profile.headSha;
        name='synthetic';status='queued';conclusion=$null;runner_id=0;runner_name=$null;runner_group_id=0;started_at=$null;
        labels=@($profile.labels)+@('ci7-run-12345')})}
    Check 'exact reviewed synthetic profile eligible' { Assert ((Get-Ci10Candidate $profile $run $jobs).JobId -eq 56789) }
    foreach($field in @('repository','head_repository')){
        Check ('wrong '+$field+' refused') {$bad=Clone $run;$bad.$field.full_name='LowcountryDigitalWorks/other';Refuses {Get-Ci10Candidate $profile $bad $jobs} 'WRONG_REPOSITORY'}
    }
    Check 'workflow path refused' {$bad=Clone $run;$bad.path='.github/workflows/other.yml';Refuses {Get-Ci10Candidate $profile $bad $jobs} 'WRONG_WORKFLOW'}
    foreach($field in @('event','head_branch','head_sha')){
        Check ('wrong '+$field+' refused') {$bad=Clone $run;$bad.$field='unknown';Refuses {Get-Ci10Candidate $profile $bad $jobs} 'WRONG_EVENT_REF_SOURCE'}
    }
    foreach($status in @('completed','cancelled','in_progress','waiting')){
        Check ('run '+$status+' refused') {$bad=Clone $run;$bad.status=$status;Refuses {Get-Ci10Candidate $profile $bad $jobs} 'RUN_NOT_QUEUED'}
    }
    foreach($status in @('completed','cancelled','in_progress')){
        Check ('job '+$status+' refused') {$bad=Clone $jobs;$bad.jobs[0].status=$status;Refuses {Get-Ci10Candidate $profile $run $bad} 'JOB_NOT_UNASSIGNED_QUEUED'}
    }
    foreach($field in @('runner_id','runner_name','runner_group_id')){
        Check ('assigned '+$field+' refused') {$bad=Clone $jobs;$bad.jobs[0].$field=1;Refuses {Get-Ci10Candidate $profile $run $bad} 'JOB_NOT_UNASSIGNED_QUEUED'}
    }
    Check 'GitHub queued timestamp is not runner assignment' {$good=Clone $jobs;$good.jobs[0].started_at='2026-10-11T20:01:00Z';Assert ((Get-Ci10Candidate $profile $run $good).RunId -eq 12345)}
    foreach($field in @('run_id','run_attempt','head_sha','name')){
        Check ('job drift '+$field+' refused') {$bad=Clone $jobs;$bad.jobs[0].$field='0';Refuses {Get-Ci10Candidate $profile $run $bad} 'JOB_IDENTITY_MISMATCH'}
    }
    Check 'missing static label refused' {$bad=Clone $jobs;$bad.jobs[0].labels=@($bad.jobs[0].labels|Where-Object{$_ -cne 'security-isolated'});Refuses {Get-Ci10Candidate $profile $run $bad} 'WRONG_LABELS'}
    Check 'extra label refused' {$bad=Clone $jobs;$bad.jobs[0].labels+=@('trusted-private');Refuses {Get-Ci10Candidate $profile $run $bad} 'WRONG_LABELS'}
    Check 'wrong dynamic label refused' {$bad=Clone $jobs;$bad.jobs[0].labels[-1]='ci7-run-999';Refuses {Get-Ci10Candidate $profile $run $bad} 'WRONG_LABELS'}
    Check 'duplicate static label refused' {$bad=Clone $jobs;$bad.jobs[0].labels[1]='self-hosted';Refuses {Get-Ci10Candidate $profile $run $bad} 'WRONG_LABELS'}
    Check 'label case drift refused' {$bad=Clone $jobs;$bad.jobs[0].labels[1]='linux';Refuses {Get-Ci10Candidate $profile $run $bad} 'WRONG_LABELS'}
    Check 'multiple jobs refused' {$bad=Clone $jobs;$bad.total_count=2;$bad.jobs+=@(Clone $bad.jobs[0]);Refuses {Get-Ci10Candidate $profile $run $bad} 'EXACTLY_ONE_JOB_REQUIRED'}
    Check 'truncated job count refused' {$bad=Clone $jobs;$bad.total_count=101;Refuses {Get-Ci10Candidate $profile $run $bad} 'EXACTLY_ONE_JOB_REQUIRED'}
    Check 'run conclusion refused' {$bad=Clone $run;$bad.conclusion='cancelled';Refuses {Get-Ci10Candidate $profile $bad $jobs} 'RUN_NOT_QUEUED'}
    Check 'job conclusion refused' {$bad=Clone $jobs;$bad.jobs[0].conclusion='success';Refuses {Get-Ci10Candidate $profile $run $bad} 'JOB_NOT_UNASSIGNED_QUEUED'}
    Check 'invalid creation time refused' {$bad=Clone $run;$bad.created_at='invalid';Refuses {Get-Ci10Candidate $profile $bad $jobs} 'RUN_TIME_INVALID'}
    $candidate=Get-Ci10Candidate $profile $run $jobs
    Check 'oldest candidate first, ID tie deterministic' {
        $second=Clone $candidate;$second.RunId=54321;$second.CreatedUtc=([datetime]'2026-10-11T21:00:00Z').ToUniversalTime()
        Assert ((Select-Ci10Oldest @($second,$candidate)).RunId -eq 12345)
        $second.CreatedUtc=$candidate.CreatedUtc
        Assert ((Select-Ci10Oldest @($second,$candidate)).RunId -eq 12345)
    }
    Check 'duplicate candidate policy refused' {Refuses {Select-Ci10Oldest @($candidate,$candidate)} 'DUPLICATE_CANDIDATE_REFUSED'}
    foreach($field in @('repository','workflowPath','headSha','controllerProfile','egress','docker','workflowSecrets','privateProductionState','cpu','memoryMiB','timeoutMinutes','dynamicLabel','jobCount')){
        Check ('profile drift '+$field+' refused') {
            $registry=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../profiles.json') -Raw|ConvertFrom-Json
            $registry.profiles[0].$field=if($field -in @('docker','privateProductionState')){$true}else{'unknown'}
            $registry|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $profilePath
            Refuses {Read-Ci10Profiles $profilePath}
        }
    }
    Check 'API scope refuses unrelated repo before request' {Refuses {Invoke-Ci10Read 'repos/LowcountryDigitalWorks/unapproved-repo/actions/runs'} 'API_SCOPE_REFUSED'}
    & $module {
        param($r,$j)
        $script:RunFixture=$r;$script:JobFixture=$j;$script:Calls=[Collections.Generic.List[string]]::new()
        $script:QueueRuns=@();$script:QueueJobs=@{};$script:QueueTotalCount=$null
        function script:Invoke-Ci10Read([string]$Path){
            $script:Calls.Add($Path)
            if($Path.Contains('business-operations') -or $Path.Contains('royal-cruise-tracker')){return [pscustomobject]@{total_count=0;workflow_runs=@()}}
            if($Path.Contains('/workflows/')){
                $runs=if($script:QueueRuns.Count){@($script:QueueRuns)}else{@($script:RunFixture)}
                $count=if($null -ne $script:QueueTotalCount){$script:QueueTotalCount}else{$runs.Count}
                return [pscustomobject]@{total_count=$count;workflow_runs=$runs}
            }
            if($Path.Contains('/jobs?')){
                $runId=[long]([regex]::Match($Path,'/runs/(\d+)/jobs').Groups[1].Value)
                if($script:QueueJobs.ContainsKey($runId)){return $script:QueueJobs[$runId]}
                return $script:JobFixture
            }
            return $script:RunFixture
        }
    } $run $jobs
    Check 'scoped queue discovers without input run ID' {Assert ((Find-Ci10QueuedJob $profiles).RunId -eq 12345)}
    Check 'fresh queue snapshot returns bounded selected identity and counts' {
        $snapshot=Get-Ci10QueueSnapshot @($profile)
        Assert ($snapshot.QueueState -ceq 'FRESH' -and $snapshot.EligibleQueuedCount -eq 1 -and $snapshot.HeldQueuedCount -eq 0)
        Assert ($snapshot.Selected.ProfileId -ceq $profile.id -and $snapshot.Selected.RunId -eq 12345 -and $snapshot.Selected.JobId -eq 56789)
        Assert (@($snapshot.PSObject.Properties.Name | Sort-Object) -join ',' -ceq 'EligibleQueuedCount,HeldQueuedCount,HeldReasonCounts,QueueState,Schema,Selected')
        $json=$snapshot|ConvertTo-Json -Depth 6 -Compress
        Assert ($json -notmatch 'head_sha|head_branch|labels|workflowPath|private|token|credential|created_at')
    }
    Check 'snapshot and dispatcher share the same selected eligible candidate' {
        $snapshot=Get-Ci10QueueSnapshot @($profile)
        $dispatch=Find-Ci10QueuedJob @($profile)
        Assert ($snapshot.EligibleQueuedCount -eq 1 -and $snapshot.Selected.RunId -eq $dispatch.RunId -and $snapshot.Selected.JobId -eq $dispatch.JobId)
    }
    Check 'held candidate excluded from eligible count with bounded reason class' {
        & $module {$script:RunFixture.head_branch='wrong-branch'}
        $snapshot=Get-Ci10QueueSnapshot @($profile)
        Assert ($snapshot.QueueState -ceq 'FRESH' -and $snapshot.EligibleQueuedCount -eq 0 -and $snapshot.HeldQueuedCount -eq 1)
        Assert ($snapshot.HeldReasonCounts.Count -eq 1 -and $snapshot.HeldReasonCounts[0].ReasonCode -ceq 'IDENTITY_MISMATCH')
        & $module {$script:RunFixture.head_branch='feat/ci-runner-ephemeral-001'}
    }
    Check 'unavailable provider never becomes fresh zero' {
        & $module {function script:Invoke-Ci10Read {throw 'API_READ_FAILED'}}
        $snapshot=Get-Ci10QueueSnapshot @($profile)
        Assert ($snapshot.QueueState -ceq 'UNAVAILABLE' -and $null -eq $snapshot.EligibleQueuedCount -and $null -eq $snapshot.HeldQueuedCount)
        Refuses {Find-Ci10QueuedJob @($profile)} 'API_READ_FAILED'
    }
    # Restore the synthetic GET fixture after the unavailable-provider proof.
    & $module {
        function script:Invoke-Ci10Read([string]$Path){
            $script:Calls.Add($Path)
            if($Path.Contains('business-operations') -or $Path.Contains('royal-cruise-tracker')){return [pscustomobject]@{total_count=0;workflow_runs=@()}}
            if($Path.Contains('/workflows/')){
                $runs=if($script:QueueRuns.Count){@($script:QueueRuns)}else{@($script:RunFixture)}
                $count=if($null -ne $script:QueueTotalCount){$script:QueueTotalCount}else{$runs.Count}
                return [pscustomobject]@{total_count=$count;workflow_runs=$runs}
            }
            if($Path.Contains('/jobs?')){
                $runId=[long]([regex]::Match($Path,'/runs/(\d+)/jobs').Groups[1].Value)
                if($script:QueueJobs.ContainsKey($runId)){return $script:QueueJobs[$runId]}
                return $script:JobFixture
            }
            return $script:RunFixture
        }
    }
    Check 'accepted profile scope is enforced before any provider read' {
        $bad=Clone $profile;$bad.repository='LowcountryDigitalWorks/unapproved'
        & $module {$script:Calls.Clear()}
        Refuses {Get-Ci10QueueSnapshot @($bad)} 'PROFILE_SCOPE_REFUSED'
        & $module {Assert ($script:Calls.Count -eq 0)}
    }
    Check 'advertised queue beyond 300 runs fails closed' {
        & $module {$script:QueueTotalCount=301}
        Refuses {Get-Ci10QueueSnapshot @($profile)} 'QUEUE_BOUND_EXCEEDED'
        & $module {$script:QueueTotalCount=$null}
    }
    Check 'duplicate run across queue pages is refused' {
        & $module {$script:QueueRuns=@($script:RunFixture,$script:RunFixture)}
        Refuses {Get-Ci10QueueSnapshot @($profile)} 'QUEUE_PAGE_RACE_REFUSED'
        & $module {$script:QueueRuns=@()}
    }
    Check 'projection source remains GET-only and cannot enter controller paths' {
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Dispatch.psm1') -Raw
        $core=$source.Substring($source.IndexOf('function Get-QueueSnapshotCore {'),$source.IndexOf('function Get-Ci10QueueSnapshot {')-$source.IndexOf('function Get-QueueSnapshotCore {'))
        Assert ($core -notmatch 'Confirm-Ci10Candidate|Start-Ci10Controller|Invoke-IsolatedRunner|Get-VM|Remove-VM|/cancel|--method\s+POST|Recover|Cleanup')
        Assert ($core -match 'Invoke-Ci10Read')
    }
    Check 'fresh selected run and job reread' {Assert ((Confirm-Ci10Candidate $candidate).JobId -eq 56789)}
    Check 'latest-attempt race refused' {
        & $module {$script:RunFixture.run_attempt=3}
        Refuses {Confirm-Ci10Candidate $candidate} 'JOB_IDENTITY_MISMATCH'
        & $module {$script:RunFixture.run_attempt=2}
    }
    Check 'changed job after selection refused' {
        & $module {$script:JobFixture.jobs[0].id=99999}
        Refuses {Confirm-Ci10Candidate $candidate} 'SELECTED_JOB_DRIFT'
        & $module {$script:JobFixture.jobs[0].id=56789}
    }
    Check 'unrelated queued jobs stay untouched, GET-only surface' {
        & $module {$script:RunFixture.head_branch='other'}
        Assert (@(Find-Ci10QueuedJob $profiles).Count -eq 0)
        & $module {$script:RunFixture.head_branch='feat/ci-runner-ephemeral-001'}
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Dispatch.psm1') -Raw
        Assert (-not $source.Contains('/cancel'))
        Assert (-not $source.Contains('--method POST'))
    }
    Check 'API failure propagates, no eligibility fallback' {
        & $module {function script:Invoke-Ci10Read {throw 'API_READ_FAILED'}}
        Refuses {Find-Ci10QueuedJob $profiles} 'API_READ_FAILED'
    }
    # Fresh module removes queue fixture overrides before testing actual file locks and ownership guards.
    $module=Import-Module (Join-Path $PSScriptRoot '../Dispatch.psm1') -Force -PassThru
    Check 'dispatcher exclusive lock and interruption release' {
        $held=Enter-Ci10DispatcherLock $fixture
        try {Refuses {Enter-Ci10DispatcherLock $fixture} 'DISPATCHER_BUSY_OR_LOCK_UNCERTAIN'} finally {$held.Dispose()}
        $again=Enter-Ci10DispatcherLock $fixture;$again.Dispose()
    }
    $controllerRoot=Join-Path $fixture 'CiRunnerEphemeral'
    Initialize-Ci7Root $controllerRoot
    & $module {
        $script:VMFixture=@();$script:CapacityBlocked=$false
        function script:Get-VM {@($script:VMFixture)}
        function script:Invoke-Ci10Read {[pscustomobject]@{total_count=0;runners=@()}}
        function script:Assert-Ci7Capacity {if($script:CapacityBlocked){throw 'CAPACITY_RAM_RESERVE_4GIB_REQUIRED'}}
    }
    Check 'global accepted controller lock refuses second dispatch' {
        $held=Enter-Ci7ControllerLock $controllerRoot
        try {Assert ((Get-Ci10ControllerGate $controllerRoot $profile) -ceq 'BUSY')} finally {$held.Dispose()}
    }
    Check 'capacity unavailable leaves queue untouched' {
        & $module {$script:CapacityBlocked=$true}
        Assert ((Get-Ci10ControllerGate $controllerRoot $profile) -ceq 'CAPACITY')
        & $module {$script:CapacityBlocked=$false}
    }
    Check 'unrelated ci7-looking VM refused, no deletion' {
        & $module {$script:VMFixture=@([pscustomobject]@{Name='ci7-unrelated';VMId='unrelated'})}
        Refuses {Get-Ci10ControllerGate $controllerRoot $profile} 'ORPHAN_VM_REQUIRES_CONCLUSIVE_STATE'
        & $module {$script:VMFixture=@()}
    }
    $configuration=New-Ci7Configuration -Repository $profile.repository -WorkflowRunId 12345 -ExpectedSha $profile.headSha -Root $controllerRoot -AllowPublicSyntheticProof
    $state=New-Ci7State $configuration ('c'*32)
    $null=New-Item -ItemType Directory -Path $state.Directory
    Save-Ci7State $state
    Check 'strict accepted stale state classified for Reap' {Assert ((Get-Ci10ControllerGate $controllerRoot $profile) -ceq 'STALE')}
    Check 'cleanup snapshots only exact reviewed stale run IDs' {Assert (@(Get-Ci10StaleRunIds $controllerRoot $profile)[0] -ceq ('c'*32))}
    Check 'active per-run lock refuses recovery race' {
        $held=[IO.File]::Open((Join-Path $state.Directory 'controller.lock'),'OpenOrCreate','ReadWrite','None')
        try {Assert ((Get-Ci10ControllerGate $controllerRoot $profile) -ceq 'BUSY')} finally {$held.Dispose()}
    }
    Check 'stale other profile refused' {
        $bad=Clone $state;$bad.Configuration.ExpectedSha='a'*40;Save-Ci7State $bad
        Refuses {Get-Ci10ControllerGate $controllerRoot $profile} 'STALE_PROFILE_OWNERSHIP_REFUSED'
        Refuses {Get-Ci10StaleRunIds $controllerRoot $profile} 'STALE_PROFILE_OWNERSHIP_REFUSED'
        Save-Ci7State $state
    }
    Check 'ambiguous stale marker refused' {
        $bad=Clone $state;$bad.Marker='other';$bad|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $state.Directory 'state.json')
        Refuses {Get-Ci10ControllerGate $controllerRoot $profile} 'RESOURCE_OWNERSHIP_AMBIGUOUS'
        Save-Ci7State $state
    }
    Check 'persistent runner cannot be dispatcher-owned state' {
        $bad=Clone $state;$bad.Name='ldw01-ci-01';$bad|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $state.Directory 'state.json')
        Refuses {Get-Ci10ControllerGate $controllerRoot $profile} 'RESOURCE_OWNERSHIP_AMBIGUOUS'
        Save-Ci7State $state
    }
    $secure=Join-Path $fixture 'secure';Protect $secure
    $releaseRoot=Join-Path $secure 'dispatcher';Protect $releaseRoot
    $releases=Join-Path $releaseRoot 'releases';Protect $releases
    $bundle=Join-Path $releases ('a'*40);Protect $bundle
    $runtimeArchive=Join-Path $fixture 'manifest-runtime.zip'
    & git -C $repo archive --format=zip ('--output='+$runtimeArchive) HEAD -- @(Get-Ci10RuntimeFiles) 2>$null
    if($LASTEXITCODE -ne 0){throw 'TEST_RUNTIME_ARCHIVE_FAILED'}
    [IO.Compression.ZipFile]::ExtractToDirectory($runtimeArchive,$bundle)
    Remove-Item -LiteralPath $runtimeArchive -Force
    $royalController=Join-Path $fixture 'manifest-royal-controller'
    New-Item -ItemType Directory -Path $royalController -Force|Out-Null
    New-ControllerFixture '54b9343af44c70db1d1403cf7f45cfc11e8bf167' $royalController
    foreach($path in @(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')})){
        Copy-Item -LiteralPath (Join-Path $royalController $path) -Destination (Join-Path $bundle $path) -Force
    }
    Copy-AcceptedDispatcherFixture (Join-Path $bundle 'ci-dispatch/Dispatch.psm1')
    $dispatcherProvenance=Get-Content -LiteralPath (Join-Path $bundle 'ci-dispatch/verifier-provenance.json') -Raw|ConvertFrom-Json
    $manifest=[ordered]@{schema=1;commit=('a'*40);tree=('b'*40);dispatcher=$dispatcherProvenance;controllerCommit='54b9343af44c70db1d1403cf7f45cfc11e8bf167';
        controllerTree='beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec';files=@(Get-Ci10RuntimeFiles|ForEach-Object{
            [ordered]@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $bundle $_) -Algorithm SHA256).Hash.ToLowerInvariant()}
        })}
    $manifestFile=Join-Path $bundle 'manifest.json'
    $manifest|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $manifestFile -Encoding utf8NoBOM
    if ($env:OS -eq 'Windows_NT') {
        foreach($item in @(Get-ChildItem -LiteralPath $bundle -Recurse -Force)){
            $acl=Get-Acl -LiteralPath $item.FullName;$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));Set-Acl -LiteralPath $item.FullName -AclObject $acl
        }
    }
    $manifestSha=(Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash.ToLowerInvariant()
    Check 'manifest controller identity equals exact matched Royal snapshot' {
        $null=Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)
        Assert ($manifest.controllerCommit -ceq '54b9343af44c70db1d1403cf7f45cfc11e8bf167' -and
            $manifest.controllerTree -ceq 'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec')
    }
    if ($env:OS -eq 'Windows_NT') {
        Check 'protected exact bundle verifies' {$null=Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)}
        Check 'dispatcher file hash drift refused' {
            $file=Join-Path $bundle 'ci-dispatch/Dispatch.psm1';$original=[IO.File]::ReadAllBytes($file)
            [IO.File]::AppendAllText($file,'# drift')
            try {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)} 'BUNDLE_VERIFIER_HASH_DRIFT'} finally {[IO.File]::WriteAllBytes($file,$original)}
        }
        Check 'controller file hash drift refused' {
            $file=Join-Path $bundle 'ci-runner/Native.cs';$original=[IO.File]::ReadAllBytes($file)
            [IO.File]::AppendAllText($file,'// drift')
            try {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)} 'BUNDLE_FILE_HASH_DRIFT'} finally {[IO.File]::WriteAllBytes($file,$original)}
        }
        Check 'manifest hash drift refused' {
            [IO.File]::AppendAllText($manifestFile,' ')
            try {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)} 'MANIFEST_HASH_DRIFT'} finally {$manifest|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $manifestFile -Encoding utf8NoBOM}
        }
        Check 'missing runtime file refused' {
            $file=Join-Path $bundle 'ci-runner/Native.cs';$original=[IO.File]::ReadAllBytes($file);Remove-Item -LiteralPath $file
            try {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)} 'BUNDLE_FILE_SET_DRIFT'} finally {
                [IO.File]::WriteAllBytes($file,$original);$acl=Get-Acl -LiteralPath $file;$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));Set-Acl -LiteralPath $file -AclObject $acl
            }
        }
        Check 'extra executable refused' {
            $file=Join-Path $bundle 'extra.ps1';[IO.File]::WriteAllText($file,'exit 0')
            try {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)} 'BUNDLE_FILE_SET_DRIFT'} finally {Remove-Item -LiteralPath $file}
        }
        Check 'dispatcher commit provenance mismatch refused' {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('c'*40) ('b'*40)} 'BUNDLE_PROVENANCE_MISMATCH'}
        Check 'tree provenance mismatch refused' {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('c'*40)} 'BUNDLE_PROVENANCE_MISMATCH'}
        Check 'controller provenance mismatch refused' {
            $bad=Clone $manifest;$bad.controllerCommit='c'*40;$bad|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $manifestFile -Encoding utf8NoBOM
            $hash=(Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash.ToLowerInvariant()
            try {Refuses {Assert-Ci10Bundle $bundle $hash ('a'*40) ('b'*40)} 'BUNDLE_PROVENANCE_MISMATCH'} finally {$manifest|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $manifestFile -Encoding utf8NoBOM}
        }
        Check 'untrusted write ACL refused' {
            $file=Join-Path $bundle 'ci-runner/Native.cs';$originalAcl=Get-Acl -LiteralPath $file;$badAcl=Get-Acl -LiteralPath $file
            $badAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Write','Allow'))
            Set-Acl -LiteralPath $file -AclObject $badAcl
            try {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)} 'BUNDLE_ACL_UNTRUSTED_WRITE'} finally {Set-Acl -LiteralPath $file -AclObject $originalAcl}
        }
        Check 'parent directory replacement authority refused' {
            $originalAcl=Get-Acl -LiteralPath $secure;$badAcl=Get-Acl -LiteralPath $secure
            $badAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'DeleteSubdirectoriesAndFiles','Allow'))
            Set-Acl -LiteralPath $secure -AclObject $badAcl
            try {Refuses {Assert-Ci10Bundle $bundle $manifestSha ('a'*40) ('b'*40)} 'BUNDLE_PARENT_REPLACEMENT_UNTRUSTED'} finally {Set-Acl -LiteralPath $secure -AclObject $originalAcl}
        }
    }
    Check 'bounded sanitized diagnostic schema' {
        Write-Ci10Log $fixture selected -ProfileId 'ci10-royal-dashboard-deploy' -RunId 12345
        $record=Get-Content -LiteralPath (Join-Path $fixture 'dispatcher.jsonl')|Select-Object -Last 1|ConvertFrom-Json
        Assert (@(Compare-Object @('utc','phase','profile','run') @($record.PSObject.Properties.Name)).Count -eq 0)
        Assert ($record.phase -ceq 'selected' -and $record.profile -ceq 'ci10-royal-dashboard-deploy' -and $record.run -eq 12345)
        Refuses {Write-Ci10Log $fixture 'secret-raw-value'}
        Refuses {Write-Ci10Log $fixture selected -ProfileId 'private-state'}
    }
    Check 'bounded log rotation three files' {
        $file=Join-Path $fixture 'dispatcher.jsonl'
        for($i=0;$i -lt 4;$i++){[IO.File]::WriteAllText($file,'x'*262145);Write-Ci10Log $fixture poll-pass}
        Assert (@(Get-ChildItem -LiteralPath $fixture -Filter 'dispatcher.jsonl*').Count -eq 3)
        Assert ((Get-Item -LiteralPath $file).Length -lt 1024)
    }
    Check 'no credentials, mounts, Docker, listener or production profile in dispatcher' {
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Dispatch.psm1') -Raw
        Assert (-not ($source -match 'gh auth token|GH_TOKEN|GITHUB_TOKEN|EncodedCommand|HttpListener|New-PSSession|docker.sock|Mount-VM'))
        Assert ($source.Contains('CopyToAsync([IO.Stream]::Null)'))
        Assert (-not $source.Contains('Stop-Process'))
    }
    Check 'task install and enable require explicit later acceptance' {
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Manage-Task.ps1') -Raw
        Assert (([regex]::Matches($source,'if \(-not \$OwnerAccepted\)')).Count -eq 2)
        Assert ($source.Contains('-LogonType Interactive -RunLevel Highest'))
        Assert ($source.Contains('-MultipleInstances IgnoreNew'))
        Assert ($source.Contains('-Mode Recover'))
        Assert (-not ($source -match 'Password|GH_TOKEN|GITHUB_TOKEN|auth token|Export-Clixml'))
    }
    Check 'interruption hold is bounded and discovery-only' {
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Invoke-Dispatcher.ps1') -Raw
        Assert ($source.Contains('[ValidateRange(0,30)][int]$DiscoverHoldSeconds = 0'))
        Assert ($source.Contains("throw 'DISCOVERY_HOLD_REQUIRES_DISCOVER_MODE'"))
        Assert ($source.Contains('if ($Mode -eq ''Discover'')'))
    }
    Check 'recovery delegates exact IDs to accepted Cleanup, never root-wide Reap' {
        $entry=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Invoke-Dispatcher.ps1') -Raw
        $moduleSource=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Dispatch.psm1') -Raw
        Assert ($entry.Contains('-CleanupRunId $runId'))
        Assert ($moduleSource.Contains("`$info.ArgumentList.Add('-LocalRunId')"))
        Assert (-not $entry.Contains('-Reap'))
    }
    'NEW_DISPATCHER_TESTS=PASS';'NEW_TEST_COUNT='+$total
} catch {
    'NEW_DISPATCHER_TESTS=FAIL';'NEW_TEST_COUNT='+$total
    'TEST_CASE='+$script:case
    'TEST_FAILURE_LINE='+$_.InvocationInfo.ScriptLineNumber
    $code=[string]$_.Exception.Message
    if($code -cnotmatch '^[A-Z][A-Z0-9_]+$'){$code='TEST_OPERATION_FAILED'}
    'CLASSIFICATION='+$code
    exit 1
} finally {
    # Exact random fixture only; check every descendant before recursive deletion.
    if(Test-Path -LiteralPath $fixture){
        $resolved=[IO.Path]::GetFullPath($fixture)
        $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
        if(-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -cnotmatch '^ci10-test-[a-f0-9]{32}$'){throw 'TEST_CLEANUP_ROOT_INVALID'}
        foreach($item in @(Get-ChildItem -LiteralPath $resolved -Recurse -Force)){Assert-Ci7Path $resolved $item.FullName}
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
