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
    $config = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/business-operations' -WorkflowRunId 12345 -ExpectedSha ('a' * 40) -Root $root
    $state = New-Ci7State $config ('b' * 32)
    [void](New-Item -ItemType Directory -Path $state.Directory)
    Check 'exact resource ownership and safe paths' {
        Assert-Ci7State $state $root
        Assert ($state.Name -ceq ('ci7-' + ('b' * 32)))
        Refuses { New-Ci7State $config '../escape' }
        Refuses { Assert-Ci7Path $root (Join-Path $root '../unrelated.vhdx') }
        $bad = $state | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $bad.Disk = Join-Path $root 'base/golden.vhdx'
        Refuses { Assert-Ci7State $bad $root }
    }
    Check 'bounded repository allowlist and explicit public proof exception' {
        Refuses { New-Ci7Configuration -Repository 'another-org/repo' -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root }
        Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/infrastructure-tools' -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root }
        Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/business-operations' -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root -AllowPublicSyntheticProof }
        $public = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/infrastructure-tools' -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root -AllowPublicSyntheticProof
        Assert $public.PublicSyntheticProof
        Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -ApprovedRepositories @('LowcountryDigitalWorks/wqt-operations') -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root }
    }
    Check 'configuration bounds and exact revision validation' {
        foreach ($memory in @(0,1024,4097)) { Refuses { New-Ci7Configuration -Repository $config.Repository -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root -MemoryMiB $memory } }
        Refuses { New-Ci7Configuration -Repository $config.Repository -WorkflowRunId 1 -ExpectedSha main -Root $root }
        Refuses { New-Ci7Configuration -Repository $config.Repository -WorkflowRunId 0 -ExpectedSha ('a' * 40) -Root $root }
        Refuses { New-Ci7Configuration -Repository $config.Repository -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root -CpuCount 3 }
        Refuses { New-Ci7Configuration -Repository $config.Repository -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root -TimeoutMinutes 31 }
    }
    Check 'global controller lock prevents concurrent provisioning or reap' {
        $first=Enter-Ci7ControllerLock $root
        try { Refuses {Enter-Ci7ControllerLock $root} } finally {$first.Dispose()}
        $second=Enter-Ci7ControllerLock $root
        $second.Dispose()
        Assert ((Get-Item -LiteralPath (Join-Path $root 'control.lock')).Length -eq 0)
    }
    Check 'persistent baseline comparison ignores JSON key order but detects changes' {
        $left = '{"vm":{"cpu":2,"disks":["owned"]},"runner":21}' | ConvertFrom-Json -AsHashtable
        $right = '{"runner":21,"vm":{"disks":["owned"],"cpu":2}}' | ConvertFrom-Json -AsHashtable
        Assert (Test-Ci7EquivalentData $left $right)
        $right.vm.cpu = 3; Assert (-not (Test-Ci7EquivalentData $left $right))
        $right.vm.cpu = 2; $right.vm.disks = @('unrelated'); Assert (-not (Test-Ci7EquivalentData $left $right))
    }
    Check 'isolation labels exclude persistent runner labels' {
        $labels = @(Get-Ci7Labels 12345)
        Assert ($labels.Count -eq 8)
        Assert (@(Compare-Object $labels @('self-hosted','Linux','X64','ldw01','ldw-ephemeral','ldw-isolated','security-isolated','ci7-run-12345') -CaseSensitive).Count -eq 0)
        Assert ('ldw-light' -cnotin $labels -and 'trusted-private' -cnotin $labels)
        Refuses { Get-Ci7Labels 0 }
    }
    Check 'one-job state machine refuses replay and skipped phases' {
        $lifecycle = New-Ci7State $config
        Refuses { Move-Ci7Phase $lifecycle Running }
        foreach ($phase in @('Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved','Complete')) { Move-Ci7Phase $lifecycle $phase }
        Refuses { Move-Ci7Phase $lifecycle Running }
        Refuses { Move-Ci7Phase $lifecycle Complete }
    }
    Check 'Hyper-V command bindings match the installed management module' {
        foreach ($source in @('../CiRunner.psm1','../Invoke-IsolatedRunner.ps1','../Prepare-Base.ps1')) {
            $tokens=$null; $errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $source),[ref]$tokens,[ref]$errors)
            Assert ($errors.Count -eq 0)
            if (Get-Command 'Get-VHD' -ErrorAction SilentlyContinue) {
                $commands=$ast.FindAll({param($node); $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -match '^(Get|Set|New|Start|Stop|Remove|Add|Disable|Convert)-(VM|VHD)'},$true)
                foreach($call in $commands){
                    $definition=Get-Command $call.GetCommandName() -ErrorAction Stop
                    foreach($element in $call.CommandElements|Where-Object{$_ -is [Management.Automation.Language.CommandParameterAst]}){
                        Assert ($definition.Parameters.ContainsKey($element.ParameterName))
                    }
                }
            }
        }
    }
    Check 'JIT is ephemeral with auto-update disabled and correct repository' {
        $state.RunnerId = 42
        $runner = @{ agentName = $state.Name; agentId = 42; gitHubUrl = 'https://github.com/' + $config.Repository; ephemeral = $true; disableUpdate = $true }
        $encoded = @{ '.runner' = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($runner | ConvertTo-Json))) } | ConvertTo-Json
        $jit = @{ encoded_jit_config = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($encoded)) }
        Assert-Ci7JitContract $state $jit
        $runner.ephemeral = $false
        $encoded = @{ '.runner' = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($runner | ConvertTo-Json))) } | ConvertTo-Json
        $jit.encoded_jit_config = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($encoded))
        Refuses { Assert-Ci7JitContract $state $jit }
        Refuses { Assert-Ci7JitContract $state @{ encoded_jit_config = 'invalid' } }
    }
    Check 'diagnostics whitelist excludes secrets and private state' {
        $sentinel = 'synthetic-secret-sentinel-DO-NOT-LOG'
        $state | Add-Member -NotePropertyName TestJit -NotePropertyValue $sentinel
        Write-Ci7Evidence $state registered
        $log = Get-Content -LiteralPath (Join-Path $root ('evidence/' + $state.RunId + '.jsonl')) -Raw
        Assert (-not $log.Contains($sentinel) -and -not $log.Contains($root) -and -not $log.Contains($config.Repository))
        $entry = $log | ConvertFrom-Json
        Assert (@($entry.PSObject.Properties.Name).Count -eq 3)
        Refuses { Write-Ci7Evidence $state $sentinel }
    }
    Check 'refusal to delete persistent or ambiguous VM identity' {
        $state.VMId = [guid]::NewGuid().ToString()
        $owned = [pscustomobject]@{ VMId = $state.VMId; Name = $state.Name; Notes = 'CI-RUNNER-EPHEMERAL-001:' + $state.RunId }
        Assert-Ci7OwnedVm $state $owned
        $owned.Name = 'CI-RUNNER-001'; Refuses { Assert-Ci7OwnedVm $state $owned }
        $owned.Name = $state.Name; $owned.Notes = ''; Refuses { Assert-Ci7OwnedVm $state $owned }
        $owned.Notes = 'CI-RUNNER-EPHEMERAL-001:' + $state.RunId; $owned.VMId = [guid]::NewGuid().ToString(); Refuses { Assert-Ci7OwnedVm $state $owned }
    }
    & $module {
        param($cfg)
        $script:ApiTestRepo=[pscustomobject]@{private=$true}
        $script:ApiTestRun=[pscustomobject]@{head_sha=$cfg.ExpectedSha;path=$cfg.WorkflowPath;repository=[pscustomobject]@{full_name=$cfg.Repository};head_repository=[pscustomobject]@{full_name=$cfg.Repository};event='push';head_branch='main'}
        $script:ApiTestJob=[pscustomobject]@{id=10;status='queued';runner_id=0;labels=@(Get-Ci7Labels $cfg.WorkflowRunId $cfg)}
        $script:ApiTestCount=1
        function script:Invoke-Ci7Api {param($Path,$Method='GET',$Body); if($Path -match '/jobs\?'){[pscustomobject]@{total_count=$script:ApiTestCount;jobs=@($script:ApiTestJob)}}elseif($Path -match '/actions/runs/'){$script:ApiTestRun}else{$script:ApiTestRepo}}
    } $config
    Check 'exact queued-job routing refuses source, labels, privacy and job-count drift' {
        Assert ((Get-Ci7ExpectedJob $config -RequireQueued).id -eq 10)
        & $module {$script:ApiTestRun.head_sha='c'*40}; Refuses {Get-Ci7ExpectedJob $config}
        & $module {param($cfg);$script:ApiTestRun.head_sha=$cfg.ExpectedSha;$script:ApiTestRun.head_repository.full_name='untrusted/fork'} $config
        Refuses {Get-Ci7ExpectedJob $config}
        & $module {param($cfg);$script:ApiTestRun.head_repository.full_name=$cfg.Repository;$script:ApiTestRepo.private=$false} $config
        Refuses {Get-Ci7ExpectedJob $config}
        & $module {$script:ApiTestRepo.private=$true;$script:ApiTestCount=2}; Refuses {Get-Ci7ExpectedJob $config}
        & $module {$script:ApiTestCount=1;$script:ApiTestJob.runner_id=42}; Refuses {Get-Ci7ExpectedJob $config -RequireQueued}
        & $module {$script:ApiTestJob.runner_id=0;$script:ApiTestJob.labels=@('self-hosted','ldw-light')}; Refuses {Get-Ci7ExpectedJob $config}
    }

    Check 'non-WQT cleanup preserves optional identity and exact expected-job ID path' {
        & $module {param($cfg);$script:ApiTestJob.labels=@(Get-Ci7Labels $cfg.WorkflowRunId $cfg)} $config
        Assert (-not $config.ProfileId -and $config.RunAttempt -eq 0 -and $config.ExpectedJobId -eq 0)
        $legacyState = New-Ci7State $config ('c' * 32)
        $legacyState.JobId = 10
        Assert ((Get-Ci7CleanupJob $legacyState).id -eq 10)
        & $module {$script:ApiTestJob.id=11}
        Refuses { Get-Ci7CleanupJob $legacyState }
        & $module {$script:ApiTestJob.id=10}
    }

    Check 'closed WQT profile rejects non-exact identity, graph, and attempt inputs' {
        $sha='a'*40; $blobSha='b'*40; $runId=88001
        $profiles=@(& $module { Get-Ci7ClosedProfiles })
        Assert ($profiles.Count -eq 3)
        Assert ($profiles[0].ReadPermissions -join ',' -ceq 'contents:read')
        Assert ($profiles[2].ReadPermissions -join ',' -ceq 'contents:read,actions:read')
        foreach($closed in $profiles){Assert (-not $closed.WorkflowSecrets -and -not $closed.PrivateProductionState -and -not $closed.Docker)}
        $profile=@($profiles | Where-Object ProfileId -CEQ 'wqt-validation')[0]
        $wqt=New-Ci7Configuration -Repository $profile.Repository -ApprovedRepositories @($profile.Repository) -WorkflowRunId $runId -ExpectedSha $sha -WorkflowPath $profile.WorkflowPath -WorkflowBlobSha $blobSha -ExpectedJobName $profile.JobName -ProfileId $profile.ProfileId -RunAttempt 2 -ExpectedJobId 501 -Root $root
        Assert ('wqt-validation' -cin $wqt.StaticLabels)
        Assert ($wqt.ReadPermissions -join ',' -ceq 'contents:read' -and -not $wqt.WorkflowSecrets -and -not $wqt.PrivateProductionState -and -not $wqt.Docker)
        & $module {
            param($c,$sha,$blobSha)
            $script:WqtRepo=[pscustomobject]@{private=$true}; $script:WqtBlob=[pscustomobject]@{sha=$blobSha}
            $script:WqtRun=[pscustomobject]@{id=$c.WorkflowRunId;status='in_progress';conclusion=$null;run_attempt=2;head_sha=$sha;path=$c.WorkflowPath;repository=[pscustomobject]@{full_name=$c.Repository};head_repository=[pscustomobject]@{full_name=$c.Repository};event='pull_request';pull_requests=@([pscustomobject]@{head=[pscustomobject]@{sha=$sha}})}
            $script:WqtJob=[pscustomobject]@{id=501;name='validate-pr';run_id=$c.WorkflowRunId;run_attempt=2;head_sha=$sha;status='queued';runner_id=0;runner_name=$null;runner_group_id=0;labels=@(Get-Ci7Labels $c.WorkflowRunId $c)}
            $script:WqtJobs=@($script:WqtJob,[pscustomobject]@{id=502;name='validate-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=503;name='scan';status='completed';conclusion='skipped'})
            function script:Invoke-Ci7Api {param($Path,$Method='GET',$Body); if($Path -match '/jobs\?'){[pscustomobject]@{total_count=$script:WqtJobs.Count;jobs=$script:WqtJobs}}elseif($Path -match '/actions/runs/\d+$'){$script:WqtRun}elseif($Path -match '/contents/'){$script:WqtBlob}else{$script:WqtRepo}}
        } $wqt $sha $blobSha
        Assert ((Get-Ci7ExpectedJob $wqt -RequireQueued).id -eq 501)
        $wrongJobId=New-Ci7Configuration -Repository $profile.Repository -ApprovedRepositories @($profile.Repository) -WorkflowRunId $runId -ExpectedSha $sha -WorkflowPath $profile.WorkflowPath -WorkflowBlobSha $blobSha -ExpectedJobName $profile.JobName -ProfileId $profile.ProfileId -RunAttempt 2 -ExpectedJobId 599 -Root $root
        Refuses { Get-Ci7ExpectedJob $wrongJobId }
        & $module {$script:WqtRun.run_attempt=1}; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {$script:WqtRun.run_attempt=2;$script:WqtRun.pull_requests=@()}; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {$script:WqtRun.pull_requests=@([pscustomobject]@{head=[pscustomobject]@{sha=$script:WqtRun.head_sha}});$script:WqtJob.run_id=99}; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {param($id,$cfg);$script:WqtJob.run_id=$id;$script:WqtJob.run_attempt=2;$script:WqtJob.head_sha='c'*40} $runId $wqt; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {param($id,$cfg);$script:WqtJob.head_sha=$cfg.ExpectedSha;$script:WqtJob.labels=@(Get-Ci7Labels $id $cfg | ForEach-Object {if($_ -ceq 'wqt-validation'){'wqt-semantic-validate'}else{$_}})} $runId $wqt; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {param($id,$cfg);$script:WqtJob.labels=@(Get-Ci7Labels $id $cfg)} $runId $wqt
        & $module {param($id,$cfg,$blob);$script:WqtJob.labels=@(Get-Ci7Labels $id $cfg);$script:WqtBlob.sha='c'*40} $runId $wqt $blobSha; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {param($blob);$script:WqtBlob.sha=$blob;$script:WqtJobs += [pscustomobject]@{id=504;name='unknown-job';status='completed';conclusion='skipped'}} $blobSha; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {$script:WqtJobs=@($script:WqtJob,[pscustomobject]@{id=502;name='validate-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=503;name='scan';status='queued';conclusion=$null})}; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {$script:WqtJobs=@($script:WqtJob,[pscustomobject]@{id=502;name='validate-manual';status='completed';conclusion='skipped'},[pscustomobject]@{id=503;name='scan';status='completed';conclusion='skipped'})}; Refuses {Get-Ci7ExpectedJob $wqt}
        & $module {$script:WqtJobs=@($script:WqtJob,[pscustomobject]@{id=502;name='validate-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=503;name='scan';status='completed';conclusion='skipped'});$script:WqtJob.runner_name='runner-a'}; Refuses {Get-Ci7ExpectedJob $wqt -RequireQueued}
        & $module {$script:WqtJob.runner_name=$null;$script:WqtJob.runner_group_id=4}; Refuses {Get-Ci7ExpectedJob $wqt -RequireQueued}
        & $module {$script:WqtJob.runner_group_id=0}; Assert ((Get-Ci7ExpectedJob $wqt -RequireQueued).id -eq 501)
        Refuses {New-Ci7Configuration -Repository $profile.Repository -ApprovedRepositories @($profile.Repository) -WorkflowRunId $runId -ExpectedSha $sha -WorkflowPath $profile.WorkflowPath -WorkflowBlobSha $blobSha -ExpectedJobName $profile.JobName -Root $root}
        Refuses {New-Ci7Configuration -Repository $profile.Repository -ApprovedRepositories @($profile.Repository) -WorkflowRunId $runId -ExpectedSha $sha -WorkflowPath $profile.WorkflowPath -WorkflowBlobSha $blobSha -ExpectedJobName $profile.JobName -ProfileId 'generic-private' -RunAttempt 2 -Root $root}
        foreach($p in $profiles){Refuses {New-Ci7Configuration -Repository $p.Repository -ApprovedRepositories @($p.Repository) -WorkflowRunId $runId -ExpectedSha $sha -WorkflowPath $p.WorkflowPath -WorkflowBlobSha $blobSha -ExpectedJobName $p.JobName -ProfileId $p.ProfileId -RunAttempt 0 -Root $root}}
    }
    Check 'semantic retention probe requires exact successful validate-pr dependency' {
        $sha='d'*40;$blobSha='e'*40;$runId=88002
        $profile=@((& $module {Get-Ci7ClosedProfiles}) | Where-Object ProfileId -CEQ 'wqt-semantic-retention-probe')[0]
        $probe=New-Ci7Configuration -Repository $profile.Repository -ApprovedRepositories @($profile.Repository) -WorkflowRunId $runId -ExpectedSha $sha -WorkflowPath $profile.WorkflowPath -WorkflowBlobSha $blobSha -ExpectedJobName $profile.JobName -ProfileId $profile.ProfileId -RunAttempt 1 -ExpectedJobId 602 -Root $root
        Assert ('wqt-semantic-retention-probe' -cin $probe.StaticLabels -and 'wqt-semantic-validate' -cnotin $probe.StaticLabels)
        Assert ($probe.ReadPermissions -join ',' -ceq 'contents:read,actions:read' -and -not $probe.WorkflowSecrets -and -not $probe.PrivateProductionState -and -not $probe.Docker)
        & $module {
            param($c,$sha,$blobSha)
            $script:WqtRepo=[pscustomobject]@{private=$true};$script:WqtBlob=[pscustomobject]@{sha=$blobSha}
            $script:WqtRun=[pscustomobject]@{id=$c.WorkflowRunId;status='in_progress';conclusion=$null;run_attempt=1;head_sha=$sha;path=$c.WorkflowPath;repository=[pscustomobject]@{full_name=$c.Repository};head_repository=[pscustomobject]@{full_name=$c.Repository};event='pull_request';pull_requests=@([pscustomobject]@{head=[pscustomobject]@{sha=$sha}})}
            $script:WqtValidate=[pscustomobject]@{id=601;name='validate-pr';run_id=$c.WorkflowRunId;run_attempt=1;head_sha=$sha;status='completed';conclusion='success'}
            $script:WqtJob=[pscustomobject]@{id=602;name='retention-probe-pr';run_id=$c.WorkflowRunId;run_attempt=1;head_sha=$sha;status='queued';conclusion=$null;runner_id=0;runner_name=$null;runner_group_id=0;labels=@(Get-Ci7Labels $c.WorkflowRunId $c)}
            $script:WqtJobs=@($script:WqtValidate,$script:WqtJob,[pscustomobject]@{id=603;name='validate-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=604;name='retention-probe-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=605;name='consume-real';status='completed';conclusion='skipped'})
            function script:Invoke-Ci7Api {param($Path,$Method='GET',$Body);if($Path -match '/actions/jobs/\d+$'){$script:WqtJob}elseif($Path -match '/jobs\?'){[pscustomobject]@{total_count=$script:WqtJobs.Count;jobs=$script:WqtJobs}}elseif($Path -match '/actions/runs/\d+$'){$script:WqtRun}elseif($Path -match '/contents/'){$script:WqtBlob}else{$script:WqtRepo}}
        } $probe $sha $blobSha
        Assert ((Get-Ci7ExpectedJob $probe -RequireQueued).id -eq 602)
        & $module {$script:WqtValidate.conclusion='failure'};Refuses {Get-Ci7ExpectedJob $probe}
        & $module {$script:WqtValidate.conclusion='success';$script:WqtJob.runner_name='runner-a'};Refuses {Get-Ci7ExpectedJob $probe -RequireQueued}
        & $module {$script:WqtJob.runner_name=$null;$script:WqtJob.runner_group_id=9};Refuses {Get-Ci7ExpectedJob $probe -RequireQueued}
    }
    Check 'semantic validation profile accepts only absent retention job before eligibility' {
        $sha='f'*40;$blobSha='1'*40;$runId=88003
        $profile=@((& $module {Get-Ci7ClosedProfiles}) | Where-Object ProfileId -CEQ 'wqt-semantic-validate')[0]
        $validate=New-Ci7Configuration -Repository $profile.Repository -ApprovedRepositories @($profile.Repository) -WorkflowRunId $runId -ExpectedSha $sha -WorkflowPath $profile.WorkflowPath -WorkflowBlobSha $blobSha -ExpectedJobName $profile.JobName -ProfileId $profile.ProfileId -RunAttempt 1 -ExpectedJobId 701 -Root $root
        & $module {
            param($c,$sha,$blobSha)
            $script:WqtRepo=[pscustomobject]@{private=$true};$script:WqtBlob=[pscustomobject]@{sha=$blobSha}
            $script:WqtRun=[pscustomobject]@{id=$c.WorkflowRunId;status='in_progress';conclusion=$null;run_attempt=1;head_sha=$sha;path=$c.WorkflowPath;repository=[pscustomobject]@{full_name=$c.Repository};head_repository=[pscustomobject]@{full_name=$c.Repository};event='pull_request';pull_requests=@([pscustomobject]@{head=[pscustomobject]@{sha=$sha}})}
            $script:WqtJob=[pscustomobject]@{id=701;name='validate-pr';run_id=$c.WorkflowRunId;run_attempt=1;head_sha=$sha;status='queued';conclusion=$null;runner_id=0;labels=@(Get-Ci7Labels $c.WorkflowRunId $c)}
            $script:WqtProbe=[pscustomobject]@{id=702;name='retention-probe-pr';run_id=$c.WorkflowRunId;run_attempt=1;head_sha=$sha;status='waiting';conclusion=$null;runner_id=0;runner_name=$null;runner_group_id=0;labels=@()}
            $script:WqtJobs=@($script:WqtJob,[pscustomobject]@{id=703;name='validate-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=704;name='retention-probe-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=705;name='consume-real';status='completed';conclusion='skipped'})
            function script:Invoke-Ci7Api {param($Path,$Method='GET',$Body);if($Path -match '/actions/jobs/\d+$'){$script:WqtJob}elseif($Path -match '/jobs\?'){[pscustomobject]@{total_count=$script:WqtJobs.Count;jobs=$script:WqtJobs}}elseif($Path -match '/actions/runs/\d+$'){$script:WqtRun}elseif($Path -match '/contents/'){$script:WqtBlob}else{$script:WqtRepo}}
        } $validate $sha $blobSha
        Assert ((Get-Ci7ExpectedJob $validate -RequireQueued).id -eq 701)
        foreach($status in @('queued','waiting','pending','requested','in_progress','completed')){
            & $module {param($s);$script:WqtJobs=@($script:WqtJobs | Where-Object {$_.name -cne 'retention-probe-pr'});$script:WqtProbe.status=$s;if($s -eq 'completed'){$script:WqtProbe.conclusion='skipped'}else{$script:WqtProbe.conclusion=$null};$script:WqtJobs += $script:WqtProbe} $status
            Refuses {Get-Ci7ExpectedJob $validate}
        }
        & $module {$script:WqtJobs=@($script:WqtJobs | Where-Object {$_.name -cne 'retention-probe-pr'});$script:WqtJobs += [pscustomobject]@{id=702;name='retention-probe-manual';status='completed';conclusion='skipped'}}
        Refuses {Get-Ci7ExpectedJob $validate}
        & $module {$script:WqtJobs=@($script:WqtJobs | Where-Object {$_.name -cne 'retention-probe-manual'});$script:WqtJob.status='completed';$script:WqtJob.conclusion='success'}
        Refuses {Get-Ci7ExpectedJob $validate -RequireQueued}
        $persisted=New-Ci7State $validate '0123456789abcdef0123456789abcdef';$persisted.JobId=701
        & $module {$script:WqtJob.status='queued';$script:WqtJob.conclusion=$null;$script:WqtJobs=@($script:WqtJob,[pscustomobject]@{id=703;name='validate-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=704;name='retention-probe-hosted';status='completed';conclusion='skipped'},[pscustomobject]@{id=705;name='consume-real';status='completed';conclusion='skipped'})}
        Assert ((Get-Ci7MonitoredJob $persisted).id -eq 701)
        & $module {$script:WqtJobs += [pscustomobject]@{id=702;name='retention-probe-pr';run_id=$script:WqtRun.id;run_attempt=1;head_sha=$script:WqtRun.head_sha;status='queued';conclusion=$null}}
        Refuses {Get-Ci7ExpectedJob $validate}
        Refuses {Get-Ci7MonitoredJob $persisted}
        & $module {$script:WqtJob.status='completed';$script:WqtJob.conclusion='failure';$script:WqtJobs += $script:WqtProbe; $script:WqtProbe.status='completed';$script:WqtProbe.conclusion='skipped'}
        Assert ((Get-Ci7PersistedCleanupJob $persisted).id -eq 701)
        Refuses {Get-Ci7ExpectedJob $validate}
        & $module {$script:WqtJob.conclusion='success';$script:WqtProbe.status='queued';$script:WqtProbe.conclusion=$null}
        Assert ((Get-Ci7MonitoredJob $persisted).id -eq 701)
        Assert ((Get-Ci7MonitoredJob $persisted).conclusion -ceq 'success')
        foreach($field in @('id','name','run_id','run_attempt','head_sha')){
            & $module {param($field,$cfg);$script:WqtJob.id=701;$script:WqtJob.name=$cfg.ExpectedJobName;$script:WqtJob.run_id=$cfg.WorkflowRunId;$script:WqtJob.run_attempt=$cfg.RunAttempt;$script:WqtJob.head_sha=$cfg.ExpectedSha;switch($field){'id'{$script:WqtJob.id=999};'name'{$script:WqtJob.name='other'};'run_id'{$script:WqtJob.run_id++};'run_attempt'{$script:WqtJob.run_attempt++};'head_sha'{$script:WqtJob.head_sha=('0'*40)}}} $field $validate
            Refuses {Get-Ci7PersistedCleanupJob $persisted};Refuses {Get-Ci7MonitoredJob $persisted}
        }
        & $module {param($cfg);$script:WqtJob.id=701;$script:WqtJob.name=$cfg.ExpectedJobName;$script:WqtJob.run_id=$cfg.WorkflowRunId;$script:WqtJob.run_attempt=$cfg.RunAttempt;$script:WqtJob.head_sha=$cfg.ExpectedSha} $validate
        $persisted.JobId=$null;Refuses {Get-Ci7PersistedCleanupJob $persisted};$persisted.JobId=701
        Refuses {Get-Ci7PersistedCleanupJob $validate.Configuration}
    }

    Check 'Royal PR release-gate profile is exact and isolated from production deploy' {
        $prRepo = 'LowcountryDigitalWorks/royal-cruise-tracker'
        $prPath = '.github/workflows/dashboard-release-gate.yml'
        $prName = 'Zero-side-effect full repository release validation'
        $prSha = 'e' * 40
        $prConfig = New-Ci7Configuration -Repository $prRepo -WorkflowRunId 99887 -ExpectedSha $prSha -Root $root -WorkflowPath $prPath -ExpectedJobName $prName
        Assert ($prConfig.WorkflowPath -ceq $prPath -and $prConfig.ExpectedJobName -ceq $prName)
        Assert ('royal-isolated' -cin $prConfig.StaticLabels -and 'security-isolated' -cnotin $prConfig.StaticLabels)
        & $module {
            param($cfg,$sha)
            $script:ApiTestRepo=[pscustomobject]@{private=$true}
            $script:ApiTestRun=[pscustomobject]@{id=$cfg.WorkflowRunId;status='queued';conclusion=$null;run_attempt=1;head_sha=$sha;path=$cfg.WorkflowPath;repository=[pscustomobject]@{full_name=$cfg.Repository};head_repository=[pscustomobject]@{full_name=$cfg.Repository};event='pull_request';head_branch='feature/release-gate'}
            $script:ApiTestJob=[pscustomobject]@{id=98;name=$cfg.ExpectedJobName;run_id=$cfg.WorkflowRunId;run_attempt=1;head_sha=$sha;status='queued';runner_id=0;labels=@(Get-Ci7Labels $cfg.WorkflowRunId $cfg)}
            $script:ApiTestCount=1
            function script:Invoke-Ci7Api { param($Path,$Method='GET',$Body)
                if ($Path -match '/jobs\?') { [pscustomobject]@{total_count=$script:ApiTestCount;jobs=@($script:ApiTestJob)} }
                elseif ($Path -match '/actions/runs/') { $script:ApiTestRun }
                else { $script:ApiTestRepo }
            }
        } $prConfig $prSha
        Assert ((Get-Ci7ExpectedJob $prConfig -RequireQueued).id -eq 98)
        & $module {$script:ApiTestRun.repository.full_name='LowcountryDigitalWorks/other'}; Refuses { Get-Ci7ExpectedJob $prConfig }
        & $module {$script:ApiTestRun.repository.full_name='LowcountryDigitalWorks/royal-cruise-tracker';$script:ApiTestRun.path='.github/workflows/other.yml'}; Refuses { Get-Ci7ExpectedJob $prConfig }
        & $module {$script:ApiTestRun.path='.github/workflows/dashboard-release-gate.yml';$script:ApiTestRun.event='push'}; Refuses { Get-Ci7ExpectedJob $prConfig }
        & $module {$script:ApiTestRun.event='pull_request';$script:ApiTestJob.name='wrong job'}; Refuses { Get-Ci7ExpectedJob $prConfig }
        & $module {$script:ApiTestJob.name='Zero-side-effect full repository release validation';$script:ApiTestJob.labels[6]='security-isolated'}; Refuses { Get-Ci7ExpectedJob $prConfig }
        & $module {param($cfg);$script:ApiTestJob.labels=@(Get-Ci7Labels $cfg.WorkflowRunId $cfg)} $prConfig
        Refuses { New-Ci7Configuration -Repository $prRepo -WorkflowRunId 99887 -ExpectedSha $prSha -Root $root -WorkflowPath $prPath -ExpectedJobName 'Manual exact-SHA' }
        $deploy = New-Ci7Configuration -Repository $prRepo -WorkflowRunId 99888 -ExpectedSha $prSha -Root $root -WorkflowPath '.github/workflows/deploy-dashboard-pr379.yml' -WorkflowBlobSha ('d' * 40) -ExpectedJobName 'Manual exact-SHA'
        & $module {param($cfg,$sha);$script:ApiTestRun.id=99888;$script:ApiTestRun.path=$cfg.WorkflowPath;$script:ApiTestRun.event='pull_request';$script:ApiTestJob.name='Manual exact-SHA';$script:ApiTestJob.run_id=99888;$script:ApiTestJob.head_sha=$sha;$script:ApiTestJob.labels=@(Get-Ci7Labels 99888 $cfg)} $deploy $prSha
        Refuses { Get-Ci7ExpectedJob $deploy }
    }
    Check 'exact Royal deployment profile contract accepted and verified' {
        $royalHeadSha = 'c' * 40
        $royalBlobSha = 'd' * 40
        $royalRepo = 'LowcountryDigitalWorks/royal-cruise-tracker'
        $royalWorkflow = '.github/workflows/deploy-dashboard-pr379.yml'
        $royalConfig = New-Ci7Configuration -Repository $royalRepo -WorkflowRunId 99999 -ExpectedSha $royalHeadSha -WorkflowPath $royalWorkflow -WorkflowBlobSha $royalBlobSha -ExpectedJobName 'Manual exact-SHA' -Root $root
        Assert ($royalConfig.Repository -ceq $royalRepo)
        Assert ($royalConfig.WorkflowPath -ceq $royalWorkflow)
        Assert ($royalConfig.WorkflowBlobSha -ceq $royalBlobSha)
        Assert ($royalConfig.ExpectedJobName -ceq 'Manual exact-SHA')
        $royalLabels = @(Get-Ci7Labels 99999 $royalConfig)
        Assert ('royal-isolated' -cin $royalLabels)
        Assert ('security-isolated' -cnotin $royalLabels)
        Assert ('ldw01-ci-01' -cnotin $royalLabels -and 'plexpc-ci-01' -cnotin $royalLabels)

        & $module {
            param($cfg,$headSha,$blobSha)
            $script:ApiTestRepo=[pscustomobject]@{private=$true}
            $script:ApiTestRun=[pscustomobject]@{id=$cfg.WorkflowRunId;status='queued';conclusion=$null;run_attempt=1;head_sha=$headSha;path=$cfg.WorkflowPath;repository=[pscustomobject]@{full_name=$cfg.Repository};head_repository=[pscustomobject]@{full_name=$cfg.Repository};event='workflow_dispatch';head_branch='main'}
            $script:ApiTestJob=[pscustomobject]@{id=99;name='Manual exact-SHA';run_id=$cfg.WorkflowRunId;run_attempt=1;head_sha=$headSha;status='queued';runner_id=0;labels=@(Get-Ci7Labels $cfg.WorkflowRunId $cfg)}
            $script:ApiTestBlob=[pscustomobject]@{sha=$blobSha}
            $script:ApiTestCount=1
            function script:Invoke-Ci7Api {
                param($Path,$Method='GET',$Body)
                if ($Path -match '/jobs\?') { [pscustomobject]@{total_count=$script:ApiTestCount;jobs=@($script:ApiTestJob)} }
                elseif ($Path -match '/actions/runs/') { $script:ApiTestRun }
                elseif ($Path -match '/contents/') { $script:ApiTestBlob }
                else { $script:ApiTestRepo }
            }
        } $royalConfig $royalHeadSha $royalBlobSha

        Assert ((Get-Ci7ExpectedJob $royalConfig -RequireQueued).id -eq 99)
        $royalState=New-Ci7State $royalConfig '1123456789abcdef0123456789abcdef';$royalState.JobId=99
        Assert ((Get-Ci7MonitoredJob $royalState).id -eq 99)

        & $module {$script:ApiTestRun.repository.full_name='LowcountryDigitalWorks/other'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.repository.full_name='LowcountryDigitalWorks/royal-cruise-tracker'}
        & $module {$script:ApiTestRun.path='.github/workflows/other.yml'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.path='.github/workflows/deploy-dashboard-pr379.yml'}
        & $module {$script:ApiTestJob.labels[3]='ldw-light'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestJob.labels[3]='ldw01'}

        # Refuses non-workflow_dispatch events for Royal
        & $module {$script:ApiTestRun.event='push'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.event='pull_request'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.event='workflow_dispatch'}

        # Refuses non-main head branch for Royal
        & $module {$script:ApiTestRun.head_branch='feature/x'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.head_branch='main'}
        & $module {$script:ApiTestRun.head_sha=('e'*40)}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.head_sha=('c'*40)}
        & $module {$script:ApiTestRun.status='in_progress'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.status='queued'}
        & $module {$script:ApiTestRun.id=88888}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestRun.id=99999}
        & $module {$script:ApiTestJob.head_sha=('e'*40)}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestJob.head_sha=('c'*40)}
        & $module {$script:ApiTestJob.name='another job'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestJob.name='deploy'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module {$script:ApiTestJob.name='Manual exact-SHA'}

        # Refuses mismatched workflow blob SHA
        & $module {$script:ApiTestBlob.sha='wrongblob'}; Refuses {Get-Ci7ExpectedJob $royalConfig}
        & $module { param($sha) $script:ApiTestBlob.sha=$sha } $royalBlobSha

        # Refuses wrong Jobs API name in closed Royal configuration
        Refuses { New-Ci7Configuration -Repository $royalRepo -WorkflowRunId 99999 -ExpectedSha $royalHeadSha -WorkflowPath $royalWorkflow -WorkflowBlobSha $royalBlobSha -ExpectedJobName 'deploy' -Root $root }

        # Refuses invalid workflow path
        Refuses { New-Ci7Configuration -Repository $royalRepo -WorkflowRunId 99999 -ExpectedSha $royalHeadSha -WorkflowPath '.github/workflows/unauthorized.yml' -Root $root }
        Refuses { New-Ci7Configuration -Repository $royalRepo -WorkflowRunId 99999 -ExpectedSha $royalHeadSha -WorkflowPath $royalWorkflow -Root $root }
        Refuses { New-Ci7Configuration -Repository $royalRepo -WorkflowRunId 99999 -ExpectedSha $royalHeadSha -WorkflowPath $royalWorkflow -WorkflowBlobSha 'bad' -Root $root }
        Refuses { New-Ci7Configuration -Repository $royalRepo -WorkflowRunId 99999 -ExpectedSha 'd77a0e01f42b7ecddd6bce0f7f226288dcc0b11e' -WorkflowPath $royalWorkflow -WorkflowBlobSha '3bfe9fec5fa4ebc10db17d41594ded8878b37064' -Root $root }
        Refuses { New-Ci7Configuration -Repository $royalRepo -WorkflowRunId 99999 -ExpectedSha $royalHeadSha -WorkflowPath $royalWorkflow -WorkflowBlobSha $royalBlobSha -StaticLabels @('self-hosted','Linux','X64','ldw01','ldw-ephemeral','ldw-isolated','ldw-light') -Root $root }
    }
    # Replace only external Hyper-V/API seams within the imported module. No live
    # VM, runner, token, network, or policy mutation occurs in this harness.
    & $module {
        $script:TestVMs = @(); $script:DeletedVMs = 0; $script:DeletedRunners = 0; $script:TestRunners = @()
        function script:Get-VM { $script:TestVMs }
        function script:Get-VMHardDiskDrive { param($VM); @([pscustomobject]@{ Path = $script:TestDisk }) }
        function script:Get-VMDvdDrive { param($VM); @([pscustomobject]@{ Path = $script:TestSeed }) }
        function script:Stop-VM { param($VM,[switch]$TurnOff,[switch]$Force,$Confirm); $VM.State = 'Off' }
        function script:Remove-VM { param($VM,[switch]$Force,$Confirm); $script:DeletedVMs++; $script:TestVMs = @() }
        function script:Invoke-Ci7Api { param($Path,$Method='GET',$Body); if ($Method -eq 'DELETE') { $script:DeletedRunners++; $script:TestRunners=@() } else { [pscustomobject]@{ total_count=$script:TestRunners.Count; runners=$script:TestRunners } } }
    }
    Check 'interrupted VM cleanup and disk/media deletion are idempotent' {
        & $module { param($s); $script:TestDisk=$s.Disk; $script:TestSeed=$s.Seed; $script:TestVMs=@([pscustomobject]@{VMId=$s.VMId;Name=$s.Name;Notes='CI-RUNNER-EPHEMERAL-001:'+$s.RunId;State='Running'}) } $state
        Set-Content -LiteralPath $state.Disk -Value synthetic
        Set-Content -LiteralPath $state.Seed -Value synthetic
        Remove-Ci7LocalResources $state
        Remove-Ci7LocalResources $state
        Assert (-not (Test-Path -LiteralPath $state.Disk) -and -not (Test-Path -LiteralPath $state.Seed))
        Assert ((& $module { $script:DeletedVMs }) -eq 1)
    }
    Check 'wrong attached disk refuses deletion before VM mutation' {
        & $module { param($s); $script:TestDisk='unrelated.vhdx'; $script:TestVMs=@([pscustomobject]@{VMId=$s.VMId;Name=$s.Name;Notes='CI-RUNNER-EPHEMERAL-001:'+$s.RunId;State='Running'}) } $state
        Refuses { Remove-Ci7LocalResources $state }
        Assert ((& $module { $script:DeletedVMs }) -eq 1)
        & $module { $script:TestVMs=@() }
    }
    Check 'interrupted runner cleanup is exact and idempotent' {
        & $module { param($s,$labels); $script:TestRunners=@([pscustomobject]@{id=$s.RunnerId;name=$s.Name;busy=$true;labels=@($labels|ForEach-Object{[pscustomobject]@{name=$_}})}) } $state @(Get-Ci7Labels $config.WorkflowRunId $config)
        Refuses { Remove-Ci7Runner $state }
        Remove-Ci7Runner $state -Interrupted
        Remove-Ci7Runner $state -Interrupted
        Assert ((& $module { $script:DeletedRunners }) -eq 1)
    }
    Check 'runner name and label ambiguity fails closed' {
        & $module { param($s); $script:TestRunners=@([pscustomobject]@{id=$s.RunnerId;name='ldw01-ci-01';busy=$false;labels=@()}) } $state
        Refuses { Remove-Ci7Runner $state -Interrupted }
        Assert ((& $module { $script:DeletedRunners }) -eq 1)
        & $module { param($s); $script:TestRunners=@([pscustomobject]@{id=$s.RunnerId;name=$s.Name;busy=$false;labels=@([pscustomobject]@{name='trusted-private'})}) } $state
        Refuses { Remove-Ci7Runner $state -Interrupted }
        Assert ((& $module { $script:DeletedRunners }) -eq 1)
    }
    Check 'bootstrap includes only JIT and guest scripts; no host credential or mount sources' {
        $moduleSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../CiRunner.psm1') -Raw
        $bootstrap = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../guest/bootstrap.sh') -Raw
        $service = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../guest/ci7-runner.service') -Raw
        Assert (-not ($moduleSource -match 'SSH_AUTH_SOCK|\.git-credentials|Copy-Item|Mount-VMHostAssignableDevice|Add-VMGpuPartitionAdapter|New-VM.*CI-RUNNER-001'))
        Assert (-not ($bootstrap -match 'docker run|dockerd|mount -t|ssh_authorized_keys|GH_TOKEN|GITHUB_TOKEN|credential.helper'))
        Assert ($service.Contains('User=ldw-runner') -and $service.Contains('Restart=no') -and $service.Contains('NoNewPrivileges=yes'))
        Assert ($bootstrap.Contains('192.168.0.0/16') -and $bootstrap.Contains('systemctl mask ssh.service ssh.socket'))
        Assert ($bootstrap.Contains('sha256sum --check --strict'))
    }
    if ($env:OS -eq 'Windows_NT') {
        Check 'real NoCloud media generation removes transient plaintext seed files' {
            New-Ci7Seed $state 'dGVzdC1qdXQtbWF0ZXJpYWw='
            Assert ((Get-Item -LiteralPath $state.Seed).Length -gt 32768)
            Assert (-not (Test-Path -LiteralPath (Join-Path $state.Directory 'seed/user-data')))
            $log = Get-Content -LiteralPath (Join-Path $root ('evidence/' + $state.RunId + '.jsonl')) -Raw
            Assert (-not $log.Contains('dGVzdC1qdXQtbWF0ZXJpYWw='))
        }
    }
    Check 'transient cleanup retains only sanitized evidence and is idempotent' {
        $state.PersistentBaseline=[pscustomobject]@{Runner='{"id":21}';VMs='{"cpu":4}'}
        & $module {param($baseline);$script:TestBaseline=$baseline;function script:Get-Ci7PersistentBaseline {param($Configuration);$script:TestBaseline}} $state.PersistentBaseline
        Remove-Ci7LocalResources $state
        Clear-Ci7TransientState $state
        Clear-Ci7TransientState $state
        Assert (-not (Test-Path -LiteralPath $state.Directory))
        $last=Get-Content -LiteralPath (Join-Path $root ('evidence/'+$state.RunId+'.jsonl'))|Select-Object -Last 1|ConvertFrom-Json
        Assert ($last.phase -ceq 'complete')
        & $module {$script:TestRunners=@()}
        Assert-Ci7AlreadyClean $root $state.RunId
        Assert-Ci7AlreadyClean $root $state.RunId
        & $module {param($s);$script:TestRunners=@([pscustomobject]@{id=999;name=$s.Name;busy=$false;labels=@()})} $state
        Refuses {Assert-Ci7AlreadyClean $root $state.RunId}
        Assert ((& $module {$script:DeletedRunners}) -eq 1)
    }
    'DETERMINISTIC_TESTS=PASS'
    'TEST_COUNT=' + $total
} finally {
    Remove-Module $module -Force
    # The randomly-created test root is checked before recursive removal.
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $full = [IO.Path]::GetFullPath($root)
    if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -cne 'CiRunnerEphemeral') { throw 'TEST_CLEANUP_ROOT_INVALID' }
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force }
}
