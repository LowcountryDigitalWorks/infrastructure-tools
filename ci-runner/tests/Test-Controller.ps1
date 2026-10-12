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
        $future = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -ApprovedRepositories @('LowcountryDigitalWorks/wqt-operations') -WorkflowRunId 1 -ExpectedSha ('a' * 40) -Root $root
        Assert-Ci7State (New-Ci7State $future) $root
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
            $commands=$ast.FindAll({param($node); $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -match '^(Get|Set|New|Start|Stop|Remove|Add|Disable|Convert)-(VM|VHD)'},$true)
            foreach($call in $commands){
                $definition=Get-Command $call.GetCommandName() -ErrorAction Stop
                foreach($element in $call.CommandElements|Where-Object{$_ -is [Management.Automation.Language.CommandParameterAst]}){
                    Assert ($definition.Parameters.ContainsKey($element.ParameterName))
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
        $script:ApiTestRun=[pscustomobject]@{head_sha=$cfg.ExpectedSha;path=$cfg.WorkflowPath;head_repository=[pscustomobject]@{full_name=$cfg.Repository};event='push';head_branch='main'}
        $script:ApiTestJob=[pscustomobject]@{id=10;status='queued';runner_id=0;labels=@(Get-Ci7Labels $cfg.WorkflowRunId)}
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
    Check 'exact WQT repo, workflow, event, job, head, and run labels accepted' {
        $wqtSha = 'c' * 40
        $wqtRunId = 5001
        $wqtCfg1 = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId $wqtRunId -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt.yml' -JobName 'validate-pr' -Root $root
        $wqtCfg2 = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId $wqtRunId -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt-semantic-consumer.yml' -JobName 'validate-pr' -Root $root
        $wqtCfg3 = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId $wqtRunId -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt-semantic-consumer.yml' -JobName 'retention-probe-pr' -Root $root

        & $module {
            param($c1, $c2, $c3)
            $script:WqtRepo = [pscustomobject]@{ private = $true }
            $script:WqtRun1 = [pscustomobject]@{ id = $c1.WorkflowRunId; run_attempt = 1; head_sha = $c1.ExpectedSha; path = $c1.WorkflowPath; head_repository = [pscustomobject]@{ full_name = $c1.Repository }; event = 'pull_request' }
            $script:WqtRun2 = [pscustomobject]@{ id = $c2.WorkflowRunId; run_attempt = 1; head_sha = $c2.ExpectedSha; path = $c2.WorkflowPath; head_repository = [pscustomobject]@{ full_name = $c2.Repository }; event = 'pull_request' }
            $script:WqtJob1 = [pscustomobject]@{ id = 101; run_id = $c1.WorkflowRunId; run_attempt = 1; name = 'validate-pr'; status = 'queued'; runner_id = 0; head_sha = $c1.ExpectedSha; labels = @(Get-Ci7Labels $c1.WorkflowRunId) }
            $script:WqtJob2A = [pscustomobject]@{ id = 102; run_id = $c2.WorkflowRunId; run_attempt = 1; name = 'validate-pr'; status = 'completed'; conclusion = 'success'; runner_id = 0; head_sha = $c2.ExpectedSha; labels = @(Get-Ci7Labels $c2.WorkflowRunId) }
            $script:WqtJob2B = [pscustomobject]@{ id = 103; run_id = $c3.WorkflowRunId; run_attempt = 1; name = 'retention-probe-pr'; status = 'queued'; runner_id = 0; head_sha = $c3.ExpectedSha; labels = @(Get-Ci7Labels $c3.WorkflowRunId) }

            function script:Invoke-Ci7Api {
                param($Path, $Method='GET', $Body)
                if ($Path -match '/wqt\.yml') {
                    if ($Path -match '/jobs\?') { [pscustomobject]@{ total_count = 1; jobs = @($script:WqtJob1) } }
                    elseif ($Path -match '/actions/runs/') { $script:WqtRun1 }
                    else { $script:WqtRepo }
                } elseif ($Path -match '/wqt-semantic-consumer\.yml') {
                    if ($Path -match '/jobs\?') { [pscustomobject]@{ total_count = 2; jobs = @($script:WqtJob2A, $script:WqtJob2B) } }
                    elseif ($Path -match '/actions/runs/') { $script:WqtRun2 }
                    else { $script:WqtRepo }
                } else {
                    if ($Path -match '/jobs\?') { [pscustomobject]@{ total_count = 1; jobs = @($script:WqtJob1) } }
                    elseif ($Path -match '/actions/runs/') { $script:WqtRun1 }
                    else { $script:WqtRepo }
                }
            }
        } $wqtCfg1 $wqtCfg2 $wqtCfg3

        $j1 = Get-Ci7ExpectedJob $wqtCfg1 -RequireQueued
        Assert ($j1.name -ceq 'validate-pr' -and $j1.id -eq 101)

        $j2 = Get-Ci7ExpectedJob $wqtCfg2
        Assert ($j2.name -ceq 'validate-pr' -and $j2.id -eq 102)

        $j3 = Get-Ci7ExpectedJob $wqtCfg3 -RequireQueued
        Assert ($j3.name -ceq 'retention-probe-pr' -and $j3.id -eq 103)
    }
    Check 'wrong repo, workflow, event, job, head, run, or attempt rejected for WQT' {
        $wqtSha = 'd' * 40
        Refuses { New-Ci7Configuration -Repository 'untrusted/wqt-operations' -WorkflowRunId 1 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt.yml' -JobName 'validate-pr' -Root $root }
        Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 1 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/unapproved.yml' -JobName 'validate-pr' -Root $root }
        Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 1 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt.yml' -JobName 'unapproved-job' -Root $root }

        $cfgWqt = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 6001 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt.yml' -JobName 'validate-pr' -RunAttempt 1 -Root $root
        & $module {
            param($c)
            $script:FailRepo = [pscustomobject]@{ private = $true }
            $script:FailRun = [pscustomobject]@{ id = $c.WorkflowRunId; run_attempt = 1; head_sha = $c.ExpectedSha; path = $c.WorkflowPath; head_repository = [pscustomobject]@{ full_name = $c.Repository }; event = 'push' }
            $script:FailJob = [pscustomobject]@{ id = 201; run_id = $c.WorkflowRunId; run_attempt = 1; name = 'validate-pr'; status = 'queued'; runner_id = 0; head_sha = $c.ExpectedSha; labels = @(Get-Ci7Labels $c.WorkflowRunId) }
            function script:Invoke-Ci7Api {
                param($Path, $Method='GET', $Body)
                if ($Path -match '/jobs\?') { [pscustomobject]@{ total_count = 1; jobs = @($script:FailJob) } }
                elseif ($Path -match '/actions/runs/') { $script:FailRun }
                else { $script:FailRepo }
            }
        } $cfgWqt
        # Event 'push' is wrong for WQT (must be 'pull_request')
        Refuses { Get-Ci7ExpectedJob $cfgWqt -RequireQueued }

        & $module { $script:FailRun.event = 'pull_request'; $script:FailRun.head_sha = 'e' * 40 }
        Refuses { Get-Ci7ExpectedJob $cfgWqt -RequireQueued }

        & $module { param($c); $script:FailRun.head_sha = $c.ExpectedSha; $script:FailRun.run_attempt = 2 } $cfgWqt
        Refuses { Get-Ci7ExpectedJob $cfgWqt -RequireQueued }
    }
    Check 'raw, pattern, and generalized unlisted jobs rejected' {
        $wqtSha = 'f' * 40
        foreach ($pattern in @('validate-*', '*', 'validate-p*', 'retention*', 'val*', 'validate-pr ')) {
            Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 1 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt.yml' -JobName $pattern -Root $root }
            Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 1 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt-semantic-consumer.yml' -JobName $pattern -Root $root }
        }
    }
    Check 'unexpected runnable jobs and skipped scan or consume-real cannot be claimed' {
        $wqtSha = '1' * 40
        foreach ($unlisted in @('scan', 'consume-real', 'arbitrary-step', 'build', 'deploy')) {
            Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 1 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt.yml' -JobName $unlisted -Root $root }
            Refuses { New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 1 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt-semantic-consumer.yml' -JobName $unlisted -Root $root }
        }
    }
    Check 'semantic retention probe refused before dependency eligibility and accepted after exact queued state' {
        $wqtSha = '2' * 40
        $wqtRunId = 7001
        $cfgProbe = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId $wqtRunId -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt-semantic-consumer.yml' -JobName 'retention-probe-pr' -Root $root

        & $module {
            param($c)
            $script:DepRepo = [pscustomobject]@{ private = $true }
            $script:DepRun = [pscustomobject]@{ id = $c.WorkflowRunId; run_attempt = 1; head_sha = $c.ExpectedSha; path = $c.WorkflowPath; head_repository = [pscustomobject]@{ full_name = $c.Repository }; event = 'pull_request' }
            $script:DepValidate = [pscustomobject]@{ id = 301; run_id = $c.WorkflowRunId; run_attempt = 1; name = 'validate-pr'; status = 'in_progress'; conclusion = $null; runner_id = 0; head_sha = $c.ExpectedSha; labels = @(Get-Ci7Labels $c.WorkflowRunId) }
            $script:DepProbe = [pscustomobject]@{ id = 302; run_id = $c.WorkflowRunId; run_attempt = 1; name = 'retention-probe-pr'; status = 'queued'; runner_id = 0; head_sha = $c.ExpectedSha; labels = @(Get-Ci7Labels $c.WorkflowRunId) }

            function script:Invoke-Ci7Api {
                param($Path, $Method='GET', $Body)
                if ($Path -match '/jobs\?') { [pscustomobject]@{ total_count = 2; jobs = @($script:DepValidate, $script:DepProbe) } }
                elseif ($Path -match '/actions/runs/') { $script:DepRun }
                else { $script:DepRepo }
            }
        } $cfgProbe

        # Refused while validate-pr is still in_progress
        Refuses { Get-Ci7ExpectedJob $cfgProbe -RequireQueued }

        # Refused if validate-pr failed
        & $module { $script:DepValidate.status = 'completed'; $script:DepValidate.conclusion = 'failure' }
        Refuses { Get-Ci7ExpectedJob $cfgProbe -RequireQueued }

        # Accepted once validate-pr is completed with success and probe is queued
        & $module { $script:DepValidate.status = 'completed'; $script:DepValidate.conclusion = 'success' }
        $probeJob = Get-Ci7ExpectedJob $cfgProbe -RequireQueued
        Assert ($probeJob.name -ceq 'retention-probe-pr' -and $probeJob.id -eq 302)
    }
    Check 'sequential eligible jobs in same run execute through separate guest lifecycles' {
        $wqtSha = '3' * 40
        $sameRunId = 8001
        $cfgVal = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId $sameRunId -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt-semantic-consumer.yml' -JobName 'validate-pr' -Root $root
        $cfgProbe = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId $sameRunId -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt-semantic-consumer.yml' -JobName 'retention-probe-pr' -Root $root

        $state1 = New-Ci7State $cfgVal
        [void](New-Item -ItemType Directory -Path $state1.Directory)
        $lock1 = [IO.File]::Open((Join-Path $state1.Directory 'controller.lock'), 'CreateNew', 'ReadWrite', 'None')
        Save-Ci7State $state1
        foreach ($p in @('Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved')) { Move-Ci7Phase $state1 $p }
        $lock1.Dispose()
        Clear-Ci7TransientState $state1

        $state2 = New-Ci7State $cfgProbe
        Assert ($state1.RunId -cne $state2.RunId)
        Assert ($state1.Directory -cne $state2.Directory)
        [void](New-Item -ItemType Directory -Path $state2.Directory)
        $lock2 = [IO.File]::Open((Join-Path $state2.Directory 'controller.lock'), 'CreateNew', 'ReadWrite', 'None')
        Save-Ci7State $state2
        foreach ($p in @('Registered','Provisioned','Running','JobCompleted','RunnerAbsent','GuestRemoved','ArtifactsRemoved')) { Move-Ci7Phase $state2 $p }
        $lock2.Dispose()
        Clear-Ci7TransientState $state2
    }
    Check 'already-completed, in-progress, or assigned job claimed refusal' {
        $wqtSha = '4' * 40
        $cfgVal = New-Ci7Configuration -Repository 'LowcountryDigitalWorks/wqt-operations' -WorkflowRunId 9001 -ExpectedSha $wqtSha -WorkflowPath '.github/workflows/wqt.yml' -JobName 'validate-pr' -Root $root

        & $module {
            param($c)
            $script:BusyRepo = [pscustomobject]@{ private = $true }
            $script:BusyRun = [pscustomobject]@{ id = $c.WorkflowRunId; run_attempt = 1; head_sha = $c.ExpectedSha; path = $c.WorkflowPath; head_repository = [pscustomobject]@{ full_name = $c.Repository }; event = 'pull_request' }
            $script:BusyJob = [pscustomobject]@{ id = 401; run_id = $c.WorkflowRunId; run_attempt = 1; name = 'validate-pr'; status = 'in_progress'; runner_id = 0; head_sha = $c.ExpectedSha; labels = @(Get-Ci7Labels $c.WorkflowRunId) }

            function script:Invoke-Ci7Api {
                param($Path, $Method='GET', $Body)
                if ($Path -match '/jobs\?') { [pscustomobject]@{ total_count = 1; jobs = @($script:BusyJob) } }
                elseif ($Path -match '/actions/runs/') { $script:BusyRun }
                else { $script:BusyRepo }
            }
        } $cfgVal

        # Status is in_progress
        Refuses { Get-Ci7ExpectedJob $cfgVal -RequireQueued }

        # Status is completed
        & $module { $script:BusyJob.status = 'completed' }
        Refuses { Get-Ci7ExpectedJob $cfgVal -RequireQueued }

        # Status is queued but runner_id assigned
        & $module { $script:BusyJob.status = 'queued'; $script:BusyJob.runner_id = 55 }
        Refuses { Get-Ci7ExpectedJob $cfgVal -RequireQueued }
    }
    Check 'WQT capabilities have no secrets or private production state enabled' {
        $profiles = & $module { Get-Ci7ClosedProfiles }
        $wqtProfiles = @($profiles | Where-Object { $_.Repository -ceq 'LowcountryDigitalWorks/wqt-operations' })
        Assert ($wqtProfiles.Count -eq 3)
        foreach ($p in $wqtProfiles) {
            Assert (-not $p.WorkflowSecrets)
            Assert (-not $p.PrivateProductionState)
            Assert (-not $p.Docker)
        }
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
        & $module { param($s,$labels); $script:TestRunners=@([pscustomobject]@{id=$s.RunnerId;name=$s.Name;busy=$true;labels=@($labels|ForEach-Object{[pscustomobject]@{name=$_}})}) } $state @(Get-Ci7Labels $config.WorkflowRunId)
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
    Check 'real NoCloud media generation removes transient plaintext seed files' {
        New-Ci7Seed $state 'dGVzdC1qdXQtbWF0ZXJpYWw='
        Assert ((Get-Item -LiteralPath $state.Seed).Length -gt 32768)
        Assert (-not (Test-Path -LiteralPath (Join-Path $state.Directory 'seed/user-data')))
        $log = Get-Content -LiteralPath (Join-Path $root ('evidence/' + $state.RunId + '.jsonl')) -Raw
        Assert (-not $log.Contains('dGVzdC1qdXQtbWF0ZXJpYWw='))
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
