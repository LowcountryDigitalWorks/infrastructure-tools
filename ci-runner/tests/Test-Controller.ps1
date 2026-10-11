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
