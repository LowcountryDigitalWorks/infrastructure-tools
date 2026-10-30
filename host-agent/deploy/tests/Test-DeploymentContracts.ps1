[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $deployRoot 'HyperVObserverDeployment.psm1') -Force

$script:Assertions = 0
function Assert-True([bool]$Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $script:Assertions++
    try { & $Action; throw "ASSERTION FAILED: $Message" }
    catch {
        if ($_.Exception.Message.StartsWith('ASSERTION FAILED:', [StringComparison]::Ordinal)) { throw }
    }
}

$constants = Get-HyperVObserverDeploymentConstants
$zeroTaskResult = Convert-HyperVObserverTaskResult -Value ([uint32]0)
Assert-True ($zeroTaskResult -is [uint32] -and $zeroTaskResult -eq 0) 'task result conversion must preserve zero as UInt32'
$highTaskResult = Convert-HyperVObserverTaskResult -Value ([uint32]3762504530)
Assert-True ($highTaskResult -is [uint32] -and $highTaskResult -eq [uint32]3762504530) 'task result conversion must preserve high-bit UInt32 values without signed overflow'
Assert-Throws { Convert-HyperVObserverTaskResult -Value ([int64]4294967296) | Out-Null } 'task result conversion must reject values above UInt32 max'
Assert-True ($constants.TaskName -eq 'HyperVObserver') 'task name must be deterministic'
Assert-True ($constants.TaskPath -eq '\LowcountryDigitalWorks\HostAgent\') 'task path must be deterministic and namespaced'
Assert-True ($constants.InstallRoot.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase)) 'install root must be under Program Files'
Assert-True ($constants.ConfigRoot.StartsWith($env:ProgramData, [StringComparison]::OrdinalIgnoreCase)) 'config root must be under ProgramData'
Assert-True ($constants.ConfigRoot.EndsWith('HostAgent\HyperVObserver', [StringComparison]::OrdinalIgnoreCase)) 'config root must be helper-specific'

$dirAcl = New-HyperVObserverDirectorySecurity
$fileAcl = New-HyperVObserverFileSecurity
Assert-True (Test-HyperVObserverAclObject -Acl $dirAcl) 'directory ACL must be protected and restricted to SYSTEM/local Administrators'
Assert-True (Test-HyperVObserverAclObject -Acl $fileAcl) 'file ACL must be protected and restricted to SYSTEM/local Administrators'

$tempParent = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP }
$tempRoot = Join-Path $tempParent ('ldw-host-agent-deploy-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $requiredFiles = @(
        'LDW.HostAgent.Core.dll',
        'LDW.HostAgent.HyperVObserver.deps.json',
        'LDW.HostAgent.HyperVObserver.dll',
        'LDW.HostAgent.HyperVObserver.exe',
        'LDW.HostAgent.HyperVObserver.runtimeconfig.json'
    )

    $publishA = Join-Path $tempRoot 'a'
    New-Item -ItemType Directory -Path $publishA | Out-Null
    foreach ($name in $requiredFiles) { Set-Content -LiteralPath (Join-Path $publishA $name) -Value "fixture-$name" -NoNewline }
    $manifestA = New-HyperVObserverDeploymentManifest -Directory $publishA
    $verifiedA = Test-HyperVObserverDeploymentManifest -Directory $publishA
    Assert-True ($manifestA.ReleaseId -eq $verifiedA.ReleaseId) 'manifest must verify deterministically'
    Assert-True (@($verifiedA.Entries).Count -eq 5) 'publish boundary must contain exactly five payload files'

    $publishB = Join-Path $tempRoot 'b'
    Copy-Item -LiteralPath $publishA -Destination $publishB -Recurse
    Remove-Item -LiteralPath (Join-Path $publishB 'deployment-manifest.json')
    Set-Content -LiteralPath (Join-Path $publishB 'LDW.HostAgent.Core.dll') -Value 'changed-core-content' -NoNewline
    $manifestB = New-HyperVObserverDeploymentManifest -Directory $publishB
    Assert-True ($manifestB.ReleaseId -ne $manifestA.ReleaseId) 'release identity must change when a dependency DLL changes even if the apphost EXE does not'

    $publishBad = Join-Path $tempRoot 'bad'
    Copy-Item -LiteralPath $publishA -Destination $publishBad -Recurse
    Remove-Item -LiteralPath (Join-Path $publishBad 'deployment-manifest.json')
    Set-Content -LiteralPath (Join-Path $publishBad 'id_ed25519') -Value 'not-a-real-key' -NoNewline
    Assert-Throws { New-HyperVObserverDeploymentManifest -Directory $publishBad | Out-Null } 'unexpected/private-trust-like publish files must fail closed'

    $publishNested = Join-Path $tempRoot 'nested'
    New-Item -ItemType Directory -Path $publishNested | Out-Null
    foreach ($name in $requiredFiles) { Set-Content -LiteralPath (Join-Path $publishNested $name) -Value "fixture-$name" -NoNewline }
    New-Item -ItemType Directory -Path (Join-Path $publishNested 'extra') | Out-Null
    Assert-Throws { New-HyperVObserverDeploymentManifest -Directory $publishNested | Out-Null } 'publish subdirectories must fail closed'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

$realTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Assert-True ($realTaskSettings.PSObject.Properties.Name -contains 'DisallowStartIfOnBatteries') 'real ScheduledTasks settings must expose DisallowStartIfOnBatteries'
Assert-True ($realTaskSettings.PSObject.Properties.Name -contains 'StopIfGoingOnBatteries') 'real ScheduledTasks settings must expose StopIfGoingOnBatteries'
Assert-True (-not [bool]$realTaskSettings.DisallowStartIfOnBatteries) 'AllowStartIfOnBatteries must map to DisallowStartIfOnBatteries=false'
Assert-True (-not [bool]$realTaskSettings.StopIfGoingOnBatteries) 'DontStopIfGoingOnBatteries must map to StopIfGoingOnBatteries=false'

$installedExe = Join-Path $constants.ReleasesRoot '0123456789abcdef\LDW.HostAgent.HyperVObserver.exe'
$spec = Get-HyperVObserverTaskSpec -InstalledExe $installedExe -ConfigPath $constants.ConfigPath
$fakeTask = [pscustomobject]@{
    TaskName = $spec.TaskName
    TaskPath = $spec.TaskPath
    Description = $spec.Description
    Actions = @([pscustomobject]@{ Execute = $spec.Execute; Arguments = $spec.Arguments })
    Principal = [pscustomobject]@{ UserId = 'SYSTEM'; RunLevel = 'Highest'; LogonType = 'ServiceAccount' }
    Triggers = @([pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskBootTrigger' } })
    Settings = [pscustomobject]@{
        Hidden = $true
        StartWhenAvailable = $true
        RestartCount = 3
        RestartInterval = 'PT1M'
        ExecutionTimeLimit = 'PT0S'
        MultipleInstances = 'IgnoreNew'
        DisallowStartIfOnBatteries = $false
        StopIfGoingOnBatteries = $false
    }
}

Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec).Count -eq 0) 'exact task identity fixture must pass'
$fakeTask.Actions[0].Execute = Join-Path $env:SystemRoot 'System32\cmd.exe'
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'action-execute') 'action drift must be detected'
$fakeTask.Actions[0].Execute = $spec.Execute
$fakeTask.Principal.UserId = 'Administrators'
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'principal-user') 'principal drift must be detected'
$fakeTask.Principal.UserId = 'SYSTEM'
$fakeTask.Settings.Hidden = $false
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'hidden') 'hidden-setting drift must be detected'
$fakeTask.Settings.Hidden = $true
$fakeTask.Settings.RestartCount = 99
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'restart-count') 'restart policy drift must be detected'
$fakeTask.Settings.RestartCount = 3
$fakeTask.Settings.DisallowStartIfOnBatteries = $true
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'allow-on-battery') 'battery-start drift must be detected using real ScheduledTasks property'
$fakeTask.Settings.DisallowStartIfOnBatteries = $false
$fakeTask.Settings.StopIfGoingOnBatteries = $true
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'dont-stop-on-battery') 'battery-stop drift must be detected using real ScheduledTasks property'
$fakeTask.Settings.StopIfGoingOnBatteries = $false
$fakeTask.Settings.DisallowStartIfOnBatteries = $null
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'allow-on-battery') 'null battery-start readback must fail closed'
$fakeTask.Settings.DisallowStartIfOnBatteries = $false
$fakeTask.Settings.StopIfGoingOnBatteries = $null
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'dont-stop-on-battery') 'null battery-stop readback must fail closed'
$fakeTask.Settings.StopIfGoingOnBatteries = $false
$fakeTask.Settings.DisallowStartIfOnBatteries = 'False'
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'allow-on-battery') 'non-boolean battery-start readback must fail closed'
$fakeTask.Settings.DisallowStartIfOnBatteries = $false

foreach ($scriptName in @('Disable-HyperVObserver.ps1', 'Enable-HyperVObserver.ps1', 'Uninstall-HyperVObserver.ps1')) {
    $source = Get-Content -LiteralPath (Join-Path $deployRoot $scriptName) -Raw
    $validationIndex = $source.IndexOf('Get-HyperVObserverValidatedContext', [StringComparison]::Ordinal)
    Assert-True ($validationIndex -ge 0) "$scriptName must validate managed state/task identity"
    foreach ($mutation in @('Stop-ScheduledTask', 'Disable-ScheduledTask', 'Enable-ScheduledTask', 'Start-ScheduledTask', 'Unregister-ScheduledTask')) {
        $mutationIndex = $source.IndexOf($mutation, [StringComparison]::Ordinal)
        if ($mutationIndex -ge 0) {
            Assert-True ($validationIndex -lt $mutationIndex) "$scriptName must validate exact task identity before $mutation"
        }
    }
}

$workerSource = Get-Content -LiteralPath (Join-Path $deployRoot 'Invoke-CiJitControlTask.ps1') -Raw
$workerTokens=$null;$workerErrors=$null
$workerAst=[Management.Automation.Language.Parser]::ParseInput($workerSource,[ref]$workerTokens,[ref]$workerErrors)
Assert-True ($workerErrors.Count -eq 0) 'CI/JIT control worker must parse'
$assertNoReparseAst=$workerAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-NoReparse'},$false)
$readRequestAst=$workerAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-Request'},$false)
Assert-True ($null -ne $assertNoReparseAst -and $null -ne $readRequestAst) 'CI/JIT request parser functions must be discoverable'
$requestFixtureRoot = Join-Path $tempParent ('ldw-ci-jit-request-contract-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $requestFixtureRoot | Out-Null
try {
    & {
        param([string]$AssertNoReparseSource,[string]$ReadRequestSource,[string]$FixtureRoot)
        . ([scriptblock]::Create($AssertNoReparseSource))
        . ([scriptblock]::Create($ReadRequestSource))
        $requestRoot=$FixtureRoot
        $requestPath=Join-Path $requestRoot 'discover.json'
        $Operation='DISCOVER'
        function Write-RequestFixture([object]$Payload) {
            $json=$Payload | ConvertTo-Json -Compress -Depth 4
            [IO.File]::WriteAllText($requestPath,$json,[Text.UTF8Encoding]::new($false))
        }

        $validId='11111111-1111-1111-1111-111111111111'
        Write-RequestFixture ([ordered]@{schema=1;operationId=$validId;operation='DISCOVER';runId=$null})
        $parsed=Read-Request
        Assert-True ($parsed.OperationId -ceq $validId -and $null -eq $parsed.RunId) 'CI/JIT request parser must accept a canonical DISCOVER request'

        Write-RequestFixture ([ordered]@{schema=1;operationId='not-a-guid';operation='DISCOVER';runId=$null})
        $refusal=$null
        try{$null=Read-Request}catch{$refusal=$_.Exception.Message}
        Assert-True ($refusal -ceq 'REQUEST_REFUSED') 'CI/JIT request parser must refuse malformed operationId'

        Write-RequestFixture ([ordered]@{schema=1;operationId=$validId;operation='DISCOVER';runId=$null;extra='refuse'})
        $refusal=$null
        try{$null=Read-Request}catch{$refusal=$_.Exception.Message}
        Assert-True ($refusal -ceq 'REQUEST_REFUSED') 'CI/JIT request parser must preserve exact request shape'
    } $assertNoReparseAst.Extent.Text $readRequestAst.Extent.Text $requestFixtureRoot
}
finally {
    if (Test-Path -LiteralPath $requestFixtureRoot) { Remove-Item -LiteralPath $requestFixtureRoot -Recurse -Force }
}

$bootstrapSource = Get-Content -LiteralPath (Join-Path $deployRoot 'Bootstrap-CiJitControlTasks.ps1') -Raw
foreach ($literal in @(
    '2bffdaf62d3f3df05c5d03220f1b06e0c4c1dd55',
    'fd52f44134dda198cb35ed7ef999e166ab143bbe',
    '02bc6f1526b27a4bf2ef786dd91ba8b816beb68c',
    'dabb1083994b635ff7d8f83ed673379276036885',
    'd10cad356a8ee8cb6201a6167b2ca5ab732a967f1945fe543520454c643ae964',
    '54b9343af44c70db1d1403cf7f45cfc11e8bf167',
    'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec'
)) {
    Assert-True ($bootstrapSource.Contains($literal, [StringComparison]::Ordinal)) "CI/JIT bootstrap must pin accepted identity $literal"
}
Assert-True ($bootstrapSource.Contains("branch','--show-current", [StringComparison]::Ordinal)) 'CI/JIT bootstrap must require a named current branch'
Assert-True ($bootstrapSource.Contains('$branch -cne ''main''', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must require main'
Assert-True ($bootstrapSource.Contains("status','--porcelain", [StringComparison]::Ordinal)) 'CI/JIT bootstrap must require a clean worktree'
Assert-True ($bootstrapSource.Contains('refs/remotes/origin/main', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must bind local HEAD to fetched origin/main'
Assert-True ($bootstrapSource.Contains('merge-base --is-ancestor', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must require accepted source ancestry'
Assert-True ($bootstrapSource.Contains('ACCEPTED_CONTROL_SOURCE_CHANGED', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must reject accepted installer/worker/status-access drift'
Assert-True ($bootstrapSource.Contains('WindowsIdentity]::GetCurrent()', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must derive owner SID locally'
Assert-True ($bootstrapSource.Contains('OWNER_SID=LOCAL_DERIVED', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must redact owner SID in output'
Assert-True ($bootstrapSource.Contains('$Mode -ne ''Uninstall''', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must preserve rollback when bundle evidence is unavailable'
Assert-True ($bootstrapSource.Contains('$parameters.AcceptInstall = $true', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must forward explicit install acceptance only when supplied'
Assert-True ($bootstrapSource.Contains('$parameters.AcceptUninstall = $true', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must forward explicit uninstall acceptance only when supplied'
Assert-True ($bootstrapSource.Contains('& $managePath @parameters', [StringComparison]::Ordinal)) 'CI/JIT bootstrap must delegate to the reviewed installer instead of reimplementing task creation'
$statusCall = '& $statusAccessPath -PermittedReaderSid $ownerSid -Confirm:$false'
Assert-True ($bootstrapSource.Contains('$Mode -ceq ''Install'' -and $AcceptInstall', [StringComparison]::Ordinal)) 'status reader ACL must require explicit Install plus AcceptInstall'
Assert-True ($bootstrapSource.Contains($statusCall, [StringComparison]::Ordinal)) 'status reader ACL must receive the locally derived owner SID'
Assert-True ($bootstrapSource.IndexOf($statusCall, [StringComparison]::Ordinal) -lt $bootstrapSource.IndexOf('& $managePath @parameters', [StringComparison]::Ordinal)) 'status reader ACL must fail closed before task installation'
Assert-True ($bootstrapSource.Contains('$statusAccessOutput.Count -ne 1', [StringComparison]::Ordinal) -and
    $bootstrapSource.Contains("[string]`$statusAccessOutput[0] -cne 'CI_JIT_STATUS_READER_ACL=PASS'", [StringComparison]::Ordinal)) 'status reader ACL output must require the single safe PASS marker'
Assert-True ($bootstrapSource.Contains('STATUS_READER_ACL_CONFIGURATION_FAILED', [StringComparison]::Ordinal)) 'status reader ACL unexpected output must fail closed'
foreach ($forbidden in @('Invoke-WebRequest','Invoke-RestMethod','curl.exe','Start-BitsTransfer','gh api','Register-ScheduledTask','New-ScheduledTask')) {
    Assert-True (-not $bootstrapSource.Contains($forbidden, [StringComparison]::OrdinalIgnoreCase)) "CI/JIT bootstrap must not add network or task-definition primitive $forbidden"
}

# Verify the bootstrap pins the accepted merged PR #144 source and rejects any
# installer/worker/status-access drift.
$bootstrapTokens=$null;$bootstrapErrors=$null
$bootstrapAst=[Management.Automation.Language.Parser]::ParseInput($bootstrapSource,[ref]$bootstrapTokens,[ref]$bootstrapErrors)
Assert-True ($bootstrapErrors.Count -eq 0) 'bootstrap must parse'
& {
    foreach($name in @('acceptedSourceCommit','acceptedManageBlob','acceptedWorkerBlob','acceptedStatusAccessBlob','manageRelative','workerRelative','statusAccessRelative')){
        $assignment=$bootstrapAst.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq ('$'+$name)},$false)
        . ([scriptblock]::Create($assignment.Extent.Text))
    }
    $acceptedManage=(& git -C $deployRoot rev-parse ($acceptedSourceCommit+':'+$manageRelative)).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $acceptedManage -ceq $acceptedManageBlob) 'bootstrap manager pin must match accepted PR #144 merge'
    $acceptedWorker=(& git -C $deployRoot rev-parse ($acceptedSourceCommit+':'+$workerRelative)).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $acceptedWorker -ceq $acceptedWorkerBlob) 'bootstrap worker pin must match accepted PR #144 merge'
    $acceptedStatusAccess=(& git -C $deployRoot rev-parse ($acceptedSourceCommit+':'+$statusAccessRelative)).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $acceptedStatusAccess -ceq $acceptedStatusAccessBlob) 'bootstrap status-access pin must match accepted source bytes'
    $currentManage=(& git -C $deployRoot rev-parse ('HEAD:'+$manageRelative)).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $currentManage -ceq $acceptedManageBlob) 'candidate manager must match accepted merged manager bytes'
    $currentWorker=(& git -C $deployRoot rev-parse ('HEAD:'+$workerRelative)).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $currentWorker -ceq $acceptedWorkerBlob) 'current worker must match accepted PR #144 merged bytes'
    $currentStatusAccess=(& git -C $deployRoot rev-parse ('HEAD:'+$statusAccessRelative)).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $currentStatusAccess -ceq $acceptedStatusAccessBlob) 'current status-access helper must match accepted bytes'
    $guard=$bootstrapAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-AcceptedCheckout'},$false)
    . ([scriptblock]::Create($guard.Extent.Text))
    $fixture=[ordered]@{Branch='main';Dirty=$false;Head=$acceptedSourceCommit;Origin=$acceptedSourceCommit;Ancestor=$true;Manage=$acceptedManageBlob;Worker=$acceptedWorkerBlob;StatusAccess=$acceptedStatusAccessBlob}
    function Invoke-GitRead([string[]]$Arguments){
        switch($Arguments[2]){
            'branch' {$fixture.Branch;return}
            'status' {if($fixture.Dirty){' M synthetic'};return}
            'rev-parse' {
                switch($Arguments[3]){
                    '--show-toplevel' {'C:\synthetic-checkout';return}
                    'HEAD' {$fixture.Head;return}
                    'refs/remotes/origin/main' {$fixture.Origin;return}
                    ('HEAD:'+$manageRelative) {$fixture.Manage;return}
                    ('HEAD:'+$workerRelative) {$fixture.Worker;return}
                    ('HEAD:'+$statusAccessRelative) {$fixture.StatusAccess;return}
                }
            }
        }
        throw 'UNEXPECTED_GIT_READ'
    }
    function git {
        if(($args -join ' ') -cne ('-C C:\synthetic-checkout merge-base --is-ancestor '+$acceptedSourceCommit+' '+$fixture.Head)){throw 'UNEXPECTED_GIT_COMMAND'}
        $script:LASTEXITCODE=if($fixture.Ancestor){0}else{1}
    }
    $context=Assert-AcceptedCheckout
    Assert-True ($context.Head -ceq $acceptedSourceCommit) 'accepted PR #144 checkout must pass guard'
    foreach($case in @(
        @{Field='Manage';Value='622ded670d2805bf163699a77c076454e92f90bc';Code='ACCEPTED_CONTROL_SOURCE_CHANGED'},
        @{Field='Manage';Value=('f'*40);Code='ACCEPTED_CONTROL_SOURCE_CHANGED'},
        @{Field='Worker';Value='1877c993dabe7e9d1e2a712a317a0d935ab74dfd';Code='ACCEPTED_CONTROL_SOURCE_CHANGED'},
        @{Field='Worker';Value=('f'*40);Code='ACCEPTED_CONTROL_SOURCE_CHANGED'},
        @{Field='StatusAccess';Value=('f'*40);Code='ACCEPTED_CONTROL_SOURCE_CHANGED'},
        @{Field='Branch';Value='feature/synthetic';Code='SOURCE_MAIN_REQUIRED'},
        @{Field='Branch';Value='';Code='SOURCE_MAIN_REQUIRED'},
        @{Field='Dirty';Value=$true;Code='SOURCE_WORKTREE_DIRTY'},
        @{Field='Origin';Value=('f'*40);Code='SOURCE_MAIN_NOT_CURRENT'},
        @{Field='Ancestor';Value=$false;Code='ACCEPTED_SOURCE_ANCESTRY_REQUIRED'}
    )){
        $previous=$fixture[$case.Field];$fixture[$case.Field]=$case.Value;$refusal=$null
        try{$null=Assert-AcceptedCheckout}catch{$refusal=$_.Exception.Message}finally{$fixture[$case.Field]=$previous}
        Assert-True ($refusal -ceq $case.Code) ('bootstrap must fail closed: '+$case.Code)
    }
}
Assert-True ($bootstrapSource.Contains('DO_NOT_RETRY_INSTALL') -and $bootstrapSource.Contains('DO_NOT_HAND_EDIT')) 'pin refresh must preserve owner-local operational holds'

$statusAccessSource = Get-Content -LiteralPath (Join-Path $deployRoot 'Configure-CiJitStatusAccess.ps1') -Raw
Assert-True ($statusAccessSource.Contains('Set-Ci10StatusReaderAcl -ReaderSid $PermittedReaderSid', [StringComparison]::Ordinal)) 'status access helper must delegate to accepted status reader ACL primitive'
Assert-True ($statusAccessSource.Contains('CI_JIT_STATUS_READER_ACL=PASS', [StringComparison]::Ordinal)) 'status access helper must emit only the bounded PASS marker on success'
$statusProjectionPath = Join-Path (Split-Path (Split-Path $deployRoot -Parent) -Parent) 'ci-dispatch/StatusProjection.psm1'
$statusProjectionSource = Get-Content -LiteralPath $statusProjectionPath -Raw
$statusProjectionTokens=$null;$statusProjectionErrors=$null
$statusProjectionAst=[Management.Automation.Language.Parser]::ParseInput($statusProjectionSource,[ref]$statusProjectionTokens,[ref]$statusProjectionErrors)
Assert-True ($statusProjectionErrors.Count -eq 0) 'status projection module must parse'
$statusReaderAclAst=$statusProjectionAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Set-Ci10StatusReaderAcl'},$false)
Assert-True ($null -ne $statusReaderAclAst) 'accepted status reader ACL primitive must be discoverable'
$statusReaderAclSource=$statusReaderAclAst.Extent.Text
Assert-True ($statusReaderAclSource.Contains('ReadAndExecute', [StringComparison]::Ordinal) -and $statusReaderAclSource.Contains('Synchronize', [StringComparison]::Ordinal)) 'owner status projection ACL must remain read/execute plus synchronize only'
foreach($forbiddenRight in @('Modify','Write','FullControl','ChangePermissions','TakeOwnership')){
    Assert-True (-not $statusReaderAclSource.Contains($forbiddenRight, [StringComparison]::Ordinal)) "owner status projection ACL must not grant $forbiddenRight"
}

$deployFiles = @(Get-ChildItem -LiteralPath $deployRoot -File | Where-Object { $_.Extension -in @('.ps1', '.psm1') })
$allDeploySource = ($deployFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
foreach ($forbidden in @(
    'Set-VM', 'Start-VM', 'Stop-VM', 'Restart-VM', 'Remove-VM',
    'Add-LocalGroupMember', 'Set-ExecutionPolicy', 'Set-AppLockerPolicy',
    'Set-NetFirewall', 'New-NetFirewall', 'ssh-keyscan', 'Invoke-WebRequest',
    'TcpListener', 'HttpListener'
)) {
    Assert-True (-not $allDeploySource.Contains($forbidden, [StringComparison]::OrdinalIgnoreCase)) "deployment scripts must not contain forbidden mutation/listener primitive $forbidden"
}

Write-Host "Host Agent deployment contract assertions PASS: $script:Assertions"
