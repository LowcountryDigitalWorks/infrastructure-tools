[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Assertions = 0
function Assert-True([bool]$Value, [string]$Message) {
    $script:Assertions++
    if (-not $Value) { throw "ASSERTION_FAILED: $Message" }
}

function Assert-Refused([scriptblock]$Action, [string]$Code) {
    $script:Assertions++
    try {
        & $Action
    } catch {
        if ($_.Exception.Message -ceq $Code) { return }
        throw "EXPECTED_REFUSAL: $Code (got $($_.Exception.Message))"
    }
    throw "EXPECTED_REFUSAL: $Code"
}

$deployRoot = Split-Path -Parent $PSScriptRoot
$managePath = Join-Path $deployRoot 'Manage-AdminPrivilegedHelper.ps1'
$workerPath = Join-Path $deployRoot 'Invoke-AdminPrivilegedOperation.ps1'
$bootstrapPath = Join-Path $deployRoot 'Bootstrap-AdminPrivilegedHelper.ps1'

# 1. AST parser validation on all 3 deployment scripts
foreach ($scriptPath in @($managePath, $workerPath, $bootstrapPath)) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "Script parses without errors: $(Split-Path -Leaf $scriptPath)"
}

# 2. Plan mode verification on Manage-AdminPrivilegedHelper.ps1 and Bootstrap-AdminPrivilegedHelper.ps1
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$ownerSid = $identity.User.Value
$actualWorkerSha = (Get-FileHash -LiteralPath $workerPath -Algorithm SHA256).Hash.ToLowerInvariant()

$managePlan = & $managePath -Mode Plan -OwnerSid $ownerSid
Assert-True ($managePlan -contains 'ADMIN_PRIVILEGED_HELPER_PLAN=PASS') 'Manage Plan emits PASS'
Assert-True ($managePlan -contains 'TASK_COUNT=1') 'Manage Plan specifies 1 task'
Assert-True ($managePlan -contains 'TRIGGER_COUNT=0') 'Manage Plan specifies 0 triggers'
Assert-True ($managePlan -contains ('OWNER_SID=' + $ownerSid)) 'Manage Plan preserves owner SID'
Assert-True ($managePlan -contains ('WORKER_SHA256=' + $actualWorkerSha)) 'Manage Plan hashes worker correctly'

# 2b. Bootstrap-AdminPrivilegedHelper.ps1 pins and checkout validation
$bootstrapSource = Get-Content -LiteralPath $bootstrapPath -Raw
$actualManageBlob = (& git hash-object $managePath).Trim()
$actualWorkerBlob = (& git hash-object $workerPath).Trim()
$actualManageSha = (Get-FileHash -LiteralPath $managePath -Algorithm SHA256).Hash.ToLowerInvariant()
$actualWorkerSha = (Get-FileHash -LiteralPath $workerPath -Algorithm SHA256).Hash.ToLowerInvariant()

Assert-True ($bootstrapSource.Contains($actualManageBlob, [StringComparison]::Ordinal)) 'Bootstrap pins current Manage blob'
Assert-True ($bootstrapSource.Contains($actualWorkerBlob, [StringComparison]::Ordinal)) 'Bootstrap pins current Worker blob'
Assert-True ($bootstrapSource.Contains($actualManageSha, [StringComparison]::Ordinal)) 'Bootstrap pins current Manage sha256'
Assert-True ($bootstrapSource.Contains($actualWorkerSha, [StringComparison]::Ordinal)) 'Bootstrap pins current Worker sha256'
Assert-True ($bootstrapSource.Contains("branch', '--show-current", [StringComparison]::Ordinal)) 'Bootstrap checks current branch'
Assert-True ($bootstrapSource.Contains('$branch -cne ''main''', [StringComparison]::Ordinal)) 'Bootstrap requires main branch'
Assert-True ($bootstrapSource.Contains("status', '--porcelain", [StringComparison]::Ordinal)) 'Bootstrap requires clean worktree'
Assert-True ($bootstrapSource.Contains('refs/remotes/origin/main', [StringComparison]::Ordinal)) 'Bootstrap binds HEAD to origin/main'
Assert-True ($bootstrapSource.Contains('LowcountryDigitalWorks/infrastructure-tools', [StringComparison]::Ordinal)) 'Bootstrap checks origin URL'
Assert-True (-not $bootstrapSource.Contains('SkipProvenance', [StringComparison]::OrdinalIgnoreCase)) 'Bootstrap has no bypass flag'

$bootstrapAst = [Management.Automation.Language.Parser]::ParseFile($bootstrapPath, [ref]$null, [ref]$null)
$checkoutFn = $bootstrapAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-AcceptedCheckout' }, $false)
if ($null -eq $checkoutFn) { throw 'FUNCTION_REQUIRED: Assert-AcceptedCheckout' }

& {
    param([string]$CheckoutFnSource, [string]$AcceptedManageBlob, [string]$AcceptedWorkerBlob)
    $manageRelative = 'host-agent/deploy/Manage-AdminPrivilegedHelper.ps1'
    $workerRelative = 'host-agent/deploy/Invoke-AdminPrivilegedOperation.ps1'
    $acceptedManageBlob = $AcceptedManageBlob
    $acceptedWorkerBlob = $AcceptedWorkerBlob
    $approvedOrigins = @(
        'https://github.com/LowcountryDigitalWorks/infrastructure-tools.git',
        'https://github.com/LowcountryDigitalWorks/infrastructure-tools',
        'git@github.com:LowcountryDigitalWorks/infrastructure-tools.git'
    )
    . ([scriptblock]::Create($CheckoutFnSource))

    $fixture = [ordered]@{
        OriginUrl = 'https://github.com/LowcountryDigitalWorks/infrastructure-tools.git'
        Branch = 'main'
        Dirty = $false
        Head = '6fb9b5926a1c45f601b083dbada0eba61d23761d'
        OriginMain = '6fb9b5926a1c45f601b083dbada0eba61d23761d'
        ManageBlob = $AcceptedManageBlob
        WorkerBlob = $AcceptedWorkerBlob
    }

    function Invoke-GitRead([string[]]$Arguments) {
        switch ($Arguments[2]) {
            'config' { $fixture.OriginUrl; return }
            'branch' { $fixture.Branch; return }
            'status' { if ($fixture.Dirty) { ' M modified' }; return }
            'rev-parse' {
                switch ($Arguments[3]) {
                    '--show-toplevel' { 'C:\synthetic-repo'; return }
                    'HEAD' { $fixture.Head; return }
                    'refs/remotes/origin/main' { $fixture.OriginMain; return }
                    'HEAD:host-agent/deploy/Manage-AdminPrivilegedHelper.ps1' { $fixture.ManageBlob; return }
                    'HEAD:host-agent/deploy/Invoke-AdminPrivilegedOperation.ps1' { $fixture.WorkerBlob; return }
                }
            }
        }
        throw "UNEXPECTED_GIT_READ: $($Arguments -join ' ')"
    }

    $accepted = Assert-AcceptedCheckout
    Assert-True ($accepted.Root -ceq 'C:\synthetic-repo') 'Synthetic Assert-AcceptedCheckout passes on valid fixture'

    # Alternate approved origins pass
    $fixture.OriginUrl = 'https://github.com/LowcountryDigitalWorks/infrastructure-tools'
    $acceptedNoGit = Assert-AcceptedCheckout
    Assert-True ($acceptedNoGit.Root -ceq 'C:\synthetic-repo') 'Assert-AcceptedCheckout passes without .git suffix'

    $fixture.OriginUrl = 'git@github.com:LowcountryDigitalWorks/infrastructure-tools.git'
    $acceptedSsh = Assert-AcceptedCheckout
    Assert-True ($acceptedSsh.Root -ceq 'C:\synthetic-repo') 'Assert-AcceptedCheckout passes with SSH URL'

    # Non-main branch rejected
    $fixture.OriginUrl = 'https://github.com/LowcountryDigitalWorks/infrastructure-tools.git'
    $fixture.Branch = 'feat/some-branch'
    Assert-Refused { Assert-AcceptedCheckout } 'SOURCE_MAIN_REQUIRED'
    $fixture.Branch = 'main'

    # Dirty worktree rejected
    $fixture.Dirty = $true
    Assert-Refused { Assert-AcceptedCheckout } 'SOURCE_WORKTREE_DIRTY'
    $fixture.Dirty = $false

    # HEAD diverged from origin/main rejected
    $fixture.Head = '1111111111111111111111111111111111111111'
    Assert-Refused { Assert-AcceptedCheckout } 'SOURCE_MAIN_NOT_CURRENT'
    $fixture.Head = $fixture.OriginMain

    # Wrong remote origin rejected
    $fixture.OriginUrl = 'https://github.com/malicious/infrastructure-tools.git'
    Assert-Refused { Assert-AcceptedCheckout } 'SOURCE_ORIGIN_REFUSED'

    # Attacker suffix / fork origins rejected
    $fixture.OriginUrl = 'https://attacker.com/LowcountryDigitalWorks/infrastructure-tools.git'
    Assert-Refused { Assert-AcceptedCheckout } 'SOURCE_ORIGIN_REFUSED'

    $fixture.OriginUrl = 'https://github.com/LowcountryDigitalWorks/infrastructure-tools-fork.git'
    Assert-Refused { Assert-AcceptedCheckout } 'SOURCE_ORIGIN_REFUSED'

    $fixture.OriginUrl = 'https://github.com/LowcountryDigitalWorks/infrastructure-tools.git'

    # Manage blob drift rejected
    $fixture.ManageBlob = '0000000000000000000000000000000000000000'
    Assert-Refused { Assert-AcceptedCheckout } 'ACCEPTED_CONTROL_SOURCE_CHANGED'
    $fixture.ManageBlob = $AcceptedManageBlob

    # Worker blob drift rejected
    $fixture.WorkerBlob = '0000000000000000000000000000000000000000'
    Assert-Refused { Assert-AcceptedCheckout } 'ACCEPTED_CONTROL_SOURCE_CHANGED'
    $fixture.WorkerBlob = $AcceptedWorkerBlob
} $checkoutFn.Extent.Text $actualManageBlob $actualWorkerBlob

# 3. Load functions from Manage-AdminPrivilegedHelper.ps1 for unit testing
$manageAst = [Management.Automation.Language.Parser]::ParseFile($managePath, [ref]$null, [ref]$null)
foreach ($name in @('Get-ExpectedArguments', 'Assert-TaskPrincipal', 'Assert-TaskDacl', 'Assert-TaskDefinition')) {
    $node = $manageAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name }, $false)
    if ($null -eq $node) { throw "FUNCTION_REQUIRED: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}

$workerInstalled = 'C:\synthetic\Invoke-AdminPrivilegedOperation.ps1'
$pwshCommand = Microsoft.PowerShell.Core\Get-Command pwsh -ErrorAction SilentlyContinue
$script:TestPwshPath = if ($pwshCommand) { $pwshCommand.Source } else { Join-Path $PSHOME 'powershell.exe' }
function Get-Command([string]$Name) {
    if ($Name -cne 'pwsh') { throw 'UNEXPECTED_COMMAND_LOOKUP' }
    [pscustomobject]@{ Source = $script:TestPwshPath }
}

$baseSddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
$ownerAce = '(A;;GRGX;;;' + $ownerSid + ')'

function New-TaskFixture {
    $action = [pscustomobject]@{
        Path = $script:TestPwshPath
        Arguments = (Get-ExpectedArguments $actualWorkerSha)
        WorkingDirectory = ''
    }
    $actions = [pscustomobject]@{ Count = 1; Value = $action }
    $actions | Add-Member ScriptMethod Item { param($Index) if ($Index -ne 1) { throw 'INDEX_REFUSED' }; $this.Value }
    $task = [pscustomobject]@{
        Sddl = $baseSddl + $ownerAce
        Definition = [pscustomobject]@{
            Triggers = [pscustomobject]@{ Count = 0 }
            Actions = $actions
            Principal = [pscustomobject]@{ UserId = $ownerSid; LogonType = 3; RunLevel = 1 }
            Settings = [pscustomobject]@{
                Enabled = $true; AllowDemandStart = $true; StartWhenAvailable = $false; MultipleInstances = 2
                DisallowStartIfOnBatteries = $false; StopIfGoingOnBatteries = $false; ExecutionTimeLimit = 'PT15M'
            }
        }
    }
    $task | Add-Member ScriptMethod GetSecurityDescriptor { param($Flags) if ($Flags -ne 0xF) { throw 'FLAGS_REFUSED' }; $this.Sddl }
    $task
}

# Task validation passes with modeled fixture
$task = New-TaskFixture
Assert-TaskDefinition $task '\LDW-ADMIN-REVIEWED-OPERATION' $actualWorkerSha
$script:Assertions++

# Zero-trigger enforcement: non-zero triggers rejected
$taskWithTrigger = New-TaskFixture
$taskWithTrigger.Definition.Triggers.Count = 1
Assert-Refused { Assert-TaskDefinition $taskWithTrigger '\LDW-ADMIN-REVIEWED-OPERATION' $actualWorkerSha } 'TASK_TRIGGER_REFUSED'

# Multiple action rejection
$taskWithTwoActions = New-TaskFixture
$taskWithTwoActions.Definition.Actions.Count = 2
Assert-Refused { Assert-TaskDefinition $taskWithTwoActions '\LDW-ADMIN-REVIEWED-OPERATION' $actualWorkerSha } 'TASK_ACTION_COUNT_REFUSED'

# Incorrect executable rejection
$taskBadExe = New-TaskFixture
$taskBadExe.Definition.Actions.Value.Path = 'cmd.exe'
Assert-Refused { Assert-TaskDefinition $taskBadExe '\LDW-ADMIN-REVIEWED-OPERATION' $actualWorkerSha } 'TASK_ACTION_REFUSED'

# Incorrect execution time limit rejection
$taskBadTimeout = New-TaskFixture
$taskBadTimeout.Definition.Settings.ExecutionTimeLimit = 'PT2H'
Assert-Refused { Assert-TaskDefinition $taskBadTimeout '\LDW-ADMIN-REVIEWED-OPERATION' $actualWorkerSha } 'TASK_SETTINGS_REFUSED'

# ExecutionPolicy Bypass refusal: task argument cannot contain Bypass
$taskBadBypass = New-TaskFixture
$taskBadBypass.Definition.Actions.Value.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $workerInstalled + '" -WorkerSha256 ' + $actualWorkerSha
Assert-Refused { Assert-TaskDefinition $taskBadBypass '\LDW-ADMIN-REVIEWED-OPERATION' $actualWorkerSha } 'TASK_ACTION_REFUSED'

# DACL enforcement: owner can invoke but CANNOT modify/write
foreach ($badAce in @(
    ('(A;;FA;;;' + $ownerSid + ')'),
    ('(A;;GW;;;' + $ownerSid + ')'),
    ('(A;;GA;;;' + $ownerSid + ')'),
    ('(A;;0x001301BF;;;' + $ownerSid + ')'), # Modify
    ('(A;;0x00120089;;;' + $ownerSid + ')')  # Read only without execute
)) {
    $badTask = New-TaskFixture
    $badTask.Sddl = $baseSddl + $badAce
    Assert-Refused { Assert-TaskDefinition $badTask '\LDW-ADMIN-REVIEWED-OPERATION' $actualWorkerSha } 'TASK_DACL_REFUSED'
}

# 4. Load worker functions from Invoke-AdminPrivilegedOperation.ps1
$workerAst = [Management.Automation.Language.Parser]::ParseFile($workerPath, [ref]$null, [ref]$null)
foreach ($name in @('Assert-NoReparse', 'Read-Request', 'Write-Result', 'Remove-RequestSlot', 'Invoke-ElevatedIdentityProof', 'Prune-StaleResults')) {
    $node = $workerAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name }, $false)
    if ($null -eq $node) { throw "FUNCTION_REQUIRED: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}

# Proof operation execution
$proof = Invoke-ElevatedIdentityProof -CorrelationId ([guid]::NewGuid().ToString('D'))
$isElevated = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isElevated) {
    Assert-True ($proof.Success) 'ElevatedIdentityProof returns Success = true in elevated session'
    Assert-True ($proof.ResultState -ceq 'PASS') 'ElevatedIdentityProof returns PASS'
    Assert-True ($proof.ReasonCode -ceq 'NONE') 'ElevatedIdentityProof returns NONE'
    Assert-True ($proof.Details.identityState -ceq 'ELEVATED_ADMINISTRATOR') 'ElevatedIdentityProof confirms ELEVATED_ADMINISTRATOR'
    Assert-True ($proof.Details.proofStatus -ceq 'VERIFIED') 'ElevatedIdentityProof confirms VERIFIED'
} else {
    Assert-True (-not $proof.Success) 'ElevatedIdentityProof returns Success = false in non-elevated session'
    Assert-True ($proof.ResultState -ceq 'FAILED') 'ElevatedIdentityProof returns FAILED when unelevated'
    Assert-True ($proof.ReasonCode -ceq 'ELEVATION_REQUIRED') 'ElevatedIdentityProof returns ELEVATION_REQUIRED when unelevated'
    Assert-True ($proof.Details.identityState -ceq 'UNELEVATED') 'ElevatedIdentityProof detects UNELEVATED'
}

# 5. Read-Request and Write-Result isolated sandbox testing
$sandbox = Join-Path $env:TEMP ('LDW_Test_PrivilegedHelper_' + [guid]::NewGuid().ToString('N'))
$requestRoot = Join-Path $sandbox 'requests'
$resultRoot = Join-Path $sandbox 'results'
$null = New-Item -ItemType Directory -Path $requestRoot -Force
$null = New-Item -ItemType Directory -Path $resultRoot -Force
$requestPath = Join-Path $requestRoot 'request.json'

try {
    # 5a. Missing request file returns null
    $nullRequest = Read-Request
    Assert-True ($null -eq $nullRequest) 'Missing request returns null'

    # 5b. Valid request parses
    $testCorrId = [guid]::NewGuid().ToString('D')
    $validPayload = [ordered]@{
        schema = 1
        correlationId = $testCorrId
        operationId = 'ELEVATED_IDENTITY_PROOF'
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($requestPath, $validPayload, [Text.UTF8Encoding]::new($false))
    $parsed = Read-Request
    Assert-True ($parsed.CorrelationId -ceq $testCorrId) 'CorrelationId parsed correctly'
    Assert-True ($parsed.OperationId -ceq 'ELEVATED_IDENTITY_PROOF') 'OperationId parsed correctly'

    # 5c. Extra parameters / injection rejected
    $injections = @(
        [ordered]@{ schema = 1; correlationId = $testCorrId; operationId = 'ELEVATED_IDENTITY_PROOF'; command = 'whoami' },
        [ordered]@{ schema = 1; correlationId = $testCorrId; operationId = 'ELEVATED_IDENTITY_PROOF'; args = @('-f') },
        [ordered]@{ schema = 1; correlationId = $testCorrId; operationId = 'ELEVATED_IDENTITY_PROOF'; path = 'C:\' },
        [ordered]@{ schema = 2; correlationId = $testCorrId; operationId = 'ELEVATED_IDENTITY_PROOF' },
        [ordered]@{ schema = 1; correlationId = 'not-a-guid'; operationId = 'ELEVATED_IDENTITY_PROOF' }
    )
    foreach ($inj in $injections) {
        [IO.File]::WriteAllText($requestPath, ($inj | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        Assert-Refused { Read-Request } 'INVALID_REQUEST'
    }

    # 5d. Write-Result creates atomic bounded result file
    $script:CorrelationId = $testCorrId
    $script:OperationId = 'ELEVATED_IDENTITY_PROOF'
    Write-Result -Success $true -State 'PASS' -Reason 'NONE' -Details @{ identityState = 'ELEVATED_ADMINISTRATOR' }

    $resultFile = Join-Path $resultRoot ($testCorrId + '.json')
    Assert-True (Test-Path -LiteralPath $resultFile -PathType Leaf) 'Result file created'
    $resultJson = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
    Assert-True ($resultJson.schema -eq 1) 'Result schema is 1'
    Assert-True ($resultJson.correlationId -ceq $testCorrId) 'Result correlationId matches'
    Assert-True ($resultJson.operationId -ceq 'ELEVATED_IDENTITY_PROOF') 'Result operationId matches'
    Assert-True ($resultJson.success -eq $true) 'Result success is true'
    Assert-True ($resultJson.resultState -ceq 'PASS') 'Result state is PASS'
    Assert-True ($resultJson.reasonCode -ceq 'NONE') 'Result reasonCode is NONE'
    Assert-True ($resultJson.details.identityState -ceq 'ELEVATED_ADMINISTRATOR') 'Details preserved'

    # 5e. Sanitization: unsafe detail characters stripped
    $script:CorrelationId = [guid]::NewGuid().ToString('D')
    Write-Result -Success $false -State 'FAILED' -Reason 'FAILED' -Details @{
        'safe_key' = 'safe-value'
        'bad key with spaces' = 'bad value'
        'dangerous' = "value`nwith`nnewlines;calc"
    }
    $sanitizedFile = Join-Path $resultRoot ($script:CorrelationId + '.json')
    $sanitizedJson = Get-Content -LiteralPath $sanitizedFile -Raw | ConvertFrom-Json
    Assert-True ($sanitizedJson.details.safe_key -ceq 'safe-value') 'Safe key preserved'
    Assert-True ($null -eq $sanitizedJson.details.PSObject.Properties['bad key with spaces']) 'Unsafe key stripped'
    Assert-True ($null -eq $sanitizedJson.details.PSObject.Properties['dangerous']) 'Unsafe value stripped'

    # 5f. Restart / crash semantics:
    # 5f-1. Terminal result already exists: completed => never execute again, unlink request slot, preserve result
    [IO.File]::WriteAllText($requestPath, $validPayload, [Text.UTF8Encoding]::new($false))
    $repeatParsed = Read-Request
    Assert-True ($null -eq $repeatParsed) 'Completed request returns null from Read-Request'
    Assert-True (-not (Test-Path -LiteralPath $requestPath)) 'Request slot unlinked when terminal result exists'
    $existingResult = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
    Assert-True ($existingResult.resultState -ceq 'PASS') 'Terminal result preserved as PASS'

    # 5f-2. In-flight STARTED result (< 15m): do not re-execute, preserve request slot and STARTED state
    $inFlightCorrId = [guid]::NewGuid().ToString('D')
    $inFlightPayload = [ordered]@{ schema = 1; correlationId = $inFlightCorrId; operationId = 'ELEVATED_IDENTITY_PROOF' } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($requestPath, $inFlightPayload, [Text.UTF8Encoding]::new($false))
    $script:CorrelationId = $inFlightCorrId
    $script:OperationId = 'ELEVATED_IDENTITY_PROOF'
    Write-Result -Success $true -State 'STARTED' -Reason 'NONE'
    $inFlightFile = Join-Path $resultRoot ($inFlightCorrId + '.json')
    (Get-Item -LiteralPath $inFlightFile).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-5)
    $inFlightParsed = Read-Request
    Assert-True ($null -eq $inFlightParsed) 'In-flight (< 15m) returns null from Read-Request'
    Assert-True (Test-Path -LiteralPath $requestPath) 'Request slot preserved for active in-flight task'
    $inFlightJson = Get-Content -LiteralPath $inFlightFile -Raw | ConvertFrom-Json
    Assert-True ($inFlightJson.resultState -ceq 'STARTED') 'In-flight record preserved as STARTED'

    # 5f-3. In-flight STARTED result (>= 15m): timeout/crash => reconcile to TIMEOUT, unlink slot, never re-execute
    (Get-Item -LiteralPath $inFlightFile).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-20)
    $inFlightTimeoutParsed = Read-Request
    Assert-True ($null -eq $inFlightTimeoutParsed) 'Timed out in-flight returns null from Read-Request'
    Assert-True (-not (Test-Path -LiteralPath $requestPath)) 'Request slot unlinked for timed out in-flight'
    $inFlightTimeoutJson = Get-Content -LiteralPath $inFlightFile -Raw | ConvertFrom-Json
    Assert-True ($inFlightTimeoutJson.resultState -ceq 'FAILED' -and $inFlightTimeoutJson.reasonCode -ceq 'TIMEOUT') 'In-flight crash reconciled to TIMEOUT'

    # 5f-4. Corrupt result file: fail closed with INVALID_ADAPTER_RESULT
    $corruptCorrId = [guid]::NewGuid().ToString('D')
    $corruptPayload = [ordered]@{ schema = 1; correlationId = $corruptCorrId; operationId = 'ELEVATED_IDENTITY_PROOF' } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($requestPath, $corruptPayload, [Text.UTF8Encoding]::new($false))
    $corruptFile = Join-Path $resultRoot ($corruptCorrId + '.json')
    [IO.File]::WriteAllText($corruptFile, '{"schema":999}', [Text.UTF8Encoding]::new($false))
    Assert-Refused { Read-Request } 'INVALID_ADAPTER_RESULT'
    Remove-Item -LiteralPath $corruptFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue

    # 5g. Stale request crash/timeout reconciliation: unstarted request > 15m writes TIMEOUT and unlinks slot
    $staleCorrId = [guid]::NewGuid().ToString('D')
    $stalePayload = [ordered]@{ schema = 1; correlationId = $staleCorrId; operationId = 'ELEVATED_IDENTITY_PROOF' } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($requestPath, $stalePayload, [Text.UTF8Encoding]::new($false))
    (Get-Item -LiteralPath $requestPath).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-20)
    $staleParsed = Read-Request
    Assert-True ($null -eq $staleParsed) 'Stale request returns null from Read-Request'
    Assert-True (-not (Test-Path -LiteralPath $requestPath)) 'Stale request file unlinked from slot'
    $staleResultFile = Join-Path $resultRoot ($staleCorrId + '.json')
    Assert-True (Test-Path -LiteralPath $staleResultFile) 'Stale result file created'
    $staleJson = Get-Content -LiteralPath $staleResultFile -Raw | ConvertFrom-Json
    Assert-True ($staleJson.resultState -ceq 'FAILED' -and $staleJson.reasonCode -ceq 'TIMEOUT') 'Stale request recorded as TIMEOUT'

    # 5h. Demand-driven result lifecycle pruning
    $oldCorrId = [guid]::NewGuid().ToString('D')
    $oldResultFile = Join-Path $resultRoot ($oldCorrId + '.json')
    [IO.File]::WriteAllText($oldResultFile, '{}', [Text.UTF8Encoding]::new($false))
    (Get-Item -LiteralPath $oldResultFile).LastWriteTimeUtc = [DateTime]::UtcNow.AddHours(-25)
    $newCorrId = [guid]::NewGuid().ToString('D')
    $newResultFile = Join-Path $resultRoot ($newCorrId + '.json')
    [IO.File]::WriteAllText($newResultFile, '{}', [Text.UTF8Encoding]::new($false))
    (Get-Item -LiteralPath $newResultFile).LastWriteTimeUtc = [DateTime]::UtcNow.AddHours(-1)
    Prune-StaleResults
    Assert-True (-not (Test-Path -LiteralPath $oldResultFile)) 'Old result (>24h) pruned'
    Assert-True (Test-Path -LiteralPath $newResultFile) 'New result preserved'

    # 5h-2. Pruning fails closed on error (throw PRUNING_FAILED)
    $lockedCorrId = [guid]::NewGuid().ToString('D')
    $lockedResultFile = Join-Path $resultRoot ($lockedCorrId + '.json')
    [IO.File]::WriteAllText($lockedResultFile, '{}', [Text.UTF8Encoding]::new($false))
    (Get-Item -LiteralPath $lockedResultFile).LastWriteTimeUtc = [DateTime]::UtcNow.AddHours(-25)
    $lockStream = [IO.File]::Open($lockedResultFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        Assert-Refused { Prune-StaleResults } 'PRUNING_FAILED'
    } finally {
        $lockStream.Dispose()
        Remove-Item -LiteralPath $lockedResultFile -Force -ErrorAction SilentlyContinue
    }

    # 5i. Safe Uninstall preflight unit tests
    $uninstallFn = $manageAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Uninstall-Tasks' }, $false)
    if ($null -eq $uninstallFn) { throw 'FUNCTION_REQUIRED: Uninstall-Tasks' }

    & {
        param([string]$UninstallSource, [string]$SandboxDir)
        $controlRoot = $SandboxDir
        $requestRoot = Join-Path $controlRoot 'requests'
        $resultRoot = Join-Path $controlRoot 'results'
        $taskName = '\LDW-ADMIN-REVIEWED-OPERATION'
        $AcceptUninstall = $true

        function Assert-Elevated { }
        function Assert-NoReparse([string]$Path) { }

        . ([scriptblock]::Create($UninstallSource))

        # Rejection when pending request exists
        $testReq = Join-Path $requestRoot 'request.json'
        [IO.File]::WriteAllText($testReq, '{}', [Text.UTF8Encoding]::new($false))
        Assert-Refused { Uninstall-Tasks } 'PENDING_REQUEST_REFUSED'
        Remove-Item -LiteralPath $testReq -Force

        # Rejection when active in-flight task (< 15m STARTED) exists
        $testRes = Join-Path $resultRoot ([guid]::NewGuid().ToString('D') + '.json')
        [IO.File]::WriteAllText($testRes, '{"schema":1,"resultState":"STARTED"}', [Text.UTF8Encoding]::new($false))
        Assert-Refused { Uninstall-Tasks } 'ACTIVE_TASK_REFUSED'
        Remove-Item -LiteralPath $testRes -Force

        # Active Task Scheduler running state (state 4, 2, or 0) rejected
        foreach ($badState in @(4, 2, 0)) {
            $mockTask = [pscustomobject]@{ State = $badState }
            $mockFolder = [pscustomobject]@{}
            $mockFolder | Add-Member ScriptMethod GetTask { param($tName) $mockTask }
            $mockFolder | Add-Member ScriptMethod DeleteTask { param($tName, $flags) }
            $mockService = [pscustomobject]@{}
            $mockService | Add-Member ScriptMethod GetFolder { param($f) $mockFolder }
            function script:Get-TaskService { $mockService }

            Assert-Refused { Uninstall-Tasks } 'ACTIVE_TASK_REFUSED'
        }
    } $uninstallFn.Extent.Text $sandbox

} finally {
    if (Test-Path -LiteralPath $sandbox) {
        Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 6. Registry Consistency Contract (C# AdminReviewedOperationRegistry == PowerShell $ReviewedOperationRegistry)
$contractCsPath = [IO.Path]::GetFullPath((Join-Path $deployRoot '..\src\LDW.AdminBroker\AdminPrivilegedControlContract.cs'))
Assert-True (Test-Path -LiteralPath $contractCsPath) 'AdminPrivilegedControlContract.cs exists'
$csContent = Get-Content -LiteralPath $contractCsPath -Raw
$classMatch = [regex]::Match($csContent, 'public static class AdminReviewedOperationRegistry\s*\{(?<classbody>.*?)\}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
Assert-True ($classMatch.Success) 'Found AdminReviewedOperationRegistry in AdminPrivilegedControlContract.cs'
$csMatches = [regex]::Matches($classMatch.Groups['classbody'].Value, '"([A-Z0-9_]+)"')
$csOperations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($m in $csMatches) {
    [void]$csOperations.Add($m.Groups[1].Value)
}

$workerContent = Get-Content -LiteralPath $workerPath -Raw
$registryMatch = [regex]::Match($workerContent, '\$ReviewedOperationRegistry\s*=\s*@\{(?<bodycontent>.*?)\n\}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
Assert-True ($registryMatch.Success) 'Found $ReviewedOperationRegistry block in worker script'

$psOperations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$opMatches = [regex]::Matches($registryMatch.Groups['bodycontent'].Value, "'([A-Z0-9_]+)'\s*=")
foreach ($m in $opMatches) {
    [void]$psOperations.Add($m.Groups[1].Value)
}

Assert-True ($csOperations.SetEquals($psOperations)) 'C# AdminReviewedOperationRegistry matches PowerShell $ReviewedOperationRegistry exactly'

Write-Host "Admin Privileged Helper contract assertions PASS: $script:Assertions"
