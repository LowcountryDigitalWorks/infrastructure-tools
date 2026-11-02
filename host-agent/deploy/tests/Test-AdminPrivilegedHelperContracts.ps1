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

$bootstrapPlan = & $bootstrapPath -Mode Plan
Assert-True ($bootstrapPlan -contains 'ADMIN_PRIVILEGED_HELPER_BOOTSTRAP=PASS') 'Bootstrap Plan emits PASS'
Assert-True ($bootstrapPlan -contains 'ADMIN_PRIVILEGED_HELPER_PLAN=PASS') 'Bootstrap forwards Plan output'
Assert-True ($bootstrapPlan -contains 'TRIGGER_COUNT=0') 'Bootstrap confirms 0 triggers'

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
foreach ($name in @('Assert-NoReparse', 'Read-Request', 'Write-Result', 'Invoke-ElevatedIdentityProof')) {
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

} finally {
    if (Test-Path -LiteralPath $sandbox) {
        Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Admin Privileged Helper contract assertions PASS: $script:Assertions"
