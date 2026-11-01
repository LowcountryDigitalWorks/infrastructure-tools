[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Assertions = 0
function Assert-True([bool]$Value, [string]$Message) {
    $script:Assertions++
    if (-not $Value) { throw "ASSERTION_FAILED: $Message" }
}

function Assert-Result($Result, [bool]$Success, [string]$State, [string]$Reason) {
    Assert-True ($Result.Success -eq $Success) "success expected $Success"
    Assert-True ($Result.State -ceq $State) "state expected $State"
    Assert-True ($Result.Reason -ceq $Reason) "reason expected $Reason"
}

$deployRoot = Split-Path -Parent $PSScriptRoot
$workerPath = Join-Path $deployRoot 'Invoke-CiJitControlTask.ps1'
$clientPath = Join-Path $deployRoot 'Invoke-CiJitLocalTaskClient.ps1'
$contractPath = Join-Path (Join-Path (Join-Path $deployRoot '..') 'src/LDW.AdminBroker') 'CiJitControlContract.cs'

# 1. Parse worker script with AST parser
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($workerPath, [ref]$tokens, [ref]$errors)
Assert-True (@($errors).Count -eq 0) 'worker script must parse without errors'

# 2. Verify required functions exist in AST
$requiredFunctions = @('Invoke-Child', 'Get-OutputValue', 'Resolve-CiJitDispatcherFailureReason', 'Invoke-DispatcherMode')
foreach ($fnName in $requiredFunctions) {
    $fnAst = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $fnName }, $false)
    Assert-True ($null -ne $fnAst) "Function $fnName must exist in worker"
}

# 3. Extract script variables and helper functions
$allowedClassificationsAst = $ast.Find({
    param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -ceq '$script:AllowedDispatcherClassifications'
}, $false)
Assert-True ($null -ne $allowedClassificationsAst) '$script:AllowedDispatcherClassifications must exist'

$patternAst = $ast.Find({
    param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -ceq '$script:DispatcherClassificationPattern'
}, $false)
Assert-True ($null -ne $patternAst) '$script:DispatcherClassificationPattern must exist'

# Load the pattern and functions in test scope
$capacityPatternAst = $ast.Find({
    param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -ceq '$script:CapacitySubreasonPattern'
}, $false)
Assert-True ($null -ne $capacityPatternAst) '$script:CapacitySubreasonPattern must exist'

. ([scriptblock]::Create($capacityPatternAst.Extent.Text))
. ([scriptblock]::Create($allowedClassificationsAst.Extent.Text))
. ([scriptblock]::Create($patternAst.Extent.Text))

$resolveFnAst = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Resolve-CiJitDispatcherFailureReason' }, $false)
. ([scriptblock]::Create($resolveFnAst.Extent.Text))

$getOutputValueAst = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-OutputValue' }, $false)
. ([scriptblock]::Create($getOutputValueAst.Extent.Text))

# 4. Unit test Resolve-CiJitDispatcherFailureReason mapping
Assert-True ((Resolve-CiJitDispatcherFailureReason 'RECOVERY_BUSY_OR_UNCERTAIN') -ceq 'RECOVERY_BUSY_OR_UNCERTAIN') 'RECOVERY_BUSY_OR_UNCERTAIN maps directly'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'DISPATCHER_BUSY_OR_LOCK_UNCERTAIN') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'DISPATCHER_BUSY_OR_LOCK_UNCERTAIN maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'CONTROLLER_GATE_UNCERTAIN') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'CONTROLLER_GATE_UNCERTAIN maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'CONTROLLER_FAILED_OR_CLEANUP_UNCERTAIN') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'CONTROLLER_FAILED_OR_CLEANUP_UNCERTAIN maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'CLEANUP_UNCONFIRMED') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'CLEANUP_UNCONFIRMED maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'STALE_PROFILE_OWNERSHIP_REFUSED') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'STALE_PROFILE_OWNERSHIP_REFUSED maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'STALE_VM_OWNERSHIP_AMBIGUOUS') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'STALE_VM_OWNERSHIP_AMBIGUOUS maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'ORPHAN_VM_REQUIRES_CONCLUSIVE_STATE') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'ORPHAN_VM_REQUIRES_CONCLUSIVE_STATE maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'RUNNER_OWNERSHIP_UNCERTAIN') -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'RUNNER_OWNERSHIP_UNCERTAIN maps to LOCK_OR_RESIDUE_UNCERTAIN'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'PROVENANCE_MISMATCH') -ceq 'PROVENANCE_MISMATCH') 'PROVENANCE_MISMATCH maps to PROVENANCE_MISMATCH'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'BUNDLE_PROVENANCE_MISMATCH') -ceq 'PROVENANCE_MISMATCH') 'BUNDLE_PROVENANCE_MISMATCH maps to PROVENANCE_MISMATCH'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'MANIFEST_HASH_DRIFT') -ceq 'PROVENANCE_MISMATCH') 'MANIFEST_HASH_DRIFT maps to PROVENANCE_MISMATCH'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'PREFLIGHT_OWNER_UNTRUSTED') -ceq 'PROVENANCE_MISMATCH') 'PREFLIGHT_OWNER_UNTRUSTED maps to PROVENANCE_MISMATCH'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'QUEUE_UNAVAILABLE') -ceq 'QUEUE_UNAVAILABLE') 'QUEUE_UNAVAILABLE maps to QUEUE_UNAVAILABLE'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'API_READ_FAILED') -ceq 'QUEUE_UNAVAILABLE') 'API_READ_FAILED maps to QUEUE_UNAVAILABLE'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'API_RESPONSE_INVALID') -ceq 'QUEUE_UNAVAILABLE') 'API_RESPONSE_INVALID maps to QUEUE_UNAVAILABLE'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'QUEUE_BOUND_EXCEEDED') -ceq 'QUEUE_UNAVAILABLE') 'QUEUE_BOUND_EXCEEDED maps to QUEUE_UNAVAILABLE'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'PROFILE_CONTRACT_REFUSED') -ceq 'TARGET_REFUSED') 'PROFILE_CONTRACT_REFUSED maps to TARGET_REFUSED'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'PROFILE_REGISTRY_REFUSED') -ceq 'TARGET_REFUSED') 'PROFILE_REGISTRY_REFUSED maps to TARGET_REFUSED'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'WRONG_REPOSITORY') -ceq 'TARGET_REFUSED') 'WRONG_REPOSITORY maps to TARGET_REFUSED'

# 5. Unit test fallbacks for unknown / malformed / missing
Assert-True ((Resolve-CiJitDispatcherFailureReason 'DISPATCHER_OPERATION_FAILED') -ceq 'FAILED') 'DISPATCHER_OPERATION_FAILED maps to generic FAILED'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'FAILED') -ceq 'FAILED') 'FAILED maps to generic FAILED'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'UNKNOWN_ERROR') -ceq 'FAILED') 'unknown code maps to generic FAILED'
Assert-True ((Resolve-CiJitDispatcherFailureReason 'SOMETHING_ARBITRARY') -ceq 'FAILED') 'arbitrary code maps to generic FAILED'
Assert-True ((Resolve-CiJitDispatcherFailureReason '') -ceq 'FAILED') 'empty classification maps to generic FAILED'
Assert-True ((Resolve-CiJitDispatcherFailureReason $null) -ceq 'FAILED') 'null classification maps to generic FAILED'

# 6. Test Invoke-Child allowlist and stderr discard with synthetic script
$invokeChildAst = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-Child' }, $false)
. ([scriptblock]::Create($invokeChildAst.Extent.Text))

$tempTestDir = Join-Path ([IO.Path]::GetTempPath()) ('ldw-recover-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempTestDir -Force | Out-Null
try {
    $syntheticChild = Join-Path $tempTestDir 'synthetic-child.ps1'

    # Case A: Child emits allowed classification + stderr message
    Set-Content -LiteralPath $syntheticChild -Value @'
[Console]::Error.WriteLine("CRITICAL: stderr leak attempt")
Write-Output "DISPATCHER_RESULT=FAIL"
Write-Output "CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN"
exit 1
'@
    $resA = Invoke-Child $syntheticChild @()
    Assert-True ($resA.ExitCode -eq 1) 'child exit code preserved'
    Assert-True (@($resA.Lines | Where-Object { $_ -ceq 'CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN' }).Count -eq 1) 'allowed classification preserved'
    Assert-True (@($resA.Lines | Where-Object { $_ -match 'stderr leak attempt' }).Count -eq 0) 'stderr was discarded'

    # Case B: Child emits forbidden / unknown classification
    Set-Content -LiteralPath $syntheticChild -Value @'
Write-Output "DISPATCHER_RESULT=FAIL"
Write-Output "CLASSIFICATION=ARBITRARY_UNAUTHORIZED_CLASSIFICATION"
Write-Output "CLASSIFICATION=malformed lowercase"
Write-Output "CLASSIFICATION="
exit 1
'@
    $resB = Invoke-Child $syntheticChild @()
    Assert-True ($resB.ExitCode -eq 1) 'child exit code preserved'
    Assert-True (@($resB.Lines | Where-Object { $_ -match 'CLASSIFICATION=' }).Count -eq 0) 'unauthorized and malformed classifications dropped'

    # Case C: Child emits duplicate classification lines (must result in Get-OutputValue returning null)
    Set-Content -LiteralPath $syntheticChild -Value @'
Write-Output "DISPATCHER_RESULT=FAIL"
Write-Output "CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN"
Write-Output "CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN"
exit 1
'@
    $resC = Invoke-Child $syntheticChild @()
    $duplicateClassification = Get-OutputValue $resC.Lines 'CLASSIFICATION'
    Assert-True ($null -eq $duplicateClassification) 'duplicate classification lines fail closed to null'
} finally {
    if (Test-Path -LiteralPath $tempTestDir) { Remove-Item -LiteralPath $tempTestDir -Recurse -Force }
}

# 7. Test Invoke-DispatcherMode logic with mocked Invoke-Child
$ManifestSha = 'a' * 64
$Commit = 'b' * 40
$Tree = 'c' * 40
$dispatcher = 'C:\dummy\Invoke-Dispatcher.ps1'

$dispatcherModeAst = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-DispatcherMode' }, $false)
. ([scriptblock]::Create($dispatcherModeAst.Extent.Text))

$script:MockedChildResult = $null
function Invoke-Child([string]$Path, [string[]]$Arguments) {
    return $script:MockedChildResult
}

# Test 7.1: Recover with RECOVERY_BUSY_OR_UNCERTAIN
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 1
    Lines = @('DISPATCHER_RESULT=FAIL', 'CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN')
}
$r1 = Invoke-DispatcherMode Recover
Assert-Result $r1 $false 'FAILED' 'RECOVERY_BUSY_OR_UNCERTAIN'

# Test 7.2: Recover with DISPATCHER_BUSY_OR_LOCK_UNCERTAIN
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 1
    Lines = @('DISPATCHER_RESULT=FAIL', 'CLASSIFICATION=DISPATCHER_BUSY_OR_LOCK_UNCERTAIN')
}
$r2 = Invoke-DispatcherMode Recover
Assert-Result $r2 $false 'FAILED' 'LOCK_OR_RESIDUE_UNCERTAIN'

# Test 7.3: Recover with BUNDLE_PROVENANCE_MISMATCH
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 1
    Lines = @('DISPATCHER_RESULT=FAIL', 'CLASSIFICATION=BUNDLE_PROVENANCE_MISMATCH')
}
$r3 = Invoke-DispatcherMode Recover
Assert-Result $r3 $false 'FAILED' 'PROVENANCE_MISMATCH'

# Test 7.4: Recover with API_READ_FAILED
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 1
    Lines = @('DISPATCHER_RESULT=FAIL', 'CLASSIFICATION=API_READ_FAILED')
}
$r4 = Invoke-DispatcherMode Recover
Assert-Result $r4 $false 'FAILED' 'QUEUE_UNAVAILABLE'

# Test 7.5: Recover with PROFILE_CONTRACT_REFUSED
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 1
    Lines = @('DISPATCHER_RESULT=FAIL', 'CLASSIFICATION=PROFILE_CONTRACT_REFUSED')
}
$r5 = Invoke-DispatcherMode Recover
Assert-Result $r5 $false 'FAILED' 'TARGET_REFUSED'

# Test 7.6: Recover with generic fail (no classification)
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 1
    Lines = @('DISPATCHER_RESULT=FAIL')
}
$r6 = Invoke-DispatcherMode Recover
Assert-Result $r6 $false 'FAILED' 'FAILED'

# Test 7.7: Recover with unrecognized classification (null returned by Get-OutputValue)
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 1
    Lines = @('DISPATCHER_RESULT=FAIL')
}
$r7 = Invoke-DispatcherMode Recover
Assert-Result $r7 $false 'FAILED' 'FAILED'

# Test 7.8: Recover success: RECOVERED -> PASS / NONE
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 0
    Lines = @('DISPATCHER_RESULT=RECOVERED')
}
$r8 = Invoke-DispatcherMode Recover
Assert-Result $r8 $true 'PASS' 'NONE'

# Test 7.9: Recover unexpected result
$script:MockedChildResult = [pscustomobject]@{
    ExitCode = 0
    Lines = @('DISPATCHER_RESULT=UNEXPECTED_STRING')
}
$r9 = Invoke-DispatcherMode Recover
Assert-Result $r9 $false 'FAILED' 'FAILED'

# 8. Verify ReasonCodes parity across files
$workerContent = Get-Content -LiteralPath $workerPath -Raw
Assert-True ($workerContent.Contains("'RECOVERY_BUSY_OR_UNCERTAIN'")) 'worker must contain RECOVERY_BUSY_OR_UNCERTAIN'

$clientContent = Get-Content -LiteralPath $clientPath -Raw
Assert-True ($clientContent.Contains("'RECOVERY_BUSY_OR_UNCERTAIN'")) 'local client must contain RECOVERY_BUSY_OR_UNCERTAIN'

$contractContent = Get-Content -LiteralPath $contractPath -Raw
Assert-True ($contractContent.Contains('"RECOVERY_BUSY_OR_UNCERTAIN"')) 'C# contract must contain RECOVERY_BUSY_OR_UNCERTAIN'

Write-Host "CI_JIT_RECOVER_CLASSIFICATION_CONTRACT=PASS ASSERTIONS=$script:Assertions"
