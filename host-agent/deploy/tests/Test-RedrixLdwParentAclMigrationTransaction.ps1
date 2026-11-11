#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleRoot = Split-Path $PSScriptRoot -Parent
$helper = Join-Path $moduleRoot 'RedrixLdwParentAclMigrationTransaction.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'HELPER_MISSING' }

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw 'HELPER_SYNTAX_ERROR' }
$forbidden = @(
    'Set-Acl', 'icacls', 'takeown', 'Invoke-Expression', 'Start-Process',
    'New-Item', 'Remove-Item', 'Move-Item', 'Copy-Item', 'Set-Content', 'Add-Content', 'Out-File',
    'Register-ScheduledTask', 'Start-ScheduledTask', 'schtasks')
$commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() })
foreach ($name in $forbidden) {
    if ($commands -contains $name) { throw ('FORBIDDEN_COMMAND_' + $name) }
}

. $helper

$checks = 0
function Assert([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw ('ASSERTION_FAILED_' + $Code) }
    $script:checks++
}

function Get-RedrixMigrationTestChildMap {
    $ref = Get-RedrixLdwParentAclMigrationReference
    $map = @{}
    foreach ($prop in $ref.protectedChildSddlSha256Utf8.PSObject.Properties) {
        $map[$prop.Name] = [string]$prop.Value
    }
    return $map
}

function Copy-RedrixMigrationLedger([hashtable]$Ledger) {
    $copy = @{}
    foreach ($key in $Ledger.Keys) { $copy[$key] = $Ledger[$key] }
    return $copy
}

$ref = Get-RedrixLdwParentAclMigrationReference
Assert ($ref.fixedV1ReviewedOperationTaskName -ceq 'LDW-ADMIN-REVIEWED-OPERATION') 'V1_TASK_NAME_PIN'
Assert ($ref.canonicalTargetSha256Utf8SddlProperty -ceq 'd0d4816b0b001698a7f49ee24dab0eff49f784bcd9164ad5504b6e45f47f0a41') 'TARGET_SHA_PIN'
Assert ($ref.syntheticHashIsNotMutationAuthority) 'SYNTHETIC_HASH_NOT_AUTHORITY'
Assert (@($ref.protectedChildSddlSha256Utf8.PSObject.Properties).Count -eq 6) 'SIX_CHILD_PINS'

$binding = Get-RedrixLdwParentAclMigrationMachineProgramDataBinding
Assert ($binding.policy -ceq 'OK') 'MACHINE_BINDING_OK'
Assert ($binding.machineProgramDataPathBound) 'MACHINE_PROGRAMDATA_PATH_BOUND'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy) -ceq 'OK') 'POLICY_NO_CALLER_OK'

$machinePd = [string]$binding.machineKnownPath
$fakePd = Join-Path $env:TEMP 'ProgramData'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy -UntrustedCallerPath $fakePd) -ceq 'CALLER_PATH_NOT_MACHINE_KNOWN') 'FAKE_TEMP_PROGRAMDATA'
$bogusLeaf = Join-Path $env:TEMP 'NotProgramData'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy -UntrustedCallerPath $bogusLeaf) -ceq 'CALLER_PATH_NOT_MACHINE_KNOWN') 'FAKE_WRONG_LEAF'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy -UntrustedCallerPath '') -ceq 'CALLER_PATH_EMPTY_REFUSED') 'CALLER_EMPTY'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy -UntrustedCallerPath '\\srv\share\ProgramData') -ceq 'UNC_CALLER_REFUSED') 'UNC_REFUSED'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy -UntrustedCallerPath ($machinePd + '\')) -ceq 'OK') 'NORMALIZED_TRAILING_SLASH'

$oldEnv = $env:ProgramData
try {
    $env:ProgramData = Join-Path $env:TEMP 'SpoofProgramData'
    $spoofBinding = Get-RedrixLdwParentAclMigrationMachineProgramDataBinding
    Assert ($spoofBinding.policy -ceq 'PROCESS_PROGRAMDATA_SPOOFED') 'PROCESS_ENV_SPOOF_BINDING'
}
finally {
    $env:ProgramData = $oldEnv
}

Assert ((Test-RedrixLdwParentAclMigrationSyntheticHashIsNotAuthorization $ref.canonicalTargetSha256Utf8SddlProperty) -ceq 'NOT_AUTHORIZED_SYNTHETIC_HASH_ONLY') 'D0D_NOT_AUTHORIZATION'
Assert ((Test-RedrixLdwParentAclMigrationSyntheticHashIsNotAuthorization 'owner-approved') -ceq 'NOT_AUTHORIZED') 'ARBITRARY_NOT_AUTHORIZED'

$snap = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $snap) -ceq 'OK') 'VALID_PRECONDITIONS'

$drift = New-RedrixLdwParentAclMockHostSnapshot -Variant ChildDrift
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $drift) -ceq 'CHILD_SDDL_DRIFT') 'CHILD_DRIFT_HOLD'

$busy = New-RedrixLdwParentAclMockHostSnapshot -Variant TaskNotQuiescent
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $busy) -ceq 'TASK_NOT_QUIESCENT') 'TASK_BUSY_HOLD'

$rehearsal = Invoke-RedrixLdwParentAclMigrationRehearsal $snap
Assert ($rehearsal.outcome -ceq 'REHEARSAL_PASS_NO_APPLY') 'REHEARSAL_PASS'
Assert ($rehearsal.machineProgramDataPolicy -ceq 'OK') 'REHEARSAL_MACHINE_POLICY'
Assert ($rehearsal.syntheticSnapshotOnly) 'REHEARSAL_SYNTHETIC_ONLY'
Assert (-not $rehearsal.hostRootTrustAsserted) 'NO_HOST_ROOT_TRUST_ASSERT'
Assert ($rehearsal.childHashParityVerified) 'CHILD_HASH_PARITY'
Assert (-not $rehearsal.physicalAclChangeAuthorized) 'NO_PHYSICAL_AUTH'
Assert ($rehearsal.targetSha256 -ceq $ref.canonicalTargetSha256Utf8SddlProperty) 'TARGET_SHA_MATCH'
Assert ($rehearsal.applyBoundary.classification -ceq 'BLOCKED_APPROVAL') 'APPLY_BLOCKED'

$apply = Invoke-RedrixLdwParentAclMigrationApplyBoundary
Assert ($apply.classification -ceq 'BLOCKED_APPROVAL') 'BOUNDARY_ALWAYS_BLOCKED'

$childMap = Get-RedrixMigrationTestChildMap
$validLedger = New-RedrixLdwParentAclMigrationLedgerEntry -Stage 'PREPARED' `
    -ParentShaBefore $ref.liveParentPreimageSha256Utf8SddlProperty `
    -TargetSha256Utf8 $ref.canonicalTargetSha256Utf8SddlProperty `
    -ChildShaBefore $childMap -ChildShaAfter $childMap `
    -JournalComplete $true -DurableReceiptWritten $true
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $validLedger) -ceq 'RECOVERY_LEDGER_COMPLETE') 'LEDGER_PREPARED'

foreach ($stage in @('COMMITTED', 'AFTER_APPLY', 'REBOOT')) {
    $lg = New-RedrixLdwParentAclMigrationLedgerEntry -Stage $stage `
        -ParentShaBefore $ref.liveParentPreimageSha256Utf8SddlProperty `
        -TargetSha256Utf8 $ref.canonicalTargetSha256Utf8SddlProperty `
        -ChildShaBefore $childMap -ChildShaAfter $childMap `
        -JournalComplete $true -DurableReceiptWritten $true
    Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $lg) -ceq 'RECOVERY_LEDGER_COMPLETE') ('LEDGER_' + $stage)
}

Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot @{ journalComplete = $true }) -ceq 'HOLD_RECOVERY_AMBIGUOUS') 'FORGED_MINIMAL_LEDGER'
$forgedMarker = Copy-RedrixMigrationLedger $validLedger
$forgedMarker['marker'] = 'FORGED'
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $forgedMarker) -ceq 'HOLD_LEDGER_FORGED') 'FORGED_MARKER'

$badPreimage = Copy-RedrixMigrationLedger $validLedger
$badPreimage['parentSha256Before'] = ('0' * 64)
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $badPreimage) -ceq 'HOLD_PREIMAGE_PIN_DRIFT') 'BAD_PREIMAGE_PIN'

$badTarget = Copy-RedrixMigrationLedger $validLedger
$badTarget['targetSha256Utf8'] = 'a11c28fd0fceea6c13d29661318b95bdb55ca0cd4ad3a0d5f5a3ceb42ce2f7c8'
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $badTarget) -ceq 'HOLD_TARGET_PIN_DRIFT') 'BAD_TARGET_PIN'

$badChild = Copy-RedrixMigrationLedger $validLedger
$badChild['childSha256Before'] = @{ CiJitControl = ('0' * 64) }
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $badChild) -ceq 'HOLD_CHILD_PIN_DRIFT') 'BAD_CHILD_PIN'

$afterDrift = Copy-RedrixMigrationLedger $validLedger
$afterDrift['stage'] = 'AFTER_APPLY'
$afterBad = Copy-RedrixMigrationLedger $childMap
$afterBad['CiJitControl'] = ('0' * 64)
$afterDrift['childSha256After'] = $afterBad
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $afterDrift) -ceq 'HOLD_CHILD_PIN_DRIFT') 'CHILD_AFTER_WRONG_DIGEST'

$noReceipt = Copy-RedrixMigrationLedger $validLedger
$noReceipt['durableReceiptWritten'] = $false
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $noReceipt) -ceq 'HOLD_RECOVERY_AMBIGUOUS') 'NO_DURABLE_RECEIPT'

$physicalFlag = Copy-RedrixMigrationLedger $validLedger
$physicalFlag['physicalApplyAttempted'] = $true
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $physicalFlag) -ceq 'HOLD_PHYSICAL_FLAG_DRIFT') 'PHYSICAL_FLAG_FORGED'

$committedNoAfter = Copy-RedrixMigrationLedger $validLedger
$committedNoAfter['stage'] = 'COMMITTED'
$committedNoAfter['childSha256After'] = $null
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $committedNoAfter) -ceq 'HOLD_CHILD_POST_STATE_MISSING') 'COMMITTED_MISSING_AFTER'

$rebootNoAfter = Copy-RedrixMigrationLedger $validLedger
$rebootNoAfter['stage'] = 'REBOOT'
$rebootNoAfter.Remove('childSha256After')
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $rebootNoAfter) -ceq 'HOLD_CHILD_POST_STATE_MISSING') 'REBOOT_MISSING_AFTER_KEY'

$extraBefore = Copy-RedrixMigrationLedger $validLedger
$extraChildMap = Copy-RedrixMigrationLedger $childMap
$extraChildMap['SeventhChild'] = ('0' * 64)
$extraBefore['childSha256Before'] = $extraChildMap
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $extraBefore) -ceq 'HOLD_CHILD_PIN_DRIFT') 'EXTRA_CHILD_BEFORE'

$extraAfter = Copy-RedrixMigrationLedger $validLedger
$extraAfter['stage'] = 'COMMITTED'
$extraAfterMap = Copy-RedrixMigrationLedger $childMap
$extraAfterMap['SeventhChild'] = ('0' * 64)
$extraAfter['childSha256After'] = $extraAfterMap
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $extraAfter) -ceq 'HOLD_CHILD_PIN_DRIFT') 'EXTRA_CHILD_AFTER'

$preparedNoReceipt = Copy-RedrixMigrationLedger $validLedger
$preparedNoReceipt['stage'] = 'PREPARED'
$preparedNoReceipt['durableReceiptWritten'] = $false
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $preparedNoReceipt) -ceq 'HOLD_RECOVERY_AMBIGUOUS') 'PREPARED_NO_RECEIPT'

$bogusStage = Copy-RedrixMigrationLedger $validLedger
$bogusStage['stage'] = 'ROLLED_BACK'
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $bogusStage) -ceq 'HOLD_LEDGER_STAGE_AMBIGUOUS') 'STAGE_MISMATCH'

Assert ((Test-RedrixLdwParentAclMigrationRollbackPolicy $null) -ceq 'ROLLBACK_REFUSED_NO_JOURNAL') 'ROLLBACK_NO_JOURNAL'
Assert ((Test-RedrixLdwParentAclMigrationRollbackPolicy @{ journalComplete = $true }) -ceq 'ROLLBACK_REFUSED_NO_JOURNAL') 'ROLLBACK_FORGED_LEDGER'
Assert ((Test-RedrixLdwParentAclMigrationRollbackPolicy $validLedger) -ceq 'ROLLBACK_POLICY_REVIEW_ONLY_NOT_EXECUTABLE') 'ROLLBACK_VALID_REVIEW_ONLY'

$before = @{ CiJitControl = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626' }
$after = @{ CiJitControl = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626' }
Assert (Test-RedrixLdwParentAclMigrationChildHashParity $before $after) 'PARITY_EQUAL'
$afterBad = @{ CiJitControl = ('0' * 64) }
Assert (-not (Test-RedrixLdwParentAclMigrationChildHashParity $before $afterBad)) 'PARITY_POST_DRIFT'

$stockTouch = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$stockTouch.StockProgramDataAclMutationAttempted = $true
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $stockTouch) -ceq 'STOCK_PROGRAMDATA_TOUCH_REFUSED') 'STOCK_PROGRAMDATA_REFUSE'

function Test-RedrixLedgerBooleanAdversarial([hashtable]$Base, [string]$Field, [object]$Value, [string]$Expected, [string]$CaseId) {
    $lg = Copy-RedrixMigrationLedger $Base
    $lg[$Field] = $Value
    $result = Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $lg
    Assert ($result -ceq $Expected) $CaseId
}

$ledgerBase = Copy-RedrixMigrationLedger $validLedger
$ledgerBase['stage'] = 'PREPARED'
foreach ($stage in @('PREPARED', 'COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')) {
    $stageLedger = Copy-RedrixMigrationLedger $validLedger
    $stageLedger['stage'] = $stage
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'journalComplete' 'false' 'HOLD_LEDGER_BOOLEAN_INVALID' ('JOURNAL_STRING_FALSE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'journalComplete' 'true' 'HOLD_LEDGER_BOOLEAN_INVALID' ('JOURNAL_STRING_TRUE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'journalComplete' 'True' 'HOLD_LEDGER_BOOLEAN_INVALID' ('JOURNAL_STRING_MIXED_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'journalComplete' 0 'HOLD_LEDGER_BOOLEAN_INVALID' ('JOURNAL_INT_ZERO_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'journalComplete' 1 'HOLD_LEDGER_BOOLEAN_INVALID' ('JOURNAL_INT_ONE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'journalComplete' @('true') 'HOLD_LEDGER_BOOLEAN_INVALID' ('JOURNAL_ARRAY_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'journalComplete' @{ ok = $true } 'HOLD_LEDGER_BOOLEAN_INVALID' ('JOURNAL_OBJECT_' + $stage)
    $missingJournal = Copy-RedrixMigrationLedger $stageLedger
    $missingJournal.Remove('journalComplete')
    Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $missingJournal) -ceq 'HOLD_RECOVERY_AMBIGUOUS') ('JOURNAL_ABSENT_' + $stage)

    Test-RedrixLedgerBooleanAdversarial $stageLedger 'durableReceiptWritten' 'false' 'HOLD_LEDGER_BOOLEAN_INVALID' ('RECEIPT_STRING_FALSE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'durableReceiptWritten' 'true' 'HOLD_LEDGER_BOOLEAN_INVALID' ('RECEIPT_STRING_TRUE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'durableReceiptWritten' 1 'HOLD_LEDGER_BOOLEAN_INVALID' ('RECEIPT_INT_ONE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'physicalApplyAttempted' 'false' 'HOLD_LEDGER_BOOLEAN_INVALID' ('PHYSICAL_STRING_FALSE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'physicalApplyAttempted' 'true' 'HOLD_LEDGER_BOOLEAN_INVALID' ('PHYSICAL_STRING_TRUE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'physicalApplyAttempted' 1 'HOLD_LEDGER_BOOLEAN_INVALID' ('PHYSICAL_INT_ONE_' + $stage)
    Test-RedrixLedgerBooleanAdversarial $stageLedger 'physicalApplyAttempted' $true 'HOLD_PHYSICAL_FLAG_DRIFT' ('PHYSICAL_BOOL_TRUE_' + $stage)
}

$forgedRecovery = Copy-RedrixMigrationLedger $validLedger
$forgedRecovery['journalComplete'] = 'false'
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $forgedRecovery) -ceq 'HOLD_LEDGER_BOOLEAN_INVALID') 'FORGED_JOURNAL_TRUTHY_STRING_NOT_COMPLETE'

function Assert-NeverRecoveryOrRollbackReview([hashtable]$Ledger, [string]$CaseId) {
    $recovery = Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $Ledger
    Assert ($recovery -cne 'RECOVERY_LEDGER_COMPLETE') ($CaseId + '_NO_RECOVERY')
    $rollback = Test-RedrixLdwParentAclMigrationRollbackPolicy $Ledger
    Assert ($rollback -cne 'ROLLBACK_POLICY_REVIEW_ONLY_NOT_EXECUTABLE') ($CaseId + '_NO_ROLLBACK_REVIEW')
}

$reproEmptyPins = Copy-RedrixMigrationLedger $validLedger
$reproEmptyPins['parentSha256Before'] = @()
$reproEmptyPins['targetSha256Utf8'] = @()
$emptyChildMap = @{}
foreach ($name in (Get-RedrixMigrationTestChildMap).Keys) { $emptyChildMap[$name] = @() }
$reproEmptyPins['childSha256Before'] = $emptyChildMap
$reproEmptyPins['childSha256After'] = $emptyChildMap
$reproEmptyPins['stage'] = 'COMMITTED'
Assert-NeverRecoveryOrRollbackReview $reproEmptyPins 'REPRO_ALL_EMPTY_ARRAY_DIGESTS'

foreach ($stage in @('PREPARED', 'COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')) {
    $stageLedger = Copy-RedrixMigrationLedger $validLedger
    $stageLedger['stage'] = $stage
  if ($stage -in @('COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')) {
        $stageLedger['childSha256After'] = Get-RedrixMigrationTestChildMap
    }

    $emptyParent = Copy-RedrixMigrationLedger $stageLedger
    $emptyParent['parentSha256Before'] = @()
    Assert-NeverRecoveryOrRollbackReview $emptyParent ('SCALAR_EMPTY_PARENT_' + $stage)

    $emptyTarget = Copy-RedrixMigrationLedger $stageLedger
    $emptyTarget['targetSha256Utf8'] = @()
    Assert-NeverRecoveryOrRollbackReview $emptyTarget ('SCALAR_EMPTY_TARGET_' + $stage)

    foreach ($childName in (Get-RedrixMigrationTestChildMap).Keys) {
        $beforeEmpty = Copy-RedrixMigrationLedger $stageLedger
        $beforeEmpty['childSha256Before'] = Copy-RedrixMigrationLedger $childMap
        $beforeEmpty['childSha256Before'][$childName] = @()
        Assert-NeverRecoveryOrRollbackReview $beforeEmpty ('SCALAR_EMPTY_BEFORE_' + $childName + '_' + $stage)

        $singleArrayPin = Copy-RedrixMigrationLedger $childMap
        $singleArrayPin[$childName] = @([string]$ref.protectedChildSddlSha256Utf8.$childName)
        $singleArrayLedger = Copy-RedrixMigrationLedger $stageLedger
        $singleArrayLedger['childSha256Before'] = $singleArrayPin
        Assert-NeverRecoveryOrRollbackReview $singleArrayLedger ('SCALAR_ONE_ELEM_ARRAY_BEFORE_' + $childName + '_' + $stage)

        if ($stage -in @('COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')) {
            $afterEmpty = Copy-RedrixMigrationLedger $stageLedger
            $afterMap = Get-RedrixMigrationTestChildMap
            $afterMap[$childName] = @()
            $afterEmpty['childSha256After'] = $afterMap
            Assert-NeverRecoveryOrRollbackReview $afterEmpty ('SCALAR_EMPTY_AFTER_' + $childName + '_' + $stage)
        }
    }
}

$snapshotEmptyChild = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$snapshotEmptyChild.ChildrenSha256Utf8Sddl['CiJitControl'] = @()
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $snapshotEmptyChild) -ceq 'CHILD_SDDL_DRIFT') 'SNAPSHOT_EMPTY_ARRAY_CHILD'

$upperPin = Copy-RedrixMigrationLedger $validLedger
$upperPin['parentSha256Before'] = $ref.liveParentPreimageSha256Utf8SddlProperty.ToUpperInvariant()
Assert-NeverRecoveryOrRollbackReview $upperPin 'SCALAR_UPPERCASE_PARENT_REJECTED'

Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $validLedger) -ceq 'RECOVERY_LEDGER_COMPLETE') 'SCALAR_GOOD_LEDGER_STILL_COMPLETE'
Assert ((Test-RedrixLdwParentAclMigrationRollbackPolicy $validLedger) -ceq 'ROLLBACK_POLICY_REVIEW_ONLY_NOT_EXECUTABLE') 'SCALAR_GOOD_ROLLBACK_REVIEW_ONLY'

function Assert-PreconditionNeverOk([pscustomobject]$Snapshot, [string]$CaseId) {
    $pre = Test-RedrixLdwParentAclMigrationPreconditions $Snapshot
    Assert ($pre -cne 'OK') ($CaseId + '_PRE_NOT_OK')
    $rehearsal = Invoke-RedrixLdwParentAclMigrationRehearsal $Snapshot
    Assert ($rehearsal.outcome -cne 'REHEARSAL_PASS_NO_APPLY') ($CaseId + '_NO_REHEARSAL_PASS')
}

$identityBase = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$emptyMarkerSnap = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$emptyMarkerSnap.Marker = @()
Assert-PreconditionNeverOk $emptyMarkerSnap 'SNAP_MARKER_EMPTY_ARRAY'

$emptyTaskSnap = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$emptyTaskSnap.V1TaskName = @()
Assert-PreconditionNeverOk $emptyTaskSnap 'SNAP_V1_NAME_EMPTY_ARRAY'

$emptyStateSnap = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$emptyStateSnap.V1TaskState = @()
Assert-PreconditionNeverOk $emptyStateSnap 'SNAP_V1_STATE_EMPTY_ARRAY'

$emptyTriggerSnap = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$emptyTriggerSnap.V1TaskTriggerCount = @()
Assert-PreconditionNeverOk $emptyTriggerSnap 'SNAP_V1_TRIGGER_EMPTY_ARRAY'

$stringZeroTrigger = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$stringZeroTrigger.V1TaskTriggerCount = '0'
Assert-PreconditionNeverOk $stringZeroTrigger 'SNAP_V1_TRIGGER_STRING_ZERO'

$int64Trigger = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$int64Trigger.V1TaskTriggerCount = [int64]0
Assert-PreconditionNeverOk $int64Trigger 'SNAP_V1_TRIGGER_INT64'

$doubleTrigger = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$doubleTrigger.V1TaskTriggerCount = [double]0
Assert-PreconditionNeverOk $doubleTrigger 'SNAP_V1_TRIGGER_DOUBLE'

$falseParentProt = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$falseParentProt.ParentAccessRulesProtected = @()
Assert-PreconditionNeverOk $falseParentProt 'SNAP_PARENT_PROTECTED_EMPTY_ARRAY'

$stringFalseStock = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$stringFalseStock.StockProgramDataAclMutationAttempted = 'false'
Assert-PreconditionNeverOk $stringFalseStock 'SNAP_STOCK_STRING_FALSE'

$spoofEmpty = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$spoofEmpty.ProcessProgramDataSpoofed = @()
Assert-PreconditionNeverOk $spoofEmpty 'SNAP_SPOOF_EMPTY_ARRAY'

$childArraySpoof = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$childArraySpoof.ChildrenSha256Utf8Sddl = @(Get-RedrixMigrationTestChildMap).Values
Assert-PreconditionNeverOk $childArraySpoof 'SNAP_CHILDREN_AS_ARRAY'

$hashtableSnap = @{
    Marker = $script:RedrixMigrationMarker
    ParentSha256Utf8Sddl = $ref.liveParentPreimageSha256Utf8SddlProperty
    ParentAccessRulesProtected = $false
    ChildrenSha256Utf8Sddl = Get-RedrixMigrationTestChildMap
    V1TaskName = $ref.fixedV1ReviewedOperationTaskName
    V1TaskState = 'Ready'
    V1TaskTriggerCount = 0
    StockProgramDataAclMutationAttempted = $false
    ProcessProgramDataSpoofed = $false
}
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $hashtableSnap) -cne 'OK') 'SNAP_HASHTABLE_NOT_PSCUSTOMOBJECT'
$arraySnap = @($identityBase)
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $arraySnap) -cne 'OK') 'SNAP_ARRAY_NOT_PSCUSTOMOBJECT'

Assert ((Test-RedrixLdwParentAclMigrationPreconditions $identityBase) -ceq 'OK') 'SNAP_IDENTITY_GOOD_CASE'

$ledgerMarkerEmpty = Copy-RedrixMigrationLedger $validLedger
$ledgerMarkerEmpty['marker'] = @()
Assert-NeverRecoveryOrRollbackReview $ledgerMarkerEmpty 'LEDGER_MARKER_EMPTY_ARRAY'

$ledgerStageEmpty = Copy-RedrixMigrationLedger $validLedger
$ledgerStageEmpty['stage'] = @()
Assert-NeverRecoveryOrRollbackReview $ledgerStageEmpty 'LEDGER_STAGE_EMPTY_ARRAY'

$ledgerStageArray = Copy-RedrixMigrationLedger $validLedger
$ledgerStageArray['stage'] = @('COMMITTED')
Assert-NeverRecoveryOrRollbackReview $ledgerStageArray 'LEDGER_STAGE_ONE_ELEM_ARRAY'

foreach ($stage in @('PREPARED', 'COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')) {
    $stageLedger = Copy-RedrixMigrationLedger $validLedger
    $stageLedger['stage'] = $stage
    if ($stage -in @('COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')) {
        $stageLedger['childSha256After'] = Get-RedrixMigrationTestChildMap
    }
    $stageLedger['marker'] = @()
    Assert-NeverRecoveryOrRollbackReview $stageLedger ('LEDGER_MARKER_EMPTY_' + $stage)
    $badStage = Copy-RedrixMigrationLedger $stageLedger
    $badStage['marker'] = $script:RedrixMigrationMarker
    $badStage['stage'] = @()
    Assert-NeverRecoveryOrRollbackReview $badStage ('LEDGER_STAGE_EMPTY_' + $stage)
}

$mixedReboot = Copy-RedrixMigrationLedger $validLedger
$mixedReboot['stage'] = 'reboot'
$mixedReboot['childSha256After'] = Get-RedrixMigrationTestChildMap
Assert-NeverRecoveryOrRollbackReview $mixedReboot 'STAGE_CASE_REBOOT_LOWER'

$mixedPrepared = Copy-RedrixMigrationLedger $validLedger
$mixedPrepared['stage'] = 'prepared'
Assert-NeverRecoveryOrRollbackReview $mixedPrepared 'STAGE_CASE_PREPARED_LOWER'

$goodCommitted = Copy-RedrixMigrationLedger $validLedger
$goodCommitted['stage'] = 'COMMITTED'
$goodCommitted['childSha256After'] = Get-RedrixMigrationTestChildMap
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $goodCommitted) -ceq 'RECOVERY_LEDGER_COMPLETE') 'STAGE_CASE_COMMITTED_UPPER_GOOD'

$mixedAfterApply = Copy-RedrixMigrationLedger $validLedger
$mixedAfterApply['stage'] = 'after_apply'
$mixedAfterApply['childSha256After'] = Get-RedrixMigrationTestChildMap
Assert-NeverRecoveryOrRollbackReview $mixedAfterApply 'STAGE_CASE_AFTER_APPLY_LOWER'

$mixedStageArray = Copy-RedrixMigrationLedger $validLedger
$mixedStageArray['stage'] = 'Reboot'
$mixedStageArray['childSha256After'] = Get-RedrixMigrationTestChildMap
Assert-NeverRecoveryOrRollbackReview $mixedStageArray 'STAGE_CASE_REBOOT_MIXED'

$lowerChildSnap = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$lowerChildren = [ordered]@{}
foreach ($entry in $lowerChildSnap.ChildrenSha256Utf8Sddl.GetEnumerator()) {
    $lowerChildren[$entry.Key.ToLowerInvariant()] = $entry.Value
}
$lowerChildSnap.ChildrenSha256Utf8Sddl = $lowerChildren
Assert-PreconditionNeverOk $lowerChildSnap 'SNAP_CHILD_KEY_LOWER_CASE'

$lowerChildLedger = Copy-RedrixMigrationLedger $validLedger
$lowerChildMap = [ordered]@{}
foreach ($entry in (Get-RedrixMigrationTestChildMap).GetEnumerator()) {
    $lowerChildMap[$entry.Key.ToLowerInvariant()] = $entry.Value
}
$lowerChildLedger['childSha256Before'] = $lowerChildMap
Assert-NeverRecoveryOrRollbackReview $lowerChildLedger 'LEDGER_CHILD_KEY_LOWER_BEFORE'

$lowerChildAfter = Copy-RedrixMigrationLedger $validLedger
$lowerChildAfter['stage'] = 'COMMITTED'
$lowerAfterMap = [ordered]@{}
foreach ($entry in (Get-RedrixMigrationTestChildMap).GetEnumerator()) {
    $lowerAfterMap[$entry.Key.ToLowerInvariant()] = $entry.Value
}
$lowerChildAfter['childSha256After'] = $lowerAfterMap
Assert-NeverRecoveryOrRollbackReview $lowerChildAfter 'LEDGER_CHILD_KEY_LOWER_AFTER'

Write-Host ('REDRIX_LDW_PARENT_ACL_MIGRATION_REHEARSAL_TESTS=PASS assertions=' + $checks)
Write-Host ('REDRIX_LDW_PARENT_ACL_MIGRATION_PHYSICAL_APPLY=BLOCKED_APPROVAL')
Write-Host ('REDRIX_LDW_PARENT_ACL_MIGRATION_AUTHORITY=NOT_PHYSICAL_AUTHORITY')
