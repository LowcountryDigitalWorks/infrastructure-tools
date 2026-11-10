#Requires -Version 5.1
<#
.SYNOPSIS
Non-executing in-memory rehearsal for a future owner-reviewed %ProgramData%\LDW parent ACL migration (#186).
Fixed contract pins only — no caller parameters, no Set-Acl, no host path mutation.
#>
Set-StrictMode -Version Latest

$script:RedrixMigrationMarker = 'LDW_REDRIX_PARENT_ACL_MIGRATION_REHEARSAL_V1'
$script:RedrixMigrationDataPath = Join-Path $PSScriptRoot 'data/RedrixLdwParentAclMigrationTransactionReference.json'
$syntheticHelper = Join-Path $PSScriptRoot 'RedrixLdwParentAclSyntheticTarget.ps1'
if (-not (Test-Path -LiteralPath $syntheticHelper -PathType Leaf)) { throw 'SYNTHETIC_HELPER_MISSING' }
. $syntheticHelper

function Get-RedrixLdwParentAclMigrationReference {
    if (-not (Test-Path -LiteralPath $script:RedrixMigrationDataPath -PathType Leaf)) { throw 'MIGRATION_REFERENCE_MISSING' }
    return (Get-Content -LiteralPath $script:RedrixMigrationDataPath -Raw | ConvertFrom-Json)
}

function New-RedrixLdwParentAclMockHostSnapshot {
    param(
        [ValidateSet('ValidPreMigration', 'ChildDrift', 'TaskNotQuiescent', 'ParentProtectedDrift')]
            [string]$Variant = 'ValidPreMigration')
    $ref = Get-RedrixLdwParentAclMigrationReference
    $children = [ordered]@{}
    foreach ($prop in $ref.protectedChildSddlSha256Utf8.PSObject.Properties) {
        $children[$prop.Name] = [string]$prop.Value
    }
    if ($Variant -ceq 'ChildDrift') {
        $children['CiJitControl'] = ('0' * 64)
    }
    $taskState = if ($Variant -ceq 'TaskNotQuiescent') { 'Running' } else { 'Ready' }
    $taskTriggers = if ($Variant -ceq 'TaskNotQuiescent') { 1 } else { 0 }
    $parentProtected = ($Variant -ceq 'ParentProtectedDrift')
    [pscustomobject]@{
        Marker = $script:RedrixMigrationMarker
        ParentSha256Utf8Sddl = [string]$ref.liveParentPreimageSha256Utf8SddlProperty
        ParentAccessRulesProtected = $parentProtected
        ChildrenSha256Utf8Sddl = $children
        V1TaskName = [string]$ref.fixedV1ReviewedOperationTaskName
        V1TaskState = $taskState
        V1TaskTriggerCount = $taskTriggers
        StockProgramDataAclMutationAttempted = $false
        ProcessProgramDataSpoofed = $false
    }
}

function Get-RedrixLdwParentAclMigrationMachineProgramDataBinding {
    $ref = Get-RedrixLdwParentAclMigrationReference
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($known)) {
        return [ordered]@{
            policy = 'MACHINE_PROGRAMDATA_MISSING'
            machineKnownPath = $null
            hostRootTrustBound = $false
        }
    }
    $pd = [IO.Path]::GetFullPath($known)
    if ([IO.Path]::GetFileName($pd.TrimEnd('\')) -cne $ref.fixedProgramDataLeafName) {
        return [ordered]@{
            policy = 'MACHINE_PROGRAMDATA_INVALID'
            machineKnownPath = $pd
            hostRootTrustBound = $false
        }
    }
    $machineReg = [Environment]::GetEnvironmentVariable('ProgramData', 'Machine')
    if ($machineReg -and ([IO.Path]::GetFullPath($machineReg) -cne $pd)) {
        return [ordered]@{
            policy = 'MACHINE_PROGRAMDATA_DRIFT'
            machineKnownPath = $pd
            hostRootTrustBound = $false
        }
    }
    $proc = $env:ProgramData
    if ($proc -and ([IO.Path]::GetFullPath($proc) -cne $pd)) {
        return [ordered]@{
            policy = 'PROCESS_PROGRAMDATA_SPOOFED'
            machineKnownPath = $pd
            hostRootTrustBound = $false
        }
    }
    return [ordered]@{
        policy = 'OK'
        machineKnownPath = $pd
        hostRootTrustBound = $true
    }
}

function Test-RedrixLdwParentAclMigrationProgramDataPathPolicy {
    param([string]$UntrustedCallerPath)
    $binding = Get-RedrixLdwParentAclMigrationMachineProgramDataBinding
    if ($binding.policy -cne 'OK') { return $binding.policy }
    $machinePd = [string]$binding.machineKnownPath
    if (-not $PSBoundParameters.ContainsKey('UntrustedCallerPath')) { return 'OK' }
    if ([string]::IsNullOrWhiteSpace($UntrustedCallerPath)) { return 'CALLER_PATH_EMPTY_REFUSED' }
    if ($UntrustedCallerPath -match '^\\\\[^\\]+\\') { return 'UNC_CALLER_REFUSED' }
    $callerFull = [IO.Path]::GetFullPath($UntrustedCallerPath).TrimEnd('\')
    $machineNorm = $machinePd.TrimEnd('\')
    if ($callerFull -cne $machineNorm) { return 'CALLER_PATH_NOT_MACHINE_KNOWN' }
    $ref = Get-RedrixLdwParentAclMigrationReference
    if ([IO.Path]::GetFileName($callerFull.TrimEnd('\')) -cne $ref.fixedProgramDataLeafName) {
        return 'MACHINE_PROGRAMDATA_INVALID'
    }
    return 'OK'
}

function Test-RedrixLdwParentAclMigrationSyntheticHashIsNotAuthorization {
    param([string]$ClaimedAuthorizationBasis)
    if ($ClaimedAuthorizationBasis -cmatch '^d0d4816b') { return 'NOT_AUTHORIZED_SYNTHETIC_HASH_ONLY' }
    if ($ClaimedAuthorizationBasis -cmatch '^a11c28fd') { return 'NOT_AUTHORIZED_REJECTED_LITERATURE_PIN' }
    return 'NOT_AUTHORIZED'
}

function Test-RedrixLdwParentAclMigrationPreconditions([pscustomobject]$Snapshot) {
    $ref = Get-RedrixLdwParentAclMigrationReference
    $errors = [System.Collections.Generic.List[string]]::new()
    if ($Snapshot.Marker -cne $script:RedrixMigrationMarker) { $errors.Add('MARKER_DRIFT') }
    if ($Snapshot.ParentSha256Utf8Sddl -cne $ref.liveParentPreimageSha256Utf8SddlProperty) { $errors.Add('PARENT_PREIMAGE_DRIFT') }
    if ($Snapshot.ParentAccessRulesProtected) { $errors.Add('ROOT_PREIMAGE_DRIFT') }
    if ($Snapshot.V1TaskName -cne $ref.fixedV1ReviewedOperationTaskName) { $errors.Add('TASK_IDENTITY_DRIFT') }
    if ($Snapshot.V1TaskState -cne 'Ready') { $errors.Add('TASK_NOT_QUIESCENT') }
    if ($Snapshot.V1TaskTriggerCount -ne 0) { $errors.Add('TASK_TRIGGER_DRIFT') }
    if ($Snapshot.StockProgramDataAclMutationAttempted) { $errors.Add('STOCK_PROGRAMDATA_TOUCH_REFUSED') }
    if ($Snapshot.ProcessProgramDataSpoofed) { return 'PROCESS_PROGRAMDATA_SPOOFED' }
    $expectedChildCount = @($ref.protectedChildSddlSha256Utf8.PSObject.Properties).Count
    if ($Snapshot.ChildrenSha256Utf8Sddl.Count -ne $expectedChildCount) { $errors.Add('TOP_LEVEL_INVENTORY_DRIFT') }
    foreach ($prop in $ref.protectedChildSddlSha256Utf8.PSObject.Properties) {
        $name = $prop.Name
        $pin = [string]$prop.Value
        if (-not $Snapshot.ChildrenSha256Utf8Sddl.Contains($name)) { $errors.Add('TOP_LEVEL_INVENTORY_DRIFT'); break }
        if ($Snapshot.ChildrenSha256Utf8Sddl[$name] -cne $pin) { $errors.Add('CHILD_SDDL_DRIFT') }
    }
    if ($errors.Count -gt 0) { return ($errors | Select-Object -First 1) }
    return 'OK'
}

function New-RedrixLdwParentAclMigrationLedgerEntry {
    param(
        [ValidateSet('PREPARED', 'COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')]
            [string]$Stage,
        [string]$ParentShaBefore,
        [string]$TargetSha256Utf8,
        [hashtable]$ChildShaBefore,
        [hashtable]$ChildShaAfter,
        [bool]$JournalComplete,
        [bool]$DurableReceiptWritten)
    [ordered]@{
        marker = $script:RedrixMigrationMarker
        stage = $Stage
        parentSha256Before = $ParentShaBefore
        targetSha256Utf8 = $TargetSha256Utf8
        childSha256Before = $ChildShaBefore
        childSha256After = $ChildShaAfter
        journalComplete = $JournalComplete
        durableReceiptWritten = $DurableReceiptWritten
        physicalApplyAttempted = $false
    }
}

function Test-RedrixLdwParentAclMigrationLedgerPins([hashtable]$Ledger) {
    $ref = Get-RedrixLdwParentAclMigrationReference
    if ($Ledger['parentSha256Before'] -cne $ref.liveParentPreimageSha256Utf8SddlProperty) { return 'HOLD_PREIMAGE_PIN_DRIFT' }
    if ($Ledger['targetSha256Utf8'] -cne $ref.canonicalTargetSha256Utf8SddlProperty) { return 'HOLD_TARGET_PIN_DRIFT' }
    $childBefore = $Ledger['childSha256Before']
    if ($null -eq $childBefore) { return 'HOLD_RECOVERY_AMBIGUOUS' }
    foreach ($prop in $ref.protectedChildSddlSha256Utf8.PSObject.Properties) {
        if (-not $childBefore.ContainsKey($prop.Name)) { return 'HOLD_CHILD_PIN_DRIFT' }
        if ($childBefore[$prop.Name] -cne [string]$prop.Value) { return 'HOLD_CHILD_PIN_DRIFT' }
    }
    return 'OK'
}

function Test-RedrixLdwParentAclMigrationChildHashParity(
    [hashtable]$Before,
    [hashtable]$After) {
    if ($Before.Count -ne $After.Count) { return $false }
    foreach ($key in $Before.Keys) {
        if (-not $After.ContainsKey($key)) { return $false }
        if ($Before[$key] -cne $After[$key]) { return $false }
    }
    return $true
}

function Test-RedrixLdwParentAclMigrationRecoveryAfterReboot([hashtable]$Ledger) {
    if ($null -eq $Ledger) { return 'HOLD_RECOVERY_AMBIGUOUS' }
    $required = @(
        'marker', 'stage', 'parentSha256Before', 'targetSha256Utf8', 'childSha256Before',
        'journalComplete', 'durableReceiptWritten', 'physicalApplyAttempted')
    foreach ($key in $required) {
        if (-not $Ledger.ContainsKey($key)) { return 'HOLD_RECOVERY_AMBIGUOUS' }
    }
    if ($Ledger['marker'] -cne $script:RedrixMigrationMarker) { return 'HOLD_LEDGER_FORGED' }
    if (-not $Ledger['journalComplete']) { return 'HOLD_RECOVERY_AMBIGUOUS' }
    if (-not $Ledger['durableReceiptWritten']) { return 'HOLD_RECOVERY_AMBIGUOUS' }
    if ($Ledger['physicalApplyAttempted']) { return 'HOLD_PHYSICAL_FLAG_DRIFT' }
    $allowedStages = @('PREPARED', 'COMMITTED', 'AFTER_APPLY', 'REBOOT', 'PRE_APPLY_REHEARSAL')
    if ($Ledger['stage'] -notin $allowedStages) { return 'HOLD_LEDGER_STAGE_AMBIGUOUS' }
    $pin = Test-RedrixLdwParentAclMigrationLedgerPins $Ledger
    if ($pin -cne 'OK') { return $pin }
    if ($Ledger.ContainsKey('childSha256After') -and $null -ne $Ledger['childSha256After']) {
        if (-not (Test-RedrixLdwParentAclMigrationChildHashParity $Ledger['childSha256Before'] $Ledger['childSha256After'])) {
            return 'HOLD_CHILD_INTEGRITY_AFTER_APPLY'
        }
    }
    if ($Ledger['stage'] -in @('COMMITTED', 'AFTER_APPLY', 'REBOOT') -and -not $Ledger['durableReceiptWritten']) {
        return 'HOLD_RECOVERY_AMBIGUOUS'
    }
    return 'RECOVERY_LEDGER_COMPLETE'
}

function Test-RedrixLdwParentAclMigrationRollbackPolicy([hashtable]$Ledger) {
    if ($null -eq $Ledger) { return 'ROLLBACK_REFUSED_NO_JOURNAL' }
    if ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $Ledger) -ne 'RECOVERY_LEDGER_COMPLETE') {
        return 'ROLLBACK_REFUSED_NO_JOURNAL'
    }
    return 'ROLLBACK_POLICY_REVIEW_ONLY_NOT_EXECUTABLE'
}

function Invoke-RedrixLdwParentAclMigrationApplyBoundary {
    return [ordered]@{
        marker = $script:RedrixMigrationMarker
        classification = 'BLOCKED_APPROVAL'
        physicalAclChangeAuthorized = $false
        reasonCode = 'SOURCE_REHEARSAL_NO_APPLY_PATH'
        requiredGates = @(
            'AUTHOR_EXCLUDED_H0_M0_EXACT_HEAD',
            'OWNER_SIGNOFF_SEPARATE_PHYSICAL_PACKET')
    }
}

function Invoke-RedrixLdwParentAclMigrationRehearsal([pscustomobject]$Snapshot) {
    $ref = Get-RedrixLdwParentAclMigrationReference
    $binding = Get-RedrixLdwParentAclMigrationMachineProgramDataBinding
    if ($binding.policy -cne 'OK') {
        return [ordered]@{
            marker = $script:RedrixMigrationMarker
            outcome = 'REHEARSAL_HOLD'
            reasonCode = $binding.policy
            physicalAclChangeAuthorized = $false
            syntheticSnapshotOnly = $true
            hostRootTrustAsserted = $false
        }
    }
    $pre = Test-RedrixLdwParentAclMigrationPreconditions $Snapshot
    if ($pre -cne 'OK') {
        return [ordered]@{
            marker = $script:RedrixMigrationMarker
            outcome = 'REHEARSAL_HOLD'
            reasonCode = $pre
            physicalAclChangeAuthorized = $false
        }
    }
    $target = New-RedrixLdwParentAclExplicitTargetSecurityDescriptor
    $targetPin = Test-RedrixLdwParentAclCanonicalPin $target
    if (-not $targetPin.shaMatchesCanonical -or -not $targetPin.sddlMatchesCanonical) {
        throw 'TARGET_PARITY_DRIFT'
    }
    $childBefore = @{}
    foreach ($entry in $Snapshot.ChildrenSha256Utf8Sddl.GetEnumerator()) { $childBefore[$entry.Key] = $entry.Value }
    $childAfter = @{}
    foreach ($key in $childBefore.Keys) { $childAfter[$key] = $childBefore[$key] }
    if (-not (Test-RedrixLdwParentAclMigrationChildHashParity $childBefore $childAfter)) {
        return [ordered]@{
            marker = $script:RedrixMigrationMarker
            outcome = 'REHEARSAL_HOLD'
            reasonCode = 'CHILD_INTEGRITY_HOLD'
            physicalAclChangeAuthorized = $false
        }
    }
    $ledger = New-RedrixLdwParentAclMigrationLedgerEntry -Stage 'PRE_APPLY_REHEARSAL' `
        -ParentShaBefore $Snapshot.ParentSha256Utf8Sddl `
        -TargetSha256Utf8 $targetPin.candidateSha256 `
        -ChildShaBefore $childBefore -ChildShaAfter $childAfter `
        -JournalComplete $true -DurableReceiptWritten $true
    if ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $ledger) -ne 'RECOVERY_LEDGER_COMPLETE') {
        throw 'LEDGER_SELF_CHECK_FAILED'
    }
    $apply = Invoke-RedrixLdwParentAclMigrationApplyBoundary
    [ordered]@{
        marker = $script:RedrixMigrationMarker
        outcome = 'REHEARSAL_PASS_NO_APPLY'
        authorityClassification = $ref.authorityClassification
        verificationStatus = $ref.verificationStatus
        machineProgramDataPolicy = $binding.policy
        syntheticSnapshotOnly = $true
        hostRootTrustAsserted = $false
        parentPreimageSha256 = $Snapshot.ParentSha256Utf8Sddl
        targetSha256 = $targetPin.candidateSha256
        childHashParityVerified = $true
        ledger = $ledger
        applyBoundary = $apply
        physicalAclChangeAuthorized = $false
        programDataSystemAclChangeAuthorized = $false
        gitHubJitAdmissionAuthorized = $false
    }
}
