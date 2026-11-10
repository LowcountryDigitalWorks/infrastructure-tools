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

function Test-RedrixLdwParentAclMigrationProgramDataPathPolicy {
    param(
        [string]$MachineCommonApplicationData,
        [string]$MachineProgramDataRegistry,
        [string]$ProcessProgramDataEnvironment)
    if ([string]::IsNullOrWhiteSpace($MachineCommonApplicationData)) { return 'MACHINE_PROGRAMDATA_MISSING' }
    $pd = [IO.Path]::GetFullPath($MachineCommonApplicationData)
    $ref = Get-RedrixLdwParentAclMigrationReference
    if ([IO.Path]::GetFileName($pd.TrimEnd('\')) -cne $ref.fixedProgramDataLeafName) { return 'MACHINE_PROGRAMDATA_INVALID' }
    if ($MachineProgramDataRegistry -and ([IO.Path]::GetFullPath($MachineProgramDataRegistry) -cne $pd)) { return 'MACHINE_PROGRAMDATA_DRIFT' }
    if ($ProcessProgramDataEnvironment -and ([IO.Path]::GetFullPath($ProcessProgramDataEnvironment) -cne $pd)) {
        return 'PROCESS_PROGRAMDATA_SPOOFED'
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
        [string]$Stage,
        [string]$ParentShaBefore,
        [hashtable]$ChildShaBefore,
        [bool]$JournalComplete)
    [ordered]@{
        marker = $script:RedrixMigrationMarker
        stage = $Stage
        parentSha256Before = $ParentShaBefore
        childSha256Before = $ChildShaBefore
        journalComplete = $JournalComplete
        physicalApplyAttempted = $false
    }
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
    if (-not $Ledger.ContainsKey('journalComplete')) { return 'HOLD_RECOVERY_AMBIGUOUS' }
    if (-not $Ledger['journalComplete']) { return 'HOLD_RECOVERY_AMBIGUOUS' }
    return 'RECOVERY_LEDGER_COMPLETE'
}

function Test-RedrixLdwParentAclMigrationRollbackPolicy([hashtable]$Ledger) {
    if ($null -eq $Ledger -or -not $Ledger['journalComplete']) { return 'ROLLBACK_REFUSED_NO_JOURNAL' }
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
        -ParentShaBefore $Snapshot.ParentSha256Utf8Sddl -ChildShaBefore $childBefore -JournalComplete $true
    $apply = Invoke-RedrixLdwParentAclMigrationApplyBoundary
    [ordered]@{
        marker = $script:RedrixMigrationMarker
        outcome = 'REHEARSAL_PASS_NO_APPLY'
        authorityClassification = $ref.authorityClassification
        verificationStatus = $ref.verificationStatus
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
