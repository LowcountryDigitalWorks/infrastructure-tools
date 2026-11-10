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
if ($null -ne $ast.ParamBlock) {
    foreach ($p in $ast.ParamBlock.Parameters) {
        if ($p.Name -notin @('Variant', 'MachineCommonApplicationData', 'MachineProgramDataRegistry',
                'ProcessProgramDataEnvironment', 'Snapshot', 'ClaimedAuthorizationBasis', 'Ledger',
                'Before', 'After', 'Stage', 'ParentShaBefore', 'ChildShaBefore', 'JournalComplete')) {
            throw ('UNEXPECTED_CALLER_PARAM_' + $p.Name)
        }
    }
}

. $helper

$checks = 0
function Assert([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw ('ASSERTION_FAILED_' + $Code) }
    $script:checks++
}

$ref = Get-RedrixLdwParentAclMigrationReference
Assert ($ref.fixedV1ReviewedOperationTaskName -ceq 'LDW-ADMIN-REVIEWED-OPERATION') 'V1_TASK_NAME_PIN'
Assert ($ref.canonicalTargetSha256Utf8SddlProperty -ceq 'd0d4816b0b001698a7f49ee24dab0eff49f784bcd9164ad5504b6e45f47f0a41') 'TARGET_SHA_PIN'
Assert ($ref.syntheticHashIsNotMutationAuthority) 'SYNTHETIC_HASH_NOT_AUTHORITY'
Assert (@($ref.protectedChildSddlSha256Utf8.PSObject.Properties).Count -eq 6) 'SIX_CHILD_PINS'

$pd = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$machinePd = [Environment]::GetEnvironmentVariable('ProgramData', 'Machine')
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy $pd $machinePd $null) -ceq 'OK') 'KNOWN_FOLDER_POLICY'
$bogus = Join-Path $env:TEMP 'NotProgramData'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy $bogus $null $null) -ceq 'MACHINE_PROGRAMDATA_INVALID') 'INVALID_FOLDER_REJECT'
Assert ((Test-RedrixLdwParentAclMigrationProgramDataPathPolicy $pd $machinePd $bogus) -ceq 'PROCESS_PROGRAMDATA_SPOOFED') 'PROCESS_ENV_SPOOF'

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
Assert ($rehearsal.childHashParityVerified) 'CHILD_HASH_PARITY'
Assert (-not $rehearsal.physicalAclChangeAuthorized) 'NO_PHYSICAL_AUTH'
Assert ($rehearsal.targetSha256 -ceq $ref.canonicalTargetSha256Utf8SddlProperty) 'TARGET_SHA_MATCH'
Assert ($rehearsal.applyBoundary.classification -ceq 'BLOCKED_APPROVAL') 'APPLY_BLOCKED'

$apply = Invoke-RedrixLdwParentAclMigrationApplyBoundary
Assert ($apply.classification -ceq 'BLOCKED_APPROVAL') 'BOUNDARY_ALWAYS_BLOCKED'

$incompleteLedger = @{ journalComplete = $false }
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $incompleteLedger) -ceq 'HOLD_RECOVERY_AMBIGUOUS') 'REBOOT_FAULT_HOLD'
$completeLedger = @{ journalComplete = $true }
Assert ((Test-RedrixLdwParentAclMigrationRecoveryAfterReboot $completeLedger) -ceq 'RECOVERY_LEDGER_COMPLETE') 'LEDGER_COMPLETE'

Assert ((Test-RedrixLdwParentAclMigrationRollbackPolicy $null) -ceq 'ROLLBACK_REFUSED_NO_JOURNAL') 'ROLLBACK_NO_JOURNAL'
Assert ((Test-RedrixLdwParentAclMigrationRollbackPolicy $incompleteLedger) -ceq 'ROLLBACK_REFUSED_NO_JOURNAL') 'ROLLBACK_INCOMPLETE_JOURNAL'

$before = @{ CiJitControl = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626' }
$after = @{ CiJitControl = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626' }
Assert (Test-RedrixLdwParentAclMigrationChildHashParity $before $after) 'PARITY_EQUAL'
$afterBad = @{ CiJitControl = ('0' * 64) }
Assert (-not (Test-RedrixLdwParentAclMigrationChildHashParity $before $afterBad)) 'PARITY_POST_DRIFT'

$stockTouch = New-RedrixLdwParentAclMockHostSnapshot -Variant ValidPreMigration
$stockTouch.StockProgramDataAclMutationAttempted = $true
Assert ((Test-RedrixLdwParentAclMigrationPreconditions $stockTouch) -ceq 'STOCK_PROGRAMDATA_TOUCH_REFUSED') 'STOCK_PROGRAMDATA_REFUSE'

Write-Host ('REDRIX_LDW_PARENT_ACL_MIGRATION_REHEARSAL_TESTS=PASS assertions=' + $checks)
Write-Host ('REDRIX_LDW_PARENT_ACL_MIGRATION_PHYSICAL_APPLY=BLOCKED_APPROVAL')
Write-Host ('REDRIX_LDW_PARENT_ACL_MIGRATION_AUTHORITY=NOT_PHYSICAL_AUTHORITY')
