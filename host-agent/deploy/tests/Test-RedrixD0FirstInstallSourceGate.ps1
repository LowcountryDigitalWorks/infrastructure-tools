#Requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'D0_SOURCE_GATE_WINPS51_X64_REQUIRED'
}
$script:Assertions=0
function Assert-D0([bool]$ok,[string]$name) {
    $script:Assertions++
    if (-not $ok) { throw ('D0_SOURCE_FIXTURE_ASSERT_' + $name) }
}
function Assert-Refused([scriptblock]$action,[string]$expected) {
    $script:Assertions++
    try { [void](& $action) }
    catch {
        if ($_.Exception.Message -ceq $expected) { return }
        throw ('D0_SOURCE_WRONG_REFUSAL expected=' + $expected + ' actual=' + $_.Exception.Message)
    }
    throw ('D0_SOURCE_EXPECTED_REFUSAL_NOT_OBSERVED ' + $expected)
}
$deployRoot=Split-Path -Parent $PSScriptRoot
$module=Join-Path $deployRoot 'RedrixD0FirstInstallReadOnly.psm1'
$entry=Join-Path $deployRoot 'Plan-RedrixD0SystemTaskFirstInstall.ps1'
Assert-D0 (Test-Path -LiteralPath $module -PathType Leaf) 'MODULE_PRESENT'
Assert-D0 (Test-Path -LiteralPath $entry -PathType Leaf) 'ENTRY_PRESENT'
$moduleErrors=$null
$entryErrors=$null
[void][Management.Automation.Language.Parser]::ParseFile($module,[ref]$null,[ref]$moduleErrors)
[void][Management.Automation.Language.Parser]::ParseFile($entry,[ref]$null,[ref]$entryErrors)
Assert-D0 ($moduleErrors.Count -eq 0) 'MODULE_PARSES'
Assert-D0 ($entryErrors.Count -eq 0) 'ENTRY_PARSES'

Import-Module -Name $module -Force
$good='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$taskGood='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
Assert-D0 (Assert-D0ExactProtectedDescriptor -Sddl $good) 'EXACT_STAGING_DACL'
Assert-D0 (Assert-D0ExactProtectedDescriptor -Sddl $taskGood -Kind SystemTask) 'EXACT_TASK_OBJECT_DACL'
Assert-D0 (Assert-D0ExactProtectedDescriptor -Sddl (
    'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')) 'SYSTEM_OWNER_STAGE_ALLOWED'

Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BUG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)') } 'D0_SOURCE_OWNER_UNTRUSTED'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)') } 'D0_SOURCE_GROUP_UNTRUSTED'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)') } 'D0_DACL_UNPROTECTED_OR_MISSING'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;OICI;FA;;;SY)') } 'D0_DACL_NOT_EXACT_TWO_ACE'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)') } 'D0_DACL_NOT_EXACT_TWO_ACE'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BU)') } 'D0_ACE_UNTRUSTED_IDENTITY'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;SY)') } 'D0_ACE_DUPLICATE'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(D;OICI;FA;;;SY)(A;OICI;FA;;;BA)') } 'D0_ACE_TYPE_OR_DENY_REFUSED'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;OICI;FR;;;SY)(A;OICI;FA;;;BA)') } 'D0_ACE_RIGHTS_DRIFT'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;OI;FA;;;SY)(A;OICI;FA;;;BA)') } 'D0_ACE_INHERITANCE_DRIFT'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)') } 'D0_ACE_INHERITANCE_DRIFT'
Assert-Refused { Assert-D0ExactProtectedDescriptor -Sddl (
    'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)') -Kind SystemTask } 'D0_ACE_INHERITANCE_DRIFT'

$leaf='ldw-d0-source-fixture-'+[Guid]::NewGuid().ToString('N')
$fixture=Join-Path ([IO.Path]::GetTempPath()) $leaf
$root=Join-Path $fixture 'LowcountryDigitalWorks/RedrixD0'
$wrong=Join-Path $fixture 'Attacker/RedrixD0'
try {
    [void][IO.Directory]::CreateDirectory($root)
    Assert-D0 (([IO.File]::GetAttributes($fixture) -band
        [IO.FileAttributes]::ReparsePoint) -eq 0) 'FIXTURE_ROOT_NOT_REPARSE'
    Assert-D0 (Assert-D0SourcePathBoundary -ProgramFilesRoot $fixture -CandidateRoot $root) 'EXACT_CHILD_FROM_TEST_ANCHOR'
    Assert-Refused { Assert-D0SourcePathBoundary -ProgramFilesRoot $fixture -CandidateRoot $wrong } 'D0_SOURCE_PATH_NOT_FIXED_OS_ROOT'
    Assert-Refused { Assert-D0SourcePathBoundary -ProgramFilesRoot $fixture -CandidateRoot (
        Join-Path $root '../Wrong') } 'D0_SOURCE_PATH_NOT_FIXED_OS_ROOT'
    [void][IO.Directory]::Delete($root)
    Assert-Refused { Assert-D0SourcePathBoundary -ProgramFilesRoot $fixture -CandidateRoot $root } 'D0_SOURCE_COMPONENT_ABSENT'
}
finally {
    if (Test-Path -LiteralPath $fixture -PathType Container) {
        if (([IO.File]::GetAttributes($fixture) -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'D0_FIXTURE_ROOT_REPARSE_CLEANUP_REFUSED'
        }
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop
    }
}
$plan=Get-D0FirstInstallSourcePlan
Assert-D0 ($plan.status -match '^D0_') 'PLAN_FAIL_CLOSED_STATUS'
Assert-D0 ($plan.physical_task_install -ceq 'NOT_AUTHORIZED_BY_PLAN') 'NO_INSTALL_AUTHORITY'
Assert-D0 ($plan.execution_principal -ceq 'SYSTEM') 'FROZEN_SYSTEM_INTENT'
Assert-D0 ($plan.task_triggers -eq 0) 'ZERO_TRIGGERS'
Assert-D0 ($plan.source_validation -cne 'AUTHENTICATED_ACCEPTED_SOURCE') 'SOURCE_NOT_AUTHENTICATED'
$moduleText=Get-Content -LiteralPath $module -Raw
$entryText=Get-Content -LiteralPath $entry -Raw
foreach ($forbidden in @('RegisterTaskDefinition(','.Run(', 'Set-Acl','Remove-Item','Copy-Item',
    'New-Item','Start-Process','schtasks.exe','Invoke-WebRequest','Invoke-RestMethod')) {
    Assert-D0 (-not $moduleText.Contains($forbidden)) ('MODULE_NO_MUTATOR_'+ $forbidden)
    Assert-D0 (-not $entryText.Contains($forbidden)) ('ENTRY_NO_MUTATOR_' + $forbidden)
}
# Next strict source gate: all three OS-source path DACL levels, not leaf-only.
# SDDL values here are a pure synthetic data contract: no SYSTEM owner is
# assigned on the hosted runner or any real ProgramFiles directory.
$ti='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$rootGood=('O:'+$ti+'G:'+$ti+'D:PAI(A;OICI;FA;;;'+$ti+
    ')(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'+
    '(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;S-1-15-2-1)')
Assert-D0 (Assert-D0ProgramFilesRootDescriptor -Sddl $rootGood) 'ROOT_BASELINE_READ_ONLY_ACES'
Assert-D0 (Assert-D0SourceAncestorDaclSnapshot -RootSddl $rootGood `
    -IntermediateSddl $good -LeafSddl $good) 'THREE_LEVEL_SDDL_VALID_LAB_ONLY'
$rootChildDelete=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(A;OICI;0x1200e9;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootChildDelete } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
$rootBuDelete=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(A;OICI;0x1300a9;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootBuDelete } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
$rootBuWriteDac=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(A;OICI;0x1600a9;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootBuWriteDac } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
$rootBuWriteOwner=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(A;OICI;0x1a00a9;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootBuWriteOwner } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
$rootBuAddSubdir=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(A;OICI;0x1200ad;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootBuAddSubdir } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
$rootBuGenericWrite=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(A;OICI;0x40000000;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootBuGenericWrite } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
$rootBuIO=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(A;OICIIO;FA;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootBuIO } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
$rootOwnerBu=$rootGood.Replace(('O:'+$ti),'O:BU')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootOwnerBu } 'D0_ROOT_OWNER_UNTRUSTED'
$rootGroupBu=$rootGood.Replace(('G:'+$ti),'G:BU')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootGroupBu } 'D0_ROOT_GROUP_UNTRUSTED'
$rootCOImmediate=$rootGood.Replace('(A;OICIIO;GA;;;CO)','(A;OICI;GA;;;CO)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootCOImmediate } 'D0_ROOT_CREATOR_OWNER_NOT_INHERIT_ONLY'
$rootForeignService=$rootGood.Replace(('(A;OICI;FA;;;'+$ti+')'),
    '(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootForeignService } 'D0_ROOT_ACE_UNKNOWN_IDENTITY'
$rootDeny=$rootGood.Replace('(A;OICI;0x1200a9;;;BU)','(D;OICI;0x1200a9;;;BU)')
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl $rootDeny } 'D0_ROOT_ACE_TYPE_OR_DENY_REFUSED'
Assert-Refused { Assert-D0ProgramFilesRootDescriptor -Sddl 'O:BAG:BAD:' } 'D0_ROOT_DACL_MISSING_OR_EMPTY'
Assert-Refused { Assert-D0SourceAncestorDaclSnapshot -RootSddl $rootChildDelete `
    -IntermediateSddl $good -LeafSddl $good } 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
Assert-Refused { Assert-D0SourceAncestorDaclSnapshot -RootSddl $rootGood `
    -IntermediateSddl 'O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' `
    -LeafSddl $good } 'D0_INTERMEDIATE_D0_DACL_UNPROTECTED_OR_MISSING'
Assert-Refused { Assert-D0SourceAncestorDaclSnapshot -RootSddl $rootGood `
    -IntermediateSddl 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200e9;;;BU)' `
    -LeafSddl $good } 'D0_INTERMEDIATE_D0_DACL_NOT_EXACT_TWO_ACE'
Assert-Refused { Assert-D0SourceAncestorDaclSnapshot -RootSddl $rootGood `
    -IntermediateSddl $good `
    -LeafSddl 'O:BUG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' } 'D0_LEAF_D0_SOURCE_OWNER_UNTRUSTED'
# Live Get-Acl traversal in a newly created TEMP tree must refuse:
# its ordinary user-owned/inherited root is not a privileged ProgramFiles root.
$ancestorFixture=Join-Path ([IO.Path]::GetTempPath()) ('ldw-d0-ancestor-'+[Guid]::NewGuid().ToString('N'))
$ancestorLeaf=Join-Path $ancestorFixture 'LowcountryDigitalWorks/RedrixD0'
try {
    [void][IO.Directory]::CreateDirectory($ancestorLeaf)
    $refused=$false
    try {
        [void](Assert-D0SourceAncestorDaclChain -ProgramFilesRoot $ancestorFixture -CandidateRoot $ancestorLeaf)
    }
    catch {
        if ($_.Exception.Message -cmatch '^D0_') { $refused=$true }
        else { throw }
    }
    Assert-D0 $refused 'REAL_TEMP_CHAIN_NOT_MISLABELED_TRUSTED_ROOT'
}
finally {
    if(Test-Path -LiteralPath $ancestorFixture -PathType Container) {
        Remove-Item -LiteralPath $ancestorFixture -Recurse -Force -ErrorAction Stop
    }
}

Write-Output ('REDRIX_D0_FIRST_INSTALL_SOURCE_GATE_TEMP=PASS assertions=' + $script:Assertions)
Write-Output 'REDRIX_D0_FIRST_INSTALL_SOURCE_AUTHENTICATED=FALSE'
Write-Output 'REDRIX_D0_FIRST_INSTALL_PHYSICAL_SYSTEM_TASK=NOT_INSTALLED'
Write-Output 'REDRIX_D0_FIRST_INSTALL_PHYSICAL_AUTHORITY=HOLD_SECURITY'
