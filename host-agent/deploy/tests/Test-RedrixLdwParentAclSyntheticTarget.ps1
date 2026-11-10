#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleRoot = Split-Path $PSScriptRoot -Parent
$helper = Join-Path $moduleRoot 'RedrixLdwParentAclSyntheticTarget.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'HELPER_MISSING' }

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw 'HELPER_SYNTAX_ERROR' }
$forbidden = @(
    'Set-Acl', 'icacls', 'takeown', 'Invoke-Expression', 'Start-Process',
    'New-Item', 'Remove-Item', 'Move-Item', 'Copy-Item', 'Set-Content', 'Add-Content', 'Out-File')
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

$preimage = Get-RedrixLdwParentAclPreimageSecurityDescriptor
Assert (Test-RedrixLdwParentAclHasUntrustedUsersRights $preimage) 'PREIMAGE_HAS_USERS_WRITE_SURFACE'
Assert (Test-RedrixLdwParentAclHasCreatorOwnerGenericAll $preimage) 'PREIMAGE_HAS_CREATOR_OWNER_GENERIC_ALL'
Assert (-not $preimage.AreAccessRulesProtected) 'PREIMAGE_IS_UNPROTECTED'

$bad = New-RedrixLdwParentAclBadCopyRemoveSecurityDescriptor
Assert (Test-RedrixLdwParentAclHasUntrustedUsersRights $bad) 'BAD_TRANSFORM_RETAINS_USERS_WRITE_OR_FORBIDDEN'
Assert ($bad.Sddl -notmatch 'O:SYG:SYD:PAI\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)\(A;OICI;0x1200a9;;;BU\)') `
    'BAD_TRANSFORM_NOT_EXACT_TARGET'

$candidate = New-RedrixLdwParentAclExplicitTargetSecurityDescriptor
Assert-RedrixLdwParentAclExplicitTargetShape $candidate
$pin = Test-RedrixLdwParentAclReviewerHypothesisPin $candidate
Assert (-not $pin.sddlMatchesHypothesis) 'EXPLICIT_BUILD_SDDL_DIFFERS_FROM_LITERATURE_STRING'
Assert ($pin.literaturePinStatus -eq 'BLOCKED_TARGET_MISMATCH') 'REVIEWER_SHA_PIN_UNVERIFIED_ON_HOST'
Assert ($pin.candidateSha256.Length -eq 64) 'CANDIDATE_SHA_PRESENT'

if ($candidate.Sddl -cmatch ';;;CO\)') { throw 'ASSERTION_FAILED_TARGET_OMITS_CREATOR_OWNER' }
Assert ($true) 'TARGET_OMITS_CREATOR_OWNER'

$preimageProtectedOnly = Get-RedrixLdwParentAclPreimageSecurityDescriptor
$preimageProtectedOnly.SetAccessRuleProtection($true, $false)
try {
    Assert-RedrixLdwParentAclExplicitTargetShape $preimageProtectedOnly
    throw 'ASSERTION_FAILED_CREATOR_OWNER_NOT_REJECTED'
}
catch {
    if ($_.Exception.Message -cnotmatch 'TARGET_CREATOR_OWNER_PRESENT|TARGET_UNEXPECTED_ACE_COUNT|TARGET_UNTRUSTED_USERS_RIGHTS') { throw }
    Assert ($true) 'CREATOR_OWNER_AND_USERS_WRITE_REJECTED'
}

$withWrite = New-RedrixLdwParentAclExplicitTargetSecurityDescriptor
$withWrite.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
        [Security.AccessControl.FileSystemRights]::Write,
        [Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
try {
    Assert-RedrixLdwParentAclExplicitTargetShape $withWrite
    throw 'ASSERTION_FAILED_USERS_WRITE_NOT_REJECTED'
}
catch {
    if ($_.Exception.Message -cnotmatch 'TARGET_UNEXPECTED_ACE_COUNT|TARGET_UNTRUSTED_USERS_RIGHTS') { throw }
    Assert ($true) 'USERS_WRITE_SURFACE_REJECTED'
}

$hypothesis = New-Object System.Security.AccessControl.DirectorySecurity
$hypothesis.SetSecurityDescriptorSddlForm($script:RedrixLdwParentAclReviewerHypothesisSddl)
try {
    Assert-RedrixLdwParentAclExplicitTargetShape $hypothesis
    Assert ($true) 'HYPOTHESIS_SDDL_PASSES_SHAPE_WHEN_LOADED'
}
catch {
    throw ('HYPOTHESIS_SDDL_SHAPE_FAILED_' + $_.Exception.Message)
}

Write-Host ('REDRIX_LDW_PARENT_ACL_SYNTHETIC_TESTS=PASS assertions=' + $checks)
Write-Host ('REDRIX_LDW_PARENT_ACL_CANDIDATE_SHA256=' + $pin.candidateSha256)
Write-Host ('REDRIX_LDW_PARENT_ACL_CANDIDATE_SDDL=' + $pin.candidateSddl)
Write-Host ('REDRIX_LDW_PARENT_ACL_LITERATURE_PIN_STATUS=' + $pin.literaturePinStatus)
Write-Host ('REDRIX_LDW_PARENT_ACL_HYPOTHESIS_HOST_SHA256=' + $pin.reviewerHypothesisSha256)
