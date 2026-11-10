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

$sidProbe = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
if ($sidProbe.Value -cne 'S-1-5-18') { throw 'SECURITYIDENTIFIER_NEW_PS51_FAILED' }

$checks = 0
function Assert([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw ('ASSERTION_FAILED_' + $Code) }
    $script:checks++
}

$preimage = Get-RedrixLdwParentAclPreimageSecurityDescriptor
Assert (Test-RedrixLdwParentAclHasUntrustedUsersRights $preimage) 'PREIMAGE_HAS_USERS_WRITE_SURFACE'
Assert (Test-RedrixLdwParentAclHasCreatorOwnerGenericAll $preimage) 'PREIMAGE_HAS_CREATOR_OWNER_GENERIC_ALL'
Assert (-not $preimage.AreAccessRulesProtected) 'PREIMAGE_IS_UNPROTECTED'
$literalHash = Get-RedrixUtf8LiteralSha256 $script:RedrixLdwParentAclPreimageSddlLiteral
$normalizedHash = Get-RedrixSddlUtf8Sha256 $preimage
Assert ($literalHash -cne $normalizedHash) 'PREIMAGE_LITERAL_NOT_CANONICAL_SDDL'
Assert ($normalizedHash -cne $script:RedrixLdwParentAclLivePreimageSha256) 'SYNTHETIC_FIXTURE_NOT_LIVE_PREIMAGE_SHA'
Assert ($preimage.Sddl -match 'DCLCRPCR') 'PREIMAGE_USERS_WRITE_NORMALIZED_MASK'

$bad = New-RedrixLdwParentAclBadCopyRemoveSecurityDescriptor
Assert (Test-RedrixLdwParentAclHasUntrustedUsersRights $bad) 'BAD_TRANSFORM_RETAINS_USERS_WRITE_OR_FORBIDDEN'
Assert ($bad.Sddl -cne $script:RedrixLdwParentAclCanonicalTargetSddl) 'BAD_TRANSFORM_NOT_CANONICAL_TARGET'

$candidate = New-RedrixLdwParentAclExplicitTargetSecurityDescriptor
Assert-RedrixLdwParentAclExplicitTargetShape $candidate
$pin = Test-RedrixLdwParentAclCanonicalPin $candidate
Assert $pin.sddlMatchesCanonical 'CANONICAL_SDDL_VERIFIED'
Assert $pin.shaMatchesCanonical 'CANONICAL_SHA_VERIFIED'
Assert $pin.invalidLiteratureRejected 'INVALID_LITERATURE_SHA_a11c_REJECTED'
Assert ($pin.candidateSha256 -ceq 'd0d4816b0b001698a7f49ee24dab0eff49f784bcd9164ad5504b6e45f47f0a41') 'PIN_D0D4816B'
Assert ($pin.candidateSha256 -cne $pin.invalidLiteratureSha256) 'A11C_NOT_ACCEPTED'
Assert ($pin.authorityClassification -ceq 'NOT_PHYSICAL_AUTHORITY') 'AUTHORITY_NOT_PHYSICAL'
Assert ($pin.verificationStatus -ceq 'SOURCE_SYNTHETIC_VERIFIED') 'VERIFICATION_SOURCE_SYNTHETIC'

$adv = Test-RedrixLdwParentAclInvalidLiteratureAdversarialHold
Assert $adv.acceptedCanonicalPin 'CANONICAL_LOADED_SDDL_PIN_D0D4816B'
Assert $adv.adversarialLiteratureWouldHold 'A11C_ADVERSARIAL_HOLD'
Assert ($adv.pinStatusIfLiteraturePinRequired -ceq 'HOLD_TARGET_MISMATCH') 'A11C_HOLD_TARGET_MISMATCH'

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

Write-Host ('REDRIX_LDW_PARENT_ACL_SYNTHETIC_TESTS=PASS assertions=' + $checks)
Write-Host ('REDRIX_LDW_PARENT_ACL_AUTHORITY_CLASSIFICATION=' + $pin.authorityClassification)
Write-Host ('REDRIX_LDW_PARENT_ACL_VERIFICATION_STATUS=' + $pin.verificationStatus)
Write-Host ('REDRIX_LDW_PARENT_ACL_CANDIDATE_SHA256=' + $pin.candidateSha256)
Write-Host ('REDRIX_LDW_PARENT_ACL_CANDIDATE_SDDL=' + $pin.candidateSddl)
Write-Host ('REDRIX_LDW_PARENT_ACL_CANONICAL_PIN_STATUS=VERIFIED')
Write-Host ('REDRIX_LDW_PARENT_ACL_INVALID_LITERATURE_a11c_STATUS=HOLD_TARGET_MISMATCH')
