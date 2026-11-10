#Requires -Version 5.1
<#
.SYNOPSIS
Pure in-memory LDW parent ACL candidate generator for source-only design proof (#186).
Never calls Set-Acl, icacls, or mutates a host path.
#>
Set-StrictMode -Version Latest

$script:RedrixLdwParentAclPreimageSddlLiteral = 'O:SYG:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)'
$script:RedrixLdwParentAclCanonicalTargetSddl = 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
$script:RedrixLdwParentAclCanonicalTargetSha256 = 'd0d4816b0b001698a7f49ee24dab0eff49f784bcd9164ad5504b6e45f47f0a41'
$script:RedrixLdwParentAclInvalidLiteratureSha256 = 'a11c28fd0fceea6c13d29661318b95bdb55ca0cd4ad3a0d5f5a3ceb42ce2f7c8'
$script:RedrixLdwParentAclLivePreimageSha256 = 'd7262f4d667814fce0820acbabe2613e352c22614ae7de2105879459c7fbb2a9'

function Get-RedrixLdwParentAclPreimageSecurityDescriptor {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($script:RedrixLdwParentAclPreimageSddlLiteral)
    return $acl
}

function Get-RedrixSddlUtf8Sha256([Security.AccessControl.FileSystemSecurity]$Acl) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Acl.Sddl)
        return ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}

function Get-RedrixUtf8LiteralSha256([string]$Text) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}

function Get-RedrixLdwParentAclTargetRuleMap([Security.AccessControl.FileSystemSecurity]$Acl) {
    $map = [ordered]@{}
    foreach ($rule in $Acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($map.Contains($sid)) { throw 'RULE_MAP_DUPLICATE_PRINCIPAL' }
        $map[$sid] = [int]$rule.FileSystemRights
    }
    return $map
}

function Assert-RedrixLdwParentAclTargetRuleParity(
    [Security.AccessControl.FileSystemSecurity]$Left,
    [Security.AccessControl.FileSystemSecurity]$Right) {
    $leftMap = Get-RedrixLdwParentAclTargetRuleMap $Left
    $rightMap = Get-RedrixLdwParentAclTargetRuleMap $Right
    if ($leftMap.Count -ne $rightMap.Count) { throw 'RULE_PARITY_COUNT' }
    foreach ($sid in $leftMap.Keys) {
        if (-not $rightMap.Contains($sid)) { throw 'RULE_PARITY_MISSING_SID' }
        if ($leftMap[$sid] -ne $rightMap[$sid]) { throw 'RULE_PARITY_MASK' }
    }
}

function New-RedrixLdwParentAclExplicitTargetSecurityDescriptor {
    $draft = New-Object System.Security.AccessControl.DirectorySecurity
    $draft.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $draft.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $draft.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $prop = [Security.AccessControl.PropagationFlags]::None
    $draft.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            $prop,
            [Security.AccessControl.AccessControlType]::Allow))
    $draft.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            $prop,
            [Security.AccessControl.AccessControlType]::Allow))
    $rxSync = [Security.AccessControl.FileSystemRights]0x1200a9
    $draft.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
            $rxSync,
            $inherit,
            $prop,
            [Security.AccessControl.AccessControlType]::Allow))
    Assert-RedrixLdwParentAclExplicitTargetShape $draft

    $canonical = New-Object System.Security.AccessControl.DirectorySecurity
    $canonical.SetSecurityDescriptorSddlForm($script:RedrixLdwParentAclCanonicalTargetSddl)
    Assert-RedrixLdwParentAclTargetRuleParity $draft $canonical
    Assert-RedrixLdwParentAclExplicitTargetShape $canonical
    if ($canonical.Sddl -cne $script:RedrixLdwParentAclCanonicalTargetSddl) {
        throw 'CANONICAL_SDDL_DRIFT'
    }
    if ((Get-RedrixSddlUtf8Sha256 $canonical) -cne $script:RedrixLdwParentAclCanonicalTargetSha256) {
        throw 'CANONICAL_SHA_DRIFT'
    }
    return $canonical
}

function New-RedrixLdwParentAclBadCopyRemoveSecurityDescriptor {
    $acl = Get-RedrixLdwParentAclPreimageSecurityDescriptor
    $acl.SetAccessRuleProtection($true, $true)
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -ceq 'S-1-3-0') {
            [void]$acl.RemoveAccessRuleSpecific($rule)
            continue
        }
        if ($sid -ceq 'S-1-5-32-545') {
            $mask = [int]$rule.FileSystemRights
            if (($mask -band 0x116) -ne 0 -or ($mask -band [int][Security.AccessControl.FileSystemRights]::Write) -ne 0) {
                [void]$acl.RemoveAccessRule($rule)
            }
        }
    }
    return $acl
}

function Test-RedrixLdwParentAclHasCreatorOwnerGenericAll([Security.AccessControl.FileSystemSecurity]$Acl) {
    $creator = 'S-1-3-0'
    $genericAll = 0x10000000
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -cne $creator) { continue }
        if (([int]$rule.FileSystemRights -band $genericAll) -ne 0) { return $true }
    }
    return $false
}

function Test-RedrixLdwParentAclHasUntrustedUsersRights([Security.AccessControl.FileSystemSecurity]$Acl) {
    $win32GenericWrite = 0x40000000
    $win32GenericAll = 0x10000000
    $forbidden = [int](
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -in @('S-1-5-18', 'S-1-5-32-544')) { continue }
        $rights = [int]$rule.FileSystemRights
        if (($rights -band $win32GenericWrite) -ne 0) { return $true }
        if (($rights -band $win32GenericAll) -ne 0) { return $true }
        if (($rights -band $forbidden) -ne 0) { return $true }
    }
    return $false
}

function Assert-RedrixLdwParentAclExplicitTargetShape([Security.AccessControl.FileSystemSecurity]$Acl) {
    if (-not $Acl.AreAccessRulesProtected) { throw 'TARGET_NOT_PROTECTED' }
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -cne 'S-1-5-18') { throw 'TARGET_OWNER_NOT_SY' }
    $group = $Acl.GetGroup([Security.Principal.SecurityIdentifier]).Value
    if ($group -cne 'S-1-5-18') { throw 'TARGET_GROUP_NOT_SY' }
    if (Test-RedrixLdwParentAclHasCreatorOwnerGenericAll $Acl) { throw 'TARGET_CREATOR_OWNER_PRESENT' }
    if (Test-RedrixLdwParentAclHasUntrustedUsersRights $Acl) { throw 'TARGET_UNTRUSTED_USERS_RIGHTS' }
    $allowed = @{}
    foreach ($rule in $Acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($allowed.ContainsKey($sid)) { throw 'TARGET_DUPLICATE_PRINCIPAL' }
        $allowed[$sid] = [int]$rule.FileSystemRights
    }
    if ($allowed.Count -ne 3) { throw 'TARGET_UNEXPECTED_ACE_COUNT' }
    if (-not $allowed.ContainsKey('S-1-5-18')) { throw 'TARGET_MISSING_SY' }
    if (-not $allowed.ContainsKey('S-1-5-32-544')) { throw 'TARGET_MISSING_BA' }
    if (-not $allowed.ContainsKey('S-1-5-32-545')) { throw 'TARGET_MISSING_BU' }
    $faMask = [int]([Security.AccessControl.FileSystemRights]::FullControl)
    if ($faMask -ne $allowed['S-1-5-18']) { throw 'TARGET_SY_NOT_FA' }
    if ($faMask -ne $allowed['S-1-5-32-544']) { throw 'TARGET_BA_NOT_FA' }
    if (0x1200a9 -ne $allowed['S-1-5-32-545']) { throw 'TARGET_BU_NOT_RX_SYNC' }
}

function Test-RedrixLdwParentAclCanonicalPin([Security.AccessControl.FileSystemSecurity]$Candidate) {
    $actualSha = Get-RedrixSddlUtf8Sha256 $Candidate
    $shaOk = ($actualSha -ceq $script:RedrixLdwParentAclCanonicalTargetSha256)
    $sddlOk = ($Candidate.Sddl -ceq $script:RedrixLdwParentAclCanonicalTargetSddl)
    return [ordered]@{
        candidateSddl = $Candidate.Sddl
        candidateSha256 = $actualSha
        canonicalSddl = $script:RedrixLdwParentAclCanonicalTargetSddl
        canonicalSha256 = $script:RedrixLdwParentAclCanonicalTargetSha256
        invalidLiteratureSha256 = $script:RedrixLdwParentAclInvalidLiteratureSha256
        shaMatchesCanonical = $shaOk
        sddlMatchesCanonical = $sddlOk
        invalidLiteratureRejected = ($actualSha -cne $script:RedrixLdwParentAclInvalidLiteratureSha256)
    }
}
