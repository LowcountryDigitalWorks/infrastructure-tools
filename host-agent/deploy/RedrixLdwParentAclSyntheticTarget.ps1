#Requires -Version 5.1
<#
.SYNOPSIS
Pure in-memory LDW parent ACL candidate generator for source-only design proof (#186).
Never calls Set-Acl, icacls, or mutates a host path.
#>
Set-StrictMode -Version Latest

$script:RedrixLdwParentAclPreimageSddl = 'O:SYG:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)'
$script:RedrixLdwParentAclReviewerHypothesisSddl = 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
$script:RedrixLdwParentAclReviewerHypothesisSha256 = 'a11c28fd0fceea6c13d29661318b95bdb55ca0cd4ad3a0d5f5a3ceb42ce2f7c8'

function Get-RedrixLdwParentAclPreimageSecurityDescriptor {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($script:RedrixLdwParentAclPreimageSddl)
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

function New-RedrixLdwParentAclExplicitTargetSecurityDescriptor {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $acl.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $prop = [Security.AccessControl.PropagationFlags]::None
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            $prop,
            [Security.AccessControl.AccessControlType]::Allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            $prop,
            [Security.AccessControl.AccessControlType]::Allow))
    $rxSync = [Security.AccessControl.FileSystemRights]0x1200a9
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),
            $rxSync,
            $inherit,
            $prop,
            [Security.AccessControl.AccessControlType]::Allow))
    return $acl
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

function Test-RedrixLdwParentAclReviewerHypothesisPin([Security.AccessControl.FileSystemSecurity]$Candidate) {
    $actual = Get-RedrixSddlUtf8Sha256 $Candidate
    $hypothesisLoad = New-Object System.Security.AccessControl.DirectorySecurity
    $hypothesisLoad.SetSecurityDescriptorSddlForm($script:RedrixLdwParentAclReviewerHypothesisSddl)
    $hypothesisSha = Get-RedrixSddlUtf8Sha256 $hypothesisLoad
    $builtMatchesHypothesisSddl = ($Candidate.Sddl -ceq $hypothesisLoad.Sddl)
    $builtMatchesReviewerPin = ($actual -ceq $script:RedrixLdwParentAclReviewerHypothesisSha256)
    return [ordered]@{
        candidateSddl = $Candidate.Sddl
        candidateSha256 = $actual
        reviewerHypothesisSddl = $hypothesisLoad.Sddl
        reviewerHypothesisSha256 = $hypothesisSha
        reviewerLiteratureSha256Pin = $script:RedrixLdwParentAclReviewerHypothesisSha256
        sddlMatchesHypothesis = $builtMatchesHypothesisSddl
        shaMatchesLiteraturePin = $builtMatchesReviewerPin
        literaturePinStatus = if ($builtMatchesReviewerPin) { 'VERIFIED_LITERATURE_PIN' } else { 'BLOCKED_TARGET_MISMATCH' }
    }
}
