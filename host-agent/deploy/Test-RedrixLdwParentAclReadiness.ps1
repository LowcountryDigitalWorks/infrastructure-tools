#Requires -Version 5.1
<#
.SYNOPSIS
REDRIX D1: read-only LDW parent ACL preflight for a future independently approved owner action.
Never installs, repairs, copies, elevates, schedules, or changes any ACL.
No caller-supplied path, arguments, expected hash, or operation mode.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$marker = 'LDW_REDRIX_PARENT_ACL_PREFLIGHT_V1'
$expectedRootSddlSha256 = 'd7262f4d667814fce0820acbabe2613e352c22614ae7de2105879459c7fbb2a9'
$expectedChildren = [ordered]@{
    'CiJitControl'          = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626'
    'CiJitStatus'           = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626'
    'CiRunnerDispatch'      = '7ad481f8a327149b1b0848cb05cd48e089f50bb0aba8acc247aa771e66445142'
    'CiRunnerEphemeral'     = '7ad481f8a327149b1b0848cb05cd48e089f50bb0aba8acc247aa771e66445142'
    'DragonflyCanaryAdjunct'= '7ad481f8a327149b1b0848cb05cd48e089f50bb0aba8acc247aa771e66445142'
    'PrivilegedControl'    = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626'
}

function Get-SddlSha256([Security.AccessControl.FileSystemSecurity]$Acl) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Acl.Sddl)
        return ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $hash.Dispose() }
}

function Assert-FixedDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw 'FIXED_DIRECTORY_MISSING' }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_DIRECTORY_REFUSED' }
}

function Assert-SystemOrAdministratorsOwner([Security.AccessControl.FileSystemSecurity]$Acl) {
    $ownerSid = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'OWNER_DRIFT' }
}

function Assert-NoBroadWrite([Security.AccessControl.FileSystemSecurity]$Acl) {
    $concrete = [int]([Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    $generic = 0x10000000 -bor 0x40000000
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Value
        if ($sid -in @('S-1-5-18', 'S-1-5-32-544')) { continue }
        $mask = [int]$rule.FileSystemRights
        if ((($mask -band $concrete) -ne 0) -or (($mask -band $generic) -ne 0)) {
            throw 'UNTRUSTED_WRITE_RIGHTS'
        }
    }
}

function Get-ReadOnlyPreflight {
    $pd = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($pd)) { throw 'MACHINE_PROGRAMDATA_MISSING' }
    $pd = [IO.Path]::GetFullPath($pd)
    if ([IO.Path]::GetFileName($pd.TrimEnd('\')) -cne 'ProgramData') { throw 'MACHINE_PROGRAMDATA_INVALID' }
    $machineValue = [Environment]::GetEnvironmentVariable('ProgramData', 'Machine')
    if ($machineValue -and ([IO.Path]::GetFullPath($machineValue) -cne $pd)) { throw 'MACHINE_PROGRAMDATA_DRIFT' }
    if ($env:ProgramData -and ([IO.Path]::GetFullPath($env:ProgramData) -cne $pd)) { throw 'PROCESS_PROGRAMDATA_SPOOFED' }
    Assert-FixedDirectory $pd
    $ldw = Join-Path $pd 'LDW'
    Assert-FixedDirectory $ldw
    $ldwAcl = Get-Acl -LiteralPath $ldw
    Assert-SystemOrAdministratorsOwner $ldwAcl
    if ($ldwAcl.AreAccessRulesProtected) { throw 'ROOT_PREIMAGE_DRIFT' }
    if ((Get-SddlSha256 $ldwAcl) -cne $expectedRootSddlSha256) { throw 'ROOT_SDDL_DRIFT' }

    $items = @(Get-ChildItem -LiteralPath $ldw -Force -ErrorAction Stop)
    if ($items.Count -ne $expectedChildren.Count) { throw 'TOP_LEVEL_INVENTORY_DRIFT' }
    foreach ($item in $items) {
        if (-not $item.PSIsContainer -or -not $expectedChildren.Contains($item.Name)) {
            throw 'TOP_LEVEL_INVENTORY_DRIFT'
        }
    }
    foreach ($name in $expectedChildren.Keys) {
        $path = Join-Path $ldw $name
        Assert-FixedDirectory $path
        $acl = Get-Acl -LiteralPath $path
        Assert-SystemOrAdministratorsOwner $acl
        if (-not $acl.AreAccessRulesProtected) { throw 'CHILD_DACL_NOT_PROTECTED' }
        Assert-NoBroadWrite $acl
        if ((Get-SddlSha256 $acl) -cne $expectedChildren[$name]) { throw 'CHILD_SDDL_DRIFT' }
    }

    $task = Get-ScheduledTask -TaskName 'LDW-ADMIN-REVIEWED-OPERATION' -ErrorAction Stop
    if (@($task).Count -ne 1) { throw 'TASK_IDENTITY_DRIFT' }
    if (@($task.Triggers | Where-Object { $null -ne $_ }).Count -ne 0) { throw 'TASK_TRIGGER_DRIFT' }
    if ($task.State -ne 'Ready') { throw 'TASK_NOT_QUIESCENT' }
    [ordered]@{
        marker = $marker
        classification = 'READ_ONLY_PREIMAGE_MATCH_NOT_AUTHORIZED'
        rootPreimageMatched = $true
        exactProtectedChildCount = $items.Count
        childrenProtectedAndPinned = $true
        existingV1TaskReadyAndTriggerless = $true
        physicalAclChangeAuthorized = $false
        programDataSystemAclChangeAuthorized = $false
        protectedBootstrapAuthorized = $false
        gitHubJitAdmissionAuthorized = $false
        nextGate = 'DISTINCT_SECURITY_REVIEW_AND_OWNER_APPROVED_LDW_ONLY_ACL_ACTION'
    }
}

try {
    $result = Get-ReadOnlyPreflight
    $result | ConvertTo-Json -Compress -Depth 4
}
catch {
    # Deliberately do not emit untrusted file paths, identities, raw SDDL or exception text.
    [ordered]@{
        marker = $marker
        classification = 'HOLD_READ_ONLY'
        reasonCode = 'PREFLIGHT_MISMATCH_OR_UNAVAILABLE'
        physicalAclChangeAuthorized = $false
        protectedBootstrapAuthorized = $false
        gitHubJitAdmissionAuthorized = $false
    } | ConvertTo-Json -Compress -Depth 4
    exit 2
}
