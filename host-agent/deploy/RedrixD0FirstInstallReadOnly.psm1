# D0 first-install source/Task Scheduler gate primitives.
# NO filesystem writer, Task Scheduler mutator, elevation, issuer or runner.
Set-StrictMode -Version Latest

function Assert-D0ExactProtectedDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Sddl,
        [ValidateSet('StagingDirectory','SystemTask')][string]$Kind='StagingDirectory'
    )
    try { $sd=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl) }
    catch { throw 'D0_DESCRIPTOR_INVALID' }
    if ($sd.Owner.Value -cne 'S-1-5-32-544' -and $sd.Owner.Value -cne 'S-1-5-18') {
        throw 'D0_SOURCE_OWNER_UNTRUSTED'
    }
    if ($sd.Group.Value -cne 'S-1-5-32-544' -and $sd.Group.Value -cne 'S-1-5-18') {
        throw 'D0_SOURCE_GROUP_UNTRUSTED'
    }
    if (($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or
        ($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
        throw 'D0_DACL_UNPROTECTED_OR_MISSING'
    }
    if ($null -eq $sd.DiscretionaryAcl -or $sd.DiscretionaryAcl.Count -ne 2) {
        throw 'D0_DACL_NOT_EXACT_TWO_ACE'
    }
    $seen=@{}
    foreach($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.IsCallback -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) {
            throw 'D0_ACE_TYPE_OR_DENY_REFUSED'
        }
        $sid=$ace.SecurityIdentifier.Value
        if ($sid -cne 'S-1-5-18' -and $sid -cne 'S-1-5-32-544') {
            throw 'D0_ACE_UNTRUSTED_IDENTITY'
        }
        if ($seen.ContainsKey($sid)) { throw 'D0_ACE_DUPLICATE' }
        $seen[$sid]=$true
        # Compare the documented file FullControl mask numerically. Explicit
        # enum-to-int casts can throw on native WinPS5.1 PowerShell binder.
        if ([int64]$ace.AccessMask -ne 0x001F01FF) {
            throw 'D0_ACE_RIGHTS_DRIFT'
        }
        # 0=no inheritance for Task Scheduler object; OI|CI=3 on directory.
        $expectedFlags = if ($Kind -ceq 'SystemTask') { 0 } else { 3 }
        if ([int64]$ace.AceFlags -ne $expectedFlags) { throw 'D0_ACE_INHERITANCE_DRIFT' }
    }
    if ($seen.Count -ne 2) { throw 'D0_ACE_SET_DRIFT' }
    return $true
}

function Assert-D0SourcePathBoundary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ProgramFilesRoot,
        [Parameter(Mandatory=$true)][string]$CandidateRoot
    )
    if ([string]::IsNullOrWhiteSpace($ProgramFilesRoot) -or
        [string]::IsNullOrWhiteSpace($CandidateRoot)) { throw 'D0_PATH_EMPTY' }
    $base=[IO.Path]::GetFullPath($ProgramFilesRoot).TrimEnd('\')
    $expected=[IO.Path]::Combine($base,'LowcountryDigitalWorks','RedrixD0')
    $actual=[IO.Path]::GetFullPath($CandidateRoot).TrimEnd('\')
    if (-not [string]::Equals($actual,$expected,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'D0_SOURCE_PATH_NOT_FIXED_OS_ROOT'
    }
    $drive=[IO.Path]::GetPathRoot($base)
    if ([string]::IsNullOrEmpty($drive) -or -not $base.StartsWith($drive,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'D0_PATH_VOLUME_REFUSED'
    }
    $cursor=$expected
    while ($true) {
        if (-not (Test-Path -LiteralPath $cursor -PathType Container)) {
            throw 'D0_SOURCE_COMPONENT_ABSENT'
        }
        $entry=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'D0_SOURCE_REPARSE_REFUSED'
        }
        if ([string]::Equals($cursor,$base,[StringComparison]::OrdinalIgnoreCase)) { break }
        $parent=[IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            -not $parent.StartsWith(($base+'\'),[StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::Equals($parent,$base,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'D0_SOURCE_ANCESTOR_ESCAPE'
        }
        $cursor=$parent
    }
    # This is a point-in-time path observation, never a handle-held
    # attacker-race guarantee or authorization for a privileged operation.
    return $true
}

# This root check is an intentionally conservative, point-in-time DACL
# snapshot. It does not hold handles or prove absence of namespace races.
function Assert-D0ProgramFilesRootDescriptor {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Sddl)
    try { $sd=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl) }
    catch { throw 'D0_ROOT_DESCRIPTOR_INVALID' }
    $ti='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $privileged=@('S-1-5-18','S-1-5-32-544',$ti)
    if ($null -eq $sd.Owner -or $privileged -cnotcontains $sd.Owner.Value) {
        throw 'D0_ROOT_OWNER_UNTRUSTED'
    }
    if ($null -eq $sd.Group -or $privileged -cnotcontains $sd.Group.Value) {
        throw 'D0_ROOT_GROUP_UNTRUSTED'
    }
    if (($sd.ControlFlags -band
        [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or
        $null -eq $sd.DiscretionaryAcl -or $sd.DiscretionaryAcl.Count -eq 0) {
        throw 'D0_ROOT_DACL_MISSING_OR_EMPTY'
    }
    # FILE_ADD_FILE | FILE_ADD_SUBDIR | FILE_WRITE_EA | FILE_DELETE_CHILD |
    # FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
    # GENERIC_ALL | GENERIC_WRITE. Even InheritOnly low-trust ACEs
    # are refused: they could affect a newly created unprotected child.
    $danger=[int64]0x500D0156
    $safeReaders=@('S-1-5-32-545','S-1-5-11','S-1-1-0',
        'S-1-15-2-1','S-1-15-2-2')
    foreach($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.IsCallback -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) {
            throw 'D0_ROOT_ACE_TYPE_OR_DENY_REFUSED'
        }
        $sid=$ace.SecurityIdentifier.Value
        if ($sid -ceq 'S-1-3-0') {
            if (([int64]$ace.AceFlags -band 0x08) -eq 0) {
                throw 'D0_ROOT_CREATOR_OWNER_NOT_INHERIT_ONLY'
            }
            continue
        }
        if ($privileged -ccontains $sid) { continue }
        if ($safeReaders -cnotcontains $sid) {
            throw 'D0_ROOT_ACE_UNKNOWN_IDENTITY'
        }
        if (([int64]$ace.AccessMask -band $danger) -ne 0) {
            throw 'D0_ROOT_ACE_DANGEROUS_RIGHTS'
        }
    }
    return $true
}

function Assert-D0SourceAncestorDaclSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RootSddl,
        [Parameter(Mandatory=$true)][string]$IntermediateSddl,
        [Parameter(Mandatory=$true)][string]$LeafSddl
    )
    [void](Assert-D0ProgramFilesRootDescriptor -Sddl $RootSddl)
    try { [void](Assert-D0ExactProtectedDescriptor -Sddl $IntermediateSddl) }
    catch { throw ('D0_INTERMEDIATE_' + $_.Exception.Message) }
    try { [void](Assert-D0ExactProtectedDescriptor -Sddl $LeafSddl) }
    catch { throw ('D0_LEAF_' + $_.Exception.Message) }
    return $true
}

function Assert-D0SourceAncestorDaclChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ProgramFilesRoot,
        [Parameter(Mandatory=$true)][string]$CandidateRoot
    )
    [void](Assert-D0SourcePathBoundary -ProgramFilesRoot $ProgramFilesRoot -CandidateRoot $CandidateRoot)
    $base=[IO.Path]::GetFullPath($ProgramFilesRoot).TrimEnd('\')
    $intermediate=[IO.Path]::Combine($base,'LowcountryDigitalWorks')
    $leaf=[IO.Path]::Combine($intermediate,'RedrixD0')
    # No in-memory hash, owner-writable checkout or caller-provided expected
    # SDDL is trusted as an installer approval. Get-Acl is read-only but
    # pathname-based, and cannot defeat active hostile directory races.
    $baseAcl=Get-Acl -LiteralPath $base -ErrorAction Stop
    $intermediateAcl=Get-Acl -LiteralPath $intermediate -ErrorAction Stop
    $leafAcl=Get-Acl -LiteralPath $leaf -ErrorAction Stop
    return (Assert-D0SourceAncestorDaclSnapshot -RootSddl $baseAcl.Sddl `
        -IntermediateSddl $intermediateAcl.Sddl -LeafSddl $leafAcl.Sddl)
}

function Get-D0FirstInstallSourcePlan {
    [CmdletBinding()]
    param()
    $result=[ordered]@{
        task='LDW-REDRIX-D0-SYSTEM-IDENTITY-ONCE'
        action='READ_ONLY_FIXED_IDENTITY_ONLY'
        execution_principal='SYSTEM'
        task_triggers=0
        source_root='OS_PROGRAM_FILES_FIXED_CHILD'
        source_validation='NOT_ESTABLISHED'
        physical_task_install='NOT_AUTHORIZED_BY_PLAN'
        status='D0_TRUST_ROOT_ABSENT'
    }
    if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
        $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
        $result.status='D0_NATIVE_WINDOWS_POWERSHELL_REQUIRED'
        return [pscustomobject]$result
    }
    $known=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($known)) {
        $result.status='D0_OS_PROGRAM_FILES_UNAVAILABLE'
        return [pscustomobject]$result
    }
    $machine=[Environment]::GetEnvironmentVariable('ProgramFiles','Machine')
    if (-not [string]::IsNullOrWhiteSpace($machine) -and
        -not [string]::Equals([IO.Path]::GetFullPath($known),
            [IO.Path]::GetFullPath($machine),[StringComparison]::OrdinalIgnoreCase)) {
        $result.status='D0_PROGRAM_FILES_MACHINE_MISMATCH'
        return [pscustomobject]$result
    }
    $leaf=[IO.Path]::Combine($known,'LowcountryDigitalWorks','RedrixD0')
    try {
        [void](Assert-D0SourceAncestorDaclChain -ProgramFilesRoot $known -CandidateRoot $leaf)
        $result.source_validation='ANCESTOR_AND_LEAF_DACL_SNAPSHOT_ONLY'
        # No externally accepted signer/pin, no at-create source verification
        # and no trusted source publisher are currently installed. This is
        # intentionally NOT a success/Go signal, even with a perfect ACL.
        $result.status='D0_INDEPENDENT_SOURCE_PIN_ABSENT'
    }
    catch {
        $knownCodes=@('D0_SOURCE_COMPONENT_ABSENT','D0_SOURCE_REPARSE_REFUSED',
          'D0_SOURCE_PATH_NOT_FIXED_OS_ROOT','D0_SOURCE_ANCESTOR_ESCAPE',
          'D0_SOURCE_OWNER_UNTRUSTED','D0_SOURCE_GROUP_UNTRUSTED',
          'D0_DACL_UNPROTECTED_OR_MISSING','D0_DACL_NOT_EXACT_TWO_ACE',
          'D0_ACE_UNTRUSTED_IDENTITY','D0_ACE_TYPE_OR_DENY_REFUSED',
          'D0_ACE_DUPLICATE','D0_ACE_RIGHTS_DRIFT','D0_ACE_INHERITANCE_DRIFT',
          'D0_ACE_SET_DRIFT','D0_DESCRIPTOR_INVALID')
        if ($knownCodes -ccontains $_.Exception.Message) {
            $result.status=$_.Exception.Message
        } else {
            $result.status='D0_SOURCE_INSPECTION_AMBIGUOUS'
        }
    }
    return [pscustomobject]$result
}

Export-ModuleMember -Function Assert-D0ExactProtectedDescriptor,Assert-D0SourcePathBoundary,Assert-D0ProgramFilesRootDescriptor,Assert-D0SourceAncestorDaclSnapshot,Assert-D0SourceAncestorDaclChain,Get-D0FirstInstallSourcePlan
