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
        [void](Assert-D0SourcePathBoundary -ProgramFilesRoot $known -CandidateRoot $leaf)
        $acl=Get-Acl -LiteralPath $leaf -ErrorAction Stop
        [void](Assert-D0ExactProtectedDescriptor -Sddl $acl.Sddl -Kind StagingDirectory)
        $result.source_validation='DIRECTORY_DACL_SNAPSHOT_ONLY'
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

Export-ModuleMember -Function Assert-D0ExactProtectedDescriptor,Assert-D0SourcePathBoundary,Get-D0FirstInstallSourcePlan
