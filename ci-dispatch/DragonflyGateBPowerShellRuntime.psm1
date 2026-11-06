# Synthetic-safe local runtime capability guard for the approved one-shot
# Dragonfly GitHub provider entrypoint. NOT a trust, credential, JIT,
# source-provenance, privileged-publication or owner-authorization gate.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-LdwDragonflyProviderShellContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Major,
        [Parameter(Mandatory)][string]$Edition,
        [Parameter(Mandatory)][bool]$Windows,
        [Parameter(Mandatory)][bool]$HasArgumentList
    )
    # The immutable V2 provider entrypoint uses ProcessStartInfo.ArgumentList,
    # which does not exist on Windows PowerShell 5.1 / .NET Framework.
    return ($Major -ge 7 -and $Edition -ceq 'Core' -and
            $Windows -and $HasArgumentList)
}

function Assert-LdwDragonflyProviderShell {
    [CmdletBinding()]
    param()
    $major = [int]$PSVersionTable.PSVersion.Major
    $edition = [string]$PSVersionTable.PSEdition
    $windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    # Reflection is safe even on Windows PowerShell 5.1, where this property
    # is unavailable. Never start a process or inspect environment secrets.
    $hasArgumentList = $null -ne [Diagnostics.ProcessStartInfo].GetProperty('ArgumentList')
    if (-not (Test-LdwDragonflyProviderShellContract -Major $major -Edition $edition -Windows $windows -HasArgumentList $hasArgumentList)) {
        throw 'DRAGONFLY_GATEB_PWSH7_REQUIRED'
    }
    'DRAGONFLY_GATEB_PWSH7_RUNTIME=PASS_LOCAL_ONLY'
}

Export-ModuleMember -Function Assert-LdwDragonflyProviderShell
