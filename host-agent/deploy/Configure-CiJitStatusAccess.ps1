[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')][string]$PermittedReaderSid
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'CI_JIT_STATUS_ACCESS_WINDOWS_ONLY' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'CI_JIT_STATUS_ACCESS_ELEVATION_REQUIRED' }
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$module = Join-Path $repo 'ci-dispatch/StatusProjection.psm1'
if (-not (Test-Path -LiteralPath $module -PathType Leaf)) { throw 'CI_JIT_STATUS_MODULE_REQUIRED' }
if ($PSCmdlet.ShouldProcess('fixed LDW CI/JIT status projection', 'grant read-only Host Agent SID access')) {
    Import-Module $module -Force
    Set-Ci10StatusReaderAcl -ReaderSid $PermittedReaderSid
    'CI_JIT_STATUS_READER_ACL=PASS'
}
