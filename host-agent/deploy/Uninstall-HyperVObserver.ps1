[CmdletBinding()]
param(
    [string]$TaskName = 'LDW Host Agent Hyper-V Observer',
    [string]$InstallRoot = "$env:ProgramFiles\LowcountryDigitalWorks\HostAgent\HyperVObserver",
    [string]$ConfigRoot = "$env:ProgramData\LowcountryDigitalWorks\HostAgent"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This rollback script must run from an elevated PowerShell session.'
    }
}

Assert-Elevated

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    try {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    finally {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

$configPath = Join-Path $ConfigRoot 'hyperv-observer.Local.json'
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    Remove-Item -LiteralPath $configPath -Force
}

if (Test-Path -LiteralPath $InstallRoot -PathType Container) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}

[pscustomobject]@{
    TaskRemoved = -not [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    HelperInstallRootRemoved = -not (Test-Path -LiteralPath $InstallRoot)
    HelperConfigRemoved = -not (Test-Path -LiteralPath $configPath)
    NormalizedSshTrustTouched = $false
}
