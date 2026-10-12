[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PublishedDirectory,

    [Parameter(Mandatory)]
    [string]$PermittedCallerSid
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'HyperVObserverDeployment.psm1') -Force
Assert-HyperVObserverSafeExplicitUserSid -Sid $PermittedCallerSid
$manifest = Test-HyperVObserverDeploymentManifest -Directory $PublishedDirectory
$constants = Get-HyperVObserverDeploymentConstants
$releaseRoot = Join-Path $constants.ReleasesRoot $manifest.ReleaseId
$installedExe = Join-Path $releaseRoot 'LDW.HostAgent.HyperVObserver.exe'
$spec = Get-HyperVObserverTaskSpec -InstalledExe $installedExe -ConfigPath $constants.ConfigPath

[pscustomobject]@{
    MutationPerformed = $false
    ReleaseId = $manifest.ReleaseId
    InstallRoot = $constants.InstallRoot
    ConfigRoot = $constants.ConfigRoot
    TaskName = $spec.TaskName
    TaskPath = $spec.TaskPath
    Principal = $spec.UserId
    RunLevel = $spec.RunLevel
    Trigger = 'AtStartup'
    Hidden = $spec.Hidden
    RestartCount = $spec.RestartCount
    RestartIntervalSeconds = $spec.RestartIntervalSeconds
    PermittedCallerSidValidated = $true
    IncrementalRuntimeCostUsd = 0
}
