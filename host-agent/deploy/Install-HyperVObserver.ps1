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
Assert-HyperVObserverElevated
Assert-HyperVObserverSafeExplicitUserSid -Sid $PermittedCallerSid
$manifest = Test-HyperVObserverDeploymentManifest -Directory $PublishedDirectory
$constants = Get-HyperVObserverDeploymentConstants
$releaseRoot = Join-Path $constants.ReleasesRoot $manifest.ReleaseId
$installedExe = Join-Path $releaseRoot 'LDW.HostAgent.HyperVObserver.exe'
$spec = Get-HyperVObserverTaskSpec -InstalledExe $installedExe -ConfigPath $constants.ConfigPath

$existingState = Read-HyperVObserverDeploymentState
$existingTask = Get-HyperVObserverScheduledTask
if ($null -ne $existingState) {
    $context = Get-HyperVObserverValidatedContext
    $configuredSid = Get-HyperVObserverConfiguredSid
    if (-not [string]::Equals([string]$existingState.releaseId, $manifest.ReleaseId, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($configuredSid, $PermittedCallerSid, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'A different managed deployment is already installed. Run the reviewed uninstall/rollback before changing release or caller authorization.'
    }

    [pscustomobject]@{
        Installed = $true
        AlreadyInstalled = $true
        ReleaseId = [string]$existingState.releaseId
        TaskName = $constants.TaskName
        TaskPath = $constants.TaskPath
        TaskState = [string]$context.Task.State
        TaskIdentityValidated = $true
        ProtectedStateValidated = $true
        IncrementalRuntimeCostUsd = 0
    }
    return
}

if ($null -ne $existingTask -or
    (Test-Path -LiteralPath $constants.InstallRoot) -or
    (Test-Path -LiteralPath $constants.ConfigRoot)) {
    throw 'Managed task/files exist without a valid deployment state. Fail closed and reconcile the partial/drifted deployment before installing.'
}

$registeredHere = $false
$tempReleaseRoot = $null
try {
    New-Item -ItemType Directory -Path $constants.InstallRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $constants.ReleasesRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $constants.ConfigRoot -Force | Out-Null
    Set-HyperVObserverProtectedDirectoryAcl -Path $constants.InstallRoot
    Set-HyperVObserverProtectedDirectoryAcl -Path $constants.ReleasesRoot
    Set-HyperVObserverProtectedDirectoryAcl -Path $constants.ConfigRoot

    $tempReleaseRoot = Join-Path $constants.ReleasesRoot ('.staging-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempReleaseRoot | Out-Null
    Set-HyperVObserverProtectedDirectoryAcl -Path $tempReleaseRoot

    foreach ($entry in $manifest.Entries) {
        $source = Join-Path $PublishedDirectory ([string]$entry.name)
        $destination = Join-Path $tempReleaseRoot ([string]$entry.name)
        Copy-Item -LiteralPath $source -Destination $destination
        Set-HyperVObserverProtectedFileAcl -Path $destination
    }

    $sourceManifest = Join-Path $PublishedDirectory $constants.ManifestFileName
    $stagedManifest = Join-Path $tempReleaseRoot $constants.ManifestFileName
    Copy-Item -LiteralPath $sourceManifest -Destination $stagedManifest
    Set-HyperVObserverProtectedFileAcl -Path $stagedManifest

    $staged = Test-HyperVObserverDeploymentManifest -Directory $tempReleaseRoot
    if (-not [string]::Equals($staged.ReleaseFingerprintSha256, $manifest.ReleaseFingerprintSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Protected staging verification does not match the published source manifest.'
    }

    Move-Item -LiteralPath $tempReleaseRoot -Destination $releaseRoot
    $tempReleaseRoot = $null
    Set-HyperVObserverProtectedDirectoryAcl -Path $releaseRoot
    foreach ($entry in $manifest.Entries) {
        Set-HyperVObserverProtectedFileAcl -Path (Join-Path $releaseRoot ([string]$entry.name))
    }
    Set-HyperVObserverProtectedFileAcl -Path (Join-Path $releaseRoot $constants.ManifestFileName)

    $config = [ordered]@{ permittedCallerSids = @($PermittedCallerSid) }
    Write-HyperVObserverProtectedJson -Path $constants.ConfigPath -Value $config

    $state = [ordered]@{
        schemaVersion = 1
        releaseId = $manifest.ReleaseId
        releaseFingerprintSha256 = $manifest.ReleaseFingerprintSha256
        installedExe = $installedExe
        configPath = $constants.ConfigPath
        taskName = $constants.TaskName
        taskPath = $constants.TaskPath
    }
    Write-HyperVObserverProtectedJson -Path $constants.StatePath -Value $state

    $action = New-ScheduledTaskAction -Execute $spec.Execute -Argument $spec.Arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $spec.UserId -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -Hidden `
        -StartWhenAvailable `
        -RestartCount $spec.RestartCount `
        -RestartInterval (New-TimeSpan -Seconds $spec.RestartIntervalSeconds) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskPath $spec.TaskPath `
        -TaskName $spec.TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description $spec.Description | Out-Null
    $registeredHere = $true

    $registered = Get-HyperVObserverScheduledTask
    Assert-HyperVObserverTaskIdentity -Task $registered -Spec $spec
    Start-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 500
        $registered = Get-HyperVObserverScheduledTask
        if ($registered.State -eq 'Running') { break }
    } while ([DateTime]::UtcNow -lt $deadline)

    if ($registered.State -ne 'Running') {
        throw 'Managed Scheduled Task did not remain Running. Inspect Task Scheduler/App Control logs; do not weaken security policy.'
    }

    $context = Get-HyperVObserverValidatedContext
    [pscustomobject]@{
        Installed = $true
        AlreadyInstalled = $false
        ReleaseId = $manifest.ReleaseId
        TaskName = $constants.TaskName
        TaskPath = $constants.TaskPath
        TaskState = [string]$context.Task.State
        TaskIdentityValidated = $true
        ProtectedStateValidated = $true
        IncrementalRuntimeCostUsd = 0
    }
}
catch {
    $installError = $_
    if ($registeredHere) {
        try {
            $task = Get-HyperVObserverScheduledTask
            if ($null -ne $task) {
                Assert-HyperVObserverTaskIdentity -Task $task -Spec $spec
                Stop-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskPath $spec.TaskPath -TaskName $spec.TaskName -Confirm:$false
            }
        }
        catch {
            throw "Install failed and automatic rollback could not prove exact task ownership. Original error: $($installError.Exception.Message) Rollback error: $($_.Exception.Message)"
        }
    }

    foreach ($path in @($constants.StatePath, $constants.ConfigPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    if ($null -ne $tempReleaseRoot -and (Test-Path -LiteralPath $tempReleaseRoot -PathType Container)) {
        Remove-Item -LiteralPath $tempReleaseRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $releaseRoot -PathType Container) {
        Remove-Item -LiteralPath $releaseRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $constants.ConfigRoot -PathType Container) {
        Remove-Item -LiteralPath $constants.ConfigRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $constants.InstallRoot -PathType Container) {
        Remove-Item -LiteralPath $constants.InstallRoot -Recurse -Force
    }

    throw $installError
}
