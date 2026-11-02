#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Plan','Install','Status','Rollback')][string]$Action,
    [string]$PackageDirectory,
    [string]$ExpectedSourceCommit,
    [string]$ExpectedSourceTree,
    [string]$ExpectedManifestSha256,
    [string]$ExpectedExecutableSha256,
    [long]$ExpectedExecutableBytes,
    [string]$ExpectedLegacyExecutableSha256,
    [string]$ExpectedLegacySourceCommit,
    [string]$ExpectedLegacySourceTree,
    [string]$ExpectedRollbackSourceCommit,
    [string]$ExpectedRollbackSourceTree,
    [string]$ExpectedRollbackManifestSha256,
    [string]$ExpectedRollbackExecutableSha256,
    [long]$ExpectedRollbackExecutableBytes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HostAgentWindowsDeployment.psm1') -Force

$constants = Get-HostAgentWindowsDeploymentConstants

function Assert-PackageExpectation {
    param([Parameter(Mandatory)]$Package)
    if ($ExpectedSourceCommit -cnotmatch '^[a-f0-9]{40}$' -or
        $ExpectedSourceTree -cnotmatch '^[a-f0-9]{40}$' -or
        $ExpectedManifestSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $ExpectedExecutableSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $ExpectedExecutableBytes -le 0) {
        throw 'HOST_AGENT_WINDOWS_EXPECTED_PACKAGE_IDENTITY_REQUIRED'
    }
    $expectedManifest = $ExpectedManifestSha256.ToLowerInvariant()
    $expectedExecutable = $ExpectedExecutableSha256.ToLowerInvariant()
    if ($Package.SourceCommit -cne $ExpectedSourceCommit -or
        $Package.SourceTree -cne $ExpectedSourceTree -or
        $Package.ManifestSha256 -cne $expectedManifest -or
        $Package.ExecutableSha256 -cne $expectedExecutable -or
        [int64]$Package.ExecutableBytes -ne $ExpectedExecutableBytes) {
        throw 'HOST_AGENT_WINDOWS_PACKAGE_IDENTITY_MISMATCH'
    }
}

function Assert-RollbackExpectation {
    param([Parameter(Mandatory)]$Rollback)
    if ($ExpectedRollbackSourceCommit -cnotmatch '^[a-f0-9]{40}$' -or
        $ExpectedRollbackSourceTree -cnotmatch '^[a-f0-9]{40}$' -or
        $ExpectedRollbackManifestSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $ExpectedRollbackExecutableSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $ExpectedRollbackExecutableBytes -le 0) {
        throw 'HOST_AGENT_WINDOWS_EXPECTED_ROLLBACK_IDENTITY_REQUIRED'
    }
    $expectedManifest = $ExpectedRollbackManifestSha256.ToLowerInvariant()
    $expectedExecutable = $ExpectedRollbackExecutableSha256.ToLowerInvariant()
    if ($Rollback.SourceCommit -cne $ExpectedRollbackSourceCommit -or
        $Rollback.SourceTree -cne $ExpectedRollbackSourceTree -or
        $Rollback.ManifestSha256 -cne $expectedManifest -or
        $Rollback.ExecutableSha256 -cne $expectedExecutable -or
        [int64]$Rollback.ExecutableBytes -ne $ExpectedRollbackExecutableBytes) {
        throw 'HOST_AGENT_WINDOWS_ROLLBACK_IDENTITY_MISMATCH'
    }
}

function Assert-NoUnexpectedPackageArguments {
    if (-not [string]::IsNullOrWhiteSpace($PackageDirectory) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedSourceTree) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedManifestSha256) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedExecutableSha256) -or
        $ExpectedExecutableBytes -ne 0) {
        throw 'HOST_AGENT_WINDOWS_UNEXPECTED_PACKAGE_ARGUMENT'
    }
}

function Get-LegacyAdoptionIdentity {
    param([Parameter(Mandatory)]$Observation)
    if ($ExpectedLegacyExecutableSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $ExpectedLegacySourceCommit -cnotmatch '^[a-f0-9]{40}$' -or
        $ExpectedLegacySourceTree -cnotmatch '^[a-f0-9]{40}$') {
        throw 'HOST_AGENT_WINDOWS_LEGACY_EXPECTATION_REQUIRED'
    }
    $expectedSha = $ExpectedLegacyExecutableSha256.ToLowerInvariant()
    if ($Observation.ExecutableSha256 -cne $expectedSha) { throw 'HOST_AGENT_WINDOWS_LEGACY_HASH_MISMATCH' }
    [pscustomobject]@{
        ExecutableSha256 = $expectedSha
        ExecutableBytes = [int64]$Observation.ExecutableBytes
        SourceCommit = $ExpectedLegacySourceCommit
        SourceTree = $ExpectedLegacySourceTree
    }
}

function Assert-NoUnexpectedLegacyArguments {
    if (-not [string]::IsNullOrWhiteSpace($ExpectedLegacyExecutableSha256) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedLegacySourceCommit) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedLegacySourceTree)) {
        throw 'HOST_AGENT_WINDOWS_UNEXPECTED_LEGACY_ARGUMENT'
    }
}

function Assert-NoUnexpectedRollbackArguments {
    if (-not [string]::IsNullOrWhiteSpace($ExpectedRollbackSourceCommit) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedRollbackSourceTree) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedRollbackManifestSha256) -or
        -not [string]::IsNullOrWhiteSpace($ExpectedRollbackExecutableSha256) -or
        $ExpectedRollbackExecutableBytes -ne 0) {
        throw 'HOST_AGENT_WINDOWS_UNEXPECTED_ROLLBACK_ARGUMENT'
    }
}

function Assert-ContextEqual {
    param(
        $Expected,
        $Actual,
        [Parameter(Mandatory)][string]$Code
    )
    if (($null -eq $Expected) -ne ($null -eq $Actual)) { throw $Code }
    if ($null -eq $Expected) { return }
    if ($Expected.SourceCommit -cne $Actual.SourceCommit -or
        $Expected.SourceTree -cne $Actual.SourceTree -or
        $Expected.ManifestSha256 -cne $Actual.ManifestSha256 -or
        $Expected.ExecutableSha256 -cne $Actual.ExecutableSha256 -or
        [int64]$Expected.ExecutableBytes -ne [int64]$Actual.ExecutableBytes) {
        throw $Code
    }
}

function Assert-ObservationEqual {
    param(
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)][string]$Code
    )
    if ($Expected.State -cne $Actual.State -or
        $Expected.ExecutableSha256 -cne $Actual.ExecutableSha256 -or
        [int64]($Expected.ExecutableBytes ?? 0) -ne [int64]($Actual.ExecutableBytes ?? 0)) {
        throw $Code
    }
    if ($Expected.State -ceq 'Managed') { Assert-ContextEqual -Expected $Expected.Context -Actual $Actual.Context -Code $Code }
}

function Assert-TransactionDirectoryPath {
    param([Parameter(Mandatory)][string]$Path)
    $root = [IO.Path]::GetFullPath($constants.InstallRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'HOST_AGENT_WINDOWS_TRANSACTION_PATH_REFUSED' }
}

function New-ProtectedTransactionDirectory {
    param([Parameter(Mandatory)][string]$Path)
    Assert-TransactionDirectoryPath -Path $Path
    if (Test-Path -LiteralPath $Path) { throw 'HOST_AGENT_WINDOWS_TRANSACTION_PATH_EXISTS' }
    $null = New-Item -ItemType Directory -Path $Path -ErrorAction Stop
    Assert-HostAgentWindowsProtectedDirectory -Path $Path
}

function Remove-TransactionDirectoryIfSafe {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Assert-TransactionDirectoryPath -Path $Path
    Assert-HostAgentWindowsProtectedDirectory -Path $Path
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}

function Copy-ManagedState {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Destination
    )
    New-ProtectedTransactionDirectory -Path $Destination
    $destExe = Join-Path $Destination $constants.ExecutableName
    $destManifest = Join-Path $Destination $constants.InstalledManifestName
    Copy-Item -LiteralPath $Context.ExecutablePath -Destination $destExe -ErrorAction Stop
    Copy-Item -LiteralPath $Context.ManifestPath -Destination $destManifest -ErrorAction Stop
    return Read-HostAgentWindowsManifest -ManifestPath $destManifest -ExecutablePath $destExe
}

function Copy-LegacyState {
    param(
        [Parameter(Mandatory)]$Identity,
        [Parameter(Mandatory)][string]$Destination
    )
    New-ProtectedTransactionDirectory -Path $Destination
    $destExe = Join-Path $Destination $constants.ExecutableName
    $destManifest = Join-Path $Destination $constants.InstalledManifestName
    Copy-Item -LiteralPath $constants.ExecutablePath -Destination $destExe -ErrorAction Stop
    $manifest = [ordered]@{
        schema = 1
        package = 'ldw-host-agent-windows'
        runtime = 'win-x64'
        source_commit = $Identity.SourceCommit
        source_tree = $Identity.SourceTree
        executable = [ordered]@{
            name = $constants.ExecutableName
            sha256 = $Identity.ExecutableSha256
            bytes = $Identity.ExecutableBytes
        }
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $destManifest -Encoding utf8NoBOM
    $context = Read-HostAgentWindowsManifest -ManifestPath $destManifest -ExecutablePath $destExe
    if ($context.ExecutableSha256 -cne $Identity.ExecutableSha256 -or $context.SourceCommit -cne $Identity.SourceCommit -or $context.SourceTree -cne $Identity.SourceTree) {
        throw 'HOST_AGENT_WINDOWS_LEGACY_ADOPTION_READBACK_FAILED'
    }
    return $context
}

function Restore-ManagedState {
    param([Parameter(Mandatory)][string]$SourceDirectory)
    $source = Read-HostAgentWindowsManifest -ManifestPath (Join-Path $SourceDirectory $constants.InstalledManifestName) -ExecutablePath (Join-Path $SourceDirectory $constants.ExecutableName)
    Assert-HostAgentWindowsSafeFile -Path $constants.ExecutablePath
    Assert-HostAgentWindowsSafeFile -Path $constants.InstalledManifestPath
    Copy-Item -LiteralPath $source.ExecutablePath -Destination $constants.ExecutablePath -Force -ErrorAction Stop
    Copy-Item -LiteralPath $source.ManifestPath -Destination $constants.InstalledManifestPath -Force -ErrorAction Stop
    $restored = Get-HostAgentWindowsInstalledContext
    Assert-ContextEqual -Expected $source -Actual $restored -Code 'HOST_AGENT_WINDOWS_TRANSACTION_RESTORE_FAILED'
}

function Restore-LegacyState {
    param(
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)]$Identity
    )
    $source = Read-HostAgentWindowsManifest -ManifestPath (Join-Path $SourceDirectory $constants.InstalledManifestName) -ExecutablePath (Join-Path $SourceDirectory $constants.ExecutableName)
    if ($source.ExecutableSha256 -cne $Identity.ExecutableSha256) { throw 'HOST_AGENT_WINDOWS_LEGACY_RESTORE_SOURCE_REFUSED' }
    Assert-HostAgentWindowsSafeFile -Path $constants.ExecutablePath
    Assert-HostAgentWindowsSafeFile -Path $constants.InstalledManifestPath
    Copy-Item -LiteralPath $source.ExecutablePath -Destination $constants.ExecutablePath -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $constants.InstalledManifestPath -PathType Leaf) {
        Remove-Item -LiteralPath $constants.InstalledManifestPath -Force -ErrorAction Stop
    }
    $observation = Get-HostAgentWindowsInstalledObservation
    if ($observation.State -cne 'Legacy' -or $observation.ExecutableSha256 -cne $Identity.ExecutableSha256) {
        throw 'HOST_AGENT_WINDOWS_LEGACY_TRANSACTION_RESTORE_FAILED'
    }
}

if ($Action -in @('Plan','Install')) {
    Assert-NoUnexpectedRollbackArguments
    if ([string]::IsNullOrWhiteSpace($PackageDirectory)) { throw 'HOST_AGENT_WINDOWS_PACKAGE_REQUIRED' }
    $package = Get-HostAgentWindowsPackageContext -PackageDirectory $PackageDirectory
    Assert-PackageExpectation -Package $package
} else {
    Assert-NoUnexpectedPackageArguments
    $package = $null
}

if ($Action -eq 'Rollback') {
    Assert-NoUnexpectedLegacyArguments
} elseif ($Action -eq 'Status') {
    Assert-NoUnexpectedLegacyArguments
    Assert-NoUnexpectedRollbackArguments
}

$runningCount = Get-HostAgentWindowsRunningCount
$installedObservation = Get-HostAgentWindowsInstalledObservation
$installed = $installedObservation.Context
$rollback = Get-HostAgentWindowsRollbackContext
$legacyIdentity = $null
if ($installedObservation.State -ceq 'Legacy') {
    if ($Action -in @('Plan','Install')) { $legacyIdentity = Get-LegacyAdoptionIdentity -Observation $installedObservation }
} elseif ($Action -in @('Plan','Install')) {
    Assert-NoUnexpectedLegacyArguments
}

if ($Action -eq 'Rollback') {
    if ($null -eq $rollback) { throw 'HOST_AGENT_WINDOWS_ROLLBACK_UNAVAILABLE' }
    Assert-RollbackExpectation -Rollback $rollback
}

if ($Action -eq 'Status') {
    [pscustomobject]@{
        Action = 'Status'
        InstalledState = $installedObservation.State
        Installed = ($installedObservation.State -ne 'Absent')
        Managed = ($installedObservation.State -ceq 'Managed')
        Legacy = ($installedObservation.State -ceq 'Legacy')
        Running = ($runningCount -gt 0)
        RunningCount = $runningCount
        SourceCommit = if ($null -ne $installed) { $installed.SourceCommit } else { $null }
        SourceTree = if ($null -ne $installed) { $installed.SourceTree } else { $null }
        ManifestSha256 = if ($null -ne $installed) { $installed.ManifestSha256 } else { $null }
        ExecutableSha256 = $installedObservation.ExecutableSha256
        ExecutableBytes = $installedObservation.ExecutableBytes
        RollbackAvailable = ($null -ne $rollback)
        RollbackSourceCommit = if ($null -ne $rollback) { $rollback.SourceCommit } else { $null }
        RollbackSourceTree = if ($null -ne $rollback) { $rollback.SourceTree } else { $null }
        RollbackManifestSha256 = if ($null -ne $rollback) { $rollback.ManifestSha256 } else { $null }
        RollbackExecutableSha256 = if ($null -ne $rollback) { $rollback.ExecutableSha256 } else { $null }
        RollbackExecutableBytes = if ($null -ne $rollback) { $rollback.ExecutableBytes } else { $null }
        MutationPerformed = $false
        IncrementalRuntimeCostUsd = 0
    }
    return
}

if ($Action -eq 'Plan') {
    [pscustomobject]@{
        Action = 'Plan'
        MutationPerformed = $false
        InstallRoot = $constants.InstallRoot
        Running = ($runningCount -gt 0)
        RunningCount = $runningCount
        CurrentState = $installedObservation.State
        CurrentSourceCommit = if ($null -ne $installed) { $installed.SourceCommit } elseif ($null -ne $legacyIdentity) { $legacyIdentity.SourceCommit } else { $null }
        CurrentExecutableSha256 = $installedObservation.ExecutableSha256
        CandidateSourceCommit = $package.SourceCommit
        CandidateSourceTree = $package.SourceTree
        CandidateManifestSha256 = $package.ManifestSha256
        CandidateExecutableSha256 = $package.ExecutableSha256
        CandidateExecutableBytes = $package.ExecutableBytes
        AlreadyInstalled = ($installedObservation.State -ceq 'Managed' -and $installed.SourceCommit -ceq $package.SourceCommit -and $installed.SourceTree -ceq $package.SourceTree -and $installed.ManifestSha256 -ceq $package.ManifestSha256 -and $installed.ExecutableSha256 -ceq $package.ExecutableSha256)
        LegacyAdoptionRequired = ($installedObservation.State -ceq 'Legacy')
        LegacyAdoptionPinned = ($null -ne $legacyIdentity)
        RollbackAvailable = ($null -ne $rollback)
        RequiresElevation = $true
        RequiresTrayStopped = $true
        StartupRegistrationMutation = $false
        IncrementalRuntimeCostUsd = 0
    }
    return
}

Assert-HostAgentWindowsAdministrator
$transactionLock = Enter-HostAgentWindowsTransactionLock -TimeoutMilliseconds 5000
try {
    if ($Action -eq 'Install') {
        Ensure-HostAgentWindowsProtectedInstallRoot
    } else {
        Assert-HostAgentWindowsProtectedInstallRoot -InstallRoot $constants.InstallRoot
    }

    if ((Get-HostAgentWindowsRunningCount) -gt 0) { throw 'HOST_AGENT_WINDOWS_RUNNING_REFUSED' }

    if ($Action -eq 'Install') {
        $freshPackage = Get-HostAgentWindowsPackageContext -PackageDirectory $PackageDirectory
        Assert-PackageExpectation -Package $freshPackage
        Assert-ContextEqual -Expected $package -Actual $freshPackage -Code 'HOST_AGENT_WINDOWS_PACKAGE_CHANGED'
        $package = $freshPackage
    }

    $freshObservation = Get-HostAgentWindowsInstalledObservation
    Assert-ObservationEqual -Expected $installedObservation -Actual $freshObservation -Code 'HOST_AGENT_WINDOWS_STATE_CHANGED'
    $freshRollback = Get-HostAgentWindowsRollbackContext
    Assert-ContextEqual -Expected $rollback -Actual $freshRollback -Code 'HOST_AGENT_WINDOWS_ROLLBACK_STATE_CHANGED'
    $installedObservation = $freshObservation
    $installed = $freshObservation.Context
    $rollback = $freshRollback

    if ($Action -eq 'Rollback') { Assert-RollbackExpectation -Rollback $rollback }

    if ($Action -eq 'Install') {
        if ($installedObservation.State -ceq 'Managed' -and
            $installed.SourceCommit -ceq $package.SourceCommit -and
            $installed.SourceTree -ceq $package.SourceTree -and
            $installed.ManifestSha256 -ceq $package.ManifestSha256 -and
            $installed.ExecutableSha256 -ceq $package.ExecutableSha256) {
            [pscustomobject]@{
                Action = 'Install'; Installed = $true; AlreadyInstalled = $true; MutationPerformed = $false
                SourceCommit = $installed.SourceCommit; SourceTree = $installed.SourceTree; ManifestSha256 = $installed.ManifestSha256
                ExecutableSha256 = $installed.ExecutableSha256; ExecutableBytes = $installed.ExecutableBytes
                RollbackAvailable = ($null -ne $rollback); IncrementalRuntimeCostUsd = 0
            }
            return
        }

        $token = [guid]::NewGuid().ToString('N')
        $stage = Join-Path $constants.InstallRoot ('.stage-' + $token)
        $previous = Join-Path $constants.InstallRoot ('.previous-' + $token)
        $rollbackOld = Join-Path $constants.InstallRoot ('.rollback-old-' + $token)
        $failedNewRollback = Join-Path $constants.InstallRoot ('.failed-new-rollback-' + $token)
        $previousMovedToRollback = $false
        $rollbackMovedAside = $false
        $previousContext = $null
        $installError = $null
        $transactionCommitted = $false
        $recoveryProven = $false

        try {
            New-ProtectedTransactionDirectory -Path $stage
            Copy-Item -LiteralPath $package.ExecutablePath -Destination (Join-Path $stage $constants.ExecutableName) -ErrorAction Stop
            Copy-Item -LiteralPath $package.ManifestPath -Destination (Join-Path $stage $constants.InstalledManifestName) -ErrorAction Stop
            $staged = Read-HostAgentWindowsManifest -ManifestPath (Join-Path $stage $constants.InstalledManifestName) -ExecutablePath (Join-Path $stage $constants.ExecutableName)
            Assert-ContextEqual -Expected $package -Actual $staged -Code 'HOST_AGENT_WINDOWS_STAGE_MISMATCH'
            Assert-PackageExpectation -Package $staged

            switch ($installedObservation.State) {
                'Managed' { $previousContext = Copy-ManagedState -Context $installed -Destination $previous }
                'Legacy' { $previousContext = Copy-LegacyState -Identity $legacyIdentity -Destination $previous }
            }

            if ((Get-HostAgentWindowsRunningCount) -gt 0) { throw 'HOST_AGENT_WINDOWS_RUNNING_REFUSED' }
            Assert-HostAgentWindowsSafeFile -Path $constants.ExecutablePath
            Assert-HostAgentWindowsSafeFile -Path $constants.InstalledManifestPath
            Copy-Item -LiteralPath $staged.ExecutablePath -Destination $constants.ExecutablePath -Force -ErrorAction Stop
            Copy-Item -LiteralPath $staged.ManifestPath -Destination $constants.InstalledManifestPath -Force -ErrorAction Stop
            $verified = Get-HostAgentWindowsInstalledContext
            Assert-ContextEqual -Expected $package -Actual $verified -Code 'HOST_AGENT_WINDOWS_INSTALL_READBACK_FAILED'

            if ($installedObservation.State -ne 'Absent') {
                if (Test-Path -LiteralPath $constants.RollbackRoot) {
                    Move-Item -LiteralPath $constants.RollbackRoot -Destination $rollbackOld -ErrorAction Stop
                    $rollbackMovedAside = $true
                    Assert-HostAgentWindowsProtectedDirectory -Path $rollbackOld
                }
                Move-Item -LiteralPath $previous -Destination $constants.RollbackRoot -ErrorAction Stop
                $previousMovedToRollback = $true
                $newRollback = Get-HostAgentWindowsRollbackContext
                Assert-ContextEqual -Expected $previousContext -Actual $newRollback -Code 'HOST_AGENT_WINDOWS_ROLLBACK_READBACK_FAILED'
                if ($rollbackMovedAside) { Remove-TransactionDirectoryIfSafe -Path $rollbackOld }
            }

            $transactionCommitted = $true
            [pscustomobject]@{
                Action = 'Install'; Installed = $true; AlreadyInstalled = $false; MutationPerformed = $true
                SourceCommit = $verified.SourceCommit; SourceTree = $verified.SourceTree; ManifestSha256 = $verified.ManifestSha256
                ExecutableSha256 = $verified.ExecutableSha256; ExecutableBytes = $verified.ExecutableBytes
                RollbackAvailable = ($installedObservation.State -ne 'Absent')
                RollbackSourceCommit = if ($null -ne $previousContext) { $previousContext.SourceCommit } else { $null }
                RollbackSourceTree = if ($null -ne $previousContext) { $previousContext.SourceTree } else { $null }
                RollbackManifestSha256 = if ($null -ne $previousContext) { $previousContext.ManifestSha256 } else { $null }
                RollbackExecutableSha256 = if ($null -ne $previousContext) { $previousContext.ExecutableSha256 } else { $null }
                RollbackExecutableBytes = if ($null -ne $previousContext) { $previousContext.ExecutableBytes } else { $null }
                AdoptedLegacy = ($installedObservation.State -ceq 'Legacy'); StartupRegistrationMutation = $false; IncrementalRuntimeCostUsd = 0
            }
            return
        } catch {
            $installError = $_
            try {
                $restoreSource = if (Test-Path -LiteralPath $previous -PathType Container) { $previous } elseif ($previousMovedToRollback -and (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container)) { $constants.RollbackRoot } else { $null }
                if ($installedObservation.State -ceq 'Managed' -and $null -ne $restoreSource) {
                    Restore-ManagedState -SourceDirectory $restoreSource
                } elseif ($installedObservation.State -ceq 'Legacy' -and $null -ne $restoreSource) {
                    Restore-LegacyState -SourceDirectory $restoreSource -Identity $legacyIdentity
                } elseif ($installedObservation.State -ceq 'Absent') {
                    foreach ($managed in @($constants.ExecutablePath,$constants.InstalledManifestPath)) {
                        Assert-HostAgentWindowsSafeFile -Path $managed
                        if (Test-Path -LiteralPath $managed -PathType Leaf) { Remove-Item -LiteralPath $managed -Force -ErrorAction Stop }
                    }
                    $absent = Get-HostAgentWindowsInstalledObservation
                    if ($absent.State -cne 'Absent') { throw 'HOST_AGENT_WINDOWS_ABSENT_TRANSACTION_RESTORE_FAILED' }
                }

                if ($rollbackMovedAside -and (Test-Path -LiteralPath $rollbackOld -PathType Container)) {
                    if (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container) {
                        Move-Item -LiteralPath $constants.RollbackRoot -Destination $failedNewRollback -ErrorAction Stop
                        Assert-HostAgentWindowsProtectedDirectory -Path $failedNewRollback
                    }
                    Move-Item -LiteralPath $rollbackOld -Destination $constants.RollbackRoot -ErrorAction Stop
                    $restoredRollback = Get-HostAgentWindowsRollbackContext
                    Assert-ContextEqual -Expected $rollback -Actual $restoredRollback -Code 'HOST_AGENT_WINDOWS_ROLLBACK_STATE_RESTORE_FAILED'
                } elseif ($null -eq $rollback -and (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container)) {
                    Move-Item -LiteralPath $constants.RollbackRoot -Destination $failedNewRollback -ErrorAction Stop
                    Assert-HostAgentWindowsProtectedDirectory -Path $failedNewRollback
                    if ($null -ne (Get-HostAgentWindowsRollbackContext)) { throw 'HOST_AGENT_WINDOWS_ROLLBACK_STATE_RESTORE_FAILED' }
                } else {
                    Assert-ContextEqual -Expected $rollback -Actual (Get-HostAgentWindowsRollbackContext) -Code 'HOST_AGENT_WINDOWS_ROLLBACK_STATE_RESTORE_FAILED'
                }
                $recoveryProven = $true
            } catch {
                throw 'HOST_AGENT_WINDOWS_INSTALL_ROLLBACK_FAILED'
            }
            throw $installError
        } finally {
            if ($transactionCommitted -or $recoveryProven) {
                foreach ($path in @($stage,$previous,$rollbackOld,$failedNewRollback)) {
                    if (Test-Path -LiteralPath $path) { Remove-TransactionDirectoryIfSafe -Path $path }
                }
            }
        }
    }

    if ($Action -eq 'Rollback') {
        if ($installedObservation.State -cne 'Managed') { throw 'HOST_AGENT_WINDOWS_MANAGED_INSTALL_REQUIRED' }
        if ($null -eq $rollback) { throw 'HOST_AGENT_WINDOWS_ROLLBACK_UNAVAILABLE' }
        Assert-RollbackExpectation -Rollback $rollback

        $token = [guid]::NewGuid().ToString('N')
        $currentBackup = Join-Path $constants.InstallRoot ('.current-' + $token)
        $rollbackOld = Join-Path $constants.InstallRoot ('.rollback-old-' + $token)
        $failedNewRollback = Join-Path $constants.InstallRoot ('.failed-new-rollback-' + $token)
        $transactionCommitted = $false
        $recoveryProven = $false
        try {
            $null = Copy-ManagedState -Context $installed -Destination $currentBackup
            if ((Get-HostAgentWindowsRunningCount) -gt 0) { throw 'HOST_AGENT_WINDOWS_RUNNING_REFUSED' }
            Assert-HostAgentWindowsSafeFile -Path $constants.ExecutablePath
            Assert-HostAgentWindowsSafeFile -Path $constants.InstalledManifestPath
            Copy-Item -LiteralPath $rollback.ExecutablePath -Destination $constants.ExecutablePath -Force -ErrorAction Stop
            Copy-Item -LiteralPath $rollback.ManifestPath -Destination $constants.InstalledManifestPath -Force -ErrorAction Stop
            $verified = Get-HostAgentWindowsInstalledContext
            Assert-ContextEqual -Expected $rollback -Actual $verified -Code 'HOST_AGENT_WINDOWS_ROLLBACK_ACTIVATION_FAILED'

            Move-Item -LiteralPath $constants.RollbackRoot -Destination $rollbackOld -ErrorAction Stop
            Assert-HostAgentWindowsProtectedDirectory -Path $rollbackOld
            Move-Item -LiteralPath $currentBackup -Destination $constants.RollbackRoot -ErrorAction Stop
            $newRollback = Get-HostAgentWindowsRollbackContext
            Assert-ContextEqual -Expected $installed -Actual $newRollback -Code 'HOST_AGENT_WINDOWS_ROLLBACK_SWAP_FAILED'
            Remove-TransactionDirectoryIfSafe -Path $rollbackOld

            $transactionCommitted = $true
            [pscustomobject]@{
                Action = 'Rollback'; Installed = $true; MutationPerformed = $true
                SourceCommit = $verified.SourceCommit; SourceTree = $verified.SourceTree; ManifestSha256 = $verified.ManifestSha256
                ExecutableSha256 = $verified.ExecutableSha256; ExecutableBytes = $verified.ExecutableBytes
                RollbackAvailable = $true; RollbackSourceCommit = $newRollback.SourceCommit; RollbackSourceTree = $newRollback.SourceTree
                RollbackManifestSha256 = $newRollback.ManifestSha256; RollbackExecutableSha256 = $newRollback.ExecutableSha256
                RollbackExecutableBytes = $newRollback.ExecutableBytes; StartupRegistrationMutation = $false
                IncrementalRuntimeCostUsd = 0
            }
            return
        } catch {
            $rollbackError = $_
            try {
                $restoreSource = if (Test-Path -LiteralPath $currentBackup -PathType Container) { $currentBackup } elseif (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container) { $constants.RollbackRoot } else { $null }
                if ($null -eq $restoreSource) { throw 'HOST_AGENT_WINDOWS_ROLLBACK_RECOVERY_SOURCE_MISSING' }
                Restore-ManagedState -SourceDirectory $restoreSource
                if (Test-Path -LiteralPath $rollbackOld -PathType Container) {
                    if (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container) {
                        Move-Item -LiteralPath $constants.RollbackRoot -Destination $failedNewRollback -ErrorAction Stop
                        Assert-HostAgentWindowsProtectedDirectory -Path $failedNewRollback
                    }
                    Move-Item -LiteralPath $rollbackOld -Destination $constants.RollbackRoot -ErrorAction Stop
                }
                $restoredRollback = Get-HostAgentWindowsRollbackContext
                Assert-ContextEqual -Expected $rollback -Actual $restoredRollback -Code 'HOST_AGENT_WINDOWS_ROLLBACK_STATE_RESTORE_FAILED'
                $recoveryProven = $true
            } catch {
                throw 'HOST_AGENT_WINDOWS_ROLLBACK_RECOVERY_FAILED'
            }
            throw $rollbackError
        } finally {
            if ($transactionCommitted -or $recoveryProven) {
                foreach ($path in @($currentBackup,$rollbackOld,$failedNewRollback)) {
                    if (Test-Path -LiteralPath $path) { Remove-TransactionDirectoryIfSafe -Path $path }
                }
            }
        }
    }
} finally {
    $transactionLock.Dispose()
}
