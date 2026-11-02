#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PackageName = 'ldw-host-agent-windows'
$script:Runtime = 'win-x64'
$script:ExecutableName = 'LDW.HostAgent.Windows.exe'
$script:PackageManifestName = 'manifest.json'
$script:InstalledManifestName = 'deployment-manifest.json'
$script:RollbackDirectoryName = 'rollback'
$script:ProductRoot = Join-Path $env:ProgramFiles 'LowcountryDigitalWorks'
$script:HostAgentRoot = Join-Path $script:ProductRoot 'HostAgent'
$script:InstallRoot = Join-Path $script:HostAgentRoot 'Windows'
$script:TransactionLockPath = Join-Path $env:ProgramFiles '.ldw-host-agent-windows-deployment.lock'

function Get-HostAgentWindowsDeploymentConstants {
    [pscustomobject]@{
        PackageName = $script:PackageName
        Runtime = $script:Runtime
        ExecutableName = $script:ExecutableName
        PackageManifestName = $script:PackageManifestName
        InstalledManifestName = $script:InstalledManifestName
        ProductRoot = [IO.Path]::GetFullPath($script:ProductRoot)
        HostAgentRoot = [IO.Path]::GetFullPath($script:HostAgentRoot)
        InstallRoot = [IO.Path]::GetFullPath($script:InstallRoot)
        ExecutablePath = [IO.Path]::GetFullPath((Join-Path $script:InstallRoot $script:ExecutableName))
        InstalledManifestPath = [IO.Path]::GetFullPath((Join-Path $script:InstallRoot $script:InstalledManifestName))
        RollbackRoot = [IO.Path]::GetFullPath((Join-Path $script:InstallRoot $script:RollbackDirectoryName))
        TransactionLockPath = [IO.Path]::GetFullPath($script:TransactionLockPath)
    }
}

function Assert-HostAgentWindowsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'HOST_AGENT_WINDOWS_ELEVATED_INSTALL_REQUIRED'
    }
}

function Assert-HostAgentWindowsNotReparse {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'HOST_AGENT_WINDOWS_REPARSE_REFUSED'
    }
}

function Get-HostAgentWindowsMutationWriteMask {
    return [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
}

function Assert-HostAgentWindowsNoBroadMutationAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545')
    $writeMask = Get-HostAgentWindowsMutationWriteMask
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = try { $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
        if ($sid -in $broadSids -and (($rule.FileSystemRights -band $writeMask) -ne 0)) {
            throw 'HOST_AGENT_WINDOWS_INSTALL_ACL_REFUSED'
        }
    }
}

function Assert-HostAgentWindowsSafeFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'HOST_AGENT_WINDOWS_FILE_TYPE_REFUSED' }
    Assert-HostAgentWindowsNotReparse -Path $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $linkType = $item.PSObject.Properties['LinkType']
    if ($null -ne $linkType -and [string]$linkType.Value -ceq 'HardLink') {
        throw 'HOST_AGENT_WINDOWS_HARDLINK_REFUSED'
    }
    Assert-HostAgentWindowsNoBroadMutationAcl -Path $Path
}

function Assert-HostAgentWindowsProtectedDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw 'HOST_AGENT_WINDOWS_PROTECTED_DIRECTORY_MISSING' }
    Assert-HostAgentWindowsNotReparse -Path $Path
    Assert-HostAgentWindowsNoBroadMutationAcl -Path $Path
}

function Assert-HostAgentWindowsProtectedPathChain {
    param([Parameter(Mandatory)][string]$TargetPath)
    $programFiles = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $target = [IO.Path]::GetFullPath($TargetPath).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $prefix = $programFiles + [IO.Path]::DirectorySeparatorChar
    if ($target -cne $programFiles -and -not $target.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'HOST_AGENT_WINDOWS_INSTALL_ROOT_REFUSED'
    }
    Assert-HostAgentWindowsProtectedDirectory -Path $programFiles
    if ($target -ceq $programFiles) { return }
    $relative = $target.Substring($prefix.Length)
    $cursor = $programFiles
    foreach ($segment in $relative.Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)) {
        $cursor = Join-Path $cursor $segment
        if (Test-Path -LiteralPath $cursor) {
            if (-not (Test-Path -LiteralPath $cursor -PathType Container)) { throw 'HOST_AGENT_WINDOWS_PROTECTED_DIRECTORY_TYPE_REFUSED' }
            Assert-HostAgentWindowsProtectedDirectory -Path $cursor
        }
    }
}

function Assert-HostAgentWindowsProtectedInstallRoot {
    param([Parameter(Mandatory)][string]$InstallRoot)
    $expected = [IO.Path]::GetFullPath($script:InstallRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $actual = [IO.Path]::GetFullPath($InstallRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($actual -cne $expected) { throw 'HOST_AGENT_WINDOWS_INSTALL_ROOT_REFUSED' }
    Assert-HostAgentWindowsProtectedPathChain -TargetPath $actual
    if (-not (Test-Path -LiteralPath $actual -PathType Container)) { throw 'HOST_AGENT_WINDOWS_PROTECTED_DIRECTORY_MISSING' }
    Assert-HostAgentWindowsProtectedDirectory -Path $actual
}

function Ensure-HostAgentWindowsProtectedInstallRoot {
    $constants = Get-HostAgentWindowsDeploymentConstants
    Assert-HostAgentWindowsProtectedPathChain -TargetPath $constants.InstallRoot
    $programFiles = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $relative = $constants.InstallRoot.Substring(($programFiles + [IO.Path]::DirectorySeparatorChar).Length)
    $cursor = $programFiles
    foreach ($segment in $relative.Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)) {
        $cursor = Join-Path $cursor $segment
        if (-not (Test-Path -LiteralPath $cursor)) {
            $null = New-Item -ItemType Directory -Path $cursor -ErrorAction Stop
        }
        Assert-HostAgentWindowsProtectedDirectory -Path $cursor
    }
    Assert-HostAgentWindowsProtectedInstallRoot -InstallRoot $constants.InstallRoot
}

function Enter-HostAgentWindowsTransactionLock {
    param([ValidateRange(100,30000)][int]$TimeoutMilliseconds = 5000)
    $constants = Get-HostAgentWindowsDeploymentConstants
    $programFiles = [IO.Path]::GetFullPath($env:ProgramFiles)
    Assert-HostAgentWindowsProtectedDirectory -Path $programFiles
    if (Test-Path -LiteralPath $constants.TransactionLockPath) {
        Assert-HostAgentWindowsSafeFile -Path $constants.TransactionLockPath
    }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        try {
            $stream = [IO.File]::Open($constants.TransactionLockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            try { Assert-HostAgentWindowsSafeFile -Path $constants.TransactionLockPath }
            catch { $stream.Dispose(); throw }
            return $stream
        } catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'HOST_AGENT_WINDOWS_TRANSACTION_BUSY' }
            Start-Sleep -Milliseconds 100
        }
    } while ($true)
}

function Assert-HostAgentWindowsExactProperties {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$Code
    )
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) { throw $Code }
}

function Read-HostAgentWindowsManifest {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$ExecutablePath
    )
    Assert-HostAgentWindowsSafeFile -Path $ManifestPath
    Assert-HostAgentWindowsSafeFile -Path $ExecutablePath
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        throw 'HOST_AGENT_WINDOWS_MANAGED_FILE_MISSING'
    }
    $manifestItem = Get-Item -LiteralPath $ManifestPath -Force
    if ($manifestItem.Length -le 0 -or $manifestItem.Length -gt 65536) { throw 'HOST_AGENT_WINDOWS_MANIFEST_SIZE_REFUSED' }
    try { $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'HOST_AGENT_WINDOWS_MANIFEST_PARSE_REFUSED' }
    Assert-HostAgentWindowsExactProperties -Object $manifest -Names @('schema','package','runtime','source_commit','source_tree','executable') -Code 'HOST_AGENT_WINDOWS_MANIFEST_SHAPE_REFUSED'
    Assert-HostAgentWindowsExactProperties -Object $manifest.executable -Names @('name','sha256','bytes') -Code 'HOST_AGENT_WINDOWS_MANIFEST_EXECUTABLE_SHAPE_REFUSED'
    if ([int]$manifest.schema -ne 1 -or [string]$manifest.package -cne $script:PackageName -or [string]$manifest.runtime -cne $script:Runtime) {
        throw 'HOST_AGENT_WINDOWS_MANIFEST_IDENTITY_REFUSED'
    }
    if ([string]$manifest.source_commit -cnotmatch '^[a-f0-9]{40}$' -or [string]$manifest.source_tree -cnotmatch '^[a-f0-9]{40}$') {
        throw 'HOST_AGENT_WINDOWS_SOURCE_IDENTITY_REFUSED'
    }
    if ([string]$manifest.executable.name -cne $script:ExecutableName -or [string]$manifest.executable.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'HOST_AGENT_WINDOWS_EXECUTABLE_IDENTITY_REFUSED'
    }
    $exeItem = Get-Item -LiteralPath $ExecutablePath -Force
    if ([int64]$manifest.executable.bytes -le 0 -or [int64]$manifest.executable.bytes -ne $exeItem.Length) {
        throw 'HOST_AGENT_WINDOWS_EXECUTABLE_SIZE_REFUSED'
    }
    $sha = (Get-FileHash -LiteralPath $ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -cne [string]$manifest.executable.sha256) { throw 'HOST_AGENT_WINDOWS_EXECUTABLE_HASH_REFUSED' }
    [pscustomobject]@{
        Manifest = $manifest
        ExecutablePath = [IO.Path]::GetFullPath($ExecutablePath)
        ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
        ManifestSha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        ExecutableSha256 = $sha
        ExecutableBytes = $exeItem.Length
        SourceCommit = [string]$manifest.source_commit
        SourceTree = [string]$manifest.source_tree
    }
}

function Get-HostAgentWindowsPackageContext {
    param([Parameter(Mandatory)][string]$PackageDirectory)
    if ([string]::IsNullOrWhiteSpace($PackageDirectory) -or -not [IO.Path]::IsPathFullyQualified($PackageDirectory)) {
        throw 'HOST_AGENT_WINDOWS_PACKAGE_PATH_REFUSED'
    }
    $root = [IO.Path]::GetFullPath($PackageDirectory)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'HOST_AGENT_WINDOWS_PACKAGE_MISSING' }
    Assert-HostAgentWindowsNotReparse -Path $root
    $children = @(Get-ChildItem -LiteralPath $root -Force)
    if (@($children | Where-Object { $_.PSIsContainer }).Count -ne 0) { throw 'HOST_AGENT_WINDOWS_PACKAGE_BOUNDARY_REFUSED' }
    $names = @($children | Where-Object { -not $_.PSIsContainer } | ForEach-Object Name | Sort-Object)
    if (($names -join ',') -cne (($script:ExecutableName,$script:PackageManifestName | Sort-Object) -join ',')) {
        throw 'HOST_AGENT_WINDOWS_PACKAGE_BOUNDARY_REFUSED'
    }
    $context = Read-HostAgentWindowsManifest -ManifestPath (Join-Path $root $script:PackageManifestName) -ExecutablePath (Join-Path $root $script:ExecutableName)
    $context | Add-Member -NotePropertyName PackageDirectory -NotePropertyValue $root
    return $context
}

function Get-HostAgentWindowsInstalledObservation {
    $constants = Get-HostAgentWindowsDeploymentConstants
    if (Test-Path -LiteralPath $constants.InstallRoot) {
        Assert-HostAgentWindowsProtectedInstallRoot -InstallRoot $constants.InstallRoot
    } else {
        Assert-HostAgentWindowsProtectedPathChain -TargetPath $constants.InstallRoot
    }
    $exePresent = Test-Path -LiteralPath $constants.ExecutablePath -PathType Leaf
    $manifestPresent = Test-Path -LiteralPath $constants.InstalledManifestPath -PathType Leaf
    if (-not $exePresent -and -not $manifestPresent) {
        return [pscustomobject]@{ State='Absent'; Context=$null; ExecutableSha256=$null; ExecutableBytes=$null }
    }
    if (-not $exePresent -and $manifestPresent) { throw 'HOST_AGENT_WINDOWS_INSTALLED_STATE_INCOMPLETE' }
    if ($exePresent -and -not $manifestPresent) {
        Assert-HostAgentWindowsSafeFile -Path $constants.ExecutablePath
        $item = Get-Item -LiteralPath $constants.ExecutablePath -Force
        return [pscustomobject]@{
            State='Legacy'
            Context=$null
            ExecutableSha256=(Get-FileHash -LiteralPath $constants.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
            ExecutableBytes=$item.Length
        }
    }
    $context = Read-HostAgentWindowsManifest -ManifestPath $constants.InstalledManifestPath -ExecutablePath $constants.ExecutablePath
    return [pscustomobject]@{ State='Managed'; Context=$context; ExecutableSha256=$context.ExecutableSha256; ExecutableBytes=$context.ExecutableBytes }
}

function Get-HostAgentWindowsInstalledContext {
    $observation = Get-HostAgentWindowsInstalledObservation
    if ($observation.State -ceq 'Absent') { return $null }
    if ($observation.State -ceq 'Legacy') { throw 'HOST_AGENT_WINDOWS_LEGACY_STATE_REQUIRES_EXPLICIT_ADOPTION' }
    return $observation.Context
}

function Get-HostAgentWindowsRollbackContext {
    $constants = Get-HostAgentWindowsDeploymentConstants
    if (-not (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container)) { return $null }
    Assert-HostAgentWindowsProtectedInstallRoot -InstallRoot $constants.InstallRoot
    Assert-HostAgentWindowsProtectedDirectory -Path $constants.RollbackRoot
    $exe = Join-Path $constants.RollbackRoot $script:ExecutableName
    $manifest = Join-Path $constants.RollbackRoot $script:InstalledManifestName
    $exePresent = Test-Path -LiteralPath $exe -PathType Leaf
    $manifestPresent = Test-Path -LiteralPath $manifest -PathType Leaf
    if ($exePresent -ne $manifestPresent -or -not $exePresent) { throw 'HOST_AGENT_WINDOWS_ROLLBACK_STATE_INCOMPLETE' }
    $unexpected = @(Get-ChildItem -LiteralPath $constants.RollbackRoot -Force | Where-Object { $_.Name -notin @($script:ExecutableName,$script:InstalledManifestName) })
    if ($unexpected.Count -gt 0) { throw 'HOST_AGENT_WINDOWS_ROLLBACK_BOUNDARY_REFUSED' }
    return Read-HostAgentWindowsManifest -ManifestPath $manifest -ExecutablePath $exe
}

function Get-HostAgentWindowsRunningCount {
    return @(Get-Process -Name 'LDW.HostAgent.Windows' -ErrorAction SilentlyContinue).Count
}

Export-ModuleMember -Function Get-HostAgentWindowsDeploymentConstants, Assert-HostAgentWindowsAdministrator, Assert-HostAgentWindowsNotReparse, Assert-HostAgentWindowsSafeFile, Assert-HostAgentWindowsNoBroadMutationAcl, Assert-HostAgentWindowsProtectedDirectory, Assert-HostAgentWindowsProtectedPathChain, Assert-HostAgentWindowsProtectedInstallRoot, Ensure-HostAgentWindowsProtectedInstallRoot, Enter-HostAgentWindowsTransactionLock, Read-HostAgentWindowsManifest, Get-HostAgentWindowsPackageContext, Get-HostAgentWindowsInstalledObservation, Get-HostAgentWindowsInstalledContext, Get-HostAgentWindowsRollbackContext, Get-HostAgentWindowsRunningCount
