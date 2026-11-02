#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $deployRoot 'HostAgentWindowsDeployment.psm1'
$publisherPath = Join-Path $deployRoot 'Publish-HostAgentWindowsPackage.ps1'
$managerPath = Join-Path $deployRoot 'Manage-HostAgentWindowsDeployment.ps1'
Import-Module $modulePath -Force

$script:Assertions = 0
function Assert-True([bool]$Condition,[string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function Assert-Throws([scriptblock]$Action,[string]$Message) {
    $script:Assertions++
    try { & $Action; throw "ASSERTION FAILED: $Message" }
    catch { if ($_.Exception.Message.StartsWith('ASSERTION FAILED:',[StringComparison]::Ordinal)) { throw } }
}

foreach ($path in @($modulePath,$publisherPath,$managerPath)) {
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-True ($errors.Count -eq 0) "PowerShell must parse: $path"
}

$constants = Get-HostAgentWindowsDeploymentConstants
Assert-True ($constants.ExecutableName -ceq 'LDW.HostAgent.Windows.exe') 'managed executable name must be fixed'
Assert-True ($constants.InstallRoot -ceq (Join-Path $env:ProgramFiles 'LowcountryDigitalWorks\HostAgent\Windows')) 'install root must be fixed under Program Files'
Assert-True ($constants.ExecutablePath -ceq (Join-Path $constants.InstallRoot 'LDW.HostAgent.Windows.exe')) 'startup-compatible executable path must be fixed'
Assert-True ($constants.RollbackRoot -ceq (Join-Path $constants.InstallRoot 'rollback')) 'rollback root must remain fixed'
Assert-True ($constants.TransactionLockPath -ceq (Join-Path $env:ProgramFiles '.ldw-host-agent-windows-deployment.lock')) 'transaction lock path must remain fixed under protected Program Files'

$module = Get-Content -LiteralPath $modulePath -Raw
foreach ($required in @(
    'Assert-HostAgentWindowsSafeFile',
    'HOST_AGENT_WINDOWS_HARDLINK_REFUSED',
    'Assert-HostAgentWindowsProtectedDirectory',
    'Assert-HostAgentWindowsProtectedPathChain',
    'Ensure-HostAgentWindowsProtectedInstallRoot',
    'Enter-HostAgentWindowsTransactionLock',
    'HOST_AGENT_WINDOWS_TRANSACTION_BUSY',
    '[IO.FileShare]::None',
    'Assert-HostAgentWindowsProtectedInstallRoot -InstallRoot $constants.InstallRoot'
)) {
    Assert-True ($module.Contains($required,[StringComparison]::Ordinal)) "module must preserve destination/lock hardening: $required"
}

$publisher = Get-Content -LiteralPath $publisherPath -Raw
foreach ($required in @(
    'host-agent/src/LDW.HostAgent.Windows/LDW.HostAgent.Windows.csproj',
    '-r win-x64 --self-contained true',
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=None',
    '-p:DebugSymbols=false',
    "package = 'ldw-host-agent-windows'",
    "runtime = 'win-x64'",
    'source_commit = $sourceCommit',
    'source_tree = $sourceTree',
    'Get-FileHash -LiteralPath $packagedExe -Algorithm SHA256',
    'status --porcelain',
    'git -C $repoRoot archive --format=zip',
    'Expand-Archive -LiteralPath $archive -DestinationPath $materialized',
    "Join-Path `$materialized 'host-agent/src/LDW.HostAgent.Windows/LDW.HostAgent.Windows.csproj'",
    'HOST_AGENT_WINDOWS_PACKAGE_SOURCE_MOVED_DURING_BUILD',
    'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_PARENT_MISSING',
    'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_REPARSE_REFUSED',
    'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_EXISTS',
    'HOST_AGENT_WINDOWS_PACKAGE=PASS'
)) {
    Assert-True ($publisher.Contains($required,[StringComparison]::Ordinal)) "publisher must preserve immutable package/provenance contract: $required"
}
foreach ($forbidden in @(
    'Invoke-WebRequest','Invoke-RestMethod','Start-BitsTransfer','curl.exe','wget.exe',
    'Register-ScheduledTask','New-ScheduledTask','Start-ScheduledTask','Stop-ScheduledTask',
    'New-Service','Set-Service','Set-ItemProperty','New-ItemProperty','Remove-ItemProperty',
    'Stop-Process','taskkill','HttpListener','TcpListener'
)) {
    Assert-True (-not $publisher.Contains($forbidden,[StringComparison]::OrdinalIgnoreCase)) "publisher must exclude runtime/startup/network mutation: $forbidden"
}
Assert-True ($publisher.Contains("LDW.HostAgent.Windows.exe,manifest.json",[StringComparison]::Ordinal)) 'package boundary must contain only executable and manifest'
$dirtyIndex = $publisher.IndexOf('HOST_AGENT_WINDOWS_PACKAGE_SOURCE_DIRTY',[StringComparison]::Ordinal)
$archiveIndex = $publisher.IndexOf('git -C $repoRoot archive --format=zip',[StringComparison]::Ordinal)
$publishIndex = $publisher.IndexOf('& dotnet publish',[StringComparison]::Ordinal)
$outputCreateIndex = $publisher.IndexOf('New-Item -ItemType Directory -Path $output',[StringComparison]::Ordinal)
$sourceMoveIndex = $publisher.IndexOf('HOST_AGENT_WINDOWS_PACKAGE_SOURCE_MOVED_DURING_BUILD',[StringComparison]::Ordinal)
Assert-True ($dirtyIndex -ge 0 -and $dirtyIndex -lt $archiveIndex -and $archiveIndex -lt $publishIndex) 'clean source must be frozen into an immutable archive before publish'
Assert-True ($sourceMoveIndex -gt $publishIndex -and $sourceMoveIndex -lt $outputCreateIndex) 'source movement must be rechecked before output creation'

$manager = Get-Content -LiteralPath $managerPath -Raw
foreach ($required in @(
    "ValidateSet('Plan','Install','Status','Rollback')",
    'ExpectedManifestSha256',
    'ExpectedExecutableSha256',
    'ExpectedExecutableBytes',
    'ExpectedRollbackManifestSha256',
    'ExpectedRollbackExecutableSha256',
    'ExpectedRollbackExecutableBytes',
    'HOST_AGENT_WINDOWS_EXPECTED_PACKAGE_IDENTITY_REQUIRED',
    'HOST_AGENT_WINDOWS_PACKAGE_IDENTITY_MISMATCH',
    'HOST_AGENT_WINDOWS_EXPECTED_ROLLBACK_IDENTITY_REQUIRED',
    'HOST_AGENT_WINDOWS_ROLLBACK_IDENTITY_MISMATCH',
    'HOST_AGENT_WINDOWS_LEGACY_EXPECTATION_REQUIRED',
    'HOST_AGENT_WINDOWS_LEGACY_HASH_MISMATCH',
    'HOST_AGENT_WINDOWS_RUNNING_REFUSED',
    'HOST_AGENT_WINDOWS_STATE_CHANGED',
    'Assert-HostAgentWindowsAdministrator',
    'Enter-HostAgentWindowsTransactionLock -TimeoutMilliseconds 5000',
    'Get-HostAgentWindowsInstalledContext',
    'Get-HostAgentWindowsRollbackContext',
    '.failed-new-rollback-',
    '$transactionCommitted -or $recoveryProven',
    "StartupRegistrationMutation = `$false",
    'HOST_AGENT_WINDOWS_INSTALL_ROLLBACK_FAILED',
    'HOST_AGENT_WINDOWS_ROLLBACK_RECOVERY_FAILED',
    'HOST_AGENT_WINDOWS_ROLLBACK_RECOVERY_SOURCE_MISMATCH',
    'HOST_AGENT_WINDOWS_ROLLBACK_RECOVERY_STATE_CHANGED',
    '$currentBackupReady = $true'
)) {
    Assert-True ($manager.Contains($required,[StringComparison]::Ordinal)) "manager must preserve fail-closed deployment contract: $required"
}
foreach ($forbidden in @(
    'Stop-Process','taskkill','Start-Process','Register-ScheduledTask','New-ScheduledTask',
    'Enable-ScheduledTask','Disable-ScheduledTask','Unregister-ScheduledTask',
    'Set-ItemProperty','New-ItemProperty','Remove-ItemProperty','New-Service','Set-Service',
    'Invoke-WebRequest','Invoke-RestMethod','curl.exe','wget.exe','HttpListener','TcpListener'
)) {
    Assert-True (-not $manager.Contains($forbidden,[StringComparison]::OrdinalIgnoreCase)) "manager must not own startup/process/network mutations: $forbidden"
}
Assert-True (-not $manager.Contains('host-agent.Local.json',[StringComparison]::OrdinalIgnoreCase)) 'manager must not read, copy, overwrite, or delete machine-local config'

$lockIndex = $manager.IndexOf('Enter-HostAgentWindowsTransactionLock -TimeoutMilliseconds 5000',[StringComparison]::Ordinal)
$ensureIndex = $manager.IndexOf('Ensure-HostAgentWindowsProtectedInstallRoot',[StringComparison]::Ordinal)
$installCopyIndex = $manager.IndexOf('Copy-Item -LiteralPath $staged.ExecutablePath -Destination $constants.ExecutablePath',[StringComparison]::Ordinal)
Assert-True ($lockIndex -ge 0 -and $ensureIndex -gt $lockIndex -and $installCopyIndex -gt $ensureIndex) 'exclusive lock and protected-root checks must precede install mutation'
Assert-True (([regex]::Matches($manager,[regex]::Escape('Get-HostAgentWindowsRunningCount'))).Count -ge 3) 'tray state must be rechecked under transaction protection and immediately before activation'
$cleanupGateIndex = $manager.IndexOf('$transactionCommitted -or $recoveryProven',[StringComparison]::Ordinal)
Assert-True ($cleanupGateIndex -ge 0) 'recovery evidence cleanup must be gated on proven commit or restoration'
Assert-True (-not $manager.Contains("elseif (Test-Path -LiteralPath `$constants.RollbackRoot -PathType Container) { `$constants.RollbackRoot }",[StringComparison]::Ordinal)) 'rollback recovery must never substitute the rollback target for an incomplete current-state backup'
Assert-True (-not $manager.Contains('Remove-TransactionDirectoryIfSafe -Path $rollbackOld',[StringComparison]::Ordinal)) 'rollback-old cleanup must occur only through the post-commit/post-recovery finally gate'

$tempParent = [IO.Path]::GetTempPath()
$tempRoot = Join-Path $tempParent ('ldw-host-agent-windows-deploy-contract-' + [guid]::NewGuid().ToString('N'))
$hardRoot = Join-Path $tempParent ('ldw-host-agent-windows-hardlink-contract-' + [guid]::NewGuid().ToString('N'))
$hardTarget = Join-Path $tempParent ('ldw-host-agent-windows-hardlink-target-' + [guid]::NewGuid().ToString('N') + '.bin')
$null = New-Item -ItemType Directory -Path $tempRoot
try {
    $exe = Join-Path $tempRoot 'LDW.HostAgent.Windows.exe'
    [IO.File]::WriteAllBytes($exe,[Text.Encoding]::UTF8.GetBytes('synthetic-host-agent-executable'))
    $sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $bytes = (Get-Item -LiteralPath $exe).Length
    $manifest = [ordered]@{
        schema = 1
        package = 'ldw-host-agent-windows'
        runtime = 'win-x64'
        source_commit = ('a' * 40)
        source_tree = ('b' * 40)
        executable = [ordered]@{ name='LDW.HostAgent.Windows.exe'; sha256=$sha; bytes=$bytes }
    }
    $manifestPath = Join-Path $tempRoot 'manifest.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    $context = Get-HostAgentWindowsPackageContext -PackageDirectory $tempRoot
    Assert-True ($context.SourceCommit -ceq ('a' * 40)) 'valid package must preserve exact source commit'
    Assert-True ($context.SourceTree -ceq ('b' * 40)) 'valid package must preserve exact source tree'
    Assert-True ($context.ExecutableSha256 -ceq $sha) 'valid package must verify executable SHA-256'
    Assert-True ($context.ManifestSha256 -ceq (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()) 'valid package must expose exact manifest SHA-256'

    Assert-Throws {
        & $managerPath -Action Plan -PackageDirectory $tempRoot -ExpectedSourceCommit ('a' * 40) -ExpectedSourceTree ('b' * 40) | Out-Null
    } 'source-only expectations must no longer authorize a package'
    Assert-Throws {
        & $managerPath -Action Plan -PackageDirectory $tempRoot `
            -ExpectedSourceCommit ('a' * 40) -ExpectedSourceTree ('b' * 40) `
            -ExpectedManifestSha256 ('0' * 64) -ExpectedExecutableSha256 $sha -ExpectedExecutableBytes $bytes | Out-Null
    } 'independent manifest digest mismatch must fail before deployment observation/mutation'
    Assert-Throws {
        & $managerPath -Action Plan -PackageDirectory $tempRoot `
            -ExpectedSourceCommit ('a' * 40) -ExpectedSourceTree ('b' * 40) `
            -ExpectedManifestSha256 $context.ManifestSha256 -ExpectedExecutableSha256 ('0' * 64) -ExpectedExecutableBytes $bytes | Out-Null
    } 'independent executable digest mismatch must fail before deployment observation/mutation'
    Assert-Throws {
        & $managerPath -Action Plan -PackageDirectory $tempRoot `
            -ExpectedSourceCommit ('a' * 40) -ExpectedSourceTree ('b' * 40) `
            -ExpectedManifestSha256 $context.ManifestSha256 -ExpectedExecutableSha256 $sha -ExpectedExecutableBytes ($bytes + 1) | Out-Null
    } 'independent executable length mismatch must fail before deployment observation/mutation'

    Set-Content -LiteralPath (Join-Path $tempRoot 'unexpected.txt') -Value 'x' -NoNewline
    Assert-Throws { Get-HostAgentWindowsPackageContext -PackageDirectory $tempRoot | Out-Null } 'unexpected package file must fail closed'
    Remove-Item -LiteralPath (Join-Path $tempRoot 'unexpected.txt')

    Add-Content -LiteralPath $exe -Value 'tamper' -NoNewline
    Assert-Throws { Get-HostAgentWindowsPackageContext -PackageDirectory $tempRoot | Out-Null } 'tampered executable must fail hash/size validation'

    # A package executable that is a hard link is refused even when manifest bytes/hash match.
    $null = New-Item -ItemType Directory -Path $hardRoot
    [IO.File]::WriteAllBytes($hardTarget,[Text.Encoding]::UTF8.GetBytes('synthetic-hardlink-target'))
    $hardExe = Join-Path $hardRoot 'LDW.HostAgent.Windows.exe'
    $null = New-Item -ItemType HardLink -Path $hardExe -Target $hardTarget
    $hardSha = (Get-FileHash -LiteralPath $hardExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $hardBytes = (Get-Item -LiteralPath $hardExe).Length
    [ordered]@{
        schema = 1
        package = 'ldw-host-agent-windows'
        runtime = 'win-x64'
        source_commit = ('c' * 40)
        source_tree = ('d' * 40)
        executable = [ordered]@{ name='LDW.HostAgent.Windows.exe'; sha256=$hardSha; bytes=$hardBytes }
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $hardRoot 'manifest.json') -Encoding utf8NoBOM
    Assert-Throws { Get-HostAgentWindowsPackageContext -PackageDirectory $hardRoot | Out-Null } 'hard-linked package executable must fail closed'
} finally {
    foreach ($path in @($tempRoot,$hardRoot)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    if (Test-Path -LiteralPath $hardTarget) { Remove-Item -LiteralPath $hardTarget -Force }
}

Write-Host "Host Agent Windows deployment contract assertions PASS: $script:Assertions"
