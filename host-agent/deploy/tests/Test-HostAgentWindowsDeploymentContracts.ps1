#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $deployRoot 'HostAgentWindowsDeployment.psm1'
$publisherPath = Join-Path $deployRoot 'Publish-HostAgentWindowsPackage.ps1'
$managerPath = Join-Path $deployRoot 'Manage-HostAgentWindowsDeployment.ps1'
$trayLaunchModulePath = Join-Path $deployRoot 'HostAgentWindowsTrayLaunch.psm1'
$trayLaunchScriptPath = Join-Path $deployRoot 'Start-HostAgentWindowsTray.ps1'
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
function Assert-ThrowsCode([scriptblock]$Action,[string]$ExpectedCode,[string]$Message) {
    $script:Assertions++
    try { & $Action | Out-Null; throw "ASSERTION FAILED: $Message" }
    catch {
        if ($_.Exception.Message.StartsWith('ASSERTION FAILED:',[StringComparison]::Ordinal)) { throw }
        if (-not $_.ToString().Contains($ExpectedCode,[StringComparison]::Ordinal)) {
            throw "ASSERTION FAILED: $Message (expected: $ExpectedCode; actual: $($_.Exception.Message))"
        }
    }
}

foreach ($path in @($modulePath,$publisherPath,$managerPath,$trayLaunchModulePath,$trayLaunchScriptPath)) {
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
    '$currentBackupReady = $true',
    '$currentBackupPromotedToRollback = $true'
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
Assert-True ($manager.Contains('elseif ($currentBackupPromotedToRollback -and (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container))',[StringComparison]::Ordinal)) 'rollback-root recovery source must be gated by positive current-backup promotion state'
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

# HOST-AGENT-DEPLOY-002: deterministic normal-user tray relaunch contract.
$trayModuleSource = Get-Content -LiteralPath $trayLaunchModulePath -Raw
$trayScriptSource = Get-Content -LiteralPath $trayLaunchScriptPath -Raw
foreach ($required in @(
    "ProcessName = 'LDW.HostAgent.Windows'",
    "ExplorerPath = Join-Path `$env:WINDIR 'explorer.exe'",
    'Get-HostAgentWindowsInstalledObservation',
    'Assert-HostAgentWindowsSafeFile',
    'HOST_AGENT_WINDOWS_TRAY_ALREADY_RUNNING',
    'HOST_AGENT_WINDOWS_TRAY_EXPLORER_SESSION_REQUIRED',
    'HOST_AGENT_WINDOWS_TRAY_AMBIGUOUS_RESULT',
    'HOST_AGENT_WINDOWS_TRAY_TOKEN_PROBE_REFUSED',
    'HOST_AGENT_WINDOWS_TRAY_ELEVATED_RESULT_REFUSED',
    'HOST_AGENT_WINDOWS_TRAY_CLEANUP_REFUSED',
    'Start-Process -FilePath $constants.ExplorerPath',
    'StartupRegistrationMutation = $false',
    'IncrementalRuntimeCostUsd = 0'
)) {
    Assert-True ($trayModuleSource.Contains($required,[StringComparison]::Ordinal)) "tray launch module must preserve bounded relaunch contract: $required"
}
foreach ($forbidden in @(
    'Set-ItemProperty','New-ItemProperty','Remove-ItemProperty','Register-ScheduledTask','New-ScheduledTask',
    'Set-ScheduledTask','Unregister-ScheduledTask','New-Service','Set-Service','sc.exe','reg.exe','Invoke-WebRequest','Invoke-RestMethod'
)) {
    Assert-True (-not $trayModuleSource.Contains($forbidden,[StringComparison]::OrdinalIgnoreCase)) "tray launch module must not gain startup/service/network mutation: $forbidden"
}
Assert-True ($trayScriptSource.Contains("[ValidateSet('Plan','Start')]",[StringComparison]::Ordinal)) 'public relaunch wrapper exposes only Plan/Start actions'
Assert-True (-not $trayScriptSource.Contains('ExecutablePath',[StringComparison]::Ordinal)) 'public relaunch wrapper must not accept caller-controlled executable paths'
Assert-True (-not $trayScriptSource.Contains('SessionId',[StringComparison]::Ordinal)) 'public relaunch wrapper must not accept caller-controlled session IDs'

$trayModule = Import-Module $trayLaunchModulePath -Force -PassThru
$trayConstants = Get-HostAgentWindowsTrayLaunchConstants
Assert-True ($trayConstants.ExecutablePath -ceq $constants.ExecutablePath) 'tray relaunch target must reuse the fixed managed deployment executable'
Assert-True ($trayConstants.ExplorerPath -ceq (Join-Path $env:WINDIR 'explorer.exe')) 'tray relaunch must delegate only through Windows Explorer'

Assert-ThrowsCode { & $trayModule { Assert-HostAgentWindowsTrayLaunchState -InstalledState 'Absent' -RunningCount 0 -SessionId 1 -ExplorerCandidateCount 1 } } 'HOST_AGENT_WINDOWS_TRAY_MANAGED_INSTALL_REQUIRED' 'unmanaged install state must fail closed'
Assert-ThrowsCode { & $trayModule { Assert-HostAgentWindowsTrayLaunchState -InstalledState 'Managed' -RunningCount 1 -SessionId 1 -ExplorerCandidateCount 1 } } 'HOST_AGENT_WINDOWS_TRAY_ALREADY_RUNNING' 'already-running tray must fail closed'
Assert-ThrowsCode { & $trayModule { Assert-HostAgentWindowsTrayLaunchState -InstalledState 'Managed' -RunningCount 0 -SessionId 0 -ExplorerCandidateCount 1 } } 'HOST_AGENT_WINDOWS_TRAY_INTERACTIVE_SESSION_REQUIRED' 'session zero must fail closed'
Assert-ThrowsCode { & $trayModule { Assert-HostAgentWindowsTrayLaunchState -InstalledState 'Managed' -RunningCount 0 -SessionId 1 -ExplorerCandidateCount 0 } } 'HOST_AGENT_WINDOWS_TRAY_EXPLORER_SESSION_REQUIRED' 'missing normal-user Explorer shell must fail closed'

$syntheticExe = Join-Path $env:TEMP 'LDW.HostAgent.Windows.exe'
$success = & $trayModule {
    param($exe)
    $state = [pscustomobject]@{ LaunchCount=0; Stopped=[Collections.Generic.List[int]]::new() }
    $launch = { param($path,$session) $state.LaunchCount++; if ($session -ne 7 -or $path -cne [IO.Path]::GetFullPath($exe)) { throw 'bad-launch-input' } }.GetNewClosure()
    $observe = { [pscustomobject]@{ Id=101; SessionId=7; Path=[IO.Path]::GetFullPath($exe) } }.GetNewClosure()
    $elevation = { param($id) if ($id -ne 101) { throw 'bad-id' }; $false }
    $stop = { param($id) $state.Stopped.Add($id) }.GetNewClosure()
    $sleep = { param($ms) }
    $result = Invoke-HostAgentWindowsTrayLaunchCore -ExecutablePath $exe -SessionId 7 -BeforeProcessIds @() -LaunchAction $launch -ObserveAction $observe -ElevationProbe $elevation -StopAction $stop -SleepAction $sleep -PollAttempts 1
    [pscustomobject]@{ Result=$result; LaunchCount=$state.LaunchCount; Stopped=@($state.Stopped) }
} $syntheticExe
Assert-True ($success.Result.Started -and -not $success.Result.Elevated -and $success.Result.ProcessId -eq 101) 'single exact normal-user result must pass'
Assert-True ($success.LaunchCount -eq 1 -and $success.Stopped.Count -eq 0) 'successful relaunch must launch once and not clean up the accepted process'

$elevated = & $trayModule {
    param($exe)
    $script:stopped = @()
    try {
        Invoke-HostAgentWindowsTrayLaunchCore -ExecutablePath $exe -SessionId 7 -BeforeProcessIds @() `
            -LaunchAction { param($path,$session) } `
            -ObserveAction { [pscustomobject]@{ Id=202; SessionId=7; Path=[IO.Path]::GetFullPath($exe) } }.GetNewClosure() `
            -ElevationProbe { param($id) $true } `
            -StopAction { param($id) $script:stopped += $id } `
            -SleepAction { param($ms) } -PollAttempts 1 | Out-Null
        [pscustomobject]@{ Error=$null; Stopped=@($script:stopped) }
    } catch { [pscustomobject]@{ Error=$_.Exception.Message; Stopped=@($script:stopped) } }
} $syntheticExe
Assert-True ($elevated.Error -ceq 'HOST_AGENT_WINDOWS_TRAY_ELEVATED_RESULT_REFUSED') 'elevated relaunch result must fail closed'
Assert-True (($elevated.Stopped -join ',') -ceq '202') 'elevated newly launched exact tray must be stopped'

$tokenFailure = & $trayModule {
    param($exe)
    $script:stopped = @()
    try {
        Invoke-HostAgentWindowsTrayLaunchCore -ExecutablePath $exe -SessionId 7 -BeforeProcessIds @() `
            -LaunchAction { param($path,$session) } `
            -ObserveAction { [pscustomobject]@{ Id=303; SessionId=7; Path=[IO.Path]::GetFullPath($exe) } }.GetNewClosure() `
            -ElevationProbe { param($id) throw 'synthetic-token-failure' } `
            -StopAction { param($id) $script:stopped += $id } `
            -SleepAction { param($ms) } -PollAttempts 1 | Out-Null
        [pscustomobject]@{ Error=$null; Stopped=@($script:stopped) }
    } catch { [pscustomobject]@{ Error=$_.Exception.Message; Stopped=@($script:stopped) } }
} $syntheticExe
Assert-True ($tokenFailure.Error -ceq 'HOST_AGENT_WINDOWS_TRAY_TOKEN_PROBE_REFUSED') 'ambiguous token state must fail closed'
Assert-True (($tokenFailure.Stopped -join ',') -ceq '303') 'token-probe failure must stop the newly launched exact tray'

$ambiguous = & $trayModule {
    param($exe)
    $script:stopped = @()
    try {
        Invoke-HostAgentWindowsTrayLaunchCore -ExecutablePath $exe -SessionId 7 -BeforeProcessIds @() `
            -LaunchAction { param($path,$session) } `
            -ObserveAction { @([pscustomobject]@{ Id=401; SessionId=7; Path=[IO.Path]::GetFullPath($exe) },[pscustomobject]@{ Id=402; SessionId=7; Path=[IO.Path]::GetFullPath($exe) }) }.GetNewClosure() `
            -ElevationProbe { param($id) $false } `
            -StopAction { param($id) $script:stopped += $id } `
            -SleepAction { param($ms) } -PollAttempts 1 | Out-Null
        [pscustomobject]@{ Error=$null; Stopped=@($script:stopped) }
    } catch { [pscustomobject]@{ Error=$_.Exception.Message; Stopped=@($script:stopped | Sort-Object) } }
} $syntheticExe
Assert-True ($ambiguous.Error -ceq 'HOST_AGENT_WINDOWS_TRAY_AMBIGUOUS_RESULT') 'multiple newly launched tray results must fail closed'
Assert-True (($ambiguous.Stopped -join ',') -ceq '401,402') 'ambiguous exact candidates must both be cleaned up'

$cleanup = & $trayModule {
    param($exe)
    $script:stopped = @()
    $candidates = @(
        [pscustomobject]@{ Id=500; SessionId=7; Path=[IO.Path]::GetFullPath($exe) },
        [pscustomobject]@{ Id=501; SessionId=8; Path=[IO.Path]::GetFullPath($exe) },
        [pscustomobject]@{ Id=502; SessionId=7; Path='C:\\Windows\\notepad.exe' },
        [pscustomobject]@{ Id=503; SessionId=7; Path=[IO.Path]::GetFullPath($exe) }
    )
    Stop-HostAgentWindowsNewTrayCandidates -Candidates $candidates -BeforeProcessIds @(500) -ExecutablePath $exe -SessionId 7 -StopAction { param($id) $script:stopped += $id }
    @($script:stopped)
} $syntheticExe
Assert-True (($cleanup -join ',') -ceq '503') 'cleanup must stop only a newly launched exact-path exact-session tray candidate'

Assert-ThrowsCode {
    & $trayModule {
        param($exe)
        Stop-HostAgentWindowsNewTrayCandidates `
            -Candidates @([pscustomobject]@{ Id=601; SessionId=7; Path=[IO.Path]::GetFullPath($exe) }) `
            -BeforeProcessIds @() -ExecutablePath $exe -SessionId 7 `
            -StopAction { param($id) throw 'synthetic-stop-failure' }
    } $syntheticExe
} 'HOST_AGENT_WINDOWS_TRAY_CLEANUP_REFUSED' 'cleanup failure must remain visible and fail closed'

Assert-ThrowsCode {
    & $trayModule {
        param($exe)
        Invoke-HostAgentWindowsTrayLaunchCore -ExecutablePath $exe -SessionId 7 -BeforeProcessIds @() `
            -LaunchAction { param($path,$session) } -ObserveAction { @() } -ElevationProbe { param($id) $false } `
            -StopAction { param($id) } -SleepAction { param($ms) } -PollAttempts 1 | Out-Null
    } $syntheticExe
} 'HOST_AGENT_WINDOWS_TRAY_LAUNCH_TIMEOUT' 'missing result must terminate at a bounded timeout'

Write-Host "Host Agent Windows deployment contract assertions PASS: $script:Assertions"
