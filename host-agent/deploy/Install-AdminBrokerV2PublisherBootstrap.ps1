# One-time closed protected V2 publisher bootstrap. Self-contained: no imports, dot-source, child scripts,
# parameters, network, git, or caller-controlled paths. Execute only from protected staging with zero arguments.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$acceptedBootstrapSha256 = '86f8f7ac74fb9c6db5ce752202705dfaf59bf36000bf89ccf28b0426ce85abab'
$acceptedV2WorkerSha256 = '75788c05edcf14199e53de239ef333dcefb9bc09385ba22de2b99cfda91bcabe'
$acceptedV1WorkerSha256 = 'db71da0a73f2943eb8837e7c1e7070a22251478e4acfba91338837c7fc699605'
$v2WorkerIdentity = 'v2-publisher-reviewed-1'
$bootstrapStagingLeaf = 'v2-publisher-once'
$bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$taskName = '\LDW-ADMIN-REVIEWED-OPERATION'

$controlRoot = Join-Path $env:ProgramData 'LDW/PrivilegedControl'
$binRoot = Join-Path $controlRoot 'bin'
$lockRoot = Join-Path $controlRoot 'lock'
$journalRoot = Join-Path $controlRoot 'journal'
$v1WorkerInstalled = Join-Path $binRoot 'Invoke-AdminPrivilegedOperation.ps1'
$v2WorkerInstalled = Join-Path $binRoot ('v2/' + $v2WorkerIdentity + '/' + $workerBundleName)
$protectedStagingRoot = Join-Path $controlRoot ('bootstrap-staging/' + $bootstrapStagingLeaf)
$expectedBootstrapPath = Join-Path $protectedStagingRoot $bootstrapFileName
$lockPath = Join-Path $lockRoot 'v2-publisher-bootstrap.lock'
$journalPath = Join-Path $journalRoot 'v2-publisher-bootstrap.jsonl'
$receiptPath = Join-Path $journalRoot 'v2-bootstrap-consumed.receipt'

$script:LockStream = $null
$script:JournalEnabled = $false
$script:V1Snapshot = $null

function Assert-Elevated {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATION_REQUIRED'
    }
}

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE_PATH_REFUSED' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Get-OwnerSid {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.User -or $identity.User.Value -cnotmatch '^S-1-5-21-(\d+-){3}\d+$') {
        throw 'OWNER_SID_REQUIRED'
    }
    $identity.User.Value
}

function Get-SystemPowerShellExecutable {
    $sysDir = [Environment]::GetFolderPath('System')
    if ([string]::IsNullOrWhiteSpace($sysDir)) { throw 'SYSTEM_DIRECTORY_REQUIRED' }
    $candidate = [IO.Path]::Combine($sysDir, 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    $full = [IO.Path]::GetFullPath($candidate)
    if ($full -notmatch '\\WindowsPowerShell\\v1\.0\\powershell\.exe$') { throw 'SYSTEM_POWERSHELL_PATH_REFUSED' }
    if ($full -match 'WindowsApps' -or $full -match 'AppData\\Local\\Microsoft\\WindowsApps') {
        throw 'WINDOWSAPPS_RUNTIME_REFUSED'
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'SYSTEM_POWERSHELL_REQUIRED' }
    $full
}

function Assert-WindowsAppsRuntimeRefused([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'TASK_RUNTIME_REFUSED' }
    $norm = [IO.Path]::GetFullPath($Path)
    if ($norm -match 'WindowsApps' -or $norm -match 'AppData\\Local\\Microsoft\\WindowsApps') {
        throw 'WINDOWSAPPS_RUNTIME_REFUSED'
    }
    if ($norm -notmatch '\\WindowsPowerShell\\v1\.0\\powershell\.exe$') {
        throw 'V2_TASK_RUNTIME_PATH_REFUSED'
    }
}

function New-ProtectedDirectoryAcl([string]$Path) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ProtectedDirectory([string]$Path) {
    Assert-NoReparse $Path
    if (-not (Test-Path -LiteralPath $Path)) { throw 'PROTECTED_PATH_MISSING' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
        throw 'CONTROL_ACL_OWNER_REFUSED'
    }
}

function Write-Journal([string]$Phase, [hashtable]$Fields) {
    if (-not $script:JournalEnabled) { return }
    $ownerSid = Get-OwnerSid
    $record = [ordered]@{
        schema = 1
        phase = $Phase
        utc = [DateTime]::UtcNow.ToString('o')
        ownerSid = $ownerSid
    }
    foreach ($key in $Fields.Keys) {
        $k = [string]$key
        $v = [string]$Fields[$key]
        if ($k -cmatch '^[a-zA-Z0-9_]{1,64}$' -and $v -cmatch '^[a-zA-Z0-9_\-\.:]{0,512}$') {
            $record[$k] = $v
        }
    }
    $line = ($record | ConvertTo-Json -Compress)
    [IO.File]::AppendAllText($journalPath, $line + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Acquire-BootstrapLock {
    Assert-NoReparse $lockRoot
    if (-not (Test-Path -LiteralPath $lockRoot -PathType Container)) {
        New-ProtectedDirectoryAcl $lockRoot
    }
    try {
        $script:LockStream = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        throw 'BUSY'
    }
}

function Release-BootstrapLock {
    if ($null -ne $script:LockStream) {
        try { $script:LockStream.Dispose() } catch { }
        $script:LockStream = $null
    }
}

function Get-TaskService {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $service
}

function Get-ExpectedV2Arguments([string]$WorkerSha, [string]$WorkerPath, [string]$PowerShellPath) {
    '-NoLogo -NoProfile -NonInteractive -File "' + $WorkerPath + '" -WorkerSha256 ' + $WorkerSha
}

function Get-ExpectedV1Arguments([string]$WorkerSha, [string]$WorkerPath) {
    '-NoLogo -NoProfile -NonInteractive -File "' + $WorkerPath + '" -WorkerSha256 ' + $WorkerSha
}

function Assert-V1WorkerInstalled {
    if (-not (Test-Path -LiteralPath $v1WorkerInstalled -PathType Leaf)) { throw 'V1_WORKER_MISSING' }
    Assert-ProtectedDirectory $binRoot
    $sha = (Get-FileHash -LiteralPath $v1WorkerInstalled -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -cne $acceptedV1WorkerSha256) { throw 'V1_WORKER_PROVENANCE_MISMATCH' }
    $sha
}

function Assert-V1TaskQuiescent([string]$OwnerSid, [string]$V1Sha) {
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
  if (-not $task) { throw 'V1_TASK_MISSING' }
    $definition = $task.Definition
    if ($definition.Triggers.Count -ne 0) { throw 'TASK_TRIGGER_REFUSED' }
    if ($definition.Actions.Count -ne 1) { throw 'TASK_ACTION_COUNT_REFUSED' }
    if (-not $definition.Settings.Enabled) { throw 'V1_TASK_DISABLED' }
    if ($definition.Settings.StartWhenAvailable) { throw 'TASK_SETTINGS_REFUSED' }
    $action = $definition.Actions.Item(1)
    if ($action.WorkingDirectory) { throw 'TASK_ACTION_REFUSED' }
    $argsV1 = Get-ExpectedV1Arguments $V1Sha $v1WorkerInstalled
    if ($action.Arguments -cne $argsV1) { throw 'V1_TASK_ARGUMENT_MISMATCH' }
    $principal = $definition.Principal
    $sid = if ([string]$principal.UserId.StartsWith('S-')) {
        $principal.UserId
    } else {
        ([Security.Principal.NTAccount]::new($principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($sid -cne $OwnerSid -or $principal.LogonType -ne 3 -or $principal.RunLevel -ne 1) {
        throw 'TASK_PRINCIPAL_REFUSED'
    }
    [pscustomobject]@{
        Enabled = [bool]$definition.Settings.Enabled
        ActionPath = [string]$action.Path
        ActionArguments = [string]$action.Arguments
    }
}

function Install-V2WorkerFromBundle {
    $bundleWorker = Join-Path $protectedStagingRoot $workerBundleName
    if (-not (Test-Path -LiteralPath $bundleWorker -PathType Leaf)) { throw 'V2_WORKER_BUNDLE_MISSING' }
    $bundleSha = (Get-FileHash -LiteralPath $bundleWorker -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bundleSha -cne $acceptedV2WorkerSha256) { throw 'V2_WORKER_PROVENANCE_MISMATCH' }
    $targetDir = Split-Path $v2WorkerInstalled -Parent
    if (Test-Path -LiteralPath $targetDir) { throw 'V2_WORKER_ALREADY_STAGED' }
    New-ProtectedDirectoryAcl $targetDir
    Copy-Item -LiteralPath $bundleWorker -Destination $v2WorkerInstalled -Force
    $installedSha = (Get-FileHash -LiteralPath $v2WorkerInstalled -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedSha -cne $acceptedV2WorkerSha256) { throw 'V2_WORKER_INSTALL_MISMATCH' }
    $installedSha
}

function Register-V2Task([string]$OwnerSid, [string]$V2Sha) {
    $powershellPath = Get-SystemPowerShellExecutable
    Assert-WindowsAppsRuntimeRefused $powershellPath
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
    $definition = $task.Definition
    $priorEnabled = [bool]$definition.Settings.Enabled
    $action = $definition.Actions.Item(1)
    $priorPath = [string]$action.Path
    $priorArgs = [string]$action.Arguments
    $newArgs = Get-ExpectedV2Arguments $V2Sha $v2WorkerInstalled $powershellPath
    $action.Path = $powershellPath
    $action.Arguments = $newArgs
    $action.WorkingDirectory = ''
    $taskSddl = $task.GetSecurityDescriptor(0xF)
    $name = $taskName.TrimStart('\')
    $folder.RegisterTaskDefinition($name, $definition, 0x06, $OwnerSid, $null, 3, $taskSddl) | Out-Null
    $readback = $folder.GetTask($taskName)
    $rbDef = $readback.Definition
    $rbAction = $rbDef.Actions.Item(1)
    if ([string]$rbAction.Path -cne $powershellPath -or [string]$rbAction.Arguments -cne $newArgs) {
        throw 'V2_TASK_READBACK_AMBIGUOUS'
    }
    Assert-WindowsAppsRuntimeRefused ([string]$rbAction.Path)
    [pscustomobject]@{
        PriorEnabled = $priorEnabled
        PriorPath = $priorPath
        PriorArguments = $priorArgs
        PowerShellPath = $powershellPath
        Arguments = $newArgs
    }
}

function Restore-V1Task([string]$OwnerSid, [object]$Snapshot, [string]$V1Sha) {
    if ($null -eq $Snapshot) { return }
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
    $definition = $task.Definition
    $definition.Settings.Enabled = $Snapshot.Enabled
    $action = $definition.Actions.Item(1)
    $action.Path = $Snapshot.ActionPath
    $action.Arguments = $Snapshot.ActionArguments
    $action.WorkingDirectory = ''
    $expectedV1 = Get-ExpectedV1Arguments $V1Sha $v1WorkerInstalled
    if ($action.Arguments -cne $expectedV1) { $action.Arguments = $Snapshot.ActionArguments }
    $taskSddl = $task.GetSecurityDescriptor(0xF)
    $name = $taskName.TrimStart('\')
    $folder.RegisterTaskDefinition($name, $definition, 0x06, $OwnerSid, $null, 3, $taskSddl) | Out-Null
}

function Remove-StagedV2Worker {
    $targetDir = Split-Path $v2WorkerInstalled -Parent
    if (Test-Path -LiteralPath $targetDir) {
        Remove-Item -LiteralPath $targetDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Disable-TaskHold {
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
    $definition = $task.Definition
    $definition.Settings.Enabled = $false
    $ownerSid = Get-OwnerSid
    $taskSddl = $task.GetSecurityDescriptor(0xF)
    $name = $taskName.TrimStart('\')
    $folder.RegisterTaskDefinition($name, $definition, 0x06, $ownerSid, $null, 3, $taskSddl) | Out-Null
}

function Assert-BootstrapProvenance {
    $actual = [IO.Path]::GetFullPath($PSCommandPath)
    $expected = [IO.Path]::GetFullPath($expectedBootstrapPath)
    if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'BOOTSTRAP_PATH_REFUSED'
    }
    Assert-ProtectedDirectory $protectedStagingRoot
    if (-not (Test-Path -LiteralPath $actual -PathType Leaf)) { throw 'BOOTSTRAP_FILE_MISSING' }
}

function Assert-NoReplay {
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) { throw 'BOOTSTRAP_ALREADY_CONSUMED' }
}

function Write-ConsumedReceipt([string]$V1Sha, [string]$V2Sha) {
    $payload = [ordered]@{
        schema = 1
        consumedUtc = [DateTime]::UtcNow.ToString('o')
        v1WorkerSha256 = $V1Sha
        v2WorkerSha256 = $V2Sha
        bootstrapSha256 = $acceptedBootstrapSha256
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($receiptPath, $payload + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

try {
    Assert-Elevated
    Assert-NoReplay
    Assert-BootstrapProvenance
    $ownerSid = Get-OwnerSid
    Assert-NoReparse $controlRoot
    foreach ($path in @($controlRoot, $binRoot, $lockRoot, $journalRoot)) {
        if (Test-Path -LiteralPath $path) { Assert-ProtectedDirectory $path }
    }
    if (-not (Test-Path -LiteralPath $journalRoot)) { New-ProtectedDirectoryAcl $journalRoot }
    $script:JournalEnabled = $true

    Acquire-BootstrapLock
    $v1Sha = Assert-V1WorkerInstalled
    $script:V1Snapshot = Assert-V1TaskQuiescent $ownerSid $v1Sha
    Write-Journal 'SNAPSHOT' @{ v1WorkerSha256 = $v1Sha; v1TaskActionPath = $script:V1Snapshot.ActionPath }

    $v2Sha = Install-V2WorkerFromBundle
    Write-Journal 'PREPARED' @{ v2WorkerSha256 = $v2Sha; v2WorkerPath = $v2WorkerInstalled }

    $update = Register-V2Task $ownerSid $v2Sha
    Write-Journal 'COMMITTED' @{
        v2WorkerSha256 = $v2Sha
        v2TaskPowerShell = $update.PowerShellPath
        priorV1ActionPath = $update.PriorPath
    }

    Write-ConsumedReceipt $v1Sha $v2Sha
    'ADMIN_BROKER_V2_BOOTSTRAP=PASS'
    'V1_WORKER_SHA256=' + $v1Sha
    'V2_WORKER_SHA256=' + $v2Sha
    'V2_TASK_POWERSHELL=' + $update.PowerShellPath
} catch {
    $msg = $_.Exception.Message
    if ($msg -eq 'V2_TASK_READBACK_AMBIGUOUS') {
        try { Disable-TaskHold } catch { }
        Write-Journal 'HOLD' @{ reason = 'TASK_UPDATE_AMBIGUOUS' }
        throw 'HOLD_TASK_UPDATE_AMBIGUOUS'
    }
    try { Remove-StagedV2Worker } catch { }
    if ($null -ne $script:V1Snapshot) {
        try {
            $v1ShaRollback = Assert-V1WorkerInstalled
            Restore-V1Task $ownerSid $script:V1Snapshot $v1ShaRollback
        } catch { }
    }
    Write-Journal 'HOLD' @{ reason = $msg }
    throw
} finally {
    Release-BootstrapLock
}
