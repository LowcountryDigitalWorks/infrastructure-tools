# One-time closed protected V2 publisher bootstrap. Self-contained: no imports, dot-source, child scripts,
# parameters, network, git, or caller-controlled paths. Execute only from protected staging with zero arguments.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$acceptedV1WorkerSha256 = 'db71da0a73f2943eb8837e7c1e7070a22251478e4acfba91338837c7fc699605'
$reviewManifestFileName = 'AdminBrokerV2BootstrapReviewManifest.json'
$v2WorkerIdentity = 'v2-publisher-reviewed-1'
$bootstrapStagingLeaf = 'v2-publisher-once'
$bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$taskName = '\LDW-ADMIN-REVIEWED-OPERATION'

$controlRoot = $null
$binRoot = $null
$lockRoot = $null
$journalRoot = $null
$v1WorkerInstalled = $null
$v2WorkerInstalled = $null
$protectedStagingRoot = $null
$expectedBootstrapPath = $null
$requestRoot = $null
$resultRoot = $null
$operationLockPath = $null
$lockPath = $null
$journalPath = $null
$receiptPath = $null
$script:BootstrapLayoutInitialized = $false
$v1InFlightMinutes = 15
$v1ResultsScanMaxFiles = 64

$script:LockStream = $null
$script:JournalEnabled = $false
$script:V1Snapshot = $null
$script:ReviewedBootstrapSha256 = $null
$script:ReviewedWorkerSha256 = $null

function Assert-Elevated {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATION_REQUIRED'
    }
}

function Get-MachineProgramDataRoot {
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($known)) { throw 'COMMONAPPLICATIONDATA_REQUIRED' }
    $full = [IO.Path]::GetFullPath($known)
    if ([IO.Path]::GetFileName($full.TrimEnd('\')) -cne 'ProgramData') { throw 'COMMONAPPLICATIONDATA_PATH_REFUSED' }
    $machineVar = [Environment]::GetEnvironmentVariable('ProgramData', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($machineVar)) {
        if ([IO.Path]::GetFullPath($machineVar) -cne $full) { throw 'PROGRAMDATA_MACHINE_MISMATCH' }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        if ([IO.Path]::GetFullPath($env:ProgramData) -cne $full) { throw 'PROGRAMDATA_ENV_SPOOFED' }
    }
    Assert-NoReparse $full
    $full
}

function Assert-WindowsProgramDataRootBaselineAcl([string]$ProgramDataRoot) {
    $canonical = Get-MachineProgramDataRoot
    $resolved = [IO.Path]::GetFullPath($ProgramDataRoot)
    if ($resolved -cne $canonical) { throw 'COMMONAPPLICATIONDATA_PATH_REFUSED' }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw 'PROTECTED_PATH_MISSING' }
    $acl = Get-Acl -LiteralPath $resolved
    if (-not $acl.AreAccessRulesProtected) { throw 'PROGRAMDATA_ROOT_BASELINE_HOLD' }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'LDW_PARENT_OWNER_REFUSED' }
    $dangerous = [int](
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [Security.AccessControl.FileSystemRights]::FullControl)
    $genericAll = 268435456
    $stockUsersWrite = 278
    $stockUsersRx = 1179817
    $usersSid = 'S-1-5-32-545'
    $creatorOwnerSid = 'S-1-3-0'
    $trustedSids = @('S-1-5-18', 'S-1-5-32-544')
    $containerInherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit
    $inheritOnly = [Security.AccessControl.PropagationFlags]::InheritOnly
    $writeSurface = [int](
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories)
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $rights = [int][Security.AccessControl.FileSystemRights]$rule.FileSystemRights
        $inh = $rule.InheritanceFlags
        $prop = $rule.PropagationFlags
        if ($sid -in $trustedSids) { continue }
        if ($rights -band $dangerous) { throw 'PROGRAMDATA_ROOT_BASELINE_HOLD' }
        if ($rights -eq $genericAll) {
            if ($sid -ceq $creatorOwnerSid -and ($prop -band $inheritOnly) -ne 0) { continue }
            throw 'PROGRAMDATA_ROOT_BASELINE_HOLD'
        }
        if ($sid -ceq $creatorOwnerSid) { throw 'PROGRAMDATA_ROOT_BASELINE_HOLD' }
        if ($sid -ceq $usersSid) {
            if (($inh -band $containerInherit) -eq 0) { throw 'PROGRAMDATA_ROOT_BASELINE_HOLD' }
            if (($prop -band $inheritOnly) -ne 0) { throw 'PROGRAMDATA_ROOT_BASELINE_HOLD' }
            if ($rights -eq $stockUsersWrite -or $rights -eq $stockUsersRx) { continue }
            throw 'PROGRAMDATA_ROOT_BASELINE_HOLD'
        }
        if ($rights -band $writeSurface) { throw 'PROGRAMDATA_ROOT_BASELINE_HOLD' }
    }
}

function Assert-TrustedDirectoryAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw 'PROTECTED_PATH_MISSING' }
    Assert-NoReparse $Path
    $resolved = [IO.Path]::GetFullPath($Path)
    $acl = Get-Acl -LiteralPath $resolved
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'LDW_PARENT_OWNER_REFUSED' }
    $forbidden = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -in @('S-1-5-18', 'S-1-5-32-544')) { continue }
        if ($rule.FileSystemRights -band $forbidden) { throw 'LDW_PARENT_ACL_HOLD' }
    }
}

function Assert-LdwParentPreflight([string]$ProgramDataRoot, [string]$LdwRoot) {
    Assert-WindowsProgramDataRootBaselineAcl $ProgramDataRoot
    if (Test-Path -LiteralPath $LdwRoot) { Assert-TrustedDirectoryAcl $LdwRoot }
}

function Initialize-BootstrapLayout {
    if ($script:BootstrapLayoutInitialized) { return }
    $programDataRoot = Get-MachineProgramDataRoot
    $ldwRoot = Join-Path $programDataRoot 'LDW'
    Assert-LdwParentPreflight $programDataRoot $ldwRoot
    $script:controlRoot = Join-Path $ldwRoot 'PrivilegedControl'
    $script:binRoot = Join-Path $script:controlRoot 'bin'
    $script:lockRoot = Join-Path $script:controlRoot 'lock'
    $script:journalRoot = Join-Path $script:controlRoot 'journal'
    $script:v1WorkerInstalled = Join-Path $script:binRoot 'Invoke-AdminPrivilegedOperation.ps1'
    $script:v2WorkerInstalled = Join-Path $script:binRoot ('v2/' + $v2WorkerIdentity + '/' + $workerBundleName)
    $script:protectedStagingRoot = Join-Path $script:controlRoot ('bootstrap-staging/' + $bootstrapStagingLeaf)
    $script:expectedBootstrapPath = Join-Path $script:protectedStagingRoot $bootstrapFileName
    $script:requestRoot = Join-Path $script:controlRoot 'requests'
    $script:resultRoot = Join-Path $script:controlRoot 'results'
    $script:operationLockPath = Join-Path $script:lockRoot 'operation.lock'
    $script:lockPath = Join-Path $script:lockRoot 'v2-publisher-bootstrap.lock'
    $script:journalPath = Join-Path $script:journalRoot 'v2-publisher-bootstrap.jsonl'
    $script:receiptPath = Join-Path $script:journalRoot 'v2-bootstrap-consumed.receipt'
    $script:BootstrapLayoutInitialized = $true
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
    if (-not [Environment]::Is64BitProcess) { throw 'POWERSHELL_HOST_BITNESS_REFUSED' }
    $windir = [Environment]::GetEnvironmentVariable('WINDIR', 'Machine')
    if ([string]::IsNullOrWhiteSpace($windir)) { throw 'WINDIR_REQUIRED' }
    $candidate = Join-Path (Join-Path $windir 'System32') 'WindowsPowerShell\v1.0\powershell.exe'
    $full = [IO.Path]::GetFullPath($candidate)
    if ($full -notmatch '(?i)\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$') { throw 'SYSTEM_POWERSHELL_PATH_REFUSED' }
    if ($full -match '(?i)SysWOW64') { throw 'SYSWOW64_RUNTIME_REFUSED' }
    if ($full -match '(?i)WindowsApps' -or $full -match '(?i)AppData\\Local\\Microsoft\\WindowsApps') {
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
    if ($norm -notmatch '(?i)\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$') {
        throw 'V2_TASK_RUNTIME_PATH_REFUSED'
    }
    if ($norm -match '(?i)SysWOW64') { throw 'SYSWOW64_RUNTIME_REFUSED' }
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
    Assert-TrustedDirectoryAcl $Path
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

function Test-OperationLockIdle {
    Assert-NoReparse $lockRoot
    if (-not (Test-Path -LiteralPath $operationLockPath -PathType Leaf)) { return }
    try {
        $probe = [IO.File]::Open($operationLockPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        $probe.Dispose()
    } catch {
        throw 'V1_OPERATION_LOCK_HELD'
    }
}

function Assert-V1OperationsQuiescent {
    Test-OperationLockIdle
    if (Test-Path -LiteralPath $requestRoot) {
        Assert-NoReparse $requestRoot
        if (Test-Path -LiteralPath (Join-Path $requestRoot 'request.json') -PathType Leaf) {
            throw 'PENDING_REQUEST_REFUSED'
        }
    }
    if (Test-Path -LiteralPath $resultRoot) {
        Assert-ProtectedDirectory $resultRoot
        $cutoff = [DateTime]::UtcNow.AddMinutes(-$v1InFlightMinutes)
        $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$'
        $files = @(Get-ChildItem -LiteralPath $resultRoot -File -ErrorAction Stop)
        if ($files.Count -gt $v1ResultsScanMaxFiles) { throw 'V1_RESULTS_BOUND_EXCEEDED' }
        foreach ($file in $files) {
            if ($file.Name -cnotmatch $guidPattern) { continue }
            if ($file.LastWriteTimeUtc -le $cutoff) { continue }
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            if ($bytes.Length -lt 2 -or $bytes.Length -gt 16384) { throw 'V1_RESULT_INVALID' }
            $text = [Text.Encoding]::UTF8.GetString($bytes)
            try {
                $doc = $text | ConvertFrom-Json -ErrorAction Stop
            } catch {
                throw 'V1_RESULT_INVALID'
            }
            $state = [string]$doc.resultState
            if ($state -ceq 'STARTED') { throw 'ACTIVE_OPERATION_REFUSED' }
        }
    }
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
    if (-not $task) { throw 'V1_TASK_MISSING' }
    $runState = [int]$task.State
    if ($runState -eq 4 -or $runState -eq 2) { throw 'ACTIVE_TASK_REFUSED' }
}

function Assert-V1TaskQuiescent([string]$OwnerSid, [string]$V1Sha) {
    Assert-V1OperationsQuiescent
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

function Install-V2WorkerFromBundle([string]$ExpectedWorkerSha256) {
    $bundleWorker = Join-Path $protectedStagingRoot $workerBundleName
    if (-not (Test-Path -LiteralPath $bundleWorker -PathType Leaf)) { throw 'V2_WORKER_BUNDLE_MISSING' }
    $bundleSha = Assert-ProtectedArtifactSha256 $bundleWorker $ExpectedWorkerSha256 'V2_WORKER_PROVENANCE_MISMATCH'
    $targetDir = Split-Path $v2WorkerInstalled -Parent
    if (Test-Path -LiteralPath $targetDir) { throw 'V2_WORKER_ALREADY_STAGED' }
    New-ProtectedDirectoryAcl $targetDir
    Copy-Item -LiteralPath $bundleWorker -Destination $v2WorkerInstalled -Force
    $installedSha = (Get-FileHash -LiteralPath $v2WorkerInstalled -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($installedSha -cne $ExpectedWorkerSha256) { throw 'V2_WORKER_INSTALL_MISMATCH' }
    $installedSha
}

function Register-V2Task([string]$OwnerSid, [string]$V2Sha) {
    $powershellPath = Get-SystemPowerShellExecutable
    Assert-WindowsAppsRuntimeRefused $powershellPath
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
    $definition = $task.Definition
    if ([bool]$definition.Settings.Enabled) { throw 'TASK_MUST_BE_HELD_BEFORE_UPDATE' }
    $priorEnabled = if ($null -ne $script:V1Snapshot) { [bool]$script:V1Snapshot.Enabled } else { [bool]$definition.Settings.Enabled }
    $action = $definition.Actions.Item(1)
    $priorPath = [string]$action.Path
    $priorArgs = [string]$action.Arguments
    $newArgs = Get-ExpectedV2Arguments $V2Sha $v2WorkerInstalled $powershellPath
    $action.Path = $powershellPath
    $action.Arguments = $newArgs
    $action.WorkingDirectory = ''
    $definition.Settings.Enabled = $true
    $taskSddl = $task.GetSecurityDescriptor(0xF)
    $name = $taskName.TrimStart('\')
    $folder.RegisterTaskDefinition($name, $definition, 0x06, $OwnerSid, $null, 3, $taskSddl) | Out-Null
    $readback = $folder.GetTask($taskName)
    $rbDef = $readback.Definition
    $rbAction = $rbDef.Actions.Item(1)
    if ([string]$rbAction.Path -cne $powershellPath -or [string]$rbAction.Arguments -cne $newArgs) {
        throw 'V2_TASK_READBACK_AMBIGUOUS'
    }
    if (-not [bool]$rbDef.Settings.Enabled) { throw 'V2_TASK_READBACK_AMBIGUOUS' }
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
    if ($null -eq $Snapshot) { throw 'V1_SNAPSHOT_MISSING' }
    $expectedV1 = Get-ExpectedV1Arguments $V1Sha $v1WorkerInstalled
    if ($Snapshot.ActionArguments -cne $expectedV1) { throw 'V1_TASK_RESTORE_PROVENANCE_MISMATCH' }
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
    $definition = $task.Definition
    $definition.Settings.Enabled = $Snapshot.Enabled
    $action = $definition.Actions.Item(1)
    $action.Path = $Snapshot.ActionPath
    $action.Arguments = $Snapshot.ActionArguments
    $action.WorkingDirectory = ''
    $taskSddl = $task.GetSecurityDescriptor(0xF)
    $name = $taskName.TrimStart('\')
    $folder.RegisterTaskDefinition($name, $definition, 0x06, $OwnerSid, $null, 3, $taskSddl) | Out-Null
    $readback = $folder.GetTask($taskName)
    $rbDef = $readback.Definition
    $rbAction = $rbDef.Actions.Item(1)
    if ([string]$rbAction.Path -cne [string]$Snapshot.ActionPath -or [string]$rbAction.Arguments -cne $expectedV1) {
        throw 'V1_TASK_RESTORE_AMBIGUOUS'
    }
    if ([bool]$rbDef.Settings.Enabled -cne [bool]$Snapshot.Enabled) {
        throw 'V1_TASK_RESTORE_AMBIGUOUS'
    }
}

function Invoke-V1TaskRollback([string]$OwnerSid, [string]$V1Sha) {
    if ($null -eq $script:V1Snapshot) { throw 'V1_ROLLBACK_SNAPSHOT_MISSING' }
    try {
        Disable-TaskHold
    } catch {
        throw 'V1_ROLLBACK_DISABLE_FAILED'
    }
    Restore-V1Task $OwnerSid $script:V1Snapshot $V1Sha
}

function Remove-StagedV2Worker {
    $targetDir = Split-Path $v2WorkerInstalled -Parent
    if (Test-Path -LiteralPath $targetDir) {
        Remove-Item -LiteralPath $targetDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Read-ReviewManifest {
    $path = Join-Path $protectedStagingRoot $reviewManifestFileName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'REVIEW_MANIFEST_MISSING' }
    Assert-NoReparse $path
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 8192) { throw 'REVIEW_MANIFEST_INVALID' }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text.IndexOf([char]0) -ge 0) { throw 'REVIEW_MANIFEST_INVALID' }
    try {
        $doc = $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'REVIEW_MANIFEST_INVALID'
    }
    if ($null -eq $doc) { throw 'REVIEW_MANIFEST_INVALID' }
    $topProps = @($doc.PSObject.Properties.Name)
    if (@(Compare-Object @('schema', 'protocol', 'artifacts') $topProps -CaseSensitive).Count) {
        throw 'REVIEW_MANIFEST_INVALID'
    }
    if ($doc.schema -ne 1) { throw 'REVIEW_MANIFEST_INVALID' }
    if ($doc.protocol -cne 'ldw.admin-broker.v2-bootstrap.review-manifest.v1') { throw 'REVIEW_MANIFEST_INVALID' }
    $items = @($doc.artifacts)
    if ($items.Count -ne 2) { throw 'REVIEW_MANIFEST_INVALID' }
    $map = @{}
    foreach ($item in $items) {
        $itemProps = @($item.PSObject.Properties.Name)
        if (@(Compare-Object @('name', 'sha256') $itemProps -CaseSensitive).Count) { throw 'REVIEW_MANIFEST_INVALID' }
        $name = [string]$item.name
        $sha = [string]$item.sha256
        if ($name -cnotin @($bootstrapFileName, $workerBundleName)) { throw 'REVIEW_MANIFEST_INVALID' }
        if ($sha -cnotmatch '^[a-f0-9]{64}$') { throw 'REVIEW_MANIFEST_INVALID' }
        if ($map.ContainsKey($name)) { throw 'REVIEW_MANIFEST_INVALID' }
        $map[$name] = $sha.ToLowerInvariant()
    }
    if ($map.Count -ne 2) { throw 'REVIEW_MANIFEST_INVALID' }
    return [pscustomobject]@{
        BootstrapSha256 = $map[$bootstrapFileName]
        WorkerSha256 = $map[$workerBundleName]
    }
}

function Assert-ProtectedArtifactSha256([string]$Path, [string]$ExpectedSha256, [string]$MismatchCode) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'ARTIFACT_MISSING' }
    Assert-NoReparse $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) { throw $MismatchCode }
    $actual
}

function Disable-TaskHold {
    $ownerSid = Get-OwnerSid
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $folder.GetTask($taskName)
    $definition = $task.Definition
    $definition.Settings.Enabled = $false
    $taskSddl = $task.GetSecurityDescriptor(0xF)
    $name = $taskName.TrimStart('\')
    $folder.RegisterTaskDefinition($name, $definition, 0x06, $ownerSid, $null, 3, $taskSddl) | Out-Null
    $readback = $folder.GetTask($taskName)
    if ([bool]$readback.Definition.Settings.Enabled) { throw 'TASK_DISABLE_HOLD_FAILED' }
}

function Assert-BootstrapProvenance {
    $actual = [IO.Path]::GetFullPath($PSCommandPath)
    $expected = [IO.Path]::GetFullPath($expectedBootstrapPath)
    if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'BOOTSTRAP_PATH_REFUSED'
    }
    Assert-ProtectedDirectory $protectedStagingRoot
    $manifest = Read-ReviewManifest
    $script:ReviewedBootstrapSha256 = $manifest.BootstrapSha256
    $script:ReviewedWorkerSha256 = $manifest.WorkerSha256
    Assert-ProtectedArtifactSha256 $actual $manifest.BootstrapSha256 'BOOTSTRAP_SHA256_MISMATCH' | Out-Null
    $bundleWorker = Join-Path $protectedStagingRoot $workerBundleName
    Assert-ProtectedArtifactSha256 $bundleWorker $manifest.WorkerSha256 'V2_WORKER_BUNDLE_MISMATCH' | Out-Null
}

function Assert-NoReplay {
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) { throw 'BOOTSTRAP_ALREADY_CONSUMED' }
}

function Write-ConsumedReceipt([string]$V1Sha, [string]$V2Sha) {
    if (-not $script:ReviewedBootstrapSha256 -or $script:ReviewedBootstrapSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'REVIEW_MANIFEST_REQUIRED'
    }
    $payload = [ordered]@{
        schema = 1
        consumedUtc = [DateTime]::UtcNow.ToString('o')
        v1WorkerSha256 = $V1Sha
        v2WorkerSha256 = $V2Sha
        bootstrapSha256 = $script:ReviewedBootstrapSha256
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($receiptPath, $payload + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

try {
    Assert-Elevated
    Initialize-BootstrapLayout
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

    Disable-TaskHold
    Write-Journal 'HOLD' @{ reason = 'V1_TASK_HELD_BEFORE_MUTATION' }

    $v2Sha = Install-V2WorkerFromBundle $script:ReviewedWorkerSha256
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
        try { Remove-StagedV2Worker } catch { throw 'V2_STAGED_REMOVE_FAILED' }
        if ($null -ne $script:V1Snapshot) {
            $v1ShaRollback = Assert-V1WorkerInstalled
            try {
                Invoke-V1TaskRollback $ownerSid $v1ShaRollback
            } catch {
                $rollbackCode = $_.Exception.Message
                if ($rollbackCode -notmatch '^[A-Z0-9_]+$') { $rollbackCode = 'V1_ROLLBACK_FAILED' }
                Write-Journal 'HOLD' @{ reason = 'TASK_UPDATE_AMBIGUOUS_ROLLBACK_FAILED'; rollbackCode = $rollbackCode }
                throw $rollbackCode
            }
        }
        Write-Journal 'HOLD' @{ reason = 'TASK_UPDATE_AMBIGUOUS_V1_RESTORED' }
        throw 'HOLD_TASK_UPDATE_AMBIGUOUS'
    }
    try { Remove-StagedV2Worker } catch { }
    if ($null -ne $script:V1Snapshot) {
        $v1ShaRollback = Assert-V1WorkerInstalled
        try {
            Invoke-V1TaskRollback $ownerSid $v1ShaRollback
            Write-Journal 'HOLD' @{ reason = 'FAILURE_V1_ROLLBACK_VERIFIED' }
        } catch {
            $rollbackCode = $_.Exception.Message
            if ($rollbackCode -notmatch '^[A-Z0-9_]+$') { $rollbackCode = 'V1_ROLLBACK_FAILED' }
            Write-Journal 'HOLD' @{ reason = 'FAILURE_ROLLBACK_FAILED'; rollbackCode = $rollbackCode }
            throw $rollbackCode
        }
    } else {
        Write-Journal 'HOLD' @{ reason = $msg }
    }
    throw
} finally {
    Release-BootstrapLock
}
