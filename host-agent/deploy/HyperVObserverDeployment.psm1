Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ManifestFileName = 'deployment-manifest.json'
$script:RequiredPublishFiles = @(
    'LDW.HostAgent.Core.dll',
    'LDW.HostAgent.HyperVObserver.deps.json',
    'LDW.HostAgent.HyperVObserver.dll',
    'LDW.HostAgent.HyperVObserver.exe',
    'LDW.HostAgent.HyperVObserver.runtimeconfig.json'
)

function Get-HyperVObserverDeploymentConstants {
    if ([string]::IsNullOrWhiteSpace($env:ProgramFiles) -or [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        throw 'ProgramFiles and ProgramData must be available on the Windows host.'
    }

    $installRoot = Join-Path $env:ProgramFiles 'LowcountryDigitalWorks\HostAgent\HyperVObserver'
    $configRoot = Join-Path $env:ProgramData 'LowcountryDigitalWorks\HostAgent\HyperVObserver'

    [pscustomobject]@{
        TaskName = 'HyperVObserver'
        TaskPath = '\LowcountryDigitalWorks\HostAgent\'
        TaskDescription = 'LDW Host Agent read-only Hyper-V observer helper for CI-RUNNER-001.'
        InstallRoot = $installRoot
        ReleasesRoot = Join-Path $installRoot 'releases'
        ConfigRoot = $configRoot
        ConfigPath = Join-Path $configRoot 'hyperv-observer.Local.json'
        StatePath = Join-Path $configRoot 'deployment-state.Local.json'
        ManifestFileName = $script:ManifestFileName
    }
}

function Assert-HyperVObserverElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This deployment action must run from an elevated PowerShell session.'
    }
}

function Assert-HyperVObserverLocalAbsolutePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Name must be an absolute local path."
    }

    if ($Path.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw "$Name must be local, not UNC/network storage."
    }
}

function Assert-HyperVObserverSafeExplicitUserSid {
    param([Parameter(Mandatory)][string]$Sid)

    if ($Sid -notmatch '^S-1-5-21-(\d+-){3}\d+$') {
        throw 'PermittedCallerSid must be an explicit machine/domain-style user SID.'
    }

    $parsed = [Security.Principal.SecurityIdentifier]::new($Sid)
    if ($parsed.IsWellKnown([Security.Principal.WellKnownSidType]::LocalSystemSid) -or
        $parsed.IsWellKnown([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)) {
        throw 'PermittedCallerSid must not be a well-known privileged principal.'
    }
}

function Get-HyperVObserverPublishEntries {
    param([Parameter(Mandatory)][string]$Directory)

    Assert-HyperVObserverLocalAbsolutePath -Path $Directory -Name 'PublishedDirectory'
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw 'PublishedDirectory does not exist.'
    }

    $items = @(Get-ChildItem -LiteralPath $Directory -Force)
    $directories = @($items | Where-Object { $_.PSIsContainer })
    if ($directories.Count -ne 0) {
        throw 'PublishedDirectory must contain only the bounded root-level helper publish files; subdirectories are not allowed.'
    }

    $payload = @($items | Where-Object { -not $_.PSIsContainer -and $_.Name -ne $script:ManifestFileName })
    foreach ($item in $payload) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "PublishedDirectory contains a reparse-point file '$($item.Name)'."
        }
    }

    $names = @($payload.Name | Sort-Object)
    $required = @($script:RequiredPublishFiles | Sort-Object)
    if (($names -join "`n") -ne ($required -join "`n")) {
        $unexpected = @($names | Where-Object { $_ -notin $required })
        $missing = @($required | Where-Object { $_ -notin $names })
        $detail = @()
        if ($unexpected.Count) { $detail += 'unexpected=' + ($unexpected -join ',') }
        if ($missing.Count) { $detail += 'missing=' + ($missing -join ',') }
        throw 'PublishedDirectory file set is outside the accepted helper boundary (' + ($detail -join '; ') + ').'
    }

    @($payload | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            name = $_.Name
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
}

function Get-HyperVObserverReleaseFingerprint {
    param([Parameter(Mandatory)][object[]]$Entries)

    $canonical = (@($Entries | Sort-Object name | ForEach-Object {
        ([string]$_.name) + '|' + ([string]$_.sha256).ToLowerInvariant()
    }) -join "`n") + "`n"

    $bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    [Convert]::ToHexString($hash).ToLowerInvariant()
}

function New-HyperVObserverDeploymentManifest {
    param([Parameter(Mandatory)][string]$Directory)

    $constants = Get-HyperVObserverDeploymentConstants
    $manifestPath = Join-Path $Directory $constants.ManifestFileName
    if (Test-Path -LiteralPath $manifestPath) {
        throw 'Deployment manifest already exists; use a fresh publish directory.'
    }

    $entries = @(Get-HyperVObserverPublishEntries -Directory $Directory)
    $fingerprint = Get-HyperVObserverReleaseFingerprint -Entries $entries
    $manifest = [ordered]@{
        schemaVersion = 1
        releaseId = $fingerprint.Substring(0, 16)
        releaseFingerprintSha256 = $fingerprint
        files = $entries
    }

    [IO.File]::WriteAllText(
        $manifestPath,
        (($manifest | ConvertTo-Json -Depth 5) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))

    [pscustomobject]@{
        ManifestPath = $manifestPath
        ReleaseId = $manifest.releaseId
        ReleaseFingerprintSha256 = $fingerprint
        Entries = $entries
    }
}

function Test-HyperVObserverDeploymentManifest {
    param([Parameter(Mandatory)][string]$Directory)

    $constants = Get-HyperVObserverDeploymentConstants
    $manifestPath = Join-Path $Directory $constants.ManifestFileName
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'PublishedDirectory is missing deployment-manifest.json.'
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 8
    }
    catch {
        throw 'deployment-manifest.json is not valid JSON.'
    }

    if ([int]$manifest.schemaVersion -ne 1 -or
        ([string]$manifest.releaseId) -notmatch '^[0-9a-f]{16}$' -or
        ([string]$manifest.releaseFingerprintSha256) -notmatch '^[0-9a-f]{64}$') {
        throw 'deployment-manifest.json has an invalid schema or release identity.'
    }

    $actualEntries = @(Get-HyperVObserverPublishEntries -Directory $Directory)
    $actualFingerprint = Get-HyperVObserverReleaseFingerprint -Entries $actualEntries
    if (-not [string]::Equals($actualFingerprint, [string]$manifest.releaseFingerprintSha256, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($actualFingerprint.Substring(0, 16), [string]$manifest.releaseId, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PublishedDirectory content does not match the deployment manifest release identity.'
    }

    $declared = @($manifest.files | Sort-Object name | ForEach-Object { ([string]$_.name) + '|' + ([string]$_.sha256).ToLowerInvariant() })
    $actual = @($actualEntries | Sort-Object name | ForEach-Object { ([string]$_.name) + '|' + ([string]$_.sha256).ToLowerInvariant() })
    if (($declared -join "`n") -ne ($actual -join "`n")) {
        throw 'deployment-manifest.json file inventory does not match PublishedDirectory.'
    }

    [pscustomobject]@{
        ManifestPath = $manifestPath
        ReleaseId = ([string]$manifest.releaseId).ToLowerInvariant()
        ReleaseFingerprintSha256 = $actualFingerprint
        Entries = $actualEntries
    }
}

function New-HyperVObserverDirectorySecurity {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow

    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow))
    }

    $acl
}

function New-HyperVObserverFileSecurity {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $allow = [Security.AccessControl.AccessControlType]::Allow

    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $allow))
    }

    $acl
}

function Test-HyperVObserverAclObject {
    param([Parameter(Mandatory)]$Acl)

    if (-not $Acl.AreAccessRulesProtected) { return $false }
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    $rules = @($Acl.Access)
    if ($rules.Count -ne 2) { return $false }

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { return $false }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin $allowed) { return $false }
        if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            return $false
        }
    }

    return $true
}

function Set-HyperVObserverProtectedDirectoryAcl {
    param([Parameter(Mandatory)][string]$Path)
    Set-Acl -LiteralPath $Path -AclObject (New-HyperVObserverDirectorySecurity)
}

function Set-HyperVObserverProtectedFileAcl {
    param([Parameter(Mandatory)][string]$Path)
    Set-Acl -LiteralPath $Path -AclObject (New-HyperVObserverFileSecurity)
}

function Test-HyperVObserverProtectedPath {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    Test-HyperVObserverAclObject -Acl (Get-Acl -LiteralPath $Path)
}

function Get-HyperVObserverTaskSpec {
    param(
        [Parameter(Mandatory)][string]$InstalledExe,
        [Parameter(Mandatory)][string]$ConfigPath
    )

    $constants = Get-HyperVObserverDeploymentConstants
    [pscustomobject]@{
        TaskName = $constants.TaskName
        TaskPath = $constants.TaskPath
        Description = $constants.TaskDescription
        Execute = [IO.Path]::GetFullPath($InstalledExe)
        Arguments = '--config "' + [IO.Path]::GetFullPath($ConfigPath) + '"'
        UserId = 'SYSTEM'
        RunLevel = 'Highest'
        LogonType = 'ServiceAccount'
        TriggerClass = 'MSFT_TaskBootTrigger'
        Hidden = $true
        StartWhenAvailable = $true
        RestartCount = 3
        RestartIntervalSeconds = 60
        ExecutionTimeLimitSeconds = 0
        MultipleInstances = 'IgnoreNew'
        AllowStartIfOnBatteries = $true
        DontStopIfGoingOnBatteries = $true
    }
}

function Convert-HyperVObserverTaskDurationToSeconds {
    param($Value)
    if ($Value -is [TimeSpan]) { return [double]$Value.TotalSeconds }
    if ($null -eq $Value) { return [double]::NaN }
    try { return [Xml.XmlConvert]::ToTimeSpan([string]$Value).TotalSeconds }
    catch { return [double]::NaN }
}

function Get-HyperVObserverTaskIdentityProblems {
    param(
        [Parameter(Mandatory)]$Task,
        [Parameter(Mandatory)]$Spec
    )

    $problems = [Collections.Generic.List[string]]::new()
    if (-not [string]::Equals([string]$Task.TaskName, [string]$Spec.TaskName, [StringComparison]::Ordinal)) { $problems.Add('task-name') }
    if (-not [string]::Equals([string]$Task.TaskPath, [string]$Spec.TaskPath, [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('task-path') }
    if (-not [string]::Equals([string]$Task.Description, [string]$Spec.Description, [StringComparison]::Ordinal)) { $problems.Add('description') }

    $actions = @($Task.Actions)
    if ($actions.Count -ne 1) {
        $problems.Add('action-count')
    }
    else {
        if (-not [string]::Equals([IO.Path]::GetFullPath([string]$actions[0].Execute), [string]$Spec.Execute, [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('action-execute') }
        if (-not [string]::Equals([string]$actions[0].Arguments, [string]$Spec.Arguments, [StringComparison]::Ordinal)) { $problems.Add('action-arguments') }
    }

    if (-not [string]::Equals([string]$Task.Principal.UserId, [string]$Spec.UserId, [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('principal-user') }
    if (-not [string]::Equals([string]$Task.Principal.RunLevel, [string]$Spec.RunLevel, [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('principal-runlevel') }
    if (-not [string]::Equals([string]$Task.Principal.LogonType, [string]$Spec.LogonType, [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('principal-logontype') }

    $triggers = @($Task.Triggers)
    if ($triggers.Count -ne 1 -or -not [string]::Equals([string]$triggers[0].CimClass.CimClassName, [string]$Spec.TriggerClass, [StringComparison]::Ordinal)) {
        $problems.Add('startup-trigger')
    }

    $settings = $Task.Settings
    if ([bool]$settings.Hidden -ne [bool]$Spec.Hidden) { $problems.Add('hidden') }
    if ([bool]$settings.StartWhenAvailable -ne [bool]$Spec.StartWhenAvailable) { $problems.Add('start-when-available') }
    if ([int]$settings.RestartCount -ne [int]$Spec.RestartCount) { $problems.Add('restart-count') }
    if ([Math]::Abs((Convert-HyperVObserverTaskDurationToSeconds $settings.RestartInterval) - [double]$Spec.RestartIntervalSeconds) -gt 0.01) { $problems.Add('restart-interval') }
    if ([Math]::Abs((Convert-HyperVObserverTaskDurationToSeconds $settings.ExecutionTimeLimit) - [double]$Spec.ExecutionTimeLimitSeconds) -gt 0.01) { $problems.Add('execution-time-limit') }
    if (-not [string]::Equals([string]$settings.MultipleInstances, [string]$Spec.MultipleInstances, [StringComparison]::OrdinalIgnoreCase)) { $problems.Add('multiple-instances') }
    if ([bool]$settings.AllowStartIfOnBatteries -ne [bool]$Spec.AllowStartIfOnBatteries) { $problems.Add('allow-on-battery') }
    if ([bool]$settings.DontStopIfGoingOnBatteries -ne [bool]$Spec.DontStopIfGoingOnBatteries) { $problems.Add('dont-stop-on-battery') }

    @($problems)
}

function Assert-HyperVObserverTaskIdentity {
    param(
        [Parameter(Mandatory)]$Task,
        [Parameter(Mandatory)]$Spec
    )

    $problems = @(Get-HyperVObserverTaskIdentityProblems -Task $Task -Spec $Spec)
    if ($problems.Count -ne 0) {
        throw 'Scheduled task identity drift detected: ' + ($problems -join ', ') + '. No task mutation was performed.'
    }
}

function Write-HyperVObserverProtectedJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    $directory = Split-Path -Parent $Path
    $temp = Join-Path $directory ((Split-Path -Leaf $Path) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($temp, (($Value | ConvertTo-Json -Depth 6) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    Set-HyperVObserverProtectedFileAcl -Path $temp
    Move-Item -LiteralPath $temp -Destination $Path -Force
    Set-HyperVObserverProtectedFileAcl -Path $Path
}

function Read-HyperVObserverDeploymentState {
    $constants = Get-HyperVObserverDeploymentConstants
    if (-not (Test-Path -LiteralPath $constants.StatePath -PathType Leaf)) { return $null }

    try { $state = Get-Content -LiteralPath $constants.StatePath -Raw | ConvertFrom-Json -Depth 6 }
    catch { throw 'Deployment state is unreadable or invalid JSON.' }

    if ([int]$state.schemaVersion -ne 1 -or ([string]$state.releaseId) -notmatch '^[0-9a-f]{16}$') {
        throw 'Deployment state schema/release identity is invalid.'
    }

    if (-not [string]::Equals([string]$state.taskName, $constants.TaskName, [StringComparison]::Ordinal) -or
        -not [string]::Equals([string]$state.taskPath, $constants.TaskPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([IO.Path]::GetFullPath([string]$state.configPath), [IO.Path]::GetFullPath($constants.ConfigPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Deployment state identity does not match the accepted machine-local contract.'
    }

    $expectedReleaseRoot = Join-Path $constants.ReleasesRoot ([string]$state.releaseId)
    $expectedExe = Join-Path $expectedReleaseRoot 'LDW.HostAgent.HyperVObserver.exe'
    if (-not [string]::Equals([IO.Path]::GetFullPath([string]$state.installedExe), [IO.Path]::GetFullPath($expectedExe), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Deployment state executable path does not match its release identity.'
    }

    $state
}

function Get-HyperVObserverConfiguredSid {
    $constants = Get-HyperVObserverDeploymentConstants
    if (-not (Test-Path -LiteralPath $constants.ConfigPath -PathType Leaf)) {
        throw 'Machine-local helper configuration is missing.'
    }

    try { $config = Get-Content -LiteralPath $constants.ConfigPath -Raw | ConvertFrom-Json -Depth 4 }
    catch { throw 'Machine-local helper configuration is invalid JSON.' }

    $properties = @($config.PSObject.Properties.Name)
    if ($properties.Count -ne 1 -or $properties[0] -ne 'permittedCallerSids') {
        throw 'Machine-local helper configuration has unexpected fields.'
    }

    $sids = @($config.permittedCallerSids)
    if ($sids.Count -ne 1) { throw 'Machine-local helper configuration must contain exactly one permitted caller SID.' }
    $sid = [string]$sids[0]
    Assert-HyperVObserverSafeExplicitUserSid -Sid $sid
    $sid
}

function Get-HyperVObserverScheduledTask {
    $constants = Get-HyperVObserverDeploymentConstants
    Get-ScheduledTask -TaskPath $constants.TaskPath -TaskName $constants.TaskName -ErrorAction SilentlyContinue
}

function Get-HyperVObserverValidatedContext {
    $constants = Get-HyperVObserverDeploymentConstants
    $state = Read-HyperVObserverDeploymentState
    if ($null -eq $state) {
        throw 'Deployment state is missing; fail closed rather than guessing task ownership.'
    }

    $releaseRoot = Join-Path $constants.ReleasesRoot ([string]$state.releaseId)
    $manifest = Test-HyperVObserverDeploymentManifest -Directory $releaseRoot
    if (-not [string]::Equals([string]$manifest.ReleaseId, [string]$state.releaseId, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installed release manifest does not match deployment state.'
    }

    $null = Get-HyperVObserverConfiguredSid
    foreach ($protectedPath in @($constants.InstallRoot, $releaseRoot, $constants.ConfigRoot, $constants.ConfigPath, $constants.StatePath)) {
        if (-not (Test-HyperVObserverProtectedPath -Path $protectedPath)) {
            throw "Protected-path ACL drift detected at '$protectedPath'."
        }
    }

    foreach ($entry in $manifest.Entries) {
        $file = Join-Path $releaseRoot ([string]$entry.name)
        if (-not (Test-HyperVObserverProtectedPath -Path $file)) {
            throw "Protected-file ACL drift detected for '$($entry.name)'."
        }
    }
    if (-not (Test-HyperVObserverProtectedPath -Path (Join-Path $releaseRoot $constants.ManifestFileName))) {
        throw 'Protected-file ACL drift detected for deployment-manifest.json.'
    }

    $task = Get-HyperVObserverScheduledTask
    if ($null -eq $task) { throw 'Managed Scheduled Task is missing.' }
    $spec = Get-HyperVObserverTaskSpec -InstalledExe ([string]$state.installedExe) -ConfigPath $constants.ConfigPath
    Assert-HyperVObserverTaskIdentity -Task $task -Spec $spec

    [pscustomobject]@{
        Constants = $constants
        State = $state
        ReleaseRoot = $releaseRoot
        Manifest = $manifest
        Task = $task
        Spec = $spec
    }
}

Export-ModuleMember -Function @(
    'Get-HyperVObserverDeploymentConstants',
    'Assert-HyperVObserverElevated',
    'Assert-HyperVObserverLocalAbsolutePath',
    'Assert-HyperVObserverSafeExplicitUserSid',
    'Get-HyperVObserverPublishEntries',
    'Get-HyperVObserverReleaseFingerprint',
    'New-HyperVObserverDeploymentManifest',
    'Test-HyperVObserverDeploymentManifest',
    'New-HyperVObserverDirectorySecurity',
    'New-HyperVObserverFileSecurity',
    'Test-HyperVObserverAclObject',
    'Set-HyperVObserverProtectedDirectoryAcl',
    'Set-HyperVObserverProtectedFileAcl',
    'Test-HyperVObserverProtectedPath',
    'Get-HyperVObserverTaskSpec',
    'Get-HyperVObserverTaskIdentityProblems',
    'Assert-HyperVObserverTaskIdentity',
    'Write-HyperVObserverProtectedJson',
    'Read-HyperVObserverDeploymentState',
    'Get-HyperVObserverConfiguredSid',
    'Get-HyperVObserverScheduledTask',
    'Get-HyperVObserverValidatedContext'
)
