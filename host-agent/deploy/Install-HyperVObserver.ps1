[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$PublishedDirectory,

    [Parameter(Mandatory)]
    [ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')]
    [string]$PermittedCallerSid,

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
        throw 'This installer must run from an elevated PowerShell session.'
    }
}

function Assert-LocalAbsolutePath([string]$Path, [string]$Name) {
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Name must be an absolute path."
    }

    $uri = [Uri]::new($Path)
    if ($uri.IsUnc) {
        throw "$Name must be a local path, not UNC/network storage."
    }
}

function Set-ProtectedDirectoryAcl([string]$Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)

    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow

    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')

    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $admins,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow))

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ProtectedFileAcl([string]$Path) {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)

    $allow = [Security.AccessControl.AccessControlType]::Allow
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')

    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $admins,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $allow))

    Set-Acl -LiteralPath $Path -AclObject $acl
}

Assert-Elevated
Assert-LocalAbsolutePath -Path $PublishedDirectory -Name 'PublishedDirectory'
Assert-LocalAbsolutePath -Path $InstallRoot -Name 'InstallRoot'
Assert-LocalAbsolutePath -Path $ConfigRoot -Name 'ConfigRoot'

$sourceExe = Join-Path $PublishedDirectory 'LDW.HostAgent.HyperVObserver.exe'
if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
    throw 'PublishedDirectory does not contain LDW.HostAgent.HyperVObserver.exe.'
}

# Resolve/validate the SID without printing it. The helper performs its own stricter
# caller-authorization validation at runtime; this installer deliberately accepts
# only normal machine/domain-style account SIDs, not well-known/builtin principals.
$null = [Security.Principal.SecurityIdentifier]::new($PermittedCallerSid)

$sourceHash = (Get-FileHash -LiteralPath $sourceExe -Algorithm SHA256).Hash.ToLowerInvariant()
$releaseName = $sourceHash.Substring(0, 16)
$releaseRoot = Join-Path (Join-Path $InstallRoot 'releases') $releaseName
$installedExe = Join-Path $releaseRoot 'LDW.HostAgent.HyperVObserver.exe'
$configPath = Join-Path $ConfigRoot 'hyperv-observer.Local.json'

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'releases') -Force | Out-Null
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
New-Item -ItemType Directory -Path $ConfigRoot -Force | Out-Null

Set-ProtectedDirectoryAcl -Path $InstallRoot
Set-ProtectedDirectoryAcl -Path (Join-Path $InstallRoot 'releases')
Set-ProtectedDirectoryAcl -Path $releaseRoot
Set-ProtectedDirectoryAcl -Path $ConfigRoot

Copy-Item -LiteralPath (Join-Path $PublishedDirectory '*') -Destination $releaseRoot -Recurse -Force
if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf)) {
    throw 'The staged release is missing LDW.HostAgent.HyperVObserver.exe.'
}

$installedHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($installedHash -ne $sourceHash) {
    throw 'Staged helper hash does not match the published source helper.'
}

# Re-apply protected ACLs after copy so copied ACL metadata cannot broaden access.
Set-ProtectedDirectoryAcl -Path $releaseRoot
Get-ChildItem -LiteralPath $releaseRoot -File -Recurse | ForEach-Object {
    Set-ProtectedFileAcl -Path $_.FullName
}

$config = [ordered]@{ permittedCallerSids = @($PermittedCallerSid) } | ConvertTo-Json -Depth 3
$tempConfig = Join-Path $ConfigRoot ('hyperv-observer.Local.json.' + [Guid]::NewGuid().ToString('N') + '.tmp')
[IO.File]::WriteAllText($tempConfig, $config + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Set-ProtectedFileAcl -Path $tempConfig
Move-Item -LiteralPath $tempConfig -Destination $configPath -Force
Set-ProtectedFileAcl -Path $configPath

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$expectedArgument = '--config "' + $configPath + '"'

if ($existing) {
    $sameAction = @($existing.Actions).Count -eq 1 -and
        [string]::Equals($existing.Actions[0].Execute, $installedExe, [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals($existing.Actions[0].Arguments, $expectedArgument, [StringComparison]::Ordinal)
    $samePrincipal = [string]::Equals($existing.Principal.UserId, 'SYSTEM', [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string]$existing.Principal.RunLevel, 'Highest', [StringComparison]::OrdinalIgnoreCase)

    if (-not ($sameAction -and $samePrincipal)) {
        throw "Scheduled task '$TaskName' already exists with a different action/principal. Run the rollback/uninstall step before replacing it."
    }
}
else {
    $action = New-ScheduledTaskAction -Execute $installedExe -Argument $expectedArgument
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description 'LDW Host Agent read-only Hyper-V observer helper for CI-RUNNER-001.' | Out-Null
}

Start-ScheduledTask -TaskName $TaskName
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    Start-Sleep -Milliseconds 500
    $task = Get-ScheduledTask -TaskName $TaskName
    if ($task.State -eq 'Running') { break }
} while ([DateTime]::UtcNow -lt $deadline)

if ($task.State -ne 'Running') {
    throw "Scheduled task '$TaskName' did not remain Running. Inspect Task Scheduler/App Control logs; do not weaken policy."
}

[pscustomobject]@{
    TaskName = $TaskName
    State = [string]$task.State
    ReleaseId = $releaseName
    SourceHashMatched = $true
    PersistentHelperInstalled = $true
}
