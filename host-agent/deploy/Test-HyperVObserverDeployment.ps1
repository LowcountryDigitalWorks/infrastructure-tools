[CmdletBinding()]
param(
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
        throw 'Deployment verification must run from an elevated PowerShell session.'
    }
}

function Test-ProtectedAcl([string]$Path) {
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { return $false }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }

        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin $allowed) { return $false }
    }

    return $true
}

Assert-Elevated

$configPath = Join-Path $ConfigRoot 'hyperv-observer.Local.json'
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop

$actionCountOk = @($task.Actions).Count -eq 1
$action = @($task.Actions)[0]
$executePath = [string]$action.Execute
$arguments = [string]$action.Arguments

$installPrefix = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') + '\'
$executeFull = [IO.Path]::GetFullPath($executePath)
$actionUnderInstallRoot = $executeFull.StartsWith($installPrefix, [StringComparison]::OrdinalIgnoreCase)
$expectedArgument = '--config "' + $configPath + '"'

$principalSystem = [string]::Equals($task.Principal.UserId, 'SYSTEM', [StringComparison]::OrdinalIgnoreCase)
$runLevelHighest = [string]::Equals([string]$task.Principal.RunLevel, 'Highest', [StringComparison]::OrdinalIgnoreCase)
$actionArgumentsOk = [string]::Equals($arguments, $expectedArgument, [StringComparison]::Ordinal)
$exeExists = Test-Path -LiteralPath $executeFull -PathType Leaf
$configExists = Test-Path -LiteralPath $configPath -PathType Leaf
$installAclProtected = (Test-Path -LiteralPath $InstallRoot -PathType Container) -and (Test-ProtectedAcl -Path $InstallRoot)
$configAclProtected = $configExists -and (Test-ProtectedAcl -Path $configPath)
$running = $task.State -eq 'Running'

$result = [ordered]@{
    TaskPresent = $true
    TaskRunning = $running
    SingleAction = $actionCountOk
    ActionUnderInstallRoot = $actionUnderInstallRoot
    ActionArgumentsExpected = $actionArgumentsOk
    PrincipalSystem = $principalSystem
    RunLevelHighest = $runLevelHighest
    HelperExecutablePresent = $exeExists
    MachineLocalConfigPresent = $configExists
    InstallAclProtected = $installAclProtected
    ConfigAclProtected = $configAclProtected
}

[pscustomobject]$result

if ($result.Values -contains $false) {
    throw 'Persistent Hyper-V observer deployment verification failed. Do not weaken local security policy to force a pass.'
}
