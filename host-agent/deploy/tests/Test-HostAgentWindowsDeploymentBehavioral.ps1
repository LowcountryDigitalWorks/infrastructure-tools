#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$script:ManagerPath = Join-Path $deployRoot 'Manage-HostAgentWindowsDeployment.ps1'
$script:ModulePath = Join-Path $deployRoot 'HostAgentWindowsDeployment.psm1'

$script:Assertions = 0
function Assert-True([bool]$Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-Equal($Expected, $Actual, [string]$Message) {
    $script:Assertions++
    if ($Expected -cne $Actual) { throw "ASSERTION FAILED: $Message (expected: $Expected, actual: $Actual)" }
}

function Assert-ThrowsCode([scriptblock]$Action, [string]$ExpectedCode, [string]$Message) {
    $script:Assertions++
    try {
        & $Action | Out-Null
        throw "ASSERTION FAILED: $Message (expected code: $ExpectedCode)"
    } catch {
        if ($_.Exception.Message.StartsWith('ASSERTION FAILED:', [StringComparison]::Ordinal)) { throw }
        $text = $_.ToString()
        $exact = [string]::Equals($_.Exception.Message, $ExpectedCode, [StringComparison]::Ordinal)
        $contains = $text.Contains($ExpectedCode, [StringComparison]::Ordinal)
        if (-not ($exact -or $contains)) {
            throw "ASSERTION FAILED: $Message (expected code: $ExpectedCode, actual: $($_.Exception.Message))"
        }
    }
}

function Get-LiveHostAgentProcessCount {
    return @(Get-Process -Name 'LDW.HostAgent.Windows' -ErrorAction SilentlyContinue).Count
}

function Get-RunValueSnapshot {
    $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $name = 'LDW.HostAgent.Windows'
    $present = $false
    $value = $null
    if (Test-Path -LiteralPath $path -PathType Container) {
        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        if ($null -ne $item.PSObject.Properties[$name]) {
            $present = $true
            $value = [string]$item.$name
        }
    }
    return [pscustomobject]@{
        Present = $present
        Value = $value
    }
}

function Get-TrayTaskSnapshot {
    $taskPath = '\LowcountryDigitalWorks\HostAgent\'
    $taskName = 'Tray'
    $available = ($null -ne (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue))
    if (-not $available) {
        return [pscustomobject]@{
            Available = $false
            Present = $false
            Definition = $null
        }
    }

    $present = $false
    $definition = $null
    try {
        $null = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        $present = $true
        if ($null -ne (Get-Command Export-ScheduledTask -ErrorAction SilentlyContinue)) {
            $definition = [string](Export-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-String)
        }
    } catch {
        if ($_.FullyQualifiedErrorId -ne 'CmdletizationQuery_NotFound,Get-ScheduledTask') { throw }
    }

    return [pscustomobject]@{
        Available = $true
        Present = $present
        Definition = $definition
    }
}

function Get-StringOrEmpty([AllowNull()]$Value) {
    if ($null -eq $Value) { return '' }
    return [string]$Value
}

function Assert-RunSnapshotUnchanged($Before, $After) {
    Assert-Equal $Before.Present $After.Present 'HKCU Run presence must remain unchanged'
    Assert-Equal (Get-StringOrEmpty $Before.Value) (Get-StringOrEmpty $After.Value) 'HKCU Run value must remain unchanged'
}

function Assert-TrayTaskSnapshotUnchanged($Before, $After) {
    Assert-Equal $Before.Available $After.Available 'tray task API availability must remain unchanged'
    Assert-Equal $Before.Present $After.Present 'tray task presence must remain unchanged'
    Assert-Equal (Get-StringOrEmpty $Before.Definition) (Get-StringOrEmpty $After.Definition) 'tray task definition export must remain unchanged'
}

function New-ProtectedDirectoryAcl {
    param([Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$OwnerSid)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544', $OwnerSid.Value)) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Set-ProtectedDirectoryAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$OwnerSid
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $Path -Force
    }
    Set-Acl -LiteralPath $Path -AclObject (New-ProtectedDirectoryAcl -OwnerSid $OwnerSid)
}

function New-SyntheticPackage {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SourceCommit,
        [Parameter(Mandatory)][string]$SourceTree,
        [Parameter(Mandatory)][byte]$Seed,
        [Parameter(Mandatory)][int]$Length
    )
    $packageRoot = Join-Path $Root $Name
    $null = New-Item -ItemType Directory -Path $packageRoot -Force
    $exePath = Join-Path $packageRoot 'LDW.HostAgent.Windows.exe'
    $manifestPath = Join-Path $packageRoot 'manifest.json'

    $bytes = [byte[]]::new($Length)
    for ($i = 0; $i -lt $Length; $i++) {
        $bytes[$i] = [byte](($Seed + $i) % 251)
    }
    [IO.File]::WriteAllBytes($exePath, $bytes)
    $exeSha = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $exeLength = (Get-Item -LiteralPath $exePath).Length

    [ordered]@{
        schema = 1
        package = 'ldw-host-agent-windows'
        runtime = 'win-x64'
        source_commit = $SourceCommit
        source_tree = $SourceTree
        executable = [ordered]@{
            name = 'LDW.HostAgent.Windows.exe'
            sha256 = $exeSha
            bytes = $exeLength
        }
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    return [pscustomobject]@{
        PackageDirectory = $packageRoot
        SourceCommit = $SourceCommit
        SourceTree = $SourceTree
        ManifestSha256 = $manifestSha
        ExecutableSha256 = $exeSha
        ExecutableBytes = [int64]$exeLength
    }
}

function Invoke-ManagedInstall {
    param([Parameter(Mandatory)]$Package)
    return & $script:ManagerPath -Action Install `
        -PackageDirectory $Package.PackageDirectory `
        -ExpectedSourceCommit $Package.SourceCommit `
        -ExpectedSourceTree $Package.SourceTree `
        -ExpectedManifestSha256 $Package.ManifestSha256 `
        -ExpectedExecutableSha256 $Package.ExecutableSha256 `
        -ExpectedExecutableBytes $Package.ExecutableBytes
}

function Invoke-ManagedRollback {
    param([Parameter(Mandatory)]$RollbackPackage)
    return & $script:ManagerPath -Action Rollback `
        -ExpectedRollbackSourceCommit $RollbackPackage.SourceCommit `
        -ExpectedRollbackSourceTree $RollbackPackage.SourceTree `
        -ExpectedRollbackManifestSha256 $RollbackPackage.ManifestSha256 `
        -ExpectedRollbackExecutableSha256 $RollbackPackage.ExecutableSha256 `
        -ExpectedRollbackExecutableBytes $RollbackPackage.ExecutableBytes
}

function Get-ManagedStatus {
    return & $script:ManagerPath -Action Status
}

function Assert-AbsentStatus($Status, [string]$Label) {
    Assert-Equal 'Absent' $Status.InstalledState "$Label installed state must be Absent"
    Assert-Equal $false ([bool]$Status.Installed) "$Label installed flag must be false"
    Assert-Equal $false ([bool]$Status.RollbackAvailable) "$Label rollback availability must be false"
}

function Assert-ManagedStatus {
    param(
        [Parameter(Mandatory)]$Status,
        [Parameter(Mandatory)]$Installed,
        $Rollback,
        [Parameter(Mandatory)][string]$Label
    )
    Assert-Equal 'Managed' $Status.InstalledState "$Label installed state must be Managed"
    Assert-Equal $true ([bool]$Status.Installed) "$Label installed flag must be true"
    Assert-Equal $Installed.SourceCommit $Status.SourceCommit "$Label installed source commit"
    Assert-Equal $Installed.SourceTree $Status.SourceTree "$Label installed source tree"
    Assert-Equal $Installed.ManifestSha256 $Status.ManifestSha256 "$Label installed manifest digest"
    Assert-Equal $Installed.ExecutableSha256 $Status.ExecutableSha256 "$Label installed executable digest"
    Assert-Equal $Installed.ExecutableBytes ([int64]$Status.ExecutableBytes) "$Label installed executable bytes"
    if ($null -eq $Rollback) {
        Assert-Equal $false ([bool]$Status.RollbackAvailable) "$Label rollback must be unavailable"
    } else {
        Assert-Equal $true ([bool]$Status.RollbackAvailable) "$Label rollback must be available"
        Assert-Equal $Rollback.SourceCommit $Status.RollbackSourceCommit "$Label rollback source commit"
        Assert-Equal $Rollback.SourceTree $Status.RollbackSourceTree "$Label rollback source tree"
        Assert-Equal $Rollback.ManifestSha256 $Status.RollbackManifestSha256 "$Label rollback manifest digest"
        Assert-Equal $Rollback.ExecutableSha256 $Status.RollbackExecutableSha256 "$Label rollback executable digest"
        Assert-Equal $Rollback.ExecutableBytes ([int64]$Status.RollbackExecutableBytes) "$Label rollback executable bytes"
    }
}

$initialProcessCount = Get-LiveHostAgentProcessCount
if ($initialProcessCount -gt 0) { throw 'HOST_AGENT_WINDOWS_BEHAVIORAL_REAL_PROCESS_PRESENT' }
$initialRunSnapshot = Get-RunValueSnapshot
$initialTraySnapshot = Get-TrayTaskSnapshot

$originalProgramFiles = $env:ProgramFiles
$tempParent = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP }
$tempRoot = Join-Path $tempParent ('ldw-host-agent-windows-behavioral-' + [guid]::NewGuid().ToString('N'))
$syntheticProgramFiles = Join-Path $tempRoot 'ProgramFiles'
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$constants = $null
$productAclBaselineBytes = $null
$productAclInjected = $false

try {
    $null = New-Item -ItemType Directory -Path $syntheticProgramFiles -Force
    Set-ProtectedDirectoryAcl -Path $syntheticProgramFiles -OwnerSid $ownerSid

    $env:ProgramFiles = $syntheticProgramFiles
    Import-Module $script:ModulePath -Force
    $constants = Get-HostAgentWindowsDeploymentConstants
    Assert-True ($constants.InstallRoot.StartsWith($syntheticProgramFiles, [StringComparison]::OrdinalIgnoreCase)) 'synthetic Program Files root must scope managed install root'

    $packageRoot = Join-Path $tempRoot 'packages'
    $null = New-Item -ItemType Directory -Path $packageRoot -Force
    $packageA = New-SyntheticPackage -Root $packageRoot -Name 'A' -SourceCommit ('1' * 40) -SourceTree ('2' * 40) -Seed 41 -Length 131072
    $packageB = New-SyntheticPackage -Root $packageRoot -Name 'B' -SourceCommit ('3' * 40) -SourceTree ('4' * 40) -Seed 89 -Length 196608
    $packageC = New-SyntheticPackage -Root $packageRoot -Name 'C' -SourceCommit ('5' * 40) -SourceTree ('6' * 40) -Seed 137 -Length 25165824

    $null = New-Item -ItemType Directory -Path $constants.ProductRoot -Force
    Set-ProtectedDirectoryAcl -Path $constants.ProductRoot -OwnerSid $ownerSid
    $baselineAcl = Get-Acl -LiteralPath $constants.ProductRoot -ErrorAction Stop
    $productAclBaselineBytes = $baselineAcl.GetSecurityDescriptorBinaryForm()
    $broadAcl = [Security.AccessControl.DirectorySecurity]::new()
    $broadAcl.SetSecurityDescriptorBinaryForm($productAclBaselineBytes)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $broadRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,
        [Security.AccessControl.FileSystemRights]::Modify,
        $inherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$broadAcl.AddAccessRule($broadRule)
    Set-Acl -LiteralPath $constants.ProductRoot -AclObject $broadAcl
    $productAclInjected = $true

    Write-Host 'BEHAVIOR_PHASE=unsafe-acl-refusal'
    Assert-ThrowsCode { Invoke-ManagedInstall -Package $packageA } 'HOST_AGENT_WINDOWS_INSTALL_ACL_REFUSED' 'destination trust violation must fail closed before managed mutation'
    Assert-True (-not (Test-Path -LiteralPath $constants.ExecutablePath -PathType Leaf)) 'destination trust refusal must not create managed executable bytes'
    Assert-True (-not (Test-Path -LiteralPath $constants.InstalledManifestPath -PathType Leaf)) 'destination trust refusal must not create managed manifest bytes'
    Assert-True (-not (Test-Path -LiteralPath $constants.RollbackRoot -PathType Container)) 'destination trust refusal must not create rollback bytes'

    Set-ProtectedDirectoryAcl -Path $constants.ProductRoot -OwnerSid $ownerSid
    $productAclInjected = $false
    Write-Host 'BEHAVIOR_PHASE=acl-restoration-readback'
    Assert-HostAgentWindowsProtectedDirectory -Path $constants.ProductRoot

    Write-Host 'BEHAVIOR_PHASE=pre-install-status'
    $status = Get-ManagedStatus
    Assert-AbsentStatus -Status $status -Label 'pre-install'

    Write-Host 'BEHAVIOR_PHASE=install-a'
    $null = Invoke-ManagedInstall -Package $packageA
    $status = Get-ManagedStatus
    Assert-ManagedStatus -Status $status -Installed $packageA -Rollback $null -Label 'after install A'

    Write-Host 'BEHAVIOR_PHASE=install-b'
    $null = Invoke-ManagedInstall -Package $packageB
    $status = Get-ManagedStatus
    Assert-ManagedStatus -Status $status -Installed $packageB -Rollback $packageA -Label 'after install B'

    Write-Host 'BEHAVIOR_PHASE=rollback-to-a'
    $null = Invoke-ManagedRollback -RollbackPackage $packageA
    $status = Get-ManagedStatus
    Assert-ManagedStatus -Status $status -Installed $packageA -Rollback $packageB -Label 'after rollback to A'

    Write-Host 'BEHAVIOR_PHASE=lock-contention'
    $heldLock = Enter-HostAgentWindowsTransactionLock -TimeoutMilliseconds 1000
    try {
        Assert-ThrowsCode { Invoke-ManagedInstall -Package $packageB } 'HOST_AGENT_WINDOWS_TRANSACTION_BUSY' 'second transaction must fail with real lock contention'
    } finally {
        $heldLock.Dispose()
    }
    $status = Get-ManagedStatus
    Assert-ManagedStatus -Status $status -Installed $packageA -Rollback $packageB -Label 'after lock contention refusal'

    # Force a deterministic mid-transaction failure without corrupting recovery data.
    # A FileSystemWatcher sees the production-generated .stage-<token> directory and
    # creates the matching .rollback-old-<token> directory before activation reaches
    # rollback promotion. That destination denies only child creation. PowerShell then
    # fails the rollback-root Move-Item before moving any rollback contents, while the
    # collision directory itself remains safe/deletable by production cleanup.
    Write-Host 'BEHAVIOR_PHASE=forced-install-recovery'
    $collisionSource = 'LDW.HostAgent.BehaviorCollision.' + [guid]::NewGuid().ToString('N')
    $collisionWatcher = [IO.FileSystemWatcher]::new($constants.InstallRoot, '.stage-*')
    $collisionWatcher.NotifyFilter = [IO.NotifyFilters]::DirectoryName
    $collisionJob = Register-ObjectEvent -InputObject $collisionWatcher -EventName Created -SourceIdentifier $collisionSource `
        -MessageData ([pscustomobject]@{ InstallRoot=$constants.InstallRoot; OwnerSid=$ownerSid.Value }) -Action {
            $stageName = $Event.SourceEventArgs.Name
            if ($stageName -notmatch '^\.stage-[a-f0-9]{32}$') { return }
            $token = $stageName.Substring('.stage-'.Length)
            $destination = Join-Path $Event.MessageData.InstallRoot ('.rollback-old-' + $token)
            $null = New-Item -ItemType Directory -Path $destination -ErrorAction Stop
            $acl = Get-Acl -LiteralPath $destination -ErrorAction Stop
            $sid = [Security.Principal.SecurityIdentifier]::new($Event.MessageData.OwnerSid)
            $rights = [Security.AccessControl.FileSystemRights]::CreateDirectories -bor [Security.AccessControl.FileSystemRights]::CreateFiles
            $deny = [Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,[Security.AccessControl.AccessControlType]::Deny)
            [void]$acl.AddAccessRule($deny)
            Set-Acl -LiteralPath $destination -AclObject $acl -ErrorAction Stop
            'COLLISION_READY=' + $destination
        }
    $collisionWatcher.EnableRaisingEvents = $true

    $collisionError = $null
    $collisionOutput = @()
    try {
        try {
            Invoke-ManagedInstall -Package $packageC | Out-Null
            throw 'ASSERTION FAILED: mid-transaction rollback-directory move must fail'
        } catch {
            if ($_.Exception.Message.StartsWith('ASSERTION FAILED:', [StringComparison]::Ordinal)) { throw }
            $collisionError = $_.Exception.Message
        }
    } finally {
        Start-Sleep -Milliseconds 100
        $collisionOutput = @(Receive-Job -Job $collisionJob -Keep -ErrorAction Stop)
        $collisionWatcher.EnableRaisingEvents = $false
        Unregister-Event -SourceIdentifier $collisionSource -ErrorAction SilentlyContinue
        Remove-Job -Job $collisionJob -Force -ErrorAction SilentlyContinue
        $collisionWatcher.Dispose()
    }
    Assert-True (@($collisionOutput | Where-Object { [string]$_ -match '^COLLISION_READY=' }).Count -eq 1) 'collision watcher must prepare exactly one transaction-specific rollback-old destination'
    Assert-True (-not [string]::IsNullOrWhiteSpace($collisionError)) 'mid-transaction failure path must emit an error'
    Assert-True (-not [string]::Equals($collisionError, 'HOST_AGENT_WINDOWS_INSTALL_ROLLBACK_FAILED', [StringComparison]::Ordinal)) 'mid-transaction collision must restore without rollback-failure escalation'

    $status = Get-ManagedStatus
    Assert-ManagedStatus -Status $status -Installed $packageA -Rollback $packageB -Label 'after forced install failure recovery'

    $finalProcessCount = Get-LiveHostAgentProcessCount
    $finalRunSnapshot = Get-RunValueSnapshot
    $finalTraySnapshot = Get-TrayTaskSnapshot
    Assert-Equal $initialProcessCount $finalProcessCount 'live LDW.HostAgent.Windows process count must remain unchanged'
    Assert-RunSnapshotUnchanged -Before $initialRunSnapshot -After $finalRunSnapshot
    Assert-TrayTaskSnapshotUnchanged -Before $initialTraySnapshot -After $finalTraySnapshot
} finally {
    if ($productAclInjected -and $null -ne $constants -and (Test-Path -LiteralPath $constants.ProductRoot -PathType Container)) {
        try {
            Set-ProtectedDirectoryAcl -Path $constants.ProductRoot -OwnerSid $ownerSid
        } catch {
            Write-Warning "ACL restore failed: $($_.Exception.Message)"
        }
    }
    $env:ProgramFiles = $originalProgramFiles
    if (Test-Path -LiteralPath $tempRoot -PathType Container) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host "Host Agent Windows deployment behavioral assertions PASS: $script:Assertions"
