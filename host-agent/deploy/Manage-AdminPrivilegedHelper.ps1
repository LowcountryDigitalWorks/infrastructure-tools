[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Uninstall')][string]$Mode = 'Plan',
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')][string]$OwnerSid,
    [string]$WorkerSourcePath,
    [switch]$AcceptInstall,
    [switch]$AcceptUninstall
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$acceptedWorkerSha256 = 'db71da0a73f2943eb8837e7c1e7070a22251478e4acfba91338837c7fc699605'

$controlRoot = Join-Path $env:ProgramData 'LDW/PrivilegedControl'
$binRoot = Join-Path $controlRoot 'bin'
$requestRoot = Join-Path $controlRoot 'requests'
$resultRoot = Join-Path $controlRoot 'results'
$lockRoot = Join-Path $controlRoot 'lock'
$workerSource = if ($WorkerSourcePath) { $WorkerSourcePath } else { Join-Path $PSScriptRoot 'Invoke-AdminPrivilegedOperation.ps1' }
$workerInstalled = Join-Path $binRoot 'Invoke-AdminPrivilegedOperation.ps1'
$taskName = '\LDW-ADMIN-REVIEWED-OPERATION'
$taskSddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;' + $OwnerSid + ')'

function Assert-Elevated {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATED_INSTALL_REQUIRED'
    }
}

function New-ProtectedDirectoryAcl([string]$Path, [ValidateSet('Protected','Requests','Results')][string]$Kind) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if ($Kind -eq 'Requests') {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($OwnerSid), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    } elseif ($Kind -eq 'Results') {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($OwnerSid), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    } elseif ($Path -ceq $controlRoot) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($OwnerSid), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'REPARSE_PATH_REFUSED'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-DirectoryAcl([string]$Path, [ValidateSet('Protected','Requests','Results')][string]$Kind) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
        throw 'CONTROL_ACL_OWNER_REFUSED'
    }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $forbidden = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership

    $nonAdminWriters = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $forbidden) -and $_.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') })

    if ($Kind -eq 'Protected' -or $Kind -eq 'Results') {
        if ($nonAdminWriters.Count -gt 0) {
            throw 'OWNER_CONTROL_WRITE_REFUSED'
        }
        if ($Kind -eq 'Results') {
            $owner = @($rules | Where-Object { $_.IdentityReference.Value -eq $OwnerSid -and $_.AccessControlType -eq 'Allow' })
            if (-not @($owner | Where-Object { $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read }).Count) {
                throw 'OWNER_RESULT_READ_ONLY_REQUIRED'
            }
        }
    } elseif ($Kind -eq 'Requests') {
        $owner = @($rules | Where-Object { $_.IdentityReference.Value -eq $OwnerSid -and $_.AccessControlType -eq 'Allow' })
        if (-not @($owner | Where-Object { ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -eq [Security.AccessControl.FileSystemRights]::Modify }).Count) {
            throw 'OWNER_REQUEST_WRITE_REQUIRED'
        }
        $uniqueWriterSids = @($nonAdminWriters | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique)
        if ($uniqueWriterSids.Count -ne 1 -or $uniqueWriterSids[0] -cne $OwnerSid) {
            throw 'OWNER_REQUEST_WRITE_DRIFT'
        }
    }
}

function Get-ExpectedArguments([string]$WorkerSha) {
    '-NoLogo -NoProfile -NonInteractive -File "' + $workerInstalled + '" -WorkerSha256 ' + $WorkerSha
}

function Get-TaskService {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $service
}

function Assert-TaskPrincipal([object]$Principal) {
    try {
        $userId = [string]$Principal.UserId
        if ([string]::IsNullOrWhiteSpace($userId)) { throw 'IDENTITY_REQUIRED' }
        $identity = if ($userId.StartsWith('S-', [StringComparison]::OrdinalIgnoreCase)) {
            [Security.Principal.SecurityIdentifier]::new($userId)
        } else {
            [Security.Principal.NTAccount]::new($userId)
        }
        $sid = $identity.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -cne $OwnerSid -or $Principal.LogonType -ne 3 -or $Principal.RunLevel -ne 1) {
            throw 'PRINCIPAL_MISMATCH'
        }
    } catch {
        throw 'TASK_PRINCIPAL_REFUSED'
    }
}

function Assert-TaskDacl([string]$Sddl) {
    try {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if ($descriptor.Owner.Value -notin @('S-1-5-18', 'S-1-5-32-544') -or
            -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -or
            -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -or
            $null -eq $descriptor.DiscretionaryAcl) {
            throw 'DACL_REQUIRED'
        }
        $rights = @{ 'S-1-5-18' = [long]0; 'S-1-5-32-544' = [long]0; $OwnerSid = [long]0 }
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
                $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
                $ace.AceFlags -ne [Security.AccessControl.AceFlags]::None) {
                throw 'ACE_REFUSED'
            }
            $sid = $ace.SecurityIdentifier.Value
            if (-not $rights.ContainsKey($sid)) { throw 'TRUSTEE_REFUSED' }
            $mask = ([long]$ace.AccessMask -band 0xFFFFFFFFL)
            if ($mask -band 0x80000000L) { $mask = ($mask -band 0x7FFFFFFFL) -bor 0x00120089L }
            if ($mask -band 0x40000000L) { $mask = ($mask -band 0xBFFFFFFFL) -bor 0x00120116L }
            if ($mask -band 0x20000000L) { $mask = ($mask -band 0xDFFFFFFFL) -bor 0x001200A0L }
            if ($mask -band 0x10000000L) { $mask = ($mask -band 0xEFFFFFFFL) -bor 0x001F01FFL }
            $allowed = if ($sid -ceq $OwnerSid) { 0x001200A9L } else { 0x001F01FFL }
            if ($mask -eq 0 -or ($mask -band (-bnot $allowed)) -ne 0) { throw 'ACCESS_MASK_REFUSED' }
            $rights[$sid] = $rights[$sid] -bor $mask
        }
        if ($rights['S-1-5-18'] -ne 0x001F01FFL -or $rights['S-1-5-32-544'] -ne 0x001F01FFL -or
            $rights[$OwnerSid] -ne 0x001200A9L) {
            throw 'REQUIRED_ACCESS_MISSING'
        }
    } catch {
        throw 'TASK_DACL_REFUSED'
    }
}

function Assert-TaskDefinition([object]$Task, [string]$ExpectedTaskName, [string]$WorkerSha) {
    $definition = $Task.Definition
    if ($definition.Triggers.Count -ne 0) { throw 'TASK_TRIGGER_REFUSED' }
    if ($definition.Actions.Count -ne 1) { throw 'TASK_ACTION_COUNT_REFUSED' }
    $action = $definition.Actions.Item(1)
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    if (-not [string]::Equals($action.Path, $pwsh, [StringComparison]::OrdinalIgnoreCase) -or
        $action.Arguments -cne (Get-ExpectedArguments $WorkerSha) -or $action.WorkingDirectory) {
        throw 'TASK_ACTION_REFUSED'
    }
    Assert-TaskPrincipal $definition.Principal
    if (-not $definition.Settings.Enabled -or -not $definition.Settings.AllowDemandStart -or
        $definition.Settings.StartWhenAvailable -or $definition.Settings.MultipleInstances -ne 2 -or
        $definition.Settings.DisallowStartIfOnBatteries -or $definition.Settings.StopIfGoingOnBatteries -or
        $definition.Settings.ExecutionTimeLimit -cne 'PT15M') {
        throw 'TASK_SETTINGS_REFUSED'
    }
    Assert-TaskDacl ($Task.GetSecurityDescriptor(0xF))
}

function Install-Tasks {
    Assert-Elevated
    if (-not $AcceptInstall) { throw 'EXPLICIT_INSTALL_ACCEPTANCE_REQUIRED' }
    if (-not (Test-Path -LiteralPath $workerSource -PathType Leaf)) { throw 'WORKER_SOURCE_REQUIRED' }
    $sourceSha = (Get-FileHash -LiteralPath $workerSource -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceSha -cne $acceptedWorkerSha256) {
        throw 'WORKER_PROVENANCE_MISMATCH'
    }

    foreach ($path in @($controlRoot, $binRoot, $requestRoot, $resultRoot, $lockRoot)) { Assert-NoReparse $path }
    New-ProtectedDirectoryAcl $controlRoot Protected
    New-ProtectedDirectoryAcl $binRoot Protected
    New-ProtectedDirectoryAcl $requestRoot Requests
    New-ProtectedDirectoryAcl $resultRoot Results
    New-ProtectedDirectoryAcl $lockRoot Protected
    Copy-Item -LiteralPath $workerSource -Destination $workerInstalled -Force
    $workerSha = (Get-FileHash -LiteralPath $workerInstalled -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($workerSha -cne $acceptedWorkerSha256) {
        throw 'WORKER_PROVENANCE_MISMATCH'
    }

    Assert-DirectoryAcl $controlRoot Protected
    Assert-DirectoryAcl $binRoot Protected
    Assert-DirectoryAcl $requestRoot Requests
    Assert-DirectoryAcl $resultRoot Results
    Assert-DirectoryAcl $lockRoot Protected

    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source

    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Description = 'LDW fixed on-demand reviewed administrative operation. No trigger or recurrence.'
    $definition.Principal.UserId = $OwnerSid
    $definition.Principal.LogonType = 3
    $definition.Principal.RunLevel = 1
    $definition.Settings.Enabled = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.StartWhenAvailable = $false
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.MultipleInstances = 2
    $definition.Settings.ExecutionTimeLimit = 'PT15M'

    $action = $definition.Actions.Create(0)
    $action.Path = $pwsh
    $action.Arguments = Get-ExpectedArguments $workerSha

    $name = $taskName.TrimStart('\')
    $registered = $folder.RegisterTaskDefinition($name, $definition, 0x16, $OwnerSid, $null, 3, $taskSddl)
    $registered.SetSecurityDescriptor($taskSddl, 0x10)
    Assert-TaskDefinition ($folder.GetTask($taskName)) $taskName $workerSha

    'ADMIN_PRIVILEGED_HELPER_INSTALL=PASS'
    'WORKER_SHA256=' + $workerSha
}

function Get-Status {
    Assert-Elevated
    if (-not (Test-Path -LiteralPath $workerInstalled -PathType Leaf)) { throw 'WORKER_NOT_INSTALLED' }
    $workerSha = (Get-FileHash -LiteralPath $workerInstalled -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($workerSha -cne $acceptedWorkerSha256) { throw 'WORKER_PROVENANCE_MISMATCH' }

    Assert-DirectoryAcl $controlRoot Protected
    Assert-DirectoryAcl $binRoot Protected
    Assert-DirectoryAcl $requestRoot Requests
    Assert-DirectoryAcl $resultRoot Results
    Assert-DirectoryAcl $lockRoot Protected

    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    Assert-TaskDefinition ($folder.GetTask($taskName)) $taskName $workerSha

    'ADMIN_PRIVILEGED_HELPER_STATUS=PASS'
    'TRIGGER_COUNT=0'
    'WORKER_SHA256=' + $workerSha
}

function Uninstall-Tasks {
    Assert-Elevated
    if (-not $AcceptUninstall) { throw 'EXPLICIT_UNINSTALL_ACCEPTANCE_REQUIRED' }

    # 1. Prove no pending/in-flight/ambiguous request state FIRST
    if (Test-Path -LiteralPath $requestRoot) {
        Assert-NoReparse $requestRoot
        $pendingFiles = @(Get-ChildItem -LiteralPath $requestRoot -File -ErrorAction Stop)
        if ($pendingFiles.Count -gt 0) {
            throw 'PENDING_REQUEST_REFUSED'
        }
    }
    if (Test-Path -LiteralPath $resultRoot) {
        Assert-NoReparse $resultRoot
        $cutoff = [DateTime]::UtcNow.AddMinutes(-15)
        $inFlight = @(Get-ChildItem -LiteralPath $resultRoot -File -ErrorAction Stop | Where-Object {
            $_.Name -cmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\.json$' -and $_.LastWriteTimeUtc -gt $cutoff
        } | ForEach-Object {
            try {
                $doc = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
                if ($doc.resultState -ceq 'STARTED') { $_ }
            } catch { }
        })
        if ($inFlight.Count -gt 0) {
            throw 'ACTIVE_TASK_REFUSED'
        }
    }

    # 2. Resolve exact task state from Task Scheduler
    $service = Get-TaskService
    $folder = $service.GetFolder('\')
    $task = $null
    $taskFound = $false
    try {
        $task = $folder.GetTask($taskName)
        $taskFound = $true
    } catch {
        $hResult = $_.Exception.HResult
        $msg = $_.Exception.Message
        if ($hResult -eq [int]0x80070002 -or $msg -match '0x80070002|The system cannot find the file specified') {
            $taskFound = $false
        } else {
            throw 'TASK_LOOKUP_FAILED'
        }
    }

    if ($taskFound) {
        # TaskState: 0=Unknown, 1=Disabled, 2=Queued, 3=Ready, 4=Running
        $state = [int]$task.State
        if ($state -eq 4 -or $state -eq 2 -or $state -eq 0) {
            throw 'ACTIVE_TASK_REFUSED'
        }
        if ($state -ne 1 -and $state -ne 3) {
            throw 'ACTIVE_TASK_REFUSED'
        }

        # 3. Delete task
        try {
            $folder.DeleteTask($taskName.TrimStart('\'), 0)
        } catch {
            throw 'TASK_DELETE_FAILED'
        }

        # 4. Positively prove task absence
        try {
            $null = $folder.GetTask($taskName)
            throw 'TASK_DELETION_VERIFICATION_FAILED'
        } catch {
            if ($_.Exception.Message -eq 'TASK_DELETION_VERIFICATION_FAILED') { throw }
            $hResult = $_.Exception.HResult
            $msg = $_.Exception.Message
            if ($hResult -ne [int]0x80070002 -and $msg -notmatch '0x80070002|The system cannot find the file specified') {
                throw 'TASK_DELETION_VERIFICATION_FAILED'
            }
        }
    }

    # 5. Only then remove protected root
    if (Test-Path -LiteralPath $controlRoot) {
        Remove-Item -LiteralPath $controlRoot -Recurse -Force
        if (Test-Path -LiteralPath $controlRoot) {
            throw 'CONTROL_ROOT_REMOVAL_FAILED'
        }
    }
    'ADMIN_PRIVILEGED_HELPER_UNINSTALL=PASS'
}

if ($Mode -eq 'Plan') {
    if (-not (Test-Path -LiteralPath $workerSource -PathType Leaf)) { throw 'WORKER_SOURCE_REQUIRED' }
    $sha = (Get-FileHash -LiteralPath $workerSource -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -cne $acceptedWorkerSha256) { throw 'WORKER_PROVENANCE_MISMATCH' }
    'ADMIN_PRIVILEGED_HELPER_PLAN=PASS'
    'TASK_COUNT=1'
    'TRIGGER_COUNT=0'
    'OWNER_SID=' + $OwnerSid
    'WORKER_SHA256=' + $sha
} elseif ($Mode -eq 'Install') {
    Install-Tasks
} elseif ($Mode -eq 'Status') {
    Get-Status
} else {
    Uninstall-Tasks
}
