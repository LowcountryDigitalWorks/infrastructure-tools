[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Uninstall')][string]$Mode = 'Plan',
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')][string]$OwnerSid,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [switch]$AcceptInstall,
    [switch]$AcceptUninstall
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$controlRoot=Join-Path $env:ProgramData 'LDW/CiJitControl'
$binRoot=Join-Path $controlRoot 'bin'
$requestRoot=Join-Path $controlRoot 'requests'
$resultRoot=Join-Path $controlRoot 'results'
$workerSource=Join-Path $PSScriptRoot 'Invoke-CiJitControlTask.ps1'
$workerInstalled=Join-Path $binRoot 'Invoke-CiJitControlTask.ps1'
$bundleRoot=Join-Path (Join-Path $env:ProgramData 'LDW/CiRunnerDispatch/releases') $Commit
$taskMap=[ordered]@{
    '\LDW-CI-JIT-DISCOVER'='DISCOVER'
    '\LDW-CI-JIT-RUN-ONCE'='RUN_ONCE'
    '\LDW-CI-JIT-RECOVER'='RECOVER'
    '\LDW-CI-JIT-ABORT-ACTIVE'='ABORT_ACTIVE'
    '\LDW-CI-JIT-LIST-STALE'='LIST_STALE'
    '\LDW-CI-JIT-RETIRE-STALE'='RETIRE_STALE'
}
$taskSddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;'+$OwnerSid+')'

function Assert-Elevated {
    if($env:OS -ne 'Windows_NT'){throw 'WINDOWS_REQUIRED'}
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ELEVATED_INSTALL_REQUIRED'}
}

function New-ProtectedDirectoryAcl([string]$Path,[ValidateSet('Protected','Requests','Results')][string]$Kind){
    $null=New-Item -ItemType Directory -Path $Path -Force
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    if($Kind -eq 'Requests'){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($OwnerSid),'Modify','ContainerInherit,ObjectInherit','None','Allow'))
    } elseif($Kind -eq 'Results'){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($OwnerSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    } elseif($Path -ceq $controlRoot){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($OwnerSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-NoReparse([string]$Path){
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor){
        if(Test-Path -LiteralPath $cursor){if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'REPARSE_PATH_REFUSED'}}
        $parent=[IO.Path]::GetDirectoryName($cursor);if([string]::IsNullOrEmpty($parent)-or$parent-eq$cursor){break};$cursor=$parent
    }
}

function Assert-DirectoryAcl([string]$Path,[ValidateSet('Protected','Requests','Results')][string]$Kind){
    Assert-NoReparse $Path
    $acl=Get-Acl -LiteralPath $Path
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'CONTROL_ACL_OWNER_REFUSED'}
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $owner=@($rules|Where-Object{$_.IdentityReference.Value -eq $OwnerSid -and $_.AccessControlType -eq 'Allow'})
    if($Kind -eq 'Protected'){
        $forbidden=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        if(@($owner|Where-Object{$_.FileSystemRights -band $forbidden}).Count){throw 'OWNER_CONTROL_WRITE_REFUSED'}
    } elseif($Kind -eq 'Requests'){
        if(-not @($owner|Where-Object{($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -eq [Security.AccessControl.FileSystemRights]::Modify}).Count){throw 'OWNER_REQUEST_WRITE_REQUIRED'}
    } else {
        $forbidden=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        if(@($owner|Where-Object{$_.FileSystemRights -band $forbidden}).Count -or -not @($owner|Where-Object{$_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read}).Count){throw 'OWNER_RESULT_READ_ONLY_REQUIRED'}
    }
}

function Get-ExpectedArguments([string]$Operation,[string]$WorkerSha){
    '-NoLogo -NoProfile -NonInteractive -File "'+$workerInstalled+'" -Operation '+$Operation+
        ' -WorkerSha256 '+$WorkerSha+' -ManifestSha '+$ManifestSha+' -Commit '+$Commit+' -Tree '+$Tree
}

function Get-TaskService {
    $service=New-Object -ComObject 'Schedule.Service';$service.Connect();$service
}

function Assert-TaskPrincipal([object]$Principal){
    try {
        $userId=[string]$Principal.UserId
        if([string]::IsNullOrWhiteSpace($userId)){throw 'IDENTITY_REQUIRED'}
        $identity=if($userId.StartsWith('S-', [StringComparison]::OrdinalIgnoreCase)){
            [Security.Principal.SecurityIdentifier]::new($userId)
        }else{[Security.Principal.NTAccount]::new($userId)}
        $sid=$identity.Translate([Security.Principal.SecurityIdentifier]).Value
        if($sid -cne $OwnerSid -or $Principal.LogonType -ne 3 -or $Principal.RunLevel -ne 1){throw 'PRINCIPAL_MISMATCH'}
    }catch{throw 'TASK_PRINCIPAL_REFUSED'}
}

function Assert-TaskDacl([string]$Sddl){
    try {
        $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
        if($descriptor.Owner.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -or
            -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -or
            $null -eq $descriptor.DiscretionaryAcl){throw 'DACL_REQUIRED'}
        $rights=@{'S-1-5-18'=[long]0;'S-1-5-32-544'=[long]0;$OwnerSid=[long]0}
        foreach($ace in $descriptor.DiscretionaryAcl){
            if($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
                $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
                $ace.AceFlags -ne [Security.AccessControl.AceFlags]::None){throw 'ACE_REFUSED'}
            $sid=$ace.SecurityIdentifier.Value
            if(-not $rights.ContainsKey($sid)){throw 'TRUSTEE_REFUSED'}
            # Task Scheduler uses file access rights (MS-TSCH SchRpcRegisterTask).
            # Expand generic rights before checking the closed specific-rights allowlist.
            $mask=([long]$ace.AccessMask -band 0xFFFFFFFFL)
            if($mask -band 0x80000000L){$mask=($mask -band 0x7FFFFFFFL) -bor 0x00120089L} # GR
            if($mask -band 0x40000000L){$mask=($mask -band 0xBFFFFFFFL) -bor 0x00120116L} # GW
            if($mask -band 0x20000000L){$mask=($mask -band 0xDFFFFFFFL) -bor 0x001200A0L} # GX
            if($mask -band 0x10000000L){$mask=($mask -band 0xEFFFFFFFL) -bor 0x001F01FFL} # GA
            $allowed=if($sid -ceq $OwnerSid){0x001200A9L}else{0x001F01FFL}
            if($mask -eq 0 -or ($mask -band (-bnot $allowed)) -ne 0){throw 'ACCESS_MASK_REFUSED'}
            $rights[$sid]=$rights[$sid] -bor $mask
        }
        if($rights['S-1-5-18'] -ne 0x001F01FFL -or $rights['S-1-5-32-544'] -ne 0x001F01FFL -or
            $rights[$OwnerSid] -ne 0x001200A9L){throw 'REQUIRED_ACCESS_MISSING'}
    }catch{throw 'TASK_DACL_REFUSED'}
}

function Assert-TaskDefinition([object]$Task,[string]$TaskName,[string]$Operation,[string]$WorkerSha){
    $definition=$Task.Definition
    if($definition.Triggers.Count -ne 0){throw 'TASK_TRIGGER_REFUSED'}
    if($definition.Actions.Count -ne 1){throw 'TASK_ACTION_COUNT_REFUSED'}
    $action=$definition.Actions.Item(1)
    $pwsh=(Get-Command pwsh -ErrorAction Stop).Source
    if(-not [string]::Equals($action.Path,$pwsh,[StringComparison]::OrdinalIgnoreCase) -or
        $action.Arguments -cne (Get-ExpectedArguments $Operation $WorkerSha) -or $action.WorkingDirectory){throw 'TASK_ACTION_REFUSED'}
    Assert-TaskPrincipal $definition.Principal
    if(-not $definition.Settings.Enabled -or -not $definition.Settings.AllowDemandStart -or
        $definition.Settings.StartWhenAvailable -or $definition.Settings.MultipleInstances -ne 2 -or
        $definition.Settings.DisallowStartIfOnBatteries -or $definition.Settings.StopIfGoingOnBatteries -or
        $definition.Settings.ExecutionTimeLimit -cne 'PT35M'){throw 'TASK_SETTINGS_REFUSED'}
    Assert-TaskDacl ($Task.GetSecurityDescriptor(0xF))
}

function Install-Tasks {
    Assert-Elevated
    if(-not $AcceptInstall){throw 'EXPLICIT_INSTALL_ACCEPTANCE_REQUIRED'}
    if(-not (Test-Path -LiteralPath $workerSource -PathType Leaf)){throw 'WORKER_SOURCE_REQUIRED'}
    if(-not (Test-Path -LiteralPath $bundleRoot -PathType Container)){throw 'ACCEPTED_BUNDLE_REQUIRED'}
    foreach($path in @($controlRoot,$binRoot,$requestRoot,$resultRoot)){Assert-NoReparse $path}
    New-ProtectedDirectoryAcl $controlRoot Protected
    New-ProtectedDirectoryAcl $binRoot Protected
    New-ProtectedDirectoryAcl $requestRoot Requests
    New-ProtectedDirectoryAcl $resultRoot Results
    Copy-Item -LiteralPath $workerSource -Destination $workerInstalled -Force
    $workerSha=(Get-FileHash -LiteralPath $workerInstalled -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-DirectoryAcl $controlRoot Protected;Assert-DirectoryAcl $binRoot Protected;Assert-DirectoryAcl $requestRoot Requests;Assert-DirectoryAcl $resultRoot Results
    $service=Get-TaskService;$folder=$service.GetFolder('\')
    $pwsh=(Get-Command pwsh -ErrorAction Stop).Source
    foreach($entry in $taskMap.GetEnumerator()){
        $definition=$service.NewTask(0)
        $definition.RegistrationInfo.Description='LDW fixed on-demand CI/JIT control operation. No trigger or recurrence.'
        $definition.Principal.UserId=$OwnerSid;$definition.Principal.LogonType=3;$definition.Principal.RunLevel=1
        $definition.Settings.Enabled=$true;$definition.Settings.AllowDemandStart=$true;$definition.Settings.StartWhenAvailable=$false
        $definition.Settings.DisallowStartIfOnBatteries=$false;$definition.Settings.StopIfGoingOnBatteries=$false
        $definition.Settings.MultipleInstances=2;$definition.Settings.ExecutionTimeLimit='PT35M'
        $action=$definition.Actions.Create(0);$action.Path=$pwsh;$action.Arguments=Get-ExpectedArguments $entry.Value $workerSha
        $name=$entry.Key.TrimStart('\')
        # CREATE_OR_UPDATE | DONT_ADD_PRINCIPAL_ACE: keep only the explicit reviewed SDDL.
        # https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_creation
        $null=$folder.RegisterTaskDefinition($name,$definition,0x16,$OwnerSid,$null,3,$taskSddl)
        Assert-TaskDefinition ($folder.GetTask($entry.Key)) $entry.Key $entry.Value $workerSha
    }
    'CI_JIT_CONTROL_TASK_INSTALL=PASS'
    'WORKER_SHA256='+$workerSha
}

function Get-Status {
    Assert-Elevated
    if(-not (Test-Path -LiteralPath $workerInstalled -PathType Leaf)){throw 'WORKER_NOT_INSTALLED'}
    $workerSha=(Get-FileHash -LiteralPath $workerInstalled -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-DirectoryAcl $controlRoot Protected;Assert-DirectoryAcl $binRoot Protected;Assert-DirectoryAcl $requestRoot Requests;Assert-DirectoryAcl $resultRoot Results
    $service=Get-TaskService;$folder=$service.GetFolder('\')
    foreach($entry in $taskMap.GetEnumerator()){Assert-TaskDefinition ($folder.GetTask($entry.Key)) $entry.Key $entry.Value $workerSha}
    'CI_JIT_CONTROL_TASK_STATUS=PASS'
    'TRIGGER_COUNT=0'
    'WORKER_SHA256='+$workerSha
}

function Uninstall-Tasks {
    Assert-Elevated
    if(-not $AcceptUninstall){throw 'EXPLICIT_UNINSTALL_ACCEPTANCE_REQUIRED'}
    $service=Get-TaskService;$folder=$service.GetFolder('\')
    foreach($name in $taskMap.Keys){try{$task=$folder.GetTask($name);if($task.State -eq 4){throw 'ACTIVE_TASK_REFUSED'};$folder.DeleteTask($name.TrimStart('\'),0)}catch{if($_.Exception.Message -eq 'ACTIVE_TASK_REFUSED'){throw}}}
    if(Test-Path -LiteralPath $controlRoot){
        if(@(Get-ChildItem -LiteralPath $requestRoot -File -ErrorAction SilentlyContinue).Count){throw 'PENDING_REQUEST_REFUSED'}
        Remove-Item -LiteralPath $controlRoot -Recurse -Force
    }
    'CI_JIT_CONTROL_TASK_UNINSTALL=PASS'
}

if($Mode -eq 'Plan'){
    if(-not (Test-Path -LiteralPath $workerSource -PathType Leaf)){throw 'WORKER_SOURCE_REQUIRED'}
    $sha=(Get-FileHash -LiteralPath $workerSource -Algorithm SHA256).Hash.ToLowerInvariant()
    'CI_JIT_CONTROL_TASK_PLAN=PASS';'TASK_COUNT='+$taskMap.Count;'TRIGGER_COUNT=0';'OWNER_SID='+$OwnerSid;'WORKER_SHA256='+$sha;'BUNDLE_COMMIT='+$Commit
}elseif($Mode -eq 'Install'){Install-Tasks}elseif($Mode -eq 'Status'){Get-Status}else{Uninstall-Tasks}
