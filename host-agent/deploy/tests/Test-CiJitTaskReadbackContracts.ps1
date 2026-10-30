[CmdletBinding()]
param([switch]$HostedTaskSchedulerSemantic)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$managePath=Join-Path (Split-Path -Parent $PSScriptRoot) 'Manage-CiJitControlTasks.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($managePath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'MANAGE_PARSE_FAILED'}
# Load functions only. Never evaluate the installer's top-level dispatcher or directories.
foreach($name in @('Get-ExpectedArguments','Assert-TaskPrincipal','Assert-TaskDacl','Assert-TaskDefinition')){
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false)
    if($null -eq $node){throw "FUNCTION_REQUIRED: $name"}
    . ([scriptblock]::Create($node.Extent.Text))
}
$script:Assertions=0
function Assert-True([bool]$Value,[string]$Message){
    $script:Assertions++;if(-not $Value){throw "ASSERTION_FAILED: $Message"}
}
function Assert-Refused([scriptblock]$Action,[string]$Code){
    $script:Assertions++
    try{& $Action}catch{if($_.Exception.Message -ceq $Code){return};throw}
    throw "EXPECTED_REFUSAL: $Code"
}

$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$OwnerSid=$identity.User.Value
$ownerName=$identity.User.Translate([Security.Principal.NTAccount]).Value
$workerInstalled='C:\synthetic\Invoke-CiJitControlTask.ps1'
$ManifestSha='a'*64;$Commit='b'*40;$Tree='c'*40;$workerSha='d'*64
$pwshCommand=Microsoft.PowerShell.Core\Get-Command pwsh -ErrorAction SilentlyContinue
$script:TestPwshPath=if($pwshCommand){$pwshCommand.Source}else{Join-Path $PSHOME 'powershell.exe'}
function Get-Command([string]$Name){
    if($Name -cne 'pwsh'){throw 'UNEXPECTED_COMMAND_LOOKUP'}
    [pscustomobject]@{Source=$script:TestPwshPath}
}
$baseSddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
$ownerAce='(A;;GRGX;;;'+$OwnerSid+')'
function New-TaskFixture {
    $action=[pscustomobject]@{Path=$script:TestPwshPath;Arguments=(Get-ExpectedArguments DISCOVER $workerSha);WorkingDirectory=''}
    $actions=[pscustomobject]@{Count=1;Value=$action}
    $actions|Add-Member ScriptMethod Item {param($Index) if($Index -ne 1){throw 'INDEX_REFUSED'};$this.Value}
    $task=[pscustomobject]@{
        Sddl=$baseSddl+$ownerAce
        Definition=[pscustomobject]@{
            Triggers=[pscustomobject]@{Count=0};Actions=$actions
            Principal=[pscustomobject]@{UserId=$ownerName;LogonType=3;RunLevel=1}
            Settings=[pscustomobject]@{Enabled=$true;AllowDemandStart=$true;StartWhenAvailable=$false;MultipleInstances=2;
                DisallowStartIfOnBatteries=$false;StopIfGoingOnBatteries=$false;ExecutionTimeLimit='PT35M'}
        }
    }
    $task|Add-Member ScriptMethod GetSecurityDescriptor {param($Flags) if($Flags -ne 0xF){throw 'FLAGS_REFUSED'};$this.Sddl}
    $task
}
function Assert-Fixture([object]$Task){Assert-TaskDefinition $Task '\SYNTHETIC' DISCOVER $workerSha}

$task=New-TaskFixture
Assert-Fixture $task # Real Windows account-name -> exact current-user SID translation.
$script:Assertions++
$task.Definition.Principal.UserId=$OwnerSid;Assert-Fixture $task;$script:Assertions++
foreach($badId in @('S-1-5-21-100-200-300-9999',($env:COMPUTERNAME+'\LDW-NoSuchUser-'+[guid]::NewGuid().ToString('N')),'','S-invalid')){
    $task=New-TaskFixture;$task.Definition.Principal.UserId=$badId
    Assert-Refused {Assert-Fixture $task} 'TASK_PRINCIPAL_REFUSED'
}
foreach($field in @('LogonType','RunLevel')){
    $task=New-TaskFixture;$task.Definition.Principal.$field=0
    Assert-Refused {Assert-Fixture $task} 'TASK_PRINCIPAL_REFUSED'
}

foreach($sddl in @(
    ($baseSddl+'(A;;0x001200A9;;;'+$OwnerSid+')'),
    ($baseSddl+'(A;;0x00120089;;;'+$OwnerSid+')(A;;0x001200A9;;;'+$OwnerSid+')'),
    ('O:SYG:BAD:P(A;;0x001200A9;;;'+$OwnerSid+')(A;;0x001F01FF;;;BA)(A;;GA;;;SY)')
)){
    $task=New-TaskFixture;$task.Sddl=$sddl;Assert-Fixture $task;$script:Assertions++
}
# Every bit outside FILE_GENERIC_READ | FILE_GENERIC_EXECUTE is refused, including
# write-data/append/EA/attributes, DELETE, WRITE_DAC, WRITE_OWNER and unknown bits.
for($bit=0;$bit -lt 32;$bit++){
    $extra=1L -shl $bit
    if(($extra -band 0x001200A9L) -ne 0){continue}
    $mask=0x001200A9L -bor $extra
    # GR/GX are explicitly permitted representation equivalents; GW/GA are not.
    if($extra -in @(0x80000000L,0x20000000L)){continue}
    $task=New-TaskFixture;$task.Sddl=$baseSddl+'(A;;0x'+$mask.ToString('X8')+';;;'+$OwnerSid+')'
    Assert-Refused {Assert-Fixture $task} 'TASK_DACL_REFUSED'
}
foreach($badAce in @(
    ('(A;;FA;;;'+$OwnerSid+')'),('(A;;GW;;;'+$OwnerSid+')'),('(A;;GA;;;'+$OwnerSid+')'),
    ('(A;;0x001301BF;;;'+$OwnerSid+')'), # File Modify
    ('(A;;0x00120089;;;'+$OwnerSid+')'), # read only lacks demand-start/execute
    ('(D;;GR;;;'+$OwnerSid+')'),('(A;OI;GRGX;;;'+$OwnerSid+')'),
    '(A;;GRGX;;;WD)',''
)){
    $task=New-TaskFixture;$task.Sddl=$baseSddl+$badAce
    Assert-Refused {Assert-Fixture $task} 'TASK_DACL_REFUSED'
}
foreach($badSddl in @('not-sddl',('O:BAG:BAD:NO_ACCESS_CONTROL'),
    ('O:'+ $OwnerSid+'G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'+$ownerAce),
    ('O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)'+$ownerAce),
    ('O:BAG:BAD:P(A;;FR;;;SY)(A;;FA;;;BA)'+$ownerAce),
    ('O:BAG:BAD:P(A;;FA;;;SY)(A;;FR;;;BA)'+$ownerAce),
    ($baseSddl+$ownerAce+'(A;;GR;;;WD)'),
    ($baseSddl+$ownerAce+'(A;;GW;;;'+$OwnerSid+')'))){
    $task=New-TaskFixture;$task.Sddl=$badSddl
    Assert-Refused {Assert-Fixture $task} 'TASK_DACL_REFUSED'
}
foreach($drift in @(
    @{Field='Enabled';Value=$false},@{Field='AllowDemandStart';Value=$false},
    @{Field='StartWhenAvailable';Value=$true},@{Field='MultipleInstances';Value=0},
    @{Field='DisallowStartIfOnBatteries';Value=$true},@{Field='StopIfGoingOnBatteries';Value=$true},
    @{Field='ExecutionTimeLimit';Value='PT0S'}
)){
    $task=New-TaskFixture;$task.Definition.Settings.($drift.Field)=$drift.Value
    Assert-Refused {Assert-Fixture $task} 'TASK_SETTINGS_REFUSED'
}
$task=New-TaskFixture;$task.Definition.Triggers.Count=1;Assert-Refused {Assert-Fixture $task} 'TASK_TRIGGER_REFUSED'
$task=New-TaskFixture;$task.Definition.Actions.Count=2;Assert-Refused {Assert-Fixture $task} 'TASK_ACTION_COUNT_REFUSED'
foreach($field in @('Path','Arguments','WorkingDirectory')){
    $task=New-TaskFixture;$task.Definition.Actions.Value.$field='drift'
    Assert-Refused {Assert-Fixture $task} 'TASK_ACTION_REFUSED'
}
$source=Get-Content -LiteralPath $managePath -Raw
Assert-True ($source.Contains('RegisterTaskDefinition($name,$definition,0x16,$OwnerSid,$null,3,$taskSddl)')) 'registration must suppress automatic principal ACE'
Assert-True ($source.Contains('$registered.SetSecurityDescriptor($taskSddl,0x10)')) 'install must converge legacy task DACL before readback'
Write-Host "CI_JIT_TASK_READBACK_CONTRACT=PASS ASSERTIONS=$script:Assertions"

if($HostedTaskSchedulerSemantic){
    # Explicit opt-in AND GitHub-hosted Windows only. Never register/run local LDW tasks.
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows'){
        throw 'GITHUB_HOSTED_WINDOWS_REQUIRED'
    }
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'HOSTED_TASK_TEST_PRIVILEGE_REQUIRED'}
    $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
    $name='LDW-Readback-Test-'+[guid]::NewGuid().ToString('N')
    # No triggers, no Run call. Harmless fixed exit action even if invoked externally.
    $definition=$service.NewTask(0)
    $definition.Principal.UserId=$OwnerSid;$definition.Principal.LogonType=3;$definition.Principal.RunLevel=1
    $definition.Settings.Enabled=$true;$definition.Settings.AllowDemandStart=$true;$definition.Settings.StartWhenAvailable=$false
    $definition.Settings.MultipleInstances=2;$definition.Settings.DisallowStartIfOnBatteries=$false
    $definition.Settings.StopIfGoingOnBatteries=$false;$definition.Settings.ExecutionTimeLimit='PT35M'
    $action=$definition.Actions.Create(0);$action.Path=$script:TestPwshPath;$action.Arguments='-NoLogo -NoProfile -NonInteractive -Command "exit 0"'
    function Get-ExpectedArguments([string]$Operation,[string]$WorkerSha){'-NoLogo -NoProfile -NonInteractive -Command "exit 0"'}
    $created=$false
    try{
        # Reproduce the legacy residue class directly: unprotected DACL plus an extra
        # safe owner-read ACE. The strict validator must refuse this pre-convergence state.
        $legacySddl='O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200A9;;;'+$OwnerSid+')(A;;0x00120089;;;'+$OwnerSid+')'
        $registered=$folder.RegisterTaskDefinition($name,$definition,0x2,$OwnerSid,$null,3,$legacySddl);$created=$true
        $legacyReadback=$folder.GetTask($name)
        Assert-Refused {Assert-TaskDefinition $legacyReadback $name DISCOVER $workerSha} 'TASK_DACL_REFUSED'

        # Update the definition through the production flags, then explicitly replace
        # the task security descriptor. TASK_DONT_ADD_PRINCIPAL_ACE on update alone does
        # not remove an old context-principal ACE; SetSecurityDescriptor provides the
        # reviewed exact ACL convergence step before strict readback validation.
        $registered=$folder.RegisterTaskDefinition($name,$definition,0x16,$OwnerSid,$null,3,($baseSddl+$ownerAce))
        $registered.SetSecurityDescriptor(($baseSddl+$ownerAce),0x10)
        $readback=$folder.GetTask($name)
        Assert-TaskDefinition $readback $name DISCOVER $workerSha
        $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($readback.GetSecurityDescriptor(0xF))
        Assert-True (($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0) 'explicit convergence must restore protected DACL semantics'
        $ownerAces=@($descriptor.DiscretionaryAcl|Where-Object{$_.SecurityIdentifier.Value -ceq $OwnerSid})
        Assert-True ($ownerAces.Count -eq 1) 'explicit convergence must replace legacy duplicate owner ACEs'
    }finally{
        if($created){$folder.DeleteTask($name,0)}
    }
    $remaining=@($folder.GetTasks(1)|Where-Object{$_.Name -ceq $name})
    Assert-True ($remaining.Count -eq 0) 'throwaway task must be absent after cleanup'
    Write-Host 'CI_JIT_TASK_SCHEDULER_SEMANTICS=PASS LEGACY_DACL_CONVERGENCE_NO_RUN_CLEANUP=PASS'
}
