#Requires -Version 5.1
<#
.SYNOPSIS
Disposable GitHub-HOSTED Windows Task Scheduler LocalSystem execution proof.
.DESCRIPTION
No arguments, no protected LDW01 work, no ProgramData access, no ACL changes.
Creates a random no-trigger task on a GitHub-HOSTED runner only, verifies
closed SYSTEM task principal/descriptor/action, runs one inline read-only
identity assertion, then deletes ONLY its disposable task.
Not an issuer, real bootstrap, journal creator, installer or ACL mutator.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'D0_HOSTED_WINPS51_X64_REQUIRED'
}
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
    $env:REDRIX_D0_SYNTHETIC_RUNNER_CLASS -cne 'github-hosted') {
    throw 'D0_GITHUB_HOSTED_RUNNER_ONLY'
}
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'D0_DISPOSABLE_TASK_HOST_ADMIN_REQUIRED'
}

$script:Checks = 0
function Assert-D0([bool]$Condition, [string]$Code) {
    $script:Checks++
    if (-not $Condition) { throw ('D0_TASK_ASSERT_' + $Code) }
}
function Assert-StrictTaskDescriptor([string]$Sddl) {
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    Assert-D0 ($raw.Owner.Value -ceq 'S-1-5-18') 'TASK_OWNER_SYSTEM'
    Assert-D0 ($raw.Group.Value -ceq 'S-1-5-18') 'TASK_GROUP_SYSTEM'
    Assert-D0 ((($raw.ControlFlags -band
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0)) 'TASK_DACL_PROTECTED'
    Assert-D0 ($raw.DiscretionaryAcl.Count -eq 2) 'TASK_EXACTLY_TWO_ACES'
    $required = @('S-1-5-18', 'S-1-5-32-544')
    for ($i=0; $i -lt $raw.DiscretionaryAcl.Count; $i++) {
        $ace = $raw.DiscretionaryAcl[$i]
        Assert-D0 ($ace -is [Security.AccessControl.CommonAce]) ('TASK_ACE_TYPE_' + $i)
        Assert-D0 ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed) ('TASK_ACE_ALLOW_' + $i)
        Assert-D0 ($ace.AceFlags -eq [Security.AccessControl.AceFlags]::None) ('TASK_ACE_FLAGS_' + $i)
        Assert-D0 ([int64]$ace.AccessMask -eq 0x001F01FF) ('TASK_ACE_MASK_' + $i)
        Assert-D0 ($required -ccontains $ace.SecurityIdentifier.Value) ('TASK_ACE_SID_' + $i)
        $required = @($required | Where-Object { $_ -cne $ace.SecurityIdentifier.Value })
    }
    Assert-D0 ($required.Count -eq 0) 'TASK_ACE_SET_COMPLETE'
}

$windows = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($windows)) { throw 'D0_WINDOWS_FOLDER_MISSING' }
$exe = [IO.Path]::GetFullPath(
    (Join-Path (Join-Path $windows 'System32') 'WindowsPowerShell/v1.0/powershell.exe'))
if (-not [IO.File]::Exists($exe)) { throw 'D0_WINDOWS_NATIVE_POWERSHELL_MISSING' }
if (([IO.File]::GetAttributes($exe) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'D0_WINDOWS_EXECUTABLE_REPARSE_REFUSED'
}
$signature = Get-AuthenticodeSignature -LiteralPath $exe
Assert-D0 ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid) 'SYSTEM_BINARY_SIGNATURE_VALID'

# Source-fixed inline proof; no script file, external path, arbitrary shell,
# caller field, credential, journal, endpoint, environment read or download.
# It returns exit 0 ONLY from an actual LocalSystem process.
$probe = 'if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne ' +
    '"S-1-5-18"){exit 41};[Threading.Thread]::Sleep(2800);exit 0'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
$expectedArgs = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded
$taskName = 'LDW-REDRIX-D0-HOSTED-ONLY-' + [Guid]::NewGuid().ToString('N')
$taskSddl = 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'

$service = $null
$folder = $null
$installed = $null
$ran = $false
$cleanupVerified = $false
$sourceComplete = $false
$script:Phase = 'BEFORE_SERVICE'
try {
    $script:Phase = 'CONNECT_TASK_SCHEDULER'
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    $script:Phase = 'CREATE_TASK_DEFINITION'
    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Description =
        'LDW D0 source research: one hosted-only no-trigger SYSTEM identity proof, always disposable.'
    $definition.Principal.UserId = 'SYSTEM'
    $definition.Principal.LogonType = 5
    $definition.Principal.RunLevel = 1
    $definition.Settings.Enabled = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.Hidden = $true
    $definition.Settings.ExecutionTimeLimit = 'PT30S'
    $definition.Settings.MultipleInstances = 2
    $definition.Settings.RunOnlyIfNetworkAvailable = $false
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $execAction = $definition.Actions.Create(0)
    $execAction.Path = $exe
    $execAction.Arguments = $expectedArgs
    $execAction.WorkingDirectory = Join-Path $windows 'System32'

    Assert-D0 ($definition.Triggers.Count -eq 0) 'NO_TRIGGERS_BEFORE'
    Assert-D0 ($definition.Actions.Count -eq 1) 'ONE_ACTION_BEFORE'
    Assert-D0 ($definition.Principal.LogonType -eq 5) 'SERVICE_ACCOUNT_BEFORE'
    Assert-D0 ($definition.Principal.RunLevel -eq 1) 'HIGHEST_RUNLEVEL_BEFORE'
    # TASK_CREATE=2: CREATE ONLY, never modify/replace an existing task.
    # TASK_LOGON_SERVICE_ACCOUNT=5: no stored task password.
    $script:Phase = 'REGISTER_FIXED_SYSTEM_TASK'
    $installed = $folder.RegisterTaskDefinition(
        $taskName, $definition, 2, 'SYSTEM', $null, 5, $taskSddl)
    Assert-D0 ($null -ne $installed) 'CREATE_RETURNED_HANDLE'
    $script:Phase = 'READBACK_REGISTERED_TASK'
    $task = $folder.GetTask($taskName)
    Assert-D0 ($task.Name -ceq $taskName) 'EXACT_TASK_NAME'
    Assert-D0 ($task.Definition.Triggers.Count -eq 0) 'NO_TRIGGERS_AFTER'
    Assert-D0 ($task.Definition.Actions.Count -eq 1) 'ONE_ACTION_AFTER'
    $taskAction = $task.Definition.Actions.Item(1)
    Assert-D0 (([IO.Path]::GetFullPath([string]$taskAction.Path)) -ceq $exe) 'FIXED_SYSTEM_EXE'
    Assert-D0 ([string]$taskAction.Arguments -ceq $expectedArgs) 'FIXED_INLINE_ARGUMENTS'
    Assert-D0 ($task.Definition.Principal.LogonType -eq 5) 'SERVICE_ACCOUNT_AFTER'
    Assert-D0 ($task.Definition.Principal.RunLevel -eq 1) 'HIGHEST_RUNLEVEL_AFTER'
    $identity = [string]$task.Definition.Principal.UserId
    Assert-D0 ($identity -in @('SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM')) 'SYSTEM_PRINCIPAL_AFTER'
    Assert-D0 ($task.Definition.Settings.Enabled) 'TASK_ENABLED'
    Assert-D0 ($task.Definition.Settings.AllowDemandStart) 'NO_AMBIENT_TRIGGER_DEMAND_ONLY'
    Assert-StrictTaskDescriptor ($task.GetSecurityDescriptor(7))

    # No ambient scheduler; explicitly invoke the fixed read-only SYSTEM
    # identity check ONLY on this ephemeral hosted runner.
    $script:Phase = 'RUN_FIXED_SYSTEM_IDENTITY_TASK'
    $run = $task.Run($null)
    Assert-D0 ($null -ne $run) 'RUNNING_HANDLE'
    $script:Phase = 'WAIT_FIXED_SYSTEM_IDENTITY_TASK'
    $runningObserved = $false
    $completedObserved = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    while ([DateTime]::UtcNow -lt $deadline) {
        $now = $folder.GetTask($taskName)
        if ([int]$now.State -eq 4) { $runningObserved = $true }
        if ($runningObserved -and [int]$now.State -ne 4) {
            $completedObserved = $true
            break
        }
        [Threading.Thread]::Sleep(200)
    }
    Assert-D0 $runningObserved 'ACTUAL_SYSTEM_RUN_OBSERVED'
    Assert-D0 $completedObserved 'ACTUAL_SYSTEM_RUN_TERMINAL'
    $finished = $folder.GetTask($taskName)
    Assert-D0 ([int]$finished.LastTaskResult -eq 0) 'SYSTEM_IDENTITY_EXIT_ZERO'
    Assert-D0 ($finished.Definition.Triggers.Count -eq 0) 'NO_TRIGGER_DRIFT_AFTER_RUN'
    Assert-StrictTaskDescriptor ($finished.GetSecurityDescriptor(7))
    $ran = $true
    $sourceComplete = $true
}
catch {
    Write-Output ('REDRIX_D0_HOSTED_SYSTEM_TASK_FAILURE_PHASE=' + $script:Phase)
    throw
}
finally {
    Write-Output 'REDRIX_D0_HOSTED_SYSTEM_TASK_CLEANUP=START'
    if ($null -ne $folder) {
        # Only this unpredictable fixture-owned name. No registry-wide
        # cleanup, no touch to existing V1 or protected CI/JIT tasks.
        $existing = $null
        try { $existing = $folder.GetTask($taskName) }
        catch [Runtime.InteropServices.COMException] { $existing = $null }
        catch [IO.FileNotFoundException] { $existing = $null }
        if ($null -ne $existing) {
            if ([int]$existing.State -eq 4) { $existing.Stop(0) }
            $folder.DeleteTask($taskName, 0)
        }
        $found = $false
        foreach ($entry in @($folder.GetTasks(1))) {
            if ($entry.Name -ceq $taskName) { $found = $true }
        }
        $cleanupVerified = -not $found
    }
    Write-Output ('REDRIX_D0_HOSTED_SYSTEM_TASK_CLEANUP_VERIFIED=' + $cleanupVerified)
}
Assert-D0 $sourceComplete 'REGISTER_RUN_COMPLETED'
Assert-D0 $ran 'ACTUAL_RUN_COMPLETED'
Assert-D0 $cleanupVerified 'EXACT_TASK_REMOVED'
Write-Output ('REDRIX_D0_HOSTED_SYSTEM_TASK_PROOF=PASS assertions=' + $script:Checks)
Write-Output 'REDRIX_D0_HOSTED_PROOF_LDW01_SYSTEM_TASK_INSTALLED=FALSE'
Write-Output 'REDRIX_D0_HOSTED_PROOF_INITIAL_SOURCE_ROOT_TRUSTED=FALSE'
Write-Output 'REDRIX_D0_HOSTED_PROOF_SYSTEM_JOURNAL_AT_CREATE_PROVEN=FALSE'
Write-Output 'REDRIX_D0_HOSTED_PROOF_PHYSICAL_AUTHORITY=HOLD_SECURITY'
