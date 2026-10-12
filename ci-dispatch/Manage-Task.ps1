[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Disable','Enable','Uninstall')][string]$Mode='Plan',
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha,
    [switch]$OwnerAccepted
)
$ErrorActionPreference='Stop'

function ConvertTo-Ci10PsLiteral {
    param([Parameter(Mandatory)][string]$Value)
    "'" + $Value.Replace("'","''") + "'"
}

function Get-Ci10TaskArguments {
    param(
        [Parameter(Mandatory)][string]$Bundle,
        [Parameter(Mandatory)][string]$Commit,
        [Parameter(Mandatory)][string]$Tree,
        [Parameter(Mandatory)][string]$ManifestSha
    )
    # The scheduled action begins with an inline verifier stored in the protected task definition.
    # It establishes filesystem trust before any file from the release is read as code.
    $template=@'
$ErrorActionPreference='Stop'
function AP([string]$p){$f=[IO.Path]::GetFullPath($p);$c=$f;while($c){$i=Get-Item -LiteralPath $c -Force -ErrorAction Stop;if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'TASK_PREFLIGHT_REPARSE_PATH_REFUSED'};$c=[IO.Path]::GetDirectoryName($c)};$a=Get-Acl -LiteralPath $f;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'TASK_PREFLIGHT_OWNER_UNTRUSTED'};$w=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership;$r=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));foreach($x in $r){if($x.AccessControlType -eq 'Allow' -and ($x.FileSystemRights -band $w) -and $x.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'TASK_PREFLIGHT_ACL_UNTRUSTED_WRITE'}};foreach($s in @('S-1-5-18','S-1-5-32-544')){if(-not @($r|Where-Object{$_.IdentityReference.Value -eq $s -and $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl}).Count){throw 'TASK_PREFLIGHT_ACL_REQUIRED_PRINCIPAL_MISSING'}}}
function AB([string]$p){$f=[IO.Path]::GetFullPath($p);$i=Get-Item -LiteralPath $f -Force -ErrorAction Stop;if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'TASK_PREFLIGHT_REPARSE_PATH_REFUSED'};$a=Get-Acl -LiteralPath $f;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'TASK_PREFLIGHT_PARENT_OWNER_UNTRUSTED'};$d=[Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership;foreach($x in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($x.AccessControlType -eq 'Allow' -and -not ($x.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($x.FileSystemRights -band $d) -and $x.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'TASK_PREFLIGHT_PARENT_REPLACEMENT_UNTRUSTED'}}}
$b=__BUNDLE__
$releases=[IO.Path]::GetDirectoryName($b)
$root=[IO.Path]::GetDirectoryName($releases)
$parent=[IO.Path]::GetDirectoryName($root)
$grand=[IO.Path]::GetDirectoryName($parent)
$m=Join-Path $b 'manifest.json'
$e=Join-Path $b 'ci-dispatch/Invoke-Dispatcher.ps1'
$d=Join-Path $b 'ci-dispatch/Dispatch.psm1'
foreach($p in @($root,$releases,$b,(Split-Path $e -Parent),$m,$e,$d)){AP $p}
AB $parent
AB $grand
if((Get-FileHash -LiteralPath $m -Algorithm SHA256).Hash.ToLowerInvariant() -cne __MANIFEST__){throw 'MANIFEST_HASH_DRIFT'}
$j=Get-Content -LiteralPath $m -Raw|ConvertFrom-Json
if($j.schema -ne 1 -or $j.commit -cne __COMMIT__ -or $j.tree -cne __TREE__){throw 'TASK_PREFLIGHT_PROVENANCE_MISMATCH'}
foreach($q in @('ci-dispatch/Invoke-Dispatcher.ps1','ci-dispatch/Dispatch.psm1')){$x=@($j.files|Where-Object path -CEQ $q);if($x.Count -ne 1 -or $x[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath (Join-Path $b $q) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $x[0].sha256){throw 'TASK_PREFLIGHT_HASH_DRIFT'}}
& $e -Commit __COMMIT__ -Tree __TREE__ -ManifestSha __MANIFEST__ -Mode Once
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
'@
    $command=$template.Replace('__BUNDLE__',(ConvertTo-Ci10PsLiteral $Bundle)).
        Replace('__COMMIT__',(ConvertTo-Ci10PsLiteral $Commit)).
        Replace('__TREE__',(ConvertTo-Ci10PsLiteral $Tree)).
        Replace('__MANIFEST__',(ConvertTo-Ci10PsLiteral $ManifestSha))
    $command=($command -replace '\r?\n',';').Trim([char[]]@(';'))
    '-NoLogo -NoProfile -NonInteractive -Command "'+$command+'"'
}

function ConvertFrom-Ci10TaskDuration {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return [TimeSpan]::Zero }
    if ($Value -is [TimeSpan]) { return $Value }
    try { [Xml.XmlConvert]::ToTimeSpan([string]$Value) } catch { throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN' }
}

function Assert-Ci10TaskIdentity {
    param(
        [Parameter(Mandatory)][object]$Task,
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$Arguments,
        [Parameter(Mandatory)][string]$Owner
    )
    if ($Task.TaskPath -cne '\' -or @($Task.Actions).Count -ne 1 -or
        $Task.Actions[0].Execute -cne $Executable -or $Task.Actions[0].Arguments -cne $Arguments -or
        -not [string]::IsNullOrEmpty([string]$Task.Actions[0].WorkingDirectory) -or
        $Task.Principal.UserId -ine $Owner -or $Task.Principal.LogonType -ne 'Interactive' -or
        $Task.Principal.RunLevel -ne 'Highest') {
        throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }

    $triggers=@($Task.Triggers)
    if ($triggers.Count -ne 2) { throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN' }
    $logon=@($triggers|Where-Object { $_.CimClass.CimClassName -ceq 'MSFT_TaskLogonTrigger' })
    $daily=@($triggers|Where-Object { $_.CimClass.CimClassName -ceq 'MSFT_TaskDailyTrigger' })
    if ($logon.Count -ne 1 -or $daily.Count -ne 1) { throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN' }
    $logon=$logon[0];$daily=$daily[0]
    if (-not $logon.Enabled -or $logon.UserId -ine $Owner -or
        -not [string]::IsNullOrEmpty([string]$logon.StartBoundary) -or
        -not [string]::IsNullOrEmpty([string]$logon.EndBoundary) -or
        (ConvertFrom-Ci10TaskDuration $logon.Delay) -ne [TimeSpan]::Zero -or
        (ConvertFrom-Ci10TaskDuration $logon.Repetition.Interval) -ne [TimeSpan]::Zero -or
        (ConvertFrom-Ci10TaskDuration $logon.Repetition.Duration) -ne [TimeSpan]::Zero -or
        [bool]$logon.Repetition.StopAtDurationEnd -or
        -not $daily.Enabled -or [int]$daily.DaysInterval -ne 1 -or
        -not [string]::IsNullOrEmpty([string]$daily.UserId) -or
        -not [string]::IsNullOrEmpty([string]$daily.EndBoundary) -or
        (ConvertFrom-Ci10TaskDuration $daily.RandomDelay) -ne [TimeSpan]::Zero) {
        throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    try {
        $start=[DateTimeOffset]::Parse([string]$daily.StartBoundary,[Globalization.CultureInfo]::InvariantCulture)
    } catch { throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN' }
    if ($start.ToLocalTime().TimeOfDay -ne [TimeSpan]::Zero -or
        (ConvertFrom-Ci10TaskDuration $daily.Repetition.Interval) -ne (New-TimeSpan -Minutes 1) -or
        (ConvertFrom-Ci10TaskDuration $daily.Repetition.Duration) -ne (New-TimeSpan -Days 1) -or
        -not [bool]$daily.Repetition.StopAtDurationEnd) {
        throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }

    $settings=$Task.Settings
    if ($settings.MultipleInstances -ne 'IgnoreNew' -or
        (ConvertFrom-Ci10TaskDuration $settings.ExecutionTimeLimit) -ne (New-TimeSpan -Minutes 25) -or
        -not [bool]$settings.StartWhenAvailable -or
        [bool]$settings.DisallowStartIfOnBatteries -or
        [bool]$settings.StopIfGoingOnBatteries -or
        -not [bool]$settings.AllowDemandStart -or
        -not [bool]$settings.AllowHardTerminate -or
        $settings.Compatibility -ne 'Win7' -or
        -not [string]::IsNullOrEmpty([string]$settings.DeleteExpiredTaskAfter) -or
        -not [bool]$settings.Enabled -or
        [bool]$settings.Hidden -or
        [int]$settings.Priority -ne 7 -or
        [int]$settings.RestartCount -ne 0 -or
        -not [string]::IsNullOrEmpty([string]$settings.RestartInterval) -or
        [bool]$settings.RunOnlyIfIdle -or
        [bool]$settings.WakeToRun) {
        throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
}

$taskName='LDW-CI10-Dispatcher'
$root=Join-Path $env:ProgramData 'LDW/CiRunnerDispatch'
$bundle=Join-Path $root ('releases/'+$Commit)
try {
    Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1') -Force
    $null=Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
    $executable=(Get-Command pwsh).Source
    $arguments=Get-Ci10TaskArguments -Bundle $bundle -Commit $Commit -Tree $Tree -ManifestSha $ManifestSha
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    $tasks=@(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
    if ($tasks.Count -gt 1) { throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN' }
    $task=if($tasks.Count -eq 1){$tasks[0]}else{$null}
    if ($task) { Assert-Ci10TaskIdentity -Task $task -Executable $executable -Arguments $arguments -Owner $owner }

    switch ($Mode) {
        Plan {
            'TASK_PACKET=PASS'
            'PROPOSED=OWNER_SESSION_INTERACTIVE_HIGHEST_LOGON_AND_EVERY_MINUTE_ONCE_IGNORE_NEW'
            'PRE_LOGIN_REBOOT_INDEPENDENT=NO'
        }
        Status { 'TASK_PRESENT='+$(if($task){'YES'}else{'NO'}); 'TASK_ENABLED='+$(if($task -and $task.State -ne 'Disabled'){'YES'}else{'NO'}) }
        Install {
            if (-not $OwnerAccepted) { throw 'ORCH_OWNER_ACCEPTANCE_REQUIRED' }
            if ($task) { throw 'TASK_ALREADY_EXISTS' }
            $principal=New-ScheduledTaskPrincipal -UserId $owner -LogonType Interactive -RunLevel Highest
            $action=New-ScheduledTaskAction -Execute $executable -Argument $arguments
            $logon=New-ScheduledTaskTrigger -AtLogOn -User $owner
            $repeat=New-ScheduledTaskTrigger -Once -At ([DateTime]::Today.AddDays(1)) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 1)
            $daily=New-ScheduledTaskTrigger -Daily -At ([DateTime]::Today)
            $daily.Repetition=$repeat.Repetition
            $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 25) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            $null=Register-ScheduledTask -TaskName $taskName -InputObject (New-ScheduledTask -Action $action -Principal $principal -Trigger @($logon,$daily) -Settings $settings)
            'TASK_INSTALLED=YES'
        }
        Disable { if ($task) { $null=Disable-ScheduledTask -TaskName $taskName }; 'TASK_DISABLED=YES' }
        Enable {
            if (-not $OwnerAccepted) { throw 'ORCH_OWNER_ACCEPTANCE_REQUIRED' }
            if (-not $task) { throw 'TASK_MISSING' }
            $null=Enable-ScheduledTask -TaskName $taskName; 'TASK_ENABLED=YES'
        }
        Uninstall {
            if ($task) {
                $null=Disable-ScheduledTask -TaskName $taskName
                Stop-ScheduledTask -TaskName $taskName
            }
            # Recovery does not select/claim a queued job and never kills a live controller.
            & $executable -NoLogo -NoProfile -NonInteractive -File (Join-Path $bundle 'ci-dispatch/Invoke-Dispatcher.ps1') -Commit $Commit -Tree $Tree -ManifestSha $ManifestSha -Mode Recover
            if ($LASTEXITCODE -ne 0) { throw 'ROLLBACK_RECOVERY_PENDING' }
            if ($task) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'TASK_REMOVAL_UNCONFIRMED' }
            'TASK_UNINSTALLED=YES'
            'RUNTIME_BUNDLE_RETAINED=YES'
        }
    }
} catch {
    $code=[string]$_.Exception.Message
    if($code -cnotmatch '^[A-Z][A-Z0-9_]+$'){$code='TASK_OPERATION_FAILED'}
    'TASK_RESULT=FAIL'; 'CLASSIFICATION='+$code
    exit 1
}
