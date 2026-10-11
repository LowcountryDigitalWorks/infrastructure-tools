[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Disable','Enable','Uninstall')][string]$Mode='Plan',
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha,
    [switch]$OwnerAccepted
)
$ErrorActionPreference='Stop'
$taskName='LDW-CI10-Dispatcher'
$root=Join-Path $env:ProgramData 'LDW/CiRunnerDispatch'
$bundle=Join-Path $root ('releases/'+$Commit)
try {
    Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1') -Force
    $null=Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
    $executable=(Get-Command pwsh).Source
    $entry=Join-Path $bundle 'ci-dispatch/Invoke-Dispatcher.ps1'
    $arguments='-NoLogo -NoProfile -NonInteractive -File "'+$entry+'" -Commit '+$Commit+' -Tree '+$Tree+' -ManifestSha '+$ManifestSha+' -Mode Once'
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task -and ($task.Actions.Count -ne 1 -or $task.Actions[0].Execute -cne $executable -or
        $task.Actions[0].Arguments -cne $arguments -or $task.Principal.UserId -ine $owner -or
        $task.Principal.LogonType -ne 'Interactive' -or $task.Principal.RunLevel -ne 'Highest')) { throw 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN' }
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
            & $executable -NoLogo -NoProfile -NonInteractive -File $entry -Commit $Commit -Tree $Tree -ManifestSha $ManifestSha -Mode Recover
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
