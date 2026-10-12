[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$managePath=Join-Path $repo 'ci-dispatch/Manage-Task.ps1'
$total=0
function Check([string]$Name,[scriptblock]$Body){$script:case=$Name;& $Body;$script:total++;'PASS '+$Name}
function Assert([bool]$Condition){if(-not $Condition){throw 'TEST_ASSERTION_FAILED'}}
function Clone($Object){$Object|ConvertTo-Json -Depth 15|ConvertFrom-Json}
function AssertIdentityRefuses([object]$Task,[string]$Executable,[string]$Arguments,[string]$Owner){
    $code=$null
    try{Assert-Ci10TaskIdentity -Task $Task -Executable $Executable -Arguments $Arguments -Owner $Owner}catch{$code=$_.Exception.Message}
    Assert ($code -ceq 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN')
}
function Import-FunctionFromAst([string]$Path,[string]$Name){
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'POWERSHELL_PARSE_FAILED'}
    $definition=@($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    },$true))
    if($definition.Count -ne 1){throw 'FUNCTION_EXTRACTION_FAILED'}
    Invoke-Expression ('function script:'+$Name+' '+$definition[0].Body.Extent.Text)
    $definition[0].Extent.Text
}
try {
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($managePath,[ref]$tokens,[ref]$errors)
    Check 'task manager parses' {Assert ($errors.Count -eq 0)}

    Import-FunctionFromAst $managePath 'ConvertFrom-Ci10TaskDuration' | Out-Null
    $identitySource=Import-FunctionFromAst $managePath 'Assert-Ci10TaskIdentity'

    $owner='LDW\Owner'
    $executable='C:\Program Files\PowerShell\7\pwsh.exe'
    $arguments='-NoLogo -NoProfile -NonInteractive -Command "trusted"'
    $action=[pscustomobject]@{Execute=$executable;Arguments=$arguments;WorkingDirectory=$null}
    $principal=[pscustomobject]@{UserId=$owner;LogonType='Interactive';RunLevel='Highest'}
    $repetition=[pscustomobject]@{Interval='PT1M';Duration='P1D';StopAtDurationEnd=$true}
    $emptyRepetition=[pscustomobject]@{Interval=$null;Duration=$null;StopAtDurationEnd=$false}
    $logon=[pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskLogonTrigger'};Enabled=$true;UserId=$owner;StartBoundary=$null;EndBoundary=$null;Delay=$null;Repetition=$emptyRepetition}
    $daily=[pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskDailyTrigger'};Enabled=$true;UserId=$null;DaysInterval=1;StartBoundary='2026-10-12T04:00:00Z';EndBoundary=$null;RandomDelay=$null;Repetition=$repetition}
    $settings=[pscustomobject]@{MultipleInstances='IgnoreNew';ExecutionTimeLimit='PT25M';StartWhenAvailable=$true;DisallowStartIfOnBatteries=$false;StopIfGoingOnBatteries=$false;AllowDemandStart=$true;AllowHardTerminate=$true;Compatibility='Win7';DeleteExpiredTaskAfter=$null;Enabled=$true;Hidden=$false;Priority=7;RestartCount=0;RestartInterval=$null;RunOnlyIfIdle=$false;WakeToRun=$false}
    $enabled=[pscustomobject]@{TaskPath='\';Actions=@($action);Principal=$principal;Triggers=@($logon,$daily);Settings=$settings;State='Ready'}

    Check 'exact enabled task passes identity' {
        Assert-Ci10TaskIdentity -Task $enabled -Executable $executable -Arguments $arguments -Owner $owner
    }
    Check 'exact disabled task passes identity' {
        $disabled=Clone $enabled
        $disabled.State='Disabled'
        $disabled.Settings.Enabled=$false
        Assert-Ci10TaskIdentity -Task $disabled -Executable $executable -Arguments $arguments -Owner $owner
    }
    Check 'identity excludes mutable enabled state from ownership' {
        Assert (-not $identitySource.Contains('$settings.Enabled'))
        Assert (-not $identitySource.Contains('$Task.State'))
    }
    Check 'disabled task can reach enable and uninstall branches' {
        $source=Get-Content -LiteralPath $managePath -Raw
        $identity=$source.IndexOf('Assert-Ci10TaskIdentity -Task $task')
        $switch=$source.IndexOf('switch ($Mode)')
        $enable=$source.IndexOf("Enable {",$switch)
        $uninstall=$source.IndexOf("Uninstall {",$switch)
        Assert ($identity -ge 0 -and $switch -gt $identity -and $enable -gt $switch -and $uninstall -gt $enable)
        $postIdentity=$source.Substring($identity,$switch-$identity)
        Assert (-not $postIdentity.Contains('Settings.Enabled'))
        Assert (-not $postIdentity.Contains('$Task.State'))
    }
    Check 'action drift still fails closed' {
        $bad=Clone $enabled;$bad.Actions[0].Arguments='-NoProfile -Command altered'
        AssertIdentityRefuses -Task $bad -Executable $executable -Arguments $arguments -Owner $owner
    }
    Check 'trigger drift still fails closed' {
        $bad=Clone $enabled;$bad.Triggers[1].Repetition.Interval='PT2M'
        AssertIdentityRefuses -Task $bad -Executable $executable -Arguments $arguments -Owner $owner
    }
    Check 'concurrency drift still fails closed' {
        $bad=Clone $enabled;$bad.Settings.MultipleInstances='Parallel'
        AssertIdentityRefuses -Task $bad -Executable $executable -Arguments $arguments -Owner $owner
    }
    Check 'execution-limit drift still fails closed' {
        $bad=Clone $enabled;$bad.Settings.ExecutionTimeLimit='PT30M'
        AssertIdentityRefuses -Task $bad -Executable $executable -Arguments $arguments -Owner $owner
    }
    Check 'battery drift still fails closed' {
        $bad=Clone $enabled;$bad.Settings.DisallowStartIfOnBatteries=$true
        AssertIdentityRefuses -Task $bad -Executable $executable -Arguments $arguments -Owner $owner
    }
    Check 'task-path drift still fails closed' {
        $bad=Clone $enabled;$bad.TaskPath='\Other\'
        AssertIdentityRefuses -Task $bad -Executable $executable -Arguments $arguments -Owner $owner
    }

    'DISABLED_TASK_IDENTITY_TESTS=PASS'
    'DISABLED_TASK_IDENTITY_TEST_COUNT='+$total
} catch {
    'DISABLED_TASK_IDENTITY_TESTS=FAIL'
    'DISABLED_TASK_IDENTITY_TEST_COUNT='+$total
    'TEST_CASE='+$script:case
    'TEST_FAILURE_LINE='+$_.InvocationInfo.ScriptLineNumber
    $code=[string]$_.Exception.Message
    if($code -cnotmatch '^[A-Z][A-Z0-9_]+$'){$code='TEST_OPERATION_FAILED'}
    'CLASSIFICATION='+$code
    exit 1
}
