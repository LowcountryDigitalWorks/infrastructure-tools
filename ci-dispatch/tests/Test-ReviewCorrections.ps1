[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$managePath=Join-Path $repo 'ci-dispatch/Manage-Task.ps1'
$invokePath=Join-Path $repo 'ci-dispatch/Invoke-Dispatcher.ps1'
$total=0
function Check([string]$Name,[scriptblock]$Body){$script:case=$Name;& $Body;$script:total++;'PASS '+$Name}
function Assert([bool]$Condition){if(-not $Condition){throw 'TEST_ASSERTION_FAILED'}}
function Refuses([scriptblock]$Action,[string]$Expected){
    $code=$null
    try{& $Action|Out-Null}catch{$code=$_.Exception.Message}
    Assert ($null -ne $code)
    if($Expected){Assert ($code -ceq $Expected)}
}
function Clone($Object){$Object|ConvertTo-Json -Depth 15|ConvertFrom-Json}
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
}
try {
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($managePath,[ref]$tokens,[ref]$errors)
    Check 'task manager parses' {Assert ($errors.Count -eq 0)}
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($invokePath,[ref]$tokens,[ref]$errors)
    Check 'dispatcher entry parses' {Assert ($errors.Count -eq 0)}

    foreach($name in @('ConvertTo-Ci10PsLiteral','Get-Ci10TaskArguments','ConvertFrom-Ci10TaskDuration','Assert-Ci10TaskIdentity')){
        Import-FunctionFromAst $managePath $name
    }

    $commit='a'*40;$tree='b'*40;$manifest='c'*64
    $taskArguments=Get-Ci10TaskArguments -Bundle 'C:\ProgramData\LDW\CiRunnerDispatch\releases\candidate' -Commit $commit -Tree $tree -ManifestSha $manifest
    Check 'standing task verifier precedes bundle code execution' {
        $acl=$taskArguments.IndexOf('Get-Acl')
        $hash=$taskArguments.IndexOf('Get-FileHash')
        $invoke=$taskArguments.IndexOf('& $e -Commit')
        Assert ($acl -ge 0 -and $hash -gt $acl -and $invoke -gt $hash)
        Assert (-not $taskArguments.Contains('-EncodedCommand'))
        Assert ($taskArguments.Length -lt 30000)
    }

    $invokeSource=Get-Content -LiteralPath $invokePath -Raw
    Check 'entry establishes local path trust before manifest read or module import' {
        $pathTrust=$invokeSource.IndexOf('Assert-Ci10PreImportProtectedPath $path')
        $manifestRead=$invokeSource.IndexOf('$preflight = Get-Content')
        $moduleImport=$invokeSource.IndexOf('Import-Module $modulePath')
        Assert ($pathTrust -ge 0 -and $manifestRead -gt $pathTrust -and $moduleImport -gt $manifestRead)
        Assert ($invokeSource.IndexOf('Assert-Ci10PreImportParentBoundary $parent') -lt $manifestRead)
        Assert ($invokeSource.IndexOf('Get-FileHash -LiteralPath $manifestPath') -lt $moduleImport)
    }

    $owner='LDW\Owner'
    $action=[pscustomobject]@{Execute='C:\Program Files\PowerShell\7\pwsh.exe';Arguments=$taskArguments;WorkingDirectory=$null}
    $principal=[pscustomobject]@{UserId=$owner;LogonType='Interactive';RunLevel='Highest'}
    $repetition=[pscustomobject]@{Interval='PT1M';Duration='P1D';StopAtDurationEnd=$false}
    $logon=[pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskLogonTrigger'};Enabled=$true;UserId=$owner;EndBoundary=$null}
    $daily=[pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskDailyTrigger'};Enabled=$true;DaysInterval=1;StartBoundary='2026-10-12T00:00:00';EndBoundary=$null;Repetition=$repetition}
    $settings=[pscustomobject]@{MultipleInstances='IgnoreNew';ExecutionTimeLimit='PT25M';StartWhenAvailable=$true;DisallowStartIfOnBatteries=$false;StopIfGoingOnBatteries=$false}
    $task=[pscustomobject]@{TaskPath='\';Actions=@($action);Principal=$principal;Triggers=@($logon,$daily);Settings=$settings;State='Ready'}

    Check 'full accepted task contract passes' {
        Assert-Ci10TaskIdentity -Task $task -Executable $action.Execute -Arguments $taskArguments -Owner $owner
    }
    Check 'extra trigger refused' {
        $bad=Clone $task;$bad.Triggers+=@(Clone $daily)
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'repetition drift refused' {
        $bad=Clone $task;$bad.Triggers[1].Repetition.Interval='PT2M'
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'daily start drift refused' {
        $bad=Clone $task;$bad.Triggers[1].StartBoundary='2026-10-12T00:01:00'
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'multiple instance drift refused' {
        $bad=Clone $task;$bad.Settings.MultipleInstances='Parallel'
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'execution limit drift refused' {
        $bad=Clone $task;$bad.Settings.ExecutionTimeLimit='PT30M'
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'battery setting drift refused' {
        $bad=Clone $task;$bad.Settings.DisallowStartIfOnBatteries=$true
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'action working directory drift refused' {
        $bad=Clone $task;$bad.Actions[0].WorkingDirectory='C:\Temp'
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'task path drift refused' {
        $bad=Clone $task;$bad.TaskPath='\Other\'
        Refuses {Assert-Ci10TaskIdentity $bad $action.Execute $taskArguments $owner} 'TASK_OWNERSHIP_OR_PROVENANCE_UNCERTAIN'
    }
    Check 'identity check executes before task mode switch and acceptance gates remain' {
        $source=Get-Content -LiteralPath $managePath -Raw
        Assert ($source.IndexOf('Assert-Ci10TaskIdentity -Task $task') -lt $source.IndexOf('switch ($Mode)'))
        Assert (([regex]::Matches($source,'if \(-not \$OwnerAccepted\)')).Count -eq 2)
        Assert ($source.Contains('-MultipleInstances IgnoreNew'))
        Assert ($source.Contains('-ExecutionTimeLimit (New-TimeSpan -Minutes 25)'))
        Assert (-not ($source -match 'Password|GH_TOKEN|GITHUB_TOKEN|auth token|Export-Clixml'))
    }
    'REVIEW_CORRECTION_TESTS=PASS'
    'REVIEW_CORRECTION_TEST_COUNT='+$total
} catch {
    'REVIEW_CORRECTION_TESTS=FAIL'
    'REVIEW_CORRECTION_TEST_COUNT='+$total
    'TEST_CASE='+$script:case
    'TEST_FAILURE_LINE='+$_.InvocationInfo.ScriptLineNumber
    $code=[string]$_.Exception.Message
    if($code -cnotmatch '^[A-Z][A-Z0-9_]+$'){$code='TEST_OPERATION_FAILED'}
    'CLASSIFICATION='+$code
    exit 1
}
