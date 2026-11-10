#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-RedrixLdwParentAclReadiness.ps1'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'SOURCE_MISSING' }
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw 'SYNTAX_ERROR' }
$checks = 0
function Assert([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw ("ASSERTION_FAILED_" + $Code) }
    $script:checks++
}
$commands = @($ast.FindAll({
    param($node) $node -is [Management.Automation.Language.CommandAst]
}, $true) | ForEach-Object { $_.GetCommandName() })
$forbidden = @('Set-Acl','New-Item','Remove-Item','Move-Item','Copy-Item','Rename-Item',
    'icacls','takeown','schtasks','Register-ScheduledTask','Set-ScheduledTask',
    'Start-ScheduledTask','Invoke-Expression','Start-Process','Invoke-WebRequest',
    'Invoke-RestMethod','Set-Content','Out-File','Add-Content','New-ItemProperty',
    'Set-ItemProperty','reg','cmd','rundll32','powershell','pwsh','sudo')
foreach ($name in $forbidden) {
    Assert (-not ($commands -contains $name)) ('READ_ONLY_COMMAND_' + $name)
}
Assert (-not ($commands -contains 'Invoke-Command')) 'NO_REMOTE_EXECUTION'
Assert (-not ($commands -contains 'Get-Credential')) 'NO_CREDENTIAL'
Assert ($commands -contains 'Get-Acl') 'DOES_READ_ACL'
Assert ($commands -contains 'Get-ChildItem') 'DOES_INSPECT_CHILDREN'
Assert ($commands -contains 'Get-ScheduledTask') 'DOES_INSPECT_V1_TASK'
Assert ($commands -contains 'ConvertTo-Json') 'SANITIZED_OUTPUT'
Assert ($null -eq $ast.ParamBlock) 'NO_CALLER_PARAMETERS'
$text = [IO.File]::ReadAllText($source)
Assert ($text.Contains('READ_ONLY_PREIMAGE_MATCH_NOT_AUTHORIZED')) 'NO_AUTHORIZATION_ON_MATCH'
Assert ($text.Contains('HOLD_READ_ONLY')) 'HOLD_ON_DRIFT'
Assert ($text.Contains('d7262f4d667814fce0820acbabe2613e352c22614ae7de2105879459c7fbb2a9')) 'ROOT_PIN'
Assert ($text.Contains('0x10000000 -bor 0x40000000')) 'GENERIC_RIGHTS_REFUSE'
Assert ($text.Contains('programDataSystemAclChangeAuthorized = $false')) 'NO_GLOBAL_ACL_CHANGE'
Assert ($text.Contains('physicalAclChangeAuthorized = $false')) 'NO_PHYSICAL_AUTHORIZATION'
Assert ($text.Contains('gitHubJitAdmissionAuthorized = $false')) 'NO_JIT_ADMISSION'
Assert ($text.Contains('GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)')) 'KNOWN_FOLDER_ONLY'
Assert ($text.Contains('PREFLIGHT_MISMATCH_OR_UNAVAILABLE')) 'SANITIZED_FAILURE'
$expectedNames = @('CiJitControl','CiJitStatus','CiRunnerDispatch',
    'CiRunnerEphemeral','DragonflyCanaryAdjunct','PrivilegedControl')
foreach ($name in $expectedNames) { Assert ($text.Contains("'" + $name + "'")) ('EXPECTED_CHILD_' + $name) }
Assert ($text.Contains('Get-SddlSha256 $acl')) 'EXACT_CHILD_SDDL_PIN'
Assert ($text.Contains('Assert-NoBroadWrite $acl')) 'CHILD_GENERIC_WRITE_REFUSAL'
Assert ($text.Contains('TASK_NOT_QUIESCENT')) 'TASK_NOT_QUIESCENT_HOLD'
Assert ($text.Contains('TASK_TRIGGER_DRIFT')) 'NO_TRIGGERS'
'REDRIX_LDW_PARENT_ACL_READONLY_STATIC_TESTS=PASS assertions=' + $checks
