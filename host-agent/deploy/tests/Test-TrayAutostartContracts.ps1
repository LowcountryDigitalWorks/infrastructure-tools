#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$modulePath = Join-Path (Join-Path $repoRoot 'deploy') 'TrayAutostartDeployment.psm1'
Import-Module $modulePath -Force

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw $Message
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('ldw-tray-autostart-contract-' + [Guid]::NewGuid().ToString('N'))
$originalProgramFiles = $env:ProgramFiles
try {
    $env:ProgramFiles = $tempRoot
    $exe = Join-Path $tempRoot 'LowcountryDigitalWorks\HostAgent\Windows\LDW.HostAgent.Windows.exe'
    New-Item -ItemType Directory -Path (Split-Path -Parent $exe) -Force | Out-Null
    Set-Content -LiteralPath $exe -Value 'fixture executable' -NoNewline
    $sid = 'S-1-5-21-111-222-333-1001'
    $spec = Get-TrayAutostartSpec -OwnerSid $sid

    Assert-True ($spec.TriggerClass -eq 'MSFT_TaskLogonTrigger') 'startup must be a user-logon trigger'
    Assert-True ($spec.OwnerSid -eq $sid) 'task principal must bind to the explicit user SID'
    Assert-True ($spec.LogonType -eq 'Interactive' -and $spec.RunLevel -eq 'Limited') 'tray must use the logged-in user at limited privilege'
    Assert-True ($spec.MultipleInstances -eq 'IgnoreNew') 'repeated triggers must not start duplicate task instances'
    Assert-True ($spec.Arguments -eq '' -and $spec.ExecutablePath -eq [IO.Path]::GetFullPath($exe)) 'task must use the exact protected executable and no caller-controlled arguments'

    $task = [pscustomobject]@{
        TaskName = $spec.TaskName
        TaskPath = $spec.TaskPath
        Actions = @([pscustomobject]@{ Execute = $spec.ExecutablePath; Arguments = '' })
        Triggers = @([pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = $spec.TriggerClass }; UserId = $sid })
        Principal = [pscustomobject]@{ UserId = $sid; LogonType = 'Interactive'; RunLevel = 'Limited' }
        Settings = [pscustomobject]@{
            MultipleInstances = 'IgnoreNew'
            StartWhenAvailable = $true
            ExecutionTimeLimit = 'PT0S'
            DisallowStartIfOnBatteries = $false
            StopIfGoingOnBatteries = $false
        }
        State = 'Ready'
    }
    Assert-True (@(Get-TrayAutostartIdentityProblems -Task $task -Spec $spec).Count -eq 0) 'exact task readback must pass'
    Assert-True ((Get-TrayAutostartInstallDisposition -Task $null -Spec $spec) -eq 'Register') 'absent task must take one registration path'
    Assert-True ((Get-TrayAutostartInstallDisposition -Task $task -Spec $spec) -eq 'NoOp') 'repeated install on a valid enabled task must not register a duplicate'
    $task.Principal.RunLevel = 'Highest'
    Assert-True (@(Get-TrayAutostartIdentityProblems -Task $task -Spec $spec) -contains 'principal-run-level') 'elevated task drift must fail closed'
    Assert-Throws { Get-TrayAutostartInstallDisposition -Task $task -Spec $spec } 'install must not overwrite an identity-drifted task'
    $task.Principal.RunLevel = 'Limited'
    $task.Triggers[0].UserId = 'S-1-5-21-111-222-333-1002'
    Assert-True (@(Get-TrayAutostartIdentityProblems -Task $task -Spec $spec) -contains 'trigger-user') 'wrong-user trigger drift must fail closed'
    $task.Triggers[0].UserId = $sid
    $task.Settings.MultipleInstances = 'Parallel'
    Assert-True (@(Get-TrayAutostartIdentityProblems -Task $task -Spec $spec) -contains 'multiple-instances') 'duplicate-capable task setting must fail closed'
    $task.Settings.MultipleInstances = 'IgnoreNew'
    $task.Actions[0].Arguments = '-elevated'
    Assert-True (@(Get-TrayAutostartIdentityProblems -Task $task -Spec $spec) -contains 'action-arguments') 'unexpected launch arguments must fail closed'
    $task.Actions[0].Arguments = ''
    $task.State = 'Disabled'
    Assert-True (-not (Test-TrayAutostartEnabled -Task $task)) 'disabled state must read back as disabled'
    Assert-True ((Get-TrayAutostartInstallDisposition -Task $task -Spec $spec) -eq 'Enable') 'install may re-enable the exact disabled task without registering another'
    $task.State = 'Ready'
    Assert-True (Test-TrayAutostartEnabled -Task $task) 'ready state must read back as enabled'
    $task.State = 'Queued'
    Assert-True (Test-TrayAutostartEnabled -Task $task) 'queued state is enabled while awaiting the owner logon trigger'
    $task.State = 'Unknown'
    Assert-Throws { Test-TrayAutostartEnabled -Task $task } 'unknown task state must fail closed'

    Assert-Throws { Get-TrayAutostartSpec -OwnerSid 'S-1-5-18' } 'SYSTEM/service principal must not be accepted for tray'
    Assert-Throws { Get-TrayAutostartSpec -OwnerSid $sid -ExecutablePath (Join-Path $tempRoot 'untrusted.exe') } 'unmanaged executable path must not be accepted'

    $manager = Get-Content (Join-Path $repoRoot 'deploy\Manage-TrayAutostart.ps1') -Raw
    foreach ($mutation in @('Register-ScheduledTask','Enable-ScheduledTask','Disable-ScheduledTask','Stop-ScheduledTask','Unregister-ScheduledTask')) {
        Assert-True ($manager.Contains($mutation, [StringComparison]::Ordinal)) "managed lifecycle must explicitly handle $mutation"
    }
    Assert-True ($manager.IndexOf('Assert-TrayAutostartCurrentOwner', [StringComparison]::Ordinal) -lt $manager.IndexOf('Assert-TrayAutostartAdministrator', [StringComparison]::Ordinal)) 'owner identity must be checked before privileged lifecycle changes'
    Assert-True ($manager.Contains('Get-TrayAutostartIdentityProblems', [StringComparison]::Ordinal)) 'task identity must be read before mutations'
} finally {
    $env:ProgramFiles = $originalProgramFiles
    if (Test-Path -LiteralPath $tempRoot -PathType Container) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

Write-Output 'Tray autostart contract tests PASS.'
