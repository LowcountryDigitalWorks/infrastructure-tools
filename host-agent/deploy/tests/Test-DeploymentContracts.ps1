[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $deployRoot 'HyperVObserverDeployment.psm1') -Force

$script:Assertions = 0
function Assert-True([bool]$Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $script:Assertions++
    try { & $Action; throw "ASSERTION FAILED: $Message" }
    catch {
        if ($_.Exception.Message.StartsWith('ASSERTION FAILED:', [StringComparison]::Ordinal)) { throw }
    }
}

$constants = Get-HyperVObserverDeploymentConstants
Assert-True ($constants.TaskName -eq 'HyperVObserver') 'task name must be deterministic'
Assert-True ($constants.TaskPath -eq '\LowcountryDigitalWorks\HostAgent\') 'task path must be deterministic and namespaced'
Assert-True ($constants.InstallRoot.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase)) 'install root must be under Program Files'
Assert-True ($constants.ConfigRoot.StartsWith($env:ProgramData, [StringComparison]::OrdinalIgnoreCase)) 'config root must be under ProgramData'
Assert-True ($constants.ConfigRoot.EndsWith('HostAgent\HyperVObserver', [StringComparison]::OrdinalIgnoreCase)) 'config root must be helper-specific'

$dirAcl = New-HyperVObserverDirectorySecurity
$fileAcl = New-HyperVObserverFileSecurity
Assert-True (Test-HyperVObserverAclObject -Acl $dirAcl) 'directory ACL must be protected and restricted to SYSTEM/local Administrators'
Assert-True (Test-HyperVObserverAclObject -Acl $fileAcl) 'file ACL must be protected and restricted to SYSTEM/local Administrators'

$tempParent = if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { [IO.Path]::GetTempPath() } else { $env:RUNNER_TEMP }
$tempRoot = Join-Path $tempParent ('ldw-host-agent-deploy-tests-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $requiredFiles = @(
        'LDW.HostAgent.Core.dll',
        'LDW.HostAgent.HyperVObserver.deps.json',
        'LDW.HostAgent.HyperVObserver.dll',
        'LDW.HostAgent.HyperVObserver.exe',
        'LDW.HostAgent.HyperVObserver.runtimeconfig.json'
    )

    $publishA = Join-Path $tempRoot 'a'
    New-Item -ItemType Directory -Path $publishA | Out-Null
    foreach ($name in $requiredFiles) { Set-Content -LiteralPath (Join-Path $publishA $name) -Value "fixture-$name" -NoNewline }
    $manifestA = New-HyperVObserverDeploymentManifest -Directory $publishA
    $verifiedA = Test-HyperVObserverDeploymentManifest -Directory $publishA
    Assert-True ($manifestA.ReleaseId -eq $verifiedA.ReleaseId) 'manifest must verify deterministically'
    Assert-True (@($verifiedA.Entries).Count -eq 5) 'publish boundary must contain exactly five payload files'

    $publishB = Join-Path $tempRoot 'b'
    Copy-Item -LiteralPath $publishA -Destination $publishB -Recurse
    Remove-Item -LiteralPath (Join-Path $publishB 'deployment-manifest.json')
    Set-Content -LiteralPath (Join-Path $publishB 'LDW.HostAgent.Core.dll') -Value 'changed-core-content' -NoNewline
    $manifestB = New-HyperVObserverDeploymentManifest -Directory $publishB
    Assert-True ($manifestB.ReleaseId -ne $manifestA.ReleaseId) 'release identity must change when a dependency DLL changes even if the apphost EXE does not'

    $publishBad = Join-Path $tempRoot 'bad'
    Copy-Item -LiteralPath $publishA -Destination $publishBad -Recurse
    Remove-Item -LiteralPath (Join-Path $publishBad 'deployment-manifest.json')
    Set-Content -LiteralPath (Join-Path $publishBad 'id_ed25519') -Value 'not-a-real-key' -NoNewline
    Assert-Throws { New-HyperVObserverDeploymentManifest -Directory $publishBad | Out-Null } 'unexpected/private-trust-like publish files must fail closed'

    $publishNested = Join-Path $tempRoot 'nested'
    New-Item -ItemType Directory -Path $publishNested | Out-Null
    foreach ($name in $requiredFiles) { Set-Content -LiteralPath (Join-Path $publishNested $name) -Value "fixture-$name" -NoNewline }
    New-Item -ItemType Directory -Path (Join-Path $publishNested 'extra') | Out-Null
    Assert-Throws { New-HyperVObserverDeploymentManifest -Directory $publishNested | Out-Null } 'publish subdirectories must fail closed'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

$realTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Assert-True ($realTaskSettings.PSObject.Properties.Name -contains 'DisallowStartIfOnBatteries') 'real ScheduledTasks settings must expose DisallowStartIfOnBatteries'
Assert-True ($realTaskSettings.PSObject.Properties.Name -contains 'StopIfGoingOnBatteries') 'real ScheduledTasks settings must expose StopIfGoingOnBatteries'
Assert-True (-not [bool]$realTaskSettings.DisallowStartIfOnBatteries) 'AllowStartIfOnBatteries must map to DisallowStartIfOnBatteries=false'
Assert-True (-not [bool]$realTaskSettings.StopIfGoingOnBatteries) 'DontStopIfGoingOnBatteries must map to StopIfGoingOnBatteries=false'

$installedExe = Join-Path $constants.ReleasesRoot '0123456789abcdef\LDW.HostAgent.HyperVObserver.exe'
$spec = Get-HyperVObserverTaskSpec -InstalledExe $installedExe -ConfigPath $constants.ConfigPath
$fakeTask = [pscustomobject]@{
    TaskName = $spec.TaskName
    TaskPath = $spec.TaskPath
    Description = $spec.Description
    Actions = @([pscustomobject]@{ Execute = $spec.Execute; Arguments = $spec.Arguments })
    Principal = [pscustomobject]@{ UserId = 'SYSTEM'; RunLevel = 'Highest'; LogonType = 'ServiceAccount' }
    Triggers = @([pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskBootTrigger' } })
    Settings = [pscustomobject]@{
        Hidden = $true
        StartWhenAvailable = $true
        RestartCount = 3
        RestartInterval = 'PT1M'
        ExecutionTimeLimit = 'PT0S'
        MultipleInstances = 'IgnoreNew'
        DisallowStartIfOnBatteries = $false
        StopIfGoingOnBatteries = $false
    }
}

Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec).Count -eq 0) 'exact task identity fixture must pass'
$fakeTask.Actions[0].Execute = Join-Path $env:SystemRoot 'System32\cmd.exe'
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'action-execute') 'action drift must be detected'
$fakeTask.Actions[0].Execute = $spec.Execute
$fakeTask.Principal.UserId = 'Administrators'
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'principal-user') 'principal drift must be detected'
$fakeTask.Principal.UserId = 'SYSTEM'
$fakeTask.Settings.Hidden = $false
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'hidden') 'hidden-setting drift must be detected'
$fakeTask.Settings.Hidden = $true
$fakeTask.Settings.RestartCount = 99
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'restart-count') 'restart policy drift must be detected'
$fakeTask.Settings.RestartCount = 3
$fakeTask.Settings.DisallowStartIfOnBatteries = $true
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'allow-on-battery') 'battery-start drift must be detected using real ScheduledTasks property'
$fakeTask.Settings.DisallowStartIfOnBatteries = $false
$fakeTask.Settings.StopIfGoingOnBatteries = $true
Assert-True (@(Get-HyperVObserverTaskIdentityProblems -Task $fakeTask -Spec $spec) -contains 'dont-stop-on-battery') 'battery-stop drift must be detected using real ScheduledTasks property'
$fakeTask.Settings.StopIfGoingOnBatteries = $false

foreach ($scriptName in @('Disable-HyperVObserver.ps1', 'Enable-HyperVObserver.ps1', 'Uninstall-HyperVObserver.ps1')) {
    $source = Get-Content -LiteralPath (Join-Path $deployRoot $scriptName) -Raw
    $validationIndex = $source.IndexOf('Get-HyperVObserverValidatedContext', [StringComparison]::Ordinal)
    Assert-True ($validationIndex -ge 0) "$scriptName must validate managed state/task identity"
    foreach ($mutation in @('Stop-ScheduledTask', 'Disable-ScheduledTask', 'Enable-ScheduledTask', 'Start-ScheduledTask', 'Unregister-ScheduledTask')) {
        $mutationIndex = $source.IndexOf($mutation, [StringComparison]::Ordinal)
        if ($mutationIndex -ge 0) {
            Assert-True ($validationIndex -lt $mutationIndex) "$scriptName must validate exact task identity before $mutation"
        }
    }
}

$deployFiles = @(Get-ChildItem -LiteralPath $deployRoot -File | Where-Object { $_.Extension -in @('.ps1', '.psm1') })
$allDeploySource = ($deployFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
foreach ($forbidden in @(
    'Set-VM', 'Start-VM', 'Stop-VM', 'Restart-VM', 'Remove-VM',
    'Add-LocalGroupMember', 'Set-ExecutionPolicy', 'Set-AppLockerPolicy',
    'Set-NetFirewall', 'New-NetFirewall', 'ssh-keyscan', 'Invoke-WebRequest',
    'TcpListener', 'HttpListener'
)) {
    Assert-True (-not $allDeploySource.Contains($forbidden, [StringComparison]::OrdinalIgnoreCase)) "deployment scripts must not contain forbidden mutation/listener primitive $forbidden"
}

Write-Host "Host Agent deployment contract assertions PASS: $script:Assertions"
