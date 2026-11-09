[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$installPath = Join-Path $deployRoot 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$stagePath = Join-Path $deployRoot 'Stage-AdminBrokerV2PublisherBootstrap.ps1'
$v2WorkerPath = Join-Path $deployRoot 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$script:Assertions = 0

function Assert-True([bool]$Value, [string]$Message) {
    $script:Assertions++
    if (-not $Value) { throw "ASSERTION_FAILED: $Message" }
}

function Assert-Refused([scriptblock]$Action, [string]$Code) {
    $script:Assertions++
    try {
        & $Action
    } catch {
        if ($_.Exception.Message -ceq $Code) { return }
        throw "EXPECTED_REFUSAL: $Code (got $($_.Exception.Message))"
    }
    throw "EXPECTED_REFUSAL: $Code"
}

foreach ($scriptPath in @($installPath, $stagePath, $v2WorkerPath)) {
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "Parse OK: $(Split-Path -Leaf $scriptPath)"
}

$installAst = [Management.Automation.Language.Parser]::ParseFile($installPath, [ref]$null, [ref]$errors)
$stageAst = [Management.Automation.Language.Parser]::ParseFile($stagePath, [ref]$null, [ref]$null)
Assert-True ($null -eq ($installAst.Find({ param($n) $n -is [Management.Automation.Language.ParamBlockAst] }, $false))) 'Install has no param block'
Assert-True ($null -eq ($stageAst.Find({ param($n) $n -is [Management.Automation.Language.ParamBlockAst] }, $false))) 'Stage has no param block'

$installSource = Get-Content -LiteralPath $installPath -Raw
$stageSource = Get-Content -LiteralPath $stagePath -Raw
$v2Source = Get-Content -LiteralPath $v2WorkerPath -Raw
$bootstrapSha = (Get-FileHash -LiteralPath $installPath -Algorithm SHA256).Hash.ToLowerInvariant()
$stageSha = (Get-FileHash -LiteralPath $stagePath -Algorithm SHA256).Hash.ToLowerInvariant()
$v2Sha = (Get-FileHash -LiteralPath $v2WorkerPath -Algorithm SHA256).Hash.ToLowerInvariant()

Assert-True ($installSource.Contains('acceptedBootstrapSha256', [StringComparison]::Ordinal)) 'Install records reviewed bootstrap SHA constant'
Assert-True ($stageSource.Contains($bootstrapSha, [StringComparison]::Ordinal)) 'Stage pins bootstrap SHA-256 to install file hash'
if ($installSource -match "acceptedBootstrapSha256 = '([a-f0-9]{64})'") {
    Assert-True ($Matches[1].Length -eq 64) 'Install bootstrap SHA literal is 64 hex'
}
if ($stageSource -match "acceptedBootstrapSha256 = '([a-f0-9]{64})'") {
    Assert-True ($Matches[1] -ceq $bootstrapSha) 'Stage bootstrap pin equals live install file hash'
}
Assert-True ($stageSource.Contains($v2Sha, [StringComparison]::Ordinal)) 'Stage pins V2 worker SHA-256'
Assert-True ($installSource.Contains($v2Sha, [StringComparison]::Ordinal)) 'Install pins V2 worker SHA-256'
Assert-True ($installSource.Contains('db71da0a73f2943eb8837e7c1e7070a22251478e4acfba91338837c7fc699605', [StringComparison]::Ordinal)) 'Install pins V1 worker SHA-256'

$installBody = ($installSource -split "`n" | Select-Object -Skip 2) -join "`n"
foreach ($forbidden in @(
    'Import-Module', 'Invoke-WebRequest', 'Invoke-RestMethod',
    'git ', 'ssh ', 'gh ', 'param('
)) {
    Assert-True (-not $installBody.Contains($forbidden, [StringComparison]::Ordinal)) "Install forbids: $forbidden"
}
Assert-True ($installSource.Contains('no imports, dot-source', [StringComparison]::Ordinal)) 'Install documents no dot-source'
Assert-True (-not $installSource.Contains('Start-Process', [StringComparison]::Ordinal)) 'Install forbids Start-Process'

Assert-True ($stageSource.Contains("[Environment]::GetFolderPath('System')", [StringComparison]::Ordinal)) 'Stage resolves system directory via API'
Assert-True ($stageSource.Contains("'WindowsPowerShell'", [StringComparison]::Ordinal)) 'Stage binds WindowsPowerShell segment'
Assert-True ($stageSource.Contains("'v1.0'", [StringComparison]::Ordinal)) 'Stage binds v1.0 segment'
Assert-True ($stageSource.Contains('powershell.exe', [StringComparison]::Ordinal)) 'Stage targets powershell.exe'
Assert-True ($stageSource.Contains('WINDOWSAPPS_RUNTIME_REFUSED', [StringComparison]::Ordinal)) 'Stage refuses WindowsApps runtime'
Assert-True ($stageSource.Contains('-NoProfile', [StringComparison]::Ordinal)) 'Stage launch disables profile'
Assert-True (-not $stageSource.Contains('Bypass', [StringComparison]::Ordinal)) 'Stage launch forbids ExecutionPolicy Bypass'

Assert-True ($v2Source.Contains("DRAGONFLY_V2_PUBLISH_REVIEWED", [StringComparison]::Ordinal)) 'V2 worker registers publish operation'
Assert-True ($v2Source.Contains("ELEVATED_IDENTITY_PROOF", [StringComparison]::Ordinal)) 'V2 worker preserves identity proof'
Assert-True ($installSource.Contains('WINDOWSAPPS_RUNTIME_REFUSED', [StringComparison]::Ordinal)) 'Install refuses WindowsApps for V2 task runtime'

$installFns = @('Get-SystemPowerShellExecutable', 'Assert-WindowsAppsRuntimeRefused', 'Assert-V1TaskQuiescent', 'Assert-NoReplay', 'Register-V2Task')
foreach ($name in $installFns) {
    $node = $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name }, $false)
    Assert-True ($null -ne $node) "Install defines $name"
}

& {
    param([string]$FnText)
    . ([scriptblock]::Create($FnText))
    $windowsApps = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe'
    Assert-Refused { Assert-WindowsAppsRuntimeRefused $windowsApps } 'WINDOWSAPPS_RUNTIME_REFUSED'
    $systemPs = Get-SystemPowerShellExecutable
    Assert-True ($systemPs -match '\\WindowsPowerShell\\v1\.0\\powershell\.exe$') 'System PowerShell path canonical'
    Assert-True ($systemPs -notmatch 'WindowsApps') 'System PowerShell path not WindowsApps'
} ($installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-SystemPowerShellExecutable' }, $false).Extent.Text + "`n" +
   $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-WindowsAppsRuntimeRefused' }, $false).Extent.Text)

$v2Ast = [Management.Automation.Language.Parser]::ParseFile($v2WorkerPath, [ref]$null, [ref]$null)
$publishFn = $v2Ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-DragonflyV2PublishReviewed' }, $false)
Assert-True ($null -ne $publishFn) 'V2 worker defines publish handler'
Assert-True ($publishFn.Extent.Text.Contains('PACKAGE_INBOUND_MISSING', [StringComparison]::Ordinal)) 'Publish fails closed without inbound package'

$workerAst = $v2Ast
$proofFn = $workerAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Invoke-ElevatedIdentityProof' }, $false)
Assert-True ($null -ne $proofFn) 'V2 worker retains proof handler'

Write-Host "Admin Broker V2 publisher bootstrap contract assertions PASS: $script:Assertions"
Write-Host "BOOTSTRAP_SHA256=$bootstrapSha"
Write-Host "STAGE_SHA256=$stageSha"
Write-Host "V2_WORKER_SHA256=$v2Sha"
