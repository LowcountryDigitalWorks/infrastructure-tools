[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$installPath = Join-Path $deployRoot 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$stagePath = Join-Path $deployRoot 'Stage-AdminBrokerV2PublisherBootstrap.ps1'
$v2WorkerPath = Join-Path $deployRoot 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$manifestPath = Join-Path $deployRoot 'AdminBrokerV2BootstrapReviewManifest.json'
$repoRoot = (Resolve-Path (Join-Path $deployRoot '../..')).Path
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

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($Bytes)
        [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

foreach ($scriptPath in @($installPath, $stagePath, $v2WorkerPath)) {
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "Parse OK: $(Split-Path -Leaf $scriptPath)"
}
$manifestParsed = $null
try { $manifestParsed = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch { $manifestParsed = $null }
Assert-True ($null -ne $manifestParsed) 'Parse OK: AdminBrokerV2BootstrapReviewManifest.json'

$installAst = [Management.Automation.Language.Parser]::ParseFile($installPath, [ref]$null, [ref]$null)
$stageAst = [Management.Automation.Language.Parser]::ParseFile($stagePath, [ref]$null, [ref]$null)
Assert-True ($null -eq ($installAst.Find({ param($n) $n -is [Management.Automation.Language.ParamBlockAst] }, $false))) 'Install has no param block'
Assert-True ($null -eq ($stageAst.Find({ param($n) $n -is [Management.Automation.Language.ParamBlockAst] }, $false))) 'Stage has no param block'

$installSource = Get-Content -LiteralPath $installPath -Raw
$stageSource = Get-Content -LiteralPath $stagePath -Raw
$v2Source = Get-Content -LiteralPath $v2WorkerPath -Raw
$manifestJson = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

$installSha = (Get-FileHash -LiteralPath $installPath -Algorithm SHA256).Hash.ToLowerInvariant()
$v2Sha = (Get-FileHash -LiteralPath $v2WorkerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestInstallPin = @($manifestJson.artifacts | Where-Object { $_.name -ceq 'Install-AdminBrokerV2PublisherBootstrap.ps1' }).sha256.ToLowerInvariant()
$manifestWorkerPin = @($manifestJson.artifacts | Where-Object { $_.name -ceq 'Invoke-AdminBrokerV2PublisherWorker.ps1' }).sha256.ToLowerInvariant()

Assert-True ($manifestJson.schema -eq 1) 'manifest schema'
Assert-True ($manifestJson.protocol -ceq 'ldw.admin-broker.v2-bootstrap.review-manifest.v1') 'manifest protocol'
Assert-True ($manifestInstallPin -ceq $installSha) 'manifest install pin equals materialized file SHA256'
Assert-True ($manifestWorkerPin -ceq $v2Sha) 'manifest worker pin equals materialized file SHA256'
Assert-True (-not $installSource.Contains('acceptedBootstrapSha256 =', [StringComparison]::Ordinal)) 'Install has no embedded bootstrap SHA pin'
Assert-True (-not $stageSource.Contains('acceptedBootstrapSha256', [StringComparison]::Ordinal)) 'Stage has no embedded bootstrap SHA pin'
Assert-True ($installSource.Contains('Read-ReviewManifest', [StringComparison]::Ordinal)) 'Install reads review manifest'
Assert-True ($installSource.Contains('BOOTSTRAP_SHA256_MISMATCH', [StringComparison]::Ordinal)) 'Install self-hash mismatch code'
Assert-True ($stageSource.Contains('AdminBrokerV2BootstrapReviewManifest.json', [StringComparison]::Ordinal)) 'Stage uses review manifest file'

if (Test-Path -LiteralPath (Join-Path $repoRoot '.git')) {
    $gitInstallBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/Install-AdminBrokerV2PublisherBootstrap.ps1" 2>$null).Trim()
    $gitWorkerBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/Invoke-AdminBrokerV2PublisherWorker.ps1" 2>$null).Trim()
    $gitManifestBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/AdminBrokerV2BootstrapReviewManifest.json" 2>$null).Trim()
    Assert-True ($gitInstallBlob -match '^[a-f0-9]{40}$') 'git install blob identity'
    Assert-True ($gitWorkerBlob -match '^[a-f0-9]{40}$') 'git worker blob identity'
    Assert-True ($gitManifestBlob -match '^[a-f0-9]{40}$') 'git manifest blob identity'
    $gitInstallSha = (git -C $repoRoot hash-object $installPath).Trim().ToLowerInvariant()
    Assert-True ($gitInstallBlob -ceq $gitInstallSha) 'install git blob matches working tree object'
}

$rawBytes = [IO.File]::ReadAllBytes($installPath)
$tampered = [byte[]]::new($rawBytes.Length)
[Array]::Copy($rawBytes, $tampered, $rawBytes.Length)
$tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 0x01
Assert-True ((Get-BytesSha256 $tampered) -cne $installSha) 'single-byte tamper changes SHA256'

if ($installSource -match "`r`n") {
    $lfOnly = [Text.Encoding]::UTF8.GetBytes(($installSource -replace "`r`n", "`n"))
    Assert-True ((Get-BytesSha256 $lfOnly) -cne $installSha) 'LF-only normalization drift changes SHA256'
}

$sandbox = Join-Path $env:TEMP ('LDW_V2BootstrapManifest_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $sandbox -Force
try {
    $sandboxInstall = Join-Path $sandbox 'Install-AdminBrokerV2PublisherBootstrap.ps1'
    $sandboxManifest = Join-Path $sandbox 'AdminBrokerV2BootstrapReviewManifest.json'
    Copy-Item -LiteralPath $installPath -Destination $sandboxInstall -Force
    Copy-Item -LiteralPath $manifestPath -Destination $sandboxManifest -Force

    $protectedStagingRoot = $sandbox
    $bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
    $workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
    $reviewManifestFileName = 'AdminBrokerV2BootstrapReviewManifest.json'

    $noReparseFn = $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-NoReparse' }, $false)
    $readFn = $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Read-ReviewManifest' }, $false)
    $assertFn = $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-ProtectedArtifactSha256' }, $false)
    if ($null -eq $noReparseFn -or $null -eq $readFn -or $null -eq $assertFn) { throw 'FUNCTION_REQUIRED: manifest helpers' }

    . ([scriptblock]::Create($noReparseFn.Extent.Text))
    . ([scriptblock]::Create($readFn.Extent.Text))
    . ([scriptblock]::Create($assertFn.Extent.Text))

    $first = Read-ReviewManifest
    $second = Read-ReviewManifest
    Assert-True ($first.BootstrapSha256 -ceq $second.BootstrapSha256) 'manifest read idempotent'
    Assert-ProtectedArtifactSha256 $sandboxInstall $first.BootstrapSha256 'BOOTSTRAP_SHA256_MISMATCH' | Out-Null
    [IO.File]::WriteAllBytes($sandboxInstall, $tampered)
    Assert-Refused { Assert-ProtectedArtifactSha256 $sandboxInstall $first.BootstrapSha256 'BOOTSTRAP_SHA256_MISMATCH' } 'BOOTSTRAP_SHA256_MISMATCH'

    $badManifest = (Get-Content -LiteralPath $manifestPath -Raw).Replace($manifestInstallPin, ('0' * 64))
    [IO.File]::WriteAllText($sandboxManifest, $badManifest, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllBytes($sandboxInstall, $rawBytes)
    $bad = Read-ReviewManifest
    Assert-Refused { Assert-ProtectedArtifactSha256 $sandboxInstall $bad.BootstrapSha256 'BOOTSTRAP_SHA256_MISMATCH' } 'BOOTSTRAP_SHA256_MISMATCH'
} finally {
    Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

$installBody = ($installSource -split "`n" | Select-Object -Skip 2) -join "`n"
foreach ($forbidden in @('Import-Module', 'Invoke-WebRequest', 'Invoke-RestMethod', 'git ', 'ssh ', 'gh ', 'param(')) {
    Assert-True (-not $installBody.Contains($forbidden, [StringComparison]::Ordinal)) "Install forbids: $forbidden"
}
Assert-True (-not $installSource.Contains('Start-Process', [StringComparison]::Ordinal)) 'Install forbids Start-Process'

Assert-True ($stageSource.Contains("[Environment]::GetFolderPath('System')", [StringComparison]::Ordinal)) 'Stage resolves system directory via API'
Assert-True ($stageSource.Contains('PROTECTED_COPY_HASH_MISMATCH', [StringComparison]::Ordinal)) 'Stage post-copy hash gate'
Assert-True ($installSource.Contains('HOLD_TASK_UPDATE_AMBIGUOUS', [StringComparison]::Ordinal)) 'Install ambiguous task HOLD'
Assert-True ($installSource.Contains('Remove-StagedV2Worker', [StringComparison]::Ordinal)) 'Install rollback removes staged V2 only'

Assert-True ($v2Source.Contains("DRAGONFLY_V2_PUBLISH_REVIEWED", [StringComparison]::Ordinal)) 'V2 worker registers publish operation'
Assert-True ($installSource.Contains('WINDOWSAPPS_RUNTIME_REFUSED', [StringComparison]::Ordinal)) 'Install refuses WindowsApps for V2 task runtime'

Write-Host "Admin Broker V2 publisher bootstrap contract assertions PASS: $script:Assertions"
Write-Host "REVIEW_MANIFEST_INSTALL_SHA256=$manifestInstallPin"
Write-Host "REVIEW_MANIFEST_WORKER_SHA256=$manifestWorkerPin"
Write-Host "GIT_TREE_INSTALL_SHA256=$installSha"
