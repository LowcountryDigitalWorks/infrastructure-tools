[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw 'WINDOWS_POWERSHELL_51_REQUIRED'
}

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

function Test-SourceContains([string]$Haystack, [string]$Needle) {
    $Haystack.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0
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
$manifestFileSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestInstallPin = @($manifestJson.artifacts | Where-Object { $_.name -ceq 'Install-AdminBrokerV2PublisherBootstrap.ps1' }).sha256.ToLowerInvariant()
$manifestWorkerPin = @($manifestJson.artifacts | Where-Object { $_.name -ceq 'Invoke-AdminBrokerV2PublisherWorker.ps1' }).sha256.ToLowerInvariant()

Assert-True ($manifestJson.schema -eq 1) 'manifest schema'
Assert-True ($manifestJson.protocol -ceq 'ldw.admin-broker.v2-bootstrap.review-manifest.v1') 'manifest protocol'
Assert-True ($manifestInstallPin -ceq $installSha) 'manifest install pin equals materialized file SHA256'
Assert-True ($manifestWorkerPin -ceq $v2Sha) 'manifest worker pin equals materialized file SHA256'
Assert-True (Test-SourceContains $stageSource 'trustedBootstrapSha256') 'Stage embeds reviewed bootstrap pin'
Assert-True (Test-SourceContains $stageSource 'trustedWorkerSha256') 'Stage embeds reviewed worker pin'
Assert-True (Test-SourceContains $stageSource 'trustedReviewManifestFileSha256') 'Stage embeds reviewed manifest file pin'
Assert-True (Test-SourceContains $stageSource 'REVIEWED_MANIFEST_PIN_MISMATCH') 'Stage rejects self-consistent forged manifest'
if ($stageSource -match "trustedReviewManifestFileSha256\s*=\s*'([a-f0-9]{64})'") {
    Assert-True ($Matches[1] -ceq $manifestFileSha) 'Stage manifest file pin equals materialized manifest SHA256'
} else { throw 'STAGE_PIN_PARSE_FAILED: trustedReviewManifestFileSha256' }
if ($stageSource -match "trustedBootstrapSha256\s*=\s*'([a-f0-9]{64})'") {
    Assert-True ($Matches[1] -ceq $installSha) 'Stage bootstrap pin equals materialized install SHA256'
} else { throw 'STAGE_PIN_PARSE_FAILED: trustedBootstrapSha256' }
if ($stageSource -match "trustedWorkerSha256\s*=\s*'([a-f0-9]{64})'") {
    Assert-True ($Matches[1] -ceq $v2Sha) 'Stage worker pin equals materialized worker SHA256'
} else { throw 'STAGE_PIN_PARSE_FAILED: trustedWorkerSha256' }
Assert-True (-not (Test-SourceContains $installSource 'JsonDocument')) 'Install avoids System.Text.Json'
Assert-True (-not (Test-SourceContains $stageSource 'JsonDocument')) 'Stage avoids System.Text.Json'
Assert-True (-not (Test-SourceContains $v2Source 'JsonDocument')) 'Worker avoids System.Text.Json'
Assert-True (Test-SourceContains $installSource 'Read-ReviewManifest') 'Install reads review manifest'
Assert-True (Test-SourceContains $installSource 'BOOTSTRAP_SHA256_MISMATCH') 'Install self-hash mismatch code'
Assert-True (Test-SourceContains $installSource 'POWERSHELL_HOST_BITNESS_REFUSED') 'Install refuses 32-bit host'
Assert-True (Test-SourceContains $installSource 'SYSWOW64_RUNTIME_REFUSED') 'Install refuses SysWOW64 runtime'
Assert-True (Test-SourceContains $installSource 'Restore-V1Task') 'Install can restore V1 task'
Assert-True (Test-SourceContains $installSource 'TASK_UPDATE_AMBIGUOUS_V1_RESTORED') 'Ambiguous readback restores V1'

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

    $extraFieldManifest = (Get-Content -LiteralPath $manifestPath -Raw) -replace '"schema": 1', '"schema": 1, "unexpected": true'
    [IO.File]::WriteAllText($sandboxManifest, $extraFieldManifest, [Text.UTF8Encoding]::new($false))
    Assert-Refused { Read-ReviewManifest } 'REVIEW_MANIFEST_INVALID'

    $forgeDir = Join-Path $env:TEMP ('LDW_V2Forge_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $forgeDir -Force | Out-Null
    try {
        $forgeInstall = Join-Path $forgeDir $bootstrapFileName
        $forgeWorker = Join-Path $forgeDir $workerBundleName
        $forgeManifest = Join-Path $forgeDir $reviewManifestFileName
        [IO.File]::WriteAllText($forgeInstall, '# forged', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($forgeWorker, '# forged', [Text.UTF8Encoding]::new($false))
        $forgedShaInstall = (Get-FileHash -LiteralPath $forgeInstall -Algorithm SHA256).Hash.ToLowerInvariant()
        $forgedShaWorker = (Get-FileHash -LiteralPath $forgeWorker -Algorithm SHA256).Hash.ToLowerInvariant()
        $forgedManifest = @{
            schema = 1
            protocol = 'ldw.admin-broker.v2-bootstrap.review-manifest.v1'
            artifacts = @(
                @{ name = $bootstrapFileName; sha256 = $forgedShaInstall },
                @{ name = $workerBundleName; sha256 = $forgedShaWorker }
            )
        } | ConvertTo-Json -Depth 5 -Compress
        [IO.File]::WriteAllText($forgeManifest, $forgedManifest, [Text.UTF8Encoding]::new($false))
        $assertFileFn = $stageAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-FileSha256' }, $false)
        if ($null -eq $assertFileFn) { throw 'FUNCTION_REQUIRED: Assert-FileSha256' }
        . ([scriptblock]::Create($assertFileFn.Extent.Text))
        Assert-Refused {
            Assert-FileSha256 $forgeInstall $installSha 'REVIEWED_BOOTSTRAP_SHA256_MISMATCH'
        } 'REVIEWED_BOOTSTRAP_SHA256_MISMATCH'
    } finally {
        Remove-Item -LiteralPath $forgeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
}

$installBody = ($installSource -split "`n" | Select-Object -Skip 2) -join "`n"
foreach ($forbidden in @('Import-Module', 'Invoke-WebRequest', 'Invoke-RestMethod', 'git ', 'ssh ', 'gh ', 'param(')) {
    Assert-True (-not (Test-SourceContains $installBody $forbidden)) "Install forbids: $forbidden"
}
Assert-True (-not (Test-SourceContains $installSource 'Start-Process')) 'Install forbids Start-Process'

Assert-True (Test-SourceContains $stageSource 'System32') 'Stage pins native System32 path'
Assert-True (Test-SourceContains $stageSource 'POWERSHELL_HOST_BITNESS_REFUSED') 'Stage refuses 32-bit host'
Assert-True (Test-SourceContains $stageSource 'PROTECTED_COPY_HASH_MISMATCH') 'Stage post-copy hash gate'
Assert-True (Test-SourceContains $installSource 'Remove-StagedV2Worker') 'Install rollback removes staged V2 only'

Assert-True (Test-SourceContains $v2Source 'DRAGONFLY_V2_PUBLISH_REVIEWED') 'V2 worker registers publish operation'
Assert-True (Test-SourceContains $installSource 'WINDOWSAPPS_RUNTIME_REFUSED') 'Install refuses WindowsApps for V2 task runtime'

Write-Host "Admin Broker V2 publisher bootstrap contract assertions PASS: $script:Assertions"
Write-Host "REVIEW_MANIFEST_INSTALL_SHA256=$manifestInstallPin"
Write-Host "REVIEW_MANIFEST_WORKER_SHA256=$manifestWorkerPin"
Write-Host "REVIEW_MANIFEST_FILE_SHA256=$manifestFileSha"
Write-Host "GIT_TREE_INSTALL_SHA256=$installSha"
