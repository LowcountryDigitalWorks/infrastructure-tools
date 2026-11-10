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
$inlinePath = Join-Path $deployRoot 'Bootstrap-V2ProtectedStagingInlineReference.ps1'
$ownerDocPath = Join-Path $deployRoot '../docs/OWNER_V2_BOOTSTRAP_FIRST_INSTALL_STAGE.md'
$v2WorkerPath = Join-Path $deployRoot 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$manifestPath = Join-Path $deployRoot 'AdminBrokerV2BootstrapReviewManifest.json'
$issuerPath = Join-Path $deployRoot 'AdminBrokerV2BootstrapIssuerManifest.json'
$repoRoot = (Resolve-Path (Join-Path $deployRoot '../..')).Path
$programDataKnown = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$profileKnown = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
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

foreach ($scriptPath in @($installPath, $stagePath, $inlinePath, $v2WorkerPath)) {
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "Parse OK: $(Split-Path -Leaf $scriptPath)"
}
$manifestParsed = $null
try { $manifestParsed = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch { $manifestParsed = $null }
Assert-True ($null -ne $manifestParsed) 'Parse OK: AdminBrokerV2BootstrapReviewManifest.json'
$issuerParsed = $null
try { $issuerParsed = Get-Content -LiteralPath $issuerPath -Raw | ConvertFrom-Json } catch { $issuerParsed = $null }
Assert-True ($null -ne $issuerParsed) 'Parse OK: AdminBrokerV2BootstrapIssuerManifest.json'

$installAst = [Management.Automation.Language.Parser]::ParseFile($installPath, [ref]$null, [ref]$null)
$stageAst = [Management.Automation.Language.Parser]::ParseFile($stagePath, [ref]$null, [ref]$null)
$inlineAst = [Management.Automation.Language.Parser]::ParseFile($inlinePath, [ref]$null, [ref]$null)
Assert-True ($null -eq ($installAst.Find({ param($n) $n -is [Management.Automation.Language.ParamBlockAst] }, $false))) 'Install has no param block'
Assert-True ($null -eq ($stageAst.Find({ param($n) $n -is [Management.Automation.Language.ParamBlockAst] }, $false))) 'Stage has no param block'
Assert-True ($null -eq ($inlineAst.Find({ param($n) $n -is [Management.Automation.Language.ParamBlockAst] }, $false))) 'Inline reference has no param block'

$installSource = Get-Content -LiteralPath $installPath -Raw
$stageSource = Get-Content -LiteralPath $stagePath -Raw
$inlineSource = Get-Content -LiteralPath $inlinePath -Raw
$ownerDocSource = Get-Content -LiteralPath $ownerDocPath -Raw
$v2Source = Get-Content -LiteralPath $v2WorkerPath -Raw
$manifestJson = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$issuerJson = Get-Content -LiteralPath $issuerPath -Raw | ConvertFrom-Json

$installSha = (Get-FileHash -LiteralPath $installPath -Algorithm SHA256).Hash.ToLowerInvariant()
$stageSha = (Get-FileHash -LiteralPath $stagePath -Algorithm SHA256).Hash.ToLowerInvariant()
$inlineSha = (Get-FileHash -LiteralPath $inlinePath -Algorithm SHA256).Hash.ToLowerInvariant()
$issuerFileSha = (Get-FileHash -LiteralPath $issuerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$v2Sha = (Get-FileHash -LiteralPath $v2WorkerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestFileSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestInstallPin = @($manifestJson.artifacts | Where-Object { $_.name -ceq 'Install-AdminBrokerV2PublisherBootstrap.ps1' }).sha256.ToLowerInvariant()
$manifestWorkerPin = @($manifestJson.artifacts | Where-Object { $_.name -ceq 'Invoke-AdminBrokerV2PublisherWorker.ps1' }).sha256.ToLowerInvariant()

Assert-True ($manifestJson.schema -eq 1) 'manifest schema'
Assert-True ($manifestJson.protocol -ceq 'ldw.admin-broker.v2-bootstrap.review-manifest.v1') 'manifest protocol'
Assert-True ($manifestInstallPin -ceq $installSha) 'manifest install pin equals materialized file SHA256'
Assert-True ($manifestWorkerPin -ceq $v2Sha) 'manifest worker pin equals materialized file SHA256'
Assert-True ($issuerJson.schema -eq 1) 'issuer manifest schema'
Assert-True ($issuerJson.protocol -ceq 'ldw.admin-broker.v2-bootstrap.issuer-manifest.v1') 'issuer manifest protocol'
Assert-True (@($issuerJson.artifacts).Count -eq 4) 'issuer manifest lists four artifacts'
$issuerStagePin = @($issuerJson.artifacts | Where-Object { $_.name -ceq 'Stage-AdminBrokerV2PublisherBootstrap.ps1' }).sha256.ToLowerInvariant()
Assert-True ($issuerStagePin -ceq $stageSha) 'issuer manifest stage pin equals materialized Stage SHA256'
Assert-True (-not (Test-Path -LiteralPath (Join-Path $deployRoot 'OwnerAdmin-InvokeV2BootstrapProtectedStage.ps1'))) 'Downloads owner launcher removed from source'
Assert-True (-not (@($issuerJson.artifacts | Where-Object { $_.name -ceq 'AdminBrokerV2BootstrapIssuerManifest.json' }))) 'issuer manifest has no circular self-entry'
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
Assert-True (Test-SourceContains $installSource 'Assert-V1OperationsQuiescent') 'Install asserts V1 operations quiescent'
Assert-True (Test-SourceContains $installSource 'Invoke-V1TaskRollback') 'Install uses explicit V1 rollback'
Assert-True (Test-SourceContains $installSource 'TASK_MUST_BE_HELD_BEFORE_UPDATE') 'Install refuses task update while enabled'
Assert-True (Test-SourceContains $installSource 'TASK_DISABLE_HOLD_FAILED') 'Install verifies task disable hold'
Assert-True (Test-SourceContains $installSource 'V1_TASK_RESTORE_AMBIGUOUS') 'Install verifies V1 restore readback'
Assert-True (Test-SourceContains $installSource 'V1_ROLLBACK_DISABLE_FAILED') 'Install exposes rollback disable failure code'
Assert-True (Test-SourceContains $installSource 'FAILURE_ROLLBACK_FAILED') 'Install journals rollback failure without swallowing'
Assert-True (Test-SourceContains $installSource 'V1_TASK_HELD_BEFORE_MUTATION') 'Install journals task hold before mutation'
$mainMarker = '    Acquire-BootstrapLock'
$mainStart = $installSource.IndexOf($mainMarker, [StringComparison]::Ordinal)
$mainSlice = if ($mainStart -ge 0) { $installSource.Substring($mainStart) } else { $installSource }
$holdBeforeRegister = $mainSlice.IndexOf('Disable-TaskHold', [StringComparison]::Ordinal)
$registerCall = $mainSlice.IndexOf('$update = Register-V2Task', [StringComparison]::Ordinal)
Assert-True ($holdBeforeRegister -ge 0 -and $registerCall -gt $holdBeforeRegister) 'Disable-TaskHold precedes Register-V2Task in main transaction'
Assert-True (-not (Test-SourceContains $installSource 'Restore-V1Task $ownerSid $script:V1Snapshot')) 'Install does not call Restore-V1Task without rollback wrapper in catch'

if (Test-Path -LiteralPath (Join-Path $repoRoot '.git')) {
    $gitInstallBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/Install-AdminBrokerV2PublisherBootstrap.ps1" 2>$null).Trim()
    $gitWorkerBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/Invoke-AdminBrokerV2PublisherWorker.ps1" 2>$null).Trim()
    $gitManifestBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/AdminBrokerV2BootstrapReviewManifest.json" 2>$null).Trim()
    $gitStageBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/Stage-AdminBrokerV2PublisherBootstrap.ps1" 2>$null).Trim()
    $gitInlineBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/Bootstrap-V2ProtectedStagingInlineReference.ps1" 2>$null).Trim()
    $gitIssuerBlob = (git -C $repoRoot rev-parse "HEAD:host-agent/deploy/AdminBrokerV2BootstrapIssuerManifest.json" 2>$null).Trim()
    Assert-True ($gitInstallBlob -match '^[a-f0-9]{40}$') 'git install blob identity'
    Assert-True ($gitWorkerBlob -match '^[a-f0-9]{40}$') 'git worker blob identity'
    Assert-True ($gitManifestBlob -match '^[a-f0-9]{40}$') 'git manifest blob identity'
    Assert-True ($gitStageBlob -match '^[a-f0-9]{40}$') 'git stage blob identity'
    Assert-True ($gitInlineBlob -match '^[a-f0-9]{40}$') 'git inline reference blob identity'
    Assert-True ($gitIssuerBlob -match '^[a-f0-9]{40}$') 'git issuer manifest blob identity'
    $gitInstallSha = (git -C $repoRoot hash-object $installPath).Trim().ToLowerInvariant()
    Assert-True ($gitInstallBlob -ceq $gitInstallSha) 'install git blob matches working tree object'
    Assert-True ($gitStageBlob -ceq (git -C $repoRoot hash-object $stagePath).Trim().ToLowerInvariant()) 'stage git blob matches working tree object'
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

$opsSandbox = Join-Path $env:TEMP ('LDW_V2OpsQuiescence_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $opsSandbox -Force
try {
    $noReparseOps = $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-NoReparse' }, $false)
    $opsFn = $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-V1OperationsQuiescent' }, $false)
    $lockIdleFn = $installAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Test-OperationLockIdle' }, $false)
    if ($null -eq $noReparseOps -or $null -eq $opsFn -or $null -eq $lockIdleFn) {
        throw 'FUNCTION_REQUIRED: V1 operations quiescence helpers'
    }

    $controlRoot = $opsSandbox
    $lockRoot = Join-Path $opsSandbox 'lock'
    $requestRoot = Join-Path $opsSandbox 'requests'
    $resultRoot = Join-Path $opsSandbox 'results'
    $operationLockPath = Join-Path $lockRoot 'operation.lock'
    $taskName = '\LDW-ADMIN-REVIEWED-OPERATION'
    $v1InFlightMinutes = 15
    $v1ResultsScanMaxFiles = 64

    $global:LdwV2MockSchedulerState = 3
    $global:LdwV2MockFolder = $null
    function Get-TaskService {
        $global:LdwV2MockFolder = New-Object PSObject
        $global:LdwV2MockFolder | Add-Member -MemberType ScriptMethod -Name GetTask -Value {
            param([string]$Name)
            [pscustomobject]@{ State = $global:LdwV2MockSchedulerState }
        }
        $mockService = New-Object PSObject
        $mockService | Add-Member -MemberType ScriptMethod -Name GetFolder -Value {
            param([string]$Path)
            $global:LdwV2MockFolder
        }
        $mockService
    }

    function Assert-ProtectedDirectory([string]$Path) {
        Assert-NoReparse $Path
        if (-not (Test-Path -LiteralPath $Path)) { throw 'PROTECTED_PATH_MISSING' }
    }
    . ([scriptblock]::Create($noReparseOps.Extent.Text))
    . ([scriptblock]::Create($lockIdleFn.Extent.Text))
    . ([scriptblock]::Create($opsFn.Extent.Text))

    $null = New-Item -ItemType Directory -Path $requestRoot -Force
    Assert-V1OperationsQuiescent

    [IO.File]::WriteAllText((Join-Path $requestRoot 'request.json'), '{"schema":1}', [Text.UTF8Encoding]::new($false))
    Assert-Refused { Assert-V1OperationsQuiescent } 'PENDING_REQUEST_REFUSED'
    Remove-Item -LiteralPath (Join-Path $requestRoot 'request.json') -Force

    $null = New-Item -ItemType Directory -Path $resultRoot -Force
    $corrId = [guid]::NewGuid().ToString('D')
    $startedPath = Join-Path $resultRoot ($corrId + '.json')
    $startedPayload = '{"schema":1,"correlationId":"' + $corrId + '","resultState":"STARTED"}'
    [IO.File]::WriteAllText($startedPath, $startedPayload, [Text.UTF8Encoding]::new($false))
    (Get-Item -LiteralPath $startedPath).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-5)
    Assert-Refused { Assert-V1OperationsQuiescent } 'ACTIVE_OPERATION_REFUSED'
    (Get-Item -LiteralPath $startedPath).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-20)
    Assert-V1OperationsQuiescent

    $null = New-Item -ItemType Directory -Path $lockRoot -Force
    $lockStream = [IO.File]::Open($operationLockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        Assert-Refused { Assert-V1OperationsQuiescent } 'V1_OPERATION_LOCK_HELD'
    } finally {
        $lockStream.Dispose()
        Remove-Item -LiteralPath $operationLockPath -Force
    }

    $global:LdwV2MockSchedulerState = 4
    Assert-Refused { Assert-V1OperationsQuiescent } 'ACTIVE_TASK_REFUSED'
} finally {
    Remove-Item -LiteralPath $opsSandbox -Recurse -Force -ErrorAction SilentlyContinue
}

$installBody = ($installSource -split "`n" | Select-Object -Skip 2) -join "`n"
foreach ($forbidden in @('Import-Module', 'Invoke-WebRequest', 'Invoke-RestMethod', 'git ', 'ssh ', 'gh ', 'param(')) {
    Assert-True (-not (Test-SourceContains $installBody $forbidden)) "Install forbids: $forbidden"
}
Assert-True (-not (Test-SourceContains $installSource 'Start-Process')) 'Install forbids Start-Process'

Assert-True (Test-SourceContains $stageSource 'System32') 'Stage pins native System32 path'
Assert-True (Test-SourceContains $stageSource 'POWERSHELL_HOST_BITNESS_REFUSED') 'Stage refuses 32-bit host'
Assert-True (Test-SourceContains $stageSource 'PROTECTED_COPY_HASH_MISMATCH') 'Stage post-copy hash gate'
Assert-True (Test-SourceContains $stageSource 'STAGE_DOWNLOAD_PATH_REFUSED') 'Stage refuses Downloads execution'
Assert-True (Test-SourceContains $stageSource 'STAGE_PROTECTED_PATH_REQUIRED') 'Stage requires protected path'
Assert-True (Test-SourceContains $stageSource 'STAGE_ISSUER_PIN_MISMATCH') 'Stage verifies self via issuer manifest'
Assert-True (Test-SourceContains $stageSource 'ISSUER_REVIEWED_PIN_MISMATCH') 'Stage cross-checks issuer against embedded review pins'
Assert-True (-not (Test-SourceContains $stageSource 'LDW-V2-Publisher-Bootstrap-Review')) 'Stage does not read Downloads bundle'
Assert-True (Test-SourceContains $inlineSource 'INLINE_REFERENCE_NOT_FILE_INVOKABLE') 'Inline reference refuses -File invocation'
Assert-True (Test-SourceContains $inlineSource 'ReadAllBytes') 'Inline transaction treats Downloads as byte DATA'
Assert-True (Test-SourceContains $inlineSource 'DOWNLOADS_DATA_HASH_MISMATCH') 'Inline transaction refuses download DATA tamper'
Assert-True (Test-SourceContains $inlineSource 'STAGING_ALREADY_EXISTS') 'Inline transaction refuses concurrent staging'
Assert-True (Test-SourceContains $inlineSource 'DOWNLOAD_BUNDLE_ROOT_REFUSED') 'Inline transaction pins Downloads bundle root'
Assert-True (Test-SourceContains $inlineSource 'Invoke-LdwV2BootstrapProtectedStagingInlineTransaction') 'Inline transaction entry function published'
Assert-True (Test-SourceContains $inlineSource 'Get-MachineProgramDataRootInline') 'Inline uses CommonApplicationData root'
Assert-True (Test-SourceContains $inlineSource 'LDW_PARENT_ACL_HOLD') 'Inline preflight refuses weak parent DACL'
Assert-True (Test-SourceContains $inlineSource 'USERPROFILE_ENV_SPOOFED') 'Inline refuses profile env spoof'
Assert-True (Test-SourceContains $stageSource 'Get-MachineProgramDataRoot') 'Stage uses CommonApplicationData root'
Assert-True (Test-SourceContains $stageSource 'LDW_PARENT_ACL_HOLD') 'Stage preflight refuses weak parent DACL'
Assert-True (Test-SourceContains $installSource 'Get-MachineProgramDataRoot') 'Install uses CommonApplicationData root'
Assert-True (Test-SourceContains $installSource 'PROGRAMDATA_ENV_SPOOFED') 'Install refuses ProgramData env spoof'
Assert-True (Test-SourceContains $installSource 'LDW_PARENT_ACL_HOLD') 'Install preflight refuses weak parent DACL'
Assert-True (-not (Test-SourceContains $stageSource 'Join-Path $env:ProgramData')) 'Stage does not join paths from process ProgramData env'
Assert-True (-not (Test-SourceContains $inlineSource 'Join-Path $env:ProgramData')) 'Inline does not join paths from process ProgramData env'
Assert-True (Test-SourceContains $stageSource 'PROGRAMDATA_ENV_SPOOFED') 'Stage compares process ProgramData to machine known folder'
Assert-True (Test-SourceContains $inlineSource 'PROGRAMDATA_ENV_SPOOFED') 'Inline compares process ProgramData to machine known folder'
Assert-True (Test-SourceContains $ownerDocSource 'Invoke-LdwV2BootstrapProtectedStagingInlineTransaction') 'Owner doc names inline transaction entry'
Assert-True (-not (Test-SourceContains $ownerDocSource 'OwnerAdmin-InvokeV2BootstrapProtectedStage.ps1')) 'Owner doc does not reference Downloads launcher'
Assert-True (Test-SourceContains $ownerDocSource 'Never `powershell -File` a path under Downloads while elevated') 'Owner doc states elevated -File Downloads prohibition'
Assert-True (-not ($ownerDocSource -match '(?i)-File\s+"?%USERPROFILE%\\Downloads')) 'Owner doc has no frozen -File Downloads command line'
Assert-True (-not (Test-SourceContains $stageSource 'trustedIssuerManifestFileSha256')) 'Stage avoids circular issuer self pin'
if (Test-SourceContains ([IO.File]::ReadAllText($issuerPath)) "`r`n") {
    $script:Assertions++
} else { throw 'ASSERTION_FAILED: issuer manifest materializes with CRLF line endings' }
if ($inlineSource -match "trustedIssuerManifestFileSha256 = '([a-f0-9]{64})'") {
    Assert-True ($Matches[1] -ceq $issuerFileSha) 'Inline issuer pin equals materialized issuer manifest SHA256'
} else { throw 'INLINE_PIN_PARSE_FAILED: trustedIssuerManifestFileSha256' }
if ($inlineSource -match "trustedStageSha256 = '([a-f0-9]{64})'") {
    Assert-True ($Matches[1] -ceq $stageSha) 'Inline stage pin equals materialized Stage SHA256'
} else { throw 'INLINE_PIN_PARSE_FAILED: trustedStageSha256' }

$inlineCopyFn = $inlineAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Copy-VerifiedBytesInline' }, $false)
$inlineNoReparseFn = $inlineAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-NoReparseInline' }, $false)
$inlineAssertHashFn = $inlineAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-FileSha256Inline' }, $false)
if ($null -eq $inlineCopyFn -or $null -eq $inlineNoReparseFn -or $null -eq $inlineAssertHashFn) {
    throw 'FUNCTION_REQUIRED: inline copy helpers'
}
. ([scriptblock]::Create($inlineNoReparseFn.Extent.Text))
. ([scriptblock]::Create($inlineAssertHashFn.Extent.Text))
. ([scriptblock]::Create($inlineCopyFn.Extent.Text))
$inlineSandbox = Join-Path $env:TEMP ('LDW_V2InlineCopy_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $inlineSandbox -Force
try {
    $good = Join-Path $inlineSandbox 'good.bin'
    $dest = Join-Path $inlineSandbox 'dest.bin'
    [IO.File]::WriteAllBytes($good, [byte[]](1, 2, 3))
    $goodSha = (Get-FileHash -LiteralPath $good -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-VerifiedBytesInline $good $dest $goodSha | Out-Null
    Assert-True (Test-Path -LiteralPath $dest) 'inline copy creates protected file'
    [IO.File]::WriteAllBytes($good, [byte[]](9, 9, 9))
    $destTamper = Join-Path $inlineSandbox 'dest-tamper.bin'
    Assert-Refused { Copy-VerifiedBytesInline $good $destTamper $goodSha } 'DOWNLOADS_DATA_HASH_MISMATCH'
} finally {
    Remove-Item -LiteralPath $inlineSandbox -Recurse -Force -ErrorAction SilentlyContinue
}

$launcherSubstitute = Join-Path $env:TEMP ('LDW_V2FakeLauncher_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $launcherSubstitute -Force
try {
    $fakeLauncher = Join-Path $launcherSubstitute 'OwnerAdmin-InvokeV2BootstrapProtectedStage.ps1'
    [IO.File]::WriteAllText($fakeLauncher, 'Write-Host hijacked', [Text.UTF8Encoding]::new($false))
    $proc = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fakeLauncher) `
        -Wait -PassThru -NoNewWindow
    Assert-True ($proc.ExitCode -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $programDataKnown 'LDW\PrivilegedControl\bootstrap-staging\v2-publisher-once'))) `
        'substituted Downloads launcher is not trusted bootstrap authority'
} finally {
    Remove-Item -LiteralPath $launcherSubstitute -Recurse -Force -ErrorAction SilentlyContinue
}

$inlineErrPath = Join-Path $env:TEMP ('ldw-inline-file-test-' + [guid]::NewGuid().ToString('N') + '.txt')
$pdRootFn = $stageAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-MachineProgramDataRoot' }, $false)
$aclFn = $stageAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-TrustedDirectoryAcl' }, $false)
if ($null -eq $pdRootFn -or $null -eq $aclFn) { throw 'FUNCTION_REQUIRED: machine program data helpers' }
. ([scriptblock]::Create($pdRootFn.Extent.Text))
. ([scriptblock]::Create($aclFn.Extent.Text))
$originalPd = $env:ProgramData
try {
    $env:ProgramData = 'C:\SpoofedProgramDataForTest'
    Assert-Refused { Get-MachineProgramDataRoot } 'PROGRAMDATA_ENV_SPOOFED'
} finally {
    $env:ProgramData = $originalPd
}
$aclSandbox = Join-Path $env:TEMP ('LDW_V2Acl_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $aclSandbox -Force
try {
    Assert-Refused { Assert-TrustedDirectoryAcl $aclSandbox } 'LDW_PARENT_OWNER_REFUSED'
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $acl = Get-Acl -LiteralPath $aclSandbox
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $usersSid, 'Write', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $aclSandbox -AclObject $acl
        Assert-Refused { Assert-TrustedDirectoryAcl $aclSandbox } 'LDW_PARENT_ACL_HOLD'
    }
} finally {
    Remove-Item -LiteralPath $aclSandbox -Recurse -Force -ErrorAction SilentlyContinue
}

$inlineFileProc = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $inlinePath) `
    -Wait -PassThru -NoNewWindow -RedirectStandardError $inlineErrPath
Assert-True ($inlineFileProc.ExitCode -ne 0) 'inline reference -File exits non-zero'
$inlineErr = ''
if (Test-Path -LiteralPath $inlineErrPath) {
    $inlineErr = Get-Content -LiteralPath $inlineErrPath -Raw -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $inlineErrPath -Force -ErrorAction SilentlyContinue
}
Assert-True ($inlineErr.IndexOf('INLINE_REFERENCE_NOT_FILE_INVOKABLE', [StringComparison]::Ordinal) -ge 0) 'inline reference -File refused'

$stageProtectedFn = $stageAst.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-ProtectedStagePath' }, $false)
if ($null -eq $stageProtectedFn) { throw 'FUNCTION_REQUIRED: Assert-ProtectedStagePath' }
$stagingSample = Join-Path $programDataKnown 'LDW\PrivilegedControl\bootstrap-staging\v2-publisher-once\Stage-AdminBrokerV2PublisherBootstrap.ps1'
$downloadsSample = Join-Path $profileKnown 'Downloads\LDW-V2-Publisher-Bootstrap-Review\Stage-AdminBrokerV2PublisherBootstrap.ps1'
. ([scriptblock]::Create($stageProtectedFn.Extent.Text))
Assert-Refused { Assert-ProtectedStagePath $downloadsSample $stagingSample } 'STAGE_DOWNLOAD_PATH_REFUSED'
Assert-Refused { Assert-ProtectedStagePath $installPath $stagingSample } 'STAGE_PROTECTED_PATH_REQUIRED'
Assert-True (Test-SourceContains $installSource 'Remove-StagedV2Worker') 'Install rollback removes staged V2 only'

Assert-True (Test-SourceContains $v2Source 'DRAGONFLY_V2_PUBLISH_REVIEWED') 'V2 worker registers publish operation'
Assert-True (Test-SourceContains $installSource 'WINDOWSAPPS_RUNTIME_REFUSED') 'Install refuses WindowsApps for V2 task runtime'

Write-Host "Admin Broker V2 publisher bootstrap contract assertions PASS: $script:Assertions"
Write-Host "REVIEW_MANIFEST_INSTALL_SHA256=$manifestInstallPin"
Write-Host "REVIEW_MANIFEST_WORKER_SHA256=$manifestWorkerPin"
Write-Host "REVIEW_MANIFEST_FILE_SHA256=$manifestFileSha"
Write-Host "ISSUER_MANIFEST_FILE_SHA256=$issuerFileSha"
Write-Host "STAGE_SHA256=$stageSha"
Write-Host "INLINE_REFERENCE_SHA256=$inlineSha"
Write-Host "GIT_TREE_INSTALL_SHA256=$installSha"
