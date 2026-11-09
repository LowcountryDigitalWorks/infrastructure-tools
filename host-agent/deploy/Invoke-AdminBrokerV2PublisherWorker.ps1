[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$WorkerSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$controlRoot = Join-Path $env:ProgramData 'LDW/PrivilegedControl'
$binRoot = Join-Path $controlRoot 'bin'
$requestRoot = Join-Path $controlRoot 'requests'
$resultRoot = Join-Path $controlRoot 'results'
$lockRoot = Join-Path $controlRoot 'lock'
$requestPath = Join-Path $requestRoot 'request.json'
$lockPath = Join-Path $lockRoot 'operation.lock'
$v2WorkerIdentity = 'v2-publisher-reviewed-1'
$expectedWorker = Join-Path $binRoot ('v2/' + $v2WorkerIdentity + '/Invoke-AdminBrokerV2PublisherWorker.ps1')

$script:LockStream = $null
$script:CorrelationId = $null
$script:OperationId = $null

function Assert-ElevatedTask {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATION_REQUIRED'
    }
}

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'REPARSE_PATH_REFUSED'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-ProtectedPath([string]$Path) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath ([IO.Path]::GetFullPath($Path))
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
        throw 'PROTECTED_OWNER_REFUSED'
    }
    $forbidden = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $forbidden) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
            throw 'PROTECTED_WRITE_REFUSED'
        }
    }
}

function Assert-WorkerProvenance {
    Assert-ElevatedTask
    $actualWorker = [IO.Path]::GetFullPath($PSCommandPath)
    if (-not [string]::Equals($actualWorker, [IO.Path]::GetFullPath($expectedWorker), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'WORKER_PATH_REFUSED'
    }
    foreach ($path in @($controlRoot, $binRoot, $requestRoot, $resultRoot, $lockRoot)) {
        Assert-NoReparse $path
    }
    Assert-ProtectedPath $binRoot
    Assert-ProtectedPath $actualWorker
    $actualHash = (Get-FileHash -LiteralPath $actualWorker -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $WorkerSha256) {
        throw 'PROVENANCE_MISMATCH'
    }
    if (Test-Path -LiteralPath $resultRoot) {
        Assert-ProtectedPath $resultRoot
    }
    if (Test-Path -LiteralPath $requestRoot) {
        $reqAcl = Get-Acl -LiteralPath ([IO.Path]::GetFullPath($requestRoot))
        if ($reqAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
            throw 'PROTECTED_OWNER_REFUSED'
        }
        $forbidden = [Security.AccessControl.FileSystemRights]::Write -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership
        $rules = @($reqAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $writers = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $forbidden) -and $_.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') })
        if ($writers.Count -eq 0) {
            throw 'PROTECTED_WRITE_REFUSED'
        }
        $uniqueWriterSids = @($writers | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique)
        if ($uniqueWriterSids.Count -ne 1 -or $uniqueWriterSids[0] -cnotmatch '^S-1-5-21-(\d+-){3}\d+$') {
            throw 'PROTECTED_WRITE_REFUSED'
        }
    }
}

function Prune-StaleResults {
    if (-not (Test-Path -LiteralPath $resultRoot -PathType Container)) { return }
    Assert-NoReparse $resultRoot
    $cutoff = [DateTime]::UtcNow.AddHours(-24)
    $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$'
    $pendingPattern = '^\.pending-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$'
    $files = @(Get-ChildItem -LiteralPath $resultRoot -File -ErrorAction Stop)
    $failed = $false
    foreach ($file in $files) {
        if ($file.Name -cmatch $guidPattern -or $file.Name -cmatch $pendingPattern) {
            if ($file.LastWriteTimeUtc -lt $cutoff) {
                try {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                } catch {
                    $failed = $true
                }
            }
        }
    }
    if ($failed) {
        throw 'PRUNING_FAILED'
    }
}

function Acquire-OperationLock {
    Assert-NoReparse $lockRoot
    if (-not (Test-Path -LiteralPath $lockRoot -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $lockRoot -Force
    }
    try {
        $script:LockStream = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        throw 'BUSY'
    }
}

function Release-OperationLock {
    if ($null -ne $script:LockStream) {
        try { $script:LockStream.Dispose() } catch { }
        $script:LockStream = $null
    }
}

function Read-Request {
    Assert-NoReparse $requestRoot
    Assert-NoReparse $requestPath
    if (-not (Test-Path -LiteralPath $requestPath -PathType Leaf)) {
        return $null
    }
    $bytes = [IO.File]::ReadAllBytes($requestPath)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 16384) {
        throw 'INVALID_REQUEST'
    }
    [System.ReadOnlyMemory[byte]]$jsonMemory = $bytes
    $document = [Text.Json.JsonDocument]::Parse($jsonMemory)
    try {
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw 'INVALID_REQUEST'
        }
        $names = @($root.EnumerateObject() | ForEach-Object Name)
        if ($names.Count -ne 3 -or @($names | Group-Object | Where-Object Count -ne 1).Count -or
            @(Compare-Object @('schema', 'correlationId', 'operationId') $names -CaseSensitive).Count) {
            throw 'INVALID_REQUEST'
        }
        if ($root.GetProperty('schema').GetInt32() -ne 1) {
            throw 'INVALID_REQUEST'
        }
        $corrId = $root.GetProperty('correlationId').GetString()
        [Guid]$parsedId = [Guid]::Empty
        if (-not [Guid]::TryParseExact($corrId, 'D', [ref]$parsedId)) {
            throw 'INVALID_REQUEST'
        }
        $opId = $root.GetProperty('operationId').GetString()
        if ([string]::IsNullOrWhiteSpace($opId) -or $opId -cnotmatch '^[A-Z0-9_]{1,64}$') {
            throw 'INVALID_REQUEST'
        }

        # Durable in-flight / completed check
        $targetResultPath = Join-Path $resultRoot ($corrId + '.json')
        if (Test-Path -LiteralPath $targetResultPath) {
            $existingBytes = [IO.File]::ReadAllBytes($targetResultPath)
            if ($existingBytes.Length -lt 2 -or $existingBytes.Length -gt 16384) {
                throw 'INVALID_ADAPTER_RESULT'
            }
            [System.ReadOnlyMemory[byte]]$existingMem = $existingBytes
            $existingDoc = [Text.Json.JsonDocument]::Parse($existingMem)
            try {
                $existingRoot = $existingDoc.RootElement
                if ($existingRoot.ValueKind -ne [Text.Json.JsonValueKind]::Object -or
                    $existingRoot.GetProperty('schema').GetInt32() -ne 1 -or
                    $existingRoot.GetProperty('correlationId').GetString() -cne $corrId) {
                    throw 'INVALID_ADAPTER_RESULT'
                }
                $existingState = $existingRoot.GetProperty('resultState').GetString()
                if ($existingState -ceq 'STARTED') {
                    $resultItem = Get-Item -LiteralPath $targetResultPath -Force
                    $resultAge = [DateTime]::UtcNow - $resultItem.LastWriteTimeUtc
                    if ($resultAge.TotalMinutes -lt 15) {
                        # In-flight younger than timeout: do not re-execute, preserve bounded STARTED state
                        return $null
                    }
                    # In-flight at or beyond timeout: reconcile to terminal TIMEOUT without action re-execution
                    $script:CorrelationId = $corrId
                    $script:OperationId = $opId
                    Write-Result -Success $false -State 'FAILED' -Reason 'TIMEOUT' -Details @{ timeoutReason = 'IN_FLIGHT_CRASH_OR_TIMEOUT' }
                    Remove-RequestSlot
                    return $null
                } else {
                    # Terminal result already exists: completed => never execute again
                    Remove-RequestSlot
                    return $null
                }
            } finally {
                $existingDoc.Dispose()
            }
        }

        # Result does not exist; check if request is expired
        $item = Get-Item -LiteralPath $requestPath -Force
        $age = [DateTime]::UtcNow - $item.LastWriteTimeUtc
        if ($age.TotalMinutes -ge 15) {
            $script:CorrelationId = $corrId
            $script:OperationId = $opId
            Write-Result -Success $false -State 'FAILED' -Reason 'TIMEOUT' -Details @{ timeoutReason = 'REQUEST_EXPIRED' }
            Remove-RequestSlot
            return $null
        }

        [pscustomobject]@{ CorrelationId = $corrId; OperationId = $opId }
    } finally {
        $document.Dispose()
    }
}

function Write-Result([bool]$Success, [string]$State, [string]$Reason, [hashtable]$Details = $null) {
    if (-not $script:CorrelationId -or $script:CorrelationId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        return
    }
    if ($State -cnotin @('QUEUED', 'STARTED', 'PASS', 'BLOCKED', 'FAILED', 'AMBIGUOUS')) {
        $State = 'FAILED'
    }
    if ($Reason -cnotin @('NONE', 'ADAPTER_UNAVAILABLE', 'INVALID_ADAPTER_RESULT', 'TARGET_REFUSED',
            'UNKNOWN_OPERATION', 'INVALID_REQUEST', 'BUSY', 'TIMEOUT', 'PROVENANCE_MISMATCH',
            'ELEVATION_REQUIRED', 'EXECUTION_FAILED', 'OPERATION_NOT_FOUND', 'POLICY_REJECTED',
            'DUPLICATE_REQUEST', 'FAILED')) {
        $Reason = 'FAILED'
    }

    $sanitizedDetails = [ordered]@{}
    if ($null -ne $Details) {
        foreach ($key in $Details.Keys) {
            $keyStr = [string]$key
            $valStr = [string]$Details[$key]
            if ($keyStr -cmatch '^[a-zA-Z0-9_]{1,64}$' -and $valStr -cmatch '^[a-zA-Z0-9_\-\.:]{1,256}$') {
                $sanitizedDetails[$keyStr] = $valStr
            }
        }
    }

    $payload = [ordered]@{
        schema = 1
        correlationId = $script:CorrelationId
        operationId = $(if ($script:OperationId) { $script:OperationId } else { 'UNKNOWN' })
        success = $Success
        resultState = $State
        reasonCode = $Reason
        details = $(if ($sanitizedDetails.Count -gt 0) { $sanitizedDetails } else { $null })
    }

    Assert-NoReparse $resultRoot
    if (-not (Test-Path -LiteralPath $resultRoot -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $resultRoot -Force
    }

    $tempPath = Join-Path $resultRoot ('.pending-' + $script:CorrelationId + '.json')
    $finalPath = Join-Path $resultRoot ($script:CorrelationId + '.json')
    $json = $payload | ConvertTo-Json -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 16384) {
        throw 'RESULT_TOO_LARGE'
    }
    try {
        [IO.File]::WriteAllText($tempPath, $json, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tempPath -Destination $finalPath -Force
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-RequestSlot {
    if (Test-Path -LiteralPath $requestPath) {
        Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue
    }
}

# Closed V2 publication pins (no git/network; inbound package only).
$script:V2ReleaseIdentity = '78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca-e53e016383441fde6ba22cb57821b3d26bdf4824'
$script:V2CanaryCommit = '78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca'
$script:V2CanaryTree = '5f54ee5b76f49250db1358f058745cb30b6587ef'
$script:V2EntryCommit = 'e53e016383441fde6ba22cb57821b3d26bdf4824'
$script:V2EntryTree = '18e910ba4ed5113a1a4b5065bcc8f08a5e0084cb'
$script:V2DispatchCommit = 'ce2bf253556a69dfb43de7bb8e8a4927c41c9e15'
$script:V2DispatchTree = '57ceb47f2a0a40d3b176cde0818a0ad8c5891dca'
$script:V2DispatchBlob = 'c862dd503b98060ec984206e63ef9efa5f957e8f'
$script:V2DispatchRawSha256 = '76092a5344746f4385a2b99ee0403c298ffed0458099444ddc82b67fd30f0675'
$script:V2DispatchWindowsSha256 = '0a41b338ca6b8b05ff31a26f30486381c7c836e484985a813b6fce6d07232c72'
$script:V2InboundRoot = Join-Path $env:ProgramData 'LDW/DragonflyCanaryAdjunct/inbound-reviewed-v2'
$script:V2AdjunctRoot = Join-Path $env:ProgramData 'LDW/DragonflyCanaryAdjunct'
$script:V2PinnedFiles = @(
    @{ path = 'ci-dispatch/DragonflyCanary.psm1'; commit = $script:V2CanaryCommit; tree = $script:V2CanaryTree; blob = '893c89ae65bd85464f404fa4a4ff762344915520'; representation = 'raw' },
    @{ path = 'ci-dispatch/DragonflyCanaryRuntime.psm1'; commit = $script:V2CanaryCommit; tree = $script:V2CanaryTree; blob = '7730f473d2588e885fa6a4f3aec1b486b408dbda'; representation = 'raw' },
    @{ path = 'ci-dispatch/Invoke-DragonflyCanaryProduction.ps1'; commit = $script:V2EntryCommit; tree = $script:V2EntryTree; blob = '2068368b6ba91a476d8a1f05fc6b0792dca2d263'; representation = 'raw' },
    @{ path = 'ci-dispatch/Dispatch.psm1'; commit = $script:V2DispatchCommit; tree = $script:V2DispatchTree; blob = $script:V2DispatchBlob; representation = 'crlf' }
)

function Assert-V2ProtectedLeaf([string]$Path) {
    Assert-NoReparse $Path
    if (-not (Test-Path -LiteralPath $Path)) { throw 'PROVENANCE_MISMATCH' }
    $acl = Get-Acl -LiteralPath ([IO.Path]::GetFullPath($Path))
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
        throw 'PROVENANCE_MISMATCH'
    }
}

function Invoke-DragonflyV2PublishReviewed([string]$CorrelationId) {
    if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { throw 'PROGRAMDATA_INVALID' }
    if (-not (Test-Path -LiteralPath $script:V2InboundRoot -PathType Container)) {
        return [pscustomobject]@{
            Success = $false
            ResultState = 'BLOCKED'
            ReasonCode = 'TARGET_REFUSED'
            Details = [ordered]@{ publishState = 'PACKAGE_INBOUND_MISSING' }
        }
    }
    Assert-V2ProtectedLeaf $script:V2AdjunctRoot
    Assert-V2ProtectedLeaf $script:V2InboundRoot
    $manifestPath = Join-Path $script:V2InboundRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return [pscustomobject]@{
            Success = $false
            ResultState = 'BLOCKED'
            ReasonCode = 'TARGET_REFUSED'
            Details = [ordered]@{ publishState = 'MANIFEST_MISSING' }
        }
    }
    Assert-V2ProtectedLeaf $manifestPath
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
    catch {
        return [pscustomobject]@{
            Success = $false; ResultState = 'FAILED'; ReasonCode = 'POLICY_REJECTED'
            Details = [ordered]@{ publishState = 'MANIFEST_INVALID' }
        }
    }
    if ($manifest.schema -ne 2 -or $manifest.artifact -cne 'ldw-dragonfly-canary-adjunct-v2' -or
        $manifest.releaseIdentity -cne $script:V2ReleaseIdentity -or
        $manifest.canaryCommit -cne $script:V2CanaryCommit -or $manifest.canaryTree -cne $script:V2CanaryTree -or
        $manifest.entryCommit -cne $script:V2EntryCommit -or $manifest.entryTree -cne $script:V2EntryTree -or
        $manifest.containsCredential -ne $false -or $manifest.containsBootstrap -ne $false -or $manifest.containsPrivateEndpoint -ne $false -or
        $manifest.dispatchAuthority.commit -cne $script:V2DispatchCommit -or $manifest.dispatchAuthority.tree -cne $script:V2DispatchTree -or
        $manifest.dispatchAuthority.blob -cne $script:V2DispatchBlob -or $manifest.dispatchAuthority.rawSha256 -cne $script:V2DispatchRawSha256 -or
        $manifest.dispatchAuthority.windowsSha256 -cne $script:V2DispatchWindowsSha256 -or $manifest.dispatchAuthority.materialization -cne 'crlf') {
        return [pscustomobject]@{
            Success = $false; ResultState = 'FAILED'; ReasonCode = 'POLICY_REJECTED'
            Details = [ordered]@{ publishState = 'MANIFEST_POLICY_MISMATCH' }
        }
    }
    if (@($manifest.files).Count -ne $script:V2PinnedFiles.Count) {
        return [pscustomobject]@{
            Success = $false; ResultState = 'FAILED'; ReasonCode = 'POLICY_REJECTED'
            Details = [ordered]@{ publishState = 'FILE_SET_MISMATCH' }
        }
    }
    foreach ($pin in $script:V2PinnedFiles) {
        $entry = @($manifest.files | Where-Object { $_.path -ceq $pin.path })
        if ($entry.Count -ne 1 -or $entry[0].sourceCommit -cne $pin.commit -or $entry[0].sourceTree -cne $pin.tree -or
            $entry[0].gitBlob -cne $pin.blob -or $entry[0].representation -cne $pin.representation -or
            $entry[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
            return [pscustomobject]@{
                Success = $false; ResultState = 'FAILED'; ReasonCode = 'POLICY_REJECTED'
                Details = [ordered]@{ publishState = 'MANIFEST_ENTRY_MISMATCH' }
            }
        }
        $inboundFile = Join-Path $script:V2InboundRoot $pin.path
        if (-not (Test-Path -LiteralPath $inboundFile -PathType Leaf)) {
            return [pscustomobject]@{
                Success = $false; ResultState = 'BLOCKED'; ReasonCode = 'TARGET_REFUSED'
                Details = [ordered]@{ publishState = 'INBOUND_FILE_MISSING' }
            }
        }
        Assert-V2ProtectedLeaf $inboundFile
        $hash = (Get-FileHash -LiteralPath $inboundFile -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne $entry[0].sha256) {
            return [pscustomobject]@{
                Success = $false; ResultState = 'FAILED'; ReasonCode = 'PROVENANCE_MISMATCH'
                Details = [ordered]@{ publishState = 'INBOUND_HASH_MISMATCH' }
            }
        }
        if ($pin.representation -ceq 'crlf' -and $hash -cne $script:V2DispatchWindowsSha256) {
            return [pscustomobject]@{
                Success = $false; ResultState = 'FAILED'; ReasonCode = 'PROVENANCE_MISMATCH'
                Details = [ordered]@{ publishState = 'DISPATCH_WINDOWS_HASH_MISMATCH' }
            }
        }
    }
    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $releases = Join-Path $script:V2AdjunctRoot 'releases'
    $releaseRoot = Join-Path $releases $script:V2ReleaseIdentity
    if (Test-Path -LiteralPath $releaseRoot -PathType Container) {
        $releaseManifest = Join-Path $releaseRoot 'manifest.json'
        if (Test-Path -LiteralPath $releaseManifest -PathType Leaf) {
            $existingSha = (Get-FileHash -LiteralPath $releaseManifest -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($existingSha -ceq $manifestSha) {
                return [pscustomobject]@{
                    Success = $true; ResultState = 'PASS'; ReasonCode = 'NONE'
                    Details = [ordered]@{
                        publishState = 'ALREADY_PUBLISHED'
                        manifestSha256 = $manifestSha
                        releaseIdentity = $script:V2ReleaseIdentity
                    }
                }
            }
        }
        return [pscustomobject]@{
            Success = $false; ResultState = 'AMBIGUOUS'; ReasonCode = 'TARGET_REFUSED'
            Details = [ordered]@{ publishState = 'RELEASE_COLLISION' }
        }
    }
    $null = New-Item -ItemType Directory -Path $releases -Force -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $script:V2InboundRoot -Destination $releaseRoot -Force
    return [pscustomobject]@{
        Success = $true; ResultState = 'PASS'; ReasonCode = 'NONE'
        Details = [ordered]@{
            publishState = 'PUBLISHED'
            manifestSha256 = $manifestSha
            releaseIdentity = $script:V2ReleaseIdentity
        }
    }
}

# Allowlisted proof operation
function Invoke-ElevatedIdentityProof([string]$CorrelationId) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return [pscustomobject]@{
            Success = $false
            ResultState = 'FAILED'
            ReasonCode = 'ELEVATION_REQUIRED'
            Details = [ordered]@{ identityState = 'UNELEVATED' }
        }
    }

    $hasAdminGroup = $false
    foreach ($group in $identity.Groups) {
        if ($group.Value -ceq 'S-1-5-32-544') {
            $hasAdminGroup = $true
            break
        }
    }

    if (-not $hasAdminGroup) {
        return [pscustomobject]@{
            Success = $false
            ResultState = 'FAILED'
            ReasonCode = 'ELEVATION_REQUIRED'
            Details = [ordered]@{ identityState = 'ADMIN_GROUP_MISSING' }
        }
    }

    [pscustomobject]@{
        Success = $true
        ResultState = 'PASS'
        ReasonCode = 'NONE'
        Details = [ordered]@{
            identityState = 'ELEVATED_ADMINISTRATOR'
            proofStatus = 'VERIFIED'
        }
    }
}

# Closed reviewed operation registry
$ReviewedOperationRegistry = @{
    'ELEVATED_IDENTITY_PROOF' = {
        param([string]$CorrelationId)
        Invoke-ElevatedIdentityProof -CorrelationId $CorrelationId
    }
    'DRAGONFLY_V2_PUBLISH_REVIEWED' = {
        param([string]$CorrelationId)
        Invoke-DragonflyV2PublishReviewed -CorrelationId $CorrelationId
    }
}

try {
    Assert-WorkerProvenance
    Prune-StaleResults
    Acquire-OperationLock

    $request = Read-Request
    if ($null -eq $request) {
        # Nothing queued or request was in-flight/expired/completed
        return
    }

    $script:CorrelationId = $request.CorrelationId
    $script:OperationId = $request.OperationId

    if (-not $ReviewedOperationRegistry.ContainsKey($script:OperationId)) {
        Write-Result -Success $false -State 'FAILED' -Reason 'UNKNOWN_OPERATION'
        Remove-RequestSlot
        return
    }

    # Persist protected durable in-flight record BEFORE executing action
    Write-Result -Success $true -State 'STARTED' -Reason 'NONE'

    $action = $ReviewedOperationRegistry[$script:OperationId]
    $outcome = & $action $script:CorrelationId

    Write-Result -Success $outcome.Success -State $outcome.ResultState -Reason $outcome.ReasonCode -Details $outcome.Details
    Remove-RequestSlot
} catch {
    $msg = $_.Exception.Message
    $reason = switch ($msg) {
        'WINDOWS_REQUIRED' { 'ADAPTER_UNAVAILABLE' }
        'ELEVATION_REQUIRED' { 'ELEVATION_REQUIRED' }
        'REPARSE_PATH_REFUSED' { 'PROVENANCE_MISMATCH' }
        'PROTECTED_OWNER_REFUSED' { 'PROVENANCE_MISMATCH' }
        'PROTECTED_WRITE_REFUSED' { 'PROVENANCE_MISMATCH' }
        'WORKER_PATH_REFUSED' { 'PROVENANCE_MISMATCH' }
        'PROVENANCE_MISMATCH' { 'PROVENANCE_MISMATCH' }
        'BUSY' { 'BUSY' }
        'INVALID_REQUEST' { 'INVALID_REQUEST' }
        'INVALID_ADAPTER_RESULT' { 'INVALID_ADAPTER_RESULT' }
        'UNKNOWN_OPERATION' { 'UNKNOWN_OPERATION' }
        'PRUNING_FAILED' { 'FAILED' }
        default { 'FAILED' }
    }

    if ($script:CorrelationId) {
        Write-Result -Success $false -State 'FAILED' -Reason $reason
    }
    Remove-RequestSlot
} finally {
    Release-OperationLock
}
