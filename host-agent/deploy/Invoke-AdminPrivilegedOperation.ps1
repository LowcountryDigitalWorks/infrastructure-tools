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
$expectedWorker = Join-Path $binRoot 'Invoke-AdminPrivilegedOperation.ps1'

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
