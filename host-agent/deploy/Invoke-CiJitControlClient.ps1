[CmdletBinding()]
param(
    [ValidateSet('STATUS','DISCOVER','RUN_ONCE','RECOVER','ABORT_ACTIVE','LIST_STALE','RETIRE_STALE','GET_OPERATION_RESULT')]
    [string]$Operation,
    [long]$RunId,
    [guid]$OperationId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PipeName = 'LDW.AdminBroker.v1'
$script:TargetIdentity = 'local-ci-jit'
$script:MaximumRequestCharacters = 16384
$script:MaximumResponseCharacters = 32768
$script:TimeoutMilliseconds = 5000
$script:DetailKeys = @(
    'reasonCode','operationId','profileId','runId','jobId','staleItems',
    'observedAtUtc','sourceVersion','ownerState','statusReasonCode','localStateFresh',
    'queueState','eligibleQueuedCount','heldQueuedCount','selectedProfile','selectedRunId',
    'selectedJobId','controllerPhase','capacity'
)

function Assert-CiJitClientNormalUser {
    if ($env:OS -cne 'Windows_NT') { throw 'CLIENT_WINDOWS_REQUIRED' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $identity.User -or $identity.User.Value -cnotmatch '^S-1-5-21-(\d+-){3}\d+$' -or
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'CLIENT_NORMAL_USER_REQUIRED'
    }
}

function New-CiJitClientRequest {
    param(
        [Parameter(Mandatory)][string]$RequestedOperation,
        [long]$RequestedRunId,
        [guid]$RequestedOperationId
    )

    $operationToken = switch ($RequestedOperation) {
        'STATUS' { 'CI_JIT_STATUS' }
        'DISCOVER' { 'CI_JIT_DISCOVER' }
        'RUN_ONCE' { 'CI_JIT_RUN_ONCE' }
        'RECOVER' { 'CI_JIT_RECOVER' }
        'ABORT_ACTIVE' { 'CI_JIT_ABORT_ACTIVE' }
        'LIST_STALE' { 'CI_JIT_LIST_STALE' }
        'RETIRE_STALE' { 'CI_JIT_RETIRE_STALE' }
        'GET_OPERATION_RESULT' { 'CI_JIT_GET_OPERATION_RESULT' }
        default { throw 'CLIENT_OPERATION_REFUSED' }
    }

    $parameters = [ordered]@{}
    if ($RequestedOperation -ceq 'RETIRE_STALE') {
        if ($RequestedRunId -le 0 -or $RequestedOperationId -ne [guid]::Empty) { throw 'CLIENT_ARGUMENT_REFUSED' }
        $parameters.runId = $RequestedRunId
    } elseif ($RequestedOperation -ceq 'GET_OPERATION_RESULT') {
        if ($RequestedOperationId -eq [guid]::Empty -or $RequestedRunId -ne 0) { throw 'CLIENT_ARGUMENT_REFUSED' }
        $parameters.operationId = $RequestedOperationId.ToString('D')
    } elseif ($RequestedRunId -ne 0 -or $RequestedOperationId -ne [guid]::Empty) {
        throw 'CLIENT_ARGUMENT_REFUSED'
    }

    $requestId = [guid]::NewGuid().ToString('D')
    $payload = [ordered]@{
        version = 1
        requestId = $requestId
        operation = $operationToken
        targetIdentity = $script:TargetIdentity
        parameters = $parameters
    }
    $json = $payload | ConvertTo-Json -Compress -Depth 4
    if ([string]::IsNullOrWhiteSpace($json) -or $json.Length -gt $script:MaximumRequestCharacters -or $json.Contains("`r") -or $json.Contains("`n")) {
        throw 'CLIENT_REQUEST_REFUSED'
    }
    [pscustomobject]@{ RequestId=$requestId; Operation=$operationToken; Json=$json }
}

function ConvertFrom-CiJitClientResponse {
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$ExpectedRequestId,
        [Parameter(Mandatory)][string]$ExpectedOperation
    )

    if ([string]::IsNullOrWhiteSpace($Json) -or $Json.Length -gt $script:MaximumResponseCharacters -or $Json.Contains("`r") -or $Json.Contains("`n")) {
        throw 'CLIENT_RESPONSE_REFUSED'
    }

    $document = $null
    try {
        try { $document = [Text.Json.JsonDocument]::Parse($Json) }
        catch { throw 'CLIENT_RESPONSE_REFUSED' }
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'CLIENT_RESPONSE_REFUSED' }
        $allowed = @('version','requestId','operation','success','targetIdentity','resultState','summary','errorCode','timestampUtc','details')
        $names = @($root.EnumerateObject() | ForEach-Object Name)
        if (@($names | Group-Object | Where-Object Count -ne 1).Count -or @($names | Where-Object { $_ -cnotin $allowed }).Count) {
            throw 'CLIENT_RESPONSE_REFUSED'
        }
        foreach ($required in @('version','requestId','operation','success','targetIdentity','resultState','summary','timestampUtc')) {
            if ($required -cnotin $names) { throw 'CLIENT_RESPONSE_REFUSED' }
        }

        try {
            $version = $root.GetProperty('version').GetInt32()
            $requestId = $root.GetProperty('requestId').GetString()
            $operation = $root.GetProperty('operation').GetString()
            $target = $root.GetProperty('targetIdentity').GetString()
            $summary = $root.GetProperty('summary').GetString()
            $timestamp = $root.GetProperty('timestampUtc').GetString()
        } catch { throw 'CLIENT_RESPONSE_REFUSED' }
        if ($version -ne 1 -or $requestId -cne $ExpectedRequestId -or $operation -cne $ExpectedOperation -or $target -cne $script:TargetIdentity) {
            throw 'CLIENT_RESPONSE_CORRELATION_REFUSED'
        }
        if ($null -eq $summary -or $summary.Length -gt 256 -or $summary.Contains("`r") -or $summary.Contains("`n") -or
            -not [DateTime]::TryParse($timestamp,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]([DateTime]$parsedTimestamp))) {
            throw 'CLIENT_RESPONSE_REFUSED'
        }

        $successElement = $root.GetProperty('success')
        if ($successElement.ValueKind -notin @([Text.Json.JsonValueKind]::True,[Text.Json.JsonValueKind]::False)) { throw 'CLIENT_RESPONSE_REFUSED' }
        $success = $successElement.GetBoolean()
        try { $resultState = $root.GetProperty('resultState').GetString() } catch { throw 'CLIENT_RESPONSE_REFUSED' }
        if ($resultState -cnotin @('QUEUED','STARTED','PASS','BLOCKED','FAILED','STALE','AMBIGUOUS')) { throw 'CLIENT_RESPONSE_REFUSED' }
        if (($success -and $resultState -in @('BLOCKED','FAILED','AMBIGUOUS')) -or
            (-not $success -and $resultState -in @('QUEUED','STARTED','PASS'))) { throw 'CLIENT_RESPONSE_REFUSED' }

        $details = [ordered]@{}
        $detailsElement = [Text.Json.JsonElement]::new()
        if ($root.TryGetProperty('details',[ref]$detailsElement) -and $detailsElement.ValueKind -ne [Text.Json.JsonValueKind]::Null) {
            if ($detailsElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'CLIENT_RESPONSE_REFUSED' }
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $detailsElement.EnumerateObject()) {
                if (-not $seen.Add($property.Name) -or $property.Name -cnotin $script:DetailKeys -or
                    $property.Value.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw 'CLIENT_RESPONSE_REFUSED' }
                $value = $property.Value.GetString()
                if ($null -eq $value -or $value.Length -gt 1024 -or $value.Contains("`r") -or $value.Contains("`n") -or
                    $value -match '(?i)(token|secret|password|authorization|bearer|connection[ _-]?string|[A-Z]:\\|/home/|/Users/)') {
                    throw 'CLIENT_RESPONSE_REFUSED'
                }
                $details[$property.Name] = $value
            }
        }

        $errorCode = $null
        $errorElement = [Text.Json.JsonElement]::new()
        if ($root.TryGetProperty('errorCode',[ref]$errorElement) -and $errorElement.ValueKind -ne [Text.Json.JsonValueKind]::Null) {
            if ($errorElement.ValueKind -ne [Text.Json.JsonValueKind]::String) { throw 'CLIENT_RESPONSE_REFUSED' }
            $errorCode = $errorElement.GetString()
            if ($errorCode -and $errorCode -cnotmatch '^[A-Z][A-Z0-9_]{0,63}$') { throw 'CLIENT_RESPONSE_REFUSED' }
        }

        [ordered]@{
            success = $success
            resultState = $resultState
            errorCode = $errorCode
            details = $details
        }
    } finally {
        if ($null -ne $document) { $document.Dispose() }
    }
}

function Invoke-CiJitControlPipe {
    param([Parameter(Mandatory)][pscustomobject]$Request)

    $client = [IO.Pipes.NamedPipeClientStream]::new(
        '.', $script:PipeName, [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Impersonation)
    try {
        try { $client.Connect($script:TimeoutMilliseconds) }
        catch [TimeoutException] { throw 'CLIENT_BROKER_UNAVAILABLE' }
        if (-not $client.IsConnected) { throw 'CLIENT_BROKER_UNAVAILABLE' }

        $encoding = [Text.UTF8Encoding]::new($false)
        $writer = [IO.StreamWriter]::new($client,$encoding,4096,$true)
        $reader = [IO.StreamReader]::new($client,$encoding,$false,4096,$true)
        try {
            $writer.NewLine = "`n"
            $writer.WriteLine($Request.Json)
            $writer.Flush()
            $task = $reader.ReadLineAsync()
            if (-not $task.Wait($script:TimeoutMilliseconds)) { throw 'CLIENT_RESPONSE_TIMEOUT' }
            $response = $task.GetAwaiter().GetResult()
            if ($null -eq $response) { throw 'CLIENT_RESPONSE_REFUSED' }
            ConvertFrom-CiJitClientResponse -Json $response -ExpectedRequestId $Request.RequestId -ExpectedOperation $Request.Operation
        } finally {
            $reader.Dispose()
            $writer.Dispose()
        }
    } finally { $client.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($Operation)) { throw 'CLIENT_OPERATION_REQUIRED' }
    Assert-CiJitClientNormalUser
    $request = New-CiJitClientRequest -RequestedOperation $Operation -RequestedRunId $RunId -RequestedOperationId $OperationId
    $result = Invoke-CiJitControlPipe -Request $request
    'CI_JIT_CLIENT_RESULT=' + ($result | ConvertTo-Json -Compress -Depth 4)
}
