[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$clientPath = Join-Path $deployRoot 'Invoke-CiJitControlClient.ps1'

$script:Assertions = 0
function Assert-True([bool]$Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function Assert-ThrowsExact([scriptblock]$Action, [string]$ExpectedMessage, [string]$Message) {
    $script:Assertions++
    try {
        & $Action
        throw "ASSERTION FAILED: $Message"
    }
    catch {
        if ($_.Exception.Message.StartsWith('ASSERTION FAILED:', [StringComparison]::Ordinal)) { throw }
        if ($_.Exception.Message -cne $ExpectedMessage) {
            throw "ASSERTION FAILED: $Message (expected '$ExpectedMessage', got '$($_.Exception.Message)')"
        }
    }
}

. $clientPath

Assert-True ($OperationId -eq [guid]::Empty) 'omitted script OperationId must bind to Guid.Empty rather than null'

$statusRequest = New-CiJitClientRequest -RequestedOperation 'STATUS' -RequestedRunId $RunId -RequestedOperationId $OperationId
Assert-True ($statusRequest.Operation -ceq 'CI_JIT_STATUS') 'STATUS request must preserve the closed operation token'
$statusPayload = $statusRequest.Json | ConvertFrom-Json
Assert-True ($statusPayload.version -eq 1) 'STATUS request must preserve schema version 1'
Assert-True ($statusPayload.targetIdentity -ceq 'local-ci-jit') 'STATUS request must preserve the fixed target identity'
Assert-True (@($statusPayload.parameters.PSObject.Properties).Count -eq 0) 'STATUS request must serialize no caller parameters'

$discoverRequest = New-CiJitClientRequest -RequestedOperation 'DISCOVER'
$discoverPayload = $discoverRequest.Json | ConvertFrom-Json
Assert-True ($discoverRequest.Operation -ceq 'CI_JIT_DISCOVER') 'DISCOVER request must construct without an operation ID'
Assert-True (@($discoverPayload.parameters.PSObject.Properties).Count -eq 0) 'DISCOVER request must serialize no caller parameters'

$operationId = [guid]'11111111-1111-1111-1111-111111111111'
$resultRequest = New-CiJitClientRequest -RequestedOperation 'GET_OPERATION_RESULT' -RequestedOperationId $operationId
$resultPayload = $resultRequest.Json | ConvertFrom-Json
Assert-True ($resultRequest.Operation -ceq 'CI_JIT_GET_OPERATION_RESULT') 'GET_OPERATION_RESULT must preserve the closed operation token'
Assert-True ($resultPayload.parameters.operationId -ceq $operationId.ToString('D')) 'GET_OPERATION_RESULT must serialize the exact D-format operation ID'

Assert-ThrowsExact {
    New-CiJitClientRequest -RequestedOperation 'STATUS' -RequestedOperationId $operationId | Out-Null
} 'CLIENT_ARGUMENT_REFUSED' 'STATUS must still reject a caller-supplied operation ID'

Assert-ThrowsExact {
    New-CiJitClientRequest -RequestedOperation 'GET_OPERATION_RESULT' | Out-Null
} 'CLIENT_ARGUMENT_REFUSED' 'GET_OPERATION_RESULT must still require a non-empty operation ID'

Assert-ThrowsExact {
    New-CiJitClientRequest -RequestedOperation 'RETIRE_STALE' -RequestedRunId 0 | Out-Null
} 'CLIENT_ARGUMENT_REFUSED' 'RETIRE_STALE must still require a positive run ID'

Write-Host "CI/JIT control client contract tests passed: $script:Assertions assertions."
