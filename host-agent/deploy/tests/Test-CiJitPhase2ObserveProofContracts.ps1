Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$proof = Join-Path $PSScriptRoot '../Invoke-CiJitPhase2ObserveProof.ps1'
$source = Get-Content -LiteralPath $proof -Raw
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($proof,[ref]$tokens,[ref]$errors)
if (@($errors).Count) { throw ('PHASE2_OBSERVE_PARSE_FAILED: ' + ($errors[0].Message)) }

foreach ($required in @(
    '$acceptedSourceCommit = ''024e7c0af1adc9c3cdfbb50a2710e2f0fd9446ef''',
    '$acceptedClientBlob = ''a68acd712bd33c424f3a58a7130b439e46c9455e''',
    '$clientRelative = ''host-agent/deploy/Invoke-CiJitLocalTaskClient.ps1''',
    "ValidateSet('STATUS','DISCOVER','GET_OPERATION_RESULT')",
    'Invoke-CiJitLocalTaskClient',
    'LOCAL_TASK_TRANSPORT=PASS',
    'CI_JIT_PHASE2_OBSERVE_PROOF=PASS',
    'PROOF_SOURCE_MAIN_REQUIRED',
    'PROOF_SOURCE_WORKTREE_DIRTY',
    'PROOF_SOURCE_MAIN_NOT_CURRENT',
    'PROOF_CLIENT_SOURCE_CHANGED',
    '$maximumResultPolls = 60',
    '$resultPollMilliseconds = 500'
)) {
    if (-not $source.Contains($required)) { throw "PHASE2_OBSERVE_REQUIRED_CONTRACT_MISSING: $required" }
}

foreach ($forbidden in @(
    'RUN_ONCE',
    'RECOVER',
    'ABORT_ACTIVE',
    'LIST_STALE',
    'RETIRE_STALE',
    'LDW.AdminBroker',
    'NamedPipe',
    'audit-log.jsonl',
    'Publish-AdminBrokerProofPackage',
    'schtasks.exe',
    'Start-Process',
    'ProcessStartInfo',
    'Invoke-WebRequest',
    'Invoke-RestMethod',
    'HttpClient',
    'TcpClient'
)) {
    if ($source -match [regex]::Escape($forbidden)) { throw "PHASE2_OBSERVE_FORBIDDEN_PRIMITIVE: $forbidden" }
}

$paramBlock=$ast.ParamBlock
if ($null -eq $paramBlock -or @($paramBlock.Parameters).Count -ne 0) {
    throw 'PHASE2_OBSERVE_MUST_ACCEPT_NO_PARAMETERS'
}

'CI_JIT_PHASE2_OBSERVE_PROOF_CONTRACT=PASS'
