[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$acceptedSourceCommit = '9187711faffe90bcc9f6f09d936a9f0a95289ed4'
$acceptedClientBlob = '945b463b2d88ef4ac3109e59ef0abfb77b286c88'
$clientRelative = 'host-agent/deploy/Invoke-CiJitControlClient.ps1'
$auditRelative = 'LowcountryDigitalWorks/AdminBroker/audit-log.jsonl'
$maximumResultPolls = 60
$resultPollMilliseconds = 500

function Invoke-GitRead([string[]]$Arguments) {
    $value = & git @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PROOF_GIT_READ_FAILED' }
    @($value)
}

function Assert-NormalOwnerSession {
    if ($env:OS -cne 'Windows_NT') { throw 'PROOF_WINDOWS_REQUIRED' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $identity.User -or $identity.User.Value -cnotmatch '^S-1-5-21-(\d+-){3}\d+$' -or
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'PROOF_NORMAL_USER_REQUIRED'
    }
}

function Get-AcceptedCheckout {
    $repoRoot = (Invoke-GitRead @('-C',$PSScriptRoot,'rev-parse','--show-toplevel') | Select-Object -First 1).Trim()
    if (-not $repoRoot) { throw 'PROOF_SOURCE_CHECKOUT_REQUIRED' }

    $branch = (Invoke-GitRead @('-C',$repoRoot,'branch','--show-current') | Select-Object -First 1).Trim()
    if ($branch -cne 'main') { throw 'PROOF_SOURCE_MAIN_REQUIRED' }
    if (@(Invoke-GitRead @('-C',$repoRoot,'status','--porcelain')).Count -ne 0) { throw 'PROOF_SOURCE_WORKTREE_DIRTY' }

    $head = (Invoke-GitRead @('-C',$repoRoot,'rev-parse','HEAD') | Select-Object -First 1).Trim()
    $originMain = (Invoke-GitRead @('-C',$repoRoot,'rev-parse','refs/remotes/origin/main') | Select-Object -First 1).Trim()
    if ($head -cne $originMain) { throw 'PROOF_SOURCE_MAIN_NOT_CURRENT' }

    & git -C $repoRoot merge-base --is-ancestor $acceptedSourceCommit $head 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PROOF_ACCEPTED_SOURCE_ANCESTRY_REQUIRED' }

    $clientBlob = (Invoke-GitRead @('-C',$repoRoot,'rev-parse',("HEAD:$clientRelative")) | Select-Object -First 1).Trim()
    if ($clientBlob -cne $acceptedClientBlob) { throw 'PROOF_CLIENT_SOURCE_CHANGED' }

    [pscustomobject]@{
        Root = $repoRoot
        Head = $head
        ClientPath = Join-Path $repoRoot $clientRelative
    }
}

function Invoke-FixedClientOperation {
    param(
        [Parameter(Mandatory)][ValidateSet('STATUS','DISCOVER','GET_OPERATION_RESULT')][string]$Operation,
        [guid]$OperationId = [guid]::Empty
    )

    $request = New-CiJitClientRequest -RequestedOperation $Operation -RequestedRunId 0 -RequestedOperationId $OperationId
    $result = Invoke-CiJitControlPipe -Request $request
    if ($null -eq $result) { throw 'PROOF_CLIENT_RESULT_REQUIRED' }
    $result
}

function Wait-DiscoverResult([guid]$OperationId) {
    for ($attempt = 0; $attempt -lt $maximumResultPolls; $attempt++) {
        $result = Invoke-FixedClientOperation -Operation GET_OPERATION_RESULT -OperationId $OperationId
        if (-not $result['success'] -and $result['resultState'] -ceq 'BLOCKED' -and $result['errorCode'] -ceq 'OPERATION_NOT_FOUND') {
            Start-Sleep -Milliseconds $resultPollMilliseconds
            continue
        }
        return $result
    }
    throw 'PROOF_DISCOVER_RESULT_TIMEOUT'
}

function Assert-SanitizedAudit([DateTime]$SinceUtc) {
    $auditPath = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) $auditRelative
    if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) { throw 'PROOF_AUDIT_REQUIRED' }

    $records = @()
    foreach ($line in Get-Content -LiteralPath $auditPath -ErrorAction Stop) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $record = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        $timestamp = [DateTime]::MinValue
        if ($null -eq $record.timestampUtc -or
            -not [DateTime]::TryParse([string]$record.timestampUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$timestamp) -or
            $timestamp.ToUniversalTime() -lt $SinceUtc) { continue }
        if ($record.targetIdentity -cne 'redacted' -or $record.summary -cne 'Operation audit record.') {
            throw 'PROOF_AUDIT_SANITIZATION_REFUSED'
        }
        $records += $record
    }

    foreach ($operation in @('CI_JIT_STATUS','CI_JIT_DISCOVER','CI_JIT_GET_OPERATION_RESULT')) {
        if (-not @($records | Where-Object { $_.operation -ceq $operation }).Count) {
            throw 'PROOF_AUDIT_OPERATION_REQUIRED'
        }
    }
    'BROKER_AUDIT=PASS'
}

Assert-NormalOwnerSession
$checkout = Get-AcceptedCheckout
. $checkout.ClientPath
Assert-CiJitClientNormalUser
$proofStartedUtc = [DateTime]::UtcNow.AddSeconds(-2)

$status = Invoke-FixedClientOperation -Operation STATUS
if (-not $status['success'] -or $status['resultState'] -cne 'PASS') { throw 'PROOF_STATUS_FAILED' }

$discover = Invoke-FixedClientOperation -Operation DISCOVER
if (-not $discover['success'] -or $discover['resultState'] -cne 'QUEUED' -or
    -not $discover['details'].Contains('operationId')) { throw 'PROOF_DISCOVER_QUEUE_FAILED' }
$discoverOperationId = [guid]::ParseExact([string]$discover['details']['operationId'],'D')
$discoverResult = Wait-DiscoverResult -OperationId $discoverOperationId

if ($discoverResult['resultState'] -ceq 'FAILED' -or
    $discoverResult['errorCode'] -cin @('ADAPTER_UNAVAILABLE','INVALID_ADAPTER_RESULT','FAILED')) {
    throw 'PROOF_DISCOVER_TERMINAL_FAILED'
}

Assert-SanitizedAudit -SinceUtc $proofStartedUtc
'CI_JIT_PHASE2_OBSERVE_PROOF=PASS'
'SOURCE_HEAD=' + $checkout.Head
'OWNER_SID=LOCAL_DERIVED'
'STATUS_STATE=' + [string]$status['resultState']
'DISCOVER_STATE=' + [string]$discoverResult['resultState']
if ($discoverResult['errorCode']) { 'DISCOVER_REASON=' + [string]$discoverResult['errorCode'] }
if ($discoverResult['details'].Contains('profileId')) { 'DISCOVER_PROFILE=' + [string]$discoverResult['details']['profileId'] }
if ($discoverResult['details'].Contains('runId')) { 'DISCOVER_RUN_ID=' + [string]$discoverResult['details']['runId'] }
if ($discoverResult['details'].Contains('jobId')) { 'DISCOVER_JOB_ID=' + [string]$discoverResult['details']['jobId'] }
