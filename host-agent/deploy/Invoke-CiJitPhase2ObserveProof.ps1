[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$acceptedSourceCommit = '024e7c0af1adc9c3cdfbb50a2710e2f0fd9446ef'
$acceptedClientBlob = '1ac08213a486b020e022af4e203cc175641ecbed'
$clientRelative = 'host-agent/deploy/Invoke-CiJitLocalTaskClient.ps1'
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
    $result = Invoke-CiJitLocalTaskClient -RequestedOperation $Operation -RequestedRunId 0 -RequestedOperationId $OperationId
    if ($null -eq $result) { throw 'PROOF_CLIENT_RESULT_REQUIRED' }
    $result
}

function Wait-DiscoverResult([guid]$OperationId) {
    for ($attempt = 0; $attempt -lt $maximumResultPolls; $attempt++) {
        $result = Invoke-FixedClientOperation -Operation GET_OPERATION_RESULT -OperationId $OperationId
        if (-not $result['success'] -and $result['resultState'] -ceq 'BLOCKED' -and
            $result['details'].Contains('reasonCode') -and $result['details']['reasonCode'] -ceq 'OPERATION_NOT_FOUND') {
            Start-Sleep -Milliseconds $resultPollMilliseconds
            continue
        }
        return $result
    }
    throw 'PROOF_DISCOVER_RESULT_TIMEOUT'
}

Assert-NormalOwnerSession
$checkout = Get-AcceptedCheckout
. $checkout.ClientPath
Assert-CiJitLocalTaskClientNormalUser

$status = Invoke-FixedClientOperation -Operation STATUS
if (-not $status['success'] -or $status['resultState'] -cne 'PASS' -or
    -not $status['details'].Contains('ownerState') -or -not $status['details'].Contains('queueState') -or
    -not $status['details'].Contains('capacity')) { throw 'PROOF_STATUS_FAILED' }

$discover = Invoke-FixedClientOperation -Operation DISCOVER
if (-not $discover['success'] -or $discover['resultState'] -cne 'QUEUED' -or
    -not $discover['details'].Contains('operationId')) { throw 'PROOF_DISCOVER_QUEUE_FAILED' }
$discoverOperationId = [guid]::ParseExact([string]$discover['details']['operationId'],'D')
$discoverResult = Wait-DiscoverResult -OperationId $discoverOperationId

$terminalReason = if ($discoverResult['details'].Contains('reasonCode')) { [string]$discoverResult['details']['reasonCode'] } else { $null }
if ($discoverResult['resultState'] -ceq 'FAILED' -or
    $terminalReason -cin @('ADAPTER_UNAVAILABLE','INVALID_ADAPTER_RESULT','FAILED')) {
    throw 'PROOF_DISCOVER_TERMINAL_FAILED'
}

'LOCAL_TASK_TRANSPORT=PASS'
'CI_JIT_PHASE2_OBSERVE_PROOF=PASS'
'SOURCE_HEAD=' + $checkout.Head
'OWNER_SID=LOCAL_DERIVED'
'STATUS_STATE=' + [string]$status['resultState']
'STATUS_OWNER_STATE=' + [string]$status['details']['ownerState']
'STATUS_QUEUE_STATE=' + [string]$status['details']['queueState']
'STATUS_CAPACITY=' + [string]$status['details']['capacity']
'DISCOVER_STATE=' + [string]$discoverResult['resultState']
if ($terminalReason) { 'DISCOVER_REASON=' + $terminalReason }
if ($discoverResult['details'].Contains('profileId')) { 'DISCOVER_PROFILE=' + [string]$discoverResult['details']['profileId'] }
if ($discoverResult['details'].Contains('runId')) { 'DISCOVER_RUN_ID=' + [string]$discoverResult['details']['runId'] }
if ($discoverResult['details'].Contains('jobId')) { 'DISCOVER_JOB_ID=' + [string]$discoverResult['details']['jobId'] }
