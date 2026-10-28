[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$source = Get-Content -LiteralPath (Join-Path $deployRoot 'Invoke-CiJitPhase2ObserveProof.ps1') -Raw
$script:Assertions = 0

function Assert-True([bool]$Condition,[string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

foreach ($required in @(
    '[CmdletBinding()]',
    'param()',
    '9187711faffe90bcc9f6f09d936a9f0a95289ed4',
    '945b463b2d88ef4ac3109e59ef0abfb77b286c88',
    "branch','--show-current",
    "status','--porcelain",
    'refs/remotes/origin/main',
    'merge-base --is-ancestor',
    'PROOF_CLIENT_SOURCE_CHANGED',
    'PROOF_NORMAL_USER_REQUIRED',
    '. $checkout.ClientPath',
    "ValidateSet('STATUS','DISCOVER','GET_OPERATION_RESULT')",
    'Invoke-FixedClientOperation -Operation STATUS',
    'Invoke-FixedClientOperation -Operation DISCOVER',
    'Invoke-FixedClientOperation -Operation GET_OPERATION_RESULT',
    'OPERATION_NOT_FOUND',
    'PROOF_DISCOVER_RESULT_TIMEOUT',
    'LowcountryDigitalWorks/AdminBroker/audit-log.jsonl',
    "targetIdentity -cne 'redacted'",
    "summary -cne 'Operation audit record.'",
    "@('CI_JIT_STATUS','CI_JIT_DISCOVER','CI_JIT_GET_OPERATION_RESULT')",
    'CI_JIT_PHASE2_OBSERVE_PROOF=PASS',
    'OWNER_SID=LOCAL_DERIVED'
)) {
    Assert-True ($source.Contains($required,[StringComparison]::Ordinal)) "observe proof must preserve fixed contract: $required"
}

foreach ($forbidden in @(
    'RUN_ONCE','RECOVER','ABORT_ACTIVE','LIST_STALE','RETIRE_STALE',
    'Register-ScheduledTask','New-ScheduledTask','Start-ScheduledTask','schtasks.exe',
    'Start-Process','Diagnostics.Process','ProcessStartInfo','Kill(',
    'Invoke-WebRequest','Invoke-RestMethod','Start-BitsTransfer','curl.exe','wget.exe','gh api','gh run',
    'Set-Content','Add-Content','Out-File','Remove-Item','Copy-Item','Move-Item',
    'Set-Service','New-Service','Set-ItemProperty','New-NetFirewall','Set-NetFirewall',
    'cmd.exe','powershell.exe','pwsh.exe'
)) {
    Assert-True (-not $source.Contains($forbidden,[StringComparison]::OrdinalIgnoreCase)) "observe proof must exclude mutation/network/process primitive: $forbidden"
}

Assert-True ($source.StartsWith("[CmdletBinding()]`nparam()`n",[StringComparison]::Ordinal)) 'observe proof top-level contract must expose no caller parameters'
Assert-True ($source.Contains('$maximumResultPolls = 60',[StringComparison]::Ordinal)) 'observe proof must keep result polling bounded'
Assert-True ($source.Contains('$resultPollMilliseconds = 500',[StringComparison]::Ordinal)) 'observe proof must keep fixed polling interval'

Write-Host "CI/JIT Phase-2 observe proof contract assertions PASS: $script:Assertions"
