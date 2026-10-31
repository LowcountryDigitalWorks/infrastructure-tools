Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$client = Join-Path $PSScriptRoot '../Invoke-CiJitLocalTaskClient.ps1'
$source = Get-Content -LiteralPath $client -Raw
$tokens=$null; $errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($client,[ref]$tokens,[ref]$errors)
if (@($errors).Count) { throw ('LOCAL_CLIENT_PARSE_FAILED: ' + ($errors[0].Message)) }

foreach ($required in @(
    "ValidateSet('STATUS','DISCOVER','RUN_ONCE','RECOVER','ABORT_ACTIVE','LIST_STALE','RETIRE_STALE','GET_OPERATION_RESULT')",
    '[long]$RunId = 0',
    '[guid]$OperationId = [guid]::Empty',
    '[long]$RequestedRunId = 0',
    '[guid]$RequestedOperationId = [guid]::Empty',
    "Join-Path `$env:ProgramData 'LDW/CiJitControl'",
    "Join-Path `$env:ProgramData 'LDW/CiJitStatus/status.json'",
    "DISCOVER='\LDW-CI-JIT-DISCOVER'",
    "RUN_ONCE='\LDW-CI-JIT-RUN-ONCE'",
    "RETIRE_STALE='\LDW-CI-JIT-RETIRE-STALE'",
    "System32/schtasks.exe",
    "ArgumentList.Add('/Run')",
    "ArgumentList.Add('/TN')",
    "[IO.FileMode]::CreateNew",
    "[IO.File]::Move(`$temp,`$slot,`$false)",
    "LOCAL_CLIENT_NORMAL_USER_REQUIRED",
    "LOCAL_CLIENT_REPARSE_REFUSED",
    "LOCAL_CLIENT_ARGUMENT_REFUSED"
)) {
    if (-not $source.Contains($required)) { throw "LOCAL_CLIENT_REQUIRED_CONTRACT_MISSING: $required" }
}

foreach ($forbidden in @(
    'Invoke-Expression',
    'cmd.exe',
    'powershell.exe',
    'Start-Process',
    'Invoke-WebRequest',
    'Invoke-RestMethod',
    'HttpClient',
    'TcpClient',
    'WebSocket',
    'DownloadString',
    'ProcessName',
    'ExecutablePath',
    'CommandLine'
)) {
    if ($source -match [regex]::Escape($forbidden)) { throw "LOCAL_CLIENT_FORBIDDEN_PRIMITIVE: $forbidden" }
}

. $client

$now=[DateTimeOffset]::Parse('2026-10-31T04:00:00Z')
$boot=$now.AddHours(-8)
$projection=[ordered]@{
    schema=1
    source_version='ci-jit-v1'
    boot_started_utc=$boot.ToString('O')
    local_observed_at_utc=$now.AddSeconds(-10).ToString('O')
    provenance_valid=$true
    proven_failure=$false
    controller_phase=$null
    capacity='Ready'
    reason_code=$null
    queue_observed_at_utc=$now.AddSeconds(-5).ToString('O')
    queue_state='Fresh'
    eligible_queued_count=1
    held_queued_count=0
    selected_profile='private-ci'
    selected_run_id=123
    selected_job_id=456
}
$json=$projection | ConvertTo-Json -Compress
$result=ConvertFrom-CiJitStatusProjection $json $now $boot
if (-not $result.success -or $result.resultState -cne 'PASS' -or
    $result.details.ownerState -cne 'QUEUED' -or $result.details.queueState -cne 'FRESH' -or
    $result.details.capacity -cne 'READY' -or $result.details.selectedRunId -cne '123' -or
    $result.details.selectedJobId -cne '456') {
    throw 'LOCAL_CLIENT_STATUS_PARITY_FAILED'
}

$projection.queue_observed_at_utc=$now.AddMinutes(-3).ToString('O')
$stale=ConvertFrom-CiJitStatusProjection ($projection | ConvertTo-Json -Compress) $now $boot
if ($stale.details.ownerState -cne 'UNKNOWN' -or $stale.details.queueState -cne 'STALE' -or
    $stale.details.statusReasonCode -cne 'QUEUE_STALE' -or $stale.details.Contains('selectedRunId')) {
    throw 'LOCAL_CLIENT_STATUS_STALE_FAILED'
}

$projection.queue_observed_at_utc=$now.AddSeconds(-5).ToString('O')
$projection.extra='refuse'
$threw=$false
try { $null=ConvertFrom-CiJitStatusProjection ($projection | ConvertTo-Json -Compress) $now $boot } catch { $threw=$true }
if (-not $threw) { throw 'LOCAL_CLIENT_STATUS_EXTRA_FIELD_NOT_REFUSED' }

function Invoke-LocalClientCli([string[]]$Arguments) {
    $exe = (Get-Command pwsh -ErrorAction Stop).Source
    $psi = [Diagnostics.ProcessStartInfo]::new($exe, (@('-NoLogo','-NoProfile','-NonInteractive','-File',$client) + $Arguments))
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Out = $stdout; Err = $stderr; Combined = ($stdout + $stderr) }
}

foreach ($case in @(
    @{ Name = 'STATUS'; Args = @('-Operation','STATUS'); Forbidden = 'Cannot convert null to type "System.Guid"'; ExpectRefusal = $false },
    @{ Name = 'GET_OPERATION_RESULT'; Args = @('-Operation','GET_OPERATION_RESULT'); Forbidden = 'Cannot convert null to type "System.Guid"'; ExpectRefusal = $true }
)) {
    $cli = Invoke-LocalClientCli $case.Args
    if ($cli.Combined -match [regex]::Escape($case.Forbidden)) { throw ('LOCAL_CLIENT_CLI_DEFAULT_BINDING_FAILED: ' + $case.Name) }
    if ($case['ExpectRefusal'] -eq $true -and $cli.Combined -notmatch 'LOCAL_CLIENT_ARGUMENT_REFUSED') { throw ('LOCAL_CLIENT_CLI_ARGUMENT_REFUSAL_EXPECTED: ' + $case.Name) }
}

'CI_JIT_LOCAL_TASK_CLIENT_CONTRACT=PASS'
