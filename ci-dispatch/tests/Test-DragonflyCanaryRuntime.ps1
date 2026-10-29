$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$dispatchRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $dispatchRoot 'DragonflyCanaryRuntime.psm1') -Force

function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-ThrowsMessage { param([scriptblock]$Action,[string]$Expected,[string]$Message) $ok=$false; try { & $Action } catch { $ok = $_.Exception.Message -ceq $Expected }; Assert-True $ok $Message }

$runId = 123456789
$jobId = 987654321
$head = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$labels = @('self-hosted','Linux','X64','dragonfly','jit','ldw-ephemeral','synthetic-only',('dragonfly-run-' + $runId))
$run = [pscustomobject]@{
    id=$runId; run_attempt=1; head_sha=$head; path='.github/workflows/dragonfly-jit-canary.yml'; event='workflow_dispatch'; status='queued'; conclusion=$null
    repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'}
    head_repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'}
}
$job = [pscustomobject]@{id=$jobId;run_id=$runId;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=$labels}
$runnerName = 'redrix-' + $runId + '-' + $jobId
$runnerId = 42
$settings = [ordered]@{agentName=$runnerName;agentId=$runnerId;gitHubUrl='https://github.com/LowcountryDigitalWorks/infrastructure-tools';ephemeral=$true;disableUpdate=$true} | ConvertTo-Json -Compress
$files = [ordered]@{'.runner'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($settings))} | ConvertTo-Json -Compress
$runnerLabels = @($labels | ForEach-Object { [pscustomobject]@{name=$_} })
$jit = [pscustomobject]@{runner=[pscustomobject]@{id=$runnerId;name=$runnerName;labels=$runnerLabels};encoded_jit_config=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($files))}

# Sanitized Tailscale discovery: exactly one named online REDRIX peer and one 100.64/10 IPv4.
$status = [pscustomobject]@{
    BackendState='Running'; Self=[pscustomobject]@{Online=$true}
    Peer=[pscustomobject]@{
        one=[pscustomobject]@{HostName='penguin';DNSName='penguin.example.ts.net.';Online=$true;TailscaleIPs=@('100.100.100.100')}
        two=[pscustomobject]@{HostName='other';DNSName='other.example.ts.net.';Online=$true;TailscaleIPs=@('100.101.101.101')}
    }
}
$endpoint = Get-LdwDragonflyCanaryPrivateEndpoint -StatusProvider { $status }
Assert-True ($endpoint -ceq '100.100.100.100') 'PRIVATE_ENDPOINT_SELECTION_INVALID'
$ambiguous = [pscustomobject]@{BackendState='Running';Self=[pscustomobject]@{Online=$true};Peer=[pscustomobject]@{
    one=[pscustomobject]@{HostName='penguin';DNSName='';Online=$true;TailscaleIPs=@('100.100.100.100')}
    two=[pscustomobject]@{HostName='redrix';DNSName='';Online=$true;TailscaleIPs=@('100.101.101.101')}
}}
Assert-ThrowsMessage { Get-LdwDragonflyCanaryPrivateEndpoint -StatusProvider { $ambiguous } | Out-Null } 'DRAGONFLY_CANARY_TAILSCALE_PEER_NOT_UNIQUE' 'AMBIGUOUS_PEER_NOT_REFUSED'

# SSH plan is fixed, strict, and capsule-independent.
$plan = New-LdwDragonflyCanarySshPlan -PrivateEndpoint $endpoint -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows'
$joined = @($plan.Arguments) -join "`n"
foreach ($required in @('BatchMode=yes','StrictHostKeyChecking=yes','IdentitiesOnly=yes','IdentityAgent=none','ForwardAgent=no','ClearAllForwardings=yes','PermitLocalCommand=no','RequestTTY=no')) {
    Assert-True ($joined.Contains($required)) ('SSH_PLAN_REQUIRED_MISSING:' + $required)
}
Assert-True ($plan.CapsuleOnStdin -eq $true) 'CAPSULE_NOT_STDIN_ONLY'
Assert-True (-not $joined.Contains('opaque_bootstrap')) 'BOOTSTRAP_FIELD_IN_SSH_ARGV'
Assert-True ($plan.Arguments[-1] -ceq '/nonexistent/ldw-dragonfly-jit-handoff-v1') 'SSH_SENTINEL_INVALID'

# Transport accepts only correlated sanitized canary execution success.
$capsule = [ordered]@{dispatch_id='11111111-1111-4111-8111-111111111111';job_id=$jobId;opaque_bootstrap='DO-NOT-PRINT'} | ConvertTo-Json -Compress
$processOk = {
    param($Plan,$CapsuleJson,$TimeoutSeconds)
    $value = $CapsuleJson | ConvertFrom-Json
    [pscustomobject]@{ExitCode=0;Stderr='';Stdout=([ordered]@{
        marker='CI-RUNNER-DRAGONFLY-JIT-001';profile_id='dragonfly-github-canary-v1';dispatch_id=$value.dispatch_id;job_id=$value.job_id;claimed=$true
        execution=[ordered]@{guest_qemu_exit='PASS';guest_cleanup='PASS';state='STOPPED';job_id=$value.job_id;dispatch_id=$value.dispatch_id}
    } | ConvertTo-Json -Depth 6 -Compress)}
}
$transport = Invoke-LdwDragonflyCanaryTransport -CapsuleJson $capsule -Plan $plan -ProcessInvoker $processOk
Assert-True ($transport.GuestCleanup -ceq 'PASS' -and $transport.State -ceq 'STOPPED') 'TRANSPORT_SUCCESS_NOT_ACCEPTED'
Assert-ThrowsMessage { Invoke-LdwDragonflyCanaryTransport -CapsuleJson $capsule -Plan $plan -ProcessInvoker { [pscustomobject]@{ExitCode=1;Stdout='';Stderr='secret-like-text'} } | Out-Null } 'DRAGONFLY_CANARY_TRANSPORT_FAILED' 'TRANSPORT_FAILURE_NOT_SANITIZED'

# Full once path: registration -> stdin transport -> exact provider terminal -> runner cleanup.
$script:Inventory = @()
$script:DeleteCalls = 0
$script:PostCalls = 0
$api = {
    param($Path,$Method,$Body)
    if ($Method -ceq 'GET' -and $Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners?per_page=100') {
        return [pscustomobject]@{total_count=$script:Inventory.Count;runners=@($script:Inventory)}
    }
    if ($Method -ceq 'POST') {
        $script:PostCalls++
        Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/generate-jitconfig') 'REGISTRATION_PATH_INVALID'
        $script:Inventory = @($jit.runner)
        return $jit
    }
    if ($Method -ceq 'GET' -and $Path -ceq ('repos/LowcountryDigitalWorks/infrastructure-tools/actions/runs/' + $runId)) {
        return $run
    }
    if ($Method -ceq 'GET' -and $Path -ceq ('repos/LowcountryDigitalWorks/infrastructure-tools/actions/jobs/' + $jobId)) {
        return [pscustomobject]@{id=$jobId;run_id=$runId;name='dragonfly-canary';status='completed';conclusion='success';runner_id=$runnerId;runner_name=$runnerName;labels=$labels}
    }
    if ($Method -ceq 'DELETE') {
        Assert-True ($Path -ceq ('repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/' + $runnerId)) 'FINAL_DELETE_PATH_INVALID'
        $script:DeleteCalls++
        $script:Inventory = @()
        return $null
    }
    throw ('UNEXPECTED_API:' + $Method + ':' + $Path)
}
$processFromCapsule = {
    param($Plan,$CapsuleJson,$TimeoutSeconds)
    $value = $CapsuleJson | ConvertFrom-Json
    Assert-True (-not ((@($Plan.Arguments) -join "`n").Contains($value.opaque_bootstrap))) 'BOOTSTRAP_IN_ARGV'
    [pscustomobject]@{ExitCode=0;Stderr='';Stdout=([ordered]@{
        marker=$value.marker;profile_id=$value.profile_id;dispatch_id=$value.dispatch_id;job_id=$value.job_id;claimed=$true
        execution=[ordered]@{guest_qemu_exit='PASS';guest_cleanup='PASS';state='STOPPED';job_id=$value.job_id;dispatch_id=$value.dispatch_id}
    } | ConvertTo-Json -Depth 6 -Compress)}
}
$result = Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api -StatusProvider { $status } -ProcessInvoker $processFromCapsule -SleepInvoker { param($Seconds) } -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5
Assert-True ($result.Result -ceq 'PASS') 'FULL_ONCE_RESULT_INVALID'
Assert-True ($result.ProviderConclusion -ceq 'success') 'PROVIDER_SUCCESS_NOT_PROVEN'
Assert-True ($result.BootstrapExposed -eq $false) 'BOOTSTRAP_EXPOSURE_FLAG_INVALID'
Assert-True ($script:PostCalls -eq 1 -and $script:DeleteCalls -eq 1 -and $script:Inventory.Count -eq 0) 'FULL_ONCE_CLEANUP_INVALID'

# A post-registration transport failure must still delete the exact runner and prove absence.
$script:Inventory = @()
$script:DeleteCalls = 0
$script:PostCalls = 0
Assert-ThrowsMessage {
    Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api -StatusProvider { $status } -ProcessInvoker { [pscustomobject]@{ExitCode=1;Stdout='';Stderr='not-emitted'} } -SleepInvoker { param($Seconds) } -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5 | Out-Null
} 'DRAGONFLY_CANARY_TRANSPORT_FAILED' 'POST_REGISTRATION_TRANSPORT_FAILURE_NOT_RETURNED'
Assert-True ($script:PostCalls -eq 1 -and $script:DeleteCalls -eq 1 -and $script:Inventory.Count -eq 0) 'POST_REGISTRATION_FAILURE_NOT_CLEANED'

'DRAGONFLY_CANARY_RUNTIME_CONTRACT=PASS'
