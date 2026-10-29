$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$dispatchRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $dispatchRoot 'DragonflyCanaryRuntime.psm1') -Force

function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-ThrowsMessage { param([scriptblock]$Action,[string]$Expected,[string]$Message) $ok=$false; try { & $Action } catch { $ok = $_.Exception.Message -ceq $Expected }; Assert-True $ok $Message }

$runId=123456789; $runAttempt=2; $jobId=987654321; $head='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$labels=@('self-hosted','Linux','X64','dragonfly','jit','ldw-ephemeral','synthetic-only',('dragonfly-run-'+$runId),('dragonfly-attempt-'+$runAttempt))
$run=[pscustomobject]@{id=$runId;run_attempt=$runAttempt;head_sha=$head;path='.github/workflows/dragonfly-jit-canary.yml';event='workflow_dispatch';status='queued';conclusion=$null;repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'};head_repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'}}
$job=[pscustomobject]@{id=$jobId;run_id=$runId;run_attempt=$runAttempt;head_sha=$head;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=$labels}
$runnerName='redrix-'+$runId+'-'+$runAttempt+'-'+$jobId; $runnerId=42
$settings=[ordered]@{agentName=$runnerName;agentId=$runnerId;gitHubUrl='https://github.com/LowcountryDigitalWorks/infrastructure-tools';ephemeral=$true;disableUpdate=$true}|ConvertTo-Json -Compress
$files=[ordered]@{'.runner'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($settings))}|ConvertTo-Json -Compress
$runnerLabels=@($labels|ForEach-Object{[pscustomobject]@{name=$_}})
$jit=[pscustomobject]@{runner=[pscustomobject]@{id=$runnerId;name=$runnerName;labels=$runnerLabels};encoded_jit_config=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($files))}

$status=[pscustomobject]@{BackendState='Running';Self=[pscustomobject]@{Online=$true};Peer=[pscustomobject]@{one=[pscustomobject]@{HostName='penguin';DNSName='penguin.example.ts.net.';Online=$true;TailscaleIPs=@('100.100.100.100')};two=[pscustomobject]@{HostName='other';DNSName='other.example.ts.net.';Online=$true;TailscaleIPs=@('100.101.101.101')}}}
$endpoint=Get-LdwDragonflyCanaryPrivateEndpoint -StatusProvider{$status}
Assert-True ($endpoint -ceq '100.100.100.100') 'PRIVATE_ENDPOINT_SELECTION_INVALID'
$ambiguous=[pscustomobject]@{BackendState='Running';Self=[pscustomobject]@{Online=$true};Peer=[pscustomobject]@{one=[pscustomobject]@{HostName='penguin';DNSName='';Online=$true;TailscaleIPs=@('100.100.100.100')};two=[pscustomobject]@{HostName='redrix';DNSName='';Online=$true;TailscaleIPs=@('100.101.101.101')}}}
Assert-ThrowsMessage {Get-LdwDragonflyCanaryPrivateEndpoint -StatusProvider{$ambiguous}|Out-Null} 'DRAGONFLY_CANARY_TAILSCALE_PEER_NOT_UNIQUE' 'AMBIGUOUS_PEER_NOT_REFUSED'

$plan=New-LdwDragonflyCanarySshPlan -PrivateEndpoint $endpoint -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows'
$joined=@($plan.Arguments)-join "`n"
foreach($required in @('BatchMode=yes','StrictHostKeyChecking=yes','IdentitiesOnly=yes','IdentityAgent=none','ForwardAgent=no','ClearAllForwardings=yes','PermitLocalCommand=no','RequestTTY=no')){Assert-True ($joined.Contains($required)) ('SSH_PLAN_REQUIRED_MISSING:'+$required)}
Assert-True ($plan.CapsuleOnStdin -eq $true) 'CAPSULE_NOT_STDIN_ONLY'
Assert-True ($plan.Arguments[-1] -ceq '/nonexistent/ldw-dragonfly-jit-handoff-v1') 'SSH_SENTINEL_INVALID'

$capsule=[ordered]@{dispatch_id='11111111-1111-4111-8111-111111111111';job_id=$jobId;opaque_bootstrap='DO-NOT-PRINT'}|ConvertTo-Json -Compress
$processOk={param($Plan,$CapsuleJson,$TimeoutSeconds)$value=$CapsuleJson|ConvertFrom-Json;[pscustomobject]@{ExitCode=0;Stderr='';Stdout=([ordered]@{marker='CI-RUNNER-DRAGONFLY-JIT-001';profile_id='dragonfly-github-canary-v1';dispatch_id=$value.dispatch_id;job_id=$value.job_id;claimed=$true;execution=[ordered]@{guest_qemu_exit='PASS';guest_cleanup='PASS';state='STOPPED';job_id=$value.job_id;dispatch_id=$value.dispatch_id}}|ConvertTo-Json -Depth 6 -Compress)}}
$transport=Invoke-LdwDragonflyCanaryTransport -CapsuleJson $capsule -Plan $plan -ProcessInvoker $processOk
Assert-True ($transport.GuestCleanup -ceq 'PASS') 'TRANSPORT_SUCCESS_NOT_ACCEPTED'
$echoBootstrap={param($Plan,$CapsuleJson,$TimeoutSeconds)$value=$CapsuleJson|ConvertFrom-Json;[pscustomobject]@{ExitCode=0;Stderr='';Stdout=([ordered]@{marker='CI-RUNNER-DRAGONFLY-JIT-001';profile_id='dragonfly-github-canary-v1';dispatch_id=$value.dispatch_id;job_id=$value.job_id;claimed=$true;accidental_echo=$value.opaque_bootstrap;execution=[ordered]@{guest_qemu_exit='PASS';guest_cleanup='PASS';state='STOPPED';job_id=$value.job_id;dispatch_id=$value.dispatch_id}}|ConvertTo-Json -Depth 6 -Compress)}}
Assert-ThrowsMessage {Invoke-LdwDragonflyCanaryTransport -CapsuleJson $capsule -Plan $plan -ProcessInvoker $echoBootstrap|Out-Null} 'DRAGONFLY_CANARY_TRANSPORT_BOOTSTRAP_EXPOSED' 'BOOTSTRAP_STDOUT_ECHO_NOT_REFUSED'

$script:Inventory=@();$script:DeleteCalls=0;$script:PostCalls=0;$script:AttemptReads=0
$api={
 param($Path,$Method,$Body)
 if($Method -ceq 'GET' -and $Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners?per_page=100'){return [pscustomobject]@{total_count=$script:Inventory.Count;runners=@($script:Inventory)}}
 if($Method -ceq 'GET' -and $Path -ceq ('repos/LowcountryDigitalWorks/infrastructure-tools/actions/runs/'+$runId)){return $run}
 if($Method -ceq 'GET' -and $Path -ceq ('repos/LowcountryDigitalWorks/infrastructure-tools/actions/runs/'+$runId+'/attempts/'+$runAttempt+'/jobs?per_page=100')){
   $script:AttemptReads++
   if($script:AttemptReads -eq 1){return [pscustomobject]@{total_count=1;jobs=@($job)}}
   return [pscustomobject]@{total_count=1;jobs=@([pscustomobject]@{id=$jobId;run_id=$runId;run_attempt=$runAttempt;head_sha=$head;name='dragonfly-canary';status='completed';conclusion='success';runner_id=$runnerId;runner_name=$runnerName;labels=$labels})}
 }
 if($Method -ceq 'POST'){$script:PostCalls++;$script:Inventory=@($jit.runner);return $jit}
 if($Method -ceq 'DELETE'){$script:DeleteCalls++;$script:Inventory=@();return $null}
 throw ('UNEXPECTED_API:'+$Method+':'+$Path)
}
$processFromCapsule={param($Plan,$CapsuleJson,$TimeoutSeconds)$value=$CapsuleJson|ConvertFrom-Json;Assert-True (-not ((@($Plan.Arguments)-join "`n").Contains($value.opaque_bootstrap))) 'BOOTSTRAP_IN_ARGV';[pscustomobject]@{ExitCode=0;Stderr='';Stdout=([ordered]@{marker=$value.marker;profile_id=$value.profile_id;dispatch_id=$value.dispatch_id;job_id=$value.job_id;claimed=$true;execution=[ordered]@{guest_qemu_exit='PASS';guest_cleanup='PASS';state='STOPPED';job_id=$value.job_id;dispatch_id=$value.dispatch_id}}|ConvertTo-Json -Depth 6 -Compress)}}

$ci10Root=Join-Path ([IO.Path]::GetTempPath()) ('ldw-ci10-'+[guid]::NewGuid().ToString('N'));[void](New-Item -ItemType Directory -Path $ci10Root)
try{
 $busyLock=[IO.File]::Open((Join-Path $ci10Root 'dispatcher.lock'),'OpenOrCreate','ReadWrite','None')
 try{$beforePost=$script:PostCalls;Assert-ThrowsMessage{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null} 'DISPATCHER_BUSY_OR_LOCK_UNCERTAIN' 'CI10_BUSY_LOCK_NOT_REFUSED';Assert-True ($script:PostCalls -eq $beforePost) 'REGISTRATION_OCCURRED_BEFORE_CI10_LOCK'}finally{$busyLock.Dispose()}

 $result=Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5
 Assert-True ($result.Result -ceq 'PASS' -and $result.RunAttempt -eq $runAttempt -and $result.Ci10Serialized) 'FULL_ONCE_RESULT_INVALID'
 Assert-True ($script:PostCalls -eq 1 -and $script:DeleteCalls -eq 1 -and $script:Inventory.Count -eq 0) 'FULL_ONCE_CLEANUP_INVALID'

 # Provider movement between caller snapshot and lock/re-read must fail before registration.
 $script:Inventory=@();$script:PostCalls=0;$script:DeleteCalls=0;$script:AttemptReads=0
 $movedRun=[pscustomobject]@{id=$runId;run_attempt=3;head_sha=$head;path='.github/workflows/dragonfly-jit-canary.yml';event='workflow_dispatch';status='queued';conclusion=$null;repository=$run.repository;head_repository=$run.head_repository}
 $movedApi={param($Path,$Method,$Body);if($Method -ceq 'GET' -and $Path -like '*actions/runs/'+$runId){return $movedRun};if($Method -ceq 'GET' -and $Path -like '*actions/runs/'+$runId+'/attempts/*'){return [pscustomobject]@{total_count=1;jobs=@($job)}};if($Method -ceq 'POST'){$script:PostCalls++;return $jit};if($Method -ceq 'GET' -and $Path -like '*actions/runners*'){return [pscustomobject]@{total_count=0;runners=@()}};throw 'UNEXPECTED_API'}
 Assert-ThrowsMessage{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $movedApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null} 'DRAGONFLY_CANARY_RUN_IDENTITY_INVALID' 'FRESH_PROVIDER_MOVEMENT_NOT_REFUSED'
 Assert-True ($script:PostCalls -eq 0) 'REGISTRATION_OCCURRED_AFTER_PROVIDER_MOVEMENT'

 # Ambiguous registration POST creates a durable blocker; repeated run is refused until explicit reconciliation.
 $script:UnknownInventory=@();$script:UnknownPost=0
 $uncertainApi={
   param($Path,$Method,$Body)
   if($Method -ceq 'GET' -and $Path -ceq ('repos/LowcountryDigitalWorks/infrastructure-tools/actions/runs/'+$runId)){return $run}
   if($Method -ceq 'GET' -and $Path -ceq ('repos/LowcountryDigitalWorks/infrastructure-tools/actions/runs/'+$runId+'/attempts/'+$runAttempt+'/jobs?per_page=100')){return [pscustomobject]@{total_count=1;jobs=@($job)}}
   if($Method -ceq 'GET' -and $Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners?per_page=100'){return [pscustomobject]@{total_count=$script:UnknownInventory.Count;runners=@($script:UnknownInventory)}}
   if($Method -ceq 'POST'){$script:UnknownPost++;throw 'SIMULATED_AMBIGUOUS_POST'}
   throw ('UNEXPECTED_API:'+$Method+':'+$Path)
 }
 Assert-ThrowsMessage{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $uncertainApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null} 'DRAGONFLY_CANARY_REGISTRATION_POST_UNCERTAIN' 'POST_UNCERTAINTY_NOT_RETURNED'
 Assert-True (Test-Path -LiteralPath (Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json')) 'UNCERTAINTY_MARKER_NOT_DURABLE'
 $before=$script:UnknownPost
 Assert-ThrowsMessage{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $uncertainApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null} 'DRAGONFLY_CANARY_RECONCILIATION_REQUIRED' 'BLIND_RETRY_NOT_BLOCKED'
 Assert-True ($script:UnknownPost -eq $before) 'BLIND_RETRY_REPOSTED'
 $reconciled=Resolve-LdwDragonflyCanaryRegistrationUncertainty -DispatcherRoot $ci10Root -ApiInvoker $uncertainApi -SleepInvoker{param($Seconds)} -AbsentProofReads 3
 Assert-True ($reconciled.Reconciled -and -not (Test-Path -LiteralPath (Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json'))) 'UNCERTAINTY_NOT_RECONCILED'
}finally{Remove-Item -LiteralPath $ci10Root -Recurse -Force -ErrorAction SilentlyContinue}

'DRAGONFLY_CANARY_RUNTIME_CONTRACT=PASS'
