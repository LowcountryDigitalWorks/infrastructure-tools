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
foreach($exitCode in @(0,1)){
 $echoStderr={param($Plan,$CapsuleJson,$TimeoutSeconds)$value=$CapsuleJson|ConvertFrom-Json;[pscustomobject]@{ExitCode=$exitCode;Stderr=('prefix '+$value.opaque_bootstrap+' suffix');Stdout='{}'}}
 Assert-ThrowsMessage {Invoke-LdwDragonflyCanaryTransport -CapsuleJson $capsule -Plan $plan -ProcessInvoker $echoStderr|Out-Null} 'DRAGONFLY_CANARY_TRANSPORT_BOOTSTRAP_EXPOSED' 'BOOTSTRAP_STDERR_ECHO_NOT_REFUSED'
}

$script:Inventory=@();$script:DeleteCalls=0;$script:PostCalls=0;$script:AttemptReads=0
$runPath='repos/LowcountryDigitalWorks/infrastructure-tools/actions/runs/'+$runId
$attemptJobsPath='repos/LowcountryDigitalWorks/infrastructure-tools/actions/runs/'+$runId+'/attempts/'+$runAttempt+'/jobs?per_page=100'
$runnerInventoryPath='repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners?per_page=100'
$api={
 param($Path,$Method,$Body)
 if($Method -ceq 'GET' -and $Path -ceq $runnerInventoryPath){return [pscustomobject]@{total_count=$script:Inventory.Count;runners=@($script:Inventory)}}
 if($Method -ceq 'GET' -and $Path -ceq $runPath){return $run}
 if($Method -ceq 'GET' -and $Path -ceq $attemptJobsPath){
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
 $movedApi={param($Path,$Method,$Body);if($Method -ceq 'GET' -and $Path -ceq $runPath){return $movedRun};if($Method -ceq 'GET' -and $Path -ceq $attemptJobsPath){return [pscustomobject]@{total_count=1;jobs=@($job)}};if($Method -ceq 'POST'){$script:PostCalls++;return $jit};if($Method -ceq 'GET' -and $Path -ceq $runnerInventoryPath){return [pscustomobject]@{total_count=0;runners=@()}};throw ('UNEXPECTED_API:'+$Method+':'+$Path)}
 $movementFailed=$false
 try{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $movedApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null}catch{$movementFailed=$_.Exception.Message -in @('DRAGONFLY_CANARY_RUN_IDENTITY_INVALID','DRAGONFLY_CANARY_JOB_IDENTITY_INVALID')}
 Assert-True $movementFailed 'FRESH_PROVIDER_MOVEMENT_NOT_REFUSED'
 Assert-True ($script:PostCalls -eq 0) 'REGISTRATION_OCCURRED_AFTER_PROVIDER_MOVEMENT'

 # Ambiguous registration POST creates a durable blocker; repeated run is refused until explicit reconciliation.
 $script:UnknownInventory=@();$script:UnknownPost=0
 $uncertainApi={
   param($Path,$Method,$Body)
   if($Method -ceq 'GET' -and $Path -ceq $runPath){return $run}
   if($Method -ceq 'GET' -and $Path -ceq $attemptJobsPath){return [pscustomobject]@{total_count=1;jobs=@($job)}}
   if($Method -ceq 'GET' -and $Path -ceq $runnerInventoryPath){return [pscustomobject]@{total_count=$script:UnknownInventory.Count;runners=@($script:UnknownInventory)}}
   if($Method -ceq 'POST'){$script:UnknownPost++;throw 'SIMULATED_AMBIGUOUS_POST'}
   throw ('UNEXPECTED_API:'+$Method+':'+$Path)
 }
 Assert-ThrowsMessage{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $uncertainApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null} 'DRAGONFLY_CANARY_REGISTRATION_POST_UNCERTAIN' 'POST_UNCERTAINTY_NOT_RETURNED'
 Assert-True (Test-Path -LiteralPath (Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json')) 'UNCERTAINTY_MARKER_NOT_DURABLE'
 $before=$script:UnknownPost
 Assert-ThrowsMessage{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $uncertainApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null} 'DRAGONFLY_CANARY_RECONCILIATION_REQUIRED' 'BLIND_RETRY_NOT_BLOCKED'
 Assert-True ($script:UnknownPost -eq $before) 'BLIND_RETRY_REPOSTED'
 $legacyRecord=Get-Content -LiteralPath (Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json') -Raw|ConvertFrom-Json
 $reconciled=Resolve-LdwDragonflyCanaryRegistrationUncertainty -DispatcherRoot $ci10Root -ApiInvoker $uncertainApi -SleepInvoker{param($Seconds)} -AbsentProofReads 3
 Assert-True ($reconciled.Reconciled -and -not (Test-Path -LiteralPath (Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json'))) 'UNCERTAINTY_NOT_RECONCILED'
 $legacyRecord.schema=1;$legacyRecord.PSObject.Properties.Remove('phase');$legacyRecord.PSObject.Properties.Remove('runner_id')
 $legacyRecord|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json')
 $legacyResolved=Resolve-LdwDragonflyCanaryRegistrationUncertainty -DispatcherRoot $ci10Root -ApiInvoker $uncertainApi -SleepInvoker{param($Seconds)} -AbsentProofReads 3
 Assert-True $legacyResolved.Reconciled 'LEGACY_REGISTRATION_MARKER_NOT_RECONCILED'

 # Cleanup faults never become a new registration, even if inventory later appears empty.
 foreach($fault in @('delete','absence-read','residual','primary-and-delete','provider-and-delete','private-and-delete')){
  $script:Inventory=@();$script:AttemptReads=0;$script:PostCalls=0;$script:AllCalls=0
  $script:CleanupFault=$fault;$script:Deleted=$false
  $cleanupApi={
   param($Path,$Method,$Body)
   $script:AllCalls++
   if($Method -ceq 'GET' -and $Path -ceq $runnerInventoryPath){
    if($script:Deleted -and $script:CleanupFault -ceq 'absence-read'){throw ('UPSTREAM_PRIVATE_'+$jit.encoded_jit_config)}
    return [pscustomobject]@{total_count=$script:Inventory.Count;runners=@($script:Inventory)}
   }
   if($Method -ceq 'DELETE'){
    Assert-True (Test-Path -LiteralPath (Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json')) 'DELETE_PRECEDED_DURABLE_GATE'
    if($script:CleanupFault -in @('delete','primary-and-delete','provider-and-delete','private-and-delete')){throw ('UPSTREAM_PRIVATE_'+$jit.encoded_jit_config)}
    $script:Deleted=$true
    if($script:CleanupFault -cne 'residual'){$script:Inventory=@()}
    return $null
   }
   if($Method -ceq 'GET' -and $Path -ceq $attemptJobsPath -and $script:AttemptReads -gt 0 -and $script:CleanupFault -ceq 'provider-and-delete'){throw 'DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT'}
   & $api $Path $Method $Body
  }
  $transportForCase=if($fault -ceq 'primary-and-delete'){
   {param($Plan,$CapsuleJson,$TimeoutSeconds)[pscustomobject]@{ExitCode=1;Stderr='synthetic private transport failure';Stdout=''}}
  }elseif($fault -ceq 'private-and-delete'){{param($Plan,$CapsuleJson,$TimeoutSeconds)throw ('UPSTREAM_PRIVATE_'+$jit.encoded_jit_config)}}else{$processFromCapsule}
  $caught=$null
  try{Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $cleanupApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $transportForCase -SleepInvoker{param($Seconds)} -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows' -ProviderTimeoutSeconds 5|Out-Null}catch{$caught=$_.Exception}
  Assert-True ($null -ne $caught) ('CLEANUP_FAULT_NOT_REFUSED:'+$fault)
  $expected=switch($fault){'primary-and-delete'{'DRAGONFLY_CANARY_TRANSPORT_FAILED'}'provider-and-delete'{'DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT'}'private-and-delete'{'DRAGONFLY_CANARY_OPERATION_FAILED'}default{'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCERTAIN'}}
  Assert-True ($caught.Message -ceq $expected) ('PRIMARY_FAILURE_MASKED:'+$fault)
  if($fault -like '*and-delete'){Assert-True ($caught.Data['CleanupUncertainty'] -ceq 'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCERTAIN') 'SECONDARY_CLEANUP_STATE_MISSING'}
  $markerPath=Join-Path $ci10Root 'dragonfly-canary-registration-uncertain.json'
  Assert-True (Test-Path -LiteralPath $markerPath) ('CLEANUP_MARKER_MISSING:'+$fault)
  $markerText=Get-Content -LiteralPath $markerPath -Raw;$record=$markerText|ConvertFrom-Json
  Assert-True ($record.phase -ceq 'final_cleanup' -and $record.runner_id -eq $runnerId) 'CLEANUP_IDENTITY_NOT_DURABLE'
  Assert-True (-not $markerText.Contains($jit.encoded_jit_config) -and -not $caught.ToString().Contains($jit.encoded_jit_config) -and -not $caught.ToString().Contains('UPSTREAM_PRIVATE')) 'CLEANUP_FAILURE_LEAKED_PRIVATE_TEXT'
  $script:Inventory=@();$calls=$script:AllCalls
  Assert-ThrowsMessage {Invoke-LdwDragonflyCanaryOnce -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $cleanupApi -DispatcherRoot $ci10Root -StatusProvider{$status} -ProcessInvoker $processFromCapsule -LocalAppData '/tmp/ldw-localappdata' -WindowsRoot '/windows'|Out-Null} 'DRAGONFLY_CANARY_RECONCILIATION_REQUIRED' 'EMPTY_INVENTORY_BYPASSED_MARKER'
  Assert-True ($calls -eq $script:AllCalls) 'BLOCKED_ONCE_CALLED_PROVIDER'
  $script:CleanupFault='none'
  if($fault -ceq 'delete'){
   # Matching name/labels with a different ID is never the original owned runner.
   $script:Inventory=@([pscustomobject]@{id=43;name=$runnerName;labels=$runnerLabels})
   Assert-ThrowsMessage {Resolve-LdwDragonflyCanaryRegistrationUncertainty -DispatcherRoot $ci10Root -ApiInvoker $cleanupApi -SleepInvoker{param($Seconds)}|Out-Null} 'DRAGONFLY_CANARY_RECONCILIATION_AMBIGUOUS' 'RECONCILE_RETARGETED_RUNNER'
   Assert-True (Test-Path -LiteralPath $markerPath) 'AMBIGUOUS_RECONCILE_CLEARED_MARKER'
   $script:Inventory=@($jit.runner)
  }
  $resolved=Resolve-LdwDragonflyCanaryRegistrationUncertainty -DispatcherRoot $ci10Root -ApiInvoker $cleanupApi -SleepInvoker{param($Seconds)} -AbsentProofReads 3
  Assert-True ($resolved.Reconciled -and -not (Test-Path -LiteralPath $markerPath)) ('CLEANUP_RECONCILE_FAILED:'+$fault)
 }
}finally{Remove-Item -LiteralPath $ci10Root -Recurse -Force -ErrorAction SilentlyContinue}

'DRAGONFLY_CANARY_RUNTIME_CONTRACT=PASS'
