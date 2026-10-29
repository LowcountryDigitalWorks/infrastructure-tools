$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'DragonflyCanary.psm1') -Force

function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }

$runId = 123456789
$runAttempt = 2
$jobId = 987654321
$head = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$labels = @(Get-LdwDragonflyCanaryLabels -RunId $runId -RunAttempt $runAttempt)
$run = [pscustomobject]@{
    id=$runId; run_attempt=$runAttempt; head_sha=$head; path='.github/workflows/dragonfly-jit-canary.yml'; event='workflow_dispatch'; status='queued'; conclusion=$null
    repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'}
    head_repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'}
}
$job = [pscustomobject]@{id=$jobId;run_id=$runId;run_attempt=$runAttempt;head_sha=$head;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=$labels}
$runnerName = 'redrix-' + $runId + '-' + $runAttempt + '-' + $jobId
$settings = [ordered]@{agentName=$runnerName;agentId=42;gitHubUrl='https://github.com/LowcountryDigitalWorks/infrastructure-tools';ephemeral=$true;disableUpdate=$true} | ConvertTo-Json -Compress
$files = [ordered]@{'.runner'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($settings))} | ConvertTo-Json -Compress
$runnerLabels = @($labels | ForEach-Object { [pscustomobject]@{name=$_} })
$script:FakeJit = [pscustomobject]@{runner=[pscustomobject]@{id=42;name=$runnerName;labels=$runnerLabels};encoded_jit_config=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($files))}

$script:Inventory=@();$script:GetCalls=0;$script:PostCalls=0;$script:DeleteCalls=0
$api={param($Path,$Method,$Body);if($Method -ceq 'GET'){$script:GetCalls++;Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners?per_page=100') 'INVENTORY_PATH_INVALID';return [pscustomobject]@{total_count=$script:Inventory.Count;runners=@($script:Inventory)}};if($Method -ceq 'POST'){$script:PostCalls++;Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/generate-jitconfig') 'API_PATH_INVALID';Assert-True ($Body.name -ceq $runnerName) 'RUNNER_NAME_INVALID';Assert-True (@(Compare-Object $labels @($Body.labels) -CaseSensitive).Count -eq 0) 'RUNNER_LABELS_INVALID';$script:Inventory=@($script:FakeJit.runner);return $script:FakeJit};if($Method -ceq 'DELETE'){$script:DeleteCalls++;$script:Inventory=@();return $null};throw 'UNEXPECTED_API_METHOD'}

$result=Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api -UtcNow ([datetime]'2026-10-29T08:00:00Z')
Assert-True ($script:GetCalls -eq 1 -and $script:PostCalls -eq 1 -and $script:DeleteCalls -eq 0) 'REGISTRATION_API_COUNTS_INVALID'
Assert-True ($result.RunnerId -eq 42) 'RUNNER_ID_INVALID'
$capsule=$result.CapsuleJson|ConvertFrom-Json
Assert-True ($capsule.profile_id -ceq 'dragonfly-github-canary-v1') 'PROFILE_INVALID'
Assert-True (@(Compare-Object $labels @($capsule.labels) -CaseSensitive).Count -eq 0) 'CAPSULE_ROUTING_LABELS_INVALID'
$sanitized=$result.Sanitized|ConvertTo-Json -Depth 6 -Compress
Assert-True (-not $sanitized.Contains($script:FakeJit.encoded_jit_config)) 'BOOTSTRAP_LEAKED'
Assert-True ($capsule.opaque_bootstrap -ceq $script:FakeJit.encoded_jit_config) 'BOOTSTRAP_BINDING_INVALID'

$cleanup=Remove-LdwDragonflyCanaryRegistration -Selection $result.Selection -RunnerId $result.RunnerId -ApiInvoker $api
Assert-True ($cleanup.Removed -and $cleanup.Absent -and $script:DeleteCalls -eq 1 -and $script:Inventory.Count -eq 0) 'EXACT_CLEANUP_INVALID'

foreach($case in @(
 [pscustomobject]@{Name='run';Job=[pscustomobject]@{id=$jobId;run_id=1;run_attempt=$runAttempt;head_sha=$head;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=$labels}},
 [pscustomobject]@{Name='attempt';Job=[pscustomobject]@{id=$jobId;run_id=$runId;run_attempt=1;head_sha=$head;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=$labels}},
 [pscustomobject]@{Name='head';Job=[pscustomobject]@{id=$jobId;run_id=$runId;run_attempt=$runAttempt;head_sha=('b'*40);name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=$labels}}
)){$beforeGet=$script:GetCalls;$beforePost=$script:PostCalls;$failed=$false;try{$null=Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $case.Job -ExpectedHeadSha $head -ApiInvoker $api}catch{$failed=$_.Exception.Message -ceq 'DRAGONFLY_CANARY_JOB_IDENTITY_INVALID'};Assert-True $failed ('JOB_IDENTITY_MISMATCH_NOT_REFUSED:'+$case.Name);Assert-True ($script:GetCalls -eq $beforeGet -and $script:PostCalls -eq $beforePost) ('API_CALLED_FOR_BAD_JOB:'+$case.Name)}

$badJob=[pscustomobject]@{id=$jobId;run_id=$runId;run_attempt=$runAttempt;head_sha=$head;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=@($labels[0..($labels.Count-2)])+@('dragonfly-attempt-1')}
$beforeGet=$script:GetCalls;$beforePost=$script:PostCalls;$failed=$false;try{$null=Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $badJob -ExpectedHeadSha $head -ApiInvoker $api}catch{$failed=$_.Exception.Message -ceq 'DRAGONFLY_CANARY_LABELS_INVALID'};Assert-True $failed 'INVALID_SELECTION_NOT_REFUSED';Assert-True ($script:GetCalls -eq $beforeGet -and $script:PostCalls -eq $beforePost) 'API_CALLED_BEFORE_SELECTION_VALIDATION'

$script:Inventory=@([pscustomobject]@{id=77;name=$runnerName;labels=$runnerLabels});$beforePost=$script:PostCalls;$failed=$false;try{$null=Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api}catch{$failed=$_.Exception.Message -ceq 'DRAGONFLY_CANARY_STALE_RUNNER_NAME_PRESENT'};Assert-True $failed 'STALE_RUNNER_NAME_NOT_REFUSED';Assert-True ($script:PostCalls -eq $beforePost) 'REGISTRATION_MINTED_WITH_STALE_NAME';$script:Inventory=@()

$badLabels=@($runnerLabels[0..($runnerLabels.Count-2)]);$badSettings=[ordered]@{agentName=$runnerName;agentId=43;gitHubUrl='https://github.com/LowcountryDigitalWorks/infrastructure-tools';ephemeral=$true;disableUpdate=$true}|ConvertTo-Json -Compress;$badFiles=[ordered]@{'.runner'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($badSettings))}|ConvertTo-Json -Compress;$badJit=[pscustomobject]@{runner=[pscustomobject]@{id=43;name=$runnerName;labels=$badLabels};encoded_jit_config=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($badFiles))};$script:BadInventory=@();$script:BadDeletes=0
$badApi={param($Path,$Method,$Body);if($Method -ceq 'GET'){return [pscustomobject]@{total_count=$script:BadInventory.Count;runners=@($script:BadInventory)}};if($Method -ceq 'POST'){$script:BadInventory=@($badJit.runner);return $badJit};if($Method -ceq 'DELETE'){$script:BadDeletes++;$script:BadInventory=@();return $null};throw 'UNEXPECTED_API_METHOD'}
$failed=$false;try{$null=Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $badApi}catch{$failed=$_.Exception.Message -ceq 'DRAGONFLY_CANARY_REGISTRATION_POST_UNCERTAIN'};Assert-True $failed 'PROVIDER_LABEL_DRIFT_UNCERTAINTY_NOT_REFUSED';Assert-True ($script:BadDeletes -eq 0 -and $script:BadInventory.Count -eq 1) 'AMBIGUOUS_LABEL_DRIFT_WAS_DELETED'

$script:LostInventory=@();$script:LostDeletes=0
$lostApi={param($Path,$Method,$Body);if($Method -ceq 'GET'){return [pscustomobject]@{total_count=$script:LostInventory.Count;runners=@($script:LostInventory)}};if($Method -ceq 'POST'){$script:LostInventory=@($script:FakeJit.runner);throw 'SIMULATED_RESPONSE_LOST'};if($Method -ceq 'DELETE'){$script:LostDeletes++;$script:LostInventory=@();return $null};throw 'UNEXPECTED_API_METHOD'}
$failed=$false;try{$null=Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $lostApi}catch{$failed=$_.Exception.Message -ceq 'SIMULATED_RESPONSE_LOST'};Assert-True $failed 'LOST_RESPONSE_ORIGINAL_ERROR_NOT_RETURNED_AFTER_CLEANUP';Assert-True ($script:LostDeletes -eq 1 -and $script:LostInventory.Count -eq 0) 'LOST_RESPONSE_RUNNER_NOT_RECONCILED'

$script:UnknownInventory=@();$unknownApi={param($Path,$Method,$Body);if($Method -ceq 'GET'){return [pscustomobject]@{total_count=$script:UnknownInventory.Count;runners=@($script:UnknownInventory)}};if($Method -ceq 'POST'){throw 'SIMULATED_AMBIGUOUS_POST'};throw 'UNEXPECTED_API_METHOD'}
$failed=$false;try{$null=Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $unknownApi}catch{$failed=$_.Exception.Message -ceq 'DRAGONFLY_CANARY_REGISTRATION_POST_UNCERTAIN'};Assert-True $failed 'POST_UNCERTAINTY_NOT_CLASSIFIED'

'DRAGONFLY_CANARY_POWERSHELL_CONTRACT=PASS'