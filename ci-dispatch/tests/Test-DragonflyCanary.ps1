$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'DragonflyCanary.psm1') -Force

function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }

$runId = 123456789
$jobId = 987654321
$head = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$labels = @(Get-LdwDragonflyCanaryLabels -RunId $runId)
$run = [pscustomobject]@{
    id=$runId; run_attempt=1; head_sha=$head; path='.github/workflows/dragonfly-jit-canary.yml'; event='workflow_dispatch'; status='queued'; conclusion=$null
    repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'}
    head_repository=[pscustomobject]@{full_name='LowcountryDigitalWorks/infrastructure-tools'}
}
$job = [pscustomobject]@{id=$jobId;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=$labels}
$runnerName = 'redrix-' + $runId + '-' + $jobId
$settings = [ordered]@{agentName=$runnerName;agentId=42;gitHubUrl='https://github.com/LowcountryDigitalWorks/infrastructure-tools';ephemeral=$true;disableUpdate=$true} | ConvertTo-Json -Compress
$files = [ordered]@{'.runner'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($settings))} | ConvertTo-Json -Compress
$script:FakeJit = [pscustomobject]@{runner=[pscustomobject]@{id=42;name=$runnerName};encoded_jit_config=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($files))}
$script:ApiCalls = 0
$api = {
    param($Path,$Method,$Body)
    $script:ApiCalls++
    Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/generate-jitconfig') 'API_PATH_INVALID'
    Assert-True ($Method -ceq 'POST') 'API_METHOD_INVALID'
    Assert-True ($Body.name -ceq $runnerName) 'RUNNER_NAME_INVALID'
    Assert-True (@(Compare-Object $labels @($Body.labels) -CaseSensitive).Count -eq 0) 'RUNNER_LABELS_INVALID'
    $script:FakeJit
}

$result = Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api -UtcNow ([datetime]'2026-10-29T08:00:00Z')
Assert-True ($script:ApiCalls -eq 1) 'API_CALL_COUNT_INVALID'
Assert-True ($result.RunnerId -eq 42) 'RUNNER_ID_INVALID'
$capsule = $result.CapsuleJson | ConvertFrom-Json
Assert-True ($capsule.profile_id -ceq 'dragonfly-github-canary-v1') 'PROFILE_INVALID'
Assert-True ($capsule.labels[-1] -ceq ('dragonfly-run-' + $runId)) 'DYNAMIC_LABEL_INVALID'
$sanitized = $result.Sanitized | ConvertTo-Json -Depth 6 -Compress
Assert-True (-not $sanitized.Contains($script:FakeJit.encoded_jit_config)) 'BOOTSTRAP_LEAKED'
Assert-True ($capsule.opaque_bootstrap -ceq $script:FakeJit.encoded_jit_config) 'BOOTSTRAP_BINDING_INVALID'

$bad = [pscustomobject]@{id=$jobId;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=@($labels[0..($labels.Count-2)])+@('dragonfly-run-1')}
$before = $script:ApiCalls
$failed = $false
try { $null = Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $bad -ExpectedHeadSha $head -ApiInvoker $api }
catch { $failed = $_.Exception.Message -ceq 'DRAGONFLY_CANARY_LABELS_INVALID' }
Assert-True $failed 'INVALID_SELECTION_NOT_REFUSED'
Assert-True ($script:ApiCalls -eq $before) 'API_CALLED_BEFORE_SELECTION_VALIDATION'

' DRAGONFLY_CANARY_POWERSHELL_CONTRACT=PASS'.Trim()
