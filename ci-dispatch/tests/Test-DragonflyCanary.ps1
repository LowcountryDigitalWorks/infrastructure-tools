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
$runnerLabels = @($labels | ForEach-Object { [pscustomobject]@{name=$_} })
$script:FakeJit = [pscustomobject]@{
    runner=[pscustomobject]@{id=42;name=$runnerName;labels=$runnerLabels}
    encoded_jit_config=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($files))
}

$script:Inventory = @()
$script:GetCalls = 0
$script:PostCalls = 0
$script:DeleteCalls = 0
$api = {
    param($Path,$Method,$Body)
    if ($Method -ceq 'GET') {
        $script:GetCalls++
        Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners?per_page=100') 'INVENTORY_PATH_INVALID'
        return [pscustomobject]@{total_count=$script:Inventory.Count;runners=@($script:Inventory)}
    }
    if ($Method -ceq 'POST') {
        $script:PostCalls++
        Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/generate-jitconfig') 'API_PATH_INVALID'
        Assert-True ($Body.name -ceq $runnerName) 'RUNNER_NAME_INVALID'
        Assert-True (@(Compare-Object $labels @($Body.labels) -CaseSensitive).Count -eq 0) 'RUNNER_LABELS_INVALID'
        $script:Inventory = @($script:FakeJit.runner)
        return $script:FakeJit
    }
    if ($Method -ceq 'DELETE') {
        $script:DeleteCalls++
        Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/42') 'DELETE_PATH_INVALID'
        $script:Inventory = @()
        return $null
    }
    throw 'UNEXPECTED_API_METHOD'
}

# Valid selection -> inventory absence -> one JIT registration -> sanitized capsule.
$result = Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api -UtcNow ([datetime]'2026-10-29T08:00:00Z')
Assert-True ($script:GetCalls -eq 1) 'PRE_REGISTRATION_INVENTORY_NOT_READ'
Assert-True ($script:PostCalls -eq 1) 'API_POST_COUNT_INVALID'
Assert-True ($script:DeleteCalls -eq 0) 'UNEXPECTED_DELETE_ON_SUCCESS'
Assert-True ($result.RunnerId -eq 42) 'RUNNER_ID_INVALID'
$capsule = $result.CapsuleJson | ConvertFrom-Json
Assert-True ($capsule.profile_id -ceq 'dragonfly-github-canary-v1') 'PROFILE_INVALID'
Assert-True ($capsule.labels[-1] -ceq ('dragonfly-run-' + $runId)) 'DYNAMIC_LABEL_INVALID'
$sanitized = $result.Sanitized | ConvertTo-Json -Depth 6 -Compress
Assert-True (-not $sanitized.Contains($script:FakeJit.encoded_jit_config)) 'BOOTSTRAP_LEAKED'
Assert-True ($capsule.opaque_bootstrap -ceq $script:FakeJit.encoded_jit_config) 'BOOTSTRAP_BINDING_INVALID'

# Explicit exact cleanup proves removal and then absence.
$cleanup = Remove-LdwDragonflyCanaryRegistration -Selection $result.Selection -RunnerId $result.RunnerId -ApiInvoker $api
Assert-True $cleanup.Removed 'RUNNER_NOT_REMOVED'
Assert-True $cleanup.Absent 'RUNNER_ABSENCE_NOT_PROVEN'
Assert-True ($script:DeleteCalls -eq 1) 'EXACT_DELETE_COUNT_INVALID'
Assert-True ($script:Inventory.Count -eq 0) 'RUNNER_INVENTORY_NOT_CLEAN'

# Invalid queued-job labels must fail before any provider API call, including inventory.
$badJob = [pscustomobject]@{id=$jobId;name='dragonfly-canary';status='queued';conclusion=$null;runner_id=$null;runner_name='';labels=@($labels[0..($labels.Count-2)])+@('dragonfly-run-1')}
$beforeGet = $script:GetCalls
$beforePost = $script:PostCalls
$failed = $false
try { $null = Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $badJob -ExpectedHeadSha $head -ApiInvoker $api }
catch { $failed = $_.Exception.Message -ceq 'DRAGONFLY_CANARY_LABELS_INVALID' }
Assert-True $failed 'INVALID_SELECTION_NOT_REFUSED'
Assert-True ($script:GetCalls -eq $beforeGet -and $script:PostCalls -eq $beforePost) 'API_CALLED_BEFORE_SELECTION_VALIDATION'

# Stale exact runner name must fail before a new registration is minted.
$script:Inventory = @([pscustomobject]@{id=77;name=$runnerName;labels=$runnerLabels})
$beforePost = $script:PostCalls
$failed = $false
try { $null = Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $api }
catch { $failed = $_.Exception.Message -ceq 'DRAGONFLY_CANARY_STALE_RUNNER_NAME_PRESENT' }
Assert-True $failed 'STALE_RUNNER_NAME_NOT_REFUSED'
Assert-True ($script:PostCalls -eq $beforePost) 'REGISTRATION_MINTED_WITH_STALE_NAME'
$script:Inventory = @()

# Provider-returned label drift must trigger exact cleanup and rethrow the validation error.
$badLabels = @($runnerLabels[0..($runnerLabels.Count-2)])
$badSettings = [ordered]@{agentName=$runnerName;agentId=43;gitHubUrl='https://github.com/LowcountryDigitalWorks/infrastructure-tools';ephemeral=$true;disableUpdate=$true} | ConvertTo-Json -Compress
$badFiles = [ordered]@{'.runner'=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($badSettings))} | ConvertTo-Json -Compress
$badJit = [pscustomobject]@{
    runner=[pscustomobject]@{id=43;name=$runnerName;labels=$badLabels}
    encoded_jit_config=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($badFiles))
}
$script:BadInventory = @()
$script:BadDeletes = 0
$badApi = {
    param($Path,$Method,$Body)
    if ($Method -ceq 'GET') { return [pscustomobject]@{total_count=$script:BadInventory.Count;runners=@($script:BadInventory)} }
    if ($Method -ceq 'POST') { $script:BadInventory=@($badJit.runner); return $badJit }
    if ($Method -ceq 'DELETE') {
        Assert-True ($Path -ceq 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/43') 'DRIFT_DELETE_PATH_INVALID'
        $script:BadDeletes++; $script:BadInventory=@(); return $null
    }
    throw 'UNEXPECTED_API_METHOD'
}
$failed = $false
try { $null = Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $badApi }
catch { $failed = $_.Exception.Message -ceq 'DRAGONFLY_CANARY_JIT_LABELS_INVALID' }
Assert-True $failed 'PROVIDER_LABEL_DRIFT_NOT_REFUSED'
Assert-True ($script:BadDeletes -eq 1) 'PROVIDER_LABEL_DRIFT_NOT_CLEANED'
Assert-True ($script:BadInventory.Count -eq 0) 'PROVIDER_LABEL_DRIFT_CLEANUP_NOT_PROVEN'

# If the exact cleanup cannot complete, surface a distinct cleanup-uncertain classification.
$script:UncertainInventory = @()
$uncertainApi = {
    param($Path,$Method,$Body)
    if ($Method -ceq 'GET') { return [pscustomobject]@{total_count=$script:UncertainInventory.Count;runners=@($script:UncertainInventory)} }
    if ($Method -ceq 'POST') { $script:UncertainInventory=@($badJit.runner); return $badJit }
    if ($Method -ceq 'DELETE') { throw 'SIMULATED_DELETE_FAILURE' }
    throw 'UNEXPECTED_API_METHOD'
}
$failed = $false
try { $null = Invoke-LdwDragonflyCanaryRegistration -Run $run -Job $job -ExpectedHeadSha $head -ApiInvoker $uncertainApi }
catch { $failed = $_.Exception.Message -ceq 'DRAGONFLY_CANARY_REGISTRATION_VALIDATION_FAILED_CLEANUP_UNCERTAIN' }
Assert-True $failed 'CLEANUP_UNCERTAIN_NOT_CLASSIFIED'

'DRAGONFLY_CANARY_POWERSHELL_CONTRACT=PASS'
