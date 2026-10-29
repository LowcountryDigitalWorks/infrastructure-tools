Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DragonflyCanaryProfile = [ordered]@{
    Schema = 1
    Marker = 'CI-RUNNER-DRAGONFLY-JIT-001'
    TargetHost = 'dragonfly-redrix-01'
    ProfileId = 'dragonfly-github-canary-v1'
    Repository = 'LowcountryDigitalWorks/infrastructure-tools'
    WorkflowPath = '.github/workflows/dragonfly-jit-canary.yml'
    JobName = 'dragonfly-canary'
    StaticLabels = @('self-hosted','Linux','X64','dragonfly','jit','ldw-ephemeral','synthetic-only')
    MaxBootstrapChars = 32768
    TtlSeconds = 240
}

function Get-LdwObjectField {
    param([Parameter(Mandatory)][object]$Object,[Parameter(Mandatory)][string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-LdwDragonflyCanaryProfile {
    [CmdletBinding()]param()
    [pscustomobject]$script:DragonflyCanaryProfile
}

function Get-LdwDragonflyCanaryLabels {
    [CmdletBinding()]param([Parameter(Mandatory)][long]$RunId)
    if ($RunId -le 0) { throw 'DRAGONFLY_CANARY_RUN_ID_INVALID' }
    @($script:DragonflyCanaryProfile.StaticLabels) + @('dragonfly-run-' + $RunId)
}

function Assert-LdwDragonflyCanarySelection {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][object]$Run,
        [Parameter(Mandatory)][object]$Job,
        [Parameter(Mandatory)][string]$ExpectedHeadSha
    )
    if ($ExpectedHeadSha -cnotmatch '^[0-9a-f]{40}$') { throw 'DRAGONFLY_CANARY_HEAD_SHA_INVALID' }
    $repository = Get-LdwObjectField $Run 'repository'
    $headRepository = Get-LdwObjectField $Run 'head_repository'
    if ($null -eq $repository -or $null -eq $headRepository -or
        $repository.full_name -cne $script:DragonflyCanaryProfile.Repository -or
        $headRepository.full_name -cne $script:DragonflyCanaryProfile.Repository) {
        throw 'DRAGONFLY_CANARY_REPOSITORY_INVALID'
    }
    $runId = [long](Get-LdwObjectField $Run 'id')
    $runAttempt = [int](Get-LdwObjectField $Run 'run_attempt')
    if ($runId -le 0 -or $runAttempt -le 0 -or
        (Get-LdwObjectField $Run 'head_sha') -cne $ExpectedHeadSha -or
        (Get-LdwObjectField $Run 'path') -cne $script:DragonflyCanaryProfile.WorkflowPath -or
        (Get-LdwObjectField $Run 'event') -cne 'workflow_dispatch' -or
        (Get-LdwObjectField $Run 'status') -cne 'queued' -or
        $null -ne (Get-LdwObjectField $Run 'conclusion')) {
        throw 'DRAGONFLY_CANARY_RUN_IDENTITY_INVALID'
    }
    $jobId = [long](Get-LdwObjectField $Job 'id')
    if ($jobId -le 0 -or
        (Get-LdwObjectField $Job 'name') -cne $script:DragonflyCanaryProfile.JobName -or
        (Get-LdwObjectField $Job 'status') -cne 'queued' -or
        $null -ne (Get-LdwObjectField $Job 'conclusion')) {
        throw 'DRAGONFLY_CANARY_JOB_IDENTITY_INVALID'
    }
    $runnerId = Get-LdwObjectField $Job 'runner_id'
    $runnerName = [string](Get-LdwObjectField $Job 'runner_name')
    if (($null -ne $runnerId -and [string]$runnerId -notin @('','0')) -or -not [string]::IsNullOrEmpty($runnerName)) {
        throw 'DRAGONFLY_CANARY_JOB_ALREADY_ASSIGNED'
    }
    $expectedLabels = @(Get-LdwDragonflyCanaryLabels -RunId $runId)
    $actualLabels = @((Get-LdwObjectField $Job 'labels'))
    if ($actualLabels.Count -ne $expectedLabels.Count -or @(Compare-Object $expectedLabels $actualLabels -CaseSensitive).Count) {
        throw 'DRAGONFLY_CANARY_LABELS_INVALID'
    }
    [pscustomobject]@{ RunId=$runId; RunAttempt=$runAttempt; JobId=$jobId; HeadSha=$ExpectedHeadSha; Labels=$expectedLabels }
}

function New-LdwDragonflyCanaryRegistrationRequest {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$Selection)
    $runId = [long]$Selection.RunId
    $jobId = [long]$Selection.JobId
    if ($runId -le 0 -or $jobId -le 0) { throw 'DRAGONFLY_CANARY_SELECTION_INVALID' }
    $runnerName = 'redrix-' + $runId + '-' + $jobId
    if ($runnerName.Length -gt 64) { throw 'DRAGONFLY_CANARY_RUNNER_NAME_INVALID' }
    [pscustomobject]@{
        Path = 'repos/' + $script:DragonflyCanaryProfile.Repository + '/actions/runners/generate-jitconfig'
        Method = 'POST'
        Body = [ordered]@{ name=$runnerName; runner_group_id=1; labels=@(Get-LdwDragonflyCanaryLabels -RunId $runId); work_folder='_work' }
        RunnerName = $runnerName
    }
}

function Assert-LdwDragonflyCanaryJitResponse {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][object]$Request
    )
    $encoded = [string](Get-LdwObjectField $Response 'encoded_jit_config')
    $runner = Get-LdwObjectField $Response 'runner'
    if ([string]::IsNullOrWhiteSpace($encoded) -or
        $encoded.Length -gt $script:DragonflyCanaryProfile.MaxBootstrapChars -or
        $encoded -cnotmatch '^[A-Za-z0-9+/=]+$' -or $null -eq $runner) {
        throw 'DRAGONFLY_CANARY_JIT_RESPONSE_INVALID'
    }
    $runnerId = [long](Get-LdwObjectField $runner 'id')
    $runnerName = [string](Get-LdwObjectField $runner 'name')
    if ($runnerId -le 0 -or $runnerName -cne $Request.RunnerName) { throw 'DRAGONFLY_CANARY_JIT_IDENTITY_INVALID' }

    $runnerLabels = @((Get-LdwObjectField $runner 'labels'))
    $actualLabelNames = @($runnerLabels | ForEach-Object { [string](Get-LdwObjectField $_ 'name') })
    $expectedLabelNames = @($Request.Body.labels)
    if ($actualLabelNames.Count -ne $expectedLabelNames.Count -or
        @(Compare-Object $expectedLabelNames $actualLabelNames -CaseSensitive).Count) {
        throw 'DRAGONFLY_CANARY_JIT_LABELS_INVALID'
    }

    try {
        $files = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json
        $runnerProperty = $files.PSObject.Properties['.runner']
        if ($null -eq $runnerProperty) { throw 'missing' }
        $settings = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$runnerProperty.Value)) | ConvertFrom-Json
    } catch {
        throw 'DRAGONFLY_CANARY_JIT_ONE_JOB_CONTRACT_INVALID'
    }
    if ($settings.agentName -cne $runnerName -or
        [long]$settings.agentId -ne $runnerId -or
        $settings.gitHubUrl.TrimEnd('/') -cne ('https://github.com/' + $script:DragonflyCanaryProfile.Repository) -or
        $settings.ephemeral -ne $true -or $settings.disableUpdate -ne $true) {
        throw 'DRAGONFLY_CANARY_JIT_ONE_JOB_CONTRACT_INVALID'
    }
    [pscustomobject]@{
        RunnerId=$runnerId
        RunnerName=$runnerName
        EncodedBootstrap=$encoded
        CleanupPath='repos/' + $script:DragonflyCanaryProfile.Repository + '/actions/runners/' + $runnerId
    }
}

function New-LdwDragonflyCanaryCapsule {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][object]$Selection,
        [Parameter(Mandatory)][object]$Registration,
        [datetime]$UtcNow=[datetime]::UtcNow
    )
    $bootstrap = [string]$Registration.EncodedBootstrap
    if ([string]::IsNullOrWhiteSpace($bootstrap) -or
        $bootstrap.Length -gt $script:DragonflyCanaryProfile.MaxBootstrapChars -or
        $bootstrap -cnotmatch '^[A-Za-z0-9+/=]+$') { throw 'DRAGONFLY_CANARY_BOOTSTRAP_INVALID' }
    $now = $UtcNow.ToUniversalTime()
    $capsule = [ordered]@{
        marker=$script:DragonflyCanaryProfile.Marker; schema=1; dispatch_id=[Guid]::NewGuid().ToString(); target_host=$script:DragonflyCanaryProfile.TargetHost
        issued_at=$now.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"); expires_at=$now.AddSeconds($script:DragonflyCanaryProfile.TtlSeconds).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        profile_id=$script:DragonflyCanaryProfile.ProfileId; repository=$script:DragonflyCanaryProfile.Repository; workflow=$script:DragonflyCanaryProfile.WorkflowPath
        run_id=[long]$Selection.RunId; run_attempt=[int]$Selection.RunAttempt; job_id=[long]$Selection.JobId; head_sha=[string]$Selection.HeadSha
        job_name=$script:DragonflyCanaryProfile.JobName; labels=@(Get-LdwDragonflyCanaryLabels -RunId ([long]$Selection.RunId)); opaque_bootstrap=$bootstrap
    }
    [pscustomobject]@{
        CapsuleJson = ($capsule | ConvertTo-Json -Depth 6 -Compress)
        Sanitized = [pscustomobject]@{
            marker=$capsule.marker; dispatch_id=$capsule.dispatch_id; target_host=$capsule.target_host; profile_id=$capsule.profile_id
            repository=$capsule.repository; workflow=$capsule.workflow; run_id=$capsule.run_id; run_attempt=$capsule.run_attempt; job_id=$capsule.job_id
            head_sha=$capsule.head_sha; job_name=$capsule.job_name; labels=@($capsule.labels); issued_at=$capsule.issued_at; expires_at=$capsule.expires_at
            bootstrap_present=$true
        }
    }
}

function Invoke-LdwDragonflyCanaryRegistration {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][object]$Run,
        [Parameter(Mandatory)][object]$Job,
        [Parameter(Mandatory)][string]$ExpectedHeadSha,
        [Parameter(Mandatory)][scriptblock]$ApiInvoker,
        [datetime]$UtcNow=[datetime]::UtcNow
    )
    $selection = Assert-LdwDragonflyCanarySelection -Run $Run -Job $Job -ExpectedHeadSha $ExpectedHeadSha
    $request = New-LdwDragonflyCanaryRegistrationRequest -Selection $selection
    $response = & $ApiInvoker $request.Path $request.Method $request.Body
    $registration = Assert-LdwDragonflyCanaryJitResponse -Response $response -Request $request
    $capsule = New-LdwDragonflyCanaryCapsule -Selection $selection -Registration $registration -UtcNow $UtcNow
    [pscustomobject]@{ RunnerId=$registration.RunnerId; RunnerName=$registration.RunnerName; CleanupPath=$registration.CleanupPath; CapsuleJson=$capsule.CapsuleJson; Sanitized=$capsule.Sanitized }
}

Export-ModuleMember -Function Get-LdwDragonflyCanaryProfile,Get-LdwDragonflyCanaryLabels,Assert-LdwDragonflyCanarySelection,New-LdwDragonflyCanaryRegistrationRequest,Assert-LdwDragonflyCanaryJitResponse,New-LdwDragonflyCanaryCapsule,Invoke-LdwDragonflyCanaryRegistration
