Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'DragonflyCanary.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1') -Force

$script:Repository = 'LowcountryDigitalWorks/infrastructure-tools'
$script:WorkflowPath = '.github/workflows/dragonfly-jit-canary.yml'
$script:JobName = 'dragonfly-canary'
$script:RemoteUser = 'eddie'
$script:RemoteSentinel = '/nonexistent/ldw-dragonfly-jit-handoff-v1'
$script:TransportRelativeRoot = 'LDW\CI-JIT\DragonflyTransport'
$script:UncertaintyMarkerName = 'dragonfly-canary-registration-uncertain.json'

function Get-LdwRuntimeObjectField {
    param([Parameter(Mandatory)][object]$Object,[Parameter(Mandatory)][string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $property.Value
}

function Test-LdwTailscaleIPv4 {
    param([Parameter(Mandatory)][string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address,[ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $bytes = $parsed.GetAddressBytes()
    ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127)
}

function Get-LdwDragonflyCanaryPrivateEndpoint {
    [CmdletBinding()]param([scriptblock]$StatusProvider)
    $status = if ($StatusProvider) {
        & $StatusProvider
    } else {
        $tailscale = (Get-Command tailscale.exe -ErrorAction Stop).Source
        $raw = & $tailscale status --json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { throw 'DRAGONFLY_CANARY_TAILSCALE_STATUS_FAILED' }
        try { $raw | ConvertFrom-Json }
        catch { throw 'DRAGONFLY_CANARY_TAILSCALE_STATUS_INVALID' }
    }
    $self = if ($null -ne $status) { Get-LdwRuntimeObjectField $status 'Self' } else { $null }
    if ($null -eq $status -or $null -eq $self -or
        (Get-LdwRuntimeObjectField $status 'BackendState') -cne 'Running' -or
        -not [bool](Get-LdwRuntimeObjectField $self 'Online')) {
        throw 'DRAGONFLY_CANARY_TAILSCALE_NOT_READY'
    }
    $peerRoot = Get-LdwRuntimeObjectField $status 'Peer'
    if ($null -eq $peerRoot) { throw 'DRAGONFLY_CANARY_TAILSCALE_PEER_NOT_UNIQUE' }
    $matches = @()
    foreach ($prop in $peerRoot.PSObject.Properties) {
        $peer = $prop.Value
        $host = [string](Get-LdwRuntimeObjectField $peer 'HostName')
        $dns = [string](Get-LdwRuntimeObjectField $peer 'DNSName')
        $named = $host -in @('penguin','redrix') -or
            $dns.StartsWith('penguin.',[StringComparison]::OrdinalIgnoreCase) -or
            $dns.StartsWith('redrix.',[StringComparison]::OrdinalIgnoreCase)
        if ($named) { $matches += $peer }
    }
    if ($matches.Count -ne 1 -or -not [bool](Get-LdwRuntimeObjectField $matches[0] 'Online')) {
        throw 'DRAGONFLY_CANARY_TAILSCALE_PEER_NOT_UNIQUE'
    }
    $addresses = @((Get-LdwRuntimeObjectField $matches[0] 'TailscaleIPs') | Where-Object {
        $_ -is [string] -and (Test-LdwTailscaleIPv4 $_)
    })
    if ($addresses.Count -ne 1) { throw 'DRAGONFLY_CANARY_TAILSCALE_ENDPOINT_INVALID' }
    $addresses[0]
}

function New-LdwDragonflyCanarySshPlan {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][string]$PrivateEndpoint,
        [string]$LocalAppData=$env:LOCALAPPDATA,
        [string]$WindowsRoot=$env:SystemRoot
    )
    if (-not (Test-LdwTailscaleIPv4 $PrivateEndpoint)) { throw 'DRAGONFLY_CANARY_PRIVATE_ENDPOINT_INVALID' }
    if ([string]::IsNullOrWhiteSpace($LocalAppData) -or -not [IO.Path]::IsPathRooted($LocalAppData)) { throw 'DRAGONFLY_CANARY_LOCALAPPDATA_INVALID' }
    if ([string]::IsNullOrWhiteSpace($WindowsRoot) -or -not [IO.Path]::IsPathRooted($WindowsRoot)) { throw 'DRAGONFLY_CANARY_WINDOWS_ROOT_INVALID' }
    $root = Join-Path $LocalAppData $script:TransportRelativeRoot
    $key = Join-Path $root 'id_ed25519'
    $knownHosts = Join-Path $root 'known_hosts'
    $ssh = Join-Path $WindowsRoot 'System32\OpenSSH\ssh.exe'
    $arguments = @(
        '-T','-p','22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o',('UserKnownHostsFile=' + $knownHosts),'-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
        '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','RequestTTY=no',
        '-o','ConnectTimeout=10','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=1','-o','LogLevel=ERROR',
        '-i',$key,($script:RemoteUser + '@' + $PrivateEndpoint),$script:RemoteSentinel
    )
    [pscustomobject]@{ Executable=$ssh; Arguments=$arguments; KeyPath=$key; KnownHostsPath=$knownHosts; CapsuleOnStdin=$true; PrivateEndpoint=$PrivateEndpoint }
}

function Invoke-LdwDragonflyCanaryTransport {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][string]$CapsuleJson,
        [Parameter(Mandatory)][object]$Plan,
        [scriptblock]$ProcessInvoker,
        [int]$TimeoutSeconds=780
    )
    if ([string]::IsNullOrWhiteSpace($CapsuleJson) -or $CapsuleJson.Length -gt 65536) { throw 'DRAGONFLY_CANARY_CAPSULE_INVALID' }
    try { $capsule = $CapsuleJson | ConvertFrom-Json } catch { throw 'DRAGONFLY_CANARY_CAPSULE_INVALID' }
    $bootstrap = [string](Get-LdwRuntimeObjectField $capsule 'opaque_bootstrap')
    if ([string]::IsNullOrEmpty($bootstrap)) { throw 'DRAGONFLY_CANARY_CAPSULE_INVALID' }
    $argumentText = @($Plan.Arguments) -join "`n"
    if (-not [bool]$Plan.CapsuleOnStdin -or $argumentText.Contains($CapsuleJson) -or $argumentText.Contains($bootstrap)) {
        throw 'DRAGONFLY_CANARY_TRANSPORT_PLAN_INVALID'
    }
    $rawResult = if ($ProcessInvoker) {
        & $ProcessInvoker $Plan $CapsuleJson $TimeoutSeconds
    } else {
        if (-not (Test-Path -LiteralPath $Plan.Executable -PathType Leaf) -or
            -not (Test-Path -LiteralPath $Plan.KeyPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $Plan.KnownHostsPath -PathType Leaf)) {
            throw 'DRAGONFLY_CANARY_TRANSPORT_ARTIFACT_MISSING'
        }
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = [string]$Plan.Executable; $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        foreach ($arg in @($Plan.Arguments)) { [void]$psi.ArgumentList.Add([string]$arg) }
        $process = [Diagnostics.Process]::new(); $process.StartInfo = $psi
        try {
            if (-not $process.Start()) { throw 'DRAGONFLY_CANARY_SSH_START_FAILED' }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync(); $stderrTask = $process.StandardError.ReadToEndAsync()
            $process.StandardInput.Write($CapsuleJson); $process.StandardInput.Close()
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                try { $process.Kill($true) } catch {}
                throw 'DRAGONFLY_CANARY_SSH_TIMEOUT'
            }
            $process.WaitForExit()
            [pscustomobject]@{ ExitCode=$process.ExitCode; Stdout=$stdoutTask.GetAwaiter().GetResult(); Stderr=$stderrTask.GetAwaiter().GetResult() }
        } finally { $process.Dispose() }
    }
    if ($null -eq $rawResult) { throw 'DRAGONFLY_CANARY_TRANSPORT_FAILED' }
    $stdout = [string]$rawResult.Stdout
    $stderr = [string]$rawResult.Stderr
    if ($stdout.Contains($bootstrap) -or $stderr.Contains($bootstrap)) { throw 'DRAGONFLY_CANARY_TRANSPORT_BOOTSTRAP_EXPOSED' }
    if ([int]$rawResult.ExitCode -ne 0) { throw 'DRAGONFLY_CANARY_TRANSPORT_FAILED' }
    try { $result = $stdout | ConvertFrom-Json } catch { throw 'DRAGONFLY_CANARY_TRANSPORT_RESULT_INVALID' }
    if ($result.claimed -ne $true -or $result.profile_id -cne 'dragonfly-github-canary-v1' -or $null -eq $result.execution) {
        throw 'DRAGONFLY_CANARY_TRANSPORT_RESULT_INVALID'
    }
    if ($result.execution.guest_qemu_exit -cne 'PASS' -or $result.execution.guest_cleanup -cne 'PASS' -or
        $result.execution.state -cne 'STOPPED' -or [long]$result.execution.job_id -ne [long]$result.job_id -or
        [string]$result.execution.dispatch_id -cne [string]$result.dispatch_id) {
        throw 'DRAGONFLY_CANARY_EXECUTION_RESULT_INVALID'
    }
    $serialized = $result | ConvertTo-Json -Depth 8 -Compress
    if ($serialized.Contains('opaque_bootstrap') -or $serialized.Contains($bootstrap)) { throw 'DRAGONFLY_CANARY_TRANSPORT_BOOTSTRAP_EXPOSED' }
    [pscustomobject]@{ Claimed=$true; DispatchId=[string]$result.dispatch_id; JobId=[long]$result.job_id; GuestQemuExit='PASS'; GuestCleanup='PASS'; State='STOPPED' }
}

function Get-LdwDragonflyCanaryFreshSelection {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][object]$InitialRun,
        [Parameter(Mandatory)][object]$InitialJob,
        [Parameter(Mandatory)][string]$ExpectedHeadSha,
        [Parameter(Mandatory)][scriptblock]$ApiInvoker
    )
    $runId = [long](Get-LdwRuntimeObjectField $InitialRun 'id')
    $runAttempt = [int](Get-LdwRuntimeObjectField $InitialRun 'run_attempt')
    $jobId = [long](Get-LdwRuntimeObjectField $InitialJob 'id')
    if ($runId -le 0 -or $runAttempt -le 0 -or $jobId -le 0 -or $ExpectedHeadSha -cnotmatch '^[0-9a-f]{40}$') {
        throw 'DRAGONFLY_CANARY_FRESH_SELECTION_ARGUMENT_INVALID'
    }
    $runPath = 'repos/' + $script:Repository + '/actions/runs/' + $runId
    $jobsPath = 'repos/' + $script:Repository + '/actions/runs/' + $runId + '/attempts/' + $runAttempt + '/jobs?per_page=100'
    $run = & $ApiInvoker $runPath 'GET' $null
    $jobsResponse = & $ApiInvoker $jobsPath 'GET' $null
    if ($null -eq $run -or $null -eq $jobsResponse) { throw 'DRAGONFLY_CANARY_FRESH_SELECTION_INVALID' }
    $total = [long](Get-LdwRuntimeObjectField $jobsResponse 'total_count')
    $jobs = @((Get-LdwRuntimeObjectField $jobsResponse 'jobs'))
    if ($total -lt 1 -or $total -gt 100 -or $jobs.Count -ne $total) { throw 'DRAGONFLY_CANARY_FRESH_SELECTION_INVALID' }
    $matches = @($jobs | Where-Object { [long](Get-LdwRuntimeObjectField $_ 'id') -eq $jobId })
    if ($matches.Count -ne 1) { throw 'DRAGONFLY_CANARY_FRESH_JOB_NOT_UNIQUE' }
    $selection = Assert-LdwDragonflyCanarySelection -Run $run -Job $matches[0] -ExpectedHeadSha $ExpectedHeadSha
    [pscustomobject]@{ Run=$run; Job=$matches[0]; Selection=$selection }
}

function Get-LdwDragonflyCanaryUncertaintyMarkerPath {
    param([Parameter(Mandatory)][string]$DispatcherRoot)
    if ([string]::IsNullOrWhiteSpace($DispatcherRoot) -or -not [IO.Path]::IsPathRooted($DispatcherRoot)) { throw 'DRAGONFLY_CANARY_DISPATCHER_ROOT_INVALID' }
    Join-Path ([IO.Path]::GetFullPath($DispatcherRoot)) $script:UncertaintyMarkerName
}

function Write-LdwDragonflyCanaryRegistrationUncertainty {
    param(
        [Parameter(Mandatory)][string]$DispatcherRoot,[Parameter(Mandatory)][object]$Selection,
        [ValidateSet('registration_post','final_cleanup')][string]$Phase='registration_post',
        [long]$RunnerId=0
    )
    if (($Phase -ceq 'final_cleanup' -and $RunnerId -le 0) -or ($Phase -ceq 'registration_post' -and $RunnerId -ne 0)) { throw 'DRAGONFLY_CANARY_UNCERTAINTY_IDENTITY_INVALID' }
    $path = Get-LdwDragonflyCanaryUncertaintyMarkerPath -DispatcherRoot $DispatcherRoot
    if (Test-Path -LiteralPath $path) { throw 'DRAGONFLY_CANARY_RECONCILIATION_REQUIRED' }
    $request = New-LdwDragonflyCanaryRegistrationRequest -Selection $Selection
    $record = [ordered]@{ schema=2; phase=$Phase; runner_id=$RunnerId; run_id=[long]$Selection.RunId; run_attempt=[int]$Selection.RunAttempt; job_id=[long]$Selection.JobId; head_sha=[string]$Selection.HeadSha; runner_name=[string]$request.RunnerName; recorded_at=[DateTime]::UtcNow.ToString('o') }
    $temp = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temp, (($record | ConvertTo-Json -Compress) + "`n"), [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temp -Destination $path -ErrorAction Stop
    } finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    $path
}

function Assert-LdwDragonflyNoRegistrationUncertainty {
    param([Parameter(Mandatory)][string]$DispatcherRoot)
    $path = Get-LdwDragonflyCanaryUncertaintyMarkerPath -DispatcherRoot $DispatcherRoot
    if (Test-Path -LiteralPath $path) { throw 'DRAGONFLY_CANARY_RECONCILIATION_REQUIRED' }
}

function Resolve-LdwDragonflyCanaryRegistrationUncertainty {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][string]$DispatcherRoot,
        [Parameter(Mandatory)][scriptblock]$ApiInvoker,
        [scriptblock]$SleepInvoker,
        [int]$AbsentProofReads=3
    )
    if ($AbsentProofReads -lt 2 -or $AbsentProofReads -gt 10) { throw 'DRAGONFLY_CANARY_RECONCILE_ARGUMENT_INVALID' }
    $lock = $null
    try {
        $lock = Enter-Ci10DispatcherLock -Root $DispatcherRoot
        $path = Get-LdwDragonflyCanaryUncertaintyMarkerPath -DispatcherRoot $DispatcherRoot
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return [pscustomobject]@{ Reconciled=$true; MarkerPresent=$false } }
        try { $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } catch { throw 'DRAGONFLY_CANARY_UNCERTAINTY_MARKER_INVALID' }
        if ($record.schema -notin @(1,2) -or [long]$record.run_id -le 0 -or [int]$record.run_attempt -le 0 -or [long]$record.job_id -le 0 -or
            [string]$record.head_sha -cnotmatch '^[0-9a-f]{40}$') { throw 'DRAGONFLY_CANARY_UNCERTAINTY_MARKER_INVALID' }
        $cleanupRunnerId = 0L
        if ($record.schema -eq 2) {
            if ($record.phase -notin @('registration_post','final_cleanup') -or
                ($record.phase -ceq 'registration_post' -and [long]$record.runner_id -ne 0) -or
                ($record.phase -ceq 'final_cleanup' -and [long]$record.runner_id -le 0)) { throw 'DRAGONFLY_CANARY_UNCERTAINTY_MARKER_INVALID' }
            if ($record.phase -ceq 'final_cleanup') { $cleanupRunnerId = [long]$record.runner_id }
        }
        $selection = [pscustomobject]@{ RunId=[long]$record.run_id; RunAttempt=[int]$record.run_attempt; JobId=[long]$record.job_id; HeadSha=[string]$record.head_sha }
        $request = New-LdwDragonflyCanaryRegistrationRequest -Selection $selection
        if ([string]$record.runner_name -cne [string]$request.RunnerName) { throw 'DRAGONFLY_CANARY_UNCERTAINTY_MARKER_INVALID' }
        $absentReads = 0
        for ($i=0; $i -lt $AbsentProofReads; $i++) {
            $inventory = @(Get-LdwDragonflyCanaryRunnerInventory -ApiInvoker $ApiInvoker)
            $matches = @($inventory | Where-Object {
                [string](Get-LdwRuntimeObjectField $_ 'name') -ceq $request.RunnerName -or
                ($cleanupRunnerId -gt 0 -and [long](Get-LdwRuntimeObjectField $_ 'id') -eq $cleanupRunnerId)
            })
            if ($matches.Count -gt 1) { throw 'DRAGONFLY_CANARY_RECONCILIATION_AMBIGUOUS' }
            if ($matches.Count -eq 1) {
                if (-not (Test-LdwDragonflyCanaryRunnerMatchesRequest -Runner $matches[0] -Request $request)) { throw 'DRAGONFLY_CANARY_RECONCILIATION_AMBIGUOUS' }
                $runnerId = [long](Get-LdwRuntimeObjectField $matches[0] 'id')
                if ($cleanupRunnerId -gt 0 -and $runnerId -ne $cleanupRunnerId) { throw 'DRAGONFLY_CANARY_RECONCILIATION_AMBIGUOUS' }
                $removed = Remove-LdwDragonflyCanaryRegistration -Selection $selection -RunnerId $runnerId -ApiInvoker $ApiInvoker
                if (-not $removed.Absent) { throw 'DRAGONFLY_CANARY_RECONCILIATION_UNCONFIRMED' }
                $absentReads = $AbsentProofReads
                break
            }
            $absentReads++
            if ($i + 1 -lt $AbsentProofReads) {
                if ($SleepInvoker) { & $SleepInvoker 2 } else { Start-Sleep -Seconds 2 }
            }
        }
        if ($absentReads -lt $AbsentProofReads) { throw 'DRAGONFLY_CANARY_RECONCILIATION_UNCONFIRMED' }
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $path) { throw 'DRAGONFLY_CANARY_RECONCILIATION_UNCONFIRMED' }
        [pscustomobject]@{ Reconciled=$true; MarkerPresent=$false; RunnerName=$request.RunnerName }
    } finally { if ($null -ne $lock) { $lock.Dispose() } }
}

function Assert-LdwDragonflyProviderRunStable {
    param([Parameter(Mandatory)][object]$Run,[Parameter(Mandatory)][object]$Selection)
    if ([long](Get-LdwRuntimeObjectField $Run 'id') -ne [long]$Selection.RunId -or
        [int](Get-LdwRuntimeObjectField $Run 'run_attempt') -ne [int]$Selection.RunAttempt -or
        [string](Get-LdwRuntimeObjectField $Run 'head_sha') -cne [string]$Selection.HeadSha -or
        [string](Get-LdwRuntimeObjectField $Run 'path') -cne $script:WorkflowPath -or
        [string](Get-LdwRuntimeObjectField $Run 'event') -cne 'workflow_dispatch') {
        throw 'DRAGONFLY_CANARY_PROVIDER_RUN_DRIFT'
    }
}

function Get-LdwDragonflyAttemptJob {
    param([Parameter(Mandatory)][object]$Selection,[Parameter(Mandatory)][scriptblock]$ApiInvoker)
    $path = 'repos/' + $script:Repository + '/actions/runs/' + [long]$Selection.RunId + '/attempts/' + [int]$Selection.RunAttempt + '/jobs?per_page=100'
    $response = & $ApiInvoker $path 'GET' $null
    if ($null -eq $response) { throw 'DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT' }
    $total = [long](Get-LdwRuntimeObjectField $response 'total_count')
    $jobs = @((Get-LdwRuntimeObjectField $response 'jobs'))
    if ($total -lt 1 -or $total -gt 100 -or $jobs.Count -ne $total) { throw 'DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT' }
    $matches = @($jobs | Where-Object { [long](Get-LdwRuntimeObjectField $_ 'id') -eq [long]$Selection.JobId })
    if ($matches.Count -ne 1) { throw 'DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT' }
    $matches[0]
}

function Wait-LdwDragonflyCanaryProviderTerminal {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][object]$Selection,
        [Parameter(Mandatory)][long]$RunnerId,
        [Parameter(Mandatory)][string]$RunnerName,
        [Parameter(Mandatory)][scriptblock]$ApiInvoker,
        [scriptblock]$SleepInvoker,
        [int]$TimeoutSeconds=360,
        [int]$PollSeconds=3
    )
    if ($RunnerId -le 0 -or $RunnerName -cnotmatch '^redrix-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*$' -or $TimeoutSeconds -lt 1 -or $PollSeconds -lt 1) {
        throw 'DRAGONFLY_CANARY_MONITOR_ARGUMENT_INVALID'
    }
    $expectedLabels = @(Get-LdwDragonflyCanaryLabels -RunId ([long]$Selection.RunId) -RunAttempt ([int]$Selection.RunAttempt))
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $assigned = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $runPath = 'repos/' + $script:Repository + '/actions/runs/' + [long]$Selection.RunId
        $run = & $ApiInvoker $runPath 'GET' $null
        $job = Get-LdwDragonflyAttemptJob -Selection $Selection -ApiInvoker $ApiInvoker
        Assert-LdwDragonflyProviderRunStable -Run $run -Selection $Selection
        if ([long](Get-LdwRuntimeObjectField $job 'id') -ne [long]$Selection.JobId -or
            [long](Get-LdwRuntimeObjectField $job 'run_id') -ne [long]$Selection.RunId -or
            [string](Get-LdwRuntimeObjectField $job 'head_sha') -cne [string]$Selection.HeadSha -or
            [string](Get-LdwRuntimeObjectField $job 'name') -cne $script:JobName) {
            throw 'DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT'
        }
        $labels = @((Get-LdwRuntimeObjectField $job 'labels'))
        if ($labels.Count -ne $expectedLabels.Count -or @(Compare-Object $expectedLabels $labels -CaseSensitive).Count) { throw 'DRAGONFLY_CANARY_PROVIDER_JOB_LABEL_DRIFT' }
        $status = [string](Get-LdwRuntimeObjectField $job 'status')
        $jobRunnerId = Get-LdwRuntimeObjectField $job 'runner_id'; $jobRunnerName = [string](Get-LdwRuntimeObjectField $job 'runner_name')
        if ($status -in @('in_progress','completed')) {
            if ([long]$jobRunnerId -ne $RunnerId -or $jobRunnerName -cne $RunnerName) { throw 'DRAGONFLY_CANARY_PROVIDER_RUNNER_DRIFT' }
            $assigned = $true
        } elseif ($status -ne 'queued') { throw 'DRAGONFLY_CANARY_PROVIDER_JOB_STATUS_INVALID' }
        if ($status -ceq 'completed') {
            if (-not $assigned -or [string](Get-LdwRuntimeObjectField $job 'conclusion') -cne 'success') { throw 'DRAGONFLY_CANARY_PROVIDER_TERMINAL_FAILED' }
            return [pscustomobject]@{ RunId=[long]$Selection.RunId; RunAttempt=[int]$Selection.RunAttempt; JobId=[long]$Selection.JobId; RunnerId=$RunnerId; RunnerName=$RunnerName; Assigned=$true; Conclusion='success' }
        }
        if ($SleepInvoker) { & $SleepInvoker $PollSeconds } else { Start-Sleep -Seconds $PollSeconds }
    }
    throw 'DRAGONFLY_CANARY_PROVIDER_TIMEOUT'
}

function Invoke-LdwDragonflyCanaryOnce {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][object]$Run,
        [Parameter(Mandatory)][object]$Job,
        [Parameter(Mandatory)][string]$ExpectedHeadSha,
        [Parameter(Mandatory)][scriptblock]$ApiInvoker,
        [Parameter(Mandatory)][string]$DispatcherRoot,
        [scriptblock]$StatusProvider,
        [scriptblock]$ProcessInvoker,
        [scriptblock]$SleepInvoker,
        [string]$LocalAppData=$env:LOCALAPPDATA,
        [string]$WindowsRoot=$env:SystemRoot,
        [int]$ProviderTimeoutSeconds=360
    )
    if ([string]::IsNullOrWhiteSpace($DispatcherRoot) -or -not [IO.Path]::IsPathRooted($DispatcherRoot)) { throw 'DRAGONFLY_CANARY_DISPATCHER_ROOT_INVALID' }
    $dispatcherLock = $null; $registration = $null; $primary = $null; $final = $null; $fresh = $null; $cleanupUncertain = $false
    try {
        $dispatcherLock = Enter-Ci10DispatcherLock -Root $DispatcherRoot
        Assert-LdwDragonflyNoRegistrationUncertainty -DispatcherRoot $DispatcherRoot
        $fresh = Get-LdwDragonflyCanaryFreshSelection -InitialRun $Run -InitialJob $Job -ExpectedHeadSha $ExpectedHeadSha -ApiInvoker $ApiInvoker
        try {
            $registration = Invoke-LdwDragonflyCanaryRegistration -Run $fresh.Run -Job $fresh.Job -ExpectedHeadSha $ExpectedHeadSha -ApiInvoker $ApiInvoker
        } catch {
            if ($_.Exception.Message -ceq 'DRAGONFLY_CANARY_REGISTRATION_POST_UNCERTAIN') {
                $null = Write-LdwDragonflyCanaryRegistrationUncertainty -DispatcherRoot $DispatcherRoot -Selection $fresh.Selection
            }
            throw
        }
        $endpoint = Get-LdwDragonflyCanaryPrivateEndpoint -StatusProvider $StatusProvider
        $plan = New-LdwDragonflyCanarySshPlan -PrivateEndpoint $endpoint -LocalAppData $LocalAppData -WindowsRoot $WindowsRoot
        $transport = Invoke-LdwDragonflyCanaryTransport -CapsuleJson $registration.CapsuleJson -Plan $plan -ProcessInvoker $ProcessInvoker
        if ($transport.DispatchId -cne [string]$registration.Sanitized.dispatch_id -or $transport.JobId -ne [long]$registration.Selection.JobId) { throw 'DRAGONFLY_CANARY_TRANSPORT_CORRELATION_INVALID' }
        $provider = Wait-LdwDragonflyCanaryProviderTerminal -Selection $registration.Selection -RunnerId $registration.RunnerId -RunnerName $registration.RunnerName -ApiInvoker $ApiInvoker -SleepInvoker $SleepInvoker -TimeoutSeconds $ProviderTimeoutSeconds
        $final = [pscustomobject]@{ Result='PASS'; RunId=$provider.RunId; RunAttempt=$provider.RunAttempt; JobId=$provider.JobId; RunnerId=$provider.RunnerId; ProviderConclusion=$provider.Conclusion; GuestQemuExit=$transport.GuestQemuExit; GuestCleanup=$transport.GuestCleanup; RedrixState=$transport.State; BootstrapExposed=$false; Ci10Serialized=$true }
    } catch { $primary = $_.Exception } finally {
        try {
            if ($null -ne $registration) {
                try {
                    # Write-ahead gate survives DELETE failure, lost responses and process interruption.
                    $markerPath = Write-LdwDragonflyCanaryRegistrationUncertainty -DispatcherRoot $DispatcherRoot -Selection $registration.Selection -Phase final_cleanup -RunnerId $registration.RunnerId
                    $cleanup = Remove-LdwDragonflyCanaryRegistration -Selection $registration.Selection -RunnerId $registration.RunnerId -ApiInvoker $ApiInvoker
                    if (-not $cleanup.Absent) { throw 'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCONFIRMED' }
                    Remove-Item -LiteralPath $markerPath -Force -ErrorAction Stop
                    if (Test-Path -LiteralPath $markerPath) { throw 'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCONFIRMED' }
                } catch { $cleanupUncertain = $true }
            }
        } finally { if ($null -ne $dispatcherLock) { $dispatcherLock.Dispose() } }
    }
    if ($cleanupUncertain) {
        # Never expose an upstream body/exception or mask a known primary failure with cleanup.
        $code = 'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCERTAIN'
        if ($null -ne $primary) {
            $code = 'DRAGONFLY_CANARY_OPERATION_FAILED'
            if ($primary.Message -in @(
                'DRAGONFLY_CANARY_TRANSPORT_FAILED','DRAGONFLY_CANARY_TRANSPORT_BOOTSTRAP_EXPOSED',
                'DRAGONFLY_CANARY_TRANSPORT_RESULT_INVALID','DRAGONFLY_CANARY_EXECUTION_RESULT_INVALID',
                'DRAGONFLY_CANARY_TRANSPORT_CORRELATION_INVALID','DRAGONFLY_CANARY_SSH_TIMEOUT',
                'DRAGONFLY_CANARY_TRANSPORT_ARTIFACT_MISSING','DRAGONFLY_CANARY_TRANSPORT_PLAN_INVALID',
                'DRAGONFLY_CANARY_PROVIDER_RUN_DRIFT','DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT',
                'DRAGONFLY_CANARY_PROVIDER_JOB_LABEL_DRIFT','DRAGONFLY_CANARY_PROVIDER_RUNNER_DRIFT',
                'DRAGONFLY_CANARY_PROVIDER_TERMINAL_FAILED','DRAGONFLY_CANARY_PROVIDER_TIMEOUT','DRAGONFLY_CANARY_PROVIDER_JOB_STATUS_INVALID',
                'DRAGONFLY_CANARY_TAILSCALE_NOT_READY','DRAGONFLY_CANARY_TAILSCALE_PEER_NOT_UNIQUE',
                'DRAGONFLY_CANARY_TAILSCALE_ENDPOINT_INVALID','DRAGONFLY_CANARY_TAILSCALE_STATUS_FAILED','DRAGONFLY_CANARY_TAILSCALE_STATUS_INVALID'
            )) { $code = $primary.Message }
        }
        $failure = [InvalidOperationException]::new($code)
        $failure.Data['CleanupUncertainty'] = 'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCERTAIN'
        throw $failure
    }
    if ($null -ne $primary) { throw $primary }
    if ($null -eq $final) { throw 'DRAGONFLY_CANARY_RESULT_MISSING' }
    $final
}

Export-ModuleMember -Function Get-LdwDragonflyCanaryPrivateEndpoint,New-LdwDragonflyCanarySshPlan,Invoke-LdwDragonflyCanaryTransport,Get-LdwDragonflyCanaryFreshSelection,Resolve-LdwDragonflyCanaryRegistrationUncertainty,Wait-LdwDragonflyCanaryProviderTerminal,Invoke-LdwDragonflyCanaryOnce
