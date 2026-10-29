Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'DragonflyCanary.psm1') -Force

$script:Repository = 'LowcountryDigitalWorks/infrastructure-tools'
$script:WorkflowPath = '.github/workflows/dragonfly-jit-canary.yml'
$script:JobName = 'dragonfly-canary'
$script:TargetHost = 'dragonfly-redrix-01'
$script:RemoteUser = 'eddie'
$script:RemoteSentinel = '/nonexistent/ldw-dragonfly-jit-handoff-v1'
$script:TransportRelativeRoot = 'LDW\CI-JIT\DragonflyTransport'
$script:ExpectedStaticLabels = @('self-hosted','Linux','X64','dragonfly','jit','ldw-ephemeral','synthetic-only')

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
    if ($null -eq $status -or
        (Get-LdwRuntimeObjectField $status 'BackendState') -cne 'Running' -or
        -not [bool](Get-LdwRuntimeObjectField (Get-LdwRuntimeObjectField $status 'Self') 'Online')) {
        throw 'DRAGONFLY_CANARY_TAILSCALE_NOT_READY'
    }
    $peerRoot = Get-LdwRuntimeObjectField $status 'Peer'
    if ($null -eq $peerRoot) { throw 'DRAGONFLY_CANARY_TAILSCALE_PEER_NOT_UNIQUE' }
    $matches = @()
    foreach ($prop in $peerRoot.PSObject.Properties) {
        $peer = $prop.Value
        $host = [string](Get-LdwRuntimeObjectField $peer 'HostName')
        $dns = [string](Get-LdwRuntimeObjectField $peer 'DNSName')
        $named = $host -in @('penguin','redrix') -or $dns.StartsWith('penguin.',[StringComparison]::OrdinalIgnoreCase) -or $dns.StartsWith('redrix.',[StringComparison]::OrdinalIgnoreCase)
        if ($named) { $matches += $peer }
    }
    if ($matches.Count -ne 1 -or -not [bool](Get-LdwRuntimeObjectField $matches[0] 'Online')) {
        throw 'DRAGONFLY_CANARY_TAILSCALE_PEER_NOT_UNIQUE'
    }
    $addresses = @((Get-LdwRuntimeObjectField $matches[0] 'TailscaleIPs') | Where-Object { $_ -is [string] -and (Test-LdwTailscaleIPv4 $_) })
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
        '-T','-p','22',
        '-o','BatchMode=yes',
        '-o','StrictHostKeyChecking=yes',
        '-o',('UserKnownHostsFile=' + $knownHosts),
        '-o','IdentitiesOnly=yes',
        '-o','IdentityAgent=none',
        '-o','ForwardAgent=no',
        '-o','ClearAllForwardings=yes',
        '-o','PermitLocalCommand=no',
        '-o','RequestTTY=no',
        '-o','ConnectTimeout=10',
        '-o','ServerAliveInterval=5',
        '-o','ServerAliveCountMax=1',
        '-o','LogLevel=ERROR',
        '-i',$key,
        ($script:RemoteUser + '@' + $PrivateEndpoint),
        $script:RemoteSentinel
    )
    [pscustomobject]@{
        Executable=$ssh
        Arguments=$arguments
        KeyPath=$key
        KnownHostsPath=$knownHosts
        CapsuleOnStdin=$true
        PrivateEndpoint=$PrivateEndpoint
    }
}

function Invoke-LdwDragonflyCanaryTransport {
    [CmdletBinding()]param(
        [Parameter(Mandatory)][string]$CapsuleJson,
        [Parameter(Mandatory)][object]$Plan,
        [scriptblock]$ProcessInvoker,
        [int]$TimeoutSeconds=780
    )
    if ([string]::IsNullOrWhiteSpace($CapsuleJson) -or $CapsuleJson.Length -gt 65536) { throw 'DRAGONFLY_CANARY_CAPSULE_INVALID' }
    if (-not [bool]$Plan.CapsuleOnStdin -or @($Plan.Arguments) -contains $CapsuleJson) { throw 'DRAGONFLY_CANARY_TRANSPORT_PLAN_INVALID' }
    $rawResult = if ($ProcessInvoker) {
        & $ProcessInvoker $Plan $CapsuleJson $TimeoutSeconds
    } else {
        if (-not (Test-Path -LiteralPath $Plan.Executable -PathType Leaf) -or
            -not (Test-Path -LiteralPath $Plan.KeyPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $Plan.KnownHostsPath -PathType Leaf)) {
            throw 'DRAGONFLY_CANARY_TRANSPORT_ARTIFACT_MISSING'
        }
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = [string]$Plan.Executable
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        foreach ($arg in @($Plan.Arguments)) { [void]$psi.ArgumentList.Add([string]$arg) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $psi
        try {
            if (-not $process.Start()) { throw 'DRAGONFLY_CANARY_SSH_START_FAILED' }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $process.StandardInput.Write($CapsuleJson)
            $process.StandardInput.Close()
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                try { $process.Kill($true) } catch {}
                throw 'DRAGONFLY_CANARY_SSH_TIMEOUT'
            }
            $process.WaitForExit()
            [pscustomobject]@{
                ExitCode=$process.ExitCode
                Stdout=$stdoutTask.GetAwaiter().GetResult()
                Stderr=$stderrTask.GetAwaiter().GetResult()
            }
        } finally { $process.Dispose() }
    }
    if ($null -eq $rawResult -or [int]$rawResult.ExitCode -ne 0) { throw 'DRAGONFLY_CANARY_TRANSPORT_FAILED' }
    try { $result = ([string]$rawResult.Stdout) | ConvertFrom-Json }
    catch { throw 'DRAGONFLY_CANARY_TRANSPORT_RESULT_INVALID' }
    if ($result.claimed -ne $true -or $result.profile_id -cne 'dragonfly-github-canary-v1' -or $null -eq $result.execution) {
        throw 'DRAGONFLY_CANARY_TRANSPORT_RESULT_INVALID'
    }
    if ($result.execution.guest_qemu_exit -cne 'PASS' -or
        $result.execution.guest_cleanup -cne 'PASS' -or
        $result.execution.state -cne 'STOPPED' -or
        [long]$result.execution.job_id -ne [long]$result.job_id -or
        [string]$result.execution.dispatch_id -cne [string]$result.dispatch_id) {
        throw 'DRAGONFLY_CANARY_EXECUTION_RESULT_INVALID'
    }
    $serialized = $result | ConvertTo-Json -Depth 8 -Compress
    if ($serialized.Contains('opaque_bootstrap')) { throw 'DRAGONFLY_CANARY_TRANSPORT_SECRET_FIELD_EXPOSED' }
    [pscustomobject]@{
        Claimed=$true
        DispatchId=[string]$result.dispatch_id
        JobId=[long]$result.job_id
        GuestQemuExit='PASS'
        GuestCleanup='PASS'
        State='STOPPED'
    }
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
    if ($RunnerId -le 0 -or $RunnerName -cnotmatch '^redrix-[1-9][0-9]*-[1-9][0-9]*$' -or $TimeoutSeconds -lt 1 -or $PollSeconds -lt 1) {
        throw 'DRAGONFLY_CANARY_MONITOR_ARGUMENT_INVALID'
    }
    $expectedLabels = @(Get-LdwDragonflyCanaryLabels -RunId ([long]$Selection.RunId))
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $assigned = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $runPath = 'repos/' + $script:Repository + '/actions/runs/' + [long]$Selection.RunId
        $jobPath = 'repos/' + $script:Repository + '/actions/jobs/' + [long]$Selection.JobId
        $run = & $ApiInvoker $runPath 'GET' $null
        $job = & $ApiInvoker $jobPath 'GET' $null
        Assert-LdwDragonflyProviderRunStable -Run $run -Selection $Selection
        if ([long](Get-LdwRuntimeObjectField $job 'id') -ne [long]$Selection.JobId -or
            [string](Get-LdwRuntimeObjectField $job 'name') -cne $script:JobName -or
            [long](Get-LdwRuntimeObjectField $job 'run_id') -ne [long]$Selection.RunId) {
            throw 'DRAGONFLY_CANARY_PROVIDER_JOB_DRIFT'
        }
        $labels = @((Get-LdwRuntimeObjectField $job 'labels'))
        if ($labels.Count -ne $expectedLabels.Count -or @(Compare-Object $expectedLabels $labels -CaseSensitive).Count) {
            throw 'DRAGONFLY_CANARY_PROVIDER_JOB_LABEL_DRIFT'
        }
        $status = [string](Get-LdwRuntimeObjectField $job 'status')
        $jobRunnerId = Get-LdwRuntimeObjectField $job 'runner_id'
        $jobRunnerName = [string](Get-LdwRuntimeObjectField $job 'runner_name')
        if ($status -in @('in_progress','completed')) {
            if ([long]$jobRunnerId -ne $RunnerId -or $jobRunnerName -cne $RunnerName) {
                throw 'DRAGONFLY_CANARY_PROVIDER_RUNNER_DRIFT'
            }
            $assigned = $true
        } elseif ($status -ne 'queued') {
            throw 'DRAGONFLY_CANARY_PROVIDER_JOB_STATUS_INVALID'
        }
        if ($status -ceq 'completed') {
            if (-not $assigned -or [string](Get-LdwRuntimeObjectField $job 'conclusion') -cne 'success') {
                throw 'DRAGONFLY_CANARY_PROVIDER_TERMINAL_FAILED'
            }
            return [pscustomobject]@{
                RunId=[long]$Selection.RunId
                JobId=[long]$Selection.JobId
                RunnerId=$RunnerId
                RunnerName=$RunnerName
                Assigned=$true
                Conclusion='success'
            }
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
        [scriptblock]$StatusProvider,
        [scriptblock]$ProcessInvoker,
        [scriptblock]$SleepInvoker,
        [string]$LocalAppData=$env:LOCALAPPDATA,
        [string]$WindowsRoot=$env:SystemRoot,
        [int]$ProviderTimeoutSeconds=360
    )
    $registration = $null
    $primary = $null
    $final = $null
    try {
        $registration = Invoke-LdwDragonflyCanaryRegistration -Run $Run -Job $Job -ExpectedHeadSha $ExpectedHeadSha -ApiInvoker $ApiInvoker
        $endpoint = Get-LdwDragonflyCanaryPrivateEndpoint -StatusProvider $StatusProvider
        $plan = New-LdwDragonflyCanarySshPlan -PrivateEndpoint $endpoint -LocalAppData $LocalAppData -WindowsRoot $WindowsRoot
        $transport = Invoke-LdwDragonflyCanaryTransport -CapsuleJson $registration.CapsuleJson -Plan $plan -ProcessInvoker $ProcessInvoker
        if ($transport.DispatchId -cne [string]$registration.Sanitized.dispatch_id -or $transport.JobId -ne [long]$registration.Selection.JobId) {
            throw 'DRAGONFLY_CANARY_TRANSPORT_CORRELATION_INVALID'
        }
        $provider = Wait-LdwDragonflyCanaryProviderTerminal -Selection $registration.Selection -RunnerId $registration.RunnerId -RunnerName $registration.RunnerName -ApiInvoker $ApiInvoker -SleepInvoker $SleepInvoker -TimeoutSeconds $ProviderTimeoutSeconds
        $final = [pscustomobject]@{
            Result='PASS'
            RunId=$provider.RunId
            JobId=$provider.JobId
            RunnerId=$provider.RunnerId
            ProviderConclusion=$provider.Conclusion
            GuestQemuExit=$transport.GuestQemuExit
            GuestCleanup=$transport.GuestCleanup
            RedrixState=$transport.State
            BootstrapExposed=$false
        }
    } catch {
        $primary = $_.Exception
    } finally {
        if ($null -ne $registration) {
            try {
                $cleanup = Remove-LdwDragonflyCanaryRegistration -Selection $registration.Selection -RunnerId $registration.RunnerId -ApiInvoker $ApiInvoker
                if (-not $cleanup.Absent) { throw 'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCONFIRMED' }
            } catch {
                throw 'DRAGONFLY_CANARY_FINAL_CLEANUP_UNCERTAIN'
            }
        }
    }
    if ($null -ne $primary) { throw $primary }
    if ($null -eq $final) { throw 'DRAGONFLY_CANARY_RESULT_MISSING' }
    $final
}

Export-ModuleMember -Function Get-LdwDragonflyCanaryPrivateEndpoint,New-LdwDragonflyCanarySshPlan,Invoke-LdwDragonflyCanaryTransport,Wait-LdwDragonflyCanaryProviderTerminal,Invoke-LdwDragonflyCanaryOnce
