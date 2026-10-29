[CmdletBinding()]
param(
    [Parameter(Mandatory)][long]$RunId,
    [Parameter(Mandatory)][int]$RunAttempt,
    [Parameter(Mandatory)][long]$JobId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$HeadSha
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Repository = 'LowcountryDigitalWorks/infrastructure-tools'
$script:DispatcherRoot = Join-Path $env:ProgramData 'LDW\CiRunnerDispatch'

function Invoke-LdwDragonflyCanaryGhWrite {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('POST','DELETE')][string]$Method,
        [object]$Body
    )
    if ($Method -ceq 'POST') {
        if ($Path -cne ('repos/' + $script:Repository + '/actions/runners/generate-jitconfig') -or $null -eq $Body) {
            throw 'DRAGONFLY_CANARY_API_WRITE_SCOPE_REFUSED'
        }
        $required = @('name','runner_group_id','labels','work_folder')
        if (@(Compare-Object $required @($Body.Keys) -CaseSensitive).Count -or
            [string]$Body.name -cnotmatch '^redrix-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*$' -or
            [int]$Body.runner_group_id -ne 1 -or [string]$Body.work_folder -cne '_work' -or
            @($Body.labels).Count -ne 9) {
            throw 'DRAGONFLY_CANARY_API_WRITE_BODY_REFUSED'
        }
    } else {
        if ($Path -cnotmatch ('^repos/' + [regex]::Escape($script:Repository) + '/actions/runners/[1-9][0-9]*$') -or $null -ne $Body) {
            throw 'DRAGONFLY_CANARY_API_WRITE_SCOPE_REFUSED'
        }
    }

    $gh = (Get-Command gh.exe -ErrorAction Stop).Source
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $gh
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    foreach ($arg in @('api','--method',$Method,$Path)) { [void]$psi.ArgumentList.Add($arg) }
    if ($Method -ceq 'POST') {
        $psi.RedirectStandardInput = $true
        [void]$psi.ArgumentList.Add('--input')
        [void]$psi.ArgumentList.Add('-')
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    try {
        if (-not $process.Start()) { throw 'DRAGONFLY_CANARY_API_WRITE_FAILED' }
        if ($Method -ceq 'POST') {
            $payload = $Body | ConvertTo-Json -Depth 4 -Compress
            if ($payload.Length -gt 8192) { throw 'DRAGONFLY_CANARY_API_WRITE_BODY_REFUSED' }
            $process.StandardInput.Write($payload)
            $process.StandardInput.Close()
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill($true) } catch {}
            throw 'DRAGONFLY_CANARY_API_WRITE_TIMEOUT'
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $null = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'DRAGONFLY_CANARY_API_WRITE_FAILED' }
        if ($Method -ceq 'DELETE') {
            if (-not [string]::IsNullOrWhiteSpace($stdout)) { throw 'DRAGONFLY_CANARY_API_DELETE_RESPONSE_INVALID' }
            return $null
        }
        if ([string]::IsNullOrWhiteSpace($stdout) -or $stdout.Length -gt 131072) {
            throw 'DRAGONFLY_CANARY_API_WRITE_RESPONSE_INVALID'
        }
        try { return $stdout | ConvertFrom-Json -ErrorAction Stop }
        catch { throw 'DRAGONFLY_CANARY_API_WRITE_RESPONSE_INVALID' }
    } finally {
        $process.Dispose()
    }
}

function Invoke-LdwDragonflyCanaryProviderApi {
    param([string]$Path,[string]$Method,[object]$Body)
    if ($Method -ceq 'GET') {
        if ($null -ne $Body) { throw 'DRAGONFLY_CANARY_API_READ_BODY_REFUSED' }
        return Invoke-Ci10Read $Path
    }
    if ($Method -cin @('POST','DELETE')) {
        return Invoke-LdwDragonflyCanaryGhWrite -Path $Path -Method $Method -Body $Body
    }
    throw 'DRAGONFLY_CANARY_API_METHOD_REFUSED'
}

try {
    if ($RunId -le 0 -or $RunAttempt -le 0 -or $JobId -le 0) { throw 'DRAGONFLY_CANARY_ENTRY_IDENTITY_INVALID' }
    if ([string]::IsNullOrWhiteSpace($env:ProgramData) -or -not [IO.Path]::IsPathRooted($env:ProgramData)) {
        throw 'DRAGONFLY_CANARY_PROGRAMDATA_INVALID'
    }

    Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot 'DragonflyCanary.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot 'DragonflyCanaryRuntime.psm1') -Force

    $runPath = 'repos/' + $script:Repository + '/actions/runs/' + $RunId
    $jobsPath = $runPath + '/attempts/' + $RunAttempt + '/jobs?per_page=100'
    $run = Invoke-Ci10Read $runPath
    $jobsResponse = Invoke-Ci10Read $jobsPath
    $jobs = @($jobsResponse.jobs)
    if ([long]$jobsResponse.total_count -lt 1 -or [long]$jobsResponse.total_count -gt 100 -or
        $jobs.Count -ne [long]$jobsResponse.total_count) {
        throw 'DRAGONFLY_CANARY_ENTRY_JOB_LIST_INVALID'
    }
    $matches = @($jobs | Where-Object { [long]$_.id -eq $JobId })
    if ($matches.Count -ne 1) { throw 'DRAGONFLY_CANARY_ENTRY_JOB_NOT_UNIQUE' }

    $api = { param($Path,$Method,$Body) Invoke-LdwDragonflyCanaryProviderApi -Path $Path -Method $Method -Body $Body }
    $result = Invoke-LdwDragonflyCanaryOnce -Run $run -Job $matches[0] -ExpectedHeadSha $HeadSha `
        -ApiInvoker $api -DispatcherRoot $script:DispatcherRoot

    [ordered]@{
        schema='dragonfly-canary-production-v1'
        result=[string]$result.Result
        run_id=[long]$result.RunId
        run_attempt=[int]$result.RunAttempt
        job_id=[long]$result.JobId
        provider_conclusion=[string]$result.ProviderConclusion
        guest_qemu_exit=[string]$result.GuestQemuExit
        guest_cleanup=[string]$result.GuestCleanup
        redrix_state=[string]$result.RedrixState
        bootstrap_exposed=[bool]$result.BootstrapExposed
        ci10_serialized=[bool]$result.Ci10Serialized
    } | ConvertTo-Json -Compress
    exit 0
} catch {
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z0-9_]+$') { $code = 'DRAGONFLY_CANARY_PRODUCTION_FAILED' }
    'DRAGONFLY_CANARY_PRODUCTION=HOLD'
    'CLASSIFICATION=' + $code
    exit 1
}
