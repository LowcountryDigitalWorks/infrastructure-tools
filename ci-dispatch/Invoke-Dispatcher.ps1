[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [ValidateSet('Once','Discover','Poll','Recover')][string]$Mode = 'Once',
    [ValidateRange(1,60)][int]$PollCount = 1,
    [ValidateRange(15,300)][int]$PollSeconds = 30
)
$ErrorActionPreference = 'Stop'
$bundle = Split-Path $PSScriptRoot -Parent
$dispatchRoot = Join-Path $env:ProgramData 'LDW/CiRunnerDispatch'
$controllerRoot = Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'
$lock = $null
$verified = $false
try {
    # Authenticate the manifest and both dispatcher scripts before loading the module.
    # Protected ACLs are the execution trust boundary; an administrator is already inside that boundary.
    $manifestPath = Join-Path $bundle 'manifest.json'
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha) { throw 'MANIFEST_HASH_DRIFT' }
    $preflight = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    foreach ($path in @('ci-dispatch/Invoke-Dispatcher.ps1','ci-dispatch/Dispatch.psm1')) {
        $entry = @($preflight.files | Where-Object path -CEQ $path)
        if ($entry.Count -ne 1 -or (Get-FileHash -LiteralPath (Join-Path $bundle $path) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[0].sha256) {
            throw 'DISPATCHER_PREFLIGHT_HASH_DRIFT'
        }
    }
    Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1') -Force
    $null = Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
    $verified = $true
    Import-Module (Join-Path $bundle 'ci-runner/CiRunner.psm1') -Force
    Assert-Ci7Elevated
    $profiles = @(Read-Ci10Profiles (Join-Path $PSScriptRoot 'profiles.json'))
    $lock = Enter-Ci10DispatcherLock $dispatchRoot
    Write-Ci10Log $dispatchRoot start
    for ($poll = 0; $poll -lt $(if ($Mode -eq 'Poll') { $PollCount } else { 1 }); $poll++) {
        $null = Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
        $gate = Get-Ci10ControllerGate $controllerRoot $profiles[0]
        if ($gate -eq 'STALE') {
            # Reap is the accepted primitive, never a prefix-only deletion implementation.
            Start-Ci10Controller $bundle $controllerRoot -Reap
            Write-Ci10Log $dispatchRoot reap-pass
            $gate = Get-Ci10ControllerGate $controllerRoot $profiles[0]
        }
        if ($Mode -eq 'Recover') {
            if ($gate -notin @('READY','CAPACITY')) { throw 'RECOVERY_BUSY_OR_UNCERTAIN' }
            'DISPATCHER_RESULT=RECOVERED'
            break
        }
        if ($gate -in @('BUSY','CAPACITY')) {
            Write-Ci10Log $dispatchRoot $gate.ToLowerInvariant()
            'DISPATCHER_RESULT=' + $gate
        } elseif ($gate -ceq 'READY') {
            $selected = @(Find-Ci10QueuedJob $profiles)
            Write-Ci10Log $dispatchRoot poll-pass
            if (-not $selected.Count) {
                Write-Ci10Log $dispatchRoot idle
                'DISPATCHER_RESULT=IDLE'
            } else {
                $candidate = Confirm-Ci10Candidate $selected[0]
                Write-Ci10Log $dispatchRoot selected -RunId $candidate.RunId
                if ($Mode -eq 'Discover') {
                    Write-Ci10Log $dispatchRoot discovery-only -RunId $candidate.RunId
                    'DISPATCHER_RESULT=DISCOVERED'
                    'DISCOVERED_RUN_ID=' + $candidate.RunId
                    'DISCOVERED_JOB_ID=' + $candidate.JobId
                    'DISCOVERED_HEAD_SHA=' + $candidate.Sha
                } else {
                    # The probe lock is released before launch. Controller closes the race independently.
                    # Re-read immediately after the final provenance and capacity checks.
                    $null = Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
                    $gate = Get-Ci10ControllerGate $controllerRoot $candidate.Profile
                    if ($gate -cne 'READY') { throw 'CONTROLLER_GATE_CHANGED' }
                    $candidate = Confirm-Ci10Candidate $candidate
                    Write-Ci10Log $dispatchRoot controller-start -RunId $candidate.RunId
                    Start-Ci10Controller $bundle $controllerRoot $candidate
                    if ((Get-Ci10ControllerGate $controllerRoot $candidate.Profile) -cne 'READY') { throw 'CLEANUP_UNCONFIRMED' }
                    Write-Ci10Log $dispatchRoot controller-pass -RunId $candidate.RunId
                    'DISPATCHER_RESULT=PASS'
                    'DISCOVERED_RUN_ID=' + $candidate.RunId
                    'DISCOVERED_JOB_ID=' + $candidate.JobId
                    'DISCOVERED_HEAD_SHA=' + $candidate.Sha
                }
            }
        } else { throw 'CONTROLLER_GATE_UNCERTAIN' }
        if ($Mode -eq 'Poll' -and $poll -lt $PollCount - 1) { Start-Sleep -Seconds $PollSeconds }
    }
} catch {
    if ($verified -and $lock) { try { Write-Ci10Log $dispatchRoot poll-fail } catch {} }
    $classification = [string]$_.Exception.Message
    if ($classification -cnotmatch '^[A-Z][A-Z0-9_]+$') { $classification = 'DISPATCHER_OPERATION_FAILED' }
    'DISPATCHER_RESULT=FAIL'
    'CLASSIFICATION=' + $classification
    exit 1
} finally {
    if ($lock) { try { Write-Ci10Log $dispatchRoot stop } catch {}; $lock.Dispose() }
}
