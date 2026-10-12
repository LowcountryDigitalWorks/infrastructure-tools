[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree,
    [ValidateSet('Once','Discover','Poll','Recover')][string]$Mode = 'Once',
    [ValidateRange(1,60)][int]$PollCount = 1,
    [ValidateRange(15,300)][int]$PollSeconds = 30,
    [ValidateRange(0,30)][int]$DiscoverHoldSeconds = 0
)
$ErrorActionPreference = 'Stop'

function Assert-Ci10PreImportParentBoundary {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PREFLIGHT_REPARSE_PATH_REFUSED' }
    $acl = Get-Acl -LiteralPath $full
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'PREFLIGHT_PARENT_OWNER_UNTRUSTED'
    }
    $replace = [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $replace) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'PREFLIGHT_PARENT_REPLACEMENT_UNTRUSTED'
        }
    }
}

function Assert-Ci10PreImportProtectedPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PREFLIGHT_REPARSE_PATH_REFUSED' }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    $acl = Get-Acl -LiteralPath $full
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'PREFLIGHT_OWNER_UNTRUSTED'
    }
    $write = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'PREFLIGHT_ACL_UNTRUSTED_WRITE'
        }
    }
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        if (-not @($rules | Where-Object {
            $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' -and
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl
        }).Count) {
            throw 'PREFLIGHT_ACL_REQUIRED_PRINCIPAL_MISSING'
        }
    }
}

$bundle = Split-Path $PSScriptRoot -Parent
$dispatchRoot = Join-Path $env:ProgramData 'LDW/CiRunnerDispatch'
$controllerRoot = Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'
$lock = $null
$verified = $false
try {
    # Establish the protected filesystem boundary before reading the manifest or importing executable module content.
    # These checks intentionally use only built-in PowerShell/.NET primitives defined in this entrypoint.
    $bundle = [IO.Path]::GetFullPath($bundle)
    $releases = [IO.Path]::GetDirectoryName($bundle)
    $releaseRoot = [IO.Path]::GetDirectoryName($releases)
    $parent = [IO.Path]::GetDirectoryName($releaseRoot)
    $grandparent = [IO.Path]::GetDirectoryName($parent)
    $manifestPath = Join-Path $bundle 'manifest.json'
    $entryPath = [IO.Path]::GetFullPath($PSCommandPath)
    $expectedEntry = [IO.Path]::GetFullPath((Join-Path $bundle 'ci-dispatch/Invoke-Dispatcher.ps1'))
    $modulePath = [IO.Path]::GetFullPath((Join-Path $bundle 'ci-dispatch/Dispatch.psm1'))
    if ($entryPath -cne $expectedEntry) { throw 'PREFLIGHT_ENTRY_PATH_MISMATCH' }

    foreach ($path in @($releaseRoot,$releases,$bundle,$PSScriptRoot,$manifestPath,$entryPath,$modulePath)) {
        Assert-Ci10PreImportProtectedPath $path
    }
    Assert-Ci10PreImportParentBoundary $parent
    Assert-Ci10PreImportParentBoundary $grandparent

    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha) {
        throw 'MANIFEST_HASH_DRIFT'
    }
    $preflight = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($preflight.schema -ne 1 -or $preflight.commit -cne $Commit -or $preflight.tree -cne $Tree) {
        throw 'PREFLIGHT_PROVENANCE_MISMATCH'
    }
    foreach ($path in @('ci-dispatch/Invoke-Dispatcher.ps1','ci-dispatch/Dispatch.psm1')) {
        $entry = @($preflight.files | Where-Object path -CEQ $path)
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            (Get-FileHash -LiteralPath (Join-Path $bundle $path) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[0].sha256) {
            throw 'DISPATCHER_PREFLIGHT_HASH_DRIFT'
        }
    }

    Import-Module $modulePath -Force
    $null = Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
    $verified = $true
    if ($DiscoverHoldSeconds -and $Mode -cne 'Discover') { throw 'DISCOVERY_HOLD_REQUIRES_DISCOVER_MODE' }
    Import-Module (Join-Path $bundle 'ci-runner/CiRunner.psm1') -Force
    Assert-Ci7Elevated
    $profiles = @(Read-Ci10Profiles (Join-Path $PSScriptRoot 'profiles.json'))
    $lock = Enter-Ci10DispatcherLock $dispatchRoot
    Write-Ci10Log $dispatchRoot start
    for ($poll = 0; $poll -lt $(if ($Mode -eq 'Poll') { $PollCount } else { 1 }); $poll++) {
        $null = Assert-Ci10Bundle $bundle $ManifestSha $Commit $Tree
        $gate = Get-Ci10ControllerGate $controllerRoot $profiles[0]
        if ($gate -eq 'STALE') {
            # Select exact validated state IDs. Root-wide Reap could include another workload appearing after the probe.
            foreach ($runId in @(Get-Ci10StaleRunIds $controllerRoot $profiles[0])) {
                Start-Ci10Controller $bundle $controllerRoot -CleanupRunId $runId
            }
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
                    # Bounded manual interruption seam: this mode can never launch a controller.
                    if ($DiscoverHoldSeconds) { Start-Sleep -Seconds $DiscoverHoldSeconds }
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
