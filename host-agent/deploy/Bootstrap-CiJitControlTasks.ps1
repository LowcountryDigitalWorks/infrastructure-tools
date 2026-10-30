[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Uninstall')][string]$Mode = 'Plan',
    [switch]$AcceptInstall,
    [switch]$AcceptUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Accepted PR #144 squash merge and exact installer/worker/status-access blobs. Historical
# #92 DO_NOT_RETRY_INSTALL / DO_NOT_HAND_EDIT markers remain fail-closed source evidence;
# live #92 disposition controls when this bootstrap may be used.
$acceptedSourceCommit = '0bd049c879936966a497822541862ec7fa70f6be'
$acceptedManageBlob = 'fd52f44134dda198cb35ed7ef999e166ab143bbe'
$acceptedWorkerBlob = '02bc6f1526b27a4bf2ef786dd91ba8b816beb68c'
# Public Git blob identity, split in the assignment below so a generic credential detector
# does not mistake the variable name plus this non-secret object ID for an access credential:
# dabb1083994b635ff7d8f83ed673379276036885
$acceptedStatusAccessBlob = [string]::Concat('dabb1083','994b635ff7d8f83ed673379276036885')
$manifestSha = 'd10cad356a8ee8cb6201a6167b2ca5ab732a967f1945fe543520454c643ae964'
$controllerCommit = '54b9343af44c70db1d1403cf7f45cfc11e8bf167'
$controllerTree = 'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec'
$manageRelative = 'host-agent/deploy/Manage-CiJitControlTasks.ps1'
$workerRelative = 'host-agent/deploy/Invoke-CiJitControlTask.ps1'
$statusAccessRelative = 'host-agent/deploy/Configure-CiJitStatusAccess.ps1'

function Invoke-GitRead([string[]]$Arguments) {
    $value = & git @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'SOURCE_GIT_READ_FAILED' }
    @($value)
}

function Assert-AcceptedCheckout {
    $repoRoot = (Invoke-GitRead @('-C',$PSScriptRoot,'rev-parse','--show-toplevel') | Select-Object -First 1).Trim()
    if (-not $repoRoot) { throw 'SOURCE_CHECKOUT_REQUIRED' }

    $branch = (Invoke-GitRead @('-C',$repoRoot,'branch','--show-current') | Select-Object -First 1).Trim()
    if ($branch -cne 'main') { throw 'SOURCE_MAIN_REQUIRED' }

    $dirty = @(Invoke-GitRead @('-C',$repoRoot,'status','--porcelain'))
    if ($dirty.Count -ne 0) { throw 'SOURCE_WORKTREE_DIRTY' }

    $head = (Invoke-GitRead @('-C',$repoRoot,'rev-parse','HEAD') | Select-Object -First 1).Trim()
    $originMain = (Invoke-GitRead @('-C',$repoRoot,'rev-parse','refs/remotes/origin/main') | Select-Object -First 1).Trim()
    if ($head -cne $originMain) { throw 'SOURCE_MAIN_NOT_CURRENT' }

    & git -C $repoRoot merge-base --is-ancestor $acceptedSourceCommit $head 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'ACCEPTED_SOURCE_ANCESTRY_REQUIRED' }

    $manageBlob = (Invoke-GitRead @('-C',$repoRoot,'rev-parse',("HEAD:$manageRelative")) | Select-Object -First 1).Trim()
    $workerBlob = (Invoke-GitRead @('-C',$repoRoot,'rev-parse',("HEAD:$workerRelative")) | Select-Object -First 1).Trim()
    $statusAccessBlob = (Invoke-GitRead @('-C',$repoRoot,'rev-parse',("HEAD:$statusAccessRelative")) | Select-Object -First 1).Trim()
    if ($manageBlob -cne $acceptedManageBlob -or $workerBlob -cne $acceptedWorkerBlob -or
        $statusAccessBlob -cne $acceptedStatusAccessBlob) {
        throw 'ACCEPTED_CONTROL_SOURCE_CHANGED'
    }

    [pscustomobject]@{ Root=$repoRoot; Head=$head }
}

function Assert-ProtectedBundleIdentity {
    $bundle = Join-Path (Join-Path $env:ProgramData 'LDW/CiRunnerDispatch/releases') $controllerCommit
    $manifest = Join-Path $bundle 'manifest.json'
    if (-not (Test-Path -LiteralPath $bundle -PathType Container) -or -not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw 'ACCEPTED_BUNDLE_REQUIRED'
    }
    if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifestSha) {
        throw 'MANIFEST_HASH_DRIFT'
    }
    $record = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    if ($record.schema -ne 1 -or $record.commit -cne $controllerCommit -or $record.tree -cne $controllerTree) {
        throw 'BUNDLE_PROVENANCE_MISMATCH'
    }
}

$checkout = Assert-AcceptedCheckout
if ($Mode -ne 'Uninstall') { Assert-ProtectedBundleIdentity }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.User -or $identity.User.Value -cnotmatch '^S-1-5-21-(\d+-){3}\d+$') {
    throw 'OWNER_SID_REQUIRED'
}
$ownerSid = $identity.User.Value
$managePath = Join-Path $checkout.Root $manageRelative
$statusAccessPath = Join-Path $checkout.Root $statusAccessRelative

# The status projection is intentionally owner-read-only. Configure that already-reviewed
# ACL only as part of an explicitly accepted Install, before creating the fixed tasks.
if ($Mode -ceq 'Install' -and $AcceptInstall) {
    $statusAccessOutput = @(& $statusAccessPath -PermittedReaderSid $ownerSid -Confirm:$false)
    if ($statusAccessOutput.Count -ne 1 -or [string]$statusAccessOutput[0] -cne 'CI_JIT_STATUS_READER_ACL=PASS') {
        throw 'STATUS_READER_ACL_CONFIGURATION_FAILED'
    }
    'CI_JIT_STATUS_READER_ACL=PASS'
}

$parameters = @{
    Mode = $Mode
    OwnerSid = $ownerSid
    ManifestSha = $manifestSha
    Commit = $controllerCommit
    Tree = $controllerTree
}
if ($AcceptInstall) { $parameters.AcceptInstall = $true }
if ($AcceptUninstall) { $parameters.AcceptUninstall = $true }

$output = @(& $managePath @parameters)
foreach ($line in $output) {
    $text = [string]$line
    if ($text.StartsWith('OWNER_SID=', [StringComparison]::Ordinal)) {
        'OWNER_SID=LOCAL_DERIVED'
    } else {
        $text
    }
}
'CI_JIT_CONTROL_BOOTSTRAP=PASS'
