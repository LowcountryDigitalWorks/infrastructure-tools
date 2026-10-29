[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Uninstall')][string]$Mode = 'Plan',
    [switch]$AcceptInstall,
    [switch]$AcceptUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Accepted PR #135 squash merge and exact installer blob. This provenance refresh
# does not lift #92 DO_NOT_RETRY_INSTALL / DO_NOT_HAND_EDIT; a later controlling
# disposition is required before owner-local installation or residue reconciliation.
$acceptedSourceCommit = '7755a1f490b2568d228717bd22f8fccd80c529ea'
$acceptedManageBlob = '58b23af25b7e4fe7da17809d9749704fc7366f56'
$acceptedWorkerBlob = '1877c993dabe7e9d1e2a712a317a0d935ab74dfd'
$manifestSha = 'd10cad356a8ee8cb6201a6167b2ca5ab732a967f1945fe543520454c643ae964'
$controllerCommit = '54b9343af44c70db1d1403cf7f45cfc11e8bf167'
$controllerTree = 'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec'
$manageRelative = 'host-agent/deploy/Manage-CiJitControlTasks.ps1'
$workerRelative = 'host-agent/deploy/Invoke-CiJitControlTask.ps1'

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
    if ($manageBlob -cne $acceptedManageBlob -or $workerBlob -cne $acceptedWorkerBlob) {
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
