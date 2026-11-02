[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Uninstall')][string]$Mode = 'Plan',
    [switch]$AcceptInstall,
    [switch]$AcceptUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Accepted control-source blob identities for Manage and Invoke scripts.
# Pinned for fail-closed bootstrap provenance verification.
$acceptedManageBlob = 'c6e5259083ced5a368ee97a2a181b99f380460ad'
$acceptedWorkerBlob = '0816c7ee063135648d210229903de9a67cc46e86'
$manageRelative = 'host-agent/deploy/Manage-AdminPrivilegedHelper.ps1'
$workerRelative = 'host-agent/deploy/Invoke-AdminPrivilegedOperation.ps1'

function Invoke-GitRead([string[]]$Arguments) {
    $value = & git @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'SOURCE_GIT_READ_FAILED' }
    @($value)
}

function Assert-AcceptedCheckout {
    $repoRoot = (Invoke-GitRead @('-C', $PSScriptRoot, 'rev-parse', '--show-toplevel') | Select-Object -First 1).Trim()
    if (-not $repoRoot) { throw 'SOURCE_CHECKOUT_REQUIRED' }

    $remoteOrigin = (Invoke-GitRead @('-C', $repoRoot, 'config', '--get', 'remote.origin.url') | Select-Object -First 1).Trim()
    if ($remoteOrigin -cnotmatch 'LowcountryDigitalWorks/infrastructure-tools(\.git)?$') {
        throw 'SOURCE_ORIGIN_REFUSED'
    }

    $branch = (Invoke-GitRead @('-C', $repoRoot, 'branch', '--show-current') | Select-Object -First 1).Trim()
    if ($branch -cne 'main') { throw 'SOURCE_MAIN_REQUIRED' }

    $dirty = @(Invoke-GitRead @('-C', $repoRoot, 'status', '--porcelain'))
    if ($dirty.Count -ne 0) { throw 'SOURCE_WORKTREE_DIRTY' }

    $head = (Invoke-GitRead @('-C', $repoRoot, 'rev-parse', 'HEAD') | Select-Object -First 1).Trim()
    $originMain = (Invoke-GitRead @('-C', $repoRoot, 'rev-parse', 'refs/remotes/origin/main') | Select-Object -First 1).Trim()
    if ($head -cne $originMain) { throw 'SOURCE_MAIN_NOT_CURRENT' }

    $manageBlob = (Invoke-GitRead @('-C', $repoRoot, 'rev-parse', ("HEAD:$manageRelative")) | Select-Object -First 1).Trim()
    $workerBlob = (Invoke-GitRead @('-C', $repoRoot, 'rev-parse', ("HEAD:$workerRelative")) | Select-Object -First 1).Trim()
    if ($manageBlob -cne $acceptedManageBlob -or $workerBlob -cne $acceptedWorkerBlob) {
        throw 'ACCEPTED_CONTROL_SOURCE_CHANGED'
    }

    [pscustomobject]@{ Root = $repoRoot; Head = $head }
}

$checkout = Assert-AcceptedCheckout

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.User -or $identity.User.Value -cnotmatch '^S-1-5-21-(\d+-){3}\d+$') {
    throw 'OWNER_SID_REQUIRED'
}
$ownerSid = $identity.User.Value
$managePath = Join-Path $checkout.Root $manageRelative

$parameters = @{
    Mode = $Mode
    OwnerSid = $ownerSid
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
'ADMIN_PRIVILEGED_HELPER_BOOTSTRAP=PASS'
