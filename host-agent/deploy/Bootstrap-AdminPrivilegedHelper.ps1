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
$acceptedManageBlob = '29082de02e274718bb930eb22c436eee40531502'
$acceptedWorkerBlob = '65e636da2db591c5723def815eab16795e6c82b5'
$acceptedManageSha256 = 'a29caaaba5c7186bbd3d64a2dbd462ffa66e7a01cc245b7a57a7e63f03b05681'
$acceptedWorkerSha256 = 'db71da0a73f2943eb8837e7c1e7070a22251478e4acfba91338837c7fc699605'

$manageRelative = 'host-agent/deploy/Manage-AdminPrivilegedHelper.ps1'
$workerRelative = 'host-agent/deploy/Invoke-AdminPrivilegedOperation.ps1'

$approvedOrigins = @(
    'https://github.com/LowcountryDigitalWorks/infrastructure-tools.git',
    'https://github.com/LowcountryDigitalWorks/infrastructure-tools',
    'git@github.com:LowcountryDigitalWorks/infrastructure-tools.git'
)

function Invoke-GitRead([string[]]$Arguments) {
    $value = & git @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'SOURCE_GIT_READ_FAILED' }
    @($value)
}

function Assert-AcceptedCheckout {
    $repoRoot = (Invoke-GitRead @('-C', $PSScriptRoot, 'rev-parse', '--show-toplevel') | Select-Object -First 1).Trim()
    if (-not $repoRoot) { throw 'SOURCE_CHECKOUT_REQUIRED' }

    $remoteOrigin = (Invoke-GitRead @('-C', $repoRoot, 'config', '--get', 'remote.origin.url') | Select-Object -First 1).Trim()
    if ($approvedOrigins -notcontains $remoteOrigin) {
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

# Materialize pinned Git blobs to an administrator-protected staging path at use time
# to eliminate mutable-working-tree TOCTOU attack surface.
$stagingRoot = Join-Path $env:ProgramData 'LDW/PrivilegedControl/staging'
if (-not (Test-Path -LiteralPath $stagingRoot)) {
    $null = New-Item -ItemType Directory -Path $stagingRoot -Force
}

# Set protected ACL on staging: SYSTEM and Administrators FullControl only
$stagingAcl = [Security.AccessControl.DirectorySecurity]::new()
$stagingAcl.SetAccessRuleProtection($true, $false)
$stagingAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach ($adminSid in @('S-1-5-18', 'S-1-5-32-544')) {
    $stagingAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($adminSid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
Set-Acl -LiteralPath $stagingRoot -AclObject $stagingAcl

$stagedManagePath = Join-Path $stagingRoot 'Manage-AdminPrivilegedHelper.ps1'
$stagedWorkerPath = Join-Path $stagingRoot 'Invoke-AdminPrivilegedOperation.ps1'

# Extract exact bytes from Git object database by immutable blob ID
$manageBytes = & git -C $checkout.Root cat-file blob $acceptedManageBlob
[IO.File]::WriteAllBytes($stagedManagePath, [Text.Encoding]::UTF8.GetBytes(($manageBytes -join "`n") + "`n"))
$workerBytes = & git -C $checkout.Root cat-file blob $acceptedWorkerBlob
[IO.File]::WriteAllBytes($stagedWorkerPath, [Text.Encoding]::UTF8.GetBytes(($workerBytes -join "`n") + "`n"))

# Verify content hashes at use time
$actualManageSha = (Get-FileHash -LiteralPath $stagedManagePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualManageSha -cne $acceptedManageSha256) {
    throw 'STAGED_MANAGER_PROVENANCE_MISMATCH'
}
$actualWorkerSha = (Get-FileHash -LiteralPath $stagedWorkerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualWorkerSha -cne $acceptedWorkerSha256) {
    throw 'STAGED_WORKER_PROVENANCE_MISMATCH'
}

$parameters = @{
    Mode = $Mode
    OwnerSid = $ownerSid
    WorkerSourcePath = $stagedWorkerPath
}
if ($AcceptInstall) { $parameters.AcceptInstall = $true }
if ($AcceptUninstall) { $parameters.AcceptUninstall = $true }

try {
    $output = @(& $stagedManagePath @parameters)
    foreach ($line in $output) {
        $text = [string]$line
        if ($text.StartsWith('OWNER_SID=', [StringComparison]::Ordinal)) {
            'OWNER_SID=LOCAL_DERIVED'
        } else {
            $text
        }
    }
    'ADMIN_PRIVILEGED_HELPER_BOOTSTRAP=PASS'
} finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
