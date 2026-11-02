[CmdletBinding()]
param(
    [ValidateSet('Plan','Install','Status','Uninstall')][string]$Mode = 'Plan',
    [switch]$AcceptInstall,
    [switch]$AcceptUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

    [pscustomobject]@{ Root = $repoRoot }
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
