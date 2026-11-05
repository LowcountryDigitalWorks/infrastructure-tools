# Read-only deterministic/synthetic proof; never launches production, GitHub
# CLI, a runner or KVM, and never reads credential/transport material.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$modulePath = Join-Path $root 'DragonflyGateBPowerShellRuntime.psm1'
$providerPath = Join-Path $root 'Invoke-DragonflyCanaryProduction.ps1'
$providerText = [IO.File]::ReadAllText($providerPath)
if (-not $providerText.Contains('$psi.ArgumentList.Add($arg)') -or
    -not $providerText.Contains('$psi.ArgumentList.Add(')) {
    throw 'DRAGONFLY_GATEB_PROVIDER_ARGUMENT_LIST_CONTRACT_CHANGED'
}
$m = Import-Module -Name $modulePath -Force -PassThru
if ($null -eq $m) { throw 'DRAGONFLY_GATEB_RUNTIME_MODULE_MISSING' }
$exports = @(Get-Command -Module $m.Name | Select-Object -ExpandProperty Name)
if ($exports.Count -ne 1 -or $exports[0] -cne 'Assert-LdwDragonflyProviderShell') {
    throw 'DRAGONFLY_GATEB_RUNTIME_EXPORT_SURFACE_CHANGED'
}

$cases = @(
    [pscustomobject]@{Major=5;Edition='Desktop';Windows=$true;Api=$false;Ok=$false},
    [pscustomobject]@{Major=5;Edition='Desktop';Windows=$true;Api=$true;Ok=$false},
    [pscustomobject]@{Major=7;Edition='Core';Windows=$true;Api=$true;Ok=$true},
    [pscustomobject]@{Major=7;Edition='Core';Windows=$true;Api=$false;Ok=$false},
    [pscustomobject]@{Major=7;Edition='Desktop';Windows=$true;Api=$true;Ok=$false},
    [pscustomobject]@{Major=7;Edition='Core';Windows=$false;Api=$true;Ok=$false},
    [pscustomobject]@{Major=6;Edition='Core';Windows=$true;Api=$true;Ok=$false},
    [pscustomobject]@{Major=8;Edition='Core';Windows=$true;Api=$true;Ok=$true}
)
foreach ($case in $cases) {
    $observed = & $m {
        param($major,$edition,$windows,$api)
        Test-LdwDragonflyProviderShellContract -Major $major -Edition $edition -Windows $windows -HasArgumentList $api
    } $case.Major $case.Edition $case.Windows $case.Api
    if ([bool]$observed -ne [bool]$case.Ok) {
        throw 'DRAGONFLY_GATEB_RUNTIME_SYNTHETIC_POLICY_FAILED'
    }
}

$isWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$hasApi = $null -ne [Diagnostics.ProcessStartInfo].GetProperty('ArgumentList')
$expectedPositive = $isWindows -and $PSVersionTable.PSEdition -ceq 'Core' -and
    $PSVersionTable.PSVersion.Major -ge 7 -and $hasApi
if ($expectedPositive) {
    $result = Assert-LdwDragonflyProviderShell
    if ($result -cne 'DRAGONFLY_GATEB_PWSH7_RUNTIME=PASS_LOCAL_ONLY') {
        throw 'DRAGONFLY_GATEB_RUNTIME_POSITIVE_MISSING'
    }
} else {
    $caught = $false
    try { $null = Assert-LdwDragonflyProviderShell }
    catch { $caught = [string]$_.Exception.Message -ceq 'DRAGONFLY_GATEB_PWSH7_REQUIRED' }
    if (-not $caught) { throw 'DRAGONFLY_GATEB_RUNTIME_UNSAFE_HOST_ACCEPTED' }
}
'DRAGONFLY_GATEB_PWSH7_SYNTHETIC=PASS'
