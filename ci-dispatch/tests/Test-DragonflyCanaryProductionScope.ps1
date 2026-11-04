# Source-only Gate B regression: PowerShell 7 production import visibility.
# Does not require GitHub credentials, protected ACLs, transport, or provider writes.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$entryPath = Join-Path $root 'Invoke-DragonflyCanaryProduction.ps1'
$entry = [IO.File]::ReadAllText($entryPath)

$runtimeImport = "Import-Module (Join-Path `$PSScriptRoot 'DragonflyCanaryRuntime.psm1') -Force"
$dispatchImport = "Import-Module (Join-Path `$PSScriptRoot 'Dispatch.psm1') -Global -Force"
$runtimeIndex = $entry.IndexOf($runtimeImport, [StringComparison]::Ordinal)
$dispatchIndex = $entry.IndexOf($dispatchImport, [StringComparison]::Ordinal)
if ($runtimeIndex -lt 0 -or $dispatchIndex -le $runtimeIndex) {
    throw 'DRAGONFLY_CANARY_PRODUCTION_IMPORT_ORDER_INVALID'
}
if (-not $entry.Contains("throw 'DRAGONFLY_CANARY_CI10_READ_NOT_BOUND'")) {
    throw 'DRAGONFLY_CANARY_PRODUCTION_BINDING_GUARD_MISSING'
}

$lockGuardIndex = $entry.IndexOf("throw 'DRAGONFLY_CANARY_CI10_LOCK_NOT_BOUND'", [StringComparison]::Ordinal)
$firstProviderReadIndex = $entry.IndexOf('$run = Invoke-Ci10Read $runPath', [StringComparison]::Ordinal)
if ($lockGuardIndex -le $dispatchIndex -or $firstProviderReadIndex -le $lockGuardIndex) {
    throw 'DRAGONFLY_CANARY_PRODUCTION_LOCK_GUARD_MISSING_OR_LATE'
}

# Reproduce the exact production import order in an isolated pwsh process.
Import-Module (Join-Path $root 'DragonflyCanary.psm1') -Force
Import-Module (Join-Path $root 'DragonflyCanaryRuntime.psm1') -Force
Import-Module (Join-Path $root 'Dispatch.psm1') -Global -Force

$read = Get-Command Invoke-Ci10Read -CommandType Function -ErrorAction SilentlyContinue
if ($null -eq $read -or $read.ModuleName -cne 'Dispatch') {
    throw 'DRAGONFLY_CANARY_PRODUCTION_CI10_READ_NOT_VISIBLE'
}
$runtime = Get-Module -Name DragonflyCanaryRuntime -ErrorAction Stop
$internalLock = & $runtime {
    Get-Command Enter-Ci10DispatcherLock -CommandType Function -ErrorAction SilentlyContinue
}
if ($null -eq $internalLock -or $internalLock.ModuleName -cne 'Dispatch') {
    throw 'DRAGONFLY_CANARY_RUNTIME_CI10_LOCK_NOT_VISIBLE'
}
$once = Get-Command Invoke-LdwDragonflyCanaryOnce -CommandType Function -ErrorAction SilentlyContinue
if ($null -eq $once -or $once.ModuleName -cne 'DragonflyCanaryRuntime') {
    throw 'DRAGONFLY_CANARY_PRODUCTION_RUNTIME_NOT_VISIBLE'
}

# An invalid API scope must fail BEFORE any provider invocation. A process-local
# gh sentinel counts accidental calls and cannot reach GitHub.
$global:DragonflySyntheticGhCalls = 0
function global:gh {
    $global:DragonflySyntheticGhCalls++
    throw 'DRAGONFLY_SYNTHETIC_GH_CALLED'
}
try {
    $refused = $false
    try { $null = Invoke-Ci10Read 'outside/allowlisted/api' }
    catch { $refused = $_.Exception.Message -ceq 'API_SCOPE_REFUSED' }
    if (-not $refused) { throw 'DRAGONFLY_CANARY_CI10_READ_SCOPE_NOT_REFUSED' }
    if ($global:DragonflySyntheticGhCalls -ne 0) {
        throw 'DRAGONFLY_CANARY_CI10_SCOPE_CALLED_GH'
    }
} finally {
    Remove-Item -LiteralPath 'Function:\global:gh' -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name DragonflySyntheticGhCalls -Scope Global -ErrorAction SilentlyContinue
}

Write-Output 'DRAGONFLY_CANARY_PRODUCTION_IMPORT_SCOPE=PASS'
