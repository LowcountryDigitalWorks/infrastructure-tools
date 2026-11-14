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

# REDRIX pre-JIT fail-before-POST source proof, not protected-runtime evidence.
# Both the CLI and direct POST writer must refuse until an independently
# accepted issuer binds the exact workflow ref/commit/blob/release generation.
$holdMarker = "throw 'DRAGONFLY_CANARY_WORKFLOW_SOURCE_UNBOUND'"
if ($entry.Split(@($holdMarker), [StringSplitOptions]::None).Count -ne 3) {
    throw 'DRAGONFLY_PREMINT_DUAL_GUARD_COUNT_INVALID'
}
$postFunctionStart = $entry.IndexOf('function Invoke-LdwDragonflyCanaryGhWrite', [StringComparison]::Ordinal)
$postGuard = $entry.IndexOf($holdMarker, $postFunctionStart, [StringComparison]::Ordinal)
$ghSpawn = $entry.IndexOf('Get-Command gh.exe', $postFunctionStart, [StringComparison]::Ordinal)
$entryGuard = $entry.LastIndexOf($holdMarker, [StringComparison]::Ordinal)
if ($postFunctionStart -lt 0 -or $postGuard -le $postFunctionStart -or
    $ghSpawn -le $postGuard -or $entryGuard -le $postGuard -or
    $entryGuard -ge $firstProviderReadIndex) {
    throw 'DRAGONFLY_PREMINT_GUARDS_MISSING_OR_TOO_LATE'
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $entryPath, [ref]$tokens, [ref]$parseErrors
)
if (@($parseErrors).Count) { throw 'DRAGONFLY_PREMINT_PARSE_INVALID' }
$functions = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -ceq 'Invoke-LdwDragonflyCanaryGhWrite'
}, $true))
if ($functions.Count -ne 1) { throw 'DRAGONFLY_PREMINT_POST_FUNCTION_AMBIGUOUS' }
# Source-only AST extraction; install only a process-fenced test copy below.
$script:Repository = 'LowcountryDigitalWorks/infrastructure-tools'
$postBody = [ordered]@{
    name = 'redrix-123-1-456'
    runner_group_id = 1
    labels = @('self-hosted','Linux','X64','dragonfly','jit','ldw-ephemeral','synthetic-only','dragonfly-run-123','dragonfly-attempt-1')
    work_folder = '_work'
}
# The reviewer found that directly calling the real writer under ambient
# GitHub auth would be unsafe if the pre-mint guard regressed. The test loads
# the exact production writer AST source with ONE synthetic unconditional
# fail-closed interception before gh.exe resolution. If production refusal
# disappears, the synthetic barrier returns a DIFFERENT error so the test
# fails without contacting a provider.
$writerText = $functions[0].Extent.Text
$providerLookup = '$gh = (Get-Command gh.exe -ErrorAction Stop).Source'
if ($writerText.Split(@($providerLookup), [StringSplitOptions]::None).Count -ne 2) {
    throw 'DRAGONFLY_PREMINT_WRITER_LOOKUP_IDENTITY_CHANGED'
}
$lookupAt = $writerText.IndexOf($providerLookup, [StringComparison]::Ordinal)
$processAt = $writerText.IndexOf('[Diagnostics.ProcessStartInfo]::new()', [StringComparison]::Ordinal)
if ($lookupAt -le 0 -or $processAt -le $lookupAt -or
    $writerText.Substring(0, $lookupAt).Contains('[Diagnostics.Process]::new()')) {
    throw 'DRAGONFLY_PREMINT_WRITER_PROCESS_BEFORE_INTERCEPTION'
}
# Do not dot-source the executable production writer. Install only a
# syntactically verified copy with an injected barrier before provider lookup.
$mockedWriter = $writerText.Replace(
    $providerLookup,
    "throw 'DRAGONFLY_TEST_MOCK_PROVIDER_PROCESS_BLOCKED'" + [Environment]::NewLine + "    " + $providerLookup
)
. ([ScriptBlock]::Create($mockedWriter))
$jitPath = 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/generate-jitconfig'
$runnerPath = 'repos/LowcountryDigitalWorks/infrastructure-tools/actions/runners/123'
foreach ($case in @(
    @{ Method = 'POST'; Path = $jitPath; Body = $postBody; Expected = 'DRAGONFLY_CANARY_WORKFLOW_SOURCE_UNBOUND' },
    @{ Method = 'post'; Path = $jitPath; Body = $postBody; Expected = 'DRAGONFLY_CANARY_API_METHOD_NONCANONICAL' },
    @{ Method = 'pOsT'; Path = $jitPath; Body = $postBody; Expected = 'DRAGONFLY_CANARY_API_METHOD_NONCANONICAL' },
    @{ Method = 'delete'; Path = $runnerPath; Body = $null; Expected = 'DRAGONFLY_CANARY_API_METHOD_NONCANONICAL' },
    @{ Method = 'DeLeTe'; Path = $runnerPath; Body = $null; Expected = 'DRAGONFLY_CANARY_API_METHOD_NONCANONICAL' },
    @{ Method = 'DELETE'; Path = $jitPath; Body = $null; Expected = 'DRAGONFLY_CANARY_API_WRITE_SCOPE_REFUSED' },
    # An otherwise valid scoped DELETE reaches only the mock barrier.
    @{ Method = 'DELETE'; Path = $runnerPath; Body = $null; Expected = 'DRAGONFLY_TEST_MOCK_PROVIDER_PROCESS_BLOCKED' }
)) {
    $actualCode = ''
    try {
        $null = Invoke-LdwDragonflyCanaryGhWrite -Path $case.Path -Method $case.Method -Body $case.Body
    } catch {
        $actualCode = [string]$_.Exception.Message
    }
    if ($actualCode -cne $case.Expected) {
        throw 'DRAGONFLY_PREMINT_WRITER_REFUSAL_INVALID'
    }
}
Write-Output 'DRAGONFLY_PREMINT_WRITER_MOCKED_BOUNDARY=PASS'

# Execute the REAL source entry using deliberately synthetic identities.
# An early HOLD must occur even when caller forges a matching-looking SHA;
# it may not import the transport, read GitHub, request JIT or launch a guest.
$originalProgramData = $env:ProgramData
try {
    $env:ProgramData = [IO.Path]::GetTempPath()
    $pwshPath = (Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    foreach ($syntheticHead in @(('a' * 40), ('b' * 40), ('f' * 40))) {
        $output = @(& $pwshPath -NoLogo -NoProfile -File $entryPath -RunId 123 -RunAttempt 1 -JobId 456 -HeadSha $syntheticHead 2>&1)
        $exitCode = $LASTEXITCODE
        $rendered = ($output | Out-String).Trim()
        $expected = @('DRAGONFLY_CANARY_PRODUCTION=HOLD', 'CLASSIFICATION=DRAGONFLY_CANARY_WORKFLOW_SOURCE_UNBOUND') -join [Environment]::NewLine
        if ($exitCode -ne 1 -or $rendered -cne $expected) {
            throw 'DRAGONFLY_PREMINT_ENTRY_NOT_CLOSED'
        }
    }
} finally {
    $env:ProgramData = $originalProgramData
}

# The verified child HOLD exits with code 1 by design. Reset only the test
# harness exit state so the successful negative assertion is not a CI failure.
$global:LASTEXITCODE = 0
Write-Output 'DRAGONFLY_CANARY_WORKFLOW_SOURCE_PREMINT=HOLD_PASS'

Write-Output 'DRAGONFLY_CANARY_PRODUCTION_IMPORT_SCOPE=PASS'
