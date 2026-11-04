# Test ONLY in a temporary Git clone; no ProgramData, elevation, JIT or provider.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$gate = Join-Path $repo 'ci-dispatch/Test-DragonflyV2PublisherProvenance.ps1'
$accepted = 'bc29bedbfe7fe8a545ce3a471e0d575c2921cefe'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ldw-v2-provenance-fixture-' + [guid]::NewGuid().ToString('N'))
$checkout = Join-Path $testRoot 'checkout'
$foreignDir = Join-Path $testRoot 'foreign'
$publisher = Join-Path $checkout 'ci-dispatch/DragonflyCanaryAdjunctV2Publisher.psm1'
$foreignPublisher = Join-Path $foreignDir 'DragonflyCanaryAdjunctV2Publisher.psm1'

function Assert-LdwV2([bool]$Ok,[string]$Failure) {
    if (-not $Ok) { throw $Failure }
}
function Assert-Refuses([scriptblock]$Action,[string]$Code) {
    $actual = $null
    try { & $Action | Out-Null } catch { $actual = [string]$_.Exception.Message }
    if ($actual -cne $Code) { throw ('V2_PROVENANCE_WRONG_REFUSAL:' + $Code + ':' + $actual) }
}
function Assert-GitWorked {
    if ($LASTEXITCODE -ne 0) { throw 'V2_PROVENANCE_FIXTURE_GIT_FAILED' }
}

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    # Local clone: no fetch, no credentials, and no protected destination.
    & git clone --quiet --no-hardlinks --config core.autocrlf=false $repo $checkout
    Assert-GitWorked
    & git -C $checkout checkout --quiet --detach $accepted
    Assert-GitWorked
    & git -C $checkout remote set-url origin 'https://github.com/LowcountryDigitalWorks/infrastructure-tools.git'
    Assert-GitWorked

    $before = & $gate -RepositoryRoot $checkout -Phase BeforeImport
    Assert-LdwV2 ($before -ceq 'DRAGONFLY_V2_PUBLISHER_PROVENANCE_BEFORE_IMPORT=PASS_SOURCE_ONLY') 'V2_PROVENANCE_VALID_BEFORE_IMPORT_FAILED'

    $acceptedModule = Import-Module -Name $publisher -Force -PassThru
    Assert-LdwV2 ($null -ne $acceptedModule) 'V2_PROVENANCE_MODULE_IMPORT_FAILED'
    # The same-path/clean-file check is advisory; without a protected lock it
    # MUST NOT claim the bytes actually loaded into the PowerShell engine.
    Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase AfterImport } 'V2_PROVENANCE_LOADED_CODE_UNVERIFIED'
    Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase BeforeImport } 'V2_PROVENANCE_PREIMPORT_MODULE_ALREADY_LOADED'
    Remove-Module -ModuleInfo $acceptedModule -Force

    # A missing module cannot pass an after-import validation.
    Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase AfterImport } 'V2_PROVENANCE_LOADED_MODULE_NOT_UNIQUE'

    # Byte-identical but loaded from an untrusted directory is NOT accepted.
    New-Item -ItemType Directory -Path $foreignDir -Force | Out-Null
    Copy-Item -LiteralPath $publisher -Destination $foreignPublisher
    $foreignModule = Import-Module -Name $foreignPublisher -Force -PassThru
    try {
        Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase AfterImport } 'V2_PROVENANCE_LOADED_MODULE_PATH_MISMATCH'
    } finally { Remove-Module -ModuleInfo $foreignModule -Force }

    # Exact origin is required. Reset in a guaranteed finally path.
    & git -C $checkout remote set-url origin 'https://example.invalid/attacker/repo.git'
    Assert-GitWorked
    try {
        Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase BeforeImport } 'V2_PROVENANCE_ORIGIN_INVALID'
    } finally {
        & git -C $checkout remote set-url origin 'https://github.com/LowcountryDigitalWorks/infrastructure-tools.git'
        Assert-GitWorked
    }

    # A modified on-disk publisher cannot inherit acceptance from Git history.
    $saved = [IO.File]::ReadAllBytes($publisher)
    try {
        [IO.File]::AppendAllText($publisher,([Environment]::NewLine + '# synthetic integrity drift'),[Text.UTF8Encoding]::new($false))
        Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase BeforeImport } 'V2_PROVENANCE_WORKTREE_DIRTY'
    } finally { [IO.File]::WriteAllBytes($publisher,$saved) }
    $recovered = & $gate -RepositoryRoot $checkout -Phase BeforeImport
    Assert-LdwV2 ($recovered -ceq 'DRAGONFLY_V2_PUBLISHER_PROVENANCE_BEFORE_IMPORT=PASS_SOURCE_ONLY') 'V2_PROVENANCE_TAMPER_RECOVERY_FAILED'


    # Reviewer M1: a module may be imported from temporarily substituted bytes,
    # then have the genuine file restored BEFORE the second disk/path inspection.
    # The ordinary source-only gate must REFUSE loaded-code provenance in this
    # counterexample; it must never call Publish or require an administrator.
    $savedTamper = [IO.File]::ReadAllBytes($publisher)
    $syntheticModule = $null
    try {
        [IO.File]::AppendAllText($publisher,([Environment]::NewLine +
            'function Publish-LdwDragonflyCanaryAdjunctV2 { "SYNTHETIC_NOT_A_PUBLISH" }' +
            [Environment]::NewLine +
            'Export-ModuleMember -Function Publish-LdwDragonflyCanaryAdjunctV2' +
            [Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        $syntheticModule = Import-Module -Name $publisher -Force -PassThru
        [IO.File]::WriteAllBytes($publisher,$savedTamper)
        Assert-LdwV2 ($null -ne $syntheticModule) 'V2_PROVENANCE_TAMPER_IMPORT_FAILED'
        Assert-LdwV2 (([string](Get-Command Publish-LdwDragonflyCanaryAdjunctV2).ScriptBlock) -match 'SYNTHETIC_NOT_A_PUBLISH') 'V2_PROVENANCE_TAMPER_IMPORT_NOT_PROVEN'
        Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase AfterImport } 'V2_PROVENANCE_LOADED_CODE_UNVERIFIED'
    } finally {
        [IO.File]::WriteAllBytes($publisher,$savedTamper)
        if ($null -ne $syntheticModule) { Remove-Module -ModuleInfo $syntheticModule -Force }
    }
    # Publication mode cannot trust an ordinary user-owned temporary checkout.
    # The accepted, protected admin-owned staging tree is a separate future gate.
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Assert-Refuses { & $gate -RepositoryRoot $checkout -Phase BeforeImport -ProtectedPublication } 'V2_PROVENANCE_PROTECTED_WINDOWS_REQUIRED'
    } else {
        $rejected = $false
        try { & $gate -RepositoryRoot $checkout -Phase BeforeImport -ProtectedPublication | Out-Null }
        catch { $rejected = ([string]$_.Exception.Message -in @('V2_PROVENANCE_PROTECTED_ADMIN_REQUIRED','V2_PROVENANCE_PROTECTED_STAGE_REQUIRED')) }
        Assert-LdwV2 $rejected 'V2_PROVENANCE_UNPROTECTED_PUBLICATION_ACCEPTED'
        # Windows' no-write/no-delete reader sharing is the import-time primitive.
        # This synthetic lock is held over a same-file attempted modification.
        $reader = [IO.File]::Open($publisher,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $writeDenied = $false
            try { [IO.File]::AppendAllText($publisher,'synthetic-attempt') }
            catch { $writeDenied = $true }
            Assert-LdwV2 $writeDenied 'V2_PROVENANCE_FILE_LOCK_DID_NOT_DENY_WRITE'
        } finally { $reader.Dispose() }
    }

    # A current feature/PR checkout is not the accepted V2 publication source.
    $localHead = (& git -C $repo rev-parse HEAD).Trim()
    $expectedRefusal = if ($localHead -ceq $accepted) { 'V2_PROVENANCE_WORKTREE_DIRTY' } else { 'V2_PROVENANCE_HEAD_MISMATCH' }
    Assert-Refuses { & $gate -RepositoryRoot $repo -Phase BeforeImport } $expectedRefusal
    $clean = @(& git -C $checkout status --porcelain)
    Assert-LdwV2 ($clean.Count -eq 0) 'V2_PROVENANCE_FIXTURE_WORKTREE_DIRTY'
} finally {
    Get-Module -Name DragonflyCanaryAdjunctV2Publisher | Remove-Module -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
'DRAGONFLY_V2_PUBLISHER_PROVENANCE_SYNTHETIC=PASS'
