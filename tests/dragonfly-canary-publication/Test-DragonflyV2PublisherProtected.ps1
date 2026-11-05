# Positive protected-gate proof ONLY on a clean GitHub-hosted Windows runner.
# Never invokes Publish-, touches real LDW01, or acquires GitHub runner secrets.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'TEST_HOST_REFUSED' }
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'TEST_ADMIN_REQUIRED' }
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$gate=Join-Path $repo 'ci-dispatch/Test-DragonflyV2PublisherProvenance.ps1'
$git=Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
$ldw=Join-Path $env:ProgramData 'LDW'
$stage=Join-Path $ldw 'DragonflyV2PublisherSource'
$module=Join-Path $stage 'ci-dispatch/DragonflyCanaryAdjunctV2Publisher.psm1'
if (Test-Path -LiteralPath $ldw) { throw 'TEST_EXISTING_LDW_REFUSED' }
$originalPath=$env:PATH
$previous=@{}
$started=$false
$guard=$false
function Protect-Fixture([string]$Path) {
    $entry=Get-Item -LiteralPath $Path -Force
    $acl=Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $flags=if ($entry.PSIsContainer) {'ContainerInherit,ObjectInherit'} else {'None'}
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'FullControl',$flags,'None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
try {
    $null=New-Item -ItemType Directory -Path $ldw
    $started=$true
    Protect-Fixture $ldw
    & $git -c core.autocrlf=false clone --quiet --no-hardlinks $repo $stage
    if ($LASTEXITCODE -ne 0) { throw 'TEST_CLONE_FAILED' }
    & $git -C $stage -c core.autocrlf=false checkout --quiet --detach bc29bedbfe7fe8a545ce3a471e0d575c2921cefe
    if ($LASTEXITCODE -ne 0) { throw 'TEST_CHECKOUT_FAILED' }
    & $git -C $stage remote set-url origin https://github.com/LowcountryDigitalWorks/infrastructure-tools.git
    if ($LASTEXITCODE -ne 0) { throw 'TEST_ORIGIN_FAILED' }
    foreach ($target in @($stage)+@(
        Get-ChildItem -LiteralPath $stage -Recurse -Force | ForEach-Object { $_.FullName }
    )) { Protect-Fixture $target }
    foreach ($key in @([Environment]::GetEnvironmentVariables().Keys)) {
        if ([string]$key -like 'GIT_*') {
            $previous[[string]$key]=[Environment]::GetEnvironmentVariable([string]$key)
            [Environment]::SetEnvironmentVariable([string]$key,$null,'Process')
        }
    }
    $env:PATH=(Join-Path $env:ProgramFiles 'Git\cmd')+';'+(Join-Path $env:SystemRoot 'System32')+';'+$env:SystemRoot
    $env:GIT_CONFIG_COUNT='2'
    $env:GIT_CONFIG_KEY_0='core.fsmonitor'
    $env:GIT_CONFIG_VALUE_0='false'
    $env:GIT_CONFIG_KEY_1='core.hooksPath'
    $env:GIT_CONFIG_VALUE_1='NUL'
    $env:GIT_OPTIONAL_LOCKS='0'
    $env:GIT_TERMINAL_PROMPT='0'

    # Reviewer M1: test PowerShell's effective command precedence, not just
    # external PATH lookup. The gate must refuse a harmless shadowing alias
    # BEFORE acquiring the protected publication guard.
    Set-Alias -Name git -Value Get-Location -Scope Script -Force
    try {
        $aliasDenied=$false
        try { $null=& $gate -RepositoryRoot $stage -Phase BeforeImport -ProtectedPublication }
        catch { $aliasDenied=([string]$_.Exception.Message -ceq 'V2_PROVENANCE_PUBLISHER_GIT_UNTRUSTED') }
        if (-not $aliasDenied) { throw 'TEST_GIT_ALIAS_SHADOW_ALLOWED' }
    } finally {
        Remove-Item Alias:\git -Force -ErrorAction SilentlyContinue
    }
    $result=& $gate -RepositoryRoot $stage -Phase BeforeImport -ProtectedPublication
    if ($result -cne 'DRAGONFLY_V2_PUBLISHER_PROVENANCE_BEFORE_IMPORT=PASS_PROTECTED') { throw 'TEST_BEFORE_FAILED' }
    $guard=$true
    $null=Import-Module -Name $module -Force -PassThru

    # A caller-session function can also shadow the publisher's bare git
    # command after module import. Refuse it while retaining the held lock.
    function git { throw 'TEST_GIT_FUNCTION_SHADOW_EXECUTED' }
    try {
        $functionDenied=$false
        try { $null=& $gate -RepositoryRoot $stage -Phase AfterImport -ProtectedPublication }
        catch { $functionDenied=([string]$_.Exception.Message -ceq 'V2_PROVENANCE_PUBLISHER_GIT_UNTRUSTED') }
        if (-not $functionDenied) { throw 'TEST_GIT_FUNCTION_SHADOW_ALLOWED' }
    } finally {
        Remove-Item Function:\git -Force -ErrorAction SilentlyContinue
    }
    $result=& $gate -RepositoryRoot $stage -Phase AfterImport -ProtectedPublication
    if ($result -cne 'DRAGONFLY_V2_PUBLISHER_PROVENANCE_AFTER_IMPORT=PASS_PROTECTED') { throw 'TEST_AFTER_FAILED' }
    $denied=$false
    try { [IO.File]::AppendAllText($module,'fixture-writer') } catch { $denied=$true }
    if (-not $denied) { throw 'TEST_WRITER_ALLOWED' }
    $denied=$false
    try { [IO.File]::Move($module,$module+'.renamed') } catch { $denied=$true }
    if (-not $denied) { throw 'TEST_RENAME_ALLOWED' }
    $env:GIT_CONFIG_VALUE_0='true'
    $denied=$false
    try { $null=& $gate -RepositoryRoot $stage -Phase AfterImport -ProtectedPublication }
    catch { $denied=([string]$_.Exception.Message -ceq 'V2_PROVENANCE_GIT_ENVIRONMENT_UNSAFE') }
    if (-not $denied) { throw 'TEST_ENV_ALLOWED' }
    $env:GIT_CONFIG_VALUE_0='false'
    if ((& $gate -RepositoryRoot $stage -Phase AfterImport -ProtectedPublication) -cne
        'DRAGONFLY_V2_PUBLISHER_PROVENANCE_AFTER_IMPORT=PASS_PROTECTED') {
        throw 'TEST_AFTER_ENV_RESTORE_FAILED'
    }

    # The existing protected fixture previously stopped at import. Exercise
    # the REAL accepted V2 publisher while its file lock stays live, but ONLY
    # inside this disposable hosted-Runner ProgramData fixture. Never invoke
    # this test script on LDW01; never consume the owner's publication consent.
    $expectedId='78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca-e53e016383441fde6ba22cb57821b3d26bdf4824'
    $publication=Publish-LdwDragonflyCanaryAdjunctV2 -RepositoryRoot $stage
    if (-not $publication.Published -or
        (Split-Path $publication.ReleaseRoot -Leaf) -cne $expectedId -or
        $publication.ManifestSha256 -cnotmatch '^[a-f0-9]{64}
} finally {
    if ($guard) {
        $released=& $gate -RepositoryRoot $stage -Phase Release -ProtectedPublication
        if ($released -cne 'DRAGONFLY_V2_PUBLISHER_PROVENANCE_GUARD_RELEASE=PASS') { throw 'TEST_RELEASE_FAILED' }
    }
    Get-Module DragonflyCanaryAdjunctV2Publisher | Remove-Module -Force -ErrorAction SilentlyContinue
    $env:PATH=$originalPath
    foreach ($key in @([Environment]::GetEnvironmentVariables().Keys)) {
        if ([string]$key -like 'GIT_*') { [Environment]::SetEnvironmentVariable([string]$key,$null,'Process') }
    }
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key,$previous[$key],'Process') }
    if ($started -and (Test-Path -LiteralPath $ldw)) { Remove-Item -LiteralPath $ldw -Recurse -Force }
}
) {
        throw 'TEST_PROTECTED_ACTUAL_PUBLISH_FAILED'
    }
    $manifestPath=Join-Path $publication.ReleaseRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $publication.ManifestSha256) { throw 'TEST_PROTECTED_MANIFEST_HASH_DRIFT' }
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 2 -or
        $manifest.artifact -cne 'ldw-dragonfly-canary-adjunct-v2' -or
        $manifest.releaseIdentity -cne $expectedId -or
        $manifest.containsCredential -ne $false -or
        $manifest.containsBootstrap -ne $false -or
        $manifest.containsPrivateEndpoint -ne $false -or
        @($manifest.files).Count -ne 4) {
        throw 'TEST_PROTECTED_MANIFEST_CONTENT_INVALID'
    }
    $verified=Test-LdwDragonflyCanaryAdjunctV2 -ManifestSha256 $publication.ManifestSha256
    if (-not $verified.Valid) { throw 'TEST_PROTECTED_ACTUAL_READBACK_FAILED' }

    # Retry is intentionally only a synthetic hosted idempotence test; a
    # real one-shot AdminBroker publication still requires its replay guard.
    $repeat=Publish-LdwDragonflyCanaryAdjunctV2 -RepositoryRoot $stage
    if (-not $repeat.Published -or
        $repeat.ReleaseRoot -cne $publication.ReleaseRoot -or
        $repeat.ManifestSha256 -cne $publication.ManifestSha256) {
        throw 'TEST_PROTECTED_PUBLICATION_NONIDEMPOTENT'
    }
    $releases=Join-Path $ldw 'DragonflyCanaryAdjunct/releases'
    if (@(Get-ChildItem -LiteralPath $releases -Directory -Force).Count -ne 1) {
        throw 'TEST_PROTECTED_EXTRA_RELEASE'
    }
    $bundleRoot=Join-Path $ldw 'DragonflyCanaryAdjunct'
    if (@(Get-ChildItem -LiteralPath $bundleRoot -Directory -Force |
        Where-Object { $_.Name -match '^stage-' }).Count -ne 0) {
        throw 'TEST_PROTECTED_STAGE_RESIDUE'
    }
    if ((& $gate -RepositoryRoot $stage -Phase AfterImport -ProtectedPublication) -cne
        'DRAGONFLY_V2_PUBLISHER_PROVENANCE_AFTER_IMPORT=PASS_PROTECTED') {
        throw 'TEST_PROTECTED_POST_PUBLISH_LOCK_LOST'
    }
    'DRAGONFLY_V2_PROTECTED_ACTUAL_PUBLISH_HOSTED=PASS'
    'DRAGONFLY_V2_PROTECTED_GATE_HOSTED=PASS'
} finally {
    if ($guard) {
        $released=& $gate -RepositoryRoot $stage -Phase Release -ProtectedPublication
        if ($released -cne 'DRAGONFLY_V2_PUBLISHER_PROVENANCE_GUARD_RELEASE=PASS') { throw 'TEST_RELEASE_FAILED' }
    }
    Get-Module DragonflyCanaryAdjunctV2Publisher | Remove-Module -Force -ErrorAction SilentlyContinue
    $env:PATH=$originalPath
    foreach ($key in @([Environment]::GetEnvironmentVariables().Keys)) {
        if ([string]$key -like 'GIT_*') { [Environment]::SetEnvironmentVariable([string]$key,$null,'Process') }
    }
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key,$previous[$key],'Process') }
    if ($started -and (Test-Path -LiteralPath $ldw)) { Remove-Item -LiteralPath $ldw -Recurse -Force }
}
