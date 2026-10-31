[CmdletBinding()]
param([string]$AcceptedArchive)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '../AcceptedAdminBrokerProvenance.psm1'
$module = Import-Module $modulePath -Force -PassThru
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('broker-provenance-test-' + [guid]::NewGuid().ToString('N'))
$script:Assertions = 0
function Assert-True([bool]$Condition, [string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function Assert-Refused([scriptblock]$Action, [string]$Reason) {
    $message = ''
    try { & $Action } catch { $message = $_.Exception.Message }
    Assert-True ($message -ceq $Reason) "expected $Reason, received $message"
}
function Git-Fixture([string[]]$Arguments) {
    & git -C $fixture @Arguments 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'TEST_GIT_FAILED' }
}
function Commit-Fixture {
    Git-Fixture @('add','--all')
    Git-Fixture @('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture')
    return (& git -C $fixture rev-parse HEAD).Trim()
}
function New-TestArchive([object[]]$Entries) {
    $path = Join-Path $fixture 'fixture.zip'
    $stream = [IO.File]::Create($path)
    $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entry in $Entries) {
            $member = $zip.CreateEntry($entry.name).Open()
            try { $member.Write([Text.Encoding]::UTF8.GetBytes($entry.text)) } finally { $member.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    return $path
}
try {
    & git clone --quiet --shared --no-checkout $repo $fixture
    if ($LASTEXITCODE -ne 0) { throw 'TEST_CLONE_FAILED' }
    $release = 'ae2c7a564d7ea3d31f4c4961c681ae72d43e5f80'
    Git-Fixture @('checkout','--quiet','--detach',$release)
    $expected = & $module { param($r,$h) Assert-SourceInputs $r $h } $fixture $release
    Assert-True ($expected -cmatch '^[a-f0-9]{64}$') 'baseline has canonical input fingerprint'
    $current = (& git -C $repo rev-parse HEAD).Trim()
    $actual = & $module { param($r,$h) Assert-SourceInputs $r $h } $repo $current
    Assert-True ($expected -ceq $actual) 'current accepted source matches historical complete input closure'
    $parent = (& git -C $fixture rev-parse "$release`^").Trim()
    Assert-Refused { & $module { param($r,$h) Assert-SourceInputs $r $h } $fixture $parent } 'BROKER_PROVENANCE_ANCESTRY_REQUIRED'
    Git-Fixture @('update-index','--chmod=+x','host-agent/src/LDW.AdminBroker/AssemblyInfo.cs')
    Git-Fixture @('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','mode fixture')
    $modeHead = (& git -C $fixture rev-parse HEAD).Trim()
    Assert-Refused { & $module { param($r,$h) Assert-SourceInputs $r $h } $fixture $modeHead } 'BROKER_PROVENANCE_INPUT_TYPE_REFUSED'

    # All reference edges, added/deleted files, ancestor build inputs, publisher and workflow.
    $mutations = @(
        'host-agent/src/LDW.AdminBroker.Host/Program.cs',
        'host-agent/src/LDW.AdminBroker/LDW.AdminBroker.csproj',
        'host-agent/src/LDW.LocalSecretStore/LocalSecretStore.cs',
        'host-agent/src/LDW.LocalSecretProbe/Program.cs',
        'host-agent/src/LDW.HostAgent.Core/Telemetry.cs',
        'host-agent/src/LDW.AdminBroker/added.cs',
        'Directory.Build.props','host-agent/Directory.Build.targets',
        'host-agent/src/Directory.Packages.props','global.json','NuGet.Config',
        'host-agent/deploy/Publish-AdminBrokerProofPackage.ps1',
        '.github/workflows/host-agent-persistent-helper-validation.yml'
    )
    foreach ($path in $mutations) {
        Git-Fixture @('reset','--hard',$release)
        [IO.File]::AppendAllText((Join-Path $fixture $path), "`nfixture change`n")
        $head = Commit-Fixture
        Assert-Refused { & $module { param($r,$h) Assert-SourceInputs $r $h } $fixture $head } 'BROKER_PROVENANCE_SOURCE_INPUTS_CHANGED'
    }
    Git-Fixture @('reset','--hard',$release)
    Remove-Item -LiteralPath (Join-Path $fixture 'host-agent/src/LDW.AdminBroker/AssemblyInfo.cs')
    $head = Commit-Fixture
    Assert-Refused { & $module { param($r,$h) Assert-SourceInputs $r $h } $fixture $head } 'BROKER_PROVENANCE_SOURCE_INPUTS_CHANGED'
    Git-Fixture @('reset','--hard',$release)
    [IO.File]::WriteAllText((Join-Path $fixture 'unrelated-evidence.md'), 'unrelated')
    $head = Commit-Fixture
    # Conservative ancestor inventory includes root additions too.
    Assert-Refused { & $module { param($r,$h) Assert-SourceInputs $r $h } $fixture $head } 'BROKER_PROVENANCE_SOURCE_INPUTS_CHANGED'
    Git-Fixture @('reset','--hard',$release)
    [IO.File]::AppendAllText((Join-Path $fixture 'host-agent/deploy/Bootstrap-CiJitControlTasks.ps1'), "`n# unrelated deployment change`n")
    $head = Commit-Fixture
    $same = & $module { param($r,$h) Assert-SourceInputs $r $h } $fixture $head
    Assert-True ($same -ceq $expected) 'deployment-only HEAD movement does not require broker rebuild'

    $file = @{name='LDW.AdminBroker.Host.exe'; text='synthetic inert bytes'}
    $bytes = [Text.Encoding]::UTF8.GetBytes($file.text)
    $inventory = @(@{name=$file.name; bytes=$bytes.Length; sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()})
    $zipPath = New-TestArchive @($file)
    $zipSha = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    & $module { param($p,$s,$f) Assert-Archive $p $s $f } $zipPath $zipSha $inventory
    Assert-True $true 'synthetic archive stream verifies without extraction or execution'
    Assert-Refused { & $module { param($p,$f) Assert-Archive $p $script:ArchiveSha $f } $zipPath $inventory } 'BROKER_PROVENANCE_ARCHIVE_HASH_MISMATCH'
    $inventory[0].sha256 = '0' * 64
    Assert-Refused { & $module { param($p,$s,$f) Assert-Archive $p $s $f } $zipPath $zipSha $inventory } 'BROKER_PROVENANCE_MEMBER_HASH_MISMATCH'
    foreach ($entries in @(
        @($file,$file),
        @(@{name='../LDW.AdminBroker.Host.exe';text=$file.text}),
        @(@{name='ldw.adminbroker.host.exe';text=$file.text}),
        @($file,@{name='extra';text='x'})
    )) {
        $zipPath = New-TestArchive $entries
        $zipSha = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Refused { & $module { param($p,$s,$f) Assert-Archive $p $s $f } $zipPath $zipSha $inventory } 'BROKER_PROVENANCE_INVENTORY_MISMATCH'
    }
    $exports = @($module.ExportedFunctions.Keys)
    Assert-True ($exports.Count -eq 1 -and $exports[0] -ceq 'Test-AcceptedAdminBrokerProvenance') 'only fixed readback entry is exported'
    $command = Get-Command Test-AcceptedAdminBrokerProvenance
    Assert-True (@($command.Parameters.Keys | Where-Object { $_ -notin [Management.Automation.PSCmdlet]::CommonParameters -and $_ -notin [Management.Automation.PSCmdlet]::OptionalCommonParameters }).Count -eq 0) 'no release/path/hash/source overrides'
    if ($AcceptedArchive) {
        & $module { param($p) Assert-Archive $p $script:ArchiveSha $script:Files } $AcceptedArchive
        Assert-True $true 'real historical archive and all three members match fixed accepted pins'
    }
    "Accepted Admin Broker provenance assertions PASS: $script:Assertions"
} finally {
    Remove-Module $module -Force
    # Only the locally created GUID fixture beneath TEMP may be removed.
    if ([IO.Path]::GetDirectoryName($fixture) -cne [IO.Path]::GetTempPath().TrimEnd('\','/')) { throw 'TEST_CLEANUP_PATH_REFUSED' }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
