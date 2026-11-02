$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$module = Import-Module (Join-Path $repo 'ci-dispatch/DragonflyCanaryAdjunctPublisher.psm1') -Force -PassThru
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Invoke-Git([string[]]$GitArgs) {
    $result = & git @GitArgs 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'FIXTURE_GIT_FAILED' }
    $result
}
function Export-Source($Repository,$Source,$Destination,$Stage) {
    & $module {
        param($r,$s,$d,$t)
        Export-LdwAdjunctPinnedFile -RepositoryRoot $r -Source $s -Destination $d -StageRoot $t
    } $Repository $Source $Destination $Stage
}

Assert-True ($PSVersionTable.PSVersion.Major -eq 5) 'WINDOWS_POWERSHELL_51_REQUIRED'
Assert-True (-not ([Diagnostics.ProcessStartInfo]::new().PSObject.Properties.Name -contains 'ArgumentList')) 'FIXTURE_EXPECTED_NO_ARGUMENTLIST'

$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-materialization-ps51-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    $fixture = Join-Path $root 'repo with spaces'
    $null = Invoke-Git @('init','--quiet',$fixture)
    $payload = [byte[]](0..255) + [byte[]]@(0,13,10,255,128)
    [IO.File]::WriteAllBytes((Join-Path $fixture 'payload.bin'),$payload)
    $null = Invoke-Git @('-C',$fixture,'add','payload.bin')
    $null = Invoke-Git @('-C',$fixture,'-c','user.name=Synthetic Test','-c','user.email=synthetic@example.invalid','commit','--quiet','-m','ps51 fixture')
    $commit = Invoke-Git @('-C',$fixture,'rev-parse','HEAD')
    $tree = Invoke-Git @('-C',$fixture,'rev-parse','HEAD^{tree}')
    $blob = Invoke-Git @('-C',$fixture,'rev-parse','HEAD:payload.bin')
    $source = [pscustomobject]@{path='payload.bin';commit=$commit;tree=$tree;blob=$blob;representation='raw'}
    $stage = Join-Path $root 'stage'
    $null = New-Item -ItemType Directory -Path $stage
    $destination = Join-Path $stage 'output/payload.bin'
    $record = Export-Source $fixture $source $destination $stage
    Assert-True (Test-Path -LiteralPath $destination -PathType Leaf) 'PS51_EXPORT_OUTPUT_MISSING'
    Assert-True ([Convert]::ToBase64String([IO.File]::ReadAllBytes($destination)) -ceq [Convert]::ToBase64String($payload)) 'PS51_EXPORT_BYTES_DRIFTED'
    Assert-True ($record.gitBlob -ceq $blob) 'PS51_EXPORT_BLOB_IDENTITY_DRIFTED'
    'DRAGONFLY_ADJUNCT_MATERIALIZATION_PS51=PASS'
} finally {
    $resolved = [IO.Path]::GetFullPath($root)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -cnotmatch '^ldw-materialization-ps51-[a-f0-9]{32}$') { throw 'FIXTURE_CLEANUP_PATH_REFUSED' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    Remove-Module $module.Name -Force
}
