$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$module = Import-Module (Join-Path $repo 'ci-dispatch/DragonflyCanaryAdjunctPublisher.psm1') -Force -PassThru
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-ThrowsMessage([scriptblock]$Action,[string]$Expected) {
    $message = $null
    try { & $Action | Out-Null } catch { $message = $_.Exception.Message }
    Assert-True ($message -ceq $Expected) ('EXPECTED:' + $Expected + ';ACTUAL:' + $message)
}
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

$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-materialization-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    # Spaces exercise argument boundaries. All fixtures are public/synthetic; no protected publication.
    $fixture = Join-Path $root 'repo with spaces'
    $null = Invoke-Git @('init','--quiet',$fixture)
    $null = Invoke-Git @('-C',$fixture,'config','core.autocrlf','true')
    [IO.File]::WriteAllText((Join-Path $fixture '.gitattributes'),"*.txt text eol=crlf`n*.bin -text`n",[Text.UTF8Encoding]::new($false))
    $textBytes = [Text.Encoding]::UTF8.GetBytes("line one`ncaf$([char]0xe9)`n")
    $binaryBytes = [byte[]](0..255) + [byte[]]@(0,13,10,255,128)
    [IO.File]::WriteAllBytes((Join-Path $fixture 'raw.txt'),$textBytes)
    [IO.File]::WriteAllBytes((Join-Path $fixture 'raw.bin'),$binaryBytes)
    $null = Invoke-Git @('-C',$fixture,'add','.')
    $null = Invoke-Git @('-C',$fixture,'-c','user.name=Synthetic Test','-c','user.email=synthetic@example.invalid','commit','--quiet','-m','synthetic materialization fixture')
    $commit = Invoke-Git @('-C',$fixture,'rev-parse','HEAD')
    $tree = Invoke-Git @('-C',$fixture,'rev-parse','HEAD^{tree}')
    $blob = Invoke-Git @('-C',$fixture,'rev-parse','HEAD:raw.txt')
    $source = [pscustomobject]@{path='raw.txt';commit=$commit;tree=$tree;blob=$blob;representation='raw'}

    # Real git archive applies working-tree conversion even though commit:path has the right blob.
    $archive = Join-Path $root 'drift.zip'
    $null = Invoke-Git @('-C',$fixture,'archive','--format=zip',('--output=' + $archive),$commit,'--','raw.txt')
    $extract = Join-Path $root 'archive'
    [IO.Compression.ZipFile]::ExtractToDirectory($archive,$extract)
    $archiveBlob = & $module { param($p) Get-LdwAdjunctGitBlobSha1 $p } (Join-Path $extract 'raw.txt')
    Assert-True ($archiveBlob -cne $blob) 'ARCHIVE_DRIFT_NOT_REPRODUCED'

    foreach ($setting in @('true','false','input')) {
        $null = Invoke-Git @('-C',$fixture,'config','core.autocrlf',$setting)
        foreach ($name in @('raw.txt','raw.bin')) {
            $source.path = $name
            $source.blob = Invoke-Git @('-C',$fixture,'rev-parse',('HEAD:' + $name))
            $stage = Join-Path $root ($setting + '-' + $name)
            $null = New-Item -ItemType Directory -Path $stage
            $destination = Join-Path $stage 'output/payload'
            $record = Export-Source $fixture $source $destination $stage
            $expected = if ($name -ceq 'raw.txt') { $textBytes } else { $binaryBytes }
            Assert-True ([Convert]::ToBase64String([IO.File]::ReadAllBytes($destination)) -ceq [Convert]::ToBase64String($expected)) 'BLOB_BYTES_DRIFTED'
            Assert-True ($record.gitBlob -ceq $source.blob) 'BLOB_RECORD_DRIFTED'
        }
    }
    $stage = Join-Path $root 'negative'
    $null = New-Item -ItemType Directory -Path $stage
    $destination = Join-Path $stage 'output/payload'
    $source.blob = '0000000000000000000000000000000000000000'
    Assert-ThrowsMessage { Export-Source $fixture $source $destination $stage } 'ADJUNCT_SOURCE_BLOB_MISMATCH'
    Assert-True (-not (Test-Path -LiteralPath $destination)) 'MISMATCH_WROTE_DESTINATION'

    # Git replacement objects must not allow different bytes through the identity gate.
    $source.path = 'raw.txt'; $source.blob = $blob
    $otherBlob = Invoke-Git @('-C',$fixture,'rev-parse','HEAD:raw.bin')
    $null = Invoke-Git @('-C',$fixture,'replace',$blob,$otherBlob)
    try {
        Assert-ThrowsMessage { Export-Source $fixture $source $destination $stage } 'ADJUNCT_SOURCE_BLOB_MISMATCH'
        Assert-True (-not (Test-Path -LiteralPath $destination)) 'REPLACED_BLOB_WROTE_DESTINATION'
    } finally { $null = Invoke-Git @('-C',$fixture,'replace','-d',$blob) }

    # Export every real historical pin without publishing. Raw files retain blob identity;
    # Dispatch must satisfy both its original raw SHA and the accepted Windows CRLF SHA.
    $sources = & $module { $script:Files }
    foreach ($pin in $sources) {
        $stage = Join-Path $root $pin.blob
        $null = New-Item -ItemType Directory -Path $stage
        $destination = Join-Path $stage $pin.path
        $record = Export-Source $repo $pin $destination $stage
        if ($pin.representation -ceq 'raw') {
            $actual = & $module { param($p) Get-LdwAdjunctGitBlobSha1 $p } $destination
            Assert-True ($actual -ceq $pin.blob) 'PINNED_RAW_BLOB_DRIFTED'
        } else {
            Assert-True ($record.sha256 -ceq '0a41b338ca6b8b05ff31a26f30486381c7c836e484985a813b6fce6d07232c72') 'DISPATCH_WINDOWS_SHA_DRIFTED'
            $raw = [Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText($destination).Replace("`r`n","`n"))
            $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
            Assert-True ($sha -ceq '76092a5344746f4385a2b99ee0403c298ffed0458099444ddc82b67fd30f0675') 'DISPATCH_RAW_SHA_DRIFTED'
        }
    }
    # A correctly identified non-Dispatch blob may never pass the CRLF representation pin.
    $source.path = 'raw.txt'; $source.blob = $blob; $source.representation = 'crlf'
    $stage = Join-Path $root 'wrong-dispatch'
    $null = New-Item -ItemType Directory -Path $stage
    Assert-ThrowsMessage { Export-Source $fixture $source (Join-Path $stage 'output/payload') $stage } 'ADJUNCT_DISPATCH_RAW_HASH_MISMATCH'

    $dispatchPin = @($sources | Where-Object representation -CEQ 'crlf')[0]
    $stage = Join-Path $root 'windows-hash-negative'
    $null = New-Item -ItemType Directory -Path $stage
    Assert-ThrowsMessage {
        & $module {
            param($r,$s,$d,$t)
            $saved = $script:DispatchWindowsSha256
            try {
                $script:DispatchWindowsSha256 = '0' * 64
                Export-LdwAdjunctPinnedFile -RepositoryRoot $r -Source $s -Destination $d -StageRoot $t
            } finally { $script:DispatchWindowsSha256 = $saved }
        } $repo $dispatchPin (Join-Path $stage 'output/payload') $stage
    } 'ADJUNCT_DISPATCH_WINDOWS_HASH_MISMATCH'

    # A tree can still name a missing loose object: cat-file failure must not publish bytes.
    $objectPath = Join-Path $fixture ('.git/objects/' + $blob.Substring(0,2) + '/' + $blob.Substring(2))
    $objectRoot = [IO.Path]::GetFullPath((Join-Path $fixture '.git/objects')) + [IO.Path]::DirectorySeparatorChar
    Assert-True ([IO.Path]::GetFullPath($objectPath).StartsWith($objectRoot,[StringComparison]::OrdinalIgnoreCase)) 'FIXTURE_OBJECT_PATH_REFUSED'
    Remove-Item -LiteralPath $objectPath -Force
    $source.representation = 'raw'
    $stage = Join-Path $root 'missing-object'
    $null = New-Item -ItemType Directory -Path $stage
    $destination = Join-Path $stage 'output/payload'
    Assert-ThrowsMessage { Export-Source $fixture $source $destination $stage } 'ADJUNCT_SOURCE_EXPORT_FAILED'
    Assert-True (-not (Test-Path -LiteralPath $destination)) 'FAILED_EXPORT_WROTE_DESTINATION'
    'DRAGONFLY_ADJUNCT_MATERIALIZATION=PASS'
} finally {
    $resolved = [IO.Path]::GetFullPath($root)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -cnotmatch '^ldw-materialization-[a-f0-9]{32}$') { throw 'FIXTURE_CLEANUP_PATH_REFUSED' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    Remove-Module $module.Name -Force
}
