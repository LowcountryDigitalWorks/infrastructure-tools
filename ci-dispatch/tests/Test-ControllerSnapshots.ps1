[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $PSScriptRoot '../Dispatch.psm1') -Force
$root=Join-Path ([IO.Path]::GetTempPath()) ('ci10-snapshot-test-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$total=0
function Check([string]$Name,[scriptblock]$Body){$script:case=$Name;& $Body;$script:total++;'PASS '+$Name}
function Assert([bool]$Condition){if(-not $Condition){throw 'TEST_ASSERTION_FAILED'}}
function Refuses([scriptblock]$Action,[string]$Expected){
    $code=$null;try{& $Action|Out-Null}catch{$code=$_.Exception.Message}
    Assert ($null -ne $code -and $code -ceq $Expected)
}
function New-ControllerFixture([string]$Commit,[string]$Destination){
    $paths=@(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')})
    $zip=$Destination+'.zip'
    & git -C $repo archive --format=zip ('--output='+$zip) $Commit -- @paths 2>$null
    if($LASTEXITCODE -ne 0){throw 'TEST_SNAPSHOT_ARCHIVE_FAILED'}
    [IO.Compression.ZipFile]::ExtractToDirectory($zip,$Destination)
    Remove-Item -LiteralPath $zip -Force
}
try {
    $snapshots=@(Get-Ci10AcceptedControllerSnapshots)
    Check 'registry is limited to the two independently accepted controller snapshots' {
        Assert ($snapshots.Count -eq 2)
        Assert ($snapshots[0].commit -ceq '49f39f5d3a66251ed18c2e776d843feb25f65fe1')
        Assert ($snapshots[0].tree -ceq '4d241fe9bc0fbf190daf2e36be0e9c52966c5a7b')
        Assert ($snapshots[1].commit -ceq '54b9343af44c70db1d1403cf7f45cfc11e8bf167')
        Assert ($snapshots[1].tree -ceq 'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec')
    }
    foreach($snapshot in $snapshots){
        Check ('all runtime controller files match '+$snapshot.commit.Substring(0,7)) {
            $candidate=Join-Path $root ('candidate-'+$snapshot.commit)
            $stage=Join-Path $root ('stage-'+$snapshot.commit)
            $null=New-Item -ItemType Directory -Path $candidate,$stage
            New-ControllerFixture $snapshot.commit $candidate
            $matched=Get-Ci10MatchedControllerSnapshot -RepositoryRoot $repo -ControllerRoot $candidate `
                -ControllerFiles @(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')}) -StagingRoot $stage
            Assert ($matched.commit -ceq $snapshot.commit -and $matched.tree -ceq $snapshot.tree)
            $manifest=[pscustomobject]@{controllerCommit=$matched.commit;controllerTree=$matched.tree;files=@(
                Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')}|ForEach-Object{
                    [pscustomobject]@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $candidate $_) -Algorithm SHA256).Hash.ToLowerInvariant()}
                }
            )}
            $fromManifest=Get-Ci10ManifestControllerSnapshot $manifest
            Assert ($fromManifest.commit -ceq $matched.commit -and $fromManifest.tree -ceq $matched.tree)
        }
    }
    Check 'unknown controller drift is refused' {
        $candidate=Join-Path $root 'candidate-unknown';$stage=Join-Path $root 'stage-unknown'
        $null=New-Item -ItemType Directory -Path $candidate,$stage
        New-ControllerFixture $snapshots[1].commit $candidate
        [IO.File]::AppendAllText((Join-Path $candidate 'ci-runner/CiRunner.psm1'),'# unknown drift')
        Refuses {Get-Ci10MatchedControllerSnapshot -RepositoryRoot $repo -ControllerRoot $candidate `
            -ControllerFiles @(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')}) -StagingRoot $stage} 'ACCEPTED_CONTROLLER_CHANGED'
    }
    Check 'mixed controller files are refused by publisher and manifest verifier' {
        $candidate=Join-Path $root 'candidate-mixed';$stage=Join-Path $root 'stage-mixed'
        $royal=Join-Path $root ('candidate-'+$snapshots[1].commit)
        $original=Join-Path $root ('candidate-'+$snapshots[0].commit)
        $null=New-Item -ItemType Directory -Path $candidate,$stage
        Get-ChildItem -LiteralPath $royal -Recurse -File|ForEach-Object{
            $relative=[IO.Path]::GetRelativePath($royal,$_.FullName);$destination=Join-Path $candidate $relative
            $null=New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
            Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
        }
        Copy-Item -LiteralPath (Join-Path $original 'ci-runner/CiRunner.psm1') -Destination (Join-Path $candidate 'ci-runner/CiRunner.psm1') -Force
        Refuses {Get-Ci10MatchedControllerSnapshot -RepositoryRoot $repo -ControllerRoot $candidate `
            -ControllerFiles @(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')}) -StagingRoot $stage} 'ACCEPTED_CONTROLLER_CHANGED'
        $mixedManifest=[pscustomobject]@{controllerCommit=$snapshots[1].commit;controllerTree=$snapshots[1].tree;files=@(
            Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')}|ForEach-Object{
                [pscustomobject]@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $candidate $_) -Algorithm SHA256).Hash.ToLowerInvariant()}
            }
        )}
        Refuses {Get-Ci10ManifestControllerSnapshot $mixedManifest} 'BUNDLE_CONTROLLER_SNAPSHOT_MISMATCH'
    }
    Check 'accepted verifier provenance pairs with exact Royal controller target' {
        $dispatcherPath=Join-Path $root 'verifier-bundle/ci-dispatch/Dispatch.psm1'
        $recordPath=Join-Path $root 'verifier-bundle/ci-dispatch/verifier-provenance.json'
        $null=New-Item -ItemType Directory -Path (Split-Path $dispatcherPath -Parent) -Force
        Copy-Item -LiteralPath (Join-Path $repo 'ci-dispatch/Dispatch.psm1') -Destination $dispatcherPath
        Copy-Item -LiteralPath (Join-Path $repo 'ci-dispatch/verifier-provenance.json') -Destination $recordPath
        $accepted=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json
        $verifierManifest=[pscustomobject]@{dispatcher=$accepted;files=@(
            [pscustomobject]@{path='ci-dispatch/Dispatch.psm1';sha256=$accepted.sha256}
        )}
        $provenance=Get-Ci10ManifestDispatcherProvenance -BundleRoot (Join-Path $root 'verifier-bundle') -Manifest $verifierManifest
        Assert ($provenance.commit -ceq '805b71f36232412e072b0c860c1f4d665511d347')
        $royal=Join-Path $root ('candidate-'+$snapshots[1].commit)
        $stage=Join-Path $root 'stage-verifier-royal'
        $null=New-Item -ItemType Directory -Path $stage -Force
        $matched=Get-Ci10MatchedControllerSnapshot -RepositoryRoot $repo -ControllerRoot $royal `
            -ControllerFiles @(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')}) -StagingRoot $stage
        Assert ($matched.commit -ceq '54b9343af44c70db1d1403cf7f45cfc11e8bf167' -and
            $matched.tree -ceq 'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec')
    }
    Check 'missing and wrong dispatcher provenance refuse' {
        $record=Get-Content -LiteralPath (Join-Path $repo 'ci-dispatch/verifier-provenance.json') -Raw|ConvertFrom-Json
        $bundle=Join-Path $root 'verifier-bundle'
        $good=[pscustomobject]@{dispatcher=$record;files=@([pscustomobject]@{path='ci-dispatch/Dispatch.psm1';sha256=$record.sha256})}
        $missing=[pscustomobject]@{files=$good.files}
        Refuses {Get-Ci10ManifestDispatcherProvenance -BundleRoot $bundle -Manifest $missing} 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH'
        $wrong=[pscustomobject]@{dispatcher=[pscustomobject]@{commit=('a'*40);tree=$record.tree;blob=$record.blob;sha256=$record.sha256};files=$good.files}
        Refuses {Get-Ci10ManifestDispatcherProvenance -BundleRoot $bundle -Manifest $wrong} 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH'
    }
    Check 'dispatcher file hash drift refuses' {
        $bundle=Join-Path $root 'verifier-bundle'
        $path=Join-Path $bundle 'ci-dispatch/Dispatch.psm1'
        $original=[IO.File]::ReadAllBytes($path)
        [IO.File]::AppendAllText($path,'# altered verifier')
        $record=Get-Content -LiteralPath (Join-Path $bundle 'ci-dispatch/verifier-provenance.json') -Raw|ConvertFrom-Json
        $manifest=[pscustomobject]@{dispatcher=$record;files=@([pscustomobject]@{path='ci-dispatch/Dispatch.psm1';sha256=$record.sha256})}
        try {Refuses {Get-Ci10ManifestDispatcherProvenance -BundleRoot $bundle -Manifest $manifest} 'BUNDLE_VERIFIER_HASH_DRIFT'}
        finally {[IO.File]::WriteAllBytes($path,$original)}
    }
    Check 'clean unaccepted HEAD cannot change immutable verifier source' {
        $publisherPath=Join-Path $PSScriptRoot '../Publish-Bundle.ps1'
        $tokens=$null;$parseErrors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $publisherPath),[ref]$tokens,[ref]$parseErrors)
        if($parseErrors.Count){throw 'TEST_PUBLISHER_PARSE_FAILED'}
        $function=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Export-Ci10PinnedSourceFile'},$false)
        $guard=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-Ci10AcceptedHeadDispatcherSource'},$false)
        Assert ($function.Count -eq 1 -and $guard.Count -eq 1)
        Invoke-Expression $function[0].Extent.Text
        Invoke-Expression $guard[0].Extent.Text
        $unaccepted=Join-Path $root 'unaccepted-repository'
        & git clone --shared --no-checkout $repo $unaccepted 2>$null
        if($LASTEXITCODE -ne 0){throw 'TEST_UNACCEPTED_CLONE_FAILED'}
        & git -C $unaccepted checkout -b unaccepted $((git -C $repo rev-parse HEAD).Trim()) 2>$null
        if($LASTEXITCODE -ne 0){throw 'TEST_UNACCEPTED_CHECKOUT_FAILED'}
        & git -C $unaccepted config user.name 'CI-10 deterministic test'
        & git -C $unaccepted config user.email 'ci10-test@example.invalid'
        [IO.File]::AppendAllText((Join-Path $unaccepted 'ci-dispatch/Dispatch.psm1'),'# unaccepted clean HEAD')
        & git -C $unaccepted add ci-dispatch/Dispatch.psm1
        & git -C $unaccepted commit -m 'Create unaccepted clean verifier head' 2>$null
        if($LASTEXITCODE -ne 0 -or (& git -C $unaccepted status --porcelain)){throw 'TEST_UNACCEPTED_HEAD_SETUP_FAILED'}
        $script:AcceptedDispatcherSource=[pscustomobject]@{blob='662981a2955a3cd3f3526aeb666e185f989c4a18'}
        Refuses {Assert-Ci10AcceptedHeadDispatcherSource $unaccepted} 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
        $stage=Join-Path $root 'stage-unaccepted'
        $null=New-Item -ItemType Directory -Path $stage -Force
        $destination=Join-Path $root 'pinned-source/ci-dispatch/Dispatch.psm1'
        $null=New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
        Export-Ci10PinnedSourceFile '805b71f36232412e072b0c860c1f4d665511d347' `
            '9fcb587f14282a00d794acf65fda3177f824bb5c' '662981a2955a3cd3f3526aeb666e185f989c4a18' `
            'bf8da2a7ed95887bb7b7e3ddbf1ba10fe97f9a3ff9eb384ae9e16740674241ef' $unaccepted `
            'ci-dispatch/Dispatch.psm1' $destination $stage
        Assert ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            'bf8da2a7ed95887bb7b7e3ddbf1ba10fe97f9a3ff9eb384ae9e16740674241ef')
        Assert ((git -C $unaccepted rev-parse HEAD).Trim() -cne '805b71f36232412e072b0c860c1f4d665511d347')
    }
    Check 'publisher has no caller-selected controller or dispatcher acceptance path' {
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Publish-Bundle.ps1') -Raw
        $parameters=([regex]::Match($source,'(?s)^.*?param\((.*?)\)')).Groups[1].Value
        Assert (-not ($parameters -match 'AcceptedController|ControllerCommit|ControllerTree|Snapshot'))
        Assert ($source.Contains('Get-Ci10MatchedControllerSnapshot'))
        Assert ($source.Contains('805b71f36232412e072b0c860c1f4d665511d347'))
        Assert ($source.Contains('7c856daf5a8e4dc4d101ab088259008a78fc68f2'))
        Assert ($source.Contains('Export-Ci10PinnedSourceFile'))
        $guardPosition=$source.IndexOf('Assert-Ci10AcceptedHeadDispatcherSource $repo',[StringComparison]::Ordinal)
        $importPosition=$source.IndexOf("Import-Module (Join-Path `$PSScriptRoot 'Dispatch.psm1')",[StringComparison]::Ordinal)
        Assert ($guardPosition -ge 0 -and $guardPosition -lt $importPosition)
        Assert (-not ($source -match "git archive[^\r\n]*'HEAD'[^\r\n]*Dispatch\.psm1"))
        Assert (-not ($parameters -match 'Dispatcher|Verifier|Blob|Provenance'))
    }
    'CONTROLLER_SNAPSHOT_TESTS=PASS'
    'CONTROLLER_SNAPSHOT_TEST_COUNT='+$total
} catch {
    'CONTROLLER_SNAPSHOT_TESTS=FAIL'
    'CONTROLLER_SNAPSHOT_TEST_COUNT='+$total
    'TEST_CASE='+$script:case
    'TEST_FAILURE_LINE='+$_.InvocationInfo.ScriptLineNumber
    $code=[string]$_.Exception.Message
    if($code -cnotmatch '^[A-Z][A-Z0-9_]+$'){$code='TEST_OPERATION_FAILED'}
    'CLASSIFICATION='+$code
    exit 1
} finally {
    $resolved=[IO.Path]::GetFullPath($root)
    $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if($resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path $resolved -Leaf) -match '^ci10-snapshot-test-[a-f0-9]{32}$' -and (Test-Path -LiteralPath $resolved)){
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
