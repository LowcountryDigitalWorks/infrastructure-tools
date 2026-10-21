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
    Check 'publisher exposes no caller selected accepted baseline' {
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Publish-Bundle.ps1') -Raw
        $parameters=([regex]::Match($source,'(?s)^.*?param\((.*?)\)')).Groups[1].Value
        Assert (-not ($parameters -match 'AcceptedController|ControllerCommit|ControllerTree|Snapshot'))
        Assert ($source.Contains('Get-Ci10MatchedControllerSnapshot'))
        Assert ($source.Contains("'HEAD' -- 'ci-dispatch/Dispatch.psm1'"))
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
