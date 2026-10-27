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
    if($null -eq $code -or $code -cne $Expected){'REFUSAL_EXPECTED='+$Expected+' ACTUAL='+$code}
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
    Check 'registry contains the three independently bounded controller snapshots' {
        Assert ($snapshots.Count -eq 3)
        Assert ($snapshots[0].commit -ceq '49f39f5d3a66251ed18c2e776d843feb25f65fe1')
        Assert ($snapshots[0].tree -ceq '4d241fe9bc0fbf190daf2e36be0e9c52966c5a7b')
        Assert ($snapshots[1].commit -ceq '54b9343af44c70db1d1403cf7f45cfc11e8bf167')
        Assert ($snapshots[1].tree -ceq 'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec')
        Assert ($snapshots[2].commit -ceq '68a535fd3df17bae59fdb86386fac85e024b1650')
        Assert ($snapshots[2].tree -ceq '46f9601340762c0c6a552028ec3cd5a5c234d340')
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
        Assert ($provenance.blob -ceq '2bd5cf864bb45ae1cb710f7dc8614060d8447143')
        $royal=Join-Path $root ('candidate-'+$snapshots[1].commit)
        $stage=Join-Path $root 'stage-verifier-royal'
        $null=New-Item -ItemType Directory -Path $stage -Force
        $matched=Get-Ci10MatchedControllerSnapshot -RepositoryRoot $repo -ControllerRoot $royal `
            -ControllerFiles @(Get-Ci10RuntimeFiles|Where-Object{$_.StartsWith('ci-runner/')}) -StagingRoot $stage
        Assert ($matched.commit -ceq '54b9343af44c70db1d1403cf7f45cfc11e8bf167' -and
            $matched.tree -ceq 'beb9b9096b2f4bfa41ad877ad4f6a41150fbcfec')
    }
    Check 'publisher parent boundary rejects replaceable staging ancestors' {
        $publisherPath=Join-Path $PSScriptRoot '../Publish-Bundle.ps1'
        $tokens=$null;$parseErrors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $publisherPath),[ref]$tokens,[ref]$parseErrors)
        if($parseErrors.Count){throw 'TEST_PUBLISHER_PARSE_FAILED'}
        $function=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Assert-Ci10PublisherParentBoundary'},$false)
        Assert ($function.Count -eq 1)
        Invoke-Expression $function[0].Extent.Text
        $source=Get-Content -LiteralPath $publisherPath -Raw
        $parentCheck=$source.IndexOf('Assert-Ci10PublisherParentBoundary $rootParent',[StringComparison]::Ordinal)
        $stageCreate=$source.IndexOf('$staging = Join-Path $root',[StringComparison]::Ordinal)
        $dispatcherImport=$source.IndexOf('Import-Module $stagedDispatcherPath',[StringComparison]::Ordinal)
        Assert ($parentCheck -ge 0 -and $parentCheck -lt $stageCreate -and $parentCheck -lt $dispatcherImport)

        function global:Get-Acl { param([string]$LiteralPath) $global:ci10ParentAclFixture }
        try {
            $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
            $users=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
            $trusted=[Security.AccessControl.DirectorySecurity]::new()
            $trusted.SetOwner($admin)
            $trusted.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $admin,[Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
            $trusted.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $users,[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
                [Security.AccessControl.InheritanceFlags]::ContainerInherit,[Security.AccessControl.PropagationFlags]::InheritOnly,
                [Security.AccessControl.AccessControlType]::Allow))
            $global:ci10ParentAclFixture=$trusted
            Assert-Ci10PublisherParentBoundary 'fixture-parent'

            $replaceable=[Security.AccessControl.DirectorySecurity]::new()
            $replaceable.SetOwner($admin)
            $replaceable.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $admin,[Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
            $replaceable.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $users,[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
                [Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
            $global:ci10ParentAclFixture=$replaceable
            Refuses {Assert-Ci10PublisherParentBoundary 'fixture-parent'} 'BUNDLE_PARENT_REPLACEMENT_UNTRUSTED'
        } finally {
            Remove-Item Function:\Get-Acl -ErrorAction SilentlyContinue
            Remove-Variable ci10ParentAclFixture -Scope Global -ErrorAction SilentlyContinue
        }
    }
    Check 'squash-equivalent main-only checkout resolves exact accepted verifier blobs' {
        $publisherPath=Join-Path $PSScriptRoot '../Publish-Bundle.ps1'
        $tokens=$null;$parseErrors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $publisherPath),[ref]$tokens,[ref]$parseErrors)
        if($parseErrors.Count){throw 'TEST_PUBLISHER_PARSE_FAILED'}
        $function=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Export-Ci10PinnedSourceFile'},$false)
        $guard=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-Ci10AcceptedHeadDispatcherSource'},$false)
        $materializer=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-Ci10VerifiedDispatcherPath'},$false)
        Assert ($function.Count -eq 1 -and $guard.Count -eq 1 -and $materializer.Count -eq 1)
        Invoke-Expression $function[0].Extent.Text
        Invoke-Expression $guard[0].Extent.Text
        Invoke-Expression $materializer[0].Extent.Text
        $script:AcceptedDispatcherSource=[pscustomobject]@{path='ci-dispatch/Dispatch.psm1';blob='2bd5cf864bb45ae1cb710f7dc8614060d8447143';sha256='fdcf67a7bbfeacd5d293876bbfa7622e41de98e09ddbeecbed6bcb7d2abea6d9'}
        $script:AcceptedVerifierRecordSource=[pscustomobject]@{path='ci-dispatch/verifier-provenance.json';blob='0537fcd212e8e9174f3b7388fcb992f9fccda8b6';sha256='c821f3184cf17694036a59f7c13377c3ac82d618166c2c576f67e4e85c455ba5'}
        $mainOnly=Join-Path $root 'squash-equivalent-main-only'
        $null=New-Item -ItemType Directory -Path (Join-Path $mainOnly 'ci-dispatch') -Force
        & git init $mainOnly 2>$null
        if($LASTEXITCODE -ne 0){throw 'TEST_MAIN_ONLY_INIT_FAILED'}
        & git -C $mainOnly config user.name 'CI-10 deterministic test'
        & git -C $mainOnly config user.email 'ci10-test@example.invalid'
        & git -C $mainOnly config core.autocrlf true
        Copy-Item -LiteralPath (Join-Path $repo $script:AcceptedDispatcherSource.path) -Destination (Join-Path $mainOnly $script:AcceptedDispatcherSource.path)
        Copy-Item -LiteralPath (Join-Path $repo $script:AcceptedVerifierRecordSource.path) -Destination (Join-Path $mainOnly $script:AcceptedVerifierRecordSource.path)
        & git -C $mainOnly add -- ci-dispatch/Dispatch.psm1 ci-dispatch/verifier-provenance.json
        & git -C $mainOnly commit -m 'Create squash-equivalent accepted verifier tree' 2>$null
        if($LASTEXITCODE -ne 0 -or (& git -C $mainOnly status --porcelain)){throw 'TEST_MAIN_ONLY_COMMIT_FAILED'}
        Assert ((git -C $mainOnly rev-parse 'HEAD:ci-dispatch/Dispatch.psm1').Trim() -ceq $script:AcceptedDispatcherSource.blob)
        Assert ((git -C $mainOnly rev-parse 'HEAD:ci-dispatch/verifier-provenance.json').Trim() -ceq $script:AcceptedVerifierRecordSource.blob)
        Assert ((git -C $mainOnly rev-list --count HEAD).Trim() -ceq '1')
        Assert-Ci10AcceptedHeadDispatcherSource $mainOnly
        foreach($transient in @('805b71f36232412e072b0c860c1f4d665511d347','7c856daf5a8e4dc4d101ab088259008a78fc68f2')){
            & git -C $mainOnly cat-file -e ($transient+'^{commit}') 2>$null
            if($LASTEXITCODE -eq 0){throw 'TEST_TRANSIENT_COMMIT_PRESENT'}
        }
        $stage=Join-Path $root 'stage-main-only';$null=New-Item -ItemType Directory -Path $stage -Force
        foreach($source in @($script:AcceptedDispatcherSource,$script:AcceptedVerifierRecordSource)){
            $destination=Join-Path $root ('resolved-main-only/'+$source.path)
            $null=New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
            Export-Ci10PinnedSourceFile $mainOnly $source.path $destination $stage
            Assert ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $source.sha256)
        }
        $marker=Join-Path $root 'hidden-dispatcher-executed.txt'
        [IO.File]::WriteAllText((Join-Path $mainOnly $script:AcceptedDispatcherSource.path),
            "[IO.File]::WriteAllText('$marker','executed'); throw 'HIDDEN_DISPATCHER_EXECUTED'")
        & git -C $mainOnly update-index --skip-worktree ci-dispatch/Dispatch.psm1
        if($LASTEXITCODE -ne 0 -or (& git -C $mainOnly status --porcelain)){throw 'TEST_HIDDEN_DISPATCHER_SETUP_FAILED'}
        $stagedDispatcher=Get-Ci10VerifiedDispatcherPath $mainOnly $stage
        Assert ($stagedDispatcher -ceq (Join-Path $stage 'verified-dispatcher/ci-dispatch/Dispatch.psm1'))
        Assert ((Get-FileHash -LiteralPath $stagedDispatcher -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            $script:AcceptedDispatcherSource.sha256)
        Import-Module $stagedDispatcher -Force
        Assert (-not (Test-Path -LiteralPath $marker))
        Assert ((Get-Command Get-Ci10RuntimeFiles).Source -ceq 'Dispatch')
        Refuses {Export-Ci10PinnedSourceFile $mainOnly 'ci-dispatch/Dispatch.psm1.bak' (Join-Path $root 'wrong-path') $stage} 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
        $missing=Join-Path $root 'missing-source-repository';$null=New-Item -ItemType Directory -Path $missing
        & git init $missing 2>$null
        if($LASTEXITCODE -ne 0){throw 'TEST_MISSING_SOURCE_INIT_FAILED'}
        Refuses {Export-Ci10PinnedSourceFile $missing $script:AcceptedDispatcherSource.path (Join-Path $root 'missing-source-output') $stage} 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
    }
    Check 'missing and wrong dispatcher provenance refuse' {
        $record=Get-Content -LiteralPath (Join-Path $repo 'ci-dispatch/verifier-provenance.json') -Raw|ConvertFrom-Json
        $bundle=Join-Path $root 'verifier-bundle'
        $good=[pscustomobject]@{dispatcher=$record;files=@([pscustomobject]@{path='ci-dispatch/Dispatch.psm1';sha256=$record.sha256})}
        $missing=[pscustomobject]@{files=$good.files}
        Refuses {Get-Ci10ManifestDispatcherProvenance -BundleRoot $bundle -Manifest $missing} 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH'
        $wrong=[pscustomobject]@{dispatcher=[pscustomobject]@{commit=$record.commit;tree=$record.tree;blob=('a'*40);sha256=$record.sha256};files=$good.files}
        Refuses {Get-Ci10ManifestDispatcherProvenance -BundleRoot $bundle -Manifest $wrong} 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH'
        $wrongHash=[pscustomobject]@{dispatcher=[pscustomobject]@{commit=$record.commit;tree=$record.tree;blob=$record.blob;sha256=('a'*64)};files=$good.files}
        Refuses {Get-Ci10ManifestDispatcherProvenance -BundleRoot $bundle -Manifest $wrongHash} 'BUNDLE_VERIFIER_PROVENANCE_MISMATCH'
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
    Check 'clean unaccepted HEAD cannot supply pinned verifier bytes' {
        $publisherPath=Join-Path $PSScriptRoot '../Publish-Bundle.ps1'
        $tokens=$null;$parseErrors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $publisherPath),[ref]$tokens,[ref]$parseErrors)
        if($parseErrors.Count){throw 'TEST_PUBLISHER_PARSE_FAILED'}
        $function=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Export-Ci10PinnedSourceFile'},$false)
        $guard=$ast.FindAll({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-Ci10AcceptedHeadDispatcherSource'},$false)
        Assert ($function.Count -eq 1 -and $guard.Count -eq 1)
        Invoke-Expression $function[0].Extent.Text
        Invoke-Expression $guard[0].Extent.Text
        $script:AcceptedDispatcherSource=[pscustomobject]@{path='ci-dispatch/Dispatch.psm1';blob='2bd5cf864bb45ae1cb710f7dc8614060d8447143';sha256='fdcf67a7bbfeacd5d293876bbfa7622e41de98e09ddbeecbed6bcb7d2abea6d9'}
        $script:AcceptedVerifierRecordSource=[pscustomobject]@{path='ci-dispatch/verifier-provenance.json';blob='0537fcd212e8e9174f3b7388fcb992f9fccda8b6';sha256='c821f3184cf17694036a59f7c13377c3ac82d618166c2c576f67e4e85c455ba5'}
        $unaccepted=Join-Path $root 'unaccepted-repository'
        $null=New-Item -ItemType Directory -Path (Join-Path $unaccepted 'ci-dispatch') -Force
        & git init $unaccepted 2>$null
        if($LASTEXITCODE -ne 0){throw 'TEST_UNACCEPTED_INIT_FAILED'}
        & git -C $unaccepted config user.name 'CI-10 deterministic test'
        & git -C $unaccepted config user.email 'ci10-test@example.invalid'
        Copy-Item -LiteralPath (Join-Path $repo 'ci-dispatch/Dispatch.psm1') -Destination (Join-Path $unaccepted 'ci-dispatch/Dispatch.psm1')
        [IO.File]::AppendAllText((Join-Path $unaccepted 'ci-dispatch/Dispatch.psm1'),'# unaccepted clean HEAD')
        & git -C $unaccepted add ci-dispatch/Dispatch.psm1
        & git -C $unaccepted commit -m 'Create unaccepted clean verifier head' 2>$null
        if($LASTEXITCODE -ne 0 -or (& git -C $unaccepted status --porcelain)){throw 'TEST_UNACCEPTED_HEAD_SETUP_FAILED'}
        Refuses {Assert-Ci10AcceptedHeadDispatcherSource $unaccepted} 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
        $stage=Join-Path $root 'stage-unaccepted'
        $null=New-Item -ItemType Directory -Path $stage -Force
        $destination=Join-Path $root 'pinned-source/ci-dispatch/Dispatch.psm1'
        $null=New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
        Refuses {Export-Ci10PinnedSourceFile $unaccepted $script:AcceptedDispatcherSource.path $destination $stage} 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
        $unacceptedRecord=Join-Path $root 'unaccepted-record-repository'
        $null=New-Item -ItemType Directory -Path (Join-Path $unacceptedRecord 'ci-dispatch') -Force
        & git init $unacceptedRecord 2>$null
        if($LASTEXITCODE -ne 0){throw 'TEST_UNACCEPTED_RECORD_INIT_FAILED'}
        & git -C $unacceptedRecord config user.name 'CI-10 deterministic test'
        & git -C $unacceptedRecord config user.email 'ci10-test@example.invalid'
        Copy-Item -LiteralPath (Join-Path $repo $script:AcceptedVerifierRecordSource.path) -Destination (Join-Path $unacceptedRecord $script:AcceptedVerifierRecordSource.path)
        [IO.File]::AppendAllText((Join-Path $unacceptedRecord $script:AcceptedVerifierRecordSource.path),' ')
        & git -C $unacceptedRecord add ci-dispatch/verifier-provenance.json
        & git -C $unacceptedRecord commit -m 'Create unaccepted verifier record' 2>$null
        if($LASTEXITCODE -ne 0 -or (& git -C $unacceptedRecord status --porcelain)){throw 'TEST_UNACCEPTED_RECORD_COMMIT_FAILED'}
        Refuses {Export-Ci10PinnedSourceFile $unacceptedRecord $script:AcceptedVerifierRecordSource.path (Join-Path $root 'wrong-record-output') $stage} 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
    }
    Check 'publisher entrypoint refuses hostile controller and hidden dispatcher before executing either' {
        $publisherPath=Join-Path $PSScriptRoot '../Publish-Bundle.ps1'
        $tokens=$null;$parseErrors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $publisherPath),[ref]$tokens,[ref]$parseErrors)
        if($parseErrors.Count){throw 'TEST_PUBLISHER_PARSE_FAILED'}
        $moduleImports=@($ast.FindAll({param($node)$node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Import-Module'},$true))
        Assert ($moduleImports.Count -eq 1 -and $moduleImports[0].Extent.Text.Contains('$stagedDispatcherPath'))
        # Scan all command extents so Import-Module, dot-source and call-operator forms are covered.
        $ciRunnerCommands=@($ast.FindAll({param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and $node.Extent.Text -match 'CiRunner\.psm1'
        },$true))
        Assert ($ciRunnerCommands.Count -eq 0)

        $untrusted=Join-Path $root 'untrusted-controller-repository'
        $null=New-Item -ItemType Directory -Path (Join-Path $untrusted 'ci-dispatch'),(Join-Path $untrusted 'ci-runner') -Force
        & git init $untrusted 2>$null
        if($LASTEXITCODE -ne 0){throw 'TEST_UNTRUSTED_CONTROLLER_INIT_FAILED'}
        & git -C $untrusted config user.name 'CI-10 deterministic test'
        & git -C $untrusted config user.email 'ci10-test@example.invalid'
        $marker=Join-Path $root 'untrusted-module-executed.txt'
        $dispatcherMarker=Join-Path $root 'hidden-dispatcher-entrypoint-executed.txt'
        Copy-Item -LiteralPath (Join-Path $repo 'ci-dispatch/Dispatch.psm1') -Destination (Join-Path $untrusted 'ci-dispatch/Dispatch.psm1')
        Copy-Item -LiteralPath (Join-Path $repo 'ci-dispatch/Publish-Bundle.ps1') -Destination (Join-Path $untrusted 'ci-dispatch/Publish-Bundle.ps1')
        $acceptedController=Join-Path $root ('candidate-'+$snapshots[1].commit)
        Get-ChildItem -LiteralPath $acceptedController -Recurse -File|ForEach-Object{
            $relative=[IO.Path]::GetRelativePath($acceptedController,$_.FullName)
            $destination=Join-Path $untrusted $relative
            $null=New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
            Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
        }
        [IO.File]::WriteAllText((Join-Path $untrusted 'ci-runner/CiRunner.psm1'),
            "[IO.File]::WriteAllText('$marker','executed'); throw 'UNTRUSTED_MODULE_EXECUTED'")
        & git -C $untrusted add --all
        & git -C $untrusted commit -m 'Create clean unaccepted controller module' 2>$null
        if($LASTEXITCODE -ne 0 -or (& git -C $untrusted status --porcelain)){throw 'TEST_UNTRUSTED_CONTROLLER_SETUP_FAILED'}
        Assert ((git -C $untrusted rev-parse 'HEAD:ci-dispatch/Dispatch.psm1').Trim() -ceq
            '2bd5cf864bb45ae1cb710f7dc8614060d8447143')
        [IO.File]::WriteAllText((Join-Path $untrusted 'ci-dispatch/Dispatch.psm1'),
            "[IO.File]::WriteAllText('$dispatcherMarker','executed'); throw 'HIDDEN_DISPATCHER_EXECUTED'")
        & git -C $untrusted update-index --skip-worktree ci-dispatch/Dispatch.psm1
        if($LASTEXITCODE -ne 0 -or (& git -C $untrusted status --porcelain)){throw 'TEST_HIDDEN_DISPATCHER_ENTRY_SETUP_FAILED'}
        $tree=(& git -C $untrusted rev-parse 'HEAD^{tree}').Trim()
        $oldProgramData=$env:ProgramData
        $env:ProgramData=$root
        try {
            $entryOutput=& pwsh -NoLogo -NoProfile -File (Join-Path $untrusted 'ci-dispatch/Publish-Bundle.ps1') `
                -Commit ((& git -C $untrusted rev-parse HEAD).Trim()) -Tree $tree 2>&1
            $entryExit=$LASTEXITCODE
        } finally { $env:ProgramData=$oldProgramData }
        Assert ($entryExit -ne 0)
        Assert ($entryOutput -join "`n" -match 'BUNDLE_PUBLISHED=FAIL')
        Assert (-not (Test-Path -LiteralPath $marker))
        Assert (-not (Test-Path -LiteralPath $dispatcherMarker))
    }
    Check 'publisher has no caller-selected controller or dispatcher acceptance path' {
        $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Publish-Bundle.ps1') -Raw
        $parameters=([regex]::Match($source,'(?s)^.*?param\((.*?)\)')).Groups[1].Value
        Assert (-not ($parameters -match 'AcceptedController|ControllerCommit|ControllerTree|Snapshot'))
        Assert ($source.Contains('Get-Ci10MatchedControllerSnapshot'))
        Assert ($source.Contains('2bd5cf864bb45ae1cb710f7dc8614060d8447143'))
        Assert ($source.Contains('0537fcd212e8e9174f3b7388fcb992f9fccda8b6'))
        Assert ($source.Contains("path='ci-dispatch/Dispatch.psm1'"))
        Assert ($source.Contains("path='ci-dispatch/verifier-provenance.json'"))
        Assert (-not ($source.Contains('805b71f36232412e072b0c860c1f4d665511d347')))
        Assert (-not ($source.Contains('7c856daf5a8e4dc4d101ab088259008a78fc68f2')))
        Assert ($source.Contains('Export-Ci10PinnedSourceFile'))
        $guardPosition=$source.IndexOf('Assert-Ci10AcceptedHeadDispatcherSource $repo',[StringComparison]::Ordinal)
        $importPosition=$source.IndexOf('Import-Module $stagedDispatcherPath',[StringComparison]::Ordinal)
        Assert ($guardPosition -ge 0 -and $guardPosition -lt $importPosition)
        Assert (-not ($source -match 'Import-Module\s+\(Join-Path `\$repo\s+''ci-runner/CiRunner\.psm1''\)'))
        $blobCheckPosition=$source.IndexOf("rev-parse ('HEAD:'+ `$source.path)",[StringComparison]::Ordinal)
        $archivePosition=$source.IndexOf("'--output='+`$archive) HEAD -- `$source.path",[StringComparison]::Ordinal)
        Assert ($blobCheckPosition -ge 0 -and $blobCheckPosition -lt $archivePosition)
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
