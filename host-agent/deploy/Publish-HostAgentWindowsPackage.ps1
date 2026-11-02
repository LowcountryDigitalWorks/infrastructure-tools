#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -cne 'Windows_NT') { throw 'HOST_AGENT_WINDOWS_PACKAGE_WINDOWS_REQUIRED' }
if ([string]::IsNullOrWhiteSpace($OutputDirectory) -or -not [IO.Path]::IsPathFullyQualified($OutputDirectory)) {
    throw 'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_PATH_REFUSED'
}

function Assert-DirectoryChainNoReparse {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { throw 'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_PARENT_MISSING' }
    $cursor = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_REPARSE_REFUSED'
        }
        $cursor = $cursor.Parent
    }
}

function Assert-SafeRegularFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'HOST_AGENT_WINDOWS_PACKAGE_FILE_MISSING' }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'HOST_AGENT_WINDOWS_PACKAGE_FILE_REPARSE_REFUSED' }
    $linkType = $item.PSObject.Properties['LinkType']
    if ($null -ne $linkType -and [string]$linkType.Value -ceq 'HardLink') { throw 'HOST_AGENT_WINDOWS_PACKAGE_FILE_HARDLINK_REFUSED' }
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
$outputParent = [IO.Path]::GetDirectoryName($output)
if ([string]::IsNullOrWhiteSpace($outputParent)) { throw 'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_PATH_REFUSED' }
Assert-DirectoryChainNoReparse -Path $outputParent
if (Test-Path -LiteralPath $output) { throw 'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_EXISTS' }

$sourceCommit = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim()
$sourceTree = (& git -C $repoRoot rev-parse 'HEAD^{tree}' 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[a-f0-9]{40}$' -or $sourceTree -cnotmatch '^[a-f0-9]{40}$') {
    throw 'HOST_AGENT_WINDOWS_PACKAGE_SOURCE_IDENTITY_FAILED'
}
$dirty = @(& git -C $repoRoot status --porcelain)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'HOST_AGENT_WINDOWS_PACKAGE_SOURCE_DIRTY' }

$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
Assert-DirectoryChainNoReparse -Path $tempParent
$temp = Join-Path $tempParent ('ldw-host-agent-windows-package-' + [guid]::NewGuid().ToString('N'))
$archive = Join-Path $temp 'source.zip'
$materialized = Join-Path $temp 'source'
$publish = Join-Path $temp 'publish'
$exeName = 'LDW.HostAgent.Windows.exe'

try {
    $null = New-Item -ItemType Directory -Path $temp -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $materialized -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $publish -ErrorAction Stop

    & git -C $repoRoot archive --format=zip --output=$archive $sourceCommit
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw 'HOST_AGENT_WINDOWS_PACKAGE_ARCHIVE_FAILED'
    }
    Assert-SafeRegularFile -Path $archive
    Expand-Archive -LiteralPath $archive -DestinationPath $materialized -ErrorAction Stop

    $project = Join-Path $materialized 'host-agent/src/LDW.HostAgent.Windows/LDW.HostAgent.Windows.csproj'
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) { throw 'HOST_AGENT_WINDOWS_PACKAGE_MATERIALIZATION_FAILED' }
    Assert-SafeRegularFile -Path $project

    # Build only from the immutable git-archive materialization. All bin/obj intermediates
    # therefore live below the random temporary materialization rather than the working tree.
    & dotnet publish $project -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None `
        -p:DebugSymbols=false `
        -p:EnableCompressionInSingleFile=true `
        -o $publish
    if ($LASTEXITCODE -ne 0) { throw 'HOST_AGENT_WINDOWS_PACKAGE_PUBLISH_FAILED' }

    $publishedFiles = @(Get-ChildItem -LiteralPath $publish -File -Force)
    if ($publishedFiles.Count -ne 1 -or $publishedFiles[0].Name -cne $exeName) {
        throw 'HOST_AGENT_WINDOWS_PACKAGE_PUBLISH_BOUNDARY_REFUSED'
    }
    Assert-SafeRegularFile -Path (Join-Path $publish $exeName)

    $sourceCommitAfter = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim()
    $sourceTreeAfter = (& git -C $repoRoot rev-parse 'HEAD^{tree}' 2>$null).Trim()
    $dirtyAfter = @(& git -C $repoRoot status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $sourceCommitAfter -cne $sourceCommit -or $sourceTreeAfter -cne $sourceTree -or $dirtyAfter.Count -ne 0) {
        throw 'HOST_AGENT_WINDOWS_PACKAGE_SOURCE_MOVED_DURING_BUILD'
    }

    Assert-DirectoryChainNoReparse -Path $outputParent
    if (Test-Path -LiteralPath $output) { throw 'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_EXISTS' }
    $null = New-Item -ItemType Directory -Path $output -ErrorAction Stop
    $outputItem = Get-Item -LiteralPath $output -Force -ErrorAction Stop
    if (($outputItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'HOST_AGENT_WINDOWS_PACKAGE_OUTPUT_REPARSE_REFUSED' }

    $packagedExe = Join-Path $output $exeName
    Copy-Item -LiteralPath (Join-Path $publish $exeName) -Destination $packagedExe -ErrorAction Stop
    Assert-SafeRegularFile -Path $packagedExe

    $exeItem = Get-Item -LiteralPath $packagedExe -Force
    $exeSha = (Get-FileHash -LiteralPath $packagedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        schema = 1
        package = 'ldw-host-agent-windows'
        runtime = 'win-x64'
        source_commit = $sourceCommit
        source_tree = $sourceTree
        executable = [ordered]@{
            name = $exeName
            sha256 = $exeSha
            bytes = $exeItem.Length
        }
    }
    $manifestPath = Join-Path $output 'manifest.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    Assert-SafeRegularFile -Path $manifestPath
    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $packageFiles = @(Get-ChildItem -LiteralPath $output -Force)
    if (@($packageFiles | Where-Object { $_.PSIsContainer }).Count -ne 0) { throw 'HOST_AGENT_WINDOWS_PACKAGE_BOUNDARY_REFUSED' }
    $names = @($packageFiles.Name | Sort-Object)
    if (($names -join ',') -cne 'LDW.HostAgent.Windows.exe,manifest.json') { throw 'HOST_AGENT_WINDOWS_PACKAGE_BOUNDARY_REFUSED' }

    'HOST_AGENT_WINDOWS_PACKAGE=PASS'
    'HOST_AGENT_WINDOWS_PACKAGE_SOURCE_COMMIT=' + $sourceCommit
    'HOST_AGENT_WINDOWS_PACKAGE_SOURCE_TREE=' + $sourceTree
    'HOST_AGENT_WINDOWS_PACKAGE_MANIFEST_SHA256=' + $manifestSha
    'HOST_AGENT_WINDOWS_PACKAGE_EXECUTABLE_SHA256=' + $exeSha
    'HOST_AGENT_WINDOWS_PACKAGE_EXECUTABLE_BYTES=' + $exeItem.Length
} finally {
    if (Test-Path -LiteralPath $temp) {
        $tempItem = Get-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        if ($null -ne $tempItem -and ($tempItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
