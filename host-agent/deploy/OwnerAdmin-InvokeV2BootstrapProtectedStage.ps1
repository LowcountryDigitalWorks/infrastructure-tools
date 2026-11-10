# Fixed elevated owner-admin entry (Downloads only): verifies the independently reviewed issuer manifest,
# materializes the full bundle under protected ProgramData staging, then launches Stage only from that protected copy.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$issuerManifestFileName = 'AdminBrokerV2BootstrapIssuerManifest.json'
$stageFileName = 'Stage-AdminBrokerV2PublisherBootstrap.ps1'
$bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$reviewManifestFileName = 'AdminBrokerV2BootstrapReviewManifest.json'
$ownerLaunchFileName = 'OwnerAdmin-InvokeV2BootstrapProtectedStage.ps1'
$reviewDownloadRoot = Join-Path $env:USERPROFILE 'Downloads\LDW-V2-Publisher-Bootstrap-Review'
$stagingLeaf = 'v2-publisher-once'
# Independently reviewed frozen pins (issuer manifest lists stage/owner; owner self-hash comes from issuer content only).
$trustedReviewManifestFileSha256 = 'bc774896b562a6574f340dd46560814f5ef1b3a50ead19286688bb732dc552de'
$trustedBootstrapSha256 = '4e14986198531436672c659b556461b790321a18344981dbfa0c743680790c85'
$trustedWorkerSha256 = '051124b03f88694f19f557954e844ffe1f71c24187c7998a4cf6e8ce55aaa4f1'
$trustedStageSha256 = 'bbecf942a3035f981cacbff2bf1128dfe19684bec7d7b7d67c13af8e72edc97d'

function Assert-Elevated {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATION_REQUIRED'
    }
}

function Get-SystemPowerShellExecutable {
    if (-not [Environment]::Is64BitProcess) { throw 'POWERSHELL_HOST_BITNESS_REFUSED' }
    $windir = [Environment]::GetEnvironmentVariable('WINDIR', 'Machine')
    if ([string]::IsNullOrWhiteSpace($windir)) { throw 'WINDIR_REQUIRED' }
    $candidate = Join-Path (Join-Path $windir 'System32') 'WindowsPowerShell\v1.0\powershell.exe'
    $full = [IO.Path]::GetFullPath($candidate)
    if ($full -notmatch '(?i)\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$') { throw 'SYSTEM_POWERSHELL_PATH_REFUSED' }
    if ($full -match '(?i)SysWOW64') { throw 'SYSWOW64_RUNTIME_REFUSED' }
    if ($full -match '(?i)WindowsApps') { throw 'WINDOWSAPPS_RUNTIME_REFUSED' }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'SYSTEM_POWERSHELL_REQUIRED' }
    $full
}

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE_PATH_REFUSED' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function New-ProtectedDirectoryAcl([string]$Path) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Read-IssuerManifest([string]$ManifestPath) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw 'ISSUER_MANIFEST_MISSING' }
    Assert-NoReparse $ManifestPath
    $bytes = [IO.File]::ReadAllBytes($ManifestPath)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 16384) { throw 'ISSUER_MANIFEST_INVALID' }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text.IndexOf([char]0) -ge 0) { throw 'ISSUER_MANIFEST_INVALID' }
    try {
        $doc = $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'ISSUER_MANIFEST_INVALID'
    }
    if ($null -eq $doc) { throw 'ISSUER_MANIFEST_INVALID' }
    $topProps = @($doc.PSObject.Properties.Name)
    if (@(Compare-Object @('schema', 'protocol', 'artifacts') $topProps -CaseSensitive).Count) {
        throw 'ISSUER_MANIFEST_INVALID'
    }
    if ($doc.schema -ne 1) { throw 'ISSUER_MANIFEST_INVALID' }
    if ($doc.protocol -cne 'ldw.admin-broker.v2-bootstrap.issuer-manifest.v1') { throw 'ISSUER_MANIFEST_INVALID' }
    $expectedNames = @(
        $reviewManifestFileName,
        $bootstrapFileName,
        $workerBundleName,
        $stageFileName,
        $ownerLaunchFileName
    )
    $items = @($doc.artifacts)
    if ($items.Count -ne $expectedNames.Count) { throw 'ISSUER_MANIFEST_INVALID' }
    $map = @{}
    foreach ($item in $items) {
        $itemProps = @($item.PSObject.Properties.Name)
        if (@(Compare-Object @('name', 'sha256') $itemProps -CaseSensitive).Count) { throw 'ISSUER_MANIFEST_INVALID' }
        $name = [string]$item.name
        $sha = [string]$item.sha256
        if ($name -cnotin $expectedNames) { throw 'ISSUER_MANIFEST_INVALID' }
        if ($sha -cnotmatch '^[a-f0-9]{64}$') { throw 'ISSUER_MANIFEST_INVALID' }
        if ($map.ContainsKey($name)) { throw 'ISSUER_MANIFEST_INVALID' }
        $map[$name] = $sha.ToLowerInvariant()
    }
    if ($map.Count -ne $expectedNames.Count) { throw 'ISSUER_MANIFEST_INVALID' }
    return $map
}

function Assert-FileSha256([string]$Path, [string]$ExpectedSha256, [string]$MismatchCode) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'ARTIFACT_MISSING' }
    Assert-NoReparse $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) { throw $MismatchCode }
}

function Assert-DownloadBundleRoot([string]$Root) {
    $full = [IO.Path]::GetFullPath($Root)
    $downloads = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE 'Downloads'))
    if (-not $full.StartsWith($downloads, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'DOWNLOAD_BUNDLE_ROOT_REFUSED'
    }
    Assert-NoReparse $full
}

Assert-Elevated
$commandPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($commandPath)) { throw 'OWNER_LAUNCH_PATH_REQUIRED' }
$commandFull = [IO.Path]::GetFullPath($commandPath)
$expectedLaunchLeaf = [IO.Path]::GetFullPath((Join-Path $reviewDownloadRoot $ownerLaunchFileName))
if ($commandFull -cne $expectedLaunchLeaf) { throw 'OWNER_LAUNCH_PATH_REFUSED' }
Assert-DownloadBundleRoot $reviewDownloadRoot

$ldwRoot = Join-Path $env:ProgramData 'LDW'
if (-not (Test-Path -LiteralPath $ldwRoot -PathType Container)) { throw 'LDW_ROOT_MISSING' }
Assert-NoReparse $ldwRoot
Assert-NoReparse $env:ProgramData
$stagingRoot = Join-Path $ldwRoot ('PrivilegedControl/bootstrap-staging/' + $stagingLeaf)
if (Test-Path -LiteralPath $stagingRoot) { throw 'STAGING_ALREADY_EXISTS' }
New-ProtectedDirectoryAcl $stagingRoot

$downloadIssuer = Join-Path $reviewDownloadRoot $issuerManifestFileName
$downloadPaths = @($downloadIssuer)
foreach ($leaf in @($reviewManifestFileName, $bootstrapFileName, $workerBundleName, $stageFileName, $ownerLaunchFileName)) {
    $downloadPaths += Join-Path $reviewDownloadRoot $leaf
}
foreach ($path in $downloadPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'REVIEWED_BUNDLE_INCOMPLETE' }
}

$issuerPins = Read-IssuerManifest $downloadIssuer
if ($issuerPins[$reviewManifestFileName] -cne $trustedReviewManifestFileSha256 -or
    $issuerPins[$bootstrapFileName] -cne $trustedBootstrapSha256 -or
    $issuerPins[$workerBundleName] -cne $trustedWorkerSha256 -or
    $issuerPins[$stageFileName] -cne $trustedStageSha256) {
    throw 'ISSUER_REVIEWED_PIN_MISMATCH'
}
Assert-FileSha256 $commandFull $issuerPins[$ownerLaunchFileName] 'OWNER_LAUNCH_SHA256_MISMATCH'
Assert-FileSha256 (Join-Path $reviewDownloadRoot $reviewManifestFileName) $trustedReviewManifestFileSha256 'REVIEWED_MANIFEST_FILE_SHA256_MISMATCH'
Assert-FileSha256 (Join-Path $reviewDownloadRoot $bootstrapFileName) $trustedBootstrapSha256 'REVIEWED_BOOTSTRAP_SHA256_MISMATCH'
Assert-FileSha256 (Join-Path $reviewDownloadRoot $workerBundleName) $trustedWorkerSha256 'REVIEWED_WORKER_SHA256_MISMATCH'
Assert-FileSha256 (Join-Path $reviewDownloadRoot $stageFileName) $trustedStageSha256 'REVIEWED_STAGE_SHA256_MISMATCH'

$protectedPaths = @{}
$copyMap = @{
    $issuerManifestFileName = (Get-FileHash -LiteralPath $downloadIssuer -Algorithm SHA256).Hash.ToLowerInvariant()
    $reviewManifestFileName = $trustedReviewManifestFileSha256
    $bootstrapFileName = $trustedBootstrapSha256
    $workerBundleName = $trustedWorkerSha256
    $stageFileName = $trustedStageSha256
    $ownerLaunchFileName = $issuerPins[$ownerLaunchFileName]
}
foreach ($leaf in $copyMap.Keys) {
    $src = Join-Path $reviewDownloadRoot $leaf
    $dest = Join-Path $stagingRoot $leaf
    Copy-Item -LiteralPath $src -Destination $dest -Force
    Assert-FileSha256 $dest $copyMap[$leaf] 'PROTECTED_COPY_HASH_MISMATCH'
    $protectedPaths[$leaf] = $dest
}

$protectedStage = $protectedPaths[$stageFileName]

$powershellExe = Get-SystemPowerShellExecutable
$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $powershellExe
$psi.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $protectedStage + '"'
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.WorkingDirectory = $stagingRoot
$process = [Diagnostics.Process]::Start($psi)
if ($null -eq $process) { throw 'STAGE_LAUNCH_FAILED' }
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw 'STAGE_EXIT_NONZERO' }
'OWNER_ADMIN_V2_PROTECTED_STAGE=PASS'
