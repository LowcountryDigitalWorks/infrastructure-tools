# SOURCE REFERENCE ONLY — paste this entire file into an elevated native 64-bit System32
# Windows PowerShell 5.1 admin console after normal-user hash verification.
# Never invoke via -File from Downloads, a checkout, PATH alias, or any script path (TOCTOU).
# Downloads bytes are DATA read with [IO.File]::ReadAllBytes / Get-FileHash only.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        throw 'INLINE_REFERENCE_NOT_FILE_INVOKABLE'
    }
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$issuerManifestFileName = 'AdminBrokerV2BootstrapIssuerManifest.json'
$stageFileName = 'Stage-AdminBrokerV2PublisherBootstrap.ps1'
$bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$reviewManifestFileName = 'AdminBrokerV2BootstrapReviewManifest.json'
$stagingLeaf = 'v2-publisher-once'
$fixedReviewDownloadSuffix = 'Downloads\LDW-V2-Publisher-Bootstrap-Review'
$trustedIssuerManifestFileSha256 = 'cbee01cc9539de647205fdbd63f4b4999cc4e27480a40bfaf1d7aaded88f57d0'
$trustedReviewManifestFileSha256 = '65ecded7bc8cdb3db43d36c2a2dc5a8576a4f3ef3f1cb1dcd771d95e081e5ba7'
$trustedBootstrapSha256 = '4ecb1d07bdc267af299dc4ff093d5b962aa72207b90911060848b1026ec181e7'
$trustedWorkerSha256 = '051124b03f88694f19f557954e844ffe1f71c24187c7998a4cf6e8ce55aaa4f1'
$trustedStageSha256 = 'fb4e5722f340b24639536b12f5292cf80a8d3ed60199e3461a2bd82d621250b3'

function Assert-ElevatedInline {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATION_REQUIRED'
    }
}

function Get-TrustedUserProfileRoot {
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if ([string]::IsNullOrWhiteSpace($known)) { throw 'USERPROFILE_REQUIRED' }
    $full = [IO.Path]::GetFullPath($known)
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        if ([IO.Path]::GetFullPath($env:USERPROFILE) -cne $full) { throw 'USERPROFILE_ENV_SPOOFED' }
    }
    Assert-NoReparseInline $full
    $full
}

function Get-ReviewDownloadBundleRootInline {
    $root = Join-Path (Get-TrustedUserProfileRoot) $fixedReviewDownloadSuffix
    $full = [IO.Path]::GetFullPath($root)
    Assert-NoReparseInline $full
    $full
}

function Get-MachineProgramDataRootInline {
    $known = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($known)) { throw 'COMMONAPPLICATIONDATA_REQUIRED' }
    $full = [IO.Path]::GetFullPath($known)
    if ([IO.Path]::GetFileName($full.TrimEnd('\')) -cne 'ProgramData') { throw 'COMMONAPPLICATIONDATA_PATH_REFUSED' }
    $machineVar = [Environment]::GetEnvironmentVariable('ProgramData', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($machineVar)) {
        if ([IO.Path]::GetFullPath($machineVar) -cne $full) { throw 'PROGRAMDATA_MACHINE_MISMATCH' }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        if ([IO.Path]::GetFullPath($env:ProgramData) -cne $full) { throw 'PROGRAMDATA_ENV_SPOOFED' }
    }
    Assert-NoReparseInline $full
    $full
}

function Assert-TrustedDirectoryAclInline([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw 'PROTECTED_PATH_MISSING' }
    Assert-NoReparseInline $Path
    $resolved = [IO.Path]::GetFullPath($Path)
    $acl = Get-Acl -LiteralPath $resolved
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'LDW_PARENT_OWNER_REFUSED' }
    $forbidden = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -in @('S-1-5-18', 'S-1-5-32-544')) { continue }
        if ($rule.FileSystemRights -band $forbidden) { throw 'LDW_PARENT_ACL_HOLD' }
    }
}

function Assert-LdwParentPreflightInline([string]$ProgramDataRoot, [string]$LdwRoot) {
    Assert-TrustedDirectoryAclInline $ProgramDataRoot
    if (Test-Path -LiteralPath $LdwRoot) { Assert-TrustedDirectoryAclInline $LdwRoot }
}

function Get-SystemPowerShellExecutableInline {
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

function Assert-NoReparseInline([string]$Path) {
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

function New-ProtectedDirectoryAclInline([string]$Path) {
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

function Read-IssuerManifestInline([string]$ManifestPath) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw 'ISSUER_MANIFEST_MISSING' }
    Assert-NoReparseInline $ManifestPath
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
        $stageFileName
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

function Assert-FileSha256Inline([string]$Path, [string]$ExpectedSha256, [string]$MismatchCode) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'ARTIFACT_MISSING' }
    Assert-NoReparseInline $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) { throw $MismatchCode }
}

function Assert-DownloadBundleRootInline([string]$Root) {
    $full = [IO.Path]::GetFullPath($Root)
    $expected = Get-ReviewDownloadBundleRootInline
    if ($full -cne $expected) { throw 'DOWNLOAD_BUNDLE_ROOT_REFUSED' }
}

function Copy-VerifiedBytesInline([string]$SourcePath, [string]$DestPath, [string]$ExpectedSha256) {
    Assert-NoReparseInline $SourcePath
    $bytes = [IO.File]::ReadAllBytes($SourcePath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($bytes)
        $actual = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    if ($actual -cne $ExpectedSha256) { throw 'DOWNLOADS_DATA_HASH_MISMATCH' }
    $destDir = [IO.Path]::GetDirectoryName($DestPath)
    if (-not [string]::IsNullOrEmpty($destDir)) {
        $null = New-Item -ItemType Directory -Path $destDir -Force
    }
    $flags = [IO.FileOptions]::None
    $stream = [IO.File]::Open($DestPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
    } finally {
        $stream.Dispose()
    }
    Assert-FileSha256Inline $DestPath $ExpectedSha256 'PROTECTED_COPY_HASH_MISMATCH'
}

function Invoke-LdwV2BootstrapProtectedStagingInlineTransaction {
    Assert-ElevatedInline
    $reviewDownloadRoot = Get-ReviewDownloadBundleRootInline
    Assert-DownloadBundleRootInline $reviewDownloadRoot

    $programDataRoot = Get-MachineProgramDataRootInline
    $ldwRoot = Join-Path $programDataRoot 'LDW'
    if (-not (Test-Path -LiteralPath $ldwRoot -PathType Container)) { throw 'LDW_ROOT_MISSING' }
    Assert-LdwParentPreflightInline $programDataRoot $ldwRoot
    $stagingRoot = Join-Path $ldwRoot ('PrivilegedControl/bootstrap-staging/' + $stagingLeaf)
    if (Test-Path -LiteralPath $stagingRoot) { throw 'STAGING_ALREADY_EXISTS' }
    New-ProtectedDirectoryAclInline $stagingRoot

    $bundleLeaves = @(
        $issuerManifestFileName,
        $reviewManifestFileName,
        $bootstrapFileName,
        $workerBundleName,
        $stageFileName
    )
    foreach ($leaf in $bundleLeaves) {
        $path = Join-Path $reviewDownloadRoot $leaf
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'REVIEWED_BUNDLE_INCOMPLETE' }
    }

    $downloadIssuer = Join-Path $reviewDownloadRoot $issuerManifestFileName
    Assert-FileSha256Inline $downloadIssuer $trustedIssuerManifestFileSha256 'ISSUER_MANIFEST_FILE_SHA256_MISMATCH'
    $issuerPins = Read-IssuerManifestInline $downloadIssuer
    if ($issuerPins[$reviewManifestFileName] -cne $trustedReviewManifestFileSha256 -or
        $issuerPins[$bootstrapFileName] -cne $trustedBootstrapSha256 -or
        $issuerPins[$workerBundleName] -cne $trustedWorkerSha256 -or
        $issuerPins[$stageFileName] -cne $trustedStageSha256) {
        throw 'ISSUER_REVIEWED_PIN_MISMATCH'
    }

    $copyMap = @{
        $issuerManifestFileName = $trustedIssuerManifestFileSha256
        $reviewManifestFileName = $trustedReviewManifestFileSha256
        $bootstrapFileName = $trustedBootstrapSha256
        $workerBundleName = $trustedWorkerSha256
        $stageFileName = $trustedStageSha256
    }
    foreach ($leaf in $copyMap.Keys) {
        $src = Join-Path $reviewDownloadRoot $leaf
        $dest = Join-Path $stagingRoot $leaf
        Copy-VerifiedBytesInline $src $dest $copyMap[$leaf]
    }

    $protectedStage = Join-Path $stagingRoot $stageFileName
    $powershellExe = Get-SystemPowerShellExecutableInline
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
    'OWNER_INLINE_V2_PROTECTED_STAGE=PASS'
}
