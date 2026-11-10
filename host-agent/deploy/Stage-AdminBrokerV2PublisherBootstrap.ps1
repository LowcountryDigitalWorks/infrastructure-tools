# Runs only from protected ProgramData staging: validates issuer + review manifests and pinned artifacts,
# then launches Install only from the protected copy via native 64-bit System32 Windows PowerShell.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stageFileName = 'Stage-AdminBrokerV2PublisherBootstrap.ps1'
$issuerManifestFileName = 'AdminBrokerV2BootstrapIssuerManifest.json'
$bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$reviewManifestFileName = 'AdminBrokerV2BootstrapReviewManifest.json'
$stagingLeaf = 'v2-publisher-once'
# Independently reviewed byte pins for the install bundle (issuer manifest cross-checks these literals; Stage has no self-digest pin).
$trustedReviewManifestFileSha256 = '65ecded7bc8cdb3db43d36c2a2dc5a8576a4f3ef3f1cb1dcd771d95e081e5ba7'
$trustedBootstrapSha256 = '4ecb1d07bdc267af299dc4ff093d5b962aa72207b90911060848b1026ec181e7'
$trustedWorkerSha256 = '051124b03f88694f19f557954e844ffe1f71c24187c7998a4cf6e8ce55aaa4f1'

function Assert-Elevated {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATION_REQUIRED'
    }
}

function Get-MachineProgramDataRoot {
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
    Assert-NoReparse $full
    $full
}

function Assert-TrustedDirectoryAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw 'PROTECTED_PATH_MISSING' }
    Assert-NoReparse $Path
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

function Assert-LdwParentPreflight([string]$ProgramDataRoot, [string]$LdwRoot) {
    Assert-TrustedDirectoryAcl $ProgramDataRoot
    if (Test-Path -LiteralPath $LdwRoot) { Assert-TrustedDirectoryAcl $LdwRoot }
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

function Assert-ProtectedStagePath([string]$CommandPath, [string]$ExpectedProtectedStagePath) {
    if ([string]::IsNullOrWhiteSpace($CommandPath)) { throw 'STAGE_PROTECTED_PATH_REQUIRED' }
    $actual = [IO.Path]::GetFullPath($CommandPath)
    $expected = [IO.Path]::GetFullPath($ExpectedProtectedStagePath)
    $profileRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if ([string]::IsNullOrWhiteSpace($profileRoot)) { throw 'USERPROFILE_REQUIRED' }
    $downloads = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetFullPath($profileRoot)) 'Downloads'))
    if ($actual.StartsWith($downloads, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'STAGE_DOWNLOAD_PATH_REFUSED'
    }
    if ($actual -cne $expected) { throw 'STAGE_PROTECTED_PATH_REQUIRED' }
    $programData = Get-MachineProgramDataRoot
    if (-not $actual.StartsWith($programData, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'STAGE_PROTECTED_PATH_REQUIRED'
    }
    Assert-NoReparse $actual
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
    $items = @($doc.artifacts)
    if ($items.Count -ne 4) { throw 'ISSUER_MANIFEST_INVALID' }
    $map = @{}
    foreach ($item in $items) {
        $itemProps = @($item.PSObject.Properties.Name)
        if (@(Compare-Object @('name', 'sha256') $itemProps -CaseSensitive).Count) { throw 'ISSUER_MANIFEST_INVALID' }
        $name = [string]$item.name
        $sha = [string]$item.sha256
        if ($sha -cnotmatch '^[a-f0-9]{64}$') { throw 'ISSUER_MANIFEST_INVALID' }
        if ($map.ContainsKey($name)) { throw 'ISSUER_MANIFEST_INVALID' }
        $map[$name] = $sha.ToLowerInvariant()
    }
    if ($map.Count -ne 4) { throw 'ISSUER_MANIFEST_INVALID' }
    return $map
}

function Read-ReviewManifest([string]$ManifestPath) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw 'REVIEW_MANIFEST_MISSING' }
    Assert-NoReparse $ManifestPath
    $bytes = [IO.File]::ReadAllBytes($ManifestPath)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 8192) { throw 'REVIEW_MANIFEST_INVALID' }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text.IndexOf([char]0) -ge 0) { throw 'REVIEW_MANIFEST_INVALID' }
    try {
        $doc = $text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'REVIEW_MANIFEST_INVALID'
    }
    if ($null -eq $doc) { throw 'REVIEW_MANIFEST_INVALID' }
    $topProps = @($doc.PSObject.Properties.Name)
    if (@(Compare-Object @('schema', 'protocol', 'artifacts') $topProps -CaseSensitive).Count) {
        throw 'REVIEW_MANIFEST_INVALID'
    }
    if ($doc.schema -ne 1) { throw 'REVIEW_MANIFEST_INVALID' }
    if ($doc.protocol -cne 'ldw.admin-broker.v2-bootstrap.review-manifest.v1') { throw 'REVIEW_MANIFEST_INVALID' }
    $items = @($doc.artifacts)
    if ($items.Count -ne 2) { throw 'REVIEW_MANIFEST_INVALID' }
    $map = @{}
    foreach ($item in $items) {
        $itemProps = @($item.PSObject.Properties.Name)
        if (@(Compare-Object @('name', 'sha256') $itemProps -CaseSensitive).Count) { throw 'REVIEW_MANIFEST_INVALID' }
        $name = [string]$item.name
        $sha = [string]$item.sha256
        if ($name -cnotin @($bootstrapFileName, $workerBundleName)) { throw 'REVIEW_MANIFEST_INVALID' }
        if ($sha -cnotmatch '^[a-f0-9]{64}$') { throw 'REVIEW_MANIFEST_INVALID' }
        if ($map.ContainsKey($name)) { throw 'REVIEW_MANIFEST_INVALID' }
        $map[$name] = $sha.ToLowerInvariant()
    }
    if ($map.Count -ne 2) { throw 'REVIEW_MANIFEST_INVALID' }
    return [pscustomobject]@{
        BootstrapSha256 = $map[$bootstrapFileName]
        WorkerSha256 = $map[$workerBundleName]
    }
}

function Assert-FileSha256([string]$Path, [string]$ExpectedSha256, [string]$MismatchCode) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'ARTIFACT_MISSING' }
    Assert-NoReparse $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) { throw $MismatchCode }
}

Assert-Elevated
$programDataRoot = Get-MachineProgramDataRoot
$ldwRoot = Join-Path $programDataRoot 'LDW'
if (-not (Test-Path -LiteralPath $ldwRoot -PathType Container)) { throw 'LDW_ROOT_MISSING' }
Assert-LdwParentPreflight $programDataRoot $ldwRoot
$stagingRoot = Join-Path $ldwRoot ('PrivilegedControl/bootstrap-staging/' + $stagingLeaf)
if (-not (Test-Path -LiteralPath $stagingRoot -PathType Container)) { throw 'STAGING_NOT_PREPARED' }
Assert-NoReparse $stagingRoot

$expectedStagePath = Join-Path $stagingRoot $stageFileName
Assert-ProtectedStagePath $PSCommandPath $expectedStagePath

$protectedIssuer = Join-Path $stagingRoot $issuerManifestFileName
$protectedBootstrap = Join-Path $stagingRoot $bootstrapFileName
$protectedWorker = Join-Path $stagingRoot $workerBundleName
$protectedReviewManifest = Join-Path $stagingRoot $reviewManifestFileName
foreach ($path in @($protectedIssuer, $protectedBootstrap, $protectedWorker, $protectedReviewManifest)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'PROTECTED_BUNDLE_INCOMPLETE' }
}

$issuerPins = Read-IssuerManifest $protectedIssuer
if ($issuerPins[$reviewManifestFileName] -cne $trustedReviewManifestFileSha256 -or
    $issuerPins[$bootstrapFileName] -cne $trustedBootstrapSha256 -or
    $issuerPins[$workerBundleName] -cne $trustedWorkerSha256) {
    throw 'ISSUER_REVIEWED_PIN_MISMATCH'
}
Assert-FileSha256 $PSCommandPath $issuerPins[$stageFileName] 'STAGE_ISSUER_PIN_MISMATCH'
Assert-FileSha256 $protectedBootstrap $trustedBootstrapSha256 'PROTECTED_COPY_HASH_MISMATCH'
Assert-FileSha256 $protectedWorker $trustedWorkerSha256 'PROTECTED_COPY_HASH_MISMATCH'
Assert-FileSha256 $protectedReviewManifest $trustedReviewManifestFileSha256 'PROTECTED_COPY_HASH_MISMATCH'

$manifest = Read-ReviewManifest $protectedReviewManifest
if ($manifest.BootstrapSha256 -cne $trustedBootstrapSha256 -or
    $manifest.WorkerSha256 -cne $trustedWorkerSha256) {
    throw 'REVIEWED_MANIFEST_PIN_MISMATCH'
}

$powershellExe = Get-SystemPowerShellExecutable
$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $powershellExe
$psi.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $protectedBootstrap + '"'
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.WorkingDirectory = $stagingRoot
$process = [Diagnostics.Process]::Start($psi)
if ($null -eq $process) { throw 'BOOTSTRAP_LAUNCH_FAILED' }
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw 'BOOTSTRAP_EXIT_NONZERO' }
'STAGE_ADMIN_BROKER_V2_BOOTSTRAP=PASS'
