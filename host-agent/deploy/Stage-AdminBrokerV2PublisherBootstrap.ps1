# Fixed owner staging command: copies reviewed bootstrap bytes into protected ProgramData staging,
# re-hashes against pinned SHA-256, then launches bootstrap only from the protected copy via native system PowerShell.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
$reviewManifestFileName = 'AdminBrokerV2BootstrapReviewManifest.json'
$reviewDownloadRoot = Join-Path $env:USERPROFILE 'Downloads\LDW-V2-Publisher-Bootstrap-Review'
$stagingLeaf = 'v2-publisher-once'

function Assert-Elevated {
    if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ELEVATION_REQUIRED'
    }
}

function Get-SystemPowerShellExecutable {
    $sysDir = [Environment]::GetFolderPath('System')
    $candidate = [IO.Path]::Combine($sysDir, 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    $full = [IO.Path]::GetFullPath($candidate)
    if ($full -notmatch '\\WindowsPowerShell\\v1\.0\\powershell\.exe$') { throw 'SYSTEM_POWERSHELL_PATH_REFUSED' }
    if ($full -match 'WindowsApps') { throw 'WINDOWSAPPS_RUNTIME_REFUSED' }
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

function Read-ReviewManifest([string]$ManifestPath) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw 'REVIEW_MANIFEST_MISSING' }
    Assert-NoReparse $ManifestPath
    $bytes = [IO.File]::ReadAllBytes($ManifestPath)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 8192) { throw 'REVIEW_MANIFEST_INVALID' }
    try {
        [System.ReadOnlyMemory[byte]]$jsonMemory = $bytes
        $doc = [Text.Json.JsonDocument]::Parse($jsonMemory)
    } catch {
        throw 'REVIEW_MANIFEST_INVALID'
    }
    try {
        $root = $doc.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'REVIEW_MANIFEST_INVALID' }
        if ($root.GetProperty('schema').GetInt32() -ne 1) { throw 'REVIEW_MANIFEST_INVALID' }
        if ($root.GetProperty('protocol').GetString() -cne 'ldw.admin-broker.v2-bootstrap.review-manifest.v1') {
            throw 'REVIEW_MANIFEST_INVALID'
        }
        $items = $root.GetProperty('artifacts')
        if ($items.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $items.GetArrayLength() -ne 2) {
            throw 'REVIEW_MANIFEST_INVALID'
        }
        $map = @{}
        foreach ($item in $items.EnumerateArray()) {
            if ($item.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'REVIEW_MANIFEST_INVALID' }
            $name = $item.GetProperty('name').GetString()
            $sha = $item.GetProperty('sha256').GetString()
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
    } finally {
        $doc.Dispose()
    }
}

function Assert-FileSha256([string]$Path, [string]$ExpectedSha256, [string]$MismatchCode) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'ARTIFACT_MISSING' }
    Assert-NoReparse $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) { throw $MismatchCode }
}

Assert-Elevated
$ldwRoot = Join-Path $env:ProgramData 'LDW'
if (-not (Test-Path -LiteralPath $ldwRoot -PathType Container)) { throw 'LDW_ROOT_MISSING' }
Assert-NoReparse $ldwRoot
Assert-NoReparse $env:ProgramData
$stagingRoot = Join-Path $ldwRoot ('PrivilegedControl/bootstrap-staging/' + $stagingLeaf)
if (Test-Path -LiteralPath $stagingRoot) { throw 'STAGING_ALREADY_EXISTS' }
New-ProtectedDirectoryAcl $stagingRoot

$downloadManifest = Join-Path $reviewDownloadRoot $reviewManifestFileName
$downloadBootstrap = Join-Path $reviewDownloadRoot $bootstrapFileName
$downloadWorker = Join-Path $reviewDownloadRoot $workerBundleName
foreach ($path in @($downloadManifest, $downloadBootstrap, $downloadWorker)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'REVIEWED_BUNDLE_INCOMPLETE' }
}
$manifest = Read-ReviewManifest $downloadManifest
Assert-FileSha256 $downloadBootstrap $manifest.BootstrapSha256 'REVIEWED_BOOTSTRAP_SHA256_MISMATCH'
Assert-FileSha256 $downloadWorker $manifest.WorkerSha256 'REVIEWED_WORKER_SHA256_MISMATCH'

$protectedBootstrap = Join-Path $stagingRoot $bootstrapFileName
$protectedWorker = Join-Path $stagingRoot $workerBundleName
$protectedManifest = Join-Path $stagingRoot $reviewManifestFileName
Copy-Item -LiteralPath $downloadBootstrap -Destination $protectedBootstrap -Force
Copy-Item -LiteralPath $downloadWorker -Destination $protectedWorker -Force
Copy-Item -LiteralPath $downloadManifest -Destination $protectedManifest -Force
Assert-FileSha256 $protectedBootstrap $manifest.BootstrapSha256 'PROTECTED_COPY_HASH_MISMATCH'
Assert-FileSha256 $protectedWorker $manifest.WorkerSha256 'PROTECTED_COPY_HASH_MISMATCH'
$manifestBytesBefore = [IO.File]::ReadAllBytes($downloadManifest)
$manifestBytesAfter = [IO.File]::ReadAllBytes($protectedManifest)
if ($manifestBytesBefore.Length -ne $manifestBytesAfter.Length) { throw 'PROTECTED_MANIFEST_DRIFT' }
for ($i = 0; $i -lt $manifestBytesBefore.Length; $i++) {
    if ($manifestBytesBefore[$i] -ne $manifestBytesAfter[$i]) { throw 'PROTECTED_MANIFEST_DRIFT' }
}
$manifestAfterCopy = Read-ReviewManifest $protectedManifest
if ($manifestAfterCopy.BootstrapSha256 -cne $manifest.BootstrapSha256 -or
    $manifestAfterCopy.WorkerSha256 -cne $manifest.WorkerSha256) {
    throw 'PROTECTED_MANIFEST_DRIFT'
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
