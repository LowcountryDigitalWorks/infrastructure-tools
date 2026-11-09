# Fixed owner staging command: copies reviewed bootstrap bytes into protected ProgramData staging,
# re-hashes against pinned SHA-256, then launches bootstrap only from the protected copy via native system PowerShell.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$acceptedBootstrapSha256 = 'a3ede74deeee78f68b5fa4db620c56d4acfe3131c587d3252281ae7c8eecd2d4'
$acceptedV2WorkerSha256 = '75788c05edcf14199e53de239ef333dcefb9bc09385ba22de2b99cfda91bcabe'
$bootstrapFileName = 'Install-AdminBrokerV2PublisherBootstrap.ps1'
$workerBundleName = 'Invoke-AdminBrokerV2PublisherWorker.ps1'
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

Assert-Elevated
$ldwRoot = Join-Path $env:ProgramData 'LDW'
if (-not (Test-Path -LiteralPath $ldwRoot -PathType Container)) { throw 'LDW_ROOT_MISSING' }
Assert-NoReparse $ldwRoot
Assert-NoReparse $env:ProgramData
$stagingRoot = Join-Path $ldwRoot ('PrivilegedControl/bootstrap-staging/' + $stagingLeaf)
if (Test-Path -LiteralPath $stagingRoot) { throw 'STAGING_ALREADY_EXISTS' }
New-ProtectedDirectoryAcl $stagingRoot

$downloadBootstrap = Join-Path $reviewDownloadRoot $bootstrapFileName
$downloadWorker = Join-Path $reviewDownloadRoot $workerBundleName
if (-not (Test-Path -LiteralPath $downloadBootstrap -PathType Leaf)) { throw 'REVIEWED_BOOTSTRAP_MISSING' }
if (-not (Test-Path -LiteralPath $downloadWorker -PathType Leaf)) { throw 'REVIEWED_WORKER_MISSING' }
$dlBootstrapSha = (Get-FileHash -LiteralPath $downloadBootstrap -Algorithm SHA256).Hash.ToLowerInvariant()
$dlWorkerSha = (Get-FileHash -LiteralPath $downloadWorker -Algorithm SHA256).Hash.ToLowerInvariant()
if ($dlBootstrapSha -cne $acceptedBootstrapSha256) { throw 'REVIEWED_BOOTSTRAP_SHA256_MISMATCH' }
if ($dlWorkerSha -cne $acceptedV2WorkerSha256) { throw 'REVIEWED_WORKER_SHA256_MISMATCH' }

$protectedBootstrap = Join-Path $stagingRoot $bootstrapFileName
$protectedWorker = Join-Path $stagingRoot $workerBundleName
Copy-Item -LiteralPath $downloadBootstrap -Destination $protectedBootstrap -Force
Copy-Item -LiteralPath $downloadWorker -Destination $protectedWorker -Force
$copyBootstrapSha = (Get-FileHash -LiteralPath $protectedBootstrap -Algorithm SHA256).Hash.ToLowerInvariant()
$copyWorkerSha = (Get-FileHash -LiteralPath $protectedWorker -Algorithm SHA256).Hash.ToLowerInvariant()
if ($copyBootstrapSha -cne $acceptedBootstrapSha256 -or $copyWorkerSha -cne $acceptedV2WorkerSha256) {
    throw 'PROTECTED_COPY_HASH_MISMATCH'
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
