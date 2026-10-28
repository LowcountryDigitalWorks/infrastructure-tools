[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -cne 'Windows_NT') { throw 'ADMIN_BROKER_PACKAGE_WINDOWS_REQUIRED' }

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
$temp = Join-Path ([IO.Path]::GetTempPath()) ('ldw-admin-broker-package-' + [guid]::NewGuid().ToString('N'))
$hostStage = Join-Path $temp 'host'
$probeStage = Join-Path $temp 'probe'

function Invoke-DotNetPublish([string]$Project, [string]$Destination) {
    & dotnet publish $Project -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None `
        -p:DebugSymbols=false `
        -p:EnableCompressionInSingleFile=true `
        -o $Destination
    if ($LASTEXITCODE -ne 0) { throw 'ADMIN_BROKER_PACKAGE_PUBLISH_FAILED' }
}

function Invoke-ExpectedFailure {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory)][int]$ExpectedExit,
        [Parameter(Mandatory)][string]$ExpectedStderr
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    foreach ($argument in $Arguments) { $null = $start.ArgumentList.Add($argument) }
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Smoke proof must be independent of any runner/user secret state.
    $null = $start.Environment.Remove('LDW_CORSAIR_NEON_SECRET')
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'ADMIN_BROKER_PACKAGE_SMOKE_START_FAILED' }
        if (-not $process.WaitForExit(10000)) {
            try { $process.Kill($true) } catch { }
            throw 'ADMIN_BROKER_PACKAGE_SMOKE_TIMEOUT'
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if ($process.ExitCode -ne $ExpectedExit -or -not [string]::IsNullOrEmpty($stdout) -or $stderr.Trim() -cne $ExpectedStderr) {
            throw 'ADMIN_BROKER_PACKAGE_SMOKE_MISMATCH'
        }
    } finally { $process.Dispose() }
}

try {
    $null = New-Item -ItemType Directory -Path $hostStage,$probeStage -Force
    if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
    $null = New-Item -ItemType Directory -Path $output -Force

    Invoke-DotNetPublish (Join-Path $repoRoot 'host-agent/src/LDW.AdminBroker.Host/LDW.AdminBroker.Host.csproj') $hostStage
    Invoke-DotNetPublish (Join-Path $repoRoot 'host-agent/src/LDW.LocalSecretProbe/LDW.LocalSecretProbe.csproj') $probeStage

    $hostExe = Join-Path $hostStage 'LDW.AdminBroker.Host.exe'
    $probeExe = Join-Path $probeStage 'LDW.LocalSecretProbe.exe'
    if (-not (Test-Path -LiteralPath $hostExe -PathType Leaf) -or -not (Test-Path -LiteralPath $probeExe -PathType Leaf)) {
        throw 'ADMIN_BROKER_PACKAGE_OUTPUT_MISSING'
    }

    $packagedHost = Join-Path $output 'LDW.AdminBroker.Host.exe'
    $packagedProbe = Join-Path $output 'LDW.LocalSecretProbe.exe'
    Copy-Item -LiteralPath $hostExe -Destination $packagedHost
    Copy-Item -LiteralPath $probeExe -Destination $packagedProbe

    # Harmless runtime smoke checks: no pipe is opened and no secret is read or stored.
    Invoke-ExpectedFailure -Executable $packagedHost -Arguments @('--package-smoke') -ExpectedExit 2 `
        -ExpectedStderr 'This interactive tool accepts no command-line arguments.'
    Invoke-ExpectedFailure -Executable $packagedProbe -Arguments @() -ExpectedExit 1 -ExpectedStderr 'SECRET_MISSING'

    $sourceCommit = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim()
    $sourceTree = (& git -C $repoRoot rev-parse 'HEAD^{tree}' 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[a-f0-9]{40}$' -or $sourceTree -cnotmatch '^[a-f0-9]{40}$') {
        throw 'ADMIN_BROKER_PACKAGE_SOURCE_IDENTITY_FAILED'
    }

    $files = foreach ($name in @('LDW.AdminBroker.Host.exe','LDW.LocalSecretProbe.exe')) {
        $path = Join-Path $output $name
        [ordered]@{
            name = $name
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = (Get-Item -LiteralPath $path).Length
        }
    }
    $manifest = [ordered]@{
        schema = 1
        package = 'ldw-admin-broker-proof'
        runtime = 'win-x64'
        source_commit = $sourceCommit
        source_tree = $sourceTree
        foreground_only = $true
        autostart = $false
        service = $false
        files = @($files)
    }
    $manifestPath = Join-Path $output 'manifest.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $packageFiles = @(Get-ChildItem -LiteralPath $output -File | Sort-Object Name)
    if ($packageFiles.Count -ne 3 -or @($packageFiles.Name) -join ',' -cne 'LDW.AdminBroker.Host.exe,LDW.LocalSecretProbe.exe,manifest.json') {
        throw 'ADMIN_BROKER_PACKAGE_BOUNDARY_REFUSED'
    }

    'ADMIN_BROKER_PACKAGE=PASS'
    'ADMIN_BROKER_PACKAGE_SOURCE_COMMIT=' + $sourceCommit
    'ADMIN_BROKER_PACKAGE_SOURCE_TREE=' + $sourceTree
    'ADMIN_BROKER_PACKAGE_MANIFEST_SHA256=' + $manifestSha
    foreach ($entry in $files) { 'ADMIN_BROKER_PACKAGE_FILE=' + $entry.name + ':' + $entry.sha256 + ':' + $entry.bytes }
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
