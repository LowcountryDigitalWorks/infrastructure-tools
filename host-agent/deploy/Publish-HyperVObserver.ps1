[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'HyperVObserverDeployment.psm1') -Force
Assert-HyperVObserverLocalAbsolutePath -Path $OutputDirectory -Name 'OutputDirectory'

if (Test-Path -LiteralPath $OutputDirectory) {
    $existing = @(Get-ChildItem -LiteralPath $OutputDirectory -Force)
    if ($existing.Count -ne 0) {
        throw 'OutputDirectory must be empty. Refusing to delete or overwrite arbitrary local files.'
    }
}
else {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

$dotnet = Get-Command dotnet -ErrorAction Stop
$versionText = (& $dotnet.Source --version).Trim()
$major = 0
if (-not [int]::TryParse(($versionText -split '\.')[0], [ref]$major) -or $major -lt 10) {
    throw "The .NET 10 SDK or newer is required. Found '$versionText'."
}

$hostAgentRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $hostAgentRoot 'src\LDW.HostAgent.HyperVObserver\LDW.HostAgent.HyperVObserver.csproj'
if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
    throw 'Hyper-V observer project could not be resolved relative to this deployment script.'
}

& $dotnet.Source publish $project `
    -c Release `
    -r win-x64 `
    --self-contained false `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -o $OutputDirectory

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}

$manifest = New-HyperVObserverDeploymentManifest -Directory $OutputDirectory
$verified = Test-HyperVObserverDeploymentManifest -Directory $OutputDirectory
if (-not [string]::Equals($manifest.ReleaseFingerprintSha256, $verified.ReleaseFingerprintSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fresh publish manifest did not verify deterministically.'
}

[pscustomobject]@{
    DotNetSdk = $versionText
    Published = $true
    ReleaseId = $verified.ReleaseId
    FileCount = @($verified.Entries).Count
    ManifestVerified = $true
}
