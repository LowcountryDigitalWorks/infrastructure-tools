[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory)) {
    throw 'OutputDirectory must be an absolute local path.'
}

$uri = [Uri]::new($OutputDirectory)
if ($uri.IsUnc) {
    throw 'OutputDirectory must be local, not UNC/network storage.'
}

$dotnet = Get-Command dotnet -ErrorAction Stop
$versionText = (& $dotnet.Source --version).Trim()
$majorText = ($versionText -split '\.')[0]
$major = 0
if (-not [int]::TryParse($majorText, [ref]$major) -or $major -lt 10) {
    throw "The .NET 10 SDK or newer is required. Found '$versionText'."
}

$scriptRoot = Split-Path -Parent $PSCommandPath
$hostAgentRoot = Split-Path -Parent $scriptRoot
$project = Join-Path $hostAgentRoot 'src\LDW.HostAgent.HyperVObserver\LDW.HostAgent.HyperVObserver.csproj'

if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
    throw 'Hyper-V observer project could not be resolved relative to this deployment script.'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

& $dotnet.Source publish $project `
    -c Release `
    -r win-x64 `
    --self-contained false `
    --no-restore:$false `
    -o $OutputDirectory

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}

$exe = Join-Path $OutputDirectory 'LDW.HostAgent.HyperVObserver.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'Publish completed without the expected helper executable.'
}

$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()

[pscustomobject]@{
    DotNetSdk = $versionText
    Published = $true
    ReleaseId = $hash.Substring(0, 16)
}
