[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$publisherPath = Join-Path $deployRoot 'Publish-AdminBrokerProofPackage.ps1'
$source = Get-Content -LiteralPath $publisherPath -Raw
$script:Assertions = 0

function Assert-True([bool]$Condition,[string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

foreach ($required in @(
    'host-agent/src/LDW.AdminBroker.Host/LDW.AdminBroker.Host.csproj',
    'host-agent/src/LDW.LocalSecretProbe/LDW.LocalSecretProbe.csproj',
    "-r win-x64 --self-contained true",
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=None',
    '-p:DebugSymbols=false',
    'LDW.AdminBroker.Host.exe',
    'LDW.LocalSecretProbe.exe',
    'manifest.json',
    "Invoke-ExpectedFailure `$packagedHost @('--package-smoke') 2 'This interactive tool accepts no command-line arguments.'",
    "Invoke-ExpectedFailure `$packagedProbe @() 1 'SECRET_MISSING'",
    "package = 'ldw-admin-broker-proof'",
    "runtime = 'win-x64'",
    'foreground_only = $true',
    'autostart = $false',
    'service = $false',
    "Get-FileHash -LiteralPath `$path -Algorithm SHA256",
    "rev-parse HEAD",
    "rev-parse 'HEAD^{tree}'",
    'ADMIN_BROKER_PACKAGE=PASS',
    'ADMIN_BROKER_PACKAGE_MANIFEST_SHA256='
)) {
    Assert-True ($source.Contains($required,[StringComparison]::Ordinal)) "publisher must preserve fixed package contract: $required"
}

foreach ($forbidden in @(
    'Invoke-WebRequest','Invoke-RestMethod','Start-BitsTransfer','curl.exe','wget.exe',
    'Register-ScheduledTask','New-ScheduledTask','Start-ScheduledTask','New-Service',
    'sc.exe','Set-Service','Set-ItemProperty','New-NetFirewall','Set-NetFirewall',
    'HttpListener','TcpListener','NamedPipeServerStream','ProcessStartInfo.FileName = "cmd',
    'ProcessStartInfo.FileName = "powershell','ProcessStartInfo.FileName = "pwsh'
)) {
    Assert-True (-not $source.Contains($forbidden,[StringComparison]::OrdinalIgnoreCase)) "publisher must exclude mutation/network primitive: $forbidden"
}

Assert-True ($source.Contains('$packageFiles.Count -ne 3',[StringComparison]::Ordinal)) 'package must contain exactly three files'
Assert-True ($source.Contains('LDW.AdminBroker.Host.exe,LDW.LocalSecretProbe.exe,manifest.json',[StringComparison]::Ordinal)) 'package boundary must be exact'
Assert-True ($source.Contains('[Diagnostics.ProcessStartInfo]::new()',[StringComparison]::Ordinal)) 'smoke checks must launch only fixed package executables'
Assert-True ($source.Contains('$start.FileName = $Executable',[StringComparison]::Ordinal)) 'smoke helper must use its fixed executable argument'
Assert-True (-not $source.Contains('Environment[', [StringComparison]::OrdinalIgnoreCase)) 'publisher must not set secret environment variables'

Write-Host "Admin Broker package contract assertions PASS: $script:Assertions"
