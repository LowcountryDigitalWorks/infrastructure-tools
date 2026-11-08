#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "ASSERT_FAILED:$Message" }
}

function Assert-ThrowsMessage {
    param([scriptblock] $Block, [string] $Pattern, [string] $Label)
    $threw = $false
    try { & $Block } catch { $threw = $_.Exception.Message -match $Pattern }
    Assert-True $threw "expected throw matching $Pattern for $Label"
}

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$scriptPath = Join-Path $repoRoot 'host-inventory/Get-OfficePcInventory.ps1'
$script:OfficePcInventorySuppressAutoInvoke = $true
. $scriptPath

function New-OfficePcSyntheticSnapshot {
    param(
        [int] $SampleCount = 3,
        [object[]] $FreeSamplesKib = @(800000, 790000, 785000),
        [int] $TotalKib = 16777216
    )
    return @{
        OsCaption                         = 'Microsoft Windows 11 Pro'
        OsBuildNumber                     = '22631'
        OsArchitecture                      = 'AMD64'
        TotalVisibleMemoryKib               = $TotalKib
        FreePhysicalMemorySamplesKib        = $FreeSamplesKib
        LogicalProcessorCount               = 8
        CpuModel                            = 'Synthetic AMD64 Model (contract)'
        CpuArchitecture                     = 'x64'
        SystemVolumeFreeBytes               = 100GB
        HyperVEnabled                       = $null
        FirmwareVirtualizationEnabled       = $null
        OnAcPower                           = $null
        SleepPolicyVerified                 = $false
        SampleCount                         = $SampleCount
        IntervalSeconds                     = 1
    }
}

Assert-True (Test-OfficePcInventorySampleCount -Count 3) 'sample 3'
Assert-True (Test-OfficePcInventorySampleCount -Count 6) 'sample 6'
Assert-True (-not (Test-OfficePcInventorySampleCount -Count 2)) 'sample 2 refused'
Assert-True (-not (Test-OfficePcInventorySampleCount -Count 7)) 'sample 7 refused'
Assert-True (Test-OfficePcInventoryIntervalSeconds -Seconds 1) 'interval 1'
Assert-True (Test-OfficePcInventoryIntervalSeconds -Seconds 5) 'interval 5'
Assert-True (-not (Test-OfficePcInventoryIntervalSeconds -Seconds 0)) 'interval 0 refused'

$base = New-OfficePcInventoryReportFromSnapshot -Snapshot (New-OfficePcSyntheticSnapshot)
Assert-True ($base.classification -eq 'INVENTORY_ONLY_NOT_ADMISSION') 'classification'
Assert-True ($base.disposition -eq 'INVENTORY_BLOCKED') 'disposition blocked'
Assert-True ($base.jit_authorized -eq $false) 'jit false'
Assert-True ($base.officepc_enrolled -eq $false) 'enrolled false'
Assert-True ($base.normal_use_baseline_verified -eq $false) 'baseline false'
Assert-True ($null -eq $base.host_reserve_mib) 'host reserve null'
Assert-True ($base.runtime_blocked -eq $true) 'runtime blocked'
Assert-True ($base.os.build -eq '22631') 'os build string'
Assert-True ($base.os.architecture -eq 'AMD64') 'os architecture whitelist'
Assert-True ($null -ne $base.memory_mib.samples_free_mib -and $base.memory_mib.samples_free_mib.Count -eq 3) 'memory samples'

$uintSnapshot = New-OfficePcSyntheticSnapshot
$uintSnapshot.TotalVisibleMemoryKib = [uint64] 16777216
$uintSnapshot.FreePhysicalMemorySamplesKib = @([uint64] 800000, [uint64] 790000, [uint64] 785000)
$uintSnapshot.LogicalProcessorCount = [uint32] 12
$uintReport = New-OfficePcInventoryReportFromSnapshot -Snapshot $uintSnapshot
Assert-True ($uintReport.memory_mib.total_physical -eq 16384) 'uint64 total physical'
Assert-True ($uintReport.cpu.logical_processors -eq 12) 'uint32 logical processors'
Assert-True ($null -ne $uintReport.memory_mib.samples_free_mib) 'uint64 samples accepted'

$badArch = New-OfficePcSyntheticSnapshot
$badArch.OsArchitecture = 'WOW64'
$badArchReport = New-OfficePcInventoryReportFromSnapshot -Snapshot $badArch
Assert-True ($badArchReport.os.architecture -eq 'UNKNOWN') 'unknown os arch'
Assert-True ($base.hyper_v_optional_feature -eq 'UNKNOWN') 'hyper-v unknown'
Assert-True ($base.firmware_virtualization -eq 'UNKNOWN') 'firmware unknown'
Assert-True ($base.power.sleep_policy -eq 'UNVERIFIED') 'sleep unverified'

$json = $base | ConvertTo-Json -Depth 6 -Compress
Assert-True (-not (Test-OfficePcInventoryForbiddenLeak -Text $json)) 'no forbidden leak base'
Assert-True ($json -notmatch 'LDW01|6144|CANDIDATE_PASS|GITHUB') 'no forbidden tokens'

$badSamples = New-OfficePcSyntheticSnapshot -FreeSamplesKib @(100, [double]::NaN, 200)
$badReport = New-OfficePcInventoryReportFromSnapshot -Snapshot $badSamples
Assert-True ($null -eq $badReport.memory_mib.samples_free_mib) 'nan samples omitted'

$shortSamples = New-OfficePcSyntheticSnapshot -FreeSamplesKib @(100, 200)
$shortReport = New-OfficePcInventoryReportFromSnapshot -Snapshot $shortSamples
Assert-True ($null -eq $shortReport.memory_mib.samples_free_mib) 'too few samples omitted'

$negativeTotal = New-OfficePcSyntheticSnapshot -TotalKib -5
$negReport = New-OfficePcInventoryReportFromSnapshot -Snapshot $negativeTotal
Assert-True ($null -eq $negReport.memory_mib.total_physical) 'negative total hold'

$secretSnapshot = New-OfficePcSyntheticSnapshot
$secretSnapshot.CpuModel = 'SECRET user@contoso.com MAC 00:11:22:33:44:55'
Assert-ThrowsMessage { New-OfficePcInventoryReportFromSnapshot -Snapshot $secretSnapshot } 'CPU_MODEL_REFUSED' 'secret leak refused'

$enabled = New-OfficePcSyntheticSnapshot
$enabled.HyperVEnabled = $true
$enReport = New-OfficePcInventoryReportFromSnapshot -Snapshot $enabled
Assert-True ($enReport.hyper_v_optional_feature -eq 'ENABLED') 'hyper-v enabled'

$snap = New-OfficePcSyntheticSnapshot
$runA = New-OfficePcInventoryReportFromSnapshot -Snapshot $snap
$runB = New-OfficePcInventoryReportFromSnapshot -Snapshot $snap
Assert-True ($runA.cpu.model -eq $runB.cpu.model) 'deterministic cpu model'
Assert-True (($runA.memory_mib.samples_free_mib -join ',') -eq ($runB.memory_mib.samples_free_mib -join ',')) 'deterministic memory samples'
Assert-True ($runA.disposition -eq $runB.disposition) 'deterministic disposition'

Assert-True ((ConvertTo-OfficePcSanitizedCpuModel -Raw '  AMD (R) Test') -eq 'AMD (R) Test') 'cpu sanitize'

Assert-True ($null -eq (ConvertTo-OfficePcBoundedUInt64 -Value 2.5)) 'reject double ram'
Assert-True ($null -eq (ConvertTo-OfficePcBoundedUInt64 -Value 0.5)) 'reject fractional ram'
Assert-True ($null -eq (ConvertTo-OfficePcBoundedUInt64 -Value ([double]::NaN))) 'reject nan ram'
Assert-True ($null -eq (ConvertTo-OfficePcBoundedUInt64 -Value '1234')) 'reject numeric string ram'
Assert-True ($null -eq (ConvertTo-OfficePcBoundedUInt64 -Value ([uint64] '18446744073709551615'))) 'reject uint64 overflow'
Assert-True ((ConvertTo-OfficePcBuildNumberString -Value '22631') -eq '22631') 'build string accepted'
Assert-True ((ConvertTo-OfficePcBuildNumberString -Value ([uint32] 22631)) -eq '22631') 'build integer accepted'

Assert-True (-not (Test-OfficePcInventoryDirectExecution)) 'dot-source is not direct execution'

$env:OFFICEPC_INVENTORY_USE_SYNTHETIC_CIM = '1'
$maliciousHook = Join-Path $PSScriptRoot 'MaliciousAutoloadHook.ps1'
Assert-True (-not (Test-Path -LiteralPath $maliciousHook)) 'malicious hook absent in repo'
$sourceText = Get-Content -LiteralPath $scriptPath -Raw
Assert-True ($sourceText -notmatch 'OFFICEPC_INVENTORY_USE_SYNTHETIC_CIM') 'no env autoload in source'
Assert-True ($sourceText -notmatch 'SyntheticCimHook') 'no hook filename in source'
Remove-Item Env:OFFICEPC_INVENTORY_USE_SYNTHETIC_CIM -ErrorAction SilentlyContinue

$escapedScript = $scriptPath.Replace("'", "''")
$childCommand = @"
`$ErrorActionPreference = 'Stop'
function Get-CimInstance {
    param([string] `$ClassName)
    switch (`$ClassName) {
        'Win32_OperatingSystem' {
            return [pscustomobject]@{
                Caption = 'Synthetic Windows'
                BuildNumber = '22631'
                TotalVisibleMemorySize = [uint64]33554432
                FreePhysicalMemory = [uint64]800000
            }
        }
        'Win32_Processor' {
            return [pscustomobject]@{
                Name = 'Synthetic Processor'
                Architecture = 9
                VirtualizationFirmwareEnabled = `$false
            }
        }
        'Win32_ComputerSystem' { return [pscustomobject]@{ NumberOfLogicalProcessors = [uint32]16 } }
        'Win32_Battery' { return `$null }
        default { return `$null }
    }
}
function Get-PSDrive {
    param([string] `$Name)
    return [pscustomobject]@{ Free = [int64]107374182400 }
}
function Get-WindowsOptionalFeature { return `$null }
& '$escapedScript' -SampleCount 3 -IntervalSeconds 1 -Output Json
"@
$fileLines = powershell -NoProfile -Command $childCommand
$fileText = ($fileLines | Where-Object { $_ -ne $null } | ForEach-Object { $_.ToString() }) -join "`n"
Assert-True ($fileText.Trim().StartsWith('{')) 'file invocation json payload'
$fileObject = $fileText | ConvertFrom-Json
Assert-True ($fileObject.disposition -eq 'INVENTORY_BLOCKED') 'file blocked disposition'
Assert-True ($fileObject.cpu.logical_processors -eq 16) 'mocked cim logical processors'

$staleHook = Join-Path $PSScriptRoot 'SyntheticCimHook.ps1'
if (Test-Path -LiteralPath $staleHook) { Remove-Item -LiteralPath $staleHook -Force }

if ($PSVersionTable.PSVersion.Major -ge 7) {
    Assert-True $true 'powershell 7 contract pass'
}
else {
    Assert-True $true 'powershell 5.1 contract pass'
}

Write-Output 'OFFICEPC_INVENTORY_CONTRACTS=PASS'
