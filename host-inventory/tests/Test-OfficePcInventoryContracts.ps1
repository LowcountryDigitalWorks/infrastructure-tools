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
$script:OfficePcInventoryCimCallCount = 0

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

$script:OfficePcInventoryLiveCollector = {
    $script:OfficePcInventoryCimCallCount++
    throw 'CIM_MUST_NOT_RUN_IN_DOT_SOURCE'
}
Assert-ThrowsMessage { Invoke-OfficePcInventoryCollection -SampleCount 3 -IntervalSeconds 1 } 'CIM_MUST_NOT' 'injected collector blocks live path'
$script:OfficePcInventoryLiveCollector = $null
Assert-True ($script:OfficePcInventoryCimCallCount -eq 1) 'collector invoked once under inject'

$hookPath = Join-Path $PSScriptRoot 'SyntheticCimHook.ps1'
$hookBody = @'
$script:OfficePcInventoryLiveCollector = {
    param($SampleCount, $IntervalSeconds)
    $samples = [System.Collections.Generic.List[uint64]]::new()
    for ($i = 0; $i -lt $SampleCount; $i++) { [void]$samples.Add([uint64](800000 - ($i * 1000))) }
    return @{
        OsCaption = 'Synthetic Windows'; OsBuildNumber = [uint32]22631; OsArchitecture = 'AMD64'
        TotalVisibleMemoryKib = [uint64]33554432; FreePhysicalMemorySamplesKib = @($samples)
        LogicalProcessorCount = [uint32]16; CpuModel = 'Synthetic'; CpuArchitecture = 'x64'
        SystemVolumeFreeBytes = [uint64]107374182400; HyperVEnabled = $null; FirmwareVirtualizationEnabled = $null
        OnAcPower = $null; SleepPolicyVerified = $false; SampleCount = $SampleCount; IntervalSeconds = $IntervalSeconds
    }
}
'@
Set-Content -LiteralPath $hookPath -Value $hookBody -Encoding UTF8
$fileLines = & {
    $prev = $env:OFFICEPC_INVENTORY_USE_SYNTHETIC_CIM
    $env:OFFICEPC_INVENTORY_USE_SYNTHETIC_CIM = '1'
    try {
        & powershell -NoProfile -File $scriptPath -SampleCount 3 -IntervalSeconds 1 -Output Json
    }
    finally {
        if ($null -eq $prev) { Remove-Item Env:OFFICEPC_INVENTORY_USE_SYNTHETIC_CIM -ErrorAction SilentlyContinue }
        else { $env:OFFICEPC_INVENTORY_USE_SYNTHETIC_CIM = $prev }
    }
}
$fileText = ($fileLines | Where-Object { $_ -ne $null } | ForEach-Object { $_.ToString() }) -join "`n"
Assert-True ($fileText.Trim().StartsWith('{')) 'single json payload'
$fileObject = $fileText | ConvertFrom-Json
Assert-True ($fileObject.disposition -eq 'INVENTORY_BLOCKED') 'file json blocked'
Assert-True ($fileObject.cpu.logical_processors -eq 16) 'file synthetic uint32 cpus'
Remove-Item -LiteralPath $hookPath -Force -ErrorAction SilentlyContinue

if ($PSVersionTable.PSVersion.Major -ge 7) {
    Assert-True $true 'powershell 7 contract pass'
}
else {
    Assert-True $true 'powershell 5.1 contract pass'
}

Write-Output 'OFFICEPC_INVENTORY_CONTRACTS=PASS'
