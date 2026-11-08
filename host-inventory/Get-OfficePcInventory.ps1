#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only OfficePC Phase-1 host inventory (local normal user; evidence only).

.DESCRIPTION
  Collects bounded, non-sensitive hardware/OS facts when invoked on OfficePC by the
  owner. Output is INVENTORY_ONLY_NOT_ADMISSION; disposition remains INVENTORY_BLOCKED
  until enrollment and normal-use baseline are separately accepted.

  Dot-sourcing loads functions only. Live collection runs only when this script file
  is executed directly (powershell -File), not when dot-sourced for contract tests.
#>
[CmdletBinding()]
param(
    [ValidateRange(3, 6)]
    [int] $SampleCount = 3,

    [ValidateRange(1, 5)]
    [int] $IntervalSeconds = 1,

    [ValidateSet('Json')]
    [string] $Output = 'Json'
)

$ErrorActionPreference = 'Stop'

$script:OfficePcInventoryMarker = 'LDW_OFFICEPC_HOST_INVENTORY'
$script:OfficePcInventoryClassification = 'INVENTORY_ONLY_NOT_ADMISSION'
$script:OfficePcInventoryDisposition = 'INVENTORY_BLOCKED'
$script:OfficePcInventoryDispositionReason = 'OfficePC enrollment and normal-use baseline are not accepted; inventory is evidence-only until owner readback on the enrolled host.'
$script:OfficePcInventoryMaxCpuModelLength = 128
$script:OfficePcInventoryMaxEditionLength = 64

function Test-OfficePcInventoryForbiddenLeak {
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $patterns = @(
        '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
        '\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
        '@',
        '\\\\[^\\]+\\[^\\]+',
        'GITHUB_TOKEN',
        'password',
        'secret'
    )
    foreach ($pattern in $patterns) {
        if ($Text -match $pattern) { return $true }
    }
    return $false
}

function ConvertTo-OfficePcSanitizedCpuModel {
    param([AllowNull()] $Raw)
    if ($null -eq $Raw -or [string]::IsNullOrWhiteSpace([string] $Raw)) { return $null }
    $text = ([string] $Raw).Trim()
    if (Test-OfficePcInventoryForbiddenLeak -Text $text) { throw 'INVENTORY_CPU_MODEL_REFUSED' }
    $builder = New-Object System.Text.StringBuilder
    foreach ($ch in $text.ToCharArray()) {
        if ($ch -match '[\p{L}\p{N}\s()._/-]' -and $builder.Length -lt $script:OfficePcInventoryMaxCpuModelLength) {
            [void] $builder.Append($ch)
        }
    }
    $sanitized = $builder.ToString().Trim()
    if ($sanitized.Length -lt 1) { return $null }
    return $sanitized
}

function ConvertTo-OfficePcArchitectureLabel {
    param([AllowNull()] $Architecture)
    if ($null -eq $Architecture) { return $null }
    switch ([int] $Architecture) {
        0 { return 'x86' }
        1 { return 'mips' }
        2 { return 'alpha' }
        3 { return 'powerpc' }
        5 { return 'arm' }
        6 { return 'ia64' }
        9 { return 'x64' }
        12 { return 'arm64' }
        default { return 'unknown' }
    }
}

function Test-OfficePcInventorySampleCount {
    param([int] $Count)
    return ($Count -ge 3 -and $Count -le 6)
}

function Test-OfficePcInventoryIntervalSeconds {
    param([int] $Seconds)
    return ($Seconds -ge 1 -and $Seconds -le 5)
}

function Test-OfficePcNonNegativeInteger {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -isnot [int] -and $Value -isnot [long]) { return $false }
    return ([int64] $Value -ge 0)
}

function Test-OfficePcPositiveInteger {
    param($Value)
    if (-not (Test-OfficePcNonNegativeInteger -Value $Value)) { return $false }
    return ([int64] $Value -gt 0)
}

function Get-OfficePcEnumTriState {
    param(
        [AllowNull()] $Value,
        [string] $TrueLabel = 'ENABLED',
        [string] $FalseLabel = 'DISABLED'
    )
    if ($null -eq $Value) { return 'UNKNOWN' }
    if ($Value -is [bool]) {
        if ($Value) { return $TrueLabel }
        return $FalseLabel
    }
    return 'UNKNOWN'
}

function New-OfficePcInventoryReportFromSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Snapshot
    )

    $totalPhysicalMib = $null
    if (Test-OfficePcPositiveInteger -Value $Snapshot.TotalVisibleMemoryKib) {
        $totalPhysicalMib = [int] [math]::Floor([int64] $Snapshot.TotalVisibleMemoryKib / 1024)
    }

    $memorySamples = $null
    $allSamplesValid = $true
    if ($null -ne $Snapshot.FreePhysicalMemorySamplesKib) {
        $samples = @($Snapshot.FreePhysicalMemorySamplesKib)
        if ($samples.Count -lt 3 -or $samples.Count -gt 6) {
            $allSamplesValid = $false
        }
        else {
            $converted = New-Object System.Collections.Generic.List[int]
            foreach ($sample in $samples) {
                if (-not (Test-OfficePcNonNegativeInteger -Value $sample)) {
                    $allSamplesValid = $false
                    break
                }
                [void] $converted.Add([int] [math]::Floor([int64] $sample / 1024))
            }
            if ($allSamplesValid) {
                $memorySamples = @($converted)
            }
        }
    }
    else {
        $allSamplesValid = $false
    }

    $systemVolumeFreeGib = $null
    if (Test-OfficePcNonNegativeInteger -Value $Snapshot.SystemVolumeFreeBytes) {
        $systemVolumeFreeGib = [math]::Round([double] $Snapshot.SystemVolumeFreeBytes / 1GB, 2)
    }

    $logicalProcessors = $null
    if (Test-OfficePcPositiveInteger -Value $Snapshot.LogicalProcessorCount) {
        $logicalProcessors = [int] $Snapshot.LogicalProcessorCount
    }

    $build = $null
    if (Test-OfficePcNonNegativeInteger -Value $Snapshot.OsBuildNumber) {
        $build = [string] [int] $Snapshot.OsBuildNumber
    }

    $edition = $null
    if ($null -ne $Snapshot.OsCaption -and -not [string]::IsNullOrWhiteSpace([string] $Snapshot.OsCaption)) {
        $edition = ([string] $Snapshot.OsCaption).Trim()
        if ($edition.Length -gt $script:OfficePcInventoryMaxEditionLength) {
            $edition = $edition.Substring(0, $script:OfficePcInventoryMaxEditionLength)
        }
    }

    $report = [ordered]@{
        schema                     = 1
        marker                     = $script:OfficePcInventoryMarker
        classification             = $script:OfficePcInventoryClassification
        disposition                = $script:OfficePcInventoryDisposition
        disposition_reason         = $script:OfficePcInventoryDispositionReason
        jit_authorized             = $false
        officepc_enrolled          = $false
        normal_use_baseline_verified = $false
        host_reserve_mib           = $null
        runtime_blocked            = $true
        os                         = [ordered]@{
            edition      = $edition
            build        = $build
            architecture = $Snapshot.OsArchitecture
        }
        cpu                        = [ordered]@{
            architecture        = $Snapshot.CpuArchitecture
            model               = (ConvertTo-OfficePcSanitizedCpuModel -Raw $Snapshot.CpuModel)
            logical_processors    = $logicalProcessors
        }
        memory_mib                 = [ordered]@{
            total_physical    = $totalPhysicalMib
            samples_free_mib  = $memorySamples
        }
        system_volume_free_gib     = $systemVolumeFreeGib
        hyper_v_optional_feature   = (Get-OfficePcEnumTriState -Value $Snapshot.HyperVEnabled)
        firmware_virtualization    = (Get-OfficePcEnumTriState -Value $Snapshot.FirmwareVirtualizationEnabled)
        power                      = [ordered]@{
            on_ac          = $(if ($null -eq $Snapshot.OnAcPower) { 'UNKNOWN' } else { (Get-OfficePcEnumTriState -Value $Snapshot.OnAcPower -TrueLabel 'AC' -FalseLabel 'BATTERY') })
            sleep_policy   = $(if ($null -eq $Snapshot.SleepPolicyVerified) { 'UNVERIFIED' } elseif ($Snapshot.SleepPolicyVerified -eq $true) { 'OBSERVED' } else { 'UNVERIFIED' })
        }
        sample_count               = $Snapshot.SampleCount
        sample_interval_seconds    = $Snapshot.IntervalSeconds
        collected_at_utc           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }

    $json = $report | ConvertTo-Json -Depth 6 -Compress
    if (Test-OfficePcInventoryForbiddenLeak -Text $json) {
        throw 'INVENTORY_REPORT_FORBIDDEN_LEAK'
    }
    return $report
}

function Get-OfficePcLiveSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(3, 6)]
        [int] $SampleCount,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 5)]
        [int] $IntervalSeconds
    )

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

    $freeSamples = New-Object System.Collections.Generic.List[uint64]
    for ($i = 0; $i -lt $SampleCount; $i++) {
        $sampleOs = if ($i -eq 0) { $os } else { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
        if ($null -eq $sampleOs -or $null -eq $sampleOs.FreePhysicalMemory) {
            throw 'INVENTORY_CIM_UNAVAILABLE'
        }
        [void] $freeSamples.Add([uint64] $sampleOs.FreePhysicalMemory)
        if ($i -lt ($SampleCount - 1)) {
            Start-Sleep -Seconds $IntervalSeconds
        }
    }

    $systemVolumeFreeBytes = $null
    try {
        $driveName = $env:SystemDrive.TrimEnd(':')
        $psDrive = Get-PSDrive -Name $driveName -ErrorAction Stop
        if ($null -ne $psDrive.Free) {
            $systemVolumeFreeBytes = [int64] $psDrive.Free
        }
    }
    catch {
        $systemVolumeFreeBytes = $null
    }

    $hyperV = $null
    try {
        if (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
            if ($null -ne $feature -and $feature.State -eq 'Enabled') { $hyperV = $true }
            elseif ($null -ne $feature -and $feature.State -eq 'Disabled') { $hyperV = $false }
        }
    }
    catch {
        $hyperV = $null
    }

    $firmwareVirt = $null
    if ($null -ne $cpu -and $null -ne $cpu.VirtualizationFirmwareEnabled) {
        $firmwareVirt = [bool] $cpu.VirtualizationFirmwareEnabled
    }

    $onAc = $null
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $battery -and $null -ne $battery.BatteryStatus) {
        $onAc = ($battery.BatteryStatus -in 3, 6, 7, 8, 9)
    }

    return @{
        OsCaption                         = $os.Caption
        OsBuildNumber                     = $os.BuildNumber
        OsArchitecture                      = $env:PROCESSOR_ARCHITECTURE
        TotalVisibleMemoryKib               = $os.TotalVisibleMemorySize
        FreePhysicalMemorySamplesKib        = @($freeSamples)
        LogicalProcessorCount               = if ($null -ne $computer) { $computer.NumberOfLogicalProcessors } else { $null }
        CpuModel                            = if ($null -ne $cpu) { $cpu.Name } else { $null }
        CpuArchitecture                     = if ($null -ne $cpu) { (ConvertTo-OfficePcArchitectureLabel -Architecture $cpu.Architecture) } else { $null }
        SystemVolumeFreeBytes               = $systemVolumeFreeBytes
        HyperVEnabled                       = $hyperV
        FirmwareVirtualizationEnabled       = $firmwareVirt
        OnAcPower                           = $onAc
        SleepPolicyVerified                 = $false
        SampleCount                         = $SampleCount
        IntervalSeconds                     = $IntervalSeconds
    }
}

function Invoke-OfficePcInventoryCollection {
    param(
        [ValidateRange(3, 6)]
        [int] $SampleCount = 3,

        [ValidateRange(1, 5)]
        [int] $IntervalSeconds = 1
    )

    if (-not (Test-OfficePcInventorySampleCount -Count $SampleCount)) {
        throw 'INVENTORY_SAMPLE_COUNT_REFUSED'
    }
    if (-not (Test-OfficePcInventoryIntervalSeconds -Seconds $IntervalSeconds)) {
        throw 'INVENTORY_INTERVAL_REFUSED'
    }

    $snapshot = Get-OfficePcLiveSnapshot -SampleCount $SampleCount -IntervalSeconds $IntervalSeconds
    return (New-OfficePcInventoryReportFromSnapshot -Snapshot $snapshot)
}

if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.ScriptName -and (Split-Path -Leaf $MyInvocation.ScriptName) -eq 'Get-OfficePcInventory.ps1') {
    if (-not (Test-OfficePcInventorySampleCount -Count $SampleCount)) { throw 'INVENTORY_SAMPLE_COUNT_REFUSED' }
    if (-not (Test-OfficePcInventoryIntervalSeconds -Seconds $IntervalSeconds)) { throw 'INVENTORY_INTERVAL_REFUSED' }
    $result = Invoke-OfficePcInventoryCollection -SampleCount $SampleCount -IntervalSeconds $IntervalSeconds
    if ($Output -eq 'Json') {
        $result | ConvertTo-Json -Depth 6
    }
}
