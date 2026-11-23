#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only administrator evidence helper for OfficePC Phase 1 (infrastructure-tools #86).

.DESCRIPTION
  SOURCE-ONLY / ZERO RUNTIME AUTHORITY. Collects only the two Phase-1 facts that
  normal-user inventory cannot prove authoritatively:
    1. Secure Boot state via Confirm-SecureBootUEFI
    2. Hyper-V VM counts and status CATEGORIES via Get-VM

  This file never elevates itself, never requests UAC, never uses an execution-policy
  bypass, never mutates state, never reads credentials, never uses the network, and
  never emits VM names, identities, private paths, serials, MAC/IP, or raw error text.
  Authoritative results require the owner to run this file from an ALREADY-ELEVATED
  PowerShell session they sanction. Under a non-elevated shell every authoritative
  field fails closed to UNKNOWN.

  Output is INVENTORY_ONLY_NOT_ADMISSION with jit_authorized=false, no host reserve
  and no proposed guest size. It grants no CI/JIT admission or runtime authority.

  Dot-sourcing loads functions only. Live collection runs only when this file is
  executed directly (powershell -NoProfile -File ...).
#>
[CmdletBinding()]
param(
    [ValidateSet('Json')]
    [string] $Output = 'Json'
)

$ErrorActionPreference = 'Stop'

# Captured at script entry; inside functions $MyInvocation refers to the function.
$script:OfficePcAdminInvokedDirectly = ($MyInvocation.InvocationName -ne '.')

if (-not (Get-Variable -Name OfficePcAdminSuppressAutoInvoke -Scope Script -ErrorAction SilentlyContinue)) {
    $script:OfficePcAdminSuppressAutoInvoke = $false
}

# TEST-ONLY injection hook. No environment, registry, file, or network autoload.
# Never set outside synthetic contract tests; production uses the real OS check.
$script:OfficePcAdminEvidenceElevationOverride = $null

$script:OfficePcAdminMarker = 'LDW_OFFICEPC_ADMIN_EVIDENCE'
$script:OfficePcAdminClassification = 'INVENTORY_ONLY_NOT_ADMISSION'
$script:OfficePcAdminDisposition = 'INVENTORY_BLOCKED'
$script:OfficePcAdminDispositionReason = 'Read-only evidence only. Enrollment, normal-use baseline, cross-host arbitration and JIT admission are not accepted (#86).'

function Test-OfficePcAdminEvidenceForbiddenLeak {
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $patterns = @(
        '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
        '\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
        '@',
        '\\\\[^\\]+\\[^\\]+',
        '[A-Za-z]:\\',
        'GITHUB_TOKEN',
        'password',
        'secret'
    )
    foreach ($pattern in $patterns) {
        if ($Text -match $pattern) { return $true }
    }
    return $false
}

function Test-OfficePcAdminEvidenceElevated {
    if ($null -ne $script:OfficePcAdminEvidenceElevationOverride -and $script:OfficePcAdminEvidenceElevationOverride -is [bool]) {
        return [bool] $script:OfficePcAdminEvidenceElevationOverride
    }
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
        return [bool] $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-OfficePcAdminEvidenceErrorClass {
    param([Parameter(Mandatory = $true)] $ErrorRecord)
    # Classify locally; return only a generic code. The message is never emitted.
    $typeName = ''
    $message = ''
    if ($null -ne $ErrorRecord.Exception) {
        $typeName = $ErrorRecord.Exception.GetType().FullName
        if ($null -ne $ErrorRecord.Exception.Message) { $message = [string] $ErrorRecord.Exception.Message }
    }
    if ($typeName -match 'CommandNotFoundException') { return 'CMDLET_UNAVAILABLE' }
    if ($typeName -match 'UnauthorizedAccess|SecurityException|AuthorizationException') { return 'ACCESS_DENIED' }
    if ($message -match '(?i)access is denied|permission|privilege|not authorized|administrator') { return 'ACCESS_DENIED' }
    if ($message -match '(?i)not supported|not available|not present|uefi|firmware|secure boot') { return 'UNSUPPORTED' }
    return 'QUERY_FAILED'
}

function Get-OfficePcAdminElevationLabel {
    param([AllowNull()] $Value)
    if ($null -eq $Value -or -not ($Value -is [bool])) { return 'UNKNOWN' }
    if ($Value) { return 'ELEVATED' }
    return 'NOT_ELEVATED'
}

function ConvertTo-OfficePcAdminTriState {
    param([AllowNull()] $Value)
    if ($null -eq $Value -or -not ($Value -is [bool])) { return 'UNKNOWN' }
    if ($Value) { return 'ENABLED' }
    return 'DISABLED'
}

function Get-OfficePcAdminSecureBootState {
    param([AllowNull()] $Value)
    switch ([string] $Value) {
        'ENABLED' { return 'ENABLED' }
        'DISABLED' { return 'DISABLED' }
        'UNSUPPORTED' { return 'UNSUPPORTED' }
        default { return 'UNKNOWN' }
    }
}

function Get-OfficePcAdminEvidenceDetail {
    param([AllowNull()] $Value)
    switch ([string] $Value) {
        'AUTHORITATIVE' { return 'AUTHORITATIVE' }
        'NOT_ELEVATED' { return 'NOT_ELEVATED' }
        'CMDLET_UNAVAILABLE' { return 'CMDLET_UNAVAILABLE' }
        'NON_UEFI_OR_UNSUPPORTED' { return 'NON_UEFI_OR_UNSUPPORTED' }
        'UNSUPPORTED' { return 'UNSUPPORTED' }
        'ACCESS_DENIED' { return 'ACCESS_DENIED' }
        'QUERY_FAILED' { return 'QUERY_FAILED' }
        default { return 'UNKNOWN' }
    }
}

function Get-OfficePcAdminVmInventoryState {
    param([AllowNull()] $Value)
    switch ([string] $Value) {
        'OBSERVED' { return 'OBSERVED' }
        default { return 'UNKNOWN' }
    }
}

function ConvertTo-OfficePcAdminBoundedCount {
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool] -or $Value -is [string]) { return $null }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { return $null }
    $number = $null
    if (-not [int]::TryParse([string] $Value, [ref] $number)) { return $null }
    if ($number -lt 0 -or $number -gt 100000) { return $null }
    return $number
}

function New-OfficePcAdminStatusCounts {
    param([AllowNull()] $Counts)
    $allowed = @('Running', 'Off', 'Saved', 'Paused', 'Other')
    $result = [ordered]@{}
    foreach ($key in $allowed) { $result[$key] = 0 }
    if ($null -eq $Counts -or -not ($Counts -is [System.Collections.IDictionary])) { return $result }
    foreach ($key in $allowed) {
        if ($Counts.Contains($key)) {
            $bounded = ConvertTo-OfficePcAdminBoundedCount -Value $Counts[$key]
            if ($null -ne $bounded) { $result[$key] = $bounded }
        }
    }
    return $result
}

function New-OfficePcAdminEvidenceReportFromSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Snapshot
    )

    $elevated = ($Snapshot.ContainsKey('Elevated') -and $Snapshot.Elevated -is [bool] -and $Snapshot.Elevated)

    $secureBootState = 'UNKNOWN'
    $secureBootDetail = 'NOT_ELEVATED'
    if ($elevated) {
        $secureBootState = Get-OfficePcAdminSecureBootState -Value $Snapshot.SecureBootState
        $secureBootDetail = Get-OfficePcAdminEvidenceDetail -Value $Snapshot.SecureBootDetail
        # A positive or negative result is admissible only with authoritative detail.
        if ($secureBootState -in @('ENABLED', 'DISABLED') -and $secureBootDetail -cne 'AUTHORITATIVE') {
            $secureBootState = 'UNKNOWN'
        }
        # The only accepted non-authoritative state/detail pairing is the known unsupported result.
        if ($secureBootState -ceq 'UNSUPPORTED' -and $secureBootDetail -cne 'NON_UEFI_OR_UNSUPPORTED') {
            $secureBootState = 'UNKNOWN'
        }
        # AUTHORITATIVE detail cannot coexist with an UNKNOWN or other state.
        if ($secureBootDetail -ceq 'AUTHORITATIVE' -and $secureBootState -notin @('ENABLED', 'DISABLED')) {
            $secureBootDetail = 'UNKNOWN'
        }
    }

    $vmState = 'UNKNOWN'
    $vmDetail = 'NOT_ELEVATED'
    $vmTotal = $null
    $statusCounts = $null
    if ($elevated) {
        $vmState = Get-OfficePcAdminVmInventoryState -Value $Snapshot.VmInventoryState
        $vmDetail = Get-OfficePcAdminEvidenceDetail -Value $Snapshot.VmDetail
        # OBSERVED requires authoritative detail; AUTHORITATIVE detail requires OBSERVED.
        if ($vmState -ceq 'OBSERVED' -and $vmDetail -cne 'AUTHORITATIVE') {
            $vmState = 'UNKNOWN'
        }
        if ($vmDetail -ceq 'AUTHORITATIVE' -and $vmState -cne 'OBSERVED') {
            $vmDetail = 'UNKNOWN'
        }
        if ($vmState -ceq 'OBSERVED' -and $vmDetail -ceq 'AUTHORITATIVE') {
            $vmTotal = ConvertTo-OfficePcAdminBoundedCount -Value $Snapshot.VmCountTotal
            $statusCounts = New-OfficePcAdminStatusCounts -Counts $Snapshot.VmStatusCounts
            if ($null -eq $vmTotal -or $null -eq $statusCounts) {
                $vmState = 'UNKNOWN'
                $vmTotal = $null
                $statusCounts = $null
            }
            else {
                $bucketSum = 0
                foreach ($key in $statusCounts.Keys) { $bucketSum += [int] $statusCounts[$key] }
                if ($bucketSum -ne $vmTotal) {
                    $vmState = 'UNKNOWN'
                    $vmTotal = $null
                    $statusCounts = $null
                }
            }
        }
    }

    $firmware = $null
    $hypervisor = $null
    if ($Snapshot.ContainsKey('FirmwareVirtualization')) { $firmware = ConvertTo-OfficePcAdminTriState -Value $Snapshot.FirmwareVirtualization }
    if ($Snapshot.ContainsKey('HypervisorPresent')) { $hypervisor = ConvertTo-OfficePcAdminTriState -Value $Snapshot.HypervisorPresent }

    $report = [ordered]@{
        schema                      = 1
        marker                      = $script:OfficePcAdminMarker
        classification              = $script:OfficePcAdminClassification
        disposition                 = $script:OfficePcAdminDisposition
        disposition_reason          = $script:OfficePcAdminDispositionReason
        jit_authorized              = $false
        admission_authorized        = $false
        runtime_blocked             = $true
        officepc_enrolled           = $false
        normal_use_baseline_verified = $false
        host_reserve_mib            = $null
        guest_mib_proposed          = $null
        owner_run                   = [ordered]@{
            invocation_mode                = 'OWNER_LOCAL_READ_ONLY'
            elevation                      = (Get-OfficePcAdminElevationLabel -Value $Snapshot.Elevated)
            self_elevation_attempted       = $false
            execution_policy_bypass_requested = $false
        }
        secure_boot                 = [ordered]@{
            authority = 'Confirm-SecureBootUEFI'
            state     = $secureBootState
            detail    = $secureBootDetail
        }
        hyperv_vm                   = [ordered]@{
            authority       = 'Get-VM'
            inventory_state = $vmState
            detail          = $vmDetail
            vm_count_total  = $vmTotal
            status_counts   = $statusCounts
        }
        virtualization_readiness    = [ordered]@{
            firmware_virtualization = $firmware
            hypervisor_present      = $hypervisor
        }
        recovery                    = [ordered]@{
            winre_status = 'UNVERIFIED'
            note         = 'No trustworthy non-path-emitting preinstalled read-only command is used for WinRE state.'
        }
        collected_at_utc            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }

    $json = $report | ConvertTo-Json -Depth 6 -Compress
    if (Test-OfficePcAdminEvidenceForbiddenLeak -Text $json) {
        throw 'ADMIN_EVIDENCE_REPORT_FORBIDDEN_LEAK'
    }
    return $report
}

function Get-OfficePcAdminEvidenceLiveSnapshot {
    $elevated = Test-OfficePcAdminEvidenceElevated

    $firmware = $null
    $hypervisor = $null
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $cpu -and $null -ne $cpu.VirtualizationFirmwareEnabled) {
            $firmware = [bool] $cpu.VirtualizationFirmwareEnabled
        }
    }
    catch { $firmware = $null }
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $computer -and $null -ne $computer.HypervisorPresent) {
            $hypervisor = [bool] $computer.HypervisorPresent
        }
    }
    catch { $hypervisor = $null }

    $secureBootState = 'UNKNOWN'
    $secureBootDetail = 'NOT_ELEVATED'
    $vmState = 'UNKNOWN'
    $vmDetail = 'NOT_ELEVATED'
    $vmTotal = $null
    $statusCounts = $null

    if ($elevated) {
        if (-not (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
            $secureBootState = 'UNKNOWN'
            $secureBootDetail = 'CMDLET_UNAVAILABLE'
        }
        else {
            try {
                $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
                if ($secureBoot -is [bool]) {
                    $secureBootState = if ($secureBoot) { 'ENABLED' } else { 'DISABLED' }
                    $secureBootDetail = 'AUTHORITATIVE'
                }
                else {
                    $secureBootState = 'UNKNOWN'
                    $secureBootDetail = 'QUERY_FAILED'
                }
            }
            catch {
                $class = Get-OfficePcAdminEvidenceErrorClass -ErrorRecord $_
                $secureBootDetail = $class
                if ($class -eq 'UNSUPPORTED') {
                    $secureBootState = 'UNSUPPORTED'
                    $secureBootDetail = 'NON_UEFI_OR_UNSUPPORTED'
                }
                else {
                    $secureBootState = 'UNKNOWN'
                }
            }
        }

        if (-not (Get-Command -Name Get-VM -ErrorAction SilentlyContinue)) {
            $vmState = 'UNKNOWN'
            $vmDetail = 'CMDLET_UNAVAILABLE'
        }
        else {
            try {
                $vms = @(Get-VM -ErrorAction Stop)
                $vmTotal = $vms.Count
                $counts = @{ Running = 0; Off = 0; Saved = 0; Paused = 0; Other = 0 }
                foreach ($vm in $vms) {
                    $bucket = 'Other'
                    if ($null -ne $vm -and $null -ne $vm.State) {
                        switch ([string] $vm.State) {
                            'Running' { $bucket = 'Running' }
                            'Off' { $bucket = 'Off' }
                            'Saved' { $bucket = 'Saved' }
                            'Paused' { $bucket = 'Paused' }
                            default { $bucket = 'Other' }
                        }
                    }
                    $counts[$bucket]++
                }
                $statusCounts = $counts
                $vmState = 'OBSERVED'
                $vmDetail = 'AUTHORITATIVE'
            }
            catch {
                $vmState = 'UNKNOWN'
                $vmDetail = Get-OfficePcAdminEvidenceErrorClass -ErrorRecord $_
                $vmTotal = $null
                $statusCounts = $null
            }
        }
    }

    return @{
        Elevated                = $elevated
        SecureBootState         = $secureBootState
        SecureBootDetail        = $secureBootDetail
        VmInventoryState        = $vmState
        VmDetail                = $vmDetail
        VmCountTotal            = $vmTotal
        VmStatusCounts          = $statusCounts
        FirmwareVirtualization  = $firmware
        HypervisorPresent       = $hypervisor
    }
}

function Test-OfficePcAdminDirectExecution {
    if ($script:OfficePcAdminSuppressAutoInvoke) { return $false }
    return $script:OfficePcAdminInvokedDirectly
}

function Invoke-OfficePcAdminEvidenceCollection {
    $snapshot = Get-OfficePcAdminEvidenceLiveSnapshot
    return (New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $snapshot)
}

if (Test-OfficePcAdminDirectExecution) {
    $result = Invoke-OfficePcAdminEvidenceCollection
    if ($Output -eq 'Json') {
        $result | ConvertTo-Json -Depth 6
    }
}
