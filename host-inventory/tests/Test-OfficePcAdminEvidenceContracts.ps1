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
$scriptPath = Join-Path $repoRoot 'host-inventory/Get-OfficePcAdminEvidence.ps1'
$script:OfficePcAdminSuppressAutoInvoke = $true
. $scriptPath

function New-OfficePcAdminSyntheticSnapshot {
    param(
        [bool] $Elevated = $true,
        [string] $SecureBootState = 'ENABLED',
        [string] $SecureBootDetail = 'AUTHORITATIVE',
        [string] $VmInventoryState = 'OBSERVED',
        [string] $VmDetail = 'AUTHORITATIVE',
        $VmCountTotal = 2,
        $VmStatusCounts = @{ Running = 1; Off = 1 },
        $FirmwareVirtualization = $true,
        $HypervisorPresent = $true
    )
    return @{
        Elevated               = $Elevated
        SecureBootState        = $SecureBootState
        SecureBootDetail       = $SecureBootDetail
        VmInventoryState       = $VmInventoryState
        VmDetail               = $VmDetail
        VmCountTotal           = $VmCountTotal
        VmStatusCounts         = $VmStatusCounts
        FirmwareVirtualization = $FirmwareVirtualization
        HypervisorPresent      = $HypervisorPresent
    }
}

$adminEvidenceChildHost = (Get-Process -Id $PID).Path

function Invoke-AdminEvidenceChild {
    param([string] $Command)
    $lines = & $adminEvidenceChildHost -NoProfile -Command $Command
    return (($lines | Where-Object { $null -ne $_ } | ForEach-Object { $_.ToString() }) -join "`n")
}

# 1. Dot-source must not run live collection.
Assert-True (-not $script:OfficePcAdminInvokedDirectly) 'dot-source captured as not direct'
Assert-True (-not (Test-OfficePcAdminDirectExecution)) 'dot-source is not direct execution'

# 2. Report classification and no-runtime-authority invariants.
$base = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot (New-OfficePcAdminSyntheticSnapshot)
Assert-True ($base.classification -eq 'INVENTORY_ONLY_NOT_ADMISSION') 'classification'
Assert-True ($base.disposition -eq 'INVENTORY_BLOCKED') 'disposition blocked'
Assert-True ($base.jit_authorized -eq $false) 'jit false'
Assert-True ($base.admission_authorized -eq $false) 'admission false'
Assert-True ($base.runtime_blocked -eq $true) 'runtime blocked'
Assert-True ($base.officepc_enrolled -eq $false) 'enrolled false'
Assert-True ($base.normal_use_baseline_verified -eq $false) 'baseline false'
Assert-True ($null -eq $base.host_reserve_mib) 'no reserve implied'
Assert-True ($null -eq $base.guest_mib_proposed) 'no guest size proposed'
Assert-True ($base.recovery.winre_status -eq 'UNVERIFIED') 'winre unverified'
Assert-True ($base.owner_run.self_elevation_attempted -eq $false) 'no self elevation'
Assert-True ($base.owner_run.execution_policy_bypass_requested -eq $false) 'no policy bypass'
Assert-True ($base.owner_run.elevation -eq 'ELEVATED') 'elevation label'

# 3. Secure Boot / VM authoritative mapping in elevated snapshot.
Assert-True ($base.secure_boot.state -eq 'ENABLED') 'secure boot enabled'
Assert-True ($base.secure_boot.authority -eq 'Confirm-SecureBootUEFI') 'secure boot authority'
Assert-True ($base.hyperv_vm.inventory_state -eq 'OBSERVED') 'vm observed'
Assert-True ($base.hyperv_vm.authority -eq 'Get-VM') 'vm authority'
Assert-True ($base.hyperv_vm.vm_count_total -eq 2) 'vm total'
Assert-True ($base.hyperv_vm.status_counts.Running -eq 1) 'running count'
Assert-True ($base.hyperv_vm.status_counts.Off -eq 1) 'off count'
Assert-True ($base.hyperv_vm.status_counts.Saved -eq 0) 'saved count zero'
Assert-True ($base.hyperv_vm.status_counts.Paused -eq 0) 'paused count zero'
Assert-True ($base.hyperv_vm.status_counts.Other -eq 0) 'other count zero'
Assert-True ($base.virtualization_readiness.firmware_virtualization -eq 'ENABLED') 'firmware mapping'
Assert-True ($base.virtualization_readiness.hypervisor_present -eq 'ENABLED') 'hypervisor mapping'

# 4. Non-elevated snapshot fails closed.
$nonElevated = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot (New-OfficePcAdminSyntheticSnapshot -Elevated $false)
Assert-True ($nonElevated.owner_run.elevation -eq 'NOT_ELEVATED') 'not elevated label'
Assert-True ($nonElevated.secure_boot.state -eq 'UNKNOWN') 'non elevated secure boot unknown'
Assert-True ($nonElevated.secure_boot.detail -eq 'NOT_ELEVATED') 'non elevated secure boot detail'
Assert-True ($nonElevated.hyperv_vm.inventory_state -eq 'UNKNOWN') 'non elevated vm unknown'
Assert-True ($null -eq $nonElevated.hyperv_vm.vm_count_total) 'non elevated vm total null'
Assert-True ($null -eq $nonElevated.hyperv_vm.status_counts) 'non elevated vm counts null'

# 5. Only category keys survive; arbitrary injected keys (e.g. VM names) are discarded.
$leaky = New-OfficePcAdminSyntheticSnapshot
$leaky.VmStatusCounts = @{ Running = 1; 'name-of-a-private-vm' = 99; Other = 1 }
$leakyReport = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $leaky
$keys = @($leakyReport.hyperv_vm.status_counts.Keys)
Assert-True (($keys -join ',') -eq 'Running,Off,Saved,Paused,Other') 'status keys whitelist'
Assert-True ($leakyReport.hyperv_vm.status_counts.Other -eq 1) 'other count kept'
Assert-True ($leakyReport.hyperv_vm.vm_count_total -eq 2) 'valid total retained after identity key discard'

# 6. Error state whitelisting and contradictory detail fail closed.
$inconsistentSecureBoot = New-OfficePcAdminSyntheticSnapshot -SecureBootState 'ENABLED' -SecureBootDetail 'ACCESS_DENIED'
$inconsistentSecureBootReport = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $inconsistentSecureBoot
Assert-True ($inconsistentSecureBootReport.secure_boot.state -eq 'UNKNOWN') 'injected ENABLED with ACCESS_DENIED forces unknown'
Assert-True ($inconsistentSecureBootReport.secure_boot.detail -eq 'ACCESS_DENIED') 'sanitized error detail preserved'
$inconsistentVm = New-OfficePcAdminSyntheticSnapshot -VmInventoryState 'OBSERVED' -VmDetail 'ACCESS_DENIED'
$inconsistentVmReport = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $inconsistentVm
Assert-True ($inconsistentVmReport.hyperv_vm.inventory_state -eq 'UNKNOWN') 'injected OBSERVED with ACCESS_DENIED forces unknown'
Assert-True ($inconsistentVmReport.hyperv_vm.detail -eq 'ACCESS_DENIED') 'vm sanitized error detail preserved'
Assert-True ($null -eq $inconsistentVmReport.hyperv_vm.vm_count_total) 'inconsistent vm total nulled'
Assert-True ($null -eq $inconsistentVmReport.hyperv_vm.status_counts) 'inconsistent vm status counts nulled'
$contradictoryAuthoritative = New-OfficePcAdminSyntheticSnapshot -SecureBootState 'UNKNOWN' -SecureBootDetail 'AUTHORITATIVE' -VmInventoryState 'UNKNOWN' -VmDetail 'AUTHORITATIVE'
$contradictoryReport = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $contradictoryAuthoritative
Assert-True ($contradictoryReport.secure_boot.state -eq 'UNKNOWN') 'authoritative with unknown secure boot state stays unknown'
Assert-True ($contradictoryReport.secure_boot.detail -eq 'UNKNOWN') 'authoritative detail cleared on unknown state'
Assert-True ($contradictoryReport.hyperv_vm.inventory_state -eq 'UNKNOWN') 'authoritative with unknown vm state stays unknown'
Assert-True ($contradictoryReport.hyperv_vm.detail -eq 'UNKNOWN') 'vm authoritative detail cleared on unknown state'
$wrongUnsupportedPairing = New-OfficePcAdminSyntheticSnapshot -SecureBootState 'UNSUPPORTED' -SecureBootDetail 'ACCESS_DENIED'
Assert-True ((New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $wrongUnsupportedPairing).secure_boot.state -eq 'UNKNOWN') 'unsupported state requires known pairing'
$bogus = New-OfficePcAdminSyntheticSnapshot -SecureBootState 'ROGUE' -SecureBootDetail 'ROGUE'
$bogusReport = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $bogus
Assert-True ($bogusReport.secure_boot.state -eq 'UNKNOWN') 'bogus state fails closed'
Assert-True ($bogusReport.secure_boot.detail -eq 'UNKNOWN') 'bogus detail fails closed'
Assert-True ((Get-OfficePcAdminVmInventoryState -Value 'ROGUE') -eq 'UNKNOWN') 'bogus vm state fails closed'

# 7. Bounded count rejects non-integral / hostile values.
Assert-True ($null -eq (ConvertTo-OfficePcAdminBoundedCount -Value '12')) 'reject numeric string count'
Assert-True ($null -eq (ConvertTo-OfficePcAdminBoundedCount -Value 2.5)) 'reject double count'
Assert-True ($null -eq (ConvertTo-OfficePcAdminBoundedCount -Value $true)) 'reject bool count'
Assert-True ($null -eq (ConvertTo-OfficePcAdminBoundedCount -Value -1)) 'reject negative count'
Assert-True ($null -eq (ConvertTo-OfficePcAdminBoundedCount -Value 100001)) 'reject overflow count'
Assert-True ((ConvertTo-OfficePcAdminBoundedCount -Value ([uint32] 7)) -eq 7) 'accept uint count'
Assert-True ((ConvertTo-OfficePcAdminTriState -Value $null) -eq 'UNKNOWN') 'null tri-state'

# 7b. Count total must equal the sum of the five status buckets.
$countMismatch = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot (New-OfficePcAdminSyntheticSnapshot -VmCountTotal 99999)
Assert-True ($countMismatch.hyperv_vm.inventory_state -eq 'UNKNOWN') 'count mismatch forces vm unknown'
Assert-True ($null -eq $countMismatch.hyperv_vm.vm_count_total) 'count mismatch nulls total'
Assert-True ($null -eq $countMismatch.hyperv_vm.status_counts) 'count mismatch nulls status counts'
$hostileCounts = New-OfficePcAdminSyntheticSnapshot
$hostileCounts.VmStatusCounts = @{ Running = '12'; Off = 1; Saved = 0; Paused = 0; Other = 0 }
$hostileCountsReport = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot $hostileCounts
Assert-True ($hostileCountsReport.hyperv_vm.inventory_state -eq 'UNKNOWN') 'hostile status count rejected by sum check'
Assert-True ($null -eq $hostileCountsReport.hyperv_vm.status_counts) 'hostile status count nulled'
$zeroCounts = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot (New-OfficePcAdminSyntheticSnapshot -VmCountTotal 0 -VmStatusCounts @{ Running = 0; Off = 0; Saved = 0; Paused = 0; Other = 0 })
Assert-True ($zeroCounts.hyperv_vm.inventory_state -eq 'OBSERVED') 'consistent zero-inventory counts accepted'
Assert-True ($zeroCounts.hyperv_vm.vm_count_total -eq 0) 'zero total preserved'

# 8. Determinism and sanitizer on the serialized report.
$json = $base | ConvertTo-Json -Depth 6 -Compress
Assert-True (-not (Test-OfficePcAdminEvidenceForbiddenLeak -Text $json)) 'no forbidden leak base'
Assert-True ($json -notmatch 'LDW01|6144|CANDIDATE_PASS|GITHUB|RunAs|Start-Process') 'no forbidden tokens'
$runA = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot (New-OfficePcAdminSyntheticSnapshot)
$runB = New-OfficePcAdminEvidenceReportFromSnapshot -Snapshot (New-OfficePcAdminSyntheticSnapshot)
Assert-True ($runA.secure_boot.state -eq $runB.secure_boot.state) 'deterministic secure boot'
Assert-True ($runA.hyperv_vm.vm_count_total -eq $runB.hyperv_vm.vm_count_total) 'deterministic vm count'
Assert-True ($runA.disposition -eq $runB.disposition) 'deterministic disposition'

# 9. Source contains no elevation, mutation, network, or credential primitives.
$sourceText = Get-Content -LiteralPath $scriptPath -Raw
$forbiddenSource = @('Start-Process', '-Verb RunAs', 'RunAs', 'ExecutionPolicy', 'Set-Service', 'New-VM', 'Start-VM', 'Stop-VM', 'Remove-VM', 'Set-VM', 'New-Net', 'Set-Net', 'Defender', 'Acl', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Get-Credential', 'gh ', 'Get-Content Env:', 'GetEnvironmentVariable')
foreach ($token in $forbiddenSource) {
    Assert-True (-not $sourceText.Contains($token)) "source free of $token"
}
Assert-True ($sourceText.Contains('Confirm-SecureBootUEFI')) 'uses authoritative secure boot command'
Assert-True ($sourceText.Contains('Get-VM')) 'uses authoritative vm command'
Assert-True (-not ($sourceText -match 'OFFICEPC_ADMIN_USE_SYNTHETIC')) 'no env autoload in source'

# 10. Child process: non-elevated shell must not call Secure Boot or VM cmdlets.
$escapedScript = $scriptPath.Replace("'", "''")
$nonelevatedChild = @"
`$ErrorActionPreference = 'Stop'
`$script:OfficePcAdminSuppressAutoInvoke = `$true
`$script:OfficePcAdminCallCount = 0
function Confirm-SecureBootUEFI { `$script:OfficePcAdminCallCount++; throw 'MUST_NOT_CALL' }
function Get-VM { `$script:OfficePcAdminCallCount++; throw 'MUST_NOT_CALL' }
function Get-CimInstance { return `$null }
. '$escapedScript'
`$script:OfficePcAdminEvidenceElevationOverride = `$false
`$snap = Get-OfficePcAdminEvidenceLiveSnapshot
Write-Output ('CALL_COUNT=' + `$script:OfficePcAdminCallCount)
Write-Output ('SB=' + `$snap.SecureBootState + '/' + `$snap.SecureBootDetail)
Write-Output ('VM=' + `$snap.VmInventoryState + '/' + `$snap.VmDetail)
"@
$nonElevatedText = Invoke-AdminEvidenceChild -Command $nonelevatedChild
Assert-True ($nonElevatedText -match 'CALL_COUNT=0') 'non elevated shell called no authoritative cmdlet'
Assert-True ($nonElevatedText -match 'SB=UNKNOWN/NOT_ELEVATED') 'non elevated secure boot fail closed'
Assert-True ($nonElevatedText -match 'VM=UNKNOWN/NOT_ELEVATED') 'non elevated vm fail closed'

# 11. Child process: elevated collection maps authoritative results and never emits VM identity.
$elevatedChild = @"
`$ErrorActionPreference = 'Stop'
`$script:OfficePcAdminSuppressAutoInvoke = `$true
function Confirm-SecureBootUEFI { return `$true }
function Get-VM {
    return @(
        [pscustomobject]@{ Name = 'private-vm-7a3c2f10-1b2c-4d3e-8f90-a1b2c3d4e5f6'; State = 'Running' },
        [pscustomobject]@{ Name = 'other-vm-AA:BB:CC:DD:EE:FF'; State = 'Off' },
        [pscustomobject]@{ Name = 'recovery'; State = 'Rebooting' }
    )
}
function Get-CimInstance { return `$null }
. '$escapedScript'
`$script:OfficePcAdminEvidenceElevationOverride = `$true
Invoke-OfficePcAdminEvidenceCollection | ConvertTo-Json -Depth 6 -Compress
"@
$elevatedText = Invoke-AdminEvidenceChild -Command $elevatedChild
Assert-True ($elevatedText.Trim().StartsWith('{')) 'elevated child emitted json'
Assert-True ($elevatedText -notmatch '7a3c2f10|AA:BB:CC|private-vm|other-vm') 'no vm identity in output'
$elevatedObject = $elevatedText | ConvertFrom-Json
Assert-True ($elevatedObject.secure_boot.state -eq 'ENABLED') 'elevated secure boot enabled'
Assert-True ($elevatedObject.hyperv_vm.inventory_state -eq 'OBSERVED') 'elevated vm observed'
Assert-True ($elevatedObject.hyperv_vm.vm_count_total -eq 3) 'elevated vm total'
Assert-True ($elevatedObject.hyperv_vm.status_counts.Running -eq 1) 'elevated running count'
Assert-True ($elevatedObject.hyperv_vm.status_counts.Off -eq 1) 'elevated off count'
Assert-True ($elevatedObject.hyperv_vm.status_counts.Other -eq 1) 'elevated other count'
Assert-True ($elevatedObject.jit_authorized -eq $false) 'elevated still jit false'

# 12. Child process: unsupported Secure Boot error is distinguished from access denied.
$unsupportedChild = @"
`$ErrorActionPreference = 'Stop'
`$script:OfficePcAdminSuppressAutoInvoke = `$true
function Confirm-SecureBootUEFI { throw 'Secure Boot is not supported on this firmware' }
function Get-VM { throw 'Access is denied' }
function Get-CimInstance { return `$null }
. '$escapedScript'
`$script:OfficePcAdminEvidenceElevationOverride = `$true
`$snap = Get-OfficePcAdminEvidenceLiveSnapshot
Write-Output ('SB=' + `$snap.SecureBootState + '/' + `$snap.SecureBootDetail)
Write-Output ('VM=' + `$snap.VmInventoryState + '/' + `$snap.VmDetail)
"@
$unsupportedText = Invoke-AdminEvidenceChild -Command $unsupportedChild
Assert-True ($unsupportedText -match 'SB=UNSUPPORTED/NON_UEFI_OR_UNSUPPORTED') 'unsupported secure boot distinguished'
Assert-True ($unsupportedText -match 'VM=UNKNOWN/ACCESS_DENIED') 'vm access denied fail closed'
Assert-True ($unsupportedText -notmatch 'not supported on this firmware|Access is denied') 'raw error text never emitted'

Write-Output 'OFFICEPC_ADMIN_EVIDENCE_CONTRACTS=PASS'
