#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "ASSERT_FAILED:$Message" }
}

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$scriptPath = Join-Path $repoRoot 'tooling-version-inventory/Get-LdwToolVersionInventory.ps1'
$script:LdwToolVersionInventorySuppressAutoInvoke = $true
. $scriptPath

Assert-True ((@(Get-LdwToolVersionInventoryCatalog)).Count -eq 3) 'catalog size'

$sanitizedVersion = ConvertTo-LdwToolVersionSanitizedPeVersion -Raw '1.4.254'
Assert-True ($sanitizedVersion -eq '1.4.254') 'sanitize version'
Assert-True ($null -eq (ConvertTo-LdwToolVersionSanitizedPeVersion -Raw 'v1.2.3')) 'reject prefix v'

$pinnedOrca = Get-LdwToolVersionPublisherPolicyFromSignature -AppId 'orca' -AuthenticodeStatus 'Valid' `
    -SignerThumbprint 'F7394FAE852E68922222C04A4364204298E6E82E' -ExpectedUnsignedPolicy $false -InstallIdentityTrusted $true
Assert-True ($pinnedOrca.trusted_publisher_policy -eq 'PINNED_SIGNER_MATCH') 'pinned orca'

$wrongSigner = Get-LdwToolVersionPublisherPolicyFromSignature -AppId 'orca' -AuthenticodeStatus 'Valid' `
    -SignerThumbprint 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' -ExpectedUnsignedPolicy $false -InstallIdentityTrusted $true
Assert-True ($wrongSigner.trusted_publisher_policy -eq 'UNVERIFIED') 'arbitrary valid signer unverified'
Assert-True ($wrongSigner.authenticode_state -eq 'Valid') 'auth still reports Valid separately'

$unsignedCodync = Get-LdwToolVersionPublisherPolicyFromSignature -AppId 'codync' -AuthenticodeStatus 'NotSigned' `
    -SignerThumbprint $null -ExpectedUnsignedPolicy $true -InstallIdentityTrusted $true
Assert-True ($unsignedCodync.trusted_publisher_policy -eq 'EXPECTED_UNSIGNED') 'codync unsigned'

$reparseRefused = Get-LdwToolVersionPublisherPolicyFromSignature -AppId 'orca' -AuthenticodeStatus 'Valid' `
    -SignerThumbprint 'F7394FAE852E68922222C04A4364204298E6E82E' -ExpectedUnsignedPolicy $false -InstallIdentityTrusted $false
Assert-True ($reparseRefused.trusted_publisher_policy -eq 'UNVERIFIED') 'identity refused'

$found = New-LdwToolVersionInventoryAppRecordFromSnapshot -Snapshot @{
    app_id                   = 'orca'
    probe_key                = 'orca-gui'
    install_state            = 'found'
    file_version             = '1.4.254'
    product_version          = '1.4.254.0'
    authenticode_state       = 'Valid'
    trusted_publisher_policy = 'PINNED_SIGNER_MATCH'
    running_state            = 'observed_name_in_owner_session'
    updater_state            = 'in_progress_evidence'
    running_scope            = 'owner_session_process_name_only'
}
Assert-True ($found.trusted_publisher_policy -eq 'PINNED_SIGNER_MATCH') 'snapshot policy'

$missing = New-LdwToolVersionInventoryAppRecordFromSnapshot -Snapshot @{
    app_id                   = 'cursor'
    probe_key                = 'cursor-gui'
    install_state            = 'not_found'
    file_version             = $null
    product_version          = $null
    authenticode_state       = $null
    trusted_publisher_policy = $null
    running_state            = 'not_observed_in_owner_session'
    updater_state            = 'unknown'
}
Assert-True ($missing.running_state -eq 'not_observed_in_owner_session') 'not observed not machine absent'

$report = New-LdwToolVersionInventoryReport -ObservedAtUtc ([datetime]'2026-11-09T01:00:00Z') -AppRecords @($found, $missing)
$json = $report | ConvertTo-Json -Depth 6 -Compress
Assert-True (-not (Test-LdwToolVersionInventoryForbiddenLeak -Text $json)) 'forbidden leak'
Assert-True ($json -notmatch 'F7394FAE852E68922222C04A4364204298E6E82E') 'thumbprint not in json'

Assert-True ((Get-LdwToolVersionUpdaterState -PendingDir $null -Markers @('installer.exe')) -eq 'unknown') 'updater unknown null dir'

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ldw-tvi-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    $marker = Join-Path $tempDir 'installer.exe'
    Set-Content -LiteralPath $marker -Value 'x' -NoNewline
    Assert-True ((Get-LdwToolVersionUpdaterState -PendingDir $tempDir -Markers @('installer.exe')) -eq 'in_progress_evidence') 'pending marker'
    Remove-Item -LiteralPath $marker -Force
    Assert-True ((Get-LdwToolVersionUpdaterState -PendingDir $tempDir -Markers @('installer.exe')) -eq 'unknown') 'missing marker unknown'
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

$missingPendingDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ldw-tvi-miss-" + [guid]::NewGuid().ToString('n'))
Assert-True ((Get-LdwToolVersionUpdaterState -PendingDir $missingPendingDir -Markers @('installer.exe')) -eq 'unknown') 'missing pending dir unknown'

Assert-True ((Get-LdwToolVersionRunningState -ProcessName '__nope__' -OwnerSessionId 1) -eq 'not_observed_in_owner_session') 'empty process list scoped'
Assert-True ((Get-LdwToolVersionRunningState -ProcessName $null) -eq 'unknown') 'blank process name'

$authMissing = Get-LdwToolVersionAuthenticodeSummary -Path '__missing__' -AppId 'orca' -ExpectedUnsignedPolicy $false -InstallIdentityTrusted $true
Assert-True ($authMissing.trusted_publisher_policy -eq 'UNVERIFIED') 'missing auth'

Write-Output 'LdwToolVersionInventory contract tests passed.'
