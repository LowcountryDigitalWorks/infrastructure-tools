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
$catalog = Get-LdwToolVersionInventoryCatalog
Assert-True ($catalog.app_id -contains 'orca') 'orca catalog'
Assert-True ($catalog.app_id -contains 'codync') 'codync catalog'
Assert-True ($catalog.app_id -contains 'cursor') 'cursor catalog'

$sanitizedVersion = ConvertTo-LdwToolVersionSanitizedPeVersion -Raw '1.4.254'
Assert-True ($sanitizedVersion -eq '1.4.254') 'sanitize version'
Assert-True ($null -eq (ConvertTo-LdwToolVersionSanitizedPeVersion -Raw 'v1.2.3')) 'reject prefix v'
Assert-True ($null -eq (ConvertTo-LdwToolVersionSanitizedPeVersion -Raw ('x' * 80))) 'reject long'

$found = New-LdwToolVersionInventoryAppRecordFromSnapshot -Snapshot @{
    app_id                   = 'orca'
    probe_key                = 'orca-gui'
    install_state            = 'found'
    file_version             = '1.4.254'
    product_version          = '1.4.254.0'
    authenticode_state       = 'Valid'
    trusted_publisher_policy = 'MATCH'
    running_state            = 'yes'
    updater_state            = 'in_progress_evidence'
}
Assert-True ($found.file_version -eq '1.4.254') 'orca version'
Assert-True ($found.updater_state -eq 'in_progress_evidence') 'updater progress'

$missing = New-LdwToolVersionInventoryAppRecordFromSnapshot -Snapshot @{
    app_id                   = 'cursor'
    probe_key                = 'cursor-gui'
    install_state            = 'not_found'
    file_version             = $null
    product_version          = $null
    authenticode_state       = $null
    trusted_publisher_policy = $null
    running_state            = 'no'
    updater_state            = 'unknown'
}
Assert-True ($missing.install_state -eq 'not_found') 'not found'

$unsigned = New-LdwToolVersionInventoryAppRecordFromSnapshot -Snapshot @{
    app_id                   = 'codync'
    probe_key                = 'codync-gui'
    install_state            = 'found'
    file_version             = '2.42.1'
    product_version          = '2.42.1.0'
    authenticode_state       = 'NotSigned'
    trusted_publisher_policy = 'EXPECTED_UNSIGNED'
    running_state            = 'unknown'
    updater_state            = 'idle_evidence'
    running_state_note       = 'HOST_WORKERS_MAY_BE_AMBIGUOUS'
}
Assert-True ($unsigned.trusted_publisher_policy -eq 'EXPECTED_UNSIGNED') 'codync unsigned policy'

$report = New-LdwToolVersionInventoryReport -ObservedAtUtc ([datetime]'2026-11-09T01:00:00Z') -AppRecords @($found, $missing, $unsigned)
Assert-True ($report.schema_version -eq 'ldw.tooling_version_inventory.v1') 'schema'
Assert-True ($report.classification -eq 'TOOL_VERSION_INVENTORY_ONLY') 'classification'
Assert-True ($report.disposition -eq 'INVENTORY_EVIDENCE_ONLY') 'disposition'
Assert-True ($report.apps.Count -eq 3) 'apps count'

$json = $report | ConvertTo-Json -Depth 6 -Compress
Assert-True (-not (Test-LdwToolVersionInventoryForbiddenLeak -Text $json)) 'forbidden leak'
Assert-True ($json -notmatch 'Users\\|LOCALAPPDATA|Program Files|certificate|Thumbprint') 'no path or cert fields'

$badJson = $json + ' C:\Users\eddie\secret'
Assert-True (Test-LdwToolVersionInventoryForbiddenLeak -Text $badJson) 'leak detector'

Assert-True ((Get-LdwToolVersionUpdaterState -PendingDir $null -Markers @('installer.exe')) -eq 'unknown') 'updater unknown null dir'

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ldw-tvi-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    $marker = Join-Path $tempDir 'installer.exe'
    Set-Content -LiteralPath $marker -Value 'x' -NoNewline
    Assert-True ((Get-LdwToolVersionUpdaterState -PendingDir $tempDir -Markers @('installer.exe')) -eq 'in_progress_evidence') 'pending marker'
    Remove-Item -LiteralPath $marker -Force
    Assert-True ((Get-LdwToolVersionUpdaterState -PendingDir $tempDir -Markers @('installer.exe')) -eq 'idle_evidence') 'idle pending dir'
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

$authUnsigned = Get-LdwToolVersionAuthenticodeSummary -Path '__missing__' -TrustedWhenValid $true -ExpectedUnsignedPolicy $true
Assert-True ($authUnsigned.authenticode_state -eq 'UNVERIFIED') 'missing auth'

Write-Output 'LdwToolVersionInventory contract tests passed.'
