#Requires -Version 5.1
<#
.SYNOPSIS
  Offline read-only fixed-allowlist tooling version inventory for LDW01 Watch evidence.

.DESCRIPTION
  Dot-sourcing loads functions only. Live probes run when invoked via powershell -File,
  not when dot-sourced for contract tests (see OfficePC inventory pattern).
#>
[CmdletBinding()]
param(
    [ValidateSet('orca', 'codync', 'cursor')]
    [string[]] $AppId
)

$ErrorActionPreference = 'Stop'

$script:LdwToolVersionInventoryInvokedDirectly = ($MyInvocation.InvocationName -ne '.')

if (-not (Get-Variable -Name LdwToolVersionInventorySuppressAutoInvoke -Scope Script -ErrorAction SilentlyContinue)) {
    $script:LdwToolVersionInventorySuppressAutoInvoke = $false
}

$script:LdwToolVersionInventorySchema = 'ldw.tooling_version_inventory.v1'
$script:LdwToolVersionInventoryClassification = 'TOOL_VERSION_INVENTORY_ONLY'
$script:LdwToolVersionInventoryDisposition = 'INVENTORY_EVIDENCE_ONLY'

function Test-LdwToolVersionInventoryForbiddenLeak {
    param([string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $patterns = @(
        '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}',
        '\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
        '@',
        '\\\\[^\\]+\\',
        ':\\Users\\',
        ':\\\\',
        'GITHUB_TOKEN',
        'password',
        'secret',
        'certificate',
        'Thumbprint',
        'Subject',
        'LOCALAPPDATA',
        'Program Files'
    )
    foreach ($pattern in $patterns) {
        if ($Text -match $pattern) { return $true }
    }
    return $false
}

function Get-LdwToolVersionInventoryCatalog {
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    return @(
        @{
            app_id                   = 'orca'
            probe_key                = 'orca-gui'
            executable_path          = (Join-Path $local 'Programs\orca\Orca.exe')
            running_process_name     = 'Orca'
            updater_pending_dir      = (Join-Path $local 'orca-updater\pending')
            updater_pending_markers    = @('orca-windows-setup.exe', 'installer.exe')
            trusted_when_valid       = $true
            expected_unsigned_policy = $false
        },
        @{
            app_id                   = 'codync'
            probe_key                = 'codync-gui'
            executable_path          = (Join-Path $local 'Programs\codync-desktop\Codync.exe')
            running_process_name     = 'Codync'
            updater_pending_dir      = (Join-Path $local 'codync-desktop-updater\pending')
            updater_pending_markers  = @('codync-desktop-setup.exe', 'installer.exe')
            trusted_when_valid       = $false
            expected_unsigned_policy = $true
        },
        @{
            app_id                   = 'cursor'
            probe_key                = 'cursor-gui'
            executable_path          = (Join-Path $local 'Programs\cursor\Cursor.exe')
            running_process_name     = 'Cursor'
            updater_pending_dir      = (Join-Path $local 'cursor-updater\pending')
            updater_pending_markers  = @('CursorSetup.exe', 'installer.exe')
            trusted_when_valid       = $true
            expected_unsigned_policy = $false
        }
    )
}

function ConvertTo-LdwToolVersionSanitizedPeVersion {
    param([AllowNull()] $Raw)
    if ($null -eq $Raw -or [string]::IsNullOrWhiteSpace([string] $Raw)) { return $null }
    $text = ([string] $Raw).Trim()
    if ($text.Length -gt 64) { return $null }
    if (-not ($text -match '^[0-9]+(\.[0-9]+)*(\.[0-9]+)?$')) { return $null }
    return $text
}

function Get-LdwToolVersionAuthenticodeSummary {
    param(
        [string] $Path,
        [bool] $TrustedWhenValid,
        [bool] $ExpectedUnsignedPolicy
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @{
            authenticode_state       = 'UNVERIFIED'
            trusted_publisher_policy = 'UNVERIFIED'
        }
    }
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return @{
                authenticode_state       = 'UNVERIFIED'
                trusted_publisher_policy = 'UNVERIFIED'
            }
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $stateName = [string] $sig.Status
        switch ($sig.Status) {
            'Valid' {
                $policy = if ($TrustedWhenValid) { 'MATCH' } else { 'MISMATCH' }
                return @{
                    authenticode_state       = 'Valid'
                    trusted_publisher_policy = $policy
                }
            }
            'NotSigned' {
                $policy = if ($ExpectedUnsignedPolicy) { 'EXPECTED_UNSIGNED' } else { 'NOT_APPLICABLE' }
                return @{
                    authenticode_state       = 'NotSigned'
                    trusted_publisher_policy = $policy
                }
            }
            default {
                return @{
                    authenticode_state       = 'UNVERIFIED'
                    trusted_publisher_policy = 'UNVERIFIED'
                }
            }
        }
    }
    catch {
        return @{
            authenticode_state       = 'UNVERIFIED'
            trusted_publisher_policy = 'UNVERIFIED'
        }
    }
}

function Get-LdwToolVersionRunningState {
    param([string] $ProcessName)
    if ([string]::IsNullOrWhiteSpace($ProcessName)) { return 'unknown' }
    try {
        $proc = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
        if ($proc.Count -eq 0) { return 'no' }
        if ($proc.Count -ge 1) { return 'yes' }
        return 'unknown'
    }
    catch {
        return 'unknown'
    }
}

function Get-LdwToolVersionUpdaterState {
    param(
        [string] $PendingDir,
        [string[]] $Markers
    )
    if ([string]::IsNullOrWhiteSpace($PendingDir)) { return 'unknown' }
    try {
        if (-not (Test-Path -LiteralPath $PendingDir)) { return 'idle_evidence' }
        foreach ($marker in $Markers) {
            $candidate = Join-Path $PendingDir $marker
            if (Test-Path -LiteralPath $candidate) { return 'in_progress_evidence' }
        }
        return 'idle_evidence'
    }
    catch {
        return 'unknown'
    }
}

function Get-LdwToolVersionInstallProbe {
    param([hashtable] $CatalogEntry)
    if (-not $CatalogEntry.ContainsKey('executable_path')) {
        return @{
            install_state = 'error'
            error_code    = 'CATALOG_INCOMPLETE'
        }
    }
    $path = $CatalogEntry.executable_path
    if (-not (Test-Path -LiteralPath $path)) {
        return @{
            install_state            = 'not_found'
            file_version             = $null
            product_version          = $null
            authenticode_state       = $null
            trusted_publisher_policy = $null
        }
    }
    try {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        $fileVersion = ConvertTo-LdwToolVersionSanitizedPeVersion -Raw $item.VersionInfo.FileVersion
        $productVersion = ConvertTo-LdwToolVersionSanitizedPeVersion -Raw $item.VersionInfo.ProductVersion
        $auth = Get-LdwToolVersionAuthenticodeSummary -Path $path `
            -TrustedWhenValid ([bool] $CatalogEntry.trusted_when_valid) `
            -ExpectedUnsignedPolicy ([bool] $CatalogEntry.expected_unsigned_policy)
        return @{
            install_state            = if ($fileVersion -or $productVersion) { 'found' } else { 'unverified' }
            file_version             = $fileVersion
            product_version          = $productVersion
            authenticode_state       = $auth.authenticode_state
            trusted_publisher_policy = $auth.trusted_publisher_policy
        }
    }
    catch {
        return @{
            install_state = 'error'
            error_code    = 'PROBE_FAILED'
        }
    }
}

function New-LdwToolVersionInventoryAppRecord {
    param([hashtable] $CatalogEntry)
    $probe = Get-LdwToolVersionInstallProbe -CatalogEntry $CatalogEntry
    $record = [ordered]@{
        app_id                   = $CatalogEntry.app_id
        probe_key                = $CatalogEntry.probe_key
        install_state            = $probe.install_state
        file_version             = $probe.file_version
        product_version          = $probe.product_version
        authenticode_state       = $probe.authenticode_state
        trusted_publisher_policy = $probe.trusted_publisher_policy
        running_state            = Get-LdwToolVersionRunningState -ProcessName $CatalogEntry.running_process_name
        updater_state            = Get-LdwToolVersionUpdaterState -PendingDir $CatalogEntry.updater_pending_dir -Markers $CatalogEntry.updater_pending_markers
    }
    if ($probe.ContainsKey('error_code')) {
        $record.error_code = $probe.error_code
    }
  if ($CatalogEntry.app_id -eq 'codync') {
        # Host worker processes are ambiguous without forbidden cmdline correlation.
        if ($record.running_state -eq 'no' -and $probe.install_state -eq 'found') {
            $record.running_state_note = 'HOST_WORKERS_MAY_BE_AMBIGUOUS'
        }
    }
    return [pscustomobject] $record
}

function New-LdwToolVersionInventoryAppRecordFromSnapshot {
    param([hashtable] $Snapshot)
    if (-not $Snapshot.ContainsKey('app_id')) { throw 'SNAPSHOT_MISSING_APP_ID' }
    $required = @(
        'probe_key', 'install_state', 'file_version', 'product_version',
        'authenticode_state', 'trusted_publisher_policy', 'running_state', 'updater_state'
    )
    foreach ($key in $required) {
        if (-not $Snapshot.ContainsKey($key)) { throw "SNAPSHOT_MISSING_$key" }
    }
    $record = [ordered]@{
        app_id                   = $Snapshot.app_id
        probe_key                = $Snapshot.probe_key
        install_state            = $Snapshot.install_state
        file_version             = $Snapshot.file_version
        product_version          = $Snapshot.product_version
        authenticode_state       = $Snapshot.authenticode_state
        trusted_publisher_policy = $Snapshot.trusted_publisher_policy
        running_state            = $Snapshot.running_state
        updater_state            = $Snapshot.updater_state
    }
    if ($Snapshot.ContainsKey('error_code')) { $record.error_code = $Snapshot.error_code }
    if ($Snapshot.ContainsKey('running_state_note')) { $record.running_state_note = $Snapshot.running_state_note }
    return [pscustomobject] $record
}

function New-LdwToolVersionInventoryReport {
    param(
        [datetime] $ObservedAtUtc,
        [object[]] $AppRecords
    )
    return [pscustomobject] [ordered]@{
        schema_version = $script:LdwToolVersionInventorySchema
        observed_at    = $ObservedAtUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        classification = $script:LdwToolVersionInventoryClassification
        disposition    = $script:LdwToolVersionInventoryDisposition
        apps           = @($AppRecords)
    }
}

function Invoke-LdwToolVersionInventoryCollection {
    param([string[]] $RequestedAppIds)
    $catalog = Get-LdwToolVersionInventoryCatalog
    if ($RequestedAppIds -and $RequestedAppIds.Count -gt 0) {
        $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($id in $RequestedAppIds) { [void] $set.Add($id) }
        $catalog = @($catalog | Where-Object { $set.Contains($_.app_id) })
    }
    $records = foreach ($entry in $catalog) {
        New-LdwToolVersionInventoryAppRecord -CatalogEntry $entry
    }
    return New-LdwToolVersionInventoryReport -ObservedAtUtc ([datetime]::UtcNow) -AppRecords $records
}

if ($script:LdwToolVersionInventoryInvokedDirectly -and -not $script:LdwToolVersionInventorySuppressAutoInvoke) {
    $report = Invoke-LdwToolVersionInventoryCollection -RequestedAppIds $AppId
    $json = $report | ConvertTo-Json -Depth 6 -Compress
    if (Test-LdwToolVersionInventoryForbiddenLeak -Text $json) {
        throw 'INVENTORY_OUTPUT_REFUSED_LEAK'
    }
    Write-Output $json
}
