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

# Reviewed signer thumbprint allowlist only (#282 IR). Valid Authenticode outside this set is never MATCH.
$script:LdwToolVersionPinnedSignerThumbprintsByApp = @{
    orca   = @('F7394FAE852E68922222C04A4364204298E6E82E')
    cursor = @('5B1BD615C4476B9850DE47DDF53F0FDF5CFCFE6C')
    codync = @()
}

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

function Get-LdwToolVersionOwnerSessionId {
    try {
        return (Get-Process -Id $PID -ErrorAction Stop).SessionId
    }
    catch {
        return $null
    }
}

function Get-LdwToolVersionInventoryCatalog {
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    return @(
        @{
            app_id                  = 'orca'
            probe_key               = 'orca-gui'
            executable_path         = (Join-Path $local 'Programs\orca\Orca.exe')
            running_process_name    = 'Orca'
            updater_pending_dir     = (Join-Path $local 'orca-updater\pending')
            updater_pending_markers = @('orca-windows-setup.exe', 'installer.exe')
            expected_unsigned_policy = $false
        },
        @{
            app_id                  = 'codync'
            probe_key               = 'codync-gui'
            executable_path         = (Join-Path $local 'Programs\codync-desktop\Codync.exe')
            running_process_name    = 'Codync'
            updater_pending_dir     = (Join-Path $local 'codync-desktop-updater\pending')
            updater_pending_markers = @('codync-desktop-setup.exe', 'installer.exe')
            expected_unsigned_policy = $true
        },
        @{
            app_id                  = 'cursor'
            probe_key               = 'cursor-gui'
            executable_path         = (Join-Path $local 'Programs\cursor\Cursor.exe')
            running_process_name    = 'Cursor'
            updater_pending_dir     = (Join-Path $local 'cursor-updater\pending')
            updater_pending_markers = @('CursorSetup.exe', 'installer.exe')
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

function Test-LdwToolVersionPinnedSignerThumbprint {
    param(
        [string] $AppId,
        [AllowNull()] [string] $Thumbprint
    )
    if ([string]::IsNullOrWhiteSpace($AppId) -or [string]::IsNullOrWhiteSpace($Thumbprint)) {
        return $false
    }
    $normalized = $Thumbprint.Trim().ToUpperInvariant()
    if (-not $script:LdwToolVersionPinnedSignerThumbprintsByApp.ContainsKey($AppId)) {
        return $false
    }
    foreach ($allowed in $script:LdwToolVersionPinnedSignerThumbprintsByApp[$AppId]) {
        if ($normalized -eq $allowed.Trim().ToUpperInvariant()) { return $true }
    }
    return $false
}

function Get-LdwToolVersionPublisherPolicyFromSignature {
    param(
        [string] $AppId,
        [AllowNull()] [string] $AuthenticodeStatus,
        [AllowNull()] [string] $SignerThumbprint,
        [bool] $ExpectedUnsignedPolicy,
        [bool] $InstallIdentityTrusted
    )
    if (-not $InstallIdentityTrusted) {
        return @{
            authenticode_state       = 'UNVERIFIED'
            trusted_publisher_policy = 'UNVERIFIED'
        }
    }
    if ([string]::IsNullOrWhiteSpace($AuthenticodeStatus)) {
        return @{
            authenticode_state       = 'UNVERIFIED'
            trusted_publisher_policy = 'UNVERIFIED'
        }
    }
    switch ($AuthenticodeStatus) {
        'Valid' {
            if ($ExpectedUnsignedPolicy) {
                return @{
                    authenticode_state       = 'UNVERIFIED'
                    trusted_publisher_policy = 'UNVERIFIED'
                }
            }
            if (Test-LdwToolVersionPinnedSignerThumbprint -AppId $AppId -Thumbprint $SignerThumbprint) {
                return @{
                    authenticode_state       = 'Valid'
                    trusted_publisher_policy = 'PINNED_SIGNER_MATCH'
                }
            }
            return @{
                authenticode_state       = 'Valid'
                trusted_publisher_policy = 'UNVERIFIED'
            }
        }
        'NotSigned' {
            if ($ExpectedUnsignedPolicy) {
                return @{
                    authenticode_state       = 'NotSigned'
                    trusted_publisher_policy = 'EXPECTED_UNSIGNED'
                }
            }
            return @{
                authenticode_state       = 'NotSigned'
                trusted_publisher_policy = 'UNVERIFIED'
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

function Get-LdwToolVersionAuthenticodeSummary {
    param(
        [string] $Path,
        [string] $AppId,
        [bool] $ExpectedUnsignedPolicy,
        [bool] $InstallIdentityTrusted
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $InstallIdentityTrusted) {
        return (Get-LdwToolVersionPublisherPolicyFromSignature -AppId $AppId `
            -AuthenticodeStatus $null -SignerThumbprint $null `
            -ExpectedUnsignedPolicy $ExpectedUnsignedPolicy -InstallIdentityTrusted $false)
    }
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return (Get-LdwToolVersionPublisherPolicyFromSignature -AppId $AppId `
                -AuthenticodeStatus $null -SignerThumbprint $null `
                -ExpectedUnsignedPolicy $ExpectedUnsignedPolicy -InstallIdentityTrusted $InstallIdentityTrusted)
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $thumb = $null
        if ($null -ne $sig.SignerCertificate) {
            $thumb = $sig.SignerCertificate.Thumbprint
        }
        return (Get-LdwToolVersionPublisherPolicyFromSignature -AppId $AppId `
            -AuthenticodeStatus ([string] $sig.Status) -SignerThumbprint $thumb `
            -ExpectedUnsignedPolicy $ExpectedUnsignedPolicy -InstallIdentityTrusted $InstallIdentityTrusted)
    }
    catch {
        return (Get-LdwToolVersionPublisherPolicyFromSignature -AppId $AppId `
            -AuthenticodeStatus $null -SignerThumbprint $null `
            -ExpectedUnsignedPolicy $ExpectedUnsignedPolicy -InstallIdentityTrusted $InstallIdentityTrusted)
    }
}

function Test-LdwToolVersionInstallPathIdentity {
    param([string] $LiteralPath)
    if ([string]::IsNullOrWhiteSpace($LiteralPath)) { return $false }
    try {
        if (-not (Test-Path -LiteralPath $LiteralPath)) { return $true }
        $current = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
        $parent = $current
        for ($depth = 0; $depth -lt 24; $depth++) {
            if (-not $parent.PSIsContainer) {
                $parent = $parent.Directory
            }
            if ($null -eq $parent) { break }
            if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            if ([string]::Equals($parent.Name, 'Programs', [StringComparison]::OrdinalIgnoreCase)) {
                break
            }
            $parent = $parent.Parent
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-LdwToolVersionRunningState {
    param(
        [string] $ProcessName,
        [AllowNull()] [int] $OwnerSessionId = $null
    )
    if ([string]::IsNullOrWhiteSpace($ProcessName)) { return 'unknown' }
    if ($null -eq $OwnerSessionId) {
        $OwnerSessionId = Get-LdwToolVersionOwnerSessionId
    }
    if ($null -eq $OwnerSessionId) { return 'unknown' }
    try {
        $sessionMatches = @(
            Get-Process -Name $ProcessName -ErrorAction SilentlyContinue |
                Where-Object { $_.SessionId -eq $OwnerSessionId }
        )
        if ($sessionMatches.Count -eq 0) {
            return 'not_observed_in_owner_session'
        }
        if ($sessionMatches.Count -eq 1) {
            return 'observed_name_in_owner_session'
        }
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
        if (-not (Test-Path -LiteralPath $PendingDir)) { return 'unknown' }
        foreach ($marker in $Markers) {
            if ([string]::IsNullOrWhiteSpace($marker)) { continue }
            $candidate = Join-Path $PendingDir $marker
            if (Test-Path -LiteralPath $candidate) {
                return 'in_progress_evidence'
            }
        }
        return 'unknown'
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
            install_identity_trusted = $null
        }
    }
    $identityTrusted = Test-LdwToolVersionInstallPathIdentity -LiteralPath $path
    if (-not $identityTrusted) {
        return @{
            install_state            = 'unverified'
            install_identity_trusted = $false
            error_code               = 'INSTALL_IDENTITY_REFUSED'
            file_version             = $null
            product_version          = $null
            authenticode_state       = 'UNVERIFIED'
            trusted_publisher_policy = 'UNVERIFIED'
        }
    }
    try {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        $fileVersion = ConvertTo-LdwToolVersionSanitizedPeVersion -Raw $item.VersionInfo.FileVersion
        $productVersion = ConvertTo-LdwToolVersionSanitizedPeVersion -Raw $item.VersionInfo.ProductVersion
        $auth = Get-LdwToolVersionAuthenticodeSummary -Path $path -AppId $CatalogEntry.app_id `
            -ExpectedUnsignedPolicy ([bool] $CatalogEntry.expected_unsigned_policy) `
            -InstallIdentityTrusted $true
        $installState = if ($fileVersion -or $productVersion) { 'found' } else { 'unverified' }
        if ($auth.trusted_publisher_policy -eq 'UNVERIFIED' -and $installState -eq 'found' -and -not $CatalogEntry.expected_unsigned_policy) {
            $installState = 'unverified'
        }
        return @{
            install_state            = $installState
            install_identity_trusted = $true
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
        running_scope              = 'owner_session_process_name_only'
    }
    if ($probe.ContainsKey('install_identity_trusted')) {
        $record.install_identity_trusted = $probe.install_identity_trusted
    }
    if ($probe.ContainsKey('error_code')) {
        $record.error_code = $probe.error_code
    }
    if ($CatalogEntry.app_id -eq 'codync') {
        if ($record.running_state -eq 'not_observed_in_owner_session' -and $probe.install_state -eq 'found') {
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
    if ($Snapshot.ContainsKey('running_scope')) { $record.running_scope = $Snapshot.running_scope }
    if ($Snapshot.ContainsKey('install_identity_trusted')) { $record.install_identity_trusted = $Snapshot.install_identity_trusted }
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
