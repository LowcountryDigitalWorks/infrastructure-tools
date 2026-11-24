#Requires -Version 5.1
# SOURCE-ONLY / PLAN-ONLY (#341). Pure classification: no I/O, no process, no network, no clock.
Set-StrictMode -Version Latest

$script:PlannerSchema = 'media-coverage-planner-v0'
$script:Sep = [string][char]31
$script:Buckets = @(
    'FULLY_VERIFIED',
    'LEGACY_MANIFEST_ONLY',
    'RAW_PENDING',
    'TRUSTED_NOT_COPIED',
    'STABLE_NON_TORRENT_CANDIDATE',
    'INCOMPLETE_TORRENT',
    'UNKNOWN_OR_AMBIGUOUS_TORRENT',
    'OTHER_EXCLUDED',
    'COLLISION_ERROR'
)

function Get-MediaField {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# Strict boolean parse. Never use PowerShell truthiness on untrusted values:
# [bool]'false' is $true, [bool]'garbage' is $true. Only typed bool or the
# exact strings 'true'/'false' (trimmed, case-insensitive) are accepted.
function Test-LdwStrictBool {
    param($Value)
    if ($Value -is [bool]) { return @{ ok = $true; value = [bool]$Value } }
    if ($Value -is [string]) {
        $s = ([string]$Value).Trim()
        if ($s -ieq 'true') { return @{ ok = $true; value = $true } }
        if ($s -ieq 'false') { return @{ ok = $true; value = $false } }
    }
    return @{ ok = $false; value = $false }
}

function ConvertTo-LdwNormId {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -isnot [string]) { return '' }
    $s = [string]$Value
    if ($s -match '[\x00-\x1f\x7f-\x9f]') { return '' }
    $s = $s.Trim()
    if ($s -eq '') { return '' }
    if ($s.Contains('/') -or $s.Contains('\') -or $s.Contains(':')) { return '' }
    return $s.ToLowerInvariant()
}

function ConvertTo-LdwNormRelativePath {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -isnot [string]) { return '' }
    $p = [string]$Value
    if ($p -match '[\x00-\x1f\x7f-\x9f]') { return '' }
    $p = $p -replace '\\', '/'
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    if ($p.StartsWith('/') -or $p -match '^[a-zA-Z]:') { return '' }
    if ($p.Contains(':') -or $p.Contains('//') -or $p.EndsWith('/')) { return '' }
    $parts = @($p -split '/')
    if ($parts.Count -eq 0) { return '' }
    foreach ($x in $parts) {
        if ($x -eq '' -or $x -eq '.' -or $x -eq '..') { return '' }
        if ($x.Contains($script:Sep)) { return '' }
    }
    return (($parts -join '/').ToLowerInvariant())
}

# Strict relative destination canonicalizer. Any absolute/drive/UNC form,
# dot or dotdot component, ADS colon, control character, injected separator,
# repeated or trailing separator is refused (returns empty -> COLLISION_ERROR).
function ConvertTo-LdwNormDestination {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -isnot [string]) { return '' }
    $p = [string]$Value
    if ($p -match '[\x00-\x1f\x7f-\x9f]') { return '' }
    $p = $p -replace '\\', '/'
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    if ($p.StartsWith('/') -or $p -match '^[a-zA-Z]:') { return '' }
    if ($p.Contains(':') -or $p.Contains('//') -or $p.EndsWith('/')) { return '' }
    $parts = @($p -split '/')
    if ($parts.Count -eq 0) { return '' }
    foreach ($x in $parts) {
        if ($x -eq '' -or $x -eq '.' -or $x -eq '..') { return '' }
        if ($x.Contains(':') -or $x.Contains($script:Sep)) { return '' }
        if ($x -match '[\x00-\x1f\x7f-\x9f]') { return '' }
    }
    return (($parts -join '/').ToLowerInvariant())
}

# Reject proof metadata that claims/represents reparse points, links or odd
# identity. Flags must themselves be strict booleans; any true flag or any
# malformed flag fails closed.
function Test-LdwProofDestinationIdentity {
    param($Proof)
    if ($null -eq $Proof) { return $true }
    foreach ($p in $Proof.PSObject.Properties) {
        if ($p.Name -match '(?i)reparse|symlink|junction|hardlink|identity') {
            $bv = Test-LdwStrictBool -Value $p.Value
            if (-not $bv.ok) { return $false }
            if ($bv.value) { return $false }
        }
    }
    return $true
}

function Test-LdwCopyClassTier {
    param([string]$Tier)
    return ($Tier -in @('full_hash_pair','full_hash_pair_plus_pieces','legacy_manifest','raw_dest_sha256'))
}

function Get-LdwMediaCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Inventory,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$ApprovedRoots,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Proofs
    )
    $sep = $script:Sep

    $approved = @{}
    foreach ($r in $ApprovedRoots) {
        $rid = ConvertTo-LdwNormId (Get-MediaField $r 'approved_root_id')
        $vid = ConvertTo-LdwNormId (Get-MediaField $r 'source_volume_id')
        if ($rid -ne '' -and $vid -ne '') { $approved[$rid + $sep + $vid] = $true }
    }

    $proofByKey = @{}
    $proofKeyDuplicate = @{}
    foreach ($p in $Proofs) {
        $vid = ConvertTo-LdwNormId (Get-MediaField $p 'source_volume_id')
        $rid = ConvertTo-LdwNormId (Get-MediaField $p 'approved_root_id')
        $rel = ConvertTo-LdwNormRelativePath (Get-MediaField $p 'relative_path')
        $key = $vid + $sep + $rid + $sep + $rel
        if ($proofByKey.ContainsKey($key)) { $proofKeyDuplicate[$key] = $true }
        else { $proofByKey[$key] = $p }
    }

    $inventoryKeySet = @{}
    foreach ($i in $Inventory) {
        $vid = ConvertTo-LdwNormId (Get-MediaField $i 'source_volume_id')
        $rid = ConvertTo-LdwNormId (Get-MediaField $i 'approved_root_id')
        $rel = ConvertTo-LdwNormRelativePath (Get-MediaField $i 'relative_path')
        $inventoryKeySet[$vid + $sep + $rid + $sep + $rel] = $true
    }
    $orphanProofCount = 0
    $orphanSeen = @{}
    foreach ($k in $proofByKey.Keys) {
        if (-not $inventoryKeySet.ContainsKey($k) -and -not $orphanSeen.ContainsKey($k)) {
            $orphanSeen[$k] = $true
            $orphanProofCount++
        }
    }

    $destCount = @{}
    foreach ($p in $Proofs) {
        $tier = ConvertTo-LdwNormId (Get-MediaField $p 'proof_tier')
        if (-not (Test-LdwCopyClassTier -Tier $tier)) { continue }
        $dest = ConvertTo-LdwNormDestination (Get-MediaField $p 'destination_path')
        if ($dest -eq '') { continue }
        if (-not $destCount.ContainsKey($dest)) { $destCount[$dest] = 0 }
        $destCount[$dest]++
    }

    $sourceSeen = @{}
    $sourceDuplicate = @{}
    foreach ($i in $Inventory) {
        $vid = ConvertTo-LdwNormId (Get-MediaField $i 'source_volume_id')
        $rid = ConvertTo-LdwNormId (Get-MediaField $i 'approved_root_id')
        $rel = ConvertTo-LdwNormRelativePath (Get-MediaField $i 'relative_path')
        $key = $vid + $sep + $rid + $sep + $rel
        if ($sourceSeen.ContainsKey($key)) { $sourceDuplicate[$key] = $true }
        else { $sourceSeen[$key] = $true }
    }

    $counts = @{}
    $bytes = @{}
    foreach ($b in $script:Buckets) { $counts[$b] = 0; $bytes[$b] = [int64]0 }
    $inputBytes = [int64]0
    $entries = New-Object 'System.Collections.Generic.List[object]'

    foreach ($i in $Inventory) {
        $vid = ConvertTo-LdwNormId (Get-MediaField $i 'source_volume_id')
        $rid = ConvertTo-LdwNormId (Get-MediaField $i 'approved_root_id')
        $rel = ConvertTo-LdwNormRelativePath (Get-MediaField $i 'relative_path')
        $key = $vid + $sep + $rid + $sep + $rel
        $rawSize = Get-MediaField $i 'size_bytes'
        $size = [int64]0
        $sizeOk = $false
        if ($rawSize -is [int] -or $rawSize -is [long]) { $size = [int64]$rawSize; if ($size -gt 0) { $sizeOk = $true } }
        if ($sizeOk) { $inputBytes += $size }

        # Strict booleans for the inventory exclusion marker.
        $excluded = $false
        $excludedOk = $true
        $excludedRaw = Get-MediaField $i 'excluded'
        if ($null -ne $excludedRaw) {
            $bv = Test-LdwStrictBool -Value $excludedRaw
            if ($bv.ok) { $excluded = $bv.value } else { $excludedOk = $false }
        }

        $bucket = ''
        $reason = ''
        $dest = ''

        if ($sourceDuplicate.ContainsKey($key)) {
            $bucket = 'COLLISION_ERROR'; $reason = 'DUPLICATE_SOURCE_KEY'
        }
        elseif ($vid -eq '' -or $rid -eq '' -or $rel -eq '') {
            $bucket = 'COLLISION_ERROR'; $reason = 'MALFORMED_SOURCE_KEY'
        }
        elseif (-not $approved.ContainsKey($rid + $sep + $vid)) {
            $bucket = 'COLLISION_ERROR'; $reason = 'WRONG_ROOT_VOLUME'
        }
        elseif (-not $sizeOk) {
            $bucket = 'COLLISION_ERROR'; $reason = 'BAD_SIZE'
        }
        elseif ($proofKeyDuplicate.ContainsKey($key)) {
            $bucket = 'COLLISION_ERROR'; $reason = 'DUPLICATE_PROOF_KEY'
        }
        else {
            $p = $null
            if ($proofByKey.ContainsKey($key)) { $p = $proofByKey[$key] }
            $tier = if ($null -ne $p) { ConvertTo-LdwNormId (Get-MediaField $p 'proof_tier') } else { '' }
            $tstate = if ($null -ne $p) { ConvertTo-LdwNormId (Get-MediaField $p 'torrent_state') } else { '' }
            if ($null -ne $p) { $dest = ConvertTo-LdwNormDestination (Get-MediaField $p 'destination_path') }
            $copyClass = Test-LdwCopyClassTier -Tier $tier

            # Strict booleans for every untrusted proof flag.
            $parsedBool = @{}
            $proofBoolOk = $true
            if ($null -ne $p) {
                foreach ($f in @('piece_proof_valid','preallocated_only','source_stable','changed_since_copy')) {
                    $bv = Test-LdwStrictBool -Value (Get-MediaField $p $f)
                    if (-not $bv.ok) { $proofBoolOk = $false; break }
                    $parsedBool[$f] = $bv.value
                }
            }
            $pieces = if ($proofBoolOk) { [bool]$parsedBool['piece_proof_valid'] } else { $false }
            $prealloc = if ($proofBoolOk) { [bool]$parsedBool['preallocated_only'] } else { $false }
            $stable = if ($proofBoolOk) { [bool]$parsedBool['source_stable'] } else { $false }
            $changed = if ($proofBoolOk) { [bool]$parsedBool['changed_since_copy'] } else { $false }

            $identityOk = Test-LdwProofDestinationIdentity -Proof $p

            $proofSizeOk = $true
            if ($null -ne $p) {
                $psRaw = Get-MediaField $p 'size_bytes'
                if ($null -ne $psRaw) {
                    if ($psRaw -is [int] -or $psRaw -is [long]) {
                        $ps = [int64]$psRaw
                        if ($ps -le 0 -or $ps -ne $size) { $proofSizeOk = $false }
                    } else { $proofSizeOk = $false }
                }
            }

            $destDuplicate = ($copyClass -and $dest -ne '' -and $destCount.ContainsKey($dest) -and $destCount[$dest] -gt 1)

            if (-not $excludedOk -or -not $proofBoolOk) { $bucket='COLLISION_ERROR'; $reason='MALFORMED_BOOL' }
            elseif (-not $identityOk) { $bucket='COLLISION_ERROR'; $reason='UNSAFE_DESTINATION_IDENTITY' }
            elseif (-not $proofSizeOk) { $bucket='COLLISION_ERROR'; $reason='PROOF_SIZE_MISMATCH' }
            elseif ($destDuplicate) { $bucket='COLLISION_ERROR'; $reason='DUPLICATE_DESTINATION' }
            elseif ($copyClass -and $dest -eq '') { $bucket='COLLISION_ERROR'; $reason='MISSING_DESTINATION' }
            elseif ($null -ne $p -and (-not $stable -or $changed)) { $bucket='COLLISION_ERROR'; $reason='UNSTABLE_OR_CHANGED_SOURCE' }
            elseif ($excluded) { $bucket='OTHER_EXCLUDED'; $reason='EXPLICIT_EXCLUSION' }
            elseif ($prealloc) { $bucket='INCOMPLETE_TORRENT'; $reason='PREALLOCATED_ONLY' }
            elseif ($tstate -eq 'incomplete') { $bucket='INCOMPLETE_TORRENT'; $reason='INCOMPLETE_TORRENT_STATE' }
            elseif ($tstate -eq 'unknown') { $bucket='UNKNOWN_OR_AMBIGUOUS_TORRENT'; $reason='UNKNOWN_TORRENT_CERTAINTY' }
            elseif ($tier -eq 'full_hash_pair_plus_pieces' -and $tstate -eq 'complete' -and $pieces) { $bucket='FULLY_VERIFIED'; $reason='HASH_PAIR_PLUS_PIECES' }
            elseif ($tier -eq 'full_hash_pair' -and $tstate -eq 'not_applicable') { $bucket='FULLY_VERIFIED'; $reason='HASH_PAIR_ONLY' }
            elseif (($tier -eq 'full_hash_pair' -or $tier -eq 'full_hash_pair_plus_pieces') -and $tstate -eq 'complete' -and -not $pieces) { $bucket='UNKNOWN_OR_AMBIGUOUS_TORRENT'; $reason='COMPLETE_TORRENT_PIECES_NOT_PROVEN' }
            elseif ($tier -eq 'legacy_manifest') { $bucket='LEGACY_MANIFEST_ONLY'; $reason='LEGACY_MANIFEST' }
            elseif ($tier -eq 'raw_dest_sha256') { $bucket='RAW_PENDING'; $reason='RAW_DEST_SHA256_ONLY' }
            elseif ($tier -eq 'none' -or $tier -eq '') {
                if ($tstate -eq 'complete') { $bucket='TRUSTED_NOT_COPIED'; $reason='NO_PROOF_TRUSTED_TORRENT' }
                elseif ($tstate -eq 'not_applicable') { $bucket='STABLE_NON_TORRENT_CANDIDATE'; $reason='NO_PROOF_STABLE_NON_TORRENT' }
                else { $bucket='UNKNOWN_OR_AMBIGUOUS_TORRENT'; $reason='NO_PROOF_NO_CERTAINTY' }
            }
            else { $bucket='UNKNOWN_OR_AMBIGUOUS_TORRENT'; $reason='UNRECOGNIZED_PROOF_TIER' }
        }

        $counts[$bucket]++
        if ($sizeOk) { $bytes[$bucket] += $size }
        $entries.Add([pscustomobject]@{
            source_key = $key
            bucket = $bucket
            reason = $reason
            size_bytes = $size
            destination_path = $dest
        })
    }

    $sumCount = 0
    $sumBytes = [int64]0
    $summary = @{}
    foreach ($b in $script:Buckets) {
        $sumCount += [int]$counts[$b]
        $sumBytes += [int64]$bytes[$b]
        $summary[$b] = [pscustomobject]@{ count = [int]$counts[$b]; bytes = [int64]$bytes[$b] }
    }
    return [pscustomobject]@{
        schema = $script:PlannerSchema
        reconciled = [bool]($sumCount -eq @($Inventory).Count -and $sumBytes -eq $inputBytes)
        reconciled_scope = 'internal_partition_only_not_external_completeness'
        fail_closed = [bool]($counts['COLLISION_ERROR'] -gt 0 -or $orphanProofCount -gt 0)
        orphan_proof_count = [int]$orphanProofCount
        input_files = [int]@($Inventory).Count
        input_bytes = $inputBytes
        buckets = [pscustomobject]$summary
        entries = $entries.ToArray()
    }
}

Export-ModuleMember -Function Get-LdwMediaCoverage
