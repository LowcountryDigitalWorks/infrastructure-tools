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

function ConvertTo-LdwNormId {
    param($Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim().ToLowerInvariant()
}

function ConvertTo-LdwNormRelativePath {
    param($Value)
    if ($null -eq $Value) { return '' }
    $p = ([string]$Value) -replace '\\', '/'
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    if ($p -match '^[a-zA-Z]:' -or $p.StartsWith('/')) { return '' }
    $parts = @($p -split '/' | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0) { return '' }
    foreach ($x in $parts) {
        if ($x -eq '.' -or $x -eq '..' -or $x.Contains($script:Sep)) { return '' }
    }
    return (($parts -join '/').ToLowerInvariant())
}

function ConvertTo-LdwNormDestination {
    param($Value)
    if ($null -eq $Value) { return '' }
    $p = ([string]$Value) -replace '\\', '/'
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    if ($p -match '(^|/)\.\.(/|$)') { return '' }
    return $p.Trim().ToLowerInvariant()
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
        try { $size = [int64]$rawSize; if ($size -gt 0) { $sizeOk = $true } } catch { $sizeOk = $false }
        if ($sizeOk) { $inputBytes += $size }

        $excluded = [bool](Get-MediaField $i 'excluded')
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
            $pieces = [bool](Get-MediaField $p 'piece_proof_valid')
            $prealloc = [bool](Get-MediaField $p 'preallocated_only')
            $stable = [bool](Get-MediaField $p 'source_stable')
            $changed = [bool](Get-MediaField $p 'changed_since_copy')

            $destDuplicate = ($copyClass -and $dest -ne '' -and $destCount.ContainsKey($dest) -and $destCount[$dest] -gt 1)

            if ($destDuplicate) { $bucket='COLLISION_ERROR'; $reason='DUPLICATE_DESTINATION' }
            elseif ($copyClass -and $dest -eq '') { $bucket='COLLISION_ERROR'; $reason='MISSING_DESTINATION' }
            elseif ($null -ne $p -and (-not $stable -or $changed)) { $bucket='COLLISION_ERROR'; $reason='UNSTABLE_OR_CHANGED_SOURCE' }
            elseif ($excluded) { $bucket='OTHER_EXCLUDED'; $reason='EXPLICIT_EXCLUSION' }
            elseif ($prealloc) { $bucket='INCOMPLETE_TORRENT'; $reason='PREALLOCATED_ONLY' }
            elseif ($tstate -eq 'incomplete') { $bucket='INCOMPLETE_TORRENT'; $reason='INCOMPLETE_TORRENT_STATE' }
            elseif ($tstate -eq 'unknown') { $bucket='UNKNOWN_OR_AMBIGUOUS_TORRENT'; $reason='UNKNOWN_TORRENT_CERTAINTY' }
            elseif ($tier -eq 'full_hash_pair_plus_pieces' -and $tstate -eq 'complete' -and $pieces) { $bucket='FULLY_VERIFIED'; $reason='HASH_PAIR_PLUS_PIECES' }
            elseif ($tier -eq 'full_hash_pair' -and $tstate -eq 'not_applicable') { $bucket='FULLY_VERIFIED'; $reason='HASH_PAIR_ONLY' }
            elseif ($tier -eq 'full_hash_pair' -and $tstate -eq 'complete' -and -not $pieces) { $bucket='UNKNOWN_OR_AMBIGUOUS_TORRENT'; $reason='COMPLETE_TORRENT_PIECES_NOT_PROVEN' }
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
        input_files = [int]@($Inventory).Count
        input_bytes = $inputBytes
        buckets = [pscustomobject]$summary
        entries = $entries.ToArray()
    }
}

Export-ModuleMember -Function Get-LdwMediaCoverage