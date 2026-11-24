#Requires -Version 5.1
# SOURCE-ONLY / PLAN-ONLY (#341). Embedded synthetic JSON only. No file, media, network or process I/O.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootsJson = @"
[
  {"approved_root_id":"ROOT-A","source_volume_id":"VOL-SYNTH-A"},
  {"approved_root_id":"ROOT-B","source_volume_id":"VOL-SYNTH-B"}
]
"@

$inventoryJson = @"
[
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/alpha.bin","size_bytes":100},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/bravo.bin","size_bytes":200},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/charlie.bin","size_bytes":300},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/delta.bin","size_bytes":400},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/echo.bin","size_bytes":500},
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/foxtrot.bin","size_bytes":600},
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/golf.bin","size_bytes":700},
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/hotel.bin","size_bytes":800},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/india.bin","size_bytes":900},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/juliet.bin","size_bytes":1000},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/kilo.bin","size_bytes":1100,"excluded":true},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/../lima.bin","size_bytes":1200},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-B","relative_path":"fixture/mike.bin","size_bytes":1300},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/alpha.bin","size_bytes":1400},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/oscar.bin","size_bytes":1500},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/papa.bin","size_bytes":1600},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/quebec.bin","size_bytes":1700},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/sierra.bin","size_bytes":1800}
]
"@

$proofsJson = @"
[
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/alpha.bin","proof_tier":"full_hash_pair_plus_pieces","torrent_state":"complete","piece_proof_valid":true,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/alpha.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/bravo.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/bravo.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/charlie.bin","proof_tier":"legacy_manifest","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/charlie.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/delta.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/delta.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/echo.bin","proof_tier":"none","torrent_state":"complete","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":""},
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/foxtrot.bin","proof_tier":"none","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":""},
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/golf.bin","proof_tier":"none","torrent_state":"incomplete","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":""},
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/hotel.bin","proof_tier":"none","torrent_state":"incomplete","piece_proof_valid":false,"preallocated_only":true,"source_stable":true,"changed_since_copy":false,"destination_path":""},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/india.bin","proof_tier":"none","torrent_state":"unknown","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":""},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/juliet.bin","proof_tier":"full_hash_pair","torrent_state":"complete","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/juliet.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/kilo.bin","proof_tier":"none","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":""},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/oscar.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/duplicate.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/papa.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/duplicate.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/quebec.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":false,"changed_since_copy":false,"destination_path":"stage/quebec.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/sierra.bin","proof_tier":"full_hash_pair_plus_pieces","torrent_state":"complete","piece_proof_valid":true,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/sierra.bin"}
]
"@

# Negative fixtures. <<SEP>> is replaced with char 0x1f so the source file
# itself carries no raw control bytes. All tokens are synthetic.
$negInventoryJson = @"
[
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/boolstr.bin","size_bytes":100,"excluded":"false"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/badbool.bin","size_bytes":200},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/badexcl.bin","size_bytes":300,"excluded":"yes"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/intbool.bin","size_bytes":400},
 {"source_volume_id":"VOL-SYNTH-A<<SEP>>EVIL","approved_root_id":"ROOT-A","relative_path":"neg/sepvol.bin","size_bytes":500},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/./dotpath.bin","size_bytes":600},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destabs.bin","size_bytes":700},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destunc.bin","size_bytes":800},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destads.bin","size_bytes":900},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destctrl.bin","size_bytes":1000},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destrep.bin","size_bytes":1100},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/sizemm.bin","size_bytes":1200},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/rawonly.bin","size_bytes":1300},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/canon1.bin","size_bytes":1400},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/canon2.bin","size_bytes":1500},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/orphansource.bin","size_bytes":1600}
]
"@

$negProofsJson = @"
[
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/boolstr.bin","proof_tier":"full_hash_pair_plus_pieces","torrent_state":"complete","piece_proof_valid":"false","preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/boolstr.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/badbool.bin","proof_tier":"full_hash_pair_plus_pieces","torrent_state":"complete","piece_proof_valid":"yes","preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/badbool.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/badexcl.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/badexcl.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/intbool.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":1,"changed_since_copy":false,"destination_path":"stage/intbool.bin"},
 {"source_volume_id":"VOL-SYNTH-A<<SEP>>EVIL","approved_root_id":"ROOT-A","relative_path":"neg/sepvol.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/sepvol.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/./dotpath.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/dotpath.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destabs.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"C:/stage/x.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destunc.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"//server/share/x.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destads.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/x.bin:stream"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destctrl.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/x.bin<<SEP>>evil"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/destrep.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/rep.bin","destination_is_reparse":true},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/sizemm.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/sizemm.bin","size_bytes":9999},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/rawonly.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/rawonly.bin","destination_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/canon1.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/CANON.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/canon2.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"STAGE\\canon.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"neg/ghost.bin","proof_tier":"full_hash_pair","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/ghost.bin"}
]
"@

$sep = [string][char]31
$roots = $rootsJson.Replace('<<SEP>>', $sep) | ConvertFrom-Json
$inventory = $inventoryJson.Replace('<<SEP>>', $sep) | ConvertFrom-Json
$proofs = $proofsJson.Replace('<<SEP>>', $sep) | ConvertFrom-Json
$negInventory = $negInventoryJson.Replace('<<SEP>>', $sep) | ConvertFrom-Json
$negProofs = $negProofsJson.Replace('<<SEP>>', $sep) | ConvertFrom-Json

$module = Join-Path (Split-Path $PSScriptRoot -Parent) 'MediaCoveragePlannerV0.psm1'
Import-Module $module -Force -ErrorAction Stop

$script:checks = 0
function Assert-D0Coverage([bool]$condition, [string]$name) {
    $script:checks++
    if (-not $condition) { throw ('MEDIA_COVERAGE_PLANNER_V0_ASSERT_' + $name) }
}
function Get-ReasonCount($result, [string]$reason) {
    return @($result.entries | Where-Object { $_.reason -ceq $reason }).Count
}

# ---------- Main happy-path fixture ----------
$r = Get-LdwMediaCoverage -Inventory $inventory -ApprovedRoots $roots -Proofs $proofs
$b = $r.buckets

Assert-D0Coverage ($r.reconciled -eq $true) 'RECONCILED'
Assert-D0Coverage ($r.reconciled_scope -ceq 'internal_partition_only_not_external_completeness') 'RECONCILED_SCOPE'
Assert-D0Coverage ($r.fail_closed -eq $true) 'FAIL_CLOSED'
Assert-D0Coverage ($r.orphan_proof_count -eq 0) 'ORPHAN_ZERO'
Assert-D0Coverage ($r.input_files -eq 18) 'INPUT_FILES'
Assert-D0Coverage ($r.input_bytes -eq 17100) 'INPUT_BYTES'
Assert-D0Coverage ($b.FULLY_VERIFIED.count -eq 2) 'COUNT_FULLY_VERIFIED'
Assert-D0Coverage ($b.LEGACY_MANIFEST_ONLY.count -eq 1) 'COUNT_LEGACY'
Assert-D0Coverage ($b.RAW_PENDING.count -eq 1) 'COUNT_RAW_PENDING'
Assert-D0Coverage ($b.TRUSTED_NOT_COPIED.count -eq 1) 'COUNT_TRUSTED_NOT_COPIED'
Assert-D0Coverage ($b.STABLE_NON_TORRENT_CANDIDATE.count -eq 1) 'COUNT_STABLE_CANDIDATE'
Assert-D0Coverage ($b.INCOMPLETE_TORRENT.count -eq 2) 'COUNT_INCOMPLETE'
Assert-D0Coverage ($b.UNKNOWN_OR_AMBIGUOUS_TORRENT.count -eq 2) 'COUNT_UNKNOWN'
Assert-D0Coverage ($b.OTHER_EXCLUDED.count -eq 1) 'COUNT_OTHER_EXCLUDED'
Assert-D0Coverage ($b.COLLISION_ERROR.count -eq 7) 'COUNT_COLLISION'
Assert-D0Coverage ($b.FULLY_VERIFIED.bytes -eq 2000) 'BYTES_FULLY_VERIFIED'
Assert-D0Coverage ($b.LEGACY_MANIFEST_ONLY.bytes -eq 300) 'BYTES_LEGACY'
Assert-D0Coverage ($b.RAW_PENDING.bytes -eq 400) 'BYTES_RAW_PENDING'
Assert-D0Coverage ($b.TRUSTED_NOT_COPIED.bytes -eq 500) 'BYTES_TRUSTED_NOT_COPIED'
Assert-D0Coverage ($b.STABLE_NON_TORRENT_CANDIDATE.bytes -eq 600) 'BYTES_STABLE_CANDIDATE'
Assert-D0Coverage ($b.INCOMPLETE_TORRENT.bytes -eq 1500) 'BYTES_INCOMPLETE'
Assert-D0Coverage ($b.UNKNOWN_OR_AMBIGUOUS_TORRENT.bytes -eq 1900) 'BYTES_UNKNOWN'
Assert-D0Coverage ($b.OTHER_EXCLUDED.bytes -eq 1100) 'BYTES_OTHER_EXCLUDED'
Assert-D0Coverage ($b.COLLISION_ERROR.bytes -eq 8800) 'BYTES_COLLISION'
Assert-D0Coverage ((Get-ReasonCount $r 'HASH_PAIR_PLUS_PIECES') -eq 1) 'REASON_PIECES'
Assert-D0Coverage ((Get-ReasonCount $r 'HASH_PAIR_ONLY') -eq 1) 'REASON_HASH_PAIR_ONLY'
Assert-D0Coverage ((Get-ReasonCount $r 'PREALLOCATED_ONLY') -eq 1) 'REASON_PREALLOCATED'
Assert-D0Coverage ((Get-ReasonCount $r 'DUPLICATE_DESTINATION') -eq 2) 'REASON_DUP_DEST'
Assert-D0Coverage ((Get-ReasonCount $r 'DUPLICATE_SOURCE_KEY') -eq 2) 'REASON_DUP_SOURCE'
Assert-D0Coverage ((Get-ReasonCount $r 'WRONG_ROOT_VOLUME') -eq 1) 'REASON_WRONG_ROOT'
Assert-D0Coverage ((Get-ReasonCount $r 'MALFORMED_SOURCE_KEY') -eq 1) 'REASON_TRAVERSAL'
Assert-D0Coverage ((Get-ReasonCount $r 'UNSTABLE_OR_CHANGED_SOURCE') -eq 1) 'REASON_UNSTABLE'
Assert-D0Coverage ((Get-ReasonCount $r 'COMPLETE_TORRENT_PIECES_NOT_PROVEN') -eq 1) 'REASON_PIECES_UNPROVEN'

# ---------- Negative fixture: strict parsing, canonical paths, fail-closed ----------
$n = Get-LdwMediaCoverage -Inventory $negInventory -ApprovedRoots $roots -Proofs $negProofs
$nb = $n.buckets

Assert-D0Coverage ($n.reconciled -eq $true) 'NEG_RECONCILED'
Assert-D0Coverage ($n.fail_closed -eq $true) 'NEG_FAIL_CLOSED'
Assert-D0Coverage ($n.orphan_proof_count -eq 1) 'NEG_ORPHAN_COUNT'
Assert-D0Coverage ($n.input_files -eq 16) 'NEG_INPUT_FILES'
Assert-D0Coverage ($n.input_bytes -eq 13600) 'NEG_INPUT_BYTES'
Assert-D0Coverage ($nb.COLLISION_ERROR.count -eq 13) 'NEG_COUNT_COLLISION'
Assert-D0Coverage ($nb.UNKNOWN_OR_AMBIGUOUS_TORRENT.count -eq 2) 'NEG_COUNT_UNKNOWN'
Assert-D0Coverage ($nb.RAW_PENDING.count -eq 1) 'NEG_COUNT_RAW_PENDING'
Assert-D0Coverage ($nb.FULLY_VERIFIED.count -eq 0) 'NEG_COUNT_FULLY_VERIFIED'
Assert-D0Coverage ((Get-ReasonCount $n 'MALFORMED_BOOL') -eq 3) 'NEG_REASON_MALFORMED_BOOL'
Assert-D0Coverage ((Get-ReasonCount $n 'MALFORMED_SOURCE_KEY') -eq 2) 'NEG_REASON_MALFORMED_SOURCE'
Assert-D0Coverage ((Get-ReasonCount $n 'MISSING_DESTINATION') -eq 4) 'NEG_REASON_BAD_DEST'
Assert-D0Coverage ((Get-ReasonCount $n 'UNSAFE_DESTINATION_IDENTITY') -eq 1) 'NEG_REASON_REPARSE'
Assert-D0Coverage ((Get-ReasonCount $n 'PROOF_SIZE_MISMATCH') -eq 1) 'NEG_REASON_SIZE_MISMATCH'
Assert-D0Coverage ((Get-ReasonCount $n 'DUPLICATE_DESTINATION') -eq 2) 'NEG_REASON_CANON_COLLISION'
Assert-D0Coverage ((Get-ReasonCount $n 'COMPLETE_TORRENT_PIECES_NOT_PROVEN') -eq 1) 'NEG_REASON_FALSE_STRING'
Assert-D0Coverage ((Get-ReasonCount $n 'NO_PROOF_NO_CERTAINTY') -eq 1) 'NEG_REASON_NO_PROOF'
Assert-D0Coverage ((Get-ReasonCount $n 'RAW_DEST_SHA256_ONLY') -eq 1) 'NEG_REASON_RAW_ONLY'

# ---------- Determinism ----------
$r2 = Get-LdwMediaCoverage -Inventory $inventory -ApprovedRoots $roots -Proofs $proofs
$n2 = Get-LdwMediaCoverage -Inventory $negInventory -ApprovedRoots $roots -Proofs $negProofs
Assert-D0Coverage (($r | ConvertTo-Json -Depth 12 -Compress) -ceq ($r2 | ConvertTo-Json -Depth 12 -Compress)) 'DETERMINISTIC_MAIN'
Assert-D0Coverage (($n | ConvertTo-Json -Depth 12 -Compress) -ceq ($n2 | ConvertTo-Json -Depth 12 -Compress)) 'DETERMINISTIC_NEG'

Write-Output ('MEDIA_COVERAGE_PLANNER_V0=PASS assertions=' + $script:checks)
Write-Output 'MEDIA_COVERAGE_PLANNER_PRIVATE_OPERATION=NOT_AUTHORIZED'
Write-Output 'MEDIA_COVERAGE_PLANNER_PLANNER_IO=NONE'
