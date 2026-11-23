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
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/kilo.bin","size_bytes":1100,"excluded":true},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/../lima.bin","size_bytes":1200},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"VOL-SYNTH-B","relative_path":"fixture/mike.bin","size_bytes":1300},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/alpha.bin","size_bytes":1400},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/oscar.bin","size_bytes":1500},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/papa.bin","size_bytes":1600},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/quebec.bin","size_bytes":1700}
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
 {"source_volume_id":"VOL-SYNTH-B","approved_root_id":"ROOT-B","relative_path":"fixture/kilo.bin","proof_tier":"none","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":""},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/oscar.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/duplicate.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/papa.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":true,"changed_since_copy":false,"destination_path":"stage/duplicate.bin"},
 {"source_volume_id":"VOL-SYNTH-A","approved_root_id":"ROOT-A","relative_path":"fixture/quebec.bin","proof_tier":"raw_dest_sha256","torrent_state":"not_applicable","piece_proof_valid":false,"preallocated_only":false,"source_stable":false,"changed_since_copy":false,"destination_path":"stage/quebec.bin"}
]
"@

$roots = $rootsJson | ConvertFrom-Json
$inventory = $inventoryJson | ConvertFrom-Json
$proofs = $proofsJson | ConvertFrom-Json

$module = Join-Path (Split-Path $PSScriptRoot -Parent) 'MediaCoveragePlannerV0.psm1'
Import-Module $module -Force -ErrorAction Stop

$script:checks = 0
function Assert-D0Coverage([bool]$condition, [string]$name) {
    $script:checks++
    if (-not $condition) { throw ('MEDIA_COVERAGE_PLANNER_V0_ASSERT_' + $name) }
}

$r = Get-LdwMediaCoverage -Inventory $inventory -ApprovedRoots $roots -Proofs $proofs
$b = $r.buckets

Assert-D0Coverage ($r.reconciled -eq $true) 'RECONCILED'
Assert-D0Coverage ($r.input_files -eq 17) 'INPUT_FILES'
Assert-D0Coverage ($r.input_bytes -eq 15300) 'INPUT_BYTES'
Assert-D0Coverage ($b.FULLY_VERIFIED.count -eq 2) 'COUNT_FULLY_VERIFIED'
Assert-D0Coverage ($b.LEGACY_MANIFEST_ONLY.count -eq 1) 'COUNT_LEGACY'
Assert-D0Coverage ($b.RAW_PENDING.count -eq 1) 'COUNT_RAW_PENDING'
Assert-D0Coverage ($b.TRUSTED_NOT_COPIED.count -eq 1) 'COUNT_TRUSTED_NOT_COPIED'
Assert-D0Coverage ($b.STABLE_NON_TORRENT_CANDIDATE.count -eq 1) 'COUNT_STABLE_CANDIDATE'
Assert-D0Coverage ($b.INCOMPLETE_TORRENT.count -eq 2) 'COUNT_INCOMPLETE'
Assert-D0Coverage ($b.UNKNOWN_OR_AMBIGUOUS_TORRENT.count -eq 2) 'COUNT_UNKNOWN'
Assert-D0Coverage ($b.OTHER_EXCLUDED.count -eq 1) 'COUNT_OTHER_EXCLUDED'
Assert-D0Coverage ($b.COLLISION_ERROR.count -eq 6) 'COUNT_COLLISION'
Assert-D0Coverage ($b.FULLY_VERIFIED.bytes -eq 300) 'BYTES_FULLY_VERIFIED'
Assert-D0Coverage ($b.LEGACY_MANIFEST_ONLY.bytes -eq 300) 'BYTES_LEGACY'
Assert-D0Coverage ($b.RAW_PENDING.bytes -eq 400) 'BYTES_RAW_PENDING'
Assert-D0Coverage ($b.TRUSTED_NOT_COPIED.bytes -eq 500) 'BYTES_TRUSTED_NOT_COPIED'
Assert-D0Coverage ($b.STABLE_NON_TORRENT_CANDIDATE.bytes -eq 600) 'BYTES_STABLE_CANDIDATE'
Assert-D0Coverage ($b.INCOMPLETE_TORRENT.bytes -eq 1500) 'BYTES_INCOMPLETE'
Assert-D0Coverage ($b.UNKNOWN_OR_AMBIGUOUS_TORRENT.bytes -eq 1900) 'BYTES_UNKNOWN'
Assert-D0Coverage ($b.OTHER_EXCLUDED.bytes -eq 1100) 'BYTES_OTHER_EXCLUDED'
Assert-D0Coverage ($b.COLLISION_ERROR.bytes -eq 8700) 'BYTES_COLLISION'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'HASH_PAIR_PLUS_PIECES' }).Count -eq 1) 'REASON_PIECES'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'HASH_PAIR_ONLY' }).Count -eq 1) 'REASON_HASH_PAIR_ONLY'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'PREALLOCATED_ONLY' }).Count -eq 1) 'REASON_PREALLOCATED'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'DUPLICATE_DESTINATION' }).Count -eq 2) 'REASON_DUP_DEST'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'DUPLICATE_SOURCE_KEY' }).Count -eq 1) 'REASON_DUP_SOURCE'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'WRONG_ROOT_VOLUME' }).Count -eq 1) 'REASON_WRONG_ROOT'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'MALFORMED_SOURCE_KEY' }).Count -eq 1) 'REASON_TRAVERSAL'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'UNSTABLE_OR_CHANGED_SOURCE' }).Count -eq 1) 'REASON_UNSTABLE'
Assert-D0Coverage (@($r.entries | Where-Object { $_.reason -ceq 'COMPLETE_TORRENT_PIECES_NOT_PROVEN' }).Count -eq 1) 'REASON_PIECES_UNPROVEN'

$r2 = Get-LdwMediaCoverage -Inventory $inventory -ApprovedRoots $roots -Proofs $proofs
$j1 = $r | ConvertTo-Json -Depth 12 -Compress
$j2 = $r2 | ConvertTo-Json -Depth 12 -Compress
Assert-D0Coverage ($j1 -ceq $j2) 'DETERMINISTIC'

Write-Output ('MEDIA_COVERAGE_PLANNER_V0=PASS assertions=' + $script:checks)
Write-Output 'MEDIA_COVERAGE_PLANNER_PRIVATE_OPERATION=NOT_AUTHORIZED'
Write-Output 'MEDIA_COVERAGE_PLANNER_PLANNER_IO=NONE'