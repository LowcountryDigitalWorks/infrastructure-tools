#Requires -Version 5.1
# Pure synthetic evidence; no network, gh.exe, task, ProgramData or privileged action.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'D0_ATTEST_CONTRACT_WINPS51_X64_REQUIRED'
}
$module = Join-Path (Split-Path $PSScriptRoot -Parent) 'RedrixD0AttestationEvidenceHold.psm1'
Import-Module $module -Force -ErrorAction Stop
$script:checks = 0
function Assert-D0([bool]$condition,[string]$name) {
    $script:checks++
    if (-not $condition) { throw ('D0_ATTEST_HOLD_ASSERT_' + $name) }
}
function Copy-Map([System.Collections.IDictionary]$map) {
    $copy=@{}
    foreach($key in $map.Keys) { $copy[$key]=$map[$key] }
    return $copy
}
$good = @{
    repository='LowcountryDigitalWorks/infrastructure-tools'
    sourceRef='refs/heads/main'
    sourceCommit='543465f6fec8d2557974f5983e17cb7d5bc90031'
    signerWorkflow='LowcountryDigitalWorks/infrastructure-tools/.github/workflows/redrix-d0-source-provenance.yml'
    signerDigest=('b'*40)
    subjectName='redrix-d0-source-probe.tar'
    subjectSha256=('c'*64)
    predicateType='https://slsa.dev/provenance/v1'
    runner='github-hosted'
}
$pins=@{
    sourceCommit=$good.sourceCommit
    signerDigest=$good.signerDigest
    subjectSha256=$good.subjectSha256
}
function Expect([object]$e,[object]$p,[string]$out,[string]$case) {
    $result=Test-RedrixD0EvidenceHold -Evidence $e -ResearchOnlyExpected $p
    Assert-D0 ($result -ceq $out) $case
}
Expect $good $pins 'HOLD_CRYPTOGRAPHIC_AND_INDEPENDENT_ACCEPTANCE_ABSENT' 'VALID_SHAPE_STILL_HOLD'
Expect $null $pins 'HOLD_EVIDENCE_SHAPE' 'MISSING_EVIDENCE'
Expect @('not-map') $pins 'HOLD_EVIDENCE_SHAPE' 'ARRAY_EVIDENCE'
Expect $good $null 'HOLD_EVIDENCE_SHAPE' 'MISSING_ACCEPTED_PINS'
Expect $good @('pins') 'HOLD_EVIDENCE_SHAPE' 'ARRAY_PINS'

foreach($key in @('repository','sourceRef','sourceCommit','signerWorkflow',
    'signerDigest','subjectName','subjectSha256','predicateType','runner')) {
    $candidate=Copy-Map $good
    [void]$candidate.Remove($key)
    Expect $candidate $pins 'HOLD_EVIDENCE_SHAPE' ('MISSING_'+$key)
    $candidate=Copy-Map $good
    $candidate[$key]=@('unexpected')
    Expect $candidate $pins 'HOLD_EVIDENCE_SHAPE' ('ARRAY_'+$key)
}
$candidate=Copy-Map $good
$candidate['signatureVerified']=$true
Expect $candidate $pins 'HOLD_EVIDENCE_SHAPE' 'UNTRUSTED_POSITIVE_FIELD_REFUSED'

$changes = @{
    repository='OtherOrg/infrastructure-tools'
    sourceRef='refs/pull/5/merge'
    signerWorkflow='EvilOrg/repo/.github/workflows/signer.yml'
    subjectName='other.tar'
    predicateType='https://example.invalid/forged'
    runner='self-hosted'
}
foreach($key in $changes.Keys){
    $candidate=Copy-Map $good
    $candidate[$key]=$changes[$key]
    Expect $candidate $pins 'HOLD_SOURCE_OR_WORKFLOW_IDENTITY' ('UNTRUSTED_'+$key)
}
foreach($key in @('sourceCommit','signerDigest','subjectSha256')) {
    $candidate=Copy-Map $good
    $candidate[$key]='abc'
    Expect $candidate $pins 'HOLD_DIGEST_SHAPE' ('BAD_DIGEST_'+$key)
    $candidate=Copy-Map $good
    $candidate[$key]=$candidate[$key].ToUpperInvariant()
    # The lab pins are lowercase fixed values, and an uppercase ID cannot pass.
    Expect $candidate $pins 'HOLD_DIGEST_SHAPE' ('NONCANONICAL_CASE_'+$key)
    $candidate=Copy-Map $good
    $candidate[$key]=('e'*$(if($key -ceq 'subjectSha256'){64}else{40}))
    Expect $candidate $pins 'HOLD_PIN_MISMATCH' ('MOVED_ID_'+$key)
    $malformed=Copy-Map $pins
    $malformed[$key]='bad'
    Expect $good $malformed 'HOLD_DIGEST_SHAPE' ('BAD_EXPECTED_'+$key)
}
foreach($key in @('sourceCommit','signerDigest','subjectSha256')){
    $absent=Copy-Map $pins
    [void]$absent.Remove($key)
    Expect $good $absent 'HOLD_EVIDENCE_SHAPE' ('PIN_ABSENT_'+$key)
}
Write-Output ('REDRIX_D0_ATTESTATION_EVIDENCE_HOLD=PASS assertions='+$script:checks)
Write-Output 'REDRIX_D0_ATTESTATION_SIGNATURE_VERIFIED=FALSE'
Write-Output 'REDRIX_D0_ATTESTATION_INDEPENDENT_APPROVAL=FALSE'
Write-Output 'REDRIX_D0_ATTESTATION_PUBLISHER_ACTIVE=FALSE'
Write-Output 'REDRIX_D0_ATTESTATION_PHYSICAL_AUTHORITY=HOLD_SECURITY'
