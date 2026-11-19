#Requires -Version 5.1
# SOURCE_ONLY #186 D0: pure, non-authorizing shape checks on hypothetical evidence.
# NEVER runs gh, GitHub, Task Scheduler, or privileged Windows operations.
Set-StrictMode -Version Latest

$script:FixedRepository = 'LowcountryDigitalWorks/infrastructure-tools'
$script:FixedRef = 'refs/heads/main'
$script:FixedSigner = 'LowcountryDigitalWorks/infrastructure-tools/.github/workflows/redrix-d0-source-provenance.yml'
$script:FixedSubject = 'redrix-d0-source-probe.tar'
$script:FixedPredicate = 'https://slsa.dev/provenance/v1'

function Test-RedrixD0EvidenceHold {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowNull()][object]$Evidence,
        [Parameter(Mandatory=$true)][AllowNull()][object]$ResearchOnlyExpected
    )
    # The caller can propose expected SHA bytes, so even a positive comparison
    # is NEVER independent acceptance, a signed verification, or physical authority.
    if ($Evidence -isnot [System.Collections.IDictionary] -or
        $ResearchOnlyExpected -isnot [System.Collections.IDictionary]) {
        return 'HOLD_EVIDENCE_SHAPE'
    }
    $fields = @('repository','sourceRef','sourceCommit','signerWorkflow',
        'signerDigest','subjectName','subjectSha256','predicateType','runner')
    $pins = @('sourceCommit','signerDigest','subjectSha256')
    if ($Evidence.Count -ne $fields.Count -or
        $ResearchOnlyExpected.Count -ne $pins.Count) {
        return 'HOLD_EVIDENCE_SHAPE'
    }
    foreach ($name in $fields) {
        if (-not $Evidence.Contains($name) -or $Evidence[$name] -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$Evidence[$name])) {
            return 'HOLD_EVIDENCE_SHAPE'
        }
    }
    foreach ($name in $pins) {
        if (-not $ResearchOnlyExpected.Contains($name) -or
            $ResearchOnlyExpected[$name] -isnot [string]) {
            return 'HOLD_ACCEPTED_PIN_ABSENT'
        }
    }
    if ($Evidence['repository'] -cne $script:FixedRepository -or
        $Evidence['sourceRef'] -cne $script:FixedRef -or
        $Evidence['signerWorkflow'] -cne $script:FixedSigner -or
        $Evidence['subjectName'] -cne $script:FixedSubject -or
        $Evidence['predicateType'] -cne $script:FixedPredicate -or
        $Evidence['runner'] -cne 'github-hosted') {
        return 'HOLD_SOURCE_OR_WORKFLOW_IDENTITY'
    }
    foreach ($name in @('sourceCommit','signerDigest')) {
        $value = [string]$Evidence[$name]
        $expected = [string]$ResearchOnlyExpected[$name]
        if ($value -cnotmatch '^[a-f0-9]{40}$' -or
            $expected -cnotmatch '^[a-f0-9]{40}$') {
            return 'HOLD_DIGEST_SHAPE'
        }
        if ($value -cne $expected) { return 'HOLD_PIN_MISMATCH' }
    }
    $subject = [string]$Evidence['subjectSha256']
    $expectedSubject = [string]$ResearchOnlyExpected['subjectSha256']
    if ($subject -cnotmatch '^[a-f0-9]{64}$' -or
        $expectedSubject -cnotmatch '^[a-f0-9]{64}$') {
        return 'HOLD_DIGEST_SHAPE'
    }
    if ($subject -cne $expectedSubject) { return 'HOLD_PIN_MISMATCH' }

    # Even perfectly shaped, matching input can be forged. This function does
    # not accept user-asserted signatureVerified=true or predicate data.
    # A future independent, installed verifier must cryptographically validate
    # certificate identity, signer source, artifact SHA and an external policy.
    return 'HOLD_CRYPTOGRAPHIC_AND_INDEPENDENT_ACCEPTANCE_ABSENT'
}

Export-ModuleMember -Function Test-RedrixD0EvidenceHold
