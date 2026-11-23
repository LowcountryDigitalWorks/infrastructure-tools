#Requires -Version 7.0
<#
.SYNOPSIS
Host2AssignmentD0 - inert, default-disabled profile-to-host assignment DESIGN contract.

.DESCRIPTION
Pure deterministic fail-closed evaluator for a FUTURE OfficePC-exclusive isolated JIT
host assignment. It has NO runtime binding: it cannot dispatch, claim, provision,
register, clean up, or admit any job. It calls no provider, GitHub, network, VM,
runner, service, privilege, or command shell. Every decision is DENY.

The only file I/O is Read-Host2AssignmentD0Contract, which reads the exact inert
fixed fixture shipped beside this module. No caller-supplied path is accepted,
and this non-authoritative read does not establish immutable provenance.

.NOTES
Design pointer: infra #86 comment 7092892405. This is NOT #269 controller admission,
NOT #186 bootstrap authority, NOT #264 disposition, and NOT #86 runtime release.
#>

$ErrorActionPreference = 'Stop'

function Assert-Host2AssignmentD0NoDuplicateKey {
    param([Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element)
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $seen.Add($property.Name)) { throw "DUPLICATE_JSON_KEY:$($property.Name)" }
            Assert-Host2AssignmentD0NoDuplicateKey -Element $property.Value
        }
        return
    }
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-Host2AssignmentD0NoDuplicateKey -Element $item
        }
    }
}

function ConvertFrom-Host2AssignmentD0Json {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $RawJson)
    if ([string]::IsNullOrWhiteSpace($RawJson)) { throw 'D0_JSON_EMPTY' }
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.AllowTrailingCommas = $false
    $options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
    $options.MaxDepth = 32
    $doc = $null
    try {
        $doc = [System.Text.Json.JsonDocument]::Parse($RawJson, $options)
        Assert-Host2AssignmentD0NoDuplicateKey -Element $doc.RootElement
        $obj = ConvertFrom-Json -InputObject $doc.RootElement.GetRawText() -AsHashtable -Depth 32
        if ($null -eq $obj -or $obj -isnot [System.Collections.IDictionary]) { throw 'D0_JSON_NOT_OBJECT' }
        return $obj
    }
    catch {
        if ($_.Exception.Message -like 'DUPLICATE_JSON_KEY:*') { throw 'D0_JSON_REJECTED:DUPLICATE_JSON_KEY' }
        throw 'D0_JSON_REJECTED'
    }
    finally {
        if ($null -ne $doc) { $doc.Dispose() }
    }
}

function Read-Host2AssignmentD0Contract {
    $full = Join-Path $PSScriptRoot 'Host2AssignmentD0.contract.json'
    if (-not [IO.File]::Exists($full)) { throw 'D0_CONTRACT_FILE_MISSING' }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'D0_CONTRACT_REPARSE_POINT' }
    return ConvertFrom-Host2AssignmentD0Json -RawJson ([IO.File]::ReadAllText($full))
}

function Assert-Host2AssignmentD0ExactStringSet {
    param([AllowNull()] $Actual, [string[]] $Expected, [string] $ErrorCode)
    if ($Actual -isnot [array] -or $Actual.Count -ne $Expected.Count) { throw $ErrorCode }
    foreach ($value in $Actual) {
        if ($value -isnot [string] -or $Expected -cnotcontains $value) { throw $ErrorCode }
    }
}

function ConvertTo-Host2AssignmentD0Generation {
    param([AllowNull()] $Value)
    if ($Value -isnot [int] -and $Value -isnot [long]) { return $null }
    if ([long]$Value -lt 0 -or [long]$Value -gt 2147483647) { return $null }
    return [int]$Value
}

function Test-Host2AssignmentD0ContractShape {
    param([Parameter(Mandatory)] [AllowNull()] $Contract)
    if ($null -eq $Contract -or $Contract -isnot [System.Collections.IDictionary]) { throw 'D0_CONTRACT_NOT_OBJECT' }

    $expectedTop = @('allowlist','authority','binding','profiles','promotion','schema','schemaVersion')
    $top = @($Contract.Keys | Sort-Object)
    if (($top -join ',') -cne ($expectedTop -join ',')) { throw 'D0_CONTRACT_TOP_LEVEL_KEYS' }
    if ($Contract['schema'] -cne 'ldw.ci.host2.assignment.d0') { throw 'D0_CONTRACT_SCHEMA' }
    if (($Contract['schemaVersion'] -isnot [int] -and $Contract['schemaVersion'] -isnot [long]) -or $Contract['schemaVersion'] -ne 1) { throw 'D0_CONTRACT_SCHEMA_VERSION' }
    if ($Contract['binding'] -cne 'NONE_RUNTIME_INERT_DESIGN_FIXTURE') { throw 'D0_CONTRACT_BINDING' }
    if ($Contract['authority'] -isnot [string] -or $Contract['authority'] -cne 'NOT_AUTHORITATIVE_NO_DISPATCH_NO_CLAIM_NO_PROVISION') { throw 'D0_CONTRACT_AUTHORITY' }
    if ($Contract['promotion'] -isnot [string] -or $Contract['promotion'] -cne 'DISABLED_NO_AUTOMATIC_PROMOTION') { throw 'D0_CONTRACT_PROMOTION' }

    $allow = $Contract['allowlist']
    if ($null -eq $allow -or $allow -isnot [System.Collections.IDictionary]) { throw 'D0_ALLOWLIST_MISSING' }
    $expectedAllow = @('hostIds','legacyHostIds','legacyHostLabels','nonMatchingRunnerClasses','operations','profileIds','receiptKinds','runnerClasses')
    $allowKeys = @($allow.Keys | Sort-Object)
    if (($allowKeys -join ',') -cne ($expectedAllow -join ',')) { throw 'D0_ALLOWLIST_KEYS' }

    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['hostIds'] -Expected @('officepc') -ErrorCode 'D0_ALLOWLIST_HOST_IDS'
    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['legacyHostIds'] -Expected @('ldw01') -ErrorCode 'D0_ALLOWLIST_LEGACY_HOST_IDS'
    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['legacyHostLabels'] -Expected @('ldw01') -ErrorCode 'D0_ALLOWLIST_LEGACY_HOST_LABELS'
    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['nonMatchingRunnerClasses'] -Expected @('trusted-private-persistent','host1-persistent-ldw01-ci-01') -ErrorCode 'D0_ALLOWLIST_NONMATCHING_RUNNER_CLASSES'
    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['operations'] -Expected @('CLAIM','START','CLEANUP') -ErrorCode 'D0_ALLOWLIST_OPERATIONS'
    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['profileIds'] -Expected @('ci10-accepted-synthetic','ci10-bo-secret-scan','ci10-royal-dashboard-deploy','ci10-royal-dashboard-release-gate-pr') -ErrorCode 'D0_ALLOWLIST_PROFILE_IDS'
    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['receiptKinds'] -Expected @('D0_SYNTHETIC_DESIGN_RECEIPT') -ErrorCode 'D0_ALLOWLIST_RECEIPT_KINDS'
    Assert-Host2AssignmentD0ExactStringSet -Actual $allow['runnerClasses'] -Expected @('isolated-jit-ephemeral') -ErrorCode 'D0_ALLOWLIST_RUNNER_CLASSES'
    $pids = @($allow['profileIds'])

    $profiles = @($Contract['profiles'])
    if ($profiles.Count -ne $pids.Count) { throw 'D0_PROFILE_COUNT' }
    $expectedEntry = @('enabled','fallbackHost','generation','primaryHost','profileId','receipt','requiredProvenance')
    $seenIds = @()
    foreach ($entry in $profiles) {
        if ($null -eq $entry -or $entry -isnot [System.Collections.IDictionary]) { throw 'D0_PROFILE_ENTRY_TYPE' }
        $keys = @($entry.Keys | Sort-Object)
        if (($keys -join ',') -cne ($expectedEntry -join ',')) { throw 'D0_PROFILE_KEYS' }
        $id = [string]$entry['profileId']
        if ($pids -cnotcontains $id) { throw 'D0_PROFILE_ID_NOT_ALLOWLISTED' }
        $seenIds += $id
        if ($entry['enabled'] -isnot [bool] -or $entry['enabled'] -ne $false) { throw 'D0_PROFILE_ENABLED' }
        if ($entry['primaryHost'] -cne 'officepc') { throw 'D0_PROFILE_PRIMARY_HOST' }
        if ($null -ne $entry['fallbackHost']) { throw 'D0_PROFILE_FALLBACK' }
        if (($entry['generation'] -isnot [int] -and $entry['generation'] -isnot [long]) -or $entry['generation'] -ne 0) { throw 'D0_PROFILE_GENERATION' }
        if ($null -ne $entry['receipt']) { throw 'D0_PROFILE_RECEIPT' }
        if ($null -ne $entry['requiredProvenance']) { throw 'D0_PROFILE_PROVENANCE' }
    }
    if (@($seenIds | Select-Object -Unique).Count -ne $seenIds.Count) { throw 'D0_DUPLICATE_FIXTURE_PROFILE' }

    $serialized = ConvertTo-Json -InputObject $Contract -Depth 32 -Compress
    if ($serialized.Contains('*')) { throw 'D0_WILDCARD_PRESENT' }
    if ($serialized -imatch 'password|credential|api[_-]?key|secret[_-]?(value|key|token)|https?://|10\.\d+\.\d+\.\d+|192\.168\.') { throw 'D0_SENSITIVE_OR_ADDRESS_LITERAL' }
    return $true
}

function Get-Host2AssignmentD0Decision {
    param(
        [Parameter(Mandatory)] [AllowNull()] $Contract,
        [AllowNull()] [string] $ProfileId,
        [AllowNull()] [string] $CandidateHost = 'officepc',
        [AllowNull()] [string] $Operation = 'CLAIM',
        [AllowNull()] $ActiveControllerCount = 1,
        [AllowNull()] [string[]] $ActiveHostIds = @('officepc'),
        [AllowNull()] [string[]] $Labels = @(),
        [AllowNull()] [string] $RunnerClass = 'isolated-jit-ephemeral',
        [AllowNull()] $Receipt = $null,
        [AllowNull()] $Provenance = $null,
        [AllowNull()] $ExpectedGeneration = 0
    )
    $deny = {
        param([string] $Code)
        [pscustomobject]@{
            decision               = 'DENY'
            reason                 = $Code
            binding                = 'NONE_RUNTIME_INERT_DESIGN_FIXTURE'
            claimIssued            = $false
            provisioningAuthorized = $false
            queueMutated           = $false
            authority              = 'NOT_AUTHORITATIVE'
        }
    }

    try { Test-Host2AssignmentD0ContractShape -Contract $Contract | Out-Null }
    catch { return & $deny 'CONTRACT_SHAPE_INVALID' }
    $allow = $Contract['allowlist']
    $expected = ConvertTo-Host2AssignmentD0Generation -Value $ExpectedGeneration
    if ($null -eq $expected) { return & $deny 'GENERATION_MALFORMED' }
    $controllerCount = ConvertTo-Host2AssignmentD0Generation -Value $ActiveControllerCount
    if ($null -eq $controllerCount) { return & $deny 'CONTROLLER_COUNT_MALFORMED' }

    if ($Operation -cnotin @($allow['operations'])) { return & $deny 'OPERATION_NOT_ALLOWED' }
    if ($RunnerClass -cnotin @($allow['runnerClasses'])) { return & $deny 'RUNNER_CLASS_MISMATCH' }
    if ([string]::IsNullOrEmpty($ProfileId)) { return & $deny 'PROFILE_MISSING' }
    if ($ProfileId -cnotin @($allow['profileIds'])) { return & $deny 'PROFILE_UNKNOWN' }
    $matches = @($Contract['profiles'] | Where-Object { $_['profileId'] -ceq $ProfileId })
    if ($matches.Count -ne 1) { return & $deny 'PROFILE_UNASSIGNED' }
    $entry = $matches[0]

    $spoofed = @($Labels | Where-Object { @($allow['legacyHostLabels']) -ccontains $_ })
    if ($spoofed.Count -gt 0) { return & $deny 'LEGACY_HOST_LABEL_SPOOF' }

    if ($Operation -ceq 'CLEANUP') {
        if ($CandidateHost -cne 'officepc') { return & $deny 'CROSS_HOST_CLEANUP_REFUSED' }
        if ($null -eq $Receipt -or $Receipt -isnot [System.Collections.IDictionary] -or [string]$Receipt['hostId'] -cne $CandidateHost) {
            return & $deny 'CROSS_HOST_CLEANUP_REFUSED'
        }
        $legacyActive = @($ActiveHostIds | Where-Object { @($allow['legacyHostIds']) -ccontains $_ })
        if ($legacyActive.Count -gt 0) { return & $deny 'CROSS_HOST_CLEANUP_REFUSED' }
    }

    if ($controllerCount -gt 1) { return & $deny 'DUPLICATE_CONTROLLER' }
    if ($controllerCount -lt 1) { return & $deny 'CONTROLLER_MISSING' }
    if (@($ActiveHostIds).Count -gt 1) { return & $deny 'MULTIPLE_ACTIVE_HOSTS' }
    $foreignActive = @($ActiveHostIds | Where-Object { $_ -cnotin @($allow['hostIds']) })
    if ($foreignActive.Count -gt 0) { return & $deny 'WRONG_HOST' }
    if ([string]::IsNullOrEmpty($CandidateHost) -or $CandidateHost -cnotin @($allow['hostIds'])) { return & $deny 'WRONG_HOST' }

    if ($null -eq $Receipt) { return & $deny 'RECEIPT_MISSING' }
    if ($Receipt -isnot [System.Collections.IDictionary]) { return & $deny 'RECEIPT_MALFORMED' }
    foreach ($key in @('kind','hostId','generation','blobSha256','issuedBy')) {
        if ($Receipt.Keys -cnotcontains $key) { return & $deny 'RECEIPT_MALFORMED' }
    }
    if ([string]$Receipt['kind'] -cnotin @($allow['receiptKinds'])) { return & $deny 'RECEIPT_MALFORMED' }
    if ([string]$Receipt['hostId'] -cne $CandidateHost) { return & $deny 'RECEIPT_HOST_MISMATCH' }
    $receiptGen = ConvertTo-Host2AssignmentD0Generation -Value $Receipt['generation']
    if ($null -eq $receiptGen) { return & $deny 'RECEIPT_MALFORMED' }
    if ($receiptGen -ne $expected) { return & $deny 'GENERATION_STALE' }

    if ($null -eq $Provenance) { return & $deny 'PROVENANCE_MISSING' }
    if ($Provenance -isnot [System.Collections.IDictionary]) { return & $deny 'PROVENANCE_MALFORMED' }
    foreach ($key in @('generation','commitSha','treeSha','blobSha256','issuer')) {
        if ($Provenance.Keys -cnotcontains $key) { return & $deny 'PROVENANCE_MALFORMED' }
    }
    $provenanceGen = ConvertTo-Host2AssignmentD0Generation -Value $Provenance['generation']
    if ($null -eq $provenanceGen) { return & $deny 'PROVENANCE_MALFORMED' }
    if ($provenanceGen -ne $expected) { return & $deny 'GENERATION_STALE' }
    if ([string]$Provenance['blobSha256'] -cne [string]$Receipt['blobSha256']) { return & $deny 'RECEIPT_PROVENANCE_DRIFT' }
    $entryGen = ConvertTo-Host2AssignmentD0Generation -Value $entry['generation']
    if ($null -eq $entryGen -or $entryGen -ne $expected) { return & $deny 'GENERATION_STALE' }

    return & $deny 'ASSIGNMENT_DISABLED'
}

Export-ModuleMember -Function ConvertFrom-Host2AssignmentD0Json, Read-Host2AssignmentD0Contract, Test-Host2AssignmentD0ContractShape, Get-Host2AssignmentD0Decision
