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
fixture shipped beside this module (or an explicitly supplied path inside that same
folder). No other path is reachable.

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
        throw "D0_JSON_REJECTED:$($_.Exception.Message)"
    }
    finally {
        if ($null -ne $doc) { $doc.Dispose() }
    }
}

function Read-Host2AssignmentD0Contract {
    param([AllowNull()] [string] $Path)
    $folder = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Join-Path $folder 'Host2AssignmentD0.contract.json' }
    $allowedRoot = [IO.Path]::GetFullPath($folder)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($allowedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'D0_CONTRACT_PATH_OUTSIDE_FOLDER'
    }
    if (-not [IO.File]::Exists($full)) { throw 'D0_CONTRACT_FILE_MISSING' }
    $raw = [IO.File]::ReadAllText($full)
    return ConvertFrom-Host2AssignmentD0Json -RawJson $raw
}

function Test-Host2AssignmentD0ContractShape {
    param([Parameter(Mandatory)] [AllowNull()] $Contract)
    if ($null -eq $Contract -or $Contract -isnot [System.Collections.IDictionary]) { throw 'D0_CONTRACT_NOT_OBJECT' }

    $expectedTop = @('allowlist','authority','binding','profiles','promotion','schema','schemaVersion')
    $top = @($Contract.Keys | Sort-Object)
    if (($top -join ',') -cne ($expectedTop -join ',')) { throw 'D0_CONTRACT_TOP_LEVEL_KEYS' }
    if ($Contract['schema'] -cne 'ldw.ci.host2.assignment.d0') { throw 'D0_CONTRACT_SCHEMA' }
    if ($Contract['schemaVersion'] -ne 1) { throw 'D0_CONTRACT_SCHEMA_VERSION' }
    if ($Contract['binding'] -cne 'NONE_RUNTIME_INERT_DESIGN_FIXTURE') { throw 'D0_CONTRACT_BINDING' }
    if ([string]$Contract['authority'] -cnotmatch 'NOT_AUTHORITATIVE') { throw 'D0_CONTRACT_AUTHORITY' }
    if ([string]$Contract['promotion'] -cnotmatch 'DISABLED') { throw 'D0_CONTRACT_PROMOTION' }

    $allow = $Contract['allowlist']
    if ($null -eq $allow -or $allow -isnot [System.Collections.IDictionary]) { throw 'D0_ALLOWLIST_MISSING' }
    $expectedAllow = @('hostIds','legacyHostIds','legacyHostLabels','nonMatchingRunnerClasses','operations','profileIds','receiptKinds','runnerClasses')
    $allowKeys = @($allow.Keys | Sort-Object)
    if (($allowKeys -join ',') -cne ($expectedAllow -join ',')) { throw 'D0_ALLOWLIST_KEYS' }

    $hosts = @($allow['hostIds'])
    if ($hosts.Count -ne 1 -or $hosts[0] -cne 'officepc') { throw 'D0_ALLOWLIST_HOST_IDS' }
    if (@($allow['legacyHostIds']) -cnotcontains 'ldw01') { throw 'D0_ALLOWLIST_LEGACY_HOST_IDS' }
    if (@($allow['legacyHostLabels']) -cnotcontains 'ldw01') { throw 'D0_ALLOWLIST_LEGACY_HOST_LABELS' }
    if (@($allow['runnerClasses']) -ccontains 'trusted-private-persistent') { throw 'D0_ALLOWLIST_RUNNER_CLASS_MIXED' }
    if (@($allow['operations']) -ccontains 'DISPATCH') { throw 'D0_ALLOWLIST_OPERATION' }

    $pids = @($allow['profileIds'])
    if ($pids.Count -ne 4) { throw 'D0_ALLOWLIST_PROFILE_COUNT' }
    if (@($pids | Select-Object -Unique).Count -ne $pids.Count) { throw 'D0_DUPLICATE_PROFILE_ID' }

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
        if ($entry['enabled'] -ne $false) { throw 'D0_PROFILE_ENABLED' }
        if ($entry['primaryHost'] -cne 'officepc') { throw 'D0_PROFILE_PRIMARY_HOST' }
        if ($null -ne $entry['fallbackHost']) { throw 'D0_PROFILE_FALLBACK' }
        if ($entry['generation'] -ne 0) { throw 'D0_PROFILE_GENERATION' }
        if ($null -ne $entry['receipt']) { throw 'D0_PROFILE_RECEIPT' }
        if ($null -ne $entry['requiredProvenance']) { throw 'D0_PROFILE_PROVENANCE' }
    }
    if (@($seenIds | Select-Object -Unique).Count -ne $seenIds.Count) { throw 'D0_DUPLICATE_FIXTURE_PROFILE' }

    $serialized = ConvertTo-Json -InputObject $Contract -Depth 32 -Compress
    if ($serialized.Contains('*')) { throw 'D0_WILDCARD_PRESENT' }
    if ($serialized -cmatch 'password|credential|api[_-]?key|secret[_-]?(value|key|token)|https?://|10\.\d+\.\d+\.\d+|192\.168\.') { throw 'D0_SENSITIVE_OR_ADDRESS_LITERAL' }
    return $true
}

function Get-Host2AssignmentD0Decision {
    param(
        [Parameter(Mandatory)] [AllowNull()] $Contract,
        [AllowNull()] [string] $ProfileId,
        [AllowNull()] [string] $CandidateHost = 'officepc',
        [AllowNull()] [string] $Operation = 'CLAIM',
        [AllowNull()] [int] $ActiveControllerCount = 1,
        [AllowNull()] [string[]] $ActiveHostIds = @('officepc'),
        [AllowNull()] [string[]] $Labels = @(),
        [AllowNull()] [string] $RunnerClass = 'isolated-jit-ephemeral',
        [AllowNull()] $Receipt = $null,
        [AllowNull()] $Provenance = $null,
        [AllowNull()] [int] $ExpectedGeneration = 0
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

    if ($ActiveControllerCount -gt 1) { return & $deny 'DUPLICATE_CONTROLLER' }
    if ($ActiveControllerCount -lt 1) { return & $deny 'CONTROLLER_MISSING' }
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
    if ([int]$Receipt['generation'] -ne $ExpectedGeneration) { return & $deny 'GENERATION_STALE' }

    if ($null -eq $Provenance) { return & $deny 'PROVENANCE_MISSING' }
    if ($Provenance -isnot [System.Collections.IDictionary]) { return & $deny 'PROVENANCE_MALFORMED' }
    foreach ($key in @('generation','commitSha','treeSha','blobSha256','issuer')) {
        if ($Provenance.Keys -cnotcontains $key) { return & $deny 'PROVENANCE_MALFORMED' }
    }
    if ([int]$Provenance['generation'] -ne $ExpectedGeneration) { return & $deny 'GENERATION_STALE' }
    if ([string]$Provenance['blobSha256'] -cne [string]$Receipt['blobSha256']) { return & $deny 'RECEIPT_PROVENANCE_DRIFT' }
    if ([int]$entry['generation'] -ne $ExpectedGeneration) { return & $deny 'GENERATION_STALE' }

    return & $deny 'ASSIGNMENT_DISABLED'
}

Export-ModuleMember -Function ConvertFrom-Host2AssignmentD0Json, Read-Host2AssignmentD0Contract, Test-Host2AssignmentD0ContractShape, Get-Host2AssignmentD0Decision
