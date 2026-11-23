#Requires -Version 7.0
<#
Synthetic, deterministic negative tests for the inert D0 host-assignment DESIGN contract.
No live provider, GitHub, network, VM, runner, service, privilege or command shell.
No files are written; the only read is the exact inert fixture via the module.
#>
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "ASSERT_FAILED:$Message" }
}

function Assert-Deny {
    param($Decision, [string] $Reason, [string] $Label)
    Assert-True ($decision.decision -ceq 'DENY') "$Label must deny"
    Assert-True ($decision.reason -ceq $Reason) "$Label expected $Reason got $($decision.reason)"
    Assert-True ($decision.claimIssued -eq $false) "$Label no claim"
    Assert-True ($decision.provisioningAuthorized -eq $false) "$Label no provisioning"
    Assert-True ($decision.queueMutated -eq $false) "$Label no queue mutation"
}

function Assert-Throws {
    param([scriptblock] $Block, [string] $Pattern, [string] $Label)
    $matched = $false
    try { & $Block } catch { $matched = $_.Exception.Message -match $Pattern }
    Assert-True $matched "$Label expected throw $Pattern"
}

$module = Join-Path (Split-Path -Parent $PSScriptRoot) 'Host2AssignmentD0.psm1'
Import-Module -Name $module -Force -ErrorAction Stop

$script:contract = Read-Host2AssignmentD0Contract
$script:receipt = [ordered]@{
    blobSha256 = ('0' * 63 + '1')
    generation = 0
    hostId     = 'officepc'
    issuedBy   = 'SYNTHETIC_TEST_ONLY'
    kind       = 'D0_SYNTHETIC_DESIGN_RECEIPT'
}
$script:provenance = [ordered]@{
    blobSha256 = ('0' * 63 + '1')
    commitSha  = ('0' * 63 + '2')
    generation = 0
    issuer     = 'SYNTHETIC_TEST_ONLY'
    treeSha    = ('0' * 63 + '3')
}

function New-D0Request {
    param([hashtable] $Override = @{})
    $base = @{
        Contract             = $script:contract
        ProfileId            = 'ci10-accepted-synthetic'
        CandidateHost        = 'officepc'
        Operation            = 'CLAIM'
        ActiveControllerCount = 1
        ActiveHostIds        = @('officepc')
        Labels               = @('self-hosted', 'Linux', 'X64', 'ldw-ephemeral', 'ldw-isolated', 'security-isolated')
        RunnerClass          = 'isolated-jit-ephemeral'
        Receipt              = $script:receipt
        Provenance           = $script:provenance
        ExpectedGeneration   = 0
    }
    foreach ($key in $Override.Keys) { $base[$key] = $Override[$key] }
    return $base
}

function Decide {
    param([hashtable] $Override = @{})
    $request = New-D0Request -Override $Override
    return Get-Host2AssignmentD0Decision @request
}

# 1. Fixture is strict, well formed and fully inert.
Assert-True (Test-Host2AssignmentD0ContractShape -Contract $script:contract) 'fixture shape'
Assert-True ($script:contract.profiles.Count -eq 4) 'four profiles'
foreach ($entry in $script:contract.profiles) {
    Assert-True ($entry.enabled -eq $false) 'every profile disabled'
    Assert-True ($entry.primaryHost -ceq 'officepc') 'officepc only in disabled fixture'
    Assert-True ($null -eq $entry.fallbackHost) 'fallback null'
    Assert-True ($null -eq $entry.receipt -and $null -eq $entry.requiredProvenance) 'no embedded receipt/provenance'
}

# 2. Even a fully consistent, well-provenanced request cannot be admitted: default disabled.
$good = Decide
Assert-Deny $good 'ASSIGNMENT_DISABLED' 'default disabled no admission'
Assert-True ($good.binding -ceq 'NONE_RUNTIME_INERT_DESIGN_FIXTURE') 'inert binding echoed'
Assert-True ($good.authority -ceq 'NOT_AUTHORITATIVE') 'not authoritative'

# 3. Duplicate controller / duplicate active host.
Assert-Deny (Decide @{ ActiveControllerCount = 2 }) 'DUPLICATE_CONTROLLER' 'duplicate controller'
Assert-Deny (Decide @{ ActiveHostIds = @('officepc', 'ldw01') }) 'MULTIPLE_ACTIVE_HOSTS' 'multiple active hosts'
Assert-Deny (Decide @{ ActiveControllerCount = 0 }) 'CONTROLLER_MISSING' 'no controller'

# 4. Wrong host, unknown/missing profile.
Assert-Deny (Decide @{ CandidateHost = 'ldw01' }) 'WRONG_HOST' 'wrong host'
Assert-Deny (Decide @{ ProfileId = 'ci10-not-a-profile' }) 'PROFILE_UNKNOWN' 'unknown profile'
Assert-Deny (Decide @{ ProfileId = '' }) 'PROFILE_MISSING' 'missing profile'

# 5. Absent / malformed / drifting receipt and provenance.
Assert-Deny (Decide @{ Receipt = $null }) 'RECEIPT_MISSING' 'absent receipt'
Assert-Deny (Decide @{ Receipt = @{ kind = 'D0_SYNTHETIC_DESIGN_RECEIPT' } }) 'RECEIPT_MALFORMED' 'malformed receipt'
Assert-Deny (Decide @{ Provenance = $null }) 'PROVENANCE_MISSING' 'absent provenance'
Assert-Deny (Decide @{ Provenance = @{ generation = 0 } }) 'PROVENANCE_MALFORMED' 'malformed provenance'
Assert-Deny (Decide @{ ExpectedGeneration = 1 }) 'GENERATION_STALE' 'stale generation'
$driftedProvenance = [ordered]@{
    blobSha256 = ('0' * 63 + '9')
    commitSha  = ('0' * 63 + '2')
    generation = 0
    issuer     = 'SYNTHETIC_TEST_ONLY'
    treeSha    = ('0' * 63 + '3')
}
Assert-Deny (Decide @{ Provenance = $driftedProvenance }) 'RECEIPT_PROVENANCE_DRIFT' 'provenance drift'

# 6. Legacy Host1 label spoof and persistent-runner class mismatch.
Assert-Deny (Decide @{ Labels = @('self-hosted', 'ldw01', 'ldw-isolated') }) 'LEGACY_HOST_LABEL_SPOOF' 'old host label spoof'
Assert-Deny (Decide @{ RunnerClass = 'trusted-private-persistent' }) 'RUNNER_CLASS_MISMATCH' 'persistent runner class'
Assert-Deny (Decide @{ RunnerClass = 'host1-persistent-ldw01-ci-01' }) 'RUNNER_CLASS_MISMATCH' 'host1 persistent baseline class'

# 7. Cross-host cleanup refuses in both directions.
$host1Receipt = [ordered]@{
    blobSha256 = ('0' * 63 + '1')
    generation = 0
    hostId     = 'ldw01'
    issuedBy   = 'SYNTHETIC_TEST_ONLY'
    kind       = 'D0_SYNTHETIC_DESIGN_RECEIPT'
}
Assert-Deny (Decide @{ Operation = 'CLEANUP'; Receipt = $host1Receipt }) 'CROSS_HOST_CLEANUP_REFUSED' 'cleanup with host1 receipt'
Assert-Deny (Decide @{ Operation = 'CLEANUP'; CandidateHost = 'ldw01'; Receipt = $host1Receipt }) 'CROSS_HOST_CLEANUP_REFUSED' 'cleanup targeting host1'

# 8. Enabling a profile or mutating the allowlist in memory fails shape validation.
$mutated = Read-Host2AssignmentD0Contract
@($mutated.profiles)[0]['enabled'] = $true
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $mutated } 'D0_PROFILE_ENABLED' 'enabled profile refused'
$mutated2 = Read-Host2AssignmentD0Contract
@($mutated2.profiles)[1]['fallbackHost'] = 'ldw01'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $mutated2 } 'D0_PROFILE_FALLBACK' 'fallback refused'
$mutated3 = Read-Host2AssignmentD0Contract
$mutated3['allowlist']['profileIds'] += 'ci10-extra'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $mutated3 } 'D0_ALLOWLIST_PROFILE_IDS|D0_PROFILE_COUNT' 'extra profile refused'

# 9. Strict JSON: duplicate keys, trailing commas and comments rejected without file I/O.
Assert-Throws { ConvertFrom-Host2AssignmentD0Json -RawJson '{"schema":"a","schema":"b"}' } 'DUPLICATE_JSON_KEY' 'duplicate json key'
Assert-Throws { ConvertFrom-Host2AssignmentD0Json -RawJson '{"schema":"a",}' } 'D0_JSON_REJECTED' 'trailing comma'
Assert-Throws { ConvertFrom-Host2AssignmentD0Json -RawJson '{/* c */"schema":"a"}' } 'D0_JSON_REJECTED' 'comment in json'
Assert-True ((ConvertFrom-Host2AssignmentD0Json -RawJson '{"a":1}')['a'] -eq 1) 'strict simple json parse'


# 9b. Typed and malformed evidence fail-closed negatives.
$badAuthority = Read-Host2AssignmentD0Contract
$badAuthority['authority'] = 'NOT_AUTHORITATIVE_BUT_AUTHORITATIVE'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $badAuthority } 'D0_CONTRACT_AUTHORITY' 'exact authority'
$badPromotion = Read-Host2AssignmentD0Contract
$badPromotion['promotion'] = 'DISABLED_BUT_ENABLED'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $badPromotion } 'D0_CONTRACT_PROMOTION' 'exact promotion'
$badSchema = Read-Host2AssignmentD0Contract
$badSchema['schemaVersion'] = '1'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $badSchema } 'D0_CONTRACT_SCHEMA_VERSION' 'no numeric string schema'
$badBoolean = Read-Host2AssignmentD0Contract
$badBoolean['profiles'][0]['enabled'] = 0
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $badBoolean } 'D0_PROFILE_ENABLED' 'strict disabled boolean'
$badFixtureGen = Read-Host2AssignmentD0Contract
$badFixtureGen['profiles'][0]['generation'] = '0'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $badFixtureGen } 'D0_PROFILE_GENERATION' 'strict fixture generation'
$badOps = Read-Host2AssignmentD0Contract
$badOps['allowlist']['operations'] += 'DISPATCH'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $badOps } 'D0_ALLOWLIST_OPERATIONS' 'closed operations'
$badRunner = Read-Host2AssignmentD0Contract
$badRunner['allowlist']['runnerClasses'] += 'trusted-private-persistent'
Assert-Throws { Test-Host2AssignmentD0ContractShape -Contract $badRunner } 'D0_ALLOWLIST_RUNNER_CLASSES' 'closed runners'
Assert-True (-not (Get-Command Read-Host2AssignmentD0Contract).Parameters.ContainsKey('Path')) 'no arbitrary fixture path parameter'
$badGenerations = @(
    @{ label='text'; value='abc' },
    @{ label='fraction'; value=1.5 },
    @{ label='array'; value=@() },
    @{ label='null'; value=$null },
    @{ label='overflow'; value=[decimal]99999999999999999999 }
)
foreach ($case in $badGenerations) {
    $receipt = [ordered]@{}
    foreach ($key in $script:receipt.Keys) { $receipt[$key] = $script:receipt[$key] }
    $receipt['generation'] = $case.value
    Assert-Deny (Decide @{ Receipt=$receipt }) 'RECEIPT_MALFORMED' "invalid receipt $($case.label)"
    $provenance = [ordered]@{}
    foreach ($key in $script:provenance.Keys) { $provenance[$key] = $script:provenance[$key] }
    $provenance['generation'] = $case.value
    Assert-Deny (Decide @{ Provenance=$provenance }) 'PROVENANCE_MALFORMED' "invalid provenance $($case.label)"
    Assert-Deny (Decide @{ ExpectedGeneration=$case.value }) 'GENERATION_MALFORMED' "invalid expected $($case.label)"
}
Assert-Deny (Decide @{ ActiveControllerCount='abc' }) 'CONTROLLER_COUNT_MALFORMED' 'invalid controller count'

# 10. Static inertness proof: no runtime-capable cmdlet or shell token in the module.
$moduleText = [IO.File]::ReadAllText($module)
foreach ($bad in @(
        'Invoke-Expression', 'Start-Process', 'Invoke-WebRequest', 'Invoke-RestMethod',
        'Get-VM', 'New-VM', 'Remove-VM', 'Get-CimInstance', 'New-Item', 'Remove-Item',
        'Set-Content', '-EncodedCommand', 'cmd /c', 'bash -c', 'Start-Service', 'Set-Service'
    )) {
    Assert-True (-not $moduleText.Contains($bad)) "no runtime token $bad"
}

Write-Output 'HOST2_ASSIGNMENT_D0_CONTRACTS=PASS'
