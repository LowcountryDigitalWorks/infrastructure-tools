[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$deployRoot = Split-Path -Parent $PSScriptRoot
$workerPath = Join-Path $deployRoot 'Invoke-CiJitControlTask.ps1'
$workerSource = Get-Content -LiteralPath $workerPath -Raw
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($workerSource,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw "ASSERTION FAILED: worker parse errors = $($errors.Count)" }

$script:Assertions = 0
function Assert-True([bool]$Condition,[string]$Message) {
    $script:Assertions++
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Get-FunctionAst([string]$Name) {
    $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name
    },$false)
}

$getOutputValueAst = Get-FunctionAst 'Get-OutputValue'
$resolveFailureAst = Get-FunctionAst 'Resolve-RecoverFailureReason'
$invokeDispatcherAst = Get-FunctionAst 'Invoke-DispatcherMode'
Assert-True ($null -ne $getOutputValueAst) 'Get-OutputValue must remain discoverable'
Assert-True ($null -ne $resolveFailureAst) 'mode-aware bounded dispatcher failure resolver must remain discoverable'
Assert-True ($null -ne $invokeDispatcherAst) 'Invoke-DispatcherMode must remain discoverable'

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('ldw-ci-jit-discover-classification-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    & {
        param(
            [string]$GetOutputValueSource,
            [string]$ResolveFailureSource,
            [string]$InvokeDispatcherSource,
            [string]$FixtureRoot
        )

        . ([scriptblock]::Create($GetOutputValueSource))
        . ([scriptblock]::Create($ResolveFailureSource))
        . ([scriptblock]::Create($InvokeDispatcherSource))

        $ManifestSha = 'a' * 64
        $Commit = 'b' * 40
        $Tree = 'c' * 40
        $dispatcher = Join-Path $FixtureRoot 'dispatcher.ps1'
        $script:FixtureChildResult = $null
        function Invoke-Child([string]$Path,[string[]]$Arguments) { $script:FixtureChildResult }

        function Set-FixtureResult(
            [int]$ExitCode,
            [string[]]$Lines,
            [Nullable[bool]]$ClassificationInvalid = $false,
            [switch]$OmitInvalidMarker
        ) {
            if ($OmitInvalidMarker) {
                $script:FixtureChildResult = [pscustomobject]@{ ExitCode=$ExitCode; Lines=$Lines }
            } else {
                $script:FixtureChildResult = [pscustomobject]@{ ExitCode=$ExitCode; Lines=$Lines; ClassificationInvalid=[bool]$ClassificationInvalid }
            }
        }

        Assert-True ((Resolve-RecoverFailureReason @('CLASSIFICATION=API_READ_FAILED') Discover) -ceq 'QUEUE_UNAVAILABLE') 'Discover API read failure must map to QUEUE_UNAVAILABLE'
        Assert-True ((Resolve-RecoverFailureReason @('CLASSIFICATION=PREFLIGHT_OWNER_UNTRUSTED') Discover) -ceq 'PROVENANCE_MISMATCH') 'Discover provenance failure must map to PROVENANCE_MISMATCH'
        Assert-True ((Resolve-RecoverFailureReason @('CLASSIFICATION=DISPATCHER_BUSY_OR_LOCK_UNCERTAIN') Discover) -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'Discover dispatcher-lock uncertainty must map to LOCK_OR_RESIDUE_UNCERTAIN'
        Assert-True ((Resolve-RecoverFailureReason @('CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN') Discover) -ceq 'FAILED') 'Recover-only classification must not widen Discover diagnostics'
        Assert-True ((Resolve-RecoverFailureReason @('CLASSIFICATION=FUTURE_UNKNOWN_CLASS') Discover) -ceq 'FAILED') 'Unknown Discover classification must remain FAILED'
        Assert-True ((Resolve-RecoverFailureReason @() Discover) -ceq 'FAILED') 'Missing Discover classification must remain FAILED'
        Assert-True ((Resolve-RecoverFailureReason @('CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN')) -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'one-argument resolver calls must retain Recover-default behavior'

        $originalProgramData = $env:ProgramData
        $env:ProgramData = $FixtureRoot
        try {
            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=API_READ_FAILED')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.State -ceq 'FAILED' -and $r.Reason -ceq 'QUEUE_UNAVAILABLE') 'Discover known queue/API failure must preserve bounded queue diagnosis'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=BUNDLE_FILE_HASH_DRIFT')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'PROVENANCE_MISMATCH') 'Discover known provenance failure must preserve bounded provenance diagnosis'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=CONTROLLER_GATE_UNCERTAIN')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'Discover known controller uncertainty must preserve bounded lock/residue diagnosis'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'FAILED') 'Discover must not map Recover-only classifications'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=FUTURE_UNKNOWN_CLASS')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'FAILED') 'Discover unknown classification must remain generic FAILED'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=API_READ_FAILED','CLASSIFICATION=QUEUE_STALE')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'FAILED') 'Discover duplicate classifications must fail closed'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=API_READ_FAILED') -ClassificationInvalid $true
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'FAILED') 'Discover mixed valid plus malformed classification state must fail closed'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'FAILED') 'Discover missing classification must fail closed'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=API_READ_FAILED') -OmitInvalidMarker
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'FAILED') 'Discover missing invalidity marker must fail closed'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=API_READ_FAILED')
            $r = Invoke-DispatcherMode Once
            Assert-True (-not $r.Success -and $r.State -ceq 'FAILED' -and $r.Reason -ceq 'FAILED') 'RUN_ONCE failure contract must remain generic even with known classification'

            Set-FixtureResult 1 @('DISPATCHER_RESULT=FAIL','CLASSIFICATION=RECOVERY_BUSY_OR_UNCERTAIN')
            $r = Invoke-DispatcherMode Recover
            Assert-True (-not $r.Success -and $r.Reason -ceq 'LOCK_OR_RESIDUE_UNCERTAIN') 'Recover mapping must remain unchanged'

            Set-FixtureResult 0 @('DISPATCHER_RESULT=IDLE')
            $r = Invoke-DispatcherMode Discover
            Assert-True ($r.Success -and $r.State -ceq 'PASS' -and $r.Reason -ceq 'NONE') 'Discover IDLE must remain PASS/NONE'

            Set-FixtureResult 0 @('DISPATCHER_RESULT=BUSY')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.State -ceq 'BLOCKED' -and $r.Reason -ceq 'BUSY') 'Discover BUSY semantics must remain unchanged'

            Set-FixtureResult 0 @('DISPATCHER_RESULT=CAPACITY','CAPACITY_SUBREASON=CAPACITY_RAM_RESERVE_4GIB_REQUIRED')
            $r = Invoke-DispatcherMode Discover
            Assert-True (-not $r.Success -and $r.State -ceq 'BLOCKED' -and $r.Reason -ceq 'CAPACITY_RAM_RESERVE_4GIB_REQUIRED') 'Discover CAPACITY semantics must remain unchanged'

            Set-FixtureResult 0 @('DISPATCHER_RESULT=DISCOVERED','DISCOVERED_RUN_ID=123','DISCOVERED_JOB_ID=456')
            $r = Invoke-DispatcherMode Discover
            Assert-True ($r.Success -and $r.State -ceq 'PASS' -and $r.Reason -ceq 'NONE' -and $r.RunId -eq 123 -and $r.JobId -eq 456) 'Discover DISCOVERED semantics and sanitized IDs must remain unchanged'

            Set-FixtureResult 0 @('DISPATCHER_RESULT=RECOVERED')
            $r = Invoke-DispatcherMode Recover
            Assert-True ($r.Success -and $r.State -ceq 'PASS' -and $r.Reason -ceq 'NONE') 'Recover success semantics must remain unchanged'
        }
        finally {
            $env:ProgramData = $originalProgramData
        }
    } $getOutputValueAst.Extent.Text $resolveFailureAst.Extent.Text $invokeDispatcherAst.Extent.Text $fixtureRoot
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}

Write-Host "CI/JIT DISCOVER classification contract assertions PASS: $script:Assertions"
