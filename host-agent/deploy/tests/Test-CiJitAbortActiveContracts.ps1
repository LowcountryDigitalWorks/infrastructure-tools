Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$worker = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-CiJitControlTask.ps1'

$tokens = $null
$errors = $null

$ast = [Management.Automation.Language.Parser]::ParseFile(
    $worker,
    [ref]$tokens,
    [ref]$errors
)

if (@($errors).Count -ne 0) {
    throw ('ABORT_WORKER_PARSE_FAILED: ' + $errors[0].Message)
}

$node = $ast.Find(
    {
        param($n)

        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -ceq 'Invoke-AbortActive'
    },
    $false
)

if ($null -eq $node) {
    throw 'ABORT_HELPER_REQUIRED'
}

$abortCalls = @(
    $ast.FindAll(
        {
            param($n)

            $n -is [Management.Automation.Language.CommandAst] -and
            $n.GetCommandName() -ceq 'Invoke-AbortActive'
        },
        $true
    )
)

if ($abortCalls.Count -ne 1) {
    throw "ABORT_SWITCH_WIRING_COUNT_REFUSED: $($abortCalls.Count)"
}

$actualAbortCall = (
    $abortCalls[0].Extent.Text -replace '\s+', ' '
).Trim()

$expectedAbortCall = "Invoke-AbortActive (Join-Path `$controllerRoot 'runs') `$runnerEntry"

if ($actualAbortCall -cne $expectedAbortCall) {
    throw "ABORT_SWITCH_WIRING_DRIFT: $actualAbortCall"
}

. ([scriptblock]::Create($node.Extent.Text))

$script:Assertions = 0
$script:CleanupCalls = [Collections.Generic.List[object]]::new()

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Value,
        [Parameter(Mandatory)][string]$Message
    )

    $script:Assertions++

    if (-not $Value) {
        throw "ASSERTION_FAILED: $Message"
    }
}

function Assert-Result {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][bool]$Success,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$Reason
    )

    Assert-True ($Result.Success -eq $Success) "success expected $Success"
    Assert-True ($Result.State -ceq $State) "state expected $State"
    Assert-True ($Result.Reason -ceq $Reason) "reason expected $Reason"
}

function Reset-CleanupCalls {
    $script:CleanupCalls.Clear()
}

function Invoke-Child {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $script:CleanupCalls.Add(
        [pscustomobject]@{
            Path = $Path
            Arguments = @($Arguments)
        }
    )

    [pscustomobject]@{
        ExitCode = 0
        Lines = @('CLEANUP_IDEMPOTENT=PASS')
    }
}

$tempRoot = Join-Path (
    [IO.Path]::GetTempPath()
) ('ldw-ci-jit-abort-' + [guid]::NewGuid().ToString('N'))

$runsPath = Join-Path $tempRoot 'runs'
$runnerPath = 'C:\synthetic\Invoke-IsolatedRunner.ps1'

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    # Missing runs directory must fail closed without invoking cleanup.
    Reset-CleanupCalls
    $result = Invoke-AbortActive $runsPath $runnerPath
    Assert-Result $result $false 'BLOCKED' 'NO_ACTIVE_JOB'
    Assert-True ($script:CleanupCalls.Count -eq 0) 'missing runs path must not invoke cleanup'

    # An unexpected non-directory at the runs path is residue uncertainty.
    New-Item -ItemType File -Path $runsPath -Force | Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortActive $runsPath $runnerPath
    Assert-Result $result $false 'BLOCKED' 'LOCK_OR_RESIDUE_UNCERTAIN'
    Assert-True ($script:CleanupCalls.Count -eq 0) 'non-directory runs path must not invoke cleanup'

    Remove-Item -LiteralPath $runsPath -Force

    # Existing but empty runs directory must behave identically to no runs path.
    New-Item -ItemType Directory -Path $runsPath -Force | Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortActive $runsPath $runnerPath
    Assert-Result $result $false 'BLOCKED' 'NO_ACTIVE_JOB'
    Assert-True ($script:CleanupCalls.Count -eq 0) 'empty runs path must not invoke cleanup'

    # One exact valid run may invoke cleanup for only that run.
    $validRun = 'a' * 32
    $validPath = Join-Path $runsPath $validRun
    New-Item -ItemType Directory -Path $validPath | Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortActive $runsPath $runnerPath
    Assert-Result $result $true 'PASS' 'NONE'
    Assert-True ($script:CleanupCalls.Count -eq 1) 'one valid run must invoke cleanup exactly once'

    $call = $script:CleanupCalls[0]

    Assert-True ($call.Path -ceq $runnerPath) 'cleanup must use exact runner path'
    Assert-True (
        ($call.Arguments -join '|') -ceq (
            '-Mode|Cleanup|-LocalRunId|' + $validRun
        )
    ) 'cleanup must target only the exact valid local run'

    Remove-Item -LiteralPath $validPath -Recurse -Force

    # Multiple valid run identities are ambiguous and must not invoke cleanup.
    foreach ($name in @(
        ('b' * 32),
        ('c' * 32)
    )) {
        New-Item -ItemType Directory -Path (Join-Path $runsPath $name) | Out-Null
    }

    Reset-CleanupCalls
    $result = Invoke-AbortActive $runsPath $runnerPath
    Assert-Result $result $false 'AMBIGUOUS' 'IDENTITY_MISMATCH'
    Assert-True ($script:CleanupCalls.Count -eq 0) 'multiple runs must not invoke cleanup'

    Get-ChildItem -LiteralPath $runsPath -Directory |
        Remove-Item -Recurse -Force

    # One malformed run identity is also ambiguous and must not invoke cleanup.
    New-Item -ItemType Directory -Path (
        Join-Path $runsPath 'not-a-valid-local-run'
    ) | Out-Null

    Reset-CleanupCalls
    $result = Invoke-AbortActive $runsPath $runnerPath
    Assert-Result $result $false 'AMBIGUOUS' 'IDENTITY_MISMATCH'
    Assert-True ($script:CleanupCalls.Count -eq 0) 'malformed run identity must not invoke cleanup'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host "CI_JIT_ABORT_ACTIVE_CONTRACT=PASS ASSERTIONS=$script:Assertions"
