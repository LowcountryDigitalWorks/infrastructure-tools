#Requires -Version 5.1
<#
.SYNOPSIS
Read-only LDW01 D0 first-install source readiness report.
.DESCRIPTION
NO install, SYSTEM task, elevation, worker, journal, ACL mutation, network,
Git, writable input path or user-provided checksum. Always HOLD physical action.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$module=Join-Path $PSScriptRoot 'RedrixD0FirstInstallReadOnly.psm1'
if (-not (Test-Path -LiteralPath $module -PathType Leaf)) {
    throw 'D0_SOURCE_GATE_MODULE_MISSING'
}
Import-Module -Name $module -Force -ErrorAction Stop
$plan=Get-D0FirstInstallSourcePlan
if ($null -eq $plan -or $plan.status -notmatch '^D0_') {
    throw 'D0_FIRST_INSTALL_PLAN_AMBIGUOUS'
}
Write-Output ('REDRIX_D0_FIRST_INSTALL_STATUS=' + $plan.status)
Write-Output ('REDRIX_D0_FIRST_INSTALL_SOURCE_VALIDATION=' + $plan.source_validation)
Write-Output 'REDRIX_D0_FIRST_INSTALL_SYSTEM_TASK_INSTALLED_BY_THIS_SCRIPT=FALSE'
Write-Output 'REDRIX_D0_FIRST_INSTALL_PARENT_ACL_MUTATED=FALSE'
Write-Output 'REDRIX_D0_FIRST_INSTALL_PHYSICAL_AUTHORITY=HOLD_SECURITY'
