#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Plan','Start')]
    [string]$Action = 'Plan'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HostAgentWindowsTrayLaunch.psm1') -Force

switch ($Action) {
    'Plan' { Get-HostAgentWindowsTrayLaunchPlan }
    'Start' { Start-HostAgentWindowsTray }
}
