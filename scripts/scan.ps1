#!/usr/bin/env pwsh
# Friendly wrapper to scan an arbitrary repo with the orchestrator.
# Usage:
#   .\scripts\scan.ps1 -Repo C:\path\to\product
#   .\scripts\scan.ps1 -Repo C:\path\to\product -MinSeverity high

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Repo,
    [string]$Rules,
    [ValidateSet("critical","high","medium","low","info")][string]$MinSeverity = "medium",
    [int]$MaxFindings = 200,
    [string]$Report,
    [switch]$NoColor
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$argv = @("--repo", $Repo, "--min-severity", $MinSeverity, "--max-findings", $MaxFindings)
if ($Rules)   { $argv += @("--rules", $Rules) }
if ($Report)  { $argv += @("--report", $Report) }
if ($NoColor) { $argv += "--no-color" }

Push-Location $root
try {
    python -m scripts.scan @argv
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
