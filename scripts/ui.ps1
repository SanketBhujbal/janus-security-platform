#!/usr/bin/env pwsh
# Launch the Agentic Security Platform UI.
# Usage: .\scripts\ui.ps1 [-Port 8000] [-NoOpen]
[CmdletBinding()]
param(
    [int]$Port = 8000,
    [string]$Host = "127.0.0.1",
    [switch]$NoOpen,
    [switch]$Reload
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$argv = @("--port", $Port, "--host", $Host)
if ($NoOpen) { $argv += "--no-open" }
if ($Reload) { $argv += "--reload" }

Push-Location $root
try {
    python -m webapp @argv
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
