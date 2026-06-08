#!/usr/bin/env pwsh
# Thin wrapper around scripts/demo.py for Windows users.
# Usage: .\scripts\demo.ps1 [--keep] [--offline] [--teardown-only]

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Push-Location $root
try {
    python -m scripts.demo @args
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
