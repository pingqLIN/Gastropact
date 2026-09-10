[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repositoryRoot
try {
    python -B automation/capture_evidence.py
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
