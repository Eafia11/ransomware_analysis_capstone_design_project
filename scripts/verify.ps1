param(
    [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"

Push-Location (Join-Path $PSScriptRoot "..")
try {
    python -m pytest backend/tests

    if (-not $SkipFrontend) {
        Push-Location "frontend"
        try {
            npm run build
        }
        finally {
            Pop-Location
        }
    }
}
finally {
    Pop-Location
}
