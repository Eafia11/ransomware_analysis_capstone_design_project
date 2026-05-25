param(
    [string]$Path = "C:\ProgramData\Winlogbeat\exported\winlogbeat",
    [int]$Tail = 20
)

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "Log path not found: $Path"
    exit 1
}

Get-Content -LiteralPath $Path -Tail $Tail -Wait
