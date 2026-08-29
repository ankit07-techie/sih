# PassiveShield AI Cyber Range — Run Scenario Script (PowerShell)
param (
    [string]$Scenario = "mixed",
    [int]$Duration = 10
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "PASSIVESHIELD CYBER RANGE — RUNNING SCENARIO: $Scenario" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$ScriptDir\.."

docker compose exec -T traffic-generator python3 -u simulator/generator_cli.py --scenario $Scenario --duration $Duration

py -3 scripts/validate_results.py
