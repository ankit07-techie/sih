# PassiveShield AI Cyber Range — Validation Script (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$ScriptDir\.."
py -3 scripts/validate_results.py
