# PassiveShield AI — Replay Workflow Verification Script (PowerShell)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PassiveShield AI - Replay Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Verify replay runner script exists
if (Test-Path "replay/replay_runner.py") {
    Write-Host "[OK] replay/replay_runner.py script found." -ForegroundColor Green
} else {
    Write-Host "[ERROR] replay/replay_runner.py missing!" -ForegroundColor Red
    exit 1
}

# 2. Verify sample PCAP fixture exists
if (Test-Path "fixtures/sample_replay.pcap") {
    Write-Host "[OK] fixtures/sample_replay.pcap fixture found." -ForegroundColor Green
} else {
    Write-Host "[ERROR] fixtures/sample_replay.pcap missing!" -ForegroundColor Red
    exit 1
}

# 3. Test dry-run replay execution
Write-Host "[INFO] Executing deterministic replay dry-run test..." -ForegroundColor Yellow
py -3 replay/replay_runner.py --pcap fixtures/sample_replay.pcap --dry-run
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Deterministic replay runner dry-run validation passed!" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Replay runner validation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Replay Workflow Verification Passed!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
