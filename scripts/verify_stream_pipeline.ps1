# PassiveShield AI — Telemetry Stream Pipeline Integration Verification (PowerShell)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PassiveShield AI - Stream Pipeline Integration" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Verify pipeline code files exist
if ((Test-Path "services/ingestion/stream_pipeline.py") -and (Test-Path "services/ingestion/telemetry_producer.py")) {
    Write-Host "[OK] Pipeline source modules found." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Pipeline source files missing!" -ForegroundColor Red
    exit 1
}

# 2. Run full unittest suite
Write-Host "[INFO] Executing integration test suite..." -ForegroundColor Yellow
py -3 -m unittest discover tests
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Telemetry stream pipeline integration tests PASSED!" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Integration test suite failed!" -ForegroundColor Red
    exit 1
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Stream Pipeline Integration Passed!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
