# PassiveShield AI Infrastructure Verification Script (PowerShell)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PassiveShield AI - Infra Health Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Verify .env.example exists
if (Test-Path ".env.example") {
    Write-Host "[OK] .env.example found." -ForegroundColor Green
} else {
    Write-Host "[ERROR] .env.example missing!" -ForegroundColor Red
    exit 1
}

# 2. Verify infra/docker-compose.yml exists
if (Test-Path "infra/docker-compose.yml") {
    Write-Host "[OK] infra/docker-compose.yml found." -ForegroundColor Green
} else {
    Write-Host "[ERROR] infra/docker-compose.yml missing!" -ForegroundColor Red
    exit 1
}

# 3. Test Docker Compose configuration syntax if docker CLI is available
$dockerCheck = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCheck) {
    Write-Host "[INFO] Validating docker compose configuration syntax..." -ForegroundColor Yellow
    docker compose -f infra/docker-compose.yml --env-file .env.example config --quiet
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Docker Compose syntax is valid!" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Docker Compose syntax validation failed!" -ForegroundColor Red
        exit $LASTEXITCODE
    }
} else {
    Write-Host "[WARN] Docker CLI not installed or not in PATH. Skipping runtime syntax check." -ForegroundColor Yellow
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Infrastructure Verification Passed!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
