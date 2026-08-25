#!/usr/bin/env bash
set -e

echo "=========================================="
echo "PassiveShield AI - Infra Health Verification"
echo "=========================================="

if [ -f ".env.example" ]; then
    echo "[OK] .env.example found."
else
    echo "[ERROR] .env.example missing!"
    exit 1
fi

if [ -f "infra/docker-compose.yml" ]; then
    echo "[OK] infra/docker-compose.yml found."
else
    echo "[ERROR] infra/docker-compose.yml missing!"
    exit 1
fi

if command -v docker >/dev/null 2>&1; then
    echo "[INFO] Validating docker compose configuration syntax..."
    docker compose -f infra/docker-compose.yml --env-file .env.example config --quiet
    echo "[OK] Docker Compose syntax is valid!"
else
    echo "[WARN] Docker CLI not found. Skipping runtime syntax check."
fi

echo "=========================================="
echo "Infrastructure Verification Passed!"
echo "=========================================="
