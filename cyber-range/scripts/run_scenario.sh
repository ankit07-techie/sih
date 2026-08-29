#!/usr/bin/env bash
# PassiveShield AI Cyber Range — Run Scenario Script (Bash)
set -e

SCENARIO="${1:-mixed}"
DURATION="${2:-10}"

echo "=========================================================="
echo "PASSIVESHIELD CYBER RANGE — RUNNING SCENARIO: ${SCENARIO}"
echo "=========================================================="

cd "$(dirname "$0")/.."

docker compose exec -T traffic-generator python3 -u simulator/generator_cli.py --scenario "${SCENARIO}" --duration "${DURATION}"

python3 scripts/validate_results.py
