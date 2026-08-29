#!/usr/bin/env bash
# PassiveShield AI Cyber Range — Capture Script
set -e

SCENARIO="${1:-mixed}"
DURATION="${2:-10}"

cd "$(dirname "$0")/.."

echo "[SENSOR] Launching passive PCAP capture for ${SCENARIO} (${DURATION}s)..."
docker compose exec -T passive-sensor python3 -u capture/passive_pcap_sensor.py --scenario "${SCENARIO}" --duration "${DURATION}"
