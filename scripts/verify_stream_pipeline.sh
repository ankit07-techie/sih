#!/usr/bin/env bash
set -e

echo "=========================================="
echo "PassiveShield AI - Stream Pipeline Integration"
echo "=========================================="

if [ -f "services/ingestion/stream_pipeline.py" ] && [ -f "services/ingestion/telemetry_producer.py" ]; then
    echo "[OK] Pipeline source modules found."
else
    echo "[ERROR] Pipeline source files missing!"
    exit 1
fi

echo "[INFO] Executing integration test suite..."
python3 -m unittest discover tests
echo "[OK] Telemetry stream pipeline integration tests PASSED!"

echo "=========================================="
echo "Stream Pipeline Integration Passed!"
echo "=========================================="
