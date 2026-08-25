#!/usr/bin/env bash
set -e

echo "=========================================="
echo "PassiveShield AI - Replay Verification"
echo "=========================================="

if [ -f "replay/replay_runner.py" ]; then
    echo "[OK] replay/replay_runner.py script found."
else
    echo "[ERROR] replay/replay_runner.py missing!"
    exit 1
fi

if [ -f "fixtures/sample_replay.pcap" ]; then
    echo "[OK] fixtures/sample_replay.pcap fixture found."
else
    echo "[ERROR] fixtures/sample_replay.pcap missing!"
    exit 1
fi

echo "[INFO] Executing deterministic replay dry-run test..."
python3 replay/replay_runner.py --pcap fixtures/sample_replay.pcap --dry-run
echo "[OK] Deterministic replay runner dry-run validation passed!"

echo "=========================================="
echo "Replay Workflow Verification Passed!"
echo "=========================================="
