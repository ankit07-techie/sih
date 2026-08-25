#!/usr/bin/env bash
set -e

echo "=========================================="
echo "PassiveShield AI - Zeek Telemetry Verification"
echo "=========================================="

if [ -f "config/zeek/local.zeek" ]; then
    echo "[OK] config/zeek/local.zeek policy file found."
else
    echo "[ERROR] config/zeek/local.zeek missing!"
    exit 1
fi

if [ -f "fixtures/sample_zeek_logs/conn.log" ] && [ -f "fixtures/sample_zeek_logs/dns.log" ] && [ -f "fixtures/sample_zeek_logs/ssl.log" ]; then
    echo "[OK] Deterministic log fixtures (conn.log, dns.log, ssl.log) found."
else
    echo "[ERROR] Sample log fixtures missing!"
    exit 1
fi

echo "[INFO] Validating JSON formatting of sample log fixtures..."
which jq >/dev/null 2>&1 && {
    jq . fixtures/sample_zeek_logs/conn.log >/dev/null
    jq . fixtures/sample_zeek_logs/dns.log >/dev/null
    jq . fixtures/sample_zeek_logs/ssl.log >/dev/null
    echo "[OK] All sample Zeek logs are valid JSON!"
} || echo "[INFO] jq not installed; verified file presence."

echo "=========================================="
echo "Zeek Telemetry Verification Passed!"
echo "=========================================="
