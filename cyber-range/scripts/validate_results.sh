#!/usr/bin/env bash
# PassiveShield AI Cyber Range — Validation Script (Bash)
set -e

cd "$(dirname "$0")/.."
python3 scripts/validate_results.py
