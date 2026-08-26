# Reusable Port Scan Feature Set Specification

## Executive Summary
This document specifies the design, feature definitions, and verification results for the `PortScanFeatureExtractor` module ([`services/features/port_scan_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/features/port_scan_features.py)).

---

## 1. Feature Extractor Architecture & Scope

The `PortScanFeatureExtractor` computes objective reconnaissance signals, target fan-out metrics, growth rate vectors, and connection failure ratios for source IP entities.

- **Location**: `services/features/port_scan_features.py`
- **Output Contract**: `shared.contracts.FeatureSnapshot` (`entity_type: "ip"`, `version: "1.0"`)
- **Isolation**: Contains **zero classification, threshold scoring, or detector decision code**. Computes mathematical features for downstream consumption by independent reconnaissance threat detectors.

---

## 2. Feature Signals & Metrics Table

| Feature Key | Category | Mathematical Definition | Target Threat Signal |
|---|---|---|---|
| `unique_dst_ports` | Fan-Out Volume | `count(distinct(destination_ports))` | Total target port footprint in window |
| `unique_dst_ips` | Fan-Out Volume | `count(distinct(destination_ips))` | Horizontal subnet scan footprint |
| `fanout_ports_per_sec` | Fan-Out Rate | `unique_dst_ports / window_seconds` | Port scanning velocity |
| `fanout_ips_per_sec` | Fan-Out Rate | `unique_dst_ips / window_seconds` | IP sweep velocity |
| `port_growth_rate` | Growth Vector | `(current_unique_ports - prev_ports) / max(1, prev_ports)` | Rapid fan-out expansion acceleration |
| `failed_conn_ratio` | Handshake Failure | `count(REJ, S0, RSTO, RSTOS0) / total_conn_samples` | Ratio of unacknowledged/rejected probes |
| `rst_ratio` | Reset Anomaly | `count(RSTO, RSTR) / total_conn_samples` | Connection reset ratio (closed port probe) |
| `stealth_scan_ratio` | Stealth Probe | `count(S0, S1, SH) / total_conn_samples` | Half-open SYN/FIN stealth scan probe ratio |

---

## 3. Test Verification Results

Unit tests are implemented in [`tests/test_port_scan_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_port_scan_features.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_port_scan_fanout_and_growth`: Verified unique destination port count (20 ports), unique IP count (5 IPs), port growth rate calculation (3.0x), and connection failure ratio (0.5).
- Total Test Suite Status: **46 tests passed, 0 failures, 0 errors** (`OK`).
