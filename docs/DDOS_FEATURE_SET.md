# Reusable DDoS Feature Set Specification

## Executive Summary
This document specifies the design, signal definitions, and test verification results for the `DDoSFeatureExtractor` module ([`services/features/ddos_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/features/ddos_features.py)).

---

## 1. Feature Extractor Architecture & Scope

The `DDoSFeatureExtractor` computes reusable, objective DDoS traffic signals for target IP entities, formatting output as standardized `FeatureSnapshot` contract instances.

- **Location**: `services/features/ddos_features.py`
- **Output Contract**: `shared.contracts.FeatureSnapshot` (`entity_type: "ip"`, `version: "1.0"`)
- **Detector Independence**: Contains **zero classification, threshold scoring, or alert decision logic**. Produces mathematical traffic signals for downstream consumption by independent threat detectors.

---

## 2. Feature Signals & Metrics Table

| Feature Key | Category | Mathematical Definition | Target Threat Signal |
|---|---|---|---|
| `pps` | Traffic Rate | `(orig_pkts + resp_pkts) / window_seconds` | Volumetric packet floods (SYN/UDP/ICMP) |
| `bps` | Traffic Rate | `(orig_bytes + resp_bytes) * 8 / window_seconds` | Bandwidth exhaustion attacks |
| `mbps` | Traffic Rate | `bps / 1,000,000.0` | Throughput in Megabits per second |
| `avg_pkt_size` | Packet Size | `total_bytes / (total_pkts + 1)` | Small packet flood vs jumbo frame anomaly |
| `syn_only_ratio` | Handshake Flag | `count(S0) / total_conn_samples` | SYN flood (unacknowledged TCP handshakes) |
| `ack_missing_ratio` | Handshake Flag | `(count(S0) + count(REJ, RSTO, RSTOS0)) / total_samples` | Incomplete/rejected handshake ratio |
| `unique_source_ips` | Diversity | `count(distinct(source_ips))` | Distributed attack footprint |
| `source_ip_entropy` | Entropy | `ShannonEntropy(source_ips)` | Source IP spoofing / distribution spread |
| `destination_port_entropy` | Entropy | `ShannonEntropy(destination_ports)` | Multi-port flood vs single-service attack |
| `port_concentration_ratio` | Concentration | `1.0 / (unique_destination_ports + 1e-5)` | Focused single-target service targeting |
| `surge_ratio_pps` | Baseline Surge | `current_pps / baseline_pps` | Anomalous packet rate surge relative to baseline |
| `surge_ratio_bps` | Baseline Surge | `current_bps / baseline_bps` | Anomalous bandwidth surge relative to baseline |

---

## 3. Test Verification Results

Unit tests are implemented in [`tests/test_ddos_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_ddos_features.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_ddos_rates_and_ratios`: Verified calculation of `pps`, `bps`, `syn_only_ratio`, `ack_missing_ratio`, `unique_source_ips`, and `surge_ratio_pps` baseline multipliers.
- Total Test Suite Status: **41 tests passed, 0 failures, 0 errors** (`OK`).
