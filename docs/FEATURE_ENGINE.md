# Reusable Feature Engine & FeatureSnapshot Specification

## Executive Summary
This document specifies the design, schema, feature calculation APIs, and verification results for the `FeatureSnapshot` event contract ([`shared/contracts/feature_snapshot.py`](file:///d:/sih%20project/PassiveShield_AI_v2/shared/contracts/feature_snapshot.py)) and the shared `FeatureEngine` interface ([`services/features/feature_engine.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/features/feature_engine.py)).

---

## 1. Module Architecture & Scope

The `FeatureEngine` operates as a decoupled, stateless feature extractor that queries windowed network metrics from `RedisStateManager` and produces standardized `FeatureSnapshot` contract instances.

- **Location**: `services/features/feature_engine.py`
- **Output Contract**: `shared.contracts.FeatureSnapshot` (`event_type: "FeatureSnapshot"`, `version: "1.0"`)
- **Isolation**: Contains **zero threat classification or scoring rules**. Strictly computes mathematical ratios, statistics, and lexical features for downstream consumption.

---

## 2. Feature Extraction APIs

### A. IP Traffic Features (`compute_ip_features`)
Extracts windowed traffic volume, flow rates, and destination fan-out for source IP entities.
- `flow_count`: Total active flows in window.
- `orig_bytes`, `resp_bytes`: Outbound and inbound byte volumes.
- `orig_pkts`, `resp_pkts`: Outbound and inbound packet counts.
- `byte_ratio`: Outbound to inbound byte ratio (`orig_bytes / (resp_bytes + 1)`).
- `bytes_per_sec`, `pkts_per_sec`: Throughput and packet rate.
- `unique_dest_ports`, `unique_dest_ips`: Destination fan-out counts.

---

### B. Inter-Arrival Beaconing Features (`compute_beacon_features`)
Extracts inter-arrival time (IAT) statistics for connection pairs (`src_ip -> dst_ip`).
- `sample_count`: Total timestamp entries.
- `mean_iat`: Average interval between connection events.
- `variance_iat`, `std_iat`: Interval variance and standard deviation.
- `cv_iat`: Coefficient of variation (`std_iat / (mean_iat + 1e-5)`). Low values (< 0.2) indicate periodic automated beaconing.

---

### C. Lexical DNS Features (`compute_dns_features`)
Extracts lexical complexity and structural features for domain names.
- `domain_length`: Character length of domain string.
- `entropy`: Shannon entropy score of domain characters.
- `digit_count`, `digit_ratio`: Digit frequency metrics.
- `subdomain_depth`: Label depth count (`domain.count('.')`).

---

## 3. Test Verification Results

Unit tests are implemented in [`tests/test_feature_engine.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_feature_engine.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_feature_snapshot_contract`: Verified `FeatureSnapshot` dataclass creation and JSON roundtrip serialization.
- `test_feature_snapshot_fixture`: Verified parsing of sample fixture [`fixtures/contracts/feature_snapshot.json`](file:///d:/sih%20project/PassiveShield_AI_v2/fixtures/contracts/feature_snapshot.json).
- `test_compute_ip_features`: Verified IP flow metrics, byte ratios, and port fan-out calculations.
- `test_compute_beacon_features`: Verified IAT mean, variance, and CV calculation for periodic beaconing streams.
- `test_compute_dns_features`: Verified domain length, Shannon entropy, and subdomain depth calculations.
- `test_shannon_entropy`: Verified Shannon entropy mathematical calculations.
- Total Test Suite Status: **40 tests passed, 0 failures, 0 errors** (`OK`).
