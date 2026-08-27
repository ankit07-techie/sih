# Reusable C2 Beaconing Feature Set Specification

## Executive Summary
This document specifies the design, feature definitions, and verification results for the `BeaconingFeatureExtractor` module ([`services/features/beaconing_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/features/beaconing_features.py)).

---

## 1. Feature Extractor Architecture & Scope

The `BeaconingFeatureExtractor` computes inter-arrival time (IAT) statistical metrics, connection periodicity scores, jitter ratios, and payload size consistency vectors for connection pairs (`src_ip -> dst_ip`).

- **Location**: `services/features/beaconing_features.py`
- **Output Contract**: `shared.contracts.FeatureSnapshot` (`entity_type: "flow_pair"`, `version: "1.0"`)
- **Isolation**: Contains **zero classification, threshold scoring, or detector decision code**. Computes objective mathematical features for downstream consumption by independent C2 beaconing threat detectors.

---

## 2. Feature Signals & Metrics Table

| Feature Key | Category | Mathematical Definition | Target Threat Signal |
|---|---|---|---|
| `sample_count` | Observation Volume | `count(timestamps)` | Total timestamp observations in ZSET history |
| `iat_count` | Observation Volume | `count(IAT_deltas)` | Total inter-arrival intervals ($N-1$) |
| `mean_iat` | Central Tendency | $\frac{1}{M}\sum IAT_i$ | Average beacon interval duration (seconds) |
| `variance_iat` | Dispersion | $\frac{1}{M-1}\sum (IAT_i - \text{mean\_iat})^2$ | Interval variance |
| `std_iat` | Dispersion | $\sqrt{\text{variance\_iat}}$ | Standard deviation of intervals |
| `cv_iat` | Regularity Ratio | $\frac{\text{std\_iat}}{\text{mean\_iat} + 1e-5}$ | Coefficient of variation (low values < 0.20 indicate periodic C2 beaconing) |
| `periodicity_score` | Regularity Score | $\max(0.0, 1.0 - \min(1.0, \text{cv\_iat}))$ | Normalized periodicity rating ($1.0 = \text{perfectly periodic}$) |
| `jitter_ratio` | Jitter | $\frac{\text{std\_iat}}{\text{mean\_iat} + 1e-5}$ | Relative interval jitter ratio |
| `payload_size_std` | Consistency | Standard deviation of `orig_bytes` | Payload byte consistency across connections |

---

## 3. Test Verification Results

Unit tests are implemented in [`tests/test_beaconing_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_beaconing_features.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_periodic_c2_beaconing`: Verified 15-second periodic beaconing produces `mean_iat = 15.0`, `variance_iat = 0.0`, `cv_iat = 0.0`, and `periodicity_score = 1.0`.
- `test_jittered_c2_beaconing`: Verified beaconing with small 1s jitter produces `cv_iat < 0.20` and `periodicity_score > 0.80`.
- `test_random_human_traffic`: Verified irregular human browsing produces `cv_iat > 0.80` and `periodicity_score < 0.20`.
- Total Test Suite Status: **53 tests passed, 0 failures, 0 errors** (`OK`).
