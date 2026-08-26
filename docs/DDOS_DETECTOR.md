# Approved DDoS Threat Detector Implementation Specification

## Executive Summary
This document specifies the implementation, evidence structure, telemetry degradation rules, severity mapping, and verification results for the `DDoSDetector` component ([`services/detectors/ddos_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/detectors/ddos_detector.py)).

---

## 1. Detector Architecture & Scope

The `DDoSDetector` evaluates streaming `FeatureSnapshot` event contracts, applies the approved mathematical scoring formulation, generates diagnostic `ThreatEvidence` objects, and returns standardized `DetectionResult` contract instances.

- **Location**: `services/detectors/ddos_detector.py`
- **Input Contract**: `shared.contracts.FeatureSnapshot`
- **Output Contract**: `shared.contracts.DetectionResult` (`detector_name: "DDoSDetector"`, `version: "1.0"`)

---

## 2. Mathematical Scoring & Telemetry Degradation

### A. Full Telemetry Scoring Formulation ($w_1=0.40, w_2=0.35, w_3=0.25$)
$$S = 0.40 \cdot S_{\text{rate}} + 0.35 \cdot S_{\text{handshake}} + 0.25 \cdot S_{\text{entropy}}$$

Where:
- $S_{\text{rate}} = \min(1.0, \max(0.0, (\text{surge\_ratio\_pps} - 1.0) / 9.0))$
- $S_{\text{handshake}} = 0.7 \cdot \text{syn\_only\_ratio} + 0.3 \cdot \text{ack\_missing\_ratio}$
- $S_{\text{entropy}} = \min(1.0, \text{unique\_source\_ips} / 100.0) \cdot (1.0 - \min(1.0, \text{destination\_port\_entropy} / 4.0))$

### B. Incomplete Telemetry Degradation ($w_1=0.75, w_2=0.0, w_3=0.25$)
When TCP handshake state features (`syn_only_ratio`, `ack_missing_ratio`) are missing or delayed in `conn.log` ingestion:
1. Handshake weight $w_2=0.35$ is automatically reallocated to volumetric rate weight ($w_1 \to 0.75$).
2. Evidence vector appends `DEGRADED_TELEMETRY` warning tag.

---

## 3. Severity & Mitigation Mapping

| Confidence Score ($S$) | Severity | `is_threat` | Mitigation Recommendation |
|---|---|---|---|
| $S < 0.35$ | `INFO` | `False` | `NO_ACTION` |
| $0.35 \le S < 0.60$ | `LOW` | `True` | `MONITOR_TRAFFIC` |
| $0.60 \le S < 0.85$ | `MEDIUM` | `True` | `FLAG_SUSPECT_IPS` |
| $0.85 \le S < 0.95$ | `HIGH` | `True` | `RATE_LIMIT_IP` |
| $S \ge 0.95$ | `CRITICAL` | `True` | `APPLY_PASSIVE_SHIELD_FILTERS` |

---

## 4. Test Verification Results

Unit and integration tests are implemented in [`tests/test_ddos_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_ddos_detector.py).

### Test Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_benign_traffic`: Verified low traffic below volumetric floors produces `INFO` severity ($S=0.0$, `is_threat=False`).
- `test_syn_flood_attack`: Verified synthetic 1000 PPS SYN flood attack triggers `HIGH`/`CRITICAL` severity ($S \ge 0.85$, `is_threat=True`) with `VOLUMETRIC_SURGE` and `SYN_FLOOD_SIGNAL` evidence.
- `test_incomplete_telemetry_degradation`: Verified weight reallocation ($w_1 \to 0.75$) and `DEGRADED_TELEMETRY` evidence when connection state flags are omitted.
- `test_deterministic_replay_pipeline`: Verified end-to-end replay pipeline from `conn.log` -> `ZeekAdapter` -> `RedisStateManager` -> `FeatureEngine` -> `DDoSDetector`.
- Total Test Suite Status: **45 tests passed, 0 failures, 0 errors** (`OK`).
