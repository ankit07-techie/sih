# Port Scan & Reconnaissance Threat Detector Implementation

## Executive Summary
This document specifies the implementation, scoring mathematical model, evidence structure, severity mapping, and verification results for the `PortScanDetector` component ([`services/detectors/port_scan_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/detectors/port_scan_detector.py)).

---

## 1. Detector Architecture & Scope

The `PortScanDetector` evaluates streaming `FeatureSnapshot` event contracts for vertical port scanning, horizontal IP sweeps, fan-out acceleration, and stealth probe reconnaissance.

- **Location**: `services/detectors/port_scan_detector.py`
- **Input Contract**: `shared.contracts.FeatureSnapshot`
- **Output Contract**: `shared.contracts.DetectionResult` (`detector_name: "PortScanDetector"`, `version: "1.0"`)

---

## 2. Mathematical Scoring & Stealth Boost

### A. Sub-Scores
1. **Vertical Scan Score ($S_{\text{vert}}$)**:
   $$S_{\text{vert}} = \min\left(1.0, \frac{\text{unique\_dst\_ports}}{50}\right) \cdot (0.5 + 0.5 \cdot \text{failed\_conn\_ratio})$$
2. **Horizontal Sweep Score ($S_{\text{horiz}}$)**:
   $$S_{\text{horiz}} = \min\left(1.0, \frac{\text{unique\_dst\_ips}}{20}\right) \cdot (0.5 + 0.5 \cdot \text{failed\_conn\_ratio})$$
3. **Growth Acceleration Score ($S_{\text{growth}}$)**:
   $$S_{\text{growth}} = \min\left(1.0, \frac{\text{port\_growth\_rate}}{3.0}\right)$$

### B. Composite Score & Stealth Multiplier
$$S_{\text{base}} = \max(S_{\text{vert}}, S_{\text{horiz}}) \cdot 0.70 + S_{\text{growth}} \cdot 0.30$$

If `stealth_scan_ratio >= 0.50` (half-open TCP `S0`, `S1`, `SH` probes), a $1.20\times$ multiplier is applied:
$$S = \min(1.0, S_{\text{base}} \cdot 1.20)$$

---

## 3. Severity & Recommended Mitigation Mapping

| Confidence Score ($S$) | Severity | `is_threat` | Recommended SOC Action |
|---|---|---|---|
| $S < 0.35$ | `INFO` | `False` | `NO_ACTION` |
| $0.35 \le S < 0.60$ | `LOW` | `True` | `MONITOR_SOURCE_IP` |
| $0.60 \le S < 0.85$ | `MEDIUM` | `True` | `FLAG_RECONNAISSANCE_IP` |
| $0.85 \le S < 0.95$ | `HIGH` | `True` | `BLOCK_RECONNAISSANCE_IP` |
| $S \ge 0.95$ | `CRITICAL` | `True` | `APPLY_PASSIVE_SHIELD_FILTERS` |

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_port_scan_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_port_scan_detector.py).

### Test Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_benign_traffic`: Verified benign fan-out (`unique_dst_ports < 5`) produces `INFO` severity ($S=0.0$, `is_threat=False`).
- `test_horizontal_ip_sweep`: Verified horizontal IP sweep across 30 IPs triggers `MEDIUM`/`HIGH` severity with `HORIZONTAL_IP_SWEEP` evidence.
- `test_vertical_port_scan`: Verified vertical scan across 100 ports triggers `CRITICAL` severity ($S \ge 0.95$) with `VERTICAL_PORT_SCAN` and `STEALTH_PROBE_SIGNAL` evidence.
- `test_slow_port_scan`: Verified slow port scan over 300s window triggers `LOW` severity ($S=0.48$).
- Total Test Suite Status: **50 tests passed, 0 failures, 0 errors** (`OK`).
