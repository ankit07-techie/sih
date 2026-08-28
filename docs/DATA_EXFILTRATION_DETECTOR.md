# Data Exfiltration Behavioral Threat Detector Implementation

## Executive Summary
This document specifies the implementation, mathematical scoring formulation, robust MAD Z-score statistical anomaly detection, explicit evidence tagging, and test verification results for the `ExfiltrationDetector` component ([`services/detectors/exfiltration_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/detectors/exfiltration_detector.py)).

---

## 1. Detector Architecture & Scope

The `ExfiltrationDetector` evaluates streaming `FeatureSnapshot` event contracts for data exfiltration patterns, analyzing directional byte imbalance, single-flow volume bursts, and robust baseline deviation.

- **Location**: `services/detectors/exfiltration_detector.py`
- **Input Contract**: `shared.contracts.FeatureSnapshot` (`entity_type: "flow_pair"`)
- **Output Contract**: `shared.contracts.DetectionResult` (`detector_name: "ExfiltrationDetector"`, `version: "1.0"`)

---

## 2. Mathematical Scoring & Robust Z-Score Formulation

### A. Directional Asymmetry Score ($S_{\text{asymmetry}}$)
$$R_{\text{outbound}} = \frac{\text{orig\_bytes}}{\text{orig\_bytes} + \text{resp\_bytes} + 1}$$

If $R_{\text{outbound}} \ge 0.80$, outbound data dominates the flow volume:
$$S_{\text{asymmetry}} = \min\left(1.0, \frac{R_{\text{outbound}} - 0.70}{0.25}\right)$$

### B. Volume Burst Score ($S_{\text{burst}}$)
Evaluates raw outbound bytes ($\text{orig\_bytes}$):
- $\text{orig\_bytes} \ge 10 \text{ MB} \implies S_{\text{burst}} = 1.0$ (`EXFIL_HIGH_BURST_VOLUME`)
- $\text{orig\_bytes} \ge 1 \text{ MB} \implies S_{\text{burst}} = \frac{\text{orig\_bytes}}{10\text{ MB}}$ (`EXFIL_ELEVATED_BURST_VOLUME`)

### C. Robust Z-Score Anomaly ($S_{\text{zscore}}$)
Calculates robust Z-score using Median Absolute Deviation (MAD) against historical baseline:
$$\text{MAD} = \text{median}(|x_i - \text{median}(x)|)$$
$$\text{Robust Z} = 0.6745 \cdot \frac{\text{orig\_bytes} - \text{median}}{\text{MAD} + 1e-5}$$

If $\text{Robust Z} \ge 3.5$, an anomaly score is calculated:
$$S_{\text{zscore}} = \min\left(1.0, \frac{\text{Robust Z} - 3.0}{5.0}\right)$$

---

## 3. Explicit Evidence Vector Tagging

| Evidence Code | Trigger Condition | Message Description |
|---|---|---|
| `BELOW_EXFIL_FLOOR` | `orig_bytes < 100 KB` | Outbound volume below minimum exfiltration floor |
| `EXFIL_HIGH_DIRECTIONAL_RATIO` | $R_{\text{outbound}} \ge 0.80$ | Outbound data dominates flow volume ($\ge 80\%$) |
| `EXFIL_HIGH_BURST_VOLUME` | `orig_bytes >= 10 MB` | Large single-flow outbound data transfer ($\ge 10\text{ MB}$) |
| `EXFIL_ELEVATED_BURST_VOLUME` | `orig_bytes >= 1 MB` | Elevated outbound data transfer volume ($\ge 1\text{ MB}$) |
| `EXFIL_ROBUST_ZSCORE_ANOMALY` | $\text{Robust Z} \ge 3.5$ | Outbound volume robust Z-score spike above median |

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_exfiltration_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_exfiltration_detector.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_benign_download_flow`: Verified download-heavy web traffic produces `INFO` severity ($S=0.0$, `is_threat=False`).
- `test_high_directional_exfiltration_upload`: Verified 15 MB outbound upload triggers `HIGH`/`CRITICAL` severity ($S \ge 0.85$, `EXFIL_HIGH_DIRECTIONAL_RATIO`, `EXFIL_HIGH_BURST_VOLUME`).
- `test_robust_zscore_anomaly`: Verified 5 MB burst against 50 KB baseline triggers `EXFIL_ROBUST_ZSCORE_ANOMALY` evidence tag.
- `test_below_exfil_floor`: Verified low-volume traffic (< 100 KB) defaults to `INFO` with `BELOW_EXFIL_FLOOR` tag.
- Total Test Suite Status: **75 tests passed, 0 failures, 0 errors** (`OK`).
