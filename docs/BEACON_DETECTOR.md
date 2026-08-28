# Approved C2 Beaconing Threat Detector Implementation

## Executive Summary
This document specifies the implementation, mathematical scoring formulation, SciPy FFT spectral peak analysis, evidence vector generation, and test verification results for the `C2BeaconDetector` component ([`services/detectors/beacon_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/detectors/beacon_detector.py)).

---

## 1. Detector Architecture & Scope

The `C2BeaconDetector` evaluates streaming `FeatureSnapshot` event contracts for Command and Control (C2) beaconing patterns, combining statistical inter-arrival time (IAT) regularity analysis with SciPy FFT spectral peak power analysis when observation length justifies frequency domain transformation.

- **Location**: `services/detectors/beacon_detector.py`
- **Input Contract**: `shared.contracts.FeatureSnapshot` (`entity_type: "flow_pair"`)
- **Output Contract**: `shared.contracts.DetectionResult` (`detector_name: "C2BeaconDetector"`, `version: "1.0"`)

---

## 2. Mathematical Scoring & Spectral Analysis

### A. Statistical Periodicity Score ($S_{\text{periodicity}}$)
$$S_{\text{periodicity}} = \max\left(0.0, 1.0 - \min\left(1.0, \frac{\text{cv\_iat}}{0.50}\right)\right)$$

Where $\text{CV} = \frac{\sigma_{\text{iat}}}{\mu_{\text{iat}} + 1e-5}$. Low CV (< 0.20) indicates highly regular automated beaconing.

### B. SciPy FFT Spectral Analysis ($S_{\text{spectral}}$)
When sample count $N \ge 16$, Fast Fourier Transform (FFT) is performed on the zero-mean IAT time-series vector:
$$E_{\text{peak}} = \frac{\max(P(f))}{\sum P(f)}$$
$$S_{\text{spectral}} = \min\left(1.0, \frac{E_{\text{peak}}}{0.60}\right)$$

### C. Composite Score & Jitter Penalty
- **With FFT Spectral Analysis ($N \ge 16$)**:
  $$S_{\text{base}} = 0.50 \cdot S_{\text{periodicity}} + 0.30 \cdot S_{\text{spectral}} + 0.20 \cdot S_{\text{payload}}$$
- **Without Spectral Analysis ($N < 16$)**:
  $$S_{\text{base}} = 0.75 \cdot S_{\text{periodicity}} + 0.25 \cdot S_{\text{payload}}$$

If $\text{CV} > 0.40$, a jitter penalty multiplier is applied to decay the score:
$$S = S_{\text{base}} \cdot \max(0.1, 1.0 - (\text{CV} - 0.40))$$

---

## 3. Evidence Outputs & Severity Mapping

| Evidence Code | Trigger Condition | Message Description |
|---|---|---|
| `INSUFFICIENT_BEACON_SAMPLES` | `sample_count < 5` | Sample count below minimum observation threshold |
| `PERIODIC_BEACONING_SIGNAL` | `cv_iat < 0.25` | Highly regular inter-arrival intervals detected |
| `SPECTRAL_PEAK_DETECTED` | `E_peak >= 0.50` | FFT spectral peak power ratio exceeds threshold |
| `FIXED_PAYLOAD_SIZE` | `payload_size_std < 10.0` | Highly consistent outbound payload sizes |
| `BURST_TRAFFIC_FILTERED` | `cv_iat > 0.80` | Irregular connection pattern / burst traffic filtered |

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_beacon_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_beacon_detector.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_insufficient_samples`: Verified `sample_count < 5` defaults to `INFO` ($S=0.0$, `is_threat=False`) with `INSUFFICIENT_BEACON_SAMPLES` evidence.
- `test_periodic_c2_beaconing`: Verified 15-second periodic beaconing produces `HIGH`/`CRITICAL` severity ($S \ge 0.85$, `PERIODIC_BEACONING_SIGNAL`).
- `test_jittered_c2_beaconing`: Verified beaconing with small 1s jitter produces `MEDIUM`/`HIGH` severity.
- `test_burst_traffic_filtered`: Verified irregular human browsing / burst traffic produces `INFO` severity ($S < 0.35$, `BURST_TRAFFIC_FILTERED`).
- `test_spectral_fft_analysis`: Verified FFT spectral peak analysis on 32 samples produces `SPECTRAL_PEAK_DETECTED` evidence.
- Total Test Suite Status: **58 tests passed, 0 failures, 0 errors** (`OK`).
