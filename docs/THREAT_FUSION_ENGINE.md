# Multi-Detector Threat Fusion Engine Specification

## Executive Summary
This document specifies the design, mathematical score fusion formula, deduplication algorithms, severity normalization rules, evidence preservation mechanisms, and test verification results for the `ThreatFusionEngine` component ([`services/analytics/threat_fusion.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/analytics/threat_fusion.py)).

---

## 1. Engine Architecture & Scope

The `ThreatFusionEngine` correlates and aggregates streaming `DetectionResult` contracts emitted by independent threat detectors (`DDoSDetector`, `PortScanDetector`, `C2BeaconDetector`, `DNSAnomalyDetector`, `ExfiltrationDetector`, `TLSMetadataAnalyzer`) into unified `FusedThreatAlert` contracts.

- **Location**: `services/analytics/threat_fusion.py`
- **Input Contract**: `shared.contracts.DetectionResult`
- **Output Contract**: `shared.contracts.FusedThreatAlert` (`event_type: "FusedThreatAlert"`, `version: "1.0"`)

---

## 2. Multi-Detector Score Fusion & Deduplication

### A. Deduplication & Highest-Score Filtering
For a given entity (`entity_id`), multiple results from the same detector are deduplicated by keeping the instance with the highest confidence score $S_{\text{max}}$.

### B. Probabilistic Multi-Detector Fusion
Combines confidence scores across independent detectors using probabilistic independence:
$$S_{\text{combined}} = 1.0 - \prod_{i=1}^K \left(1.0 - \min(0.99, S_i \cdot w_i)\right)$$

Where $w_i$ is detector credibility weight ($1.0$ default).

### C. Multi-Vector Correlation Boost
If 2 or more distinct threat detectors trigger on the same entity (e.g. `PortScanDetector` + `ExfiltrationDetector`), a $1.15\times$ correlation multiplier is applied:
$$S_{\text{fused}} = \min\left(1.0, S_{\text{combined}} \cdot 1.15\right)$$

---

## 3. Severity Normalization & Evidence Preservation

### A. Severity Normalization Mapping
| Fused Confidence Score ($S_{\text{fused}}$) | Normalized Severity | `is_threat` |
|---|---|---|
| $S_{\text{fused}} < 0.35$ | `INFO` | `False` |
| $0.35 \le S_{\text{fused}} < 0.60$ | `LOW` | `True` |
| $0.60 \le S_{\text{fused}} < 0.85$ | `MEDIUM` | `True` |
| $0.85 \le S_{\text{fused}} < 0.95$ | `HIGH` | `True` |
| $S_{\text{fused}} \ge 0.95$ | `CRITICAL` | `True` |

### B. Evidence Preservation & Provenance Tagging
All diagnostic `ThreatEvidence` items from all contributing detectors are preserved without data loss. Each evidence item is tagged with `detector_source` metadata indicating its originating detector. Duplicate evidence keys (`detector_name:code:message`) are merged.

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_threat_fusion.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_threat_fusion.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_single_detector_fusion`: Verified single detector `DetectionResult` fuses into `FusedThreatAlert` preserving score, evidence, and severity.
- `test_multi_detector_fusion`: Verified correlation boost when `PortScanDetector` ($0.75$) and `ExfiltrationDetector` ($0.85$) combine to produce `CRITICAL` severity ($S_{\text{fused}} > 0.95$).
- `test_duplicate_result_handling`: Verified duplicate detector results keep highest confidence score and deduplicate evidence.
- `test_empty_results`: Verified empty input returns `None`.
- Total Test Suite Status: **79 tests passed, 0 failures, 0 errors** (`OK`).
