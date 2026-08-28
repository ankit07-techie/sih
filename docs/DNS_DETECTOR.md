# Approved DNS Anomaly Threat Detector Implementation

## Executive Summary
This document specifies the implementation, mathematical scoring formulation, distinct DGA vs. DNS Tunneling evidence tagging, and test verification results for the `DNSAnomalyDetector` component ([`services/detectors/dns_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/detectors/dns_detector.py)).

---

## 1. Detector Architecture & Scope

The `DNSAnomalyDetector` evaluates streaming `FeatureSnapshot` event contracts for DNS anomalies, maintaining strict evidentiary separation between Domain Generation Algorithms (DGA) and DNS Tunneling data exfiltration patterns.

- **Location**: `services/detectors/dns_detector.py`
- **Input Contract**: `shared.contracts.FeatureSnapshot` (`entity_type: "domain"`)
- **Output Contract**: `shared.contracts.DetectionResult` (`detector_name: "DNSAnomalyDetector"`, `version: "1.0"`)

---

## 2. Mathematical Sub-Scoring Formulation

### A. DGA Suspicion Sub-Score ($S_{\text{dga}}$)
Focuses on algorithmic randomness, high entropy, digit density, consecutive consonants, and NXDOMAIN resolution failures:
$$S_{\text{dga}} = 0.35 \cdot S_{\text{entropy}} + 0.25 \cdot S_{\text{digits}} + 0.20 \cdot S_{\text{consonants}} + 0.20 \cdot S_{\text{nxdomain}}$$

### B. DNS Tunneling Suspicion Sub-Score ($S_{\text{tunnel}}$)
Focuses on excessive subdomain length, deep subdomain nesting, TXT record queries, and high 2-gram character entropy:
$$S_{\text{tunnel}} = 0.40 \cdot S_{\text{subdomain\_len}} + 0.25 \cdot S_{\text{subdomain\_depth}} + 0.20 \cdot S_{\text{txt\_query}} + 0.15 \cdot S_{\text{bigram\_entropy}}$$

### C. Composite Score
$$S = \max(S_{\text{dga}}, S_{\text{tunnel}})$$

---

## 3. Distinguishable Evidence Vector Tagging

### A. DGA-Specific Evidence
- `DGA_HIGH_ENTROPY`: High Shannon entropy in domain string ($\ge 3.5$).
- `DGA_DIGIT_DENSITY`: High numeric digit ratio ($\ge 25\%$).
- `DGA_CONSONANT_CLUSTER`: Long sequence of consecutive consonants ($\ge 5$).
- `DGA_NXDOMAIN_FAILURE`: Query resulted in `NXDOMAIN` failure.

### B. Tunneling-Specific Evidence
- `TUNNEL_SUBDOMAIN_LENGTH`: Excessive subdomain payload length ($\ge 20$ chars).
- `TUNNEL_DEEP_SUBDOMAIN`: Deeply nested subdomain structure ($\ge 3$ labels).
- `TUNNEL_TXT_QUERY`: DNS `TXT` record query used for exfiltration.
- `TUNNEL_HIGH_BIGRAM_ENTROPY`: High 2-gram character entropy ($\ge 3.0$).

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_dns_detector.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_dns_detector.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_benign_domain`: Verified benign domain `google.com` produces `INFO` severity ($S < 0.35$, `is_threat=False`).
- `test_dga_domain_detection`: Verified DGA domain produces `HIGH`/`CRITICAL` severity ($S \ge 0.85$) with `DGA_HIGH_ENTROPY`, `DGA_DIGIT_DENSITY`, and `DGA_NXDOMAIN_FAILURE` evidence (and zero tunneling tags).
- `test_dns_tunneling_detection`: Verified long tunneling payload produces `HIGH`/`CRITICAL` severity with `TUNNEL_SUBDOMAIN_LENGTH`, `TUNNEL_DEEP_SUBDOMAIN`, and `TUNNEL_TXT_QUERY` evidence (and zero DGA tags).
- Total Test Suite Status: **65 tests passed, 0 failures, 0 errors** (`OK`).
