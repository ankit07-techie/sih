# Backend End-to-End Integration Specification

## Executive Summary
This document specifies the design, data transformations, component pipeline stages, contract flows, and test verification results for the complete backend end-to-end integration ([`tests/test_e2e_pipeline.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_e2e_pipeline.py)).

---

## 1. End-to-End Pipeline Data Flow

```
Replay Controller (PCAP/Zeek)
       │
       ▼
Zeek Ingestion Adapter (conn.log, dns.log, ssl.log)
       │
       ▼
Redpanda Event Bus (raw_conn, raw_dns, raw_ssl)
       │
       ▼
Python Telemetry Consumer & Sliding-Window Feature Extractors
       │
       ▼
Bounded Redis State Manager (sliding windows & unique sets)
       │
       ▼
Independent Threat Detectors (DDoS, PortScan, Beacon, DNS, Exfil, TLS)
       │
       ▼
Threat Fusion Engine (Probabilistic Score Fusion & Evidence Preservation)
       │
       ▼
Standardized ThreatAlert Contract Construction
       │
       ▼
Redis Pub/Sub Alert Bus ('cyber_alerts' channel)
       │
       ▼
Node.js Express API & Socket.IO Real-Time Gateway ('alert:new' event stream)
```

---

## 2. Test Verification Results

The deterministic end-to-end pipeline test is implemented in [`tests/test_e2e_pipeline.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_e2e_pipeline.py).

### Execution Command:
```bash
py -3 -m unittest tests/test_e2e_pipeline.py
```

### Verified Pipeline Stages:
1. **Zeek Log Parsing**: `ZeekAdapter` parses `conn.log` and `ssl.log` JSON lines into `NormalizedFlowEvent` and `TLSObservation` contracts.
2. **State Manager Update**: `RedisStateManager` records flow byte/packet metrics and vertical port scan target sets.
3. **Feature Extraction & Multi-Detector Scoring**:
   - `PortScanFeatureExtractor` computes vertical scan metrics -> `PortScanDetector` outputs $S > 0.85$ threat result (`VERTICAL_PORT_SCAN`).
   - `ExfiltrationDetector` analyzes 15MB burst transfer -> outputs $S > 0.90$ threat result (`EXFIL_HIGH_BURST_VOLUME`).
   - `TLSMetadataAnalyzer` analyzes Cobalt Strike JA3 hash -> outputs $S = 0.95$ threat result (`JA3_MALWARE_SIGNATURE_MATCH`).
4. **Threat Fusion**: `ThreatFusionEngine` fuses all 3 threat results, applying multi-vector correlation boost ($S_{\text{fused}} \ge 0.95$, `CRITICAL` severity, 5 evidence items preserved).
5. **Contract Conversion & Redis Alert Bus Delivery**: Standardized `ThreatAlert` contract published to Redis channel `cyber_alerts` and received by subscriber callback.
6. **Total System Test Status**: **87 Python tests passed, 12 Node.js tests passed (0 failures)** (`OK`).
