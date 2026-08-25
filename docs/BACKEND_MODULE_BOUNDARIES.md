# Backend Module Boundaries & Dependency Topology

## Executive Summary
This document specifies the precise single-responsibility boundaries, data ownership, input/output contracts, and dependency rules for all backend components in PassiveShield AI. It establishes strict decoupling between network ingestion, streaming event infrastructure, state tracking, feature extraction, independent detectors, threat fusion, alert management, and real-time API transport.

---

## Architecture Topology Overview

```
[ Monitored Network Tap / PCAP ]
               │
               ▼ (Passive Output)
            [ Zeek ]
               │ (Raw conn/dns/ssl logs)
               ▼
           [ Producer ]
               │ (NormalizedFlowEvent / DNSObservation)
               ▼
       [ Redpanda Topics ] ◄─── (Streaming Bus)
         │           │
         ▼           ▼
[ Analytics Consumers ] ──► [ Redis State Store ]
                                  │
                                  ▼
                         [ Feature Engine ]
                                  │
                                  ▼ (FeatureSnapshot)
                       [ Redpanda Topics ]
                                  │
                                  ▼
                      [ Independent Detectors ]
                    (DDoS | PortScan | C2 | DNS)
                                  │
                                  ▼ (DetectionResult)
                        [ Threat Fusion ]
                                  │
                                  ▼ (FusedThreat)
                         [ Alert Bus ]
                         │          │
                         ▼          ▼
             [ Persistence DB ]   [ Redpanda: system-alerts ]
                         │                  │
                         ▼                  ▼
                   [ Express API ]   [ Socket.IO Service ]
                         │                  │
                         └────────┬─────────┘
                                  ▼
                           [ SOC Dashboard ]
```

---

## Detailed Module Ownership & Dependencies

### 1. Zeek (Network Telemetry Engine)
- **Primary Responsibility**: Passively captures IP network packets or reads PCAP replay files; parses binary network protocols into structured log files (`conn.log`, `dns.log`, `ssl.log`, `http.log`).
- **Input Boundary**: Monitored passive network interface (read-only) or local PCAP replay file.
- **Output Boundary**: Raw Zeek tab-delimited or JSON log files written to local spool/pipe.
- **Dependencies**:
  - *Upstream*: Monitored passive network stream / PCAP file.
  - *Downstream*: Consumed by Ingestion Producer.
  - *Forbidden*: Direct interaction with application databases, Redis, Express API, Detectors, or UI.

### 2. Producer (Ingestion Producer Adapter)
- **Primary Responsibility**: Tails raw Zeek logs or reads PCAP streams; parses and validates raw telemetry; normalizes observations into versioned internal data contracts (`NormalizedFlowEvent`, `DNSObservation`, `TLSObservation`); publishes normalized events to Redpanda topics.
- **Input Boundary**: Raw Zeek log streams / PCAP reader.
- **Output Boundary**: Published messages on Redpanda `raw-flow-events`, `dns-observations`, and `tls-observations` topics.
- **Dependencies**:
  - *Upstream*: Zeek log streams.
  - *Shared Contracts*: `NormalizedFlowEvent`, `DNSObservation`, `TLSObservation` models.
  - *Infrastructure*: Redpanda Producer Client.

### 3. Redpanda Topics (Streaming Event Bus)
- **Primary Responsibility**: High-throughput, distributed, ordered event streaming backbone. Decouples event producers from consumers and isolates data pipelines into distinct topics.
- **Topics**:
  - `raw-flow-events`: Normalized IP flow telemetry.
  - `dns-observations`: Normalized DNS query/response events.
  - `tls-observations`: Normalized TLS handshake metadata.
  - `feature-snapshots`: Aggregated feature vectors for time windows.
  - `detection-results`: Raw detection outputs from individual detectors.
  - `fused-threats`: Correlated multi-detector threat assessments.
  - `system-alerts`: Standardized, validated security alerts for delivery.
- **Dependencies**:
  - *Infrastructure*: Redpanda/Kafka cluster instance.

### 4. Analytics Consumers
- **Primary Responsibility**: Consumes normalized event streams (`raw-flow-events`, `dns-observations`) from Redpanda; maintains temporal sliding windows and aggregates traffic counters/metrics.
- **Input Boundary**: Redpanda topics (`raw-flow-events`, `dns-observations`).
- **Output Boundary**: Write operations to Redis State Store.
- **Dependencies**:
  - *Infrastructure*: Redpanda Consumer Client, Redis Client.
  - *Shared Contracts*: `NormalizedFlowEvent`, `DNSObservation`.

### 5. Redis State (Bounded State Store)
- **Primary Responsibility**: Provides low-latency, bounded temporal state storage. Manages sliding time-windows, IP packet/byte counters, connection sets, inter-arrival timestamps, and TTL expiration to prevent unbounded memory growth.
- **Input Boundary**: Write operations from Analytics Consumers.
- **Output Boundary**: Read operations by Feature Engine.
- **Dependencies**:
  - *Infrastructure*: Redis server instance.

### 6. Features (Feature Extraction Engine)
- **Primary Responsibility**: Periodically or event-trigger queries Redis State Store; calculates normalized feature vectors (`FeatureSnapshot`) for active entities (e.g. source IP, destination IP, domain name) across configured sliding windows (e.g. 10s, 60s, 300s); publishes snapshots to Redpanda.
- **Input Boundary**: State queries to Redis State Store.
- **Output Boundary**: Published `FeatureSnapshot` messages on Redpanda `feature-snapshots` topic.
- **Dependencies**:
  - *Upstream*: Redis State Store interface.
  - *Shared Contracts*: `FeatureSnapshot` model.
  - *Infrastructure*: Redpanda Producer Client.

### 7. Each Detector (Independent P0 Detectors)
- **Primary Responsibility**: Consumes `FeatureSnapshot` streams from Redpanda. Evaluates specialized detection logic independently and deterministically without cross-detector coupling. Emits `DetectionResult` with structured `ThreatEvidence`.
- **Individual Detector Logic**:
  - **DDoS / Flood Detector**: Evaluates packet/byte rate surges, SYN/ACK ratio imbalance, and source IP entropy drops.
  - **Port Scan Detector**: Evaluates unique destination ports/IPs fan-out count, connection attempt growth, and unacknowledged SYN ratios.
  - **C2 Beaconing Detector**: Evaluates inter-arrival time (IAT) variance, coefficient of variation, periodicity, and autocorrelation metrics.
  - **DNS Anomaly Detector**: Evaluates DGA domain length, Shannon entropy, digit ratios, and DNS tunnelling depth/entropy metrics.
- **Input Boundary**: Redpanda `feature-snapshots` topic.
- **Output Boundary**: Published `DetectionResult` messages on Redpanda `detection-results` topic.
- **Dependencies**:
  - *Shared Contracts*: `FeatureSnapshot`, `DetectionResult`, `ThreatEvidence`.
  - *Infrastructure*: Redpanda Consumer/Producer Client.
  - *Forbidden*: Direct imports between detectors; direct database or UI dependencies.

### 8. Fusion (Threat Fusion Engine)
- **Primary Responsibility**: Consumes `DetectionResult` messages from Redpanda `detection-results` topic; correlates co-occurring detections targeting the same entity within overlapping time windows; combines confidence scores and severity levels; emits `FusedThreat` events.
- **Input Boundary**: Redpanda `detection-results` topic.
- **Output Boundary**: Published `FusedThreat` messages on Redpanda `fused-threats` topic.
- **Dependencies**:
  - *Shared Contracts*: `DetectionResult`, `FusedThreat`.
  - *Infrastructure*: Redpanda Consumer/Producer Client.

### 9. Alert Bus (Alert Management & Lifecycle Service)
- **Primary Responsibility**: Consumes `FusedThreat` and un-fused `DetectionResult` streams; assigns unique Alert UUIDs; validates threat alerts; enforces rate-limiting and deduplication rules; persists alerts to primary database storage; publishes final `ThreatAlert` to Redpanda.
- **Input Boundary**: Redpanda `fused-threats` and `detection-results` topics.
- **Output Boundary**: Primary Database (write) & Redpanda `system-alerts` topic.
- **Dependencies**:
  - *Shared Contracts*: `FusedThreat`, `DetectionResult`, `ThreatAlert`.
  - *Infrastructure*: Primary Persistence DB Client, Redpanda Consumer/Producer Client.

### 10. Express API (REST Backend Gateway)
- **Primary Responsibility**: Serves HTTP REST endpoints for client dashboard queries (alert history search, evidence inspection detail lookup, system metrics, replay control triggering).
- **Input Boundary**: Client HTTP requests (`/api/v1/alerts`, `/api/v1/evidence/:id`, `/api/v1/replay`, `/api/v1/health`).
- **Output Boundary**: JSON REST responses.
- **Dependencies**:
  - *Upstream Interface*: Primary Persistence DB (read-only queries), Replay Engine Controller.
  - *Forbidden*: Direct execution of detector algorithms or raw packet manipulation.

### 11. Socket.IO (Real-Time WebSocket Transport)
- **Primary Responsibility**: Subscribes to Redpanda `system-alerts` topic (or Alert Bus stream); broadcasts real-time security alerts, live traffic metrics, and system status updates to connected SOC Dashboard WebSocket clients.
- **Input Boundary**: Redpanda `system-alerts` topic / Alert Bus event stream.
- **Output Boundary**: Real-time WebSocket event emission (`alert:new`, `metrics:tick`, `status:change`) to connected browser clients.
- **Dependencies**:
  - *Shared Contracts*: `ThreatAlert`, `SystemMetrics`.
  - *Infrastructure*: Socket.IO server library, Redpanda Consumer Client.

---

## Inter-Module Isolation Matrix

| Source Module | May Depend On | Must NEVER Depend On |
|---|---|---|
| **Zeek** | Monitored Network Tap / PCAP | Backend APIs, Databases, Redis, Detectors, UI |
| **Producer** | Zeek logs, Shared Contracts, Redpanda Producer | Detector logic, Database, Express API, UI |
| **Analytics Consumers** | Redpanda Consumer, Redis Client, Shared Contracts | Detector logic, Express API, UI |
| **Feature Engine** | Redis Client, Shared Contracts, Redpanda Producer | Detector algorithms, Express API, UI |
| **Detectors** | Redpanda Consumer/Producer, Shared Contracts | Other Detectors, Database, Express API, Socket.IO, UI |
| **Threat Fusion** | Redpanda Consumer/Producer, Shared Contracts | Raw packet feeds, Redis State, Express API, UI |
| **Alert Bus** | Redpanda Consumer/Producer, Shared Contracts, Persistence DB | Detector internal logic, UI |
| **Express API** | Persistence DB, Replay Controller, Express Framework | Detector algorithms, Raw packet capture |
| **Socket.IO** | Redpanda Consumer, Socket.IO Server, Shared Contracts | Detector algorithms, Direct DB writes |
