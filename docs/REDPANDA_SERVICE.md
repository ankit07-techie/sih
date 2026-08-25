# Redpanda Service Specification & Verification Guide

## Executive Summary
This document specifies the Redpanda streaming event bus service configuration, network endpoints, automated topic provisioning, health verification mechanisms, and local development workflows for PassiveShield AI.

---

## 1. Service Endpoints & Networking

Redpanda operates as the high-throughput, Kafka-compatible event streaming bus connecting ingestion producers, analytics consumers, feature extractors, threat detectors, alert services, and WebSocket transports.

| Interface | Protocol | Internal Container Endpoint | External Host Endpoint | Purpose |
|---|---|---|---|---|
| **Kafka API** | TCP (Kafka protocol) | `redpanda:9092` | `localhost:19092` | Core producer/consumer streaming traffic |
| **Schema Registry** | HTTP / REST | `http://redpanda:8081` | `http://localhost:8081` | Event schema validation & serialization |
| **HTTP Proxy** | HTTP / REST | `http://redpanda:8082` | `http://localhost:8082` | HTTP-based message publishing/consuming |
| **Redpanda Console** | HTTP / Web UI | N/A | `http://localhost:8080` | Web UI for inspecting topics, partitions, and streams |

---

## 2. Topic Architecture & Provisioning

### Topic Provisioning Approach
Topic creation is automated via the `passiveshield-redpanda-init-topics` container service during `docker compose up`. The init service waits for Redpanda broker healthcheck validation, then executes `rpk topic create` to pre-provision all pipeline topics.

### Pre-provisioned Pipeline Topics

| Topic Name | Producer Module | Consumer Modules | Data Payload Contract |
|---|---|---|---|
| `raw-flow-events` | Ingestion Producer | Analytics Consumers | `NormalizedFlowEvent` |
| `dns-observations` | Ingestion Producer | Analytics Consumers | `DNSObservation` |
| `tls-observations` | Ingestion Producer | Analytics Consumers | `TLSObservation` |
| `feature-snapshots` | Feature Engine | Independent Detectors | `FeatureSnapshot` |
| `detection-results` | P0 Detectors | Threat Fusion, Alert Bus | `DetectionResult` |
| `fused-threats` | Threat Fusion | Alert Bus | `FusedThreat` |
| `system-alerts` | Alert Bus | Socket.IO Transport, Persistence | `ThreatAlert` |

---

## 3. Health Checks & Monitoring

### Container Healthcheck
The primary `redpanda` container executes an automated `rpk` cluster health check every 10 seconds:
```bash
rpk cluster info || exit 1
```

### Manual Health Verification
To manually inspect cluster health from the host system:
```bash
# Check container status
docker compose -f infra/docker-compose.yml ps redpanda

# Inspect cluster node status inside container
docker exec -it passiveshield-redpanda rpk cluster info
```

---

## 4. Local Development Workflow

### Inspecting Topics & Partition Metadata
```bash
docker exec -it passiveshield-redpanda rpk topic list
docker exec -it passiveshield-redpanda rpk topic describe raw-flow-events
```

### Producing Test Messages via CLI
```bash
docker exec -it passiveshield-redpanda rpk topic produce raw-flow-events
# Type JSON string and press Enter:
# {"src_ip": "192.168.1.50", "dst_ip": "10.0.0.1", "dst_port": 80, "bytes": 1024}
```

### Consuming Messages via CLI
```bash
docker exec -it passiveshield-redpanda rpk topic consume raw-flow-events --num 5
```

### Programmatic Connection Examples

#### Python Client (`confluent-kafka` or `kafka-python-ng`):
```python
from kafka import KafkaProducer
import json

producer = KafkaProducer(
    bootstrap_servers=['localhost:19092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

producer.send('raw-flow-events', {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.5'})
producer.flush()
```

#### Node.js Client (`kafkajs`):
```javascript
const { Kafka } = require('kafkajs');

const kafka = new Kafka({
  clientId: 'passiveshield-app',
  brokers: ['localhost:19092']
});

const consumer = kafka.consumer({ groupId: 'alert-group' });
```
