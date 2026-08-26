# Telemetry Stream Pipeline Integration Specification & Verification

## Executive Summary
This document specifies the integration architecture, data flow stages, topic routing, error handling, and deterministic verification results for the end-to-end telemetry ingestion stream:
`tcpreplay/Input -> Zeek -> ZeekAdapter -> Telemetry Event Contracts -> TelemetryProducer -> Redpanda Topics`.

---

## 1. Integrated Pipeline Architecture

```
[ PCAP / Traffic Fixture ]
            │
            ▼
   [ tcpreplay Runner ]  <-- (replay/replay_runner.py)
            │
            ▼
      [ Zeek Engine ]    <-- (config/zeek/local.zeek)
            │
            ▼ (Raw JSON Logs: conn.log, dns.log, ssl.log)
  [ Zeek Output Adapter ]  <-- (services/ingestion/zeek_adapter.py)
            │
            ▼ (Dict Schemas)
[ Versioned Contracts ]  <-- (shared/contracts/telemetry.py)
            │
            ▼ (NormalizedFlowEvent / DNSObservation / TLSObservation)
 [ Telemetry Producer ]  <-- (services/ingestion/telemetry_producer.py)
            │
            ├──> Topic 'raw_conn'  (Flow Telemetry)
            ├──> Topic 'raw_dns'   (DNS Telemetry)
            └──> Topic 'raw_ssl'   (TLS Telemetry)
```

---

## 2. Pipeline Data Flow Stages & Topic Routing

| Pipeline Stage | Module / Component | Data Format / Protocol | Redpanda Target Topic |
|---|---|---|---|
| **1. Input Telemetry** | Replay Runner / Zeek Tap | Raw PCAP / Ethernet Frames | N/A |
| **2. Log Generation** | Zeek Engine (`local.zeek`) | JSON lines (`conn.log`, `dns.log`, `ssl.log`) | N/A |
| **3. Log Parsing** | `ZeekAdapter` | Internal Dictionary Schemas | N/A |
| **4. Contract Conversion** | Telemetry Event Contracts | Type-safe Dataclass Objects | N/A |
| **5. Stream Publishing** | `TelemetryProducer` | Async JSON Bytes (`UTF-8`) | `raw_conn`, `raw_dns`, `raw_ssl` |

---

## 3. Observed Behavior & Isolation Safeguards

1. **Passive Boundary Guarantee**: Ingestion operates strictly in read-only mode from passive PCAPs or Zeek log spools. No packets are transmitted to monitored networks.
2. **Robust Fault Isolation**:
   - Corrupt or malformed Zeek JSON lines return `None` in `ZeekAdapter` without halting log reading.
   - Events failing contract validation are logged as warnings and skipped without crashing the pipeline loop.
   - Redpanda broker disconnects raise recoverable `TelemetryProducerError` instances for upstream retry.
3. **Partition Keying**: All messages are keyed by `flow_id` to guarantee that all telemetry events belonging to a specific network session are delivered in order to the same stream partition.

---

## 4. Integration Test Verification

The integration pipeline is tested via [`tests/test_stream_pipeline.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_stream_pipeline.py).

### Test Command:
```bash
py -3 -m unittest discover tests
```

### Verified Pipeline Behaviors:
- **`conn.log` Stream**: Successfully parsed sample `conn.log` lines, converted to `NormalizedFlowEvent`, and published to `raw_conn`.
- **`dns.log` Stream**: Successfully parsed sample `dns.log` lines, converted to `DNSObservation`, and published to `raw_dns`.
- **`ssl.log` Stream**: Successfully parsed sample `ssl.log` lines, converted to `TLSObservation`, and published to `raw_ssl`.
- **Directory Ingestion Runner**: Processed sample fixtures in `fixtures/sample_zeek_logs/` and returned verified telemetry count statistics.
- **Test Suite Status**: **22/22 unit and integration tests passed** (`OK`).
