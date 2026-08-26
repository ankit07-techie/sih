# Async Telemetry Producer Specification

## Executive Summary
This document specifies the Python `TelemetryProducer` module (`services/ingestion/telemetry_producer.py`) responsible for asynchronously streaming approved telemetry event contracts to Redpanda topics (`raw_conn`, `raw_dns`, `raw_ssl`).

---

## 1. Producer Architecture & Scope

The `TelemetryProducer` acts as the streaming egress boundary for telemetry ingestion, mapping validated Python event contract objects directly to dedicated Redpanda topics.

- **Location**: `services/ingestion/telemetry_producer.py`
- **Underlying Engine**: `aiokafka.AIOKafkaProducer` with fallback mock/dry-run capabilities for offline testing.
- **Topic Mapping**:
  - `NormalizedFlowEvent` -> Redpanda topic `raw_conn`
  - `DNSObservation` -> Redpanda topic `raw_dns`
  - `TLSObservation` -> Redpanda topic `raw_ssl`
- **Keying Strategy**: Messages are partitioned using `flow_id` as the message key (`key=event.flow_id.encode('utf-8')`), ensuring that all observations associated with a specific network flow land on the same stream partition for deterministic processing.

---

## 2. API Methods & Topic Mapping

### Methods Table

| API Method | Input Contract Class | Target Redpanda Topic | Partition Key | Serialization |
|---|---|---|---|---|
| `send_flow_event(event)` | `NormalizedFlowEvent` | `raw_conn` | `flow_id` | JSON bytes (`UTF-8`) |
| `send_dns_observation(obs)` | `DNSObservation` | `raw_dns` | `flow_id` | JSON bytes (`UTF-8`) |
| `send_tls_observation(obs)` | `TLSObservation` | `raw_ssl` | `flow_id` | JSON bytes (`UTF-8`) |

---

## 3. Error Handling & Robustness

1. **Unstarted Protection**: Invoking any `send_*` method before calling `await producer.start()` raises `TelemetryProducerError`.
2. **Contract Type Safety**: Input events are type-checked against their respective contract dataclasses. Passing invalid objects raises `ContractValidationError`.
3. **Broker Exception Wrapping**: Transmission failures or broker disconnects are caught, logged with details, and re-raised as `TelemetryProducerError` to allow upstream callers to manage retry policies cleanly.

---

## 4. Test Verification Results

Focused async unit tests are implemented in [`tests/test_telemetry_producer.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_telemetry_producer.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verification Results:
- `test_start_and_stop`: Verified async lifecycle initialization and shutdown.
- `test_send_flow_event_to_raw_conn`: Verified correct topic mapping to `raw_conn` with `flow_id` key.
- `test_send_dns_observation_to_raw_dns`: Verified correct topic mapping to `raw_dns` with `flow_id` key.
- `test_send_tls_observation_to_raw_ssl`: Verified correct topic mapping to `raw_ssl` with `flow_id` key.
- `test_publish_unstarted_error`: Verified exception handling when unstarted.
- `test_invalid_event_type_error`: Verified contract validation error when invalid type is passed.
- `test_producer_failure_handling`: Verified error handling and logging during broker failures.
- Full Suite Status: **20 tests passed, 0 failures, 0 errors** (`OK`).
