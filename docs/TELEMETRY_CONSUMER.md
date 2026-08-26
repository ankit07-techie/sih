# Async Telemetry Stream Consumer Specification

## Executive Summary
This document specifies the Python `TelemetryConsumer` module (`services/analytics/telemetry_consumer.py`) responsible for asynchronously subscribing to Redpanda telemetry topics (`raw_conn`, `raw_dns`, `raw_ssl`), deserializing incoming JSON payloads into versioned contract objects, and dispatching events to analytical handlers.

---

## 1. Consumer Architecture & Scope

The `TelemetryConsumer` acts as the stream ingress foundation for analytics and feature calculation, consuming raw telemetry messages from Redpanda topics and converting them into type-safe contract dataclasses.

- **Location**: `services/analytics/telemetry_consumer.py`
- **Underlying Engine**: `aiokafka.AIOKafkaConsumer` with mock/dry-run capabilities for offline testing.
- **Consumer Group**: Default group ID `passiveshield-analytics-group`.
- **Topic Subscriptions**: `raw_conn`, `raw_dns`, `raw_ssl` (also supports aliases `raw-flow-events`, `dns-observations`, `tls-observations`).

---

## 2. Topic Mapping & Contract Deserialization

### Topic to Contract Mapping

| Subscribed Topic | Event Type | Target Data Contract Model |
|---|---|---|
| `raw_conn` / `raw-flow-events` | `NormalizedFlowEvent` | `shared.contracts.NormalizedFlowEvent` |
| `raw_dns` / `dns-observations` | `DNSObservation` | `shared.contracts.DNSObservation` |
| `raw_ssl` / `tls-observations` | `TLSObservation` | `shared.contracts.TLSObservation` |

---

## 3. Lifecycle & Error Handling Strategy

1. **Async Lifecycle**: Managed via `await consumer.start()` and `await consumer.stop()`.
2. **Graceful Fault Tolerance**:
   - Corrupt JSON bytes or invalid payloads log warnings and return `None` without interrupting `consume_loop()`.
   - Payload messages failing contract validation (e.g. invalid IP strings or out-of-range ports) are safely discarded without crashing the worker process.
3. **Async Handler Dispatching**: Supports both coroutine functions (`async def handler`) and synchronous callbacks (`def handler`). Exceptions raised inside handlers are caught, logged, and isolated from the primary message fetch loop.

---

## 4. Test Verification Results

Async unit tests are implemented in [`tests/test_telemetry_consumer.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_telemetry_consumer.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verification Results:
- `test_start_and_stop_lifecycle`: Verified async start/stop connection lifecycle.
- `test_parse_message_payload_flow`: Verified `raw_conn` message deserialization into `NormalizedFlowEvent`.
- `test_parse_message_payload_dns`: Verified `raw_dns` message deserialization into `DNSObservation`.
- `test_parse_message_payload_ssl`: Verified `raw_ssl` message deserialization into `TLSObservation`.
- `test_parse_malformed_payload`: Verified non-crashing handling of invalid IP payloads.
- `test_consume_loop_with_mock_stream`: Verified end-to-end async message loop and handler dispatching across `raw_conn` and `raw_dns` streams.
- `test_consume_unstarted_error`: Verified exception raising when consuming while unstarted.
- Full Test Suite Status: **29 tests passed, 0 failures, 0 errors** (`OK`).
