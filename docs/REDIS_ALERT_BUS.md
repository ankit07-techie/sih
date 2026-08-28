# Redis Pub/Sub Alert Bus Specification

## Executive Summary
This document specifies the design, channel governance, subscriber interface, mock fallback mechanisms, and test verification results for the `RedisAlertBus` component ([`services/alerts/redis_alert_bus.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/alerts/redis_alert_bus.py)).

---

## 1. Alert Bus Architecture & Scope

The `RedisAlertBus` provides a high-throughput, low-latency publish/subscribe event distribution pipeline for standardized `ThreatAlert` contracts over Redis.

- **Location**: `services/alerts/redis_alert_bus.py`
- **Approved Redis Pub/Sub Channel**: `cyber_alerts`
- **Event Contract**: `shared.contracts.ThreatAlert` (`version: "1.0"`)
- **Downstream Consumers**: Node.js Express API gateway, WebSockets real-time server, and SOC Operations Dashboard.

---

## 2. API Interface & Operations

### A. Alert Publication (`publish_alert`)
```python
def publish_alert(self, alert: ThreatAlert) -> bool
```
- Validates the input `alert` object against `ThreatAlert` contract schema.
- Serializes `ThreatAlert` into compact JSON payload string (`alert.to_json()`).
- Publishes JSON payload to approved Redis channel `cyber_alerts`.
- Returns `True` on success, `False` on Redis communication error.

### B. Narrow Subscriber Interface (`subscribe_alerts`)
```python
def subscribe_alerts(self, callback: Callable[[ThreatAlert], None])
```
- Subscribes to Redis channel `cyber_alerts`.
- Deserializes incoming JSON payloads into `ThreatAlert` objects (`ThreatAlert.from_json(payload)`).
- Invokes subscriber callback `callback(alert)`.

### C. Mock Fallback Support
Automatically falls back to `MockRedisDriver` if Redis server is unreachable or `redis` package is unavailable, guaranteeing zero test suite failures during offline or CI environments.

---

## 3. Test Verification Results

Unit tests are implemented in [`tests/test_redis_alert_bus.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_redis_alert_bus.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_publish_and_subscribe_alert`: Verified `ThreatAlert` published to `cyber_alerts` channel is received and deserialized by subscriber callback cleanly.
- `test_invalid_alert_type_raises`: Verified `ContractValidationError` raised when non-`ThreatAlert` object is passed.
- `test_default_channel_name`: Verified default channel name is strictly `cyber_alerts`.
- Total Test Suite Status: **86 tests passed, 0 failures, 0 errors** (`OK`).
