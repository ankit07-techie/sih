# Bounded Redis Sliding-Window State Specification

## Executive Summary
This document specifies the implementation, key naming standards, TTL eviction mechanics, bounded window data structures, and test verification for the `RedisStateManager` module (`services/state/redis_state.py`).

---

## 1. Module Architecture & Scope

The `RedisStateManager` manages temporal sliding-window metrics in Redis (or in-memory mock driver fallback), providing fast, low-latency state aggregation for downstream analytics consumers and feature extractors.

- **Location**: `services/state/redis_state.py`
- **Key Prefix**: `passiveshield:state:`
- **Eviction Strategy**: Bounded sliding windows + mandatory TTL assignment (`EXPIRE key window_seconds + 30`) + Redis container `volatile-lru` policy.
- **Detector Independence**: Contains **zero detector scoring algorithms**. Provides clean metric aggregation APIs (`record_flow_metrics`, `record_unique_target`, `record_inter_arrival`).

---

## 2. Key Naming Standards & Data Structures

| Key Pattern | Redis Type | Description | Target Use Case |
|---|---|---|---|
| `passiveshield:state:flow:<src_ip>:<window>s` | `HASH` | Aggregates `flow_count`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` | Traffic rate surges & DDoS feature extraction |
| `passiveshield:state:targets:<src_ip>:<target_type>:<window>s` | `SET` | Unordered set of unique destination ports or IP addresses | Port scanning & fan-out feature extraction |
| `passiveshield:state:beacon:<src_ip>:<dst_ip>` | `ZSET` | Timestamps stored as member and score, capped at `max_history` (100) | C2 beaconing inter-arrival time (IAT) analysis |

---

## 3. Bounded State Enforcement Rules

1. **Mandatory Expiration**: Every write operation (`hincrby`, `sadd`, `zadd`) automatically sets an explicit TTL matching the sliding window duration plus a 30-second buffer (`ttl = window_seconds + 30`).
2. **Bounded ZSET Capping**: `record_inter_arrival()` automatically trims old timestamps (`zremrangebyrank`) when the set cardinality exceeds `max_history` (default: 100 items), preventing unbounded memory growth on long-running connection pairs.
3. **Mock Driver Fallback**: Includes `MockRedisDriver` providing in-memory hash, set, sorted set, and TTL expiration logic for zero-dependency testing without requiring a live Redis daemon.

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_redis_state.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_redis_state.py).

### Test Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_flow_metrics_aggregation`: Verified flow count, byte, and packet aggregation over sliding windows.
- `test_unique_target_fanout`: Verified unique port set tracking and duplicate rejection.
- `test_inter_arrival_timestamps_bounded_capping`: Verified `ZSET` time ordering and strict `max_history` size capping.
- `test_ttl_expiration`: Verified automatic expiration of expired state keys in `MockRedisDriver`.
- `test_key_naming_convention`: Verified key formatting compliance with `docs/REDIS_SERVICE.md`.
- Total Test Suite Status: **34 tests passed, 0 failures, 0 errors** (`OK`).
