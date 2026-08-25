# Redis v7+ Service Specification & State Boundary Guide

## Executive Summary
This document specifies the Redis v7+ service configuration, bounded state storage boundaries, Pub/Sub usage policies, key naming conventions, Time-To-Live (TTL) eviction strategies, and health verification for PassiveShield AI.

---

## 1. State Usage Boundary

Redis operates strictly as a **low-latency, bounded, in-memory state store**. It provides sliding-window aggregation support for the Analytics Consumers and Feature Extraction Engine.

### What Redis IS Used For:
- **Sliding Window Counters**: Packet counts, byte counts, and connection rates over short sliding windows (e.g., 10s, 60s, 300s).
- **Entity Fan-out Tracking**: Sets of unique destination IPs or ports accessed by a source host within a time window.
- **Inter-Arrival Time (IAT) Buffers**: Sorted sets (`ZSET`) or lists storing recent connection timestamps for C2 beaconing analysis.
- **DNS Query Metrics**: Subdomain entropy counters and query frequency maps.
- **Ephemeral Session Tokens**: Short-lived auth or rate-limiting state for the Express API.

### What Redis MUST NOT Be Used For:
- **Long-Term Alert History**: All security alerts, audit logs, and metrics history belong strictly in PostgreSQL.
- **Durable Event Streaming**: Core pipeline events (`raw-flow-events`, `feature-snapshots`, `detection-results`) MUST be streamed through Redpanda topics, not Redis data structures.
- **Persistent Data Storage**: Redis memory is volatile and bounded; no critical system state may rely on Redis disk persistence.

---

## 2. Pub/Sub Usage Boundary

### Pub/Sub Guidelines
- **Allowed Use Cases**: Transient worker notifications, local cache invalidation signals, or lightweight internal heartbeat broadcasts.
- **Forbidden Use Cases**: Core threat detection pipelines, alert delivery, or event streaming. All core backend components MUST consume structured events via Redpanda topics to ensure durability, ordering, and replay capability.

---

## 3. Key Naming & TTL Strategy

### Key Naming Convention
To prevent namespace collisions and enforce auditability, all Redis keys MUST follow the standardized pattern:

```
passiveshield:<module>:<entity_type>:<entity_id>:<window_size>
```

### Standard Key Naming Examples

| Key Pattern | Module | Description | Example Key |
|---|---|---|---|
| `passiveshield:state:ip_flow:<src_ip>:<window>` | Analytics | Flow volume & packet counters for source IP | `passiveshield:state:ip_flow:192.168.1.50:60s` |
| `passiveshield:state:port_scan:<src_ip>:<window>` | Analytics | Set of unique destination ports accessed | `passiveshield:state:port_scan:10.0.0.5:10s` |
| `passiveshield:state:beacon:<src_ip>:<dst_ip>` | Analytics | Connection inter-arrival timestamps (ZSET) | `passiveshield:state:beacon:192.168.1.100:10.0.0.1` |
| `passiveshield:state:dns_entropy:<domain>:<window>` | Analytics | Subdomain count & entropy metrics | `passiveshield:state:dns_entropy:example.com:300s` |

### TTL (Time-To-Live) Strategy
To guarantee **bounded memory usage** and zero memory leaks:
1. **Mandatory Expiration**: Every write operation (`SET`, `HSET`, `ZADD`, `EXPIRE`) MUST set an explicit TTL matching or slightly exceeding the maximum sliding window duration (e.g., window + 30s buffer).
2. **Eviction Policy**: Redis is configured with `maxmemory-policy volatile-lru`. If memory reaches the 512MB container limit, Redis automatically evicts the least recently used keys that have an explicit TTL set.

---

## 4. Service Configuration & Health Verification

### Configuration File (`infra/redis.conf`)
- **Version**: Redis 7.x (Alpine)
- **Memory Limit**: `maxmemory 512mb`
- **Eviction Policy**: `volatile-lru`
- **Lazy Eviction**: `lazyfree-lazy-eviction yes` for un-blocking high-throughput deletes.

### Healthcheck Command
The container health check verifies connectivity using `redis-cli ping` with password authentication:
```bash
redis-cli -a "${REDIS_PASSWORD}" ping
```

### Manual Verification
From the host environment or container:
```bash
# Check Redis container status
docker compose -f infra/docker-compose.yml ps redis

# Test ping response inside container
docker exec -it passiveshield-redis redis-cli -a redis_dev_secret ping
# Response: PONG

# Inspect memory usage and evicted keys
docker exec -it passiveshield-redis redis-cli -a redis_dev_secret info memory
```
