# DDoS Detector Technical Design Specification

## Executive Summary
This document specifies the architectural design, inputs, scoring mathematical model, evidence structure, severity matrix, false-positive mitigation, missing telemetry handling, testing strategy, and rollback controls for the upcoming `DDoSDetector` component.

> [!IMPORTANT]
> **Specification Only**: No detector classification or threat scoring code is implemented in this task. This document serves as the approved design contract for subsequent detector implementation tasks.

---

## 1. Detector Scope & Inputs

The `DDoSDetector` evaluates streaming `FeatureSnapshot` events emitted by `DDoSFeatureExtractor` over sliding temporal windows (10s, 60s, 300s).

### Input Features (`FeatureSnapshot.features`)
1. `pps` (float): Packets per second targeting the entity.
2. `bps` (float): Bits per second targeting the entity.
3. `syn_only_ratio` (float): Ratio of unacknowledged TCP SYN connections (`S0` state).
4. `ack_missing_ratio` (float): Ratio of incomplete/rejected TCP handshakes (`S0`, `REJ`, `RSTO`).
5. `unique_source_ips` (int): Count of distinct attacking source IP addresses.
6. `source_ip_entropy` (float): Shannon entropy of source IP distribution.
7. `destination_port_entropy` (float): Shannon entropy of target destination ports.
8. `surge_ratio_pps` (float): Current PPS relative to rolling baseline (`pps / baseline_pps`).
9. `surge_ratio_bps` (float): Current BPS relative to rolling baseline (`bps / baseline_bps`).

---

## 2. Thresholds & Baseline Strategy

### A. Dynamic Adaptive Baseline
- **Rolling Baseline Window**: 1-hour moving average with exponential smoothing ($\alpha = 0.05$).
- **Surge Multipliers**:
  - `Warning Surge Threshold`: $\ge 3.0\times$ baseline pps/bps.
  - `Critical Surge Threshold`: $\ge 10.0\times$ baseline pps/bps.

### B. Static Floor Safeguards
To prevent false alarms during idle periods when baseline throughput is low, static minimum floors are enforced before triggering surge multipliers:
- `Minimum Volumetric Floor`: `pps >= 50.0` AND `bps >= 500,000` (500 Kbps).

---

## 3. Threat Scoring Model

The detector outputs a normalized threat confidence score $S \in [0.0, 1.0]$ calculated as a weighted linear combination of composite sub-scores:

$$S = w_1 \cdot S_{\text{rate}} + w_2 \cdot S_{\text{handshake}} + w_3 \cdot S_{\text{entropy}}$$

Where weights sum to $1.0$:
- **$w_1 = 0.40$ (Volumetric Surge Score $S_{\text{rate}}$)**:
  $$S_{\text{rate}} = \min\left(1.0, \frac{\text{surge\_ratio\_pps} - 1.0}{9.0}\right)$$
- **$w_2 = 0.35$ (Handshake Anomaly Score $S_{\text{handshake}}$)**:
  $$S_{\text{handshake}} = 0.7 \cdot \text{syn\_only\_ratio} + 0.3 \cdot \text{ack\_missing\_ratio}$$
- **$w_3 = 0.25$ (Entropy & Diversity Score $S_{\text{entropy}}$)**:
  $$S_{\text{entropy}} = \min\left(1.0, \frac{\text{unique\_source\_ips}}{100}\right) \cdot (1.0 - \text{destination\_port\_entropy} / 4.0)$$

---

## 4. Evidence Vector Structure

Detection events produce a structured `evidence` list formatted as key-value diagnostic strings for SOC dashboard display:

```json
[
  "VOLUMETRIC_SURGE: PPS (520.0) is 5.2x baseline (100.0)",
  "SYN_FLOOD_SIGNAL: Unacknowledged SYN ratio is 82.0% (S0 count: 246/300)",
  "DISTRIBUTED_FOOTPRINT: 142 unique source IPs active in 60s window",
  "PORT_CONCENTRATION: 94.5% traffic directed at port 80"
]
```

---

## 5. Severity Mapping Matrix

| Confidence Score ($S$) | PPS Surge | SYN-Only Ratio | Severity Output | Recommended SOC Action |
|---|---|---|---|---|
| $S < 0.35$ | $< 2.0\times$ | $< 0.20$ | `INFO` | Log silently; no alert generated |
| $0.35 \le S < 0.60$ | $\ge 3.0\times$ | $\ge 0.40$ | `LOW` | Surface on dashboard telemetry feed |
| $0.60 \le S < 0.85$ | $\ge 5.0\times$ | $\ge 0.60$ | `MEDIUM` | Flag IP in candidate alert queue |
| $S \ge 0.85$ | $\ge 10.0\times$ | $\ge 0.80$ | `HIGH` / `CRITICAL` | Generate high-priority SOC alert |

---

## 6. False-Positive Mitigation & Safeguards

1. **Flash Crowds vs. SYN Floods**: Legitimate traffic spikes (e.g. promotional sales) show high packet rates but complete TCP handshakes (`syn_only_ratio < 0.10`). High `syn_only_ratio` requirement prevents flash crowds from triggering HIGH severity alerts.
2. **Whitelisted Infrastructure**: Known CDN nodes, internal proxies, and load balancer health checks are filtered prior to scoring.
3. **Sliding Window Cooldown**: Threat score decay requires at least 2 consecutive clean 60-second windows before clearing alert state.

---

## 7. Missing Telemetry Behavior & Degradation

- **Missing Handshake Flags (`conn.log` delay)**: If `conn_states` telemetry is unavailable, $w_2$ weight is reallocated to $w_1$ (volumetric surge) and a warning tag `"DEGRADED_TELEMETRY: Missing TCP state logs"` is appended to the evidence vector.
- **Redis State Unavailability**: If Redis state is unreachable, fallback to single-flow packet rate calculation occurs without historical baseline surge comparisons.

---

## 8. Testing & Verification Plan

1. **Unit Tests (`tests/test_ddos_detector.py`)**:
   - Synthetic test vectors verifying mathematical score calculation across zero, low, medium, and extreme DDoS inputs.
   - Evidence vector formatting tests.
   - Severity classification boundary tests.
2. **Replay Integration Test**:
   - Deterministic replay of synthetic SYN flood PCAP (`fixtures/sample_replay.pcap`) verifying `HIGH` severity detection.

---

## 9. Rollback Concerns & Control Flags

- **Environment Feature Flag**: `ENABLE_DDOS_DETECTOR=true|false` in `.env`.
- **Safe Rollback**: Disabling the flag immediately stops detector evaluation without affecting streaming ingestion (`ZeekAdapter` -> `Redpanda`).
