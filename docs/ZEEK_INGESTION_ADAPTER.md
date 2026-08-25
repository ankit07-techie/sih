# Zeek Ingestion Adapter Specification & Data Mapping

## Executive Summary
This document specifies the implementation details, field mapping schemas, field validation rules, and test verification results for the `ZeekAdapter` module (`services/ingestion/zeek_adapter.py`).

---

## 1. Adapter Architecture & Scope

The `ZeekAdapter` serves as the parser and boundary converter between raw external Zeek JSON logs and PassiveShield AI's internal normalized ingestion models.

- **Scope**: Parses `conn.log`, `dns.log`, and `ssl.log` JSON streams into dictionary objects matching internal event schemas (`NormalizedFlowEvent`, `DNSObservation`, `TLSObservation`).
- **Isolation**: Has **zero dependencies** on external streaming services (no Redpanda producer), databases, or UI modules.

---

## 2. Event Schema Mapping Rules

### A. Connection Logs (`conn.log`) -> `NormalizedFlowEvent`

| Zeek Raw Field | Internal Normalized Field | Type Conversion | Default / Fallback |
|---|---|---|---|
| `ts` | `timestamp` | String (ISO-8601) | Mandatory |
| `uid` | `flow_id` | String | Mandatory |
| `id.orig_h` | `src_ip` | String | Mandatory |
| `id.orig_p` | `src_port` | Integer | Mandatory |
| `id.resp_h` | `dst_ip` | String | Mandatory |
| `id.resp_p` | `dst_port` | Integer | Mandatory |
| `proto` | `protocol` | String (lowercase) | Mandatory |
| `duration` | `duration` | Float | `0.0` |
| `orig_bytes` | `orig_bytes` | Integer | `0` |
| `resp_bytes` | `resp_bytes` | Integer | `0` |
| `orig_pkts` | `orig_packets` | Integer | `0` |
| `resp_pkts` | `resp_packets` | Integer | `0` |
| `conn_state` | `conn_state` | String | `"UNKNOWN"` |

---

### B. DNS Logs (`dns.log`) -> `DNSObservation`

| Zeek Raw Field | Internal Normalized Field | Type Conversion | Default / Fallback |
|---|---|---|---|
| `ts` | `timestamp` | String (ISO-8601) | Mandatory |
| `uid` | `flow_id` | String | Mandatory |
| `id.orig_h` | `client_ip` | String | Mandatory |
| `id.resp_h` | `server_ip` | String | `""` |
| `query` | `query_domain` | String | Mandatory |
| `qtype_name` | `query_type` | String | `"A"` |
| `rcode_name` | `response_code` | String | `"NOERROR"` |
| `answers` | `answers` | List[String] | `[]` |

---

### C. TLS/SSL Logs (`ssl.log`) -> `TLSObservation`

| Zeek Raw Field | Internal Normalized Field | Type Conversion | Default / Fallback |
|---|---|---|---|
| `ts` | `timestamp` | String (ISO-8601) | Mandatory |
| `uid` | `flow_id` | String | Mandatory |
| `id.orig_h` | `client_ip` | String | Mandatory |
| `id.resp_h` | `server_ip` | String | Mandatory |
| `version` | `tls_version` | String | `"UNKNOWN"` |
| `cipher` | `cipher_suite` | String | `"UNKNOWN"` |
| `server_name` | `sni_hostname` | String | `""` |
| `established` | `established` | Boolean | `false` |

---

## 3. Validation & Error Handling Strategy

1. **Non-Crashing Isolation**: Malformed JSON strings or empty lines return `None` without raising unhandled exceptions or interrupting line-by-line file tailing.
2. **Mandatory Key Verification**: If any mandatory field (e.g. source IP, timestamp, or flow ID) is missing or `null`, the record is safely discarded (`return None`).
3. **Type Coercion Safeguards**: Numeric values (`bytes`, `packets`, `ports`) are defensively cast to `int`/`float`, falling back to `0` or `0.0` if type casting fails.

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_zeek_adapter.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_zeek_adapter.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_parse_conn_valid`: Successfully parses valid `conn.log` JSON lines into `NormalizedFlowEvent`.
- `test_parse_conn_malformed`: Safely rejects incomplete or corrupt JSON inputs.
- `test_parse_dns_valid`: Successfully parses valid `dns.log` JSON lines into `DNSObservation`.
- `test_parse_dns_malformed`: Safely rejects invalid DNS entries.
- `test_parse_ssl_valid`: Successfully parses valid `ssl.log` JSON lines into `TLSObservation`.
- `test_parse_fixtures`: Verifies real-world JSON file fixtures in `fixtures/sample_zeek_logs/conn.log`.
