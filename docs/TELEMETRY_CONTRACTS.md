# Versioned Telemetry Event Contracts Specification

## Executive Summary
This document specifies the Python data contract models (`shared/contracts/telemetry.py`), field validation rules, serialization methods, versioning controls, and test results for `NormalizedFlowEvent`, `DNSObservation`, and `TLSObservation`.

---

## 1. Data Contracts Architecture

Telemetry event contracts serve as the **type-safe, versioned boundary interface** between ingestion log adapters (e.g. `ZeekAdapter`) and downstream streaming producers (`aiokafka`), analytics engines, and detectors.

- **Location**: `shared/contracts/telemetry.py`
- **Module Exports**: `NormalizedFlowEvent`, `DNSObservation`, `TLSObservation`, `ContractValidationError`
- **Design Pattern**: Python dataclasses with custom `__post_init__` validation hooks, `to_dict()`, `to_json()`, `from_dict()`, and `from_json()` methods.

---

## 2. Event Contract Models & Schemas

### A. `NormalizedFlowEvent`
Represents an IP flow record normalized from network connection telemetry (`conn.log` / IP flows).

- **`event_type`**: `"NormalizedFlowEvent"`
- **`version`**: `"1.0"`
- **Fields & Constraints**:
  - `timestamp` (str): ISO-8601 string, non-empty.
  - `flow_id` (str): Unique flow identifier UID, non-empty.
  - `src_ip` (str): Source IPv4/v6 address (validated).
  - `src_port` (int): Source port (0–65535).
  - `dst_ip` (str): Destination IPv4/v6 address (validated).
  - `dst_port` (int): Destination port (0–65535).
  - `protocol` (str): Transport protocol (e.g. `"tcp"`, `"udp"`).
  - `duration` (float): Flow duration in seconds (>= 0.0).
  - `orig_bytes` (int): Bytes sent by originator (>= 0).
  - `resp_bytes` (int): Bytes sent by responder (>= 0).
  - `orig_packets` (int): Packets sent by originator (>= 0).
  - `resp_packets` (int): Packets sent by responder (>= 0).
  - `conn_state` (str): Connection state summary.
  - `service` (str): Application service identifier.

---

### B. `DNSObservation`
Represents a DNS query/response transaction normalized from DNS log telemetry (`dns.log`).

- **`event_type`**: `"DNSObservation"`
- **`version`**: `"1.0"`
- **Fields & Constraints**:
  - `timestamp` (str): ISO-8601 string, non-empty.
  - `flow_id` (str): Flow UID, non-empty.
  - `client_ip` (str): Client IPv4/v6 address (validated).
  - `server_ip` (str): Server IPv4/v6 address (validated, optional).
  - `query_domain` (str): Domain name queried, non-empty.
  - `query_type` (str): Record type (e.g. `"A"`, `"AAAA"`, `"TXT"`).
  - `response_code` (str): Response status code (e.g. `"NOERROR"`, `"NXDOMAIN"`).
  - `answers` (List[str]): List of resolved IP addresses or records.

---

### C. `TLSObservation`
Represents a TLS/SSL handshake observation normalized from SSL log telemetry (`ssl.log`).

- **`event_type`**: `"TLSObservation"`
- **`version`**: `"1.0"`
- **Fields & Constraints**:
  - `timestamp` (str): ISO-8601 string, non-empty.
  - `flow_id` (str): Flow UID, non-empty.
  - `client_ip` (str): Client IPv4/v6 address (validated).
  - `server_ip` (str): Server IPv4/v6 address (validated).
  - `tls_version` (str): TLS protocol version (e.g. `"TLSv13"`).
  - `cipher_suite` (str): Cipher suite negotiated.
  - `sni_hostname` (str): Server Name Indication (SNI) host.
  - `established` (bool): Handshake completion flag.

---

## 3. Validation & Serialization Rules

1. **IP Address Validation**: IPv4 and IPv6 strings are strictly verified using `ipaddress.ip_address()`. Invalid strings raise `ContractValidationError`.
2. **Port Range Boundaries**: Ports outside 0–65535 raise `ContractValidationError`.
3. **Numeric Bounds**: Negative values for bytes, packets, or duration raise `ContractValidationError`.
4. **JSON Roundtrip Guarantee**: All contract classes implement bidirectional JSON serialization (`to_json()` / `from_json()`) and dictionary mapping (`to_dict()` / `from_dict()`).

---

## 4. Test Verification Results

Unit tests are implemented in [`tests/test_telemetry_contracts.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_telemetry_contracts.py).

### Test Suite Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verification Results:
- `test_flow_event_valid`: Passed (valid creation & JSON roundtrip).
- `test_flow_event_invalid_ip`: Passed (raises `ContractValidationError` on bad IP).
- `test_flow_event_invalid_port`: Passed (raises `ContractValidationError` on bad port).
- `test_dns_observation_valid`: Passed (valid creation & JSON roundtrip).
- `test_dns_observation_missing_domain`: Passed (raises `ContractValidationError` on empty domain).
- `test_tls_observation_valid`: Passed (valid creation & JSON roundtrip).
- `test_fixtures`: Passed (successfully parsed `fixtures/contracts/*.json`).
- Total Test Suite Execution: **13 tests, 0 failures, 0 errors** (`OK`).
