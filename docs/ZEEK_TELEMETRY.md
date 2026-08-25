# Passive Telemetry Zeek Configuration Specification

## Executive Summary
This document specifies the Zeek network analysis policy configuration, JSON telemetry logging standards, approved metadata schemas (Connection, DNS, and TLS/SSL), passivity boundary enforcement, and deterministic replay verification for PassiveShield AI.

---

## 1. Passive Boundary Enforcement
Zeek is configured as a **strictly passive, read-only network observer**.
- **No Active Probing**: Packet injection, ARP scanning, HTTP probing, and synthetic connection initiation plugins are explicitly disabled.
- **Data Source**: Operates exclusively via passive network interface taps (e.g. SPAN port, Network TAP) or offline PCAP replay files (`-r`).

---

## 2. Policy Configuration (`config/zeek/local.zeek`)

The Zeek policy file `config/zeek/local.zeek` enables JSON-formatted log streams for seamless streaming ingestion by the Ingestion Producer module.

```zeek
# Enable JSON logging format
@load policy/tuning/json-logs.zeek

# Load core protocols
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl

# Enable detailed packet & byte counting for flows
redef Conn::record_packet_count = T;

# ISO-8601 Timestamps for reliable parsing
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
```

---

## 3. Approved Telemetry Metadata Schemas

### A. Connection Telemetry (`conn.log`)
Tracks IP flow volume, packet counts, duration, and connection states.

| JSON Field | Data Type | Description | Sample Value |
|---|---|---|---|
| `ts` | String (ISO-8601) | Event observation timestamp | `"2026-08-26T00:00:01.000Z"` |
| `uid` | String | Unique Zeek connection identifier | `"C12345678901"` |
| `id.orig_h` | String (IPv4/v6) | Source IP address | `"192.168.1.50"` |
| `id.orig_p` | Integer | Source port | `49152` |
| `id.resp_h` | String (IPv4/v6) | Destination IP address | `"10.0.0.1"` |
| `id.resp_p` | Integer | Destination port | `80` |
| `proto` | String | Protocol (`tcp`, `udp`, `icmp`) | `"tcp"` |
| `duration` | Float | Connection duration in seconds | `0.125` |
| `orig_bytes` | Integer | Payload bytes sent by originator | `512` |
| `resp_bytes` | Integer | Payload bytes sent by responder | `2048` |
| `conn_state` | String | Connection state (e.g. `SF`, `S0`, `REJ`) | `"SF"` |
| `orig_pkts` | Integer | Packets sent by originator | `5` |
| `resp_pkts` | Integer | Packets sent by responder | `6` |

---

### B. DNS Telemetry (`dns.log`)
Tracks DNS queries, subdomains, query types, response codes, and resolved addresses for DGA and tunnelling detection.

| JSON Field | Data Type | Description | Sample Value |
|---|---|---|---|
| `ts` | String (ISO-8601) | Event observation timestamp | `"2026-08-26T00:00:01.100Z"` |
| `uid` | String | Associated connection UID | `"C12345678904"` |
| `id.orig_h` | String | Client IP address | `"192.168.1.50"` |
| `query` | String | Requested domain name | `"example.com"` |
| `qtype_name` | String | Query record type (`A`, `AAAA`, `TXT`, `ANY`) | `"A"` |
| `rcode_name` | String | Response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`) | `"NOERROR"` |
| `answers` | Array[String] | Resolved IP addresses / records | `["93.184.216.34"]` |

---

### C. TLS/SSL Telemetry (`ssl.log`)
Tracks TLS handshake metadata, Server Name Indication (SNI), cipher suites, and validation states.

| JSON Field | Data Type | Description | Sample Value |
|---|---|---|---|
| `ts` | String (ISO-8601) | Event observation timestamp | `"2026-08-26T00:00:02.100Z"` |
| `uid` | String | Associated connection UID | `"C12345678902"` |
| `id.orig_h` | String | Client IP address | `"192.168.1.51"` |
| `version` | String | TLS version (`TLSv12`, `TLSv13`) | `"TLSv13"` |
| `cipher` | String | Negotiated cipher suite | `"TLS_AES_256_GCM_SHA384"` |
| `server_name` | String | Server Name Indication (SNI) host | `"secure.example.com"` |
| `established` | Boolean | Handshake establishment state | `true` |

---

## 4. Deterministic Verification Path

### Automated Script Verification
Run the automated verification script from the repository root:
- **PowerShell**:
  ```powershell
  .\scripts\verify_zeek_telemetry.ps1
  ```
- **Bash**:
  ```bash
  ./scripts/verify_zeek_telemetry.sh
  ```

### Replay & Inspection Commands (Docker Container)
To test processing of local PCAPs through Zeek using the official container image:
```bash
docker run --rm -v "${PWD}/fixtures:/pcap" -v "${PWD}/config/zeek:/config" zeek/zeek:latest zeek -r /pcap/sample_traffic.pcap /config/local.zeek
```
