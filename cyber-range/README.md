# PassiveShield AI — Add-on Docker Cyber Range

## Overview
The **PassiveShield Docker Cyber Range** is an isolated, add-on threat simulation and testing environment built strictly for testing and demonstrating PassiveShield AI v2 under **SIH Problem Statement 26145** (*AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*).

It generates realistic, reproducible synthetic threat scenarios (`SYN_FLOOD`, `UDP_FLOOD`, `SLOW_HTTP`, `DNS_TUNNEL`, `DGA_SUSPICIOUS`, `C2_BEACONING`) and benign traffic entirely inside an isolated Docker network (`threat-lab-network`).

> **CRITICAL RULE**: The Cyber Range is 100% isolated. It does NOT modify existing PassiveShield core code, does NOT connect to external networks, does NOT use public IP addresses, and does NOT execute active attack code.

---

## 1. Network & Container Architecture

```
                  +-----------------------------------+
                  |  PassiveShield Isolated Lab Net   |
                  |     (threat-lab-network)          |
                  +-----------------------------------+
                       /           |           \
                      /            |            \
                     v             v             v
       +------------------+ +--------------+ +------------------+
       | traffic-generator| |victim-services| |  passive-sensor  |
       | (172.28.0.20)    | | (172.28.0.10)| | (172.28.0.30)    |
       +------------------+ +--------------+ +------------------+
                |                  ^                  |
                +--- Traffic Flow -+                  v
                                             +------------------+
                                             |  /captures/*.pcap|
                                             +------------------+
                                                      |
                                                      v
                                             +------------------+
                                             | PassiveShield AI |
                                             | Existing Pipeline|
                                             +------------------+
```

### Lab Components:
- **`threat-lab-network`**: Dedicated isolated bridge network (`172.28.0.0/16`, `internal: true`).
- **`victim-services`**: Multi-protocol target service container listening on HTTP:80, UDP:9999, DNS:53, and HTTPS:443.
- **`traffic-generator`**: Orchestrates lab scenarios (`benign_tcp`, `syn_flood`, `udp_flood`, `slow_http`, `dns_tunnel`, `dga`, `c2_beacon`, `mixed`).
- **`passive-sensor`**: Sidecar sensor recording raw binary `.pcap` files to `./captures/`.

---

## 2. Supported Scenarios

| Option | Scenario | Traffic Type | Target Service | Expected PassiveShield Result |
|---|---|---|---|---|
| **[1]** | `benign_tcp` / `benign_dns` | Legitimate HTTP & DNS | `172.28.0.10:80/53` | `BENIGN` |
| **[2]** | `syn_flood` | Controlled SYN Surge | `172.28.0.10:80` | `SYN_FLOOD` / `DDoSDetector` |
| **[3]** | `udp_flood` | Controlled UDP Packet Stream | `172.28.0.10:9999` | `UDP_FLOOD` / `DDoSDetector` |
| **[4]** | `slow_http` | Low-rate Header Streams | `172.28.0.10:80` | `SLOW_HTTP_EXHAUSTION_DETECTED` |
| **[5]** | `dns_tunnel` | High-entropy Subdomain TXT | `172.28.0.10:53` | `DNS_TUNNEL` / `DNSAnomalyDetector` |
| **[6]** | `dga` | Algorithmic Subdomain Queries | `172.28.0.10:53` | `DGA_SUSPICIOUS` / `DNSAnomalyDetector` |
| **[7]** | `c2_beacon` | Periodic outbound connections | `172.28.0.10:443` | `C2_BEACONING` / `C2BeaconDetector` |
| **[8]** | `mixed` | Simultaneous Multi-Vector | `172.28.0.10:*` | `MULTI_VECTOR_THREATS` |

---

## 3. Quick Start & Execution Guide

### Step 1: Start the Cyber Range Lab
```bash
cd cyber-range
docker compose up -d --build
```

### Step 2: Run a Specific Scenario
```bash
# Bash (Linux/macOS)
./scripts/run_scenario.sh syn_flood

# PowerShell (Windows)
.\scripts\run_scenario.ps1 -Scenario syn_flood
```

### Step 3: Run Interactive Demonstration Menu
```bash
py -3 scripts/demo_menu.py
```

### Step 4: Run Automated PCAP Validation Suite
```bash
# Bash
./scripts/validate_results.sh

# PowerShell
.\scripts\validate_results.ps1
```

---

## 4. Integration with Existing PassiveShield Pipeline

The Cyber Range generates binary `.pcap` files in `./captures/` without modifying PassiveShield core files.
The existing PassiveShield PCAP ingestion and detection pipeline ([`scripts/pcap_flow_extractor.py`](file:///d:/sih%20project/PassiveShield_AI_v2/scripts/pcap_flow_extractor.py) & [`scripts/run_pcap_e2e_validation.py`](file:///d:/sih%20project/PassiveShield_AI_v2/scripts/run_pcap_e2e_validation.py)) parses the captured `.pcap` files, extracts features, evaluates threat detectors, computes risk scores via `ThreatFusionEngine`, and streams alerts over Redis Pub/Sub (`cyber_alerts`) and Socket.IO (`alert:new`).
