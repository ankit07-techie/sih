# Deterministic Replay Workflow Specification

## Executive Summary
This document specifies the deterministic network traffic replay workflow for PassiveShield AI. It establishes procedures for repeatable threat detection demonstrations, integration testing, and reproducible debugging using pre-packaged PCAP fixtures without active probing or altering monitored network traffic.

---

## 1. Passive Boundary & Security Isolation

### Core Passive Boundary Principle
- **Zero Production Injection**: Replay traffic is **never injected** into live, production-monitored network interfaces.
- **Isolated Virtual Interfaces**: Replay is directed exclusively into isolated Linux virtual Ethernet pairs (`veth-replay`), loopback, or offline container interfaces.
- **Offline Parser Fallback**: Telemetry can also be parsed directly using offline Zeek processing (`zeek -r <pcap_file> /config/local.zeek`) without transmitting raw Ethernet frames across any physical interface.

---

## 2. Replay Tooling Architecture

### Core Runner (`replay/replay_runner.py`)
The Python replay controller provides automated PCAP header validation, speed multiplier formatting, loop iteration management, and Docker-based container execution.

### Replay Controls & Parameters

| Parameter | Default Value | Options | Purpose |
|---|---|---|---|
| `--pcap` | `fixtures/sample_replay.pcap` | Any valid `.pcap` file | Target traffic file for replay |
| `--speed` | `1.0` | `0` (Max speed), `0.5`, `1.0`, `2.0`, `5.0` | Replay rate multiplier relative to timestamps |
| `--loop` | `1` | Integer (`N`), `0` (infinite) | Number of times to loop the dataset |
| `--interface` | `eth0` | `veth-replay`, `eth0`, etc. | Destination virtual network interface |
| `--dry-run` | `False` | Flag | Validate PCAP header and print command without running |

---

## 3. Replay Verification Fixture

A deterministic sample PCAP fixture is provided in the repository:
- **Location**: `fixtures/sample_replay.pcap`
- **Format**: Standard libpcap binary (24-byte global header + Ethernet/IPv4 TCP & UDP packets).
- **Contents**: Deterministic SYN flow and DNS query frames for pipeline verification.

---

## 4. Verification Workflow

### Running Verification Automated Test
Execute the verification script from the repository root:
- **PowerShell (Windows)**:
  ```powershell
  .\scripts\verify_replay_workflow.ps1
  ```
- **Bash (Linux/macOS)**:
  ```bash
  ./scripts/verify_replay_workflow.sh
  ```

### Manual Replay Execution Examples

#### Dry-Run Command Generation:
```bash
py -3 replay/replay_runner.py --pcap fixtures/sample_replay.pcap --dry-run
```

#### Replaying Sample PCAP at 2x Speed:
```bash
py -3 replay/replay_runner.py --pcap fixtures/sample_replay.pcap --speed 2.0 --loop 3
```

#### Replaying Sample PCAP via PowerShell Wrapper:
```powershell
.\scripts\replay_pcap.ps1 -Pcap "fixtures/sample_replay.pcap" -Speed 1.0 -Loop 1 -DryRun
```
