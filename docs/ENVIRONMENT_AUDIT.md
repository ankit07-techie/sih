# Environment Prerequisite Audit

## Executive Summary
This document provides a read-only audit of the local and container execution environment for PassiveShield AI. It records tool availability, measured versions, missing dependencies, and Docker-based container alternatives.

Audit Timestamp: 2026-08-26

---

## Tool Availability Matrix

| Tool / Prerequisite | Target Specification | Status | Measured Version / Location | Container Alternative |
|---|---|---|---|---|
| **Git** | Required | **Available** | `git version 2.54.0.windows.1` | N/A |
| **Docker CLI** | Required | **Available** | `Docker version 29.1.3, build f52814d` | N/A |
| **Docker Daemon** | Required | **Stopped** | Service not running (`npipe:////./pipe/dockerDesktopLinuxEngine` unavailable) | Launch Docker Desktop |
| **Docker Compose** | Required | **Available** | `Docker Compose version v5.0.1` | N/A |
| **Python** | 3.11+ | **Available** | `Python 3.14.0` (accessible via `py -3`) | `python:3.11-slim` image |
| **Node.js** | LTS (18+) | **Available** | `v24.15.0` | `node:20-alpine` image |
| **npm** | Package Manager | **Available** | `11.12.1` | Embedded in Node container |
| **tcpreplay** | Telemetry Replay | **Missing (Native)** | Not found on Windows host `PATH` | Run via container (e.g. Debian/Ubuntu container with `tcpreplay`) |
| **Zeek** | Passive Network Analysis | **Missing (Native)** | Not found on Windows host `PATH` | Run via `zeek/zeek:latest` container |
| **Config / Credentials** | Placeholders | **Missing** | No `.env` or `.env.example` in repo root | Add `.env.example` in `/config` or root during config task |

---

## Detailed Findings

### 1. Source Control & Runtimes
- **Git**: Installed and operational. Remote configured to `https://github.com/ankit07-techie/sih.git`.
- **Python**: Installed as Python 3.14.0. Accessible on Windows via the Python Launcher `py -3`. Windows default `python` app alias points to Microsoft Store shortcut; scripts should invoke via `py -3` or standard venv setup.
- **Node.js & npm**: Node v24.15.0 and npm 11.12.1 are installed natively on the system.

### 2. Containerization Engine
- **Docker CLI & Compose**: Both binaries are present on the host system.
- **Daemon Status**: The Docker Desktop service is currently inactive. Docker Desktop must be launched before containerized replay or service tasks can execute.

### 3. Traffic Analysis & Telemetry Tools (Missing Natively)
- **tcpreplay**: Missing natively on Windows CLI.
  - *Docker Workaround*: Can be executed inside a Linux container volume-mounting local PCAP files:
    ```bash
    docker run --rm -v "${PWD}/fixtures:/pcap" debian:latest bash -c "apt-get update && apt-get install -y tcpreplay && tcpreplay -i eth0 /pcap/sample.pcap"
    ```
- **Zeek**: Missing natively on Windows CLI.
  - *Docker Workaround*: Can be executed using the official Zeek container image:
    ```bash
    docker run --rm -v "${PWD}/fixtures:/pcap" zeek/zeek:latest zeek -r /pcap/sample.pcap
    ```

### 4. Configuration & Credentials Placeholders
- No `.env` or `.env.example` credential placeholder files exist in the repository currently. A `.env.example` file should be established when initial configuration modules (`/config`) are introduced.

---

## Action Items & Next Steps
1. **Start Docker Desktop Daemon**: User should launch Docker Desktop to enable containerized workflows.
2. **Use Docker for Missing Tools**: `tcpreplay` and `Zeek` will be run via container images rather than installing native Windows ports.
3. **No Automatic Installs**: No tools were automatically installed during this audit, adhering to project security constraints.
