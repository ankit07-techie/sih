# PassiveShield AI — Docker Desktop Manual Cyber Range

## Overview
The **PassiveShield Docker Desktop Manual Cyber Range** is an add-on testing and demonstration environment designed to be operated primarily through **Docker Desktop** and a browser-based **Web Control Panel**.

It provides a graphical user interface (GUI) to trigger isolated threat simulations (`SYN_FLOOD`, `UDP_FLOOD`, `SLOW_HTTP`, `DNS_TUNNEL`, `DGA_SUSPICIOUS`, `C2_BEACONING`, `MIXED_THREAT`) without typing manual terminal attack commands.

> **ZERO CORE CHANGES**: The Cyber Range is 100% isolated inside [`cyber-range/`](file:///d:/sih%20project/PassiveShield_AI_v2/cyber-range/). Existing PassiveShield backend detectors, contracts, feature engines, threat fusion, Redis, and Socket.IO files are untouched.

---

## 1. Docker Desktop User Experience Workflow

```
       +---------------------------------------------------+
       |               1. Open Docker Desktop              |
       +---------------------------------------------------+
                                 |
                                 v
       +---------------------------------------------------+
       |        2. Start PassiveShield Cyber Range         |
       |             `docker compose up -d`                |
       +---------------------------------------------------+
                                 |
                                 v
       +---------------------------------------------------+
       |      3. Open Web Control Panel in Browser         |
       |             http://localhost:8080                 |
       +---------------------------------------------------+
                                 |
                                 v
       +---------------------------------------------------+
       |    4. Select Scenario, Duration & Intensity       |
       |               Click "START THREAT"                |
       +---------------------------------------------------+
                                 |
                                 v
       +---------------------------------------------------+
       | 5. Real Isolated Traffic -> Passive Sensor Capture|
       |        Captures: manual_<scenario>_<ts>.pcap       |
       +---------------------------------------------------+
                                 |
                                 v
       +---------------------------------------------------+
       |  6. Existing PassiveShield Engine Independent     |
       |         Threat Detection & Score Fusion           |
       +---------------------------------------------------+
                                 |
                                 v
       +---------------------------------------------------+
       | 7. Render Detection Result & Stream Live Alert UI |
       +---------------------------------------------------+
```

---

## 2. Docker Desktop Startup Instructions

### Step 1: Open Docker Desktop
Ensure Docker Engine is running on your host system.

### Step 2: Start the Cyber Range Stack
Navigate to `cyber-range/` and launch the Compose stack:
```bash
cd cyber-range
docker compose up -d --build
```

### Step 3: Open the Web Control Panel
Open your browser at:
[http://localhost:8080](http://localhost:8080)

---

## 3. Web Control Panel Features

### A. Docker Lab Status Indicators
- **Lab Network**: `ISOLATED (threat-lab-network)` (0% external routing)
- **Passive Sensor**: `ACTIVE`
- **Victim HTTP**: `ONLINE` (`172.28.0.10:80`)
- **Victim DNS**: `ONLINE` (`172.28.0.10:53`)
- **Traffic Generator**: `READY` (`172.28.0.20`)

### B. One-Click Manual Scenario Buttons
- `NORMAL HTTP` (Benign web GET & POST requests)
- `NORMAL DNS` (Standard domain resolution queries)
- `SYN FLOOD SIMULATION` (Controlled SYN packet surge)
- `UDP FLOOD SIMULATION` (High-rate UDP payload stream)
- `SLOW HTTP SIMULATION` (Slow header connection exhaustion)
- `DNS TUNNEL SIMULATION` (Encoded high-entropy TXT subdomains)
- `DGA SIMULATION` (Algorithmic pseudo-random domain queries)
- `C2 BEACON SIMULATION` (Periodic outbound TLS beaconing)
- `⚡ MIXED THREAT SIMULATION` (Simultaneous multi-vector simulation)

### C. Simulation Controls
- **Duration**: `5 sec`, `10 sec`, `30 sec`, `60 sec`
- **Intensity**: `LOW`, `MEDIUM`, `HIGH`
- **Target**: Fixed to local victim container (`172.28.0.10`)

### D. Live Execution Ticker & Result Display
- **Unique PCAP Generation**: Automatically saves each capture to `cyber-range/captures/manual_<scenario>_<timestamp>.pcap`.
- **Independent PassiveShield Result**: Shows `Threat Classification`, `Confidence %`, `Risk Score`, `Severity`, `Detector Source`, and `Evidence Diagnostic Tags`.

---

## 4. Native Local Execution (Without Docker Desktop)

If running in a local python environment without active Docker containers, start the Web Control Panel natively:
```bash
py -3 cyber-range/controller/server.py
```
Then open [http://localhost:8080](http://localhost:8080) in your browser.
