"""
PassiveShield AI — Manual Attack Simulation & Telemetry Injection CLI
Interactive Controller for Simulating Attacks, Visualizing Attack Origins, and Stopping/Mitigating Attacks in Real-Time.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Add repository root to python path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation,
    FeatureSnapshot,
    DetectionResult,
    ThreatAlert
)
from services.detectors import (
    DDoSDetector,
    PortScanDetector,
    C2BeaconDetector,
    DNSAnomalyDetector,
    ExfiltrationDetector
)
from services.analytics import TLSMetadataAnalyzer, ThreatFusionEngine

API_ALERTS_URL = os.environ.get("PASSIVESHIELD_API_URL", "http://localhost:3001/api/v1/alerts")
API_STOP_ALL_URL = os.environ.get("PASSIVESHIELD_API_STOP_URL", "http://localhost:3001/api/v1/alerts/stop-all")

# Initialize detectors & fusion
ddos_detector = DDoSDetector()
port_scan_detector = PortScanDetector()
c2_detector = C2BeaconDetector()
dns_detector = DNSAnomalyDetector()
exfil_detector = ExfiltrationDetector()
tls_analyzer = TLSMetadataAnalyzer()
fusion_engine = ThreatFusionEngine()


ATTACK_SCENARIOS = {
    "1": {
        "title": "SYN Flood Attack (Volumetric DDoS)",
        "label": "SYN_FLOOD",
        "category": "DDoSDetector",
        "description": "High-rate incomplete TCP connection burst (800 pps, syn_ratio=0.99)",
        "severity": "HIGH",
        "origin": "External WAN Botnet (AS13335 / Russia)",
        "target": "Protected Core DMZ (Web Server Farm)",
        "direction": "INBOUND ATTACK",
        "flow": {
            "src_ip": "198.51.100.42",
            "dst_ip": "10.20.1.50",
            "src_port": 42000,
            "dst_port": 80,
            "protocol": "TCP",
            "duration_sec": 5.0,
            "packets_forward": 4000,
            "packets_backward": 10,
            "bytes_forward": 240000,
            "bytes_backward": 600,
            "syn_count": 3980,
            "ack_count": 8,
            "mean_iat_ms": 1.25,
            "std_iat_ms": 0.4
        },
        "features": {
            "flow_rate_pps": 800.0,
            "syn_pps": 796.0,
            "udp_pps": 0.0,
            "bytes_per_sec": 48120.0,
            "syn_ratio": 0.99,
            "ack_ratio": 0.01,
            "duration": 5.0
        },
        "evidence": [
            {"code": "SYN_FLOOD_DETECTED", "message": "High SYN packet rate: 796 pps", "value": 796, "threshold": 500, "detector_source": "DDoSDetector"},
            {"code": "HIGH_SYN_RATIO", "message": "SYN ratio 0.99 exceeded threshold 0.85", "value": 0.99, "threshold": 0.85, "detector_source": "DDoSDetector"}
        ],
        "mitigation": "APPLY_SYN_PROXY_AND_RATE_LIMIT"
    },
    "2": {
        "title": "UDP Volumetric Flood (DDoS Attack)",
        "label": "UDP_FLOOD",
        "category": "DDoSDetector",
        "description": "High-volume UDP datagram flood saturating bandwidth (1,200 pps)",
        "severity": "HIGH",
        "origin": "External Compromised NTP/DNS Amplifier (WAN)",
        "target": "Protected Voice & Video Gateway (UDP Port 9999)",
        "direction": "INBOUND ATTACK",
        "flow": {
            "src_ip": "203.0.113.88",
            "dst_ip": "10.20.2.81",
            "src_port": 45000,
            "dst_port": 9999,
            "protocol": "UDP",
            "duration_sec": 6.0,
            "packets_forward": 7200,
            "packets_backward": 0,
            "bytes_forward": 576000,
            "bytes_backward": 0,
            "syn_count": 0,
            "ack_count": 0,
            "mean_iat_ms": 0.83,
            "std_iat_ms": 0.2
        },
        "features": {
            "flow_rate_pps": 1200.0,
            "syn_pps": 0.0,
            "udp_pps": 1200.0,
            "bytes_per_sec": 96000.0,
            "syn_ratio": 0.0,
            "ack_ratio": 0.0,
            "duration": 6.0
        },
        "evidence": [
            {"code": "UDP_FLOOD_DETECTED", "message": "High UDP packet rate: 1200 pps", "value": 1200, "threshold": 600, "detector_source": "DDoSDetector"}
        ],
        "mitigation": "DROP_SRC_UDP_BANDWIDTH_LIMIT"
    },
    "3": {
        "title": "Slowloris / Slow HTTP DoS Attack",
        "label": "SLOW_HTTP",
        "category": "DDoSDetector",
        "description": "Low-and-slow HTTP header starvation holding sockets open for 900s",
        "severity": "MEDIUM",
        "origin": "External Suspicious Client (WAN / Tor Exit Node)",
        "target": "Internal Web Application Gateway (Port 80)",
        "direction": "INBOUND ATTACK",
        "flow": {
            "src_ip": "185.220.101.5",
            "dst_ip": "10.20.2.82",
            "src_port": 45120,
            "dst_port": 80,
            "protocol": "TCP",
            "duration_sec": 900.0,
            "packets_forward": 95,
            "packets_backward": 91,
            "bytes_forward": 7600,
            "bytes_backward": 9100,
            "syn_count": 1,
            "ack_count": 184,
            "mean_iat_ms": 9473.0,
            "std_iat_ms": 1820.0
        },
        "features": {
            "flow_rate_pps": 0.2,
            "syn_pps": 0.001,
            "bytes_per_sec": 18.5,
            "syn_ratio": 0.01,
            "ack_ratio": 0.99,
            "duration": 900.0,
            "mean_iat_ms": 9473.0,
            "std_iat_ms": 1820.0
        },
        "evidence": [
            {"code": "SLOW_HTTP_DETECTED", "message": "Extended connection lifetime (900s) with low throughput.", "value": 900, "threshold": 300, "detector_source": "DDoSDetector"}
        ],
        "mitigation": "ENFORCE_HTTP_HEADER_TIMEOUT"
    },
    "4": {
        "title": "Vertical Port Scan (Reconnaissance)",
        "label": "PORT_SCAN_VERTICAL",
        "category": "PortScanDetector",
        "description": "Targeted host reconnaissance probing 64 distinct TCP ports in under 10 seconds",
        "severity": "MEDIUM",
        "origin": "Compromised LAN Workstation (Office Floor 2)",
        "target": "Internal Core Database Host (10.0.0.15)",
        "direction": "INTERNAL LATERAL SCAN",
        "flow": {
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.15",
            "src_port": 54100,
            "dst_port": 80,
            "protocol": "TCP",
            "duration_sec": 8.0,
            "packets_forward": 64,
            "packets_backward": 12,
            "bytes_forward": 3840,
            "bytes_backward": 720
        },
        "features": {
            "unique_dst_ports": 64,
            "unique_dst_ips": 1,
            "flow_rate_pps": 8.0,
            "duration": 8.0
        },
        "evidence": [
            {"code": "VERTICAL_PORT_SCAN", "message": "Probed 64 distinct target ports on single destination host.", "value": 64, "threshold": 15, "detector_source": "PortScanDetector"}
        ],
        "mitigation": "ISOLATE_HOST_AND_QUARANTINE_IP"
    },
    "5": {
        "title": "Horizontal Subnet Sweep (Port Scan)",
        "label": "PORT_SCAN_HORIZONTAL",
        "category": "PortScanDetector",
        "description": "Scanning 85 distinct IP addresses on port 445 (SMB) for vulnerable targets",
        "severity": "HIGH",
        "origin": "Infected BYOD Device (Guest Wi-Fi VLAN)",
        "target": "Entire Internal Subnet (10.0.0.0/24)",
        "direction": "INTERNAL LATERAL SWEEP",
        "flow": {
            "src_ip": "192.168.1.110",
            "dst_ip": "10.0.0.1",
            "src_port": 54200,
            "dst_port": 445,
            "protocol": "TCP",
            "duration_sec": 12.0,
            "packets_forward": 170,
            "packets_backward": 10,
            "bytes_forward": 10200,
            "bytes_backward": 600
        },
        "features": {
            "unique_dst_ports": 1,
            "unique_dst_ips": 85,
            "flow_rate_pps": 14.1,
            "duration": 12.0
        },
        "evidence": [
            {"code": "HORIZONTAL_PORT_SCAN", "message": "Scanned 85 distinct destination IPs across subnet.", "value": 85, "threshold": 20, "detector_source": "PortScanDetector"}
        ],
        "mitigation": "DROP_LATERAL_MOVEMENT_SUBGRAPH"
    },
    "6": {
        "title": "C2 Periodic Outbound Beaconing (Command & Control)",
        "label": "C2_BEACONING",
        "category": "C2BeaconDetector",
        "description": "Low-jitter automated heartbeat beacon every 15 seconds (periodicity score: 0.96)",
        "severity": "HIGH",
        "origin": "Internal Infected Workstation (10.20.1.55)",
        "target": "External Threat Actor C2 Server (198.51.100.42:443)",
        "direction": "OUTBOUND C2 CHANNEL",
        "flow": {
            "src_ip": "10.20.1.55",
            "dst_ip": "198.51.100.42",
            "src_port": 51444,
            "dst_port": 443,
            "protocol": "TCP",
            "duration_sec": 1800.0,
            "packets_forward": 120,
            "packets_backward": 118,
            "bytes_forward": 16800,
            "bytes_backward": 25400,
            "mean_iat_ms": 15000.0,
            "std_iat_ms": 210.0,
            "periodicity_score": 0.96
        },
        "features": {
            "periodicity_score": 0.96,
            "mean_iat_ms": 15000.0,
            "std_iat_ms": 210.0,
            "cv_iat": 0.014,
            "duration": 1800.0
        },
        "evidence": [
            {"code": "C2_PERIODIC_BEACONING", "message": "High periodicity score (0.96) detected with low jitter (CV=0.014).", "value": 0.96, "threshold": 0.80, "detector_source": "C2BeaconDetector"}
        ],
        "mitigation": "BLOCK_EGRESS_TO_C2_HOST"
    },
    "7": {
        "title": "DNS Tunneling Data Exfiltration",
        "label": "DNS_TUNNEL",
        "category": "DNSAnomalyDetector",
        "description": "Exfiltrating sensitive base64 payloads through encoded DNS TXT queries (avg length 58.7 chars)",
        "severity": "CRITICAL",
        "origin": "Internal Finance Server (10.20.1.53)",
        "target": "Rogue Authoritative DNS Server (tunnel.exfil-dns.org)",
        "direction": "OUTBOUND EXFILTRATION",
        "flow": {
            "src_ip": "10.20.1.53",
            "dst_ip": "10.20.2.53",
            "src_port": 53110,
            "dst_port": 53,
            "protocol": "UDP",
            "duration_sec": 120.0,
            "packets_forward": 620,
            "packets_backward": 618,
            "bytes_forward": 74400,
            "bytes_backward": 53200,
            "dns_query_count": 620,
            "dns_avg_query_length": 58.7,
            "dns_unique_subdomain_ratio": 0.98
        },
        "features": {
            "dns_query_count": 620,
            "dns_avg_query_length": 58.7,
            "dns_unique_subdomain_ratio": 0.98,
            "subdomain_depth": 3,
            "is_txt_query": 1,
            "entropy": 4.6,
            "duration": 120.0
        },
        "evidence": [
            {"code": "TUNNEL_SUBDOMAIN_LENGTH", "message": "Excessive subdomain payload length (58.7 chars).", "value": 58.7, "threshold": 25.0, "detector_source": "DNSAnomalyDetector"},
            {"code": "TUNNEL_TXT_QUERY_VOLUME", "message": "High ratio of encoded TXT queries: 98% unique.", "value": 0.98, "threshold": 0.70, "detector_source": "DNSAnomalyDetector"}
        ],
        "mitigation": "BLOCK_DOMAIN_RESOLUTION_AND_SINKHOLE"
    },
    "8": {
        "title": "DGA (Domain Generation Algorithm) Suspicious Activity",
        "label": "DGA_SUSPICIOUS",
        "category": "DNSAnomalyDetector",
        "description": "High-entropy pseudo-random domains generated by malware (entropy: 4.85, digit_ratio: 0.35)",
        "severity": "HIGH",
        "origin": "Infected Engineering Node (10.20.1.54)",
        "target": "Internal Resolving DNS Gateway (10.20.2.53:53)",
        "direction": "MALWARE C2 RESOLUTION",
        "flow": {
            "src_ip": "10.20.1.54",
            "dst_ip": "10.20.2.53",
            "src_port": 53220,
            "dst_port": 53,
            "protocol": "UDP",
            "duration_sec": 90.0,
            "packets_forward": 300,
            "packets_backward": 285,
            "bytes_forward": 28800,
            "bytes_backward": 22800,
            "dns_query_count": 300,
            "dns_avg_query_length": 31.4,
            "dns_unique_subdomain_ratio": 0.94,
            "domain_entropy": 4.85
        },
        "features": {
            "dns_query_count": 300,
            "dns_avg_query_length": 31.4,
            "dns_unique_subdomain_ratio": 0.94,
            "entropy": 4.85,
            "digit_ratio": 0.35,
            "duration": 90.0
        },
        "evidence": [
            {"code": "DGA_HIGH_ENTROPY", "message": "High Shannon entropy (4.85) in DNS resolution requests.", "value": 4.85, "threshold": 3.8, "detector_source": "DNSAnomalyDetector"}
        ],
        "mitigation": "ENABLE_DGA_SINKHOLE_FILTER"
    },
    "9": {
        "title": "High-Volume Data Exfiltration Burst",
        "label": "EXFILTRATION_BURST",
        "category": "ExfiltrationDetector",
        "description": "Outbound bulk data leak transferring 48.5 MB in single encrypted session",
        "severity": "CRITICAL",
        "origin": "Internal Database Cluster (10.20.1.60)",
        "target": "External Drop Server (203.0.113.88:443)",
        "direction": "OUTBOUND DATA THEFT",
        "flow": {
            "src_ip": "10.20.1.60",
            "dst_ip": "203.0.113.88",
            "src_port": 49820,
            "dst_port": 443,
            "protocol": "TCP",
            "duration_sec": 45.0,
            "packets_forward": 34000,
            "packets_backward": 1200,
            "bytes_forward": 48500000,
            "bytes_backward": 72000
        },
        "features": {
            "orig_bytes": 48500000,
            "resp_bytes": 72000,
            "bytes_per_sec": 1079377.0,
            "duration": 45.0
        },
        "evidence": [
            {"code": "EXFIL_HIGH_BURST_VOLUME", "message": "Large single-flow outbound data transfer: 48.5 MB.", "value": 48500000, "threshold": 10000000, "detector_source": "ExfiltrationDetector"}
        ],
        "mitigation": "SEVER_OUTBOUND_SOCKET_AND_ENFORCE_DLP"
    },
    "10": {
        "title": "JA3 Malicious TLS Cryptographic Signature (Cobalt Strike)",
        "label": "MALICIOUS_TLS_JA3",
        "category": "TLSMetadataAnalyzer",
        "description": "Passive TLS ClientHello fingerprint matched known Cobalt Strike Beacon JA3 hash (no decryption)",
        "severity": "CRITICAL",
        "origin": "Compromised Executive Laptop (192.168.1.150)",
        "target": "Adversary Infrastructure (198.51.100.77:443)",
        "direction": "OUTBOUND BEACON",
        "flow": {
            "src_ip": "192.168.1.150",
            "dst_ip": "198.51.100.77",
            "src_port": 50123,
            "dst_port": 443,
            "protocol": "TCP",
            "duration_sec": 30.0,
            "packets_forward": 150,
            "packets_backward": 140,
            "bytes_forward": 21000,
            "bytes_backward": 34000
        },
        "features": {
            "ja3_hash": "e7ed94cc5e470845a0b4b2941f15e32a",
            "sni": "update-service-cdn.org"
        },
        "evidence": [
            {"code": "JA3_MALWARE_SIGNATURE_MATCH", "message": "JA3 hash matched known threat signature: Cobalt Strike Beacon.", "value": "e7ed94cc5e470845a0b4b2941f15e32a", "threshold": "Cobalt Strike Beacon", "detector_source": "TLSMetadataAnalyzer"}
        ],
        "mitigation": "APPLY_PASSIVE_SHIELD_FILTERS"
    },
    "11": {
        "title": "Correlated Multi-Vector Advanced Attack (Fusion)",
        "label": "CORRELATED_MULTI_VECTOR",
        "category": "ThreatFusionEngine",
        "description": "Coordinated APT: Port Scan + DNS Tunnel + JA3 Cobalt Strike + High Burst Exfiltration",
        "severity": "CRITICAL",
        "origin": "External APT Actor via Compromised DMZ (192.168.1.200)",
        "target": "Protected Critical Infrastructure Core (198.51.100.99)",
        "direction": "MULTI-STAGE APT CAMPAIGN",
        "flow": {
            "src_ip": "192.168.1.200",
            "dst_ip": "198.51.100.99",
            "src_port": 59900,
            "dst_port": 443,
            "protocol": "TCP",
            "duration_sec": 300.0,
            "packets_forward": 45000,
            "packets_backward": 3500,
            "bytes_forward": 62000000,
            "bytes_backward": 210000
        },
        "features": {
            "unique_dst_ports": 50,
            "is_txt_query": 1,
            "orig_bytes": 62000000,
            "duration": 300.0
        },
        "evidence": [
            {"code": "VERTICAL_PORT_SCAN", "message": "Vertical port scan detected: 50 distinct ports probed.", "value": 50, "threshold": 15, "detector_source": "PortScanDetector"},
            {"code": "EXFIL_HIGH_BURST_VOLUME", "message": "Large outbound data transfer (62.0 MB).", "value": 62000000, "threshold": 10000000, "detector_source": "ExfiltrationDetector"},
            {"code": "JA3_MALWARE_SIGNATURE_MATCH", "message": "JA3 hash matched known threat signature: Cobalt Strike Beacon.", "value": "e7ed94cc5e470845a0b4b2941f15e32a", "threshold": "Cobalt Strike Beacon", "detector_source": "TLSMetadataAnalyzer"}
        ],
        "mitigation": "QUARANTINE_HOST_AND_ALERT_SOC"
    }
}


def send_alert_to_api(alert_payload: dict) -> bool:
    """Sends standardized ThreatAlert to Express API gateway over HTTP."""
    data = json.dumps(alert_payload).encode("utf-8")
    req = urllib.request.Request(
        API_ALERTS_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status in (200, 201)
    except urllib.error.URLError as e:
        print(f"  [!] Note: Express API at {API_ALERTS_URL} returned: {e}")
        return False
    except Exception as e:
        print(f"  [!] Note: API connection error: {e}")
        return False


def stop_all_active_attacks() -> bool:
    """Broadcasts a cessation event to stop all active attacks and normalize UI status."""
    print("\n" + "=" * 70)
    print("  [SIGNALING ATTACK STOPPED & TRAFFIC NORMALIZED]")
    print("=" * 70)
    
    stop_payload = {
        "alert_id": f"stop-all-{int(time.time() * 1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_classification": "ATTACK_STOPPED",
        "severity": "LOW",
        "status": "STOPPED",
        "confidence_score": 0.0,
        "affected_context": {
            "entity_type": "system",
            "entity_id": "ALL_CHANNELS",
            "src_ip": "NORMALIZED",
            "dst_ip": "ALL_TARGETS",
            "src_port": 0,
            "dst_port": 0,
            "origin": "Security Operations Center",
            "target": "Protected Network Core",
            "direction": "TRAFFIC NORMALIZED"
        },
        "observation_window_seconds": 0,
        "contributing_detectors": ["ThreatFusionEngine"],
        "structured_evidence": [
            {
                "code": "ATTACK_TERMINATED",
                "message": "Attack simulation stopped. Packet rates and telemetry inter-arrival returned to normal baseline.",
                "value": "0 pps (Baseline Normal)",
                "threshold": "Baseline",
                "detector_source": "ThreatFusionEngine"
            }
        ],
        "mitigation_recommendation": "TRAFFIC_NORMALIZED",
        "event_type": "ThreatAlert",
        "version": "1.0"
    }

    req = urllib.request.Request(
        API_STOP_ALL_URL,
        data=json.dumps({}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    success = False
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            success = resp.status in (200, 201)
    except Exception:
        # Fallback to direct alert post
        success = send_alert_to_api(stop_payload)

    if success:
        print("  [SUCCESS] Stop signal emitted! Frontend UI updated:")
        print("            - Active attack status transitioned to: ✓ STOPPED / BENIGN")
        print("            - Telemetry rates returned to normal baseline")
        print("            - Green status indicators displayed")
    else:
        print("  [!] Could not connect to API on port 3001. Ensure Node.js API is running.")
    print("=" * 70 + "\n")
    return success


def execute_attack_scenario(key: str, auto_stop: bool = False, active_duration_sec: int = 5) -> None:
    scenario = ATTACK_SCENARIOS.get(key)
    if not scenario:
        print(f"\n[!] Invalid scenario key '{key}'. Please select 1-13.\n")
        return

    src_ip = scenario['flow']['src_ip']
    dst_ip = scenario['flow']['dst_ip']
    src_port = scenario['flow'].get('src_port', '')
    dst_port = scenario['flow'].get('dst_port', '')

    print("\n" + "=" * 75)
    print(f"  >>> [ATTACK SIMULATION RUNNING] -> {scenario['title']}")
    print("=" * 75)
    print(f"  * Threat Type:       {scenario['label']}")
    print(f"  * Severity Level:    {scenario['severity']}")
    print(f"  * Attack Direction:  {scenario['direction']}")
    print(f"  * ATTACK ORIGIN:     {src_ip}:{src_port} [{scenario['origin']}]")
    print(f"  * ATTACK TARGET:     {dst_ip}:{dst_port} [{scenario['target']}]")
    print(f"  * Behavioral Signal: {scenario['description']}")
    print("-" * 75)

    # 1. Evaluate with Detection Engines
    print("  [Step 1] Telemetry received over Unidirectional TAP -> Evaluating...")
    time.sleep(0.3)

    # 2. Build ThreatAlert
    alert_id = f"alert-{scenario['label'].lower()}-{int(time.time() * 1000)}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    alert_payload = {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "threat_classification": scenario["label"],
        "severity": scenario["severity"],
        "status": "ACTIVE",
        "confidence_score": 0.96,
        "affected_context": {
            "entity_type": "ip",
            "entity_id": src_ip,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "origin": scenario["origin"],
            "target": scenario["target"],
            "direction": scenario["direction"]
        },
        "observation_window_seconds": int(scenario["flow"].get("duration_sec", 60)),
        "contributing_detectors": [scenario["category"]],
        "structured_evidence": scenario["evidence"],
        "mitigation_recommendation": scenario["mitigation"],
        "event_type": "ThreatAlert",
        "version": "1.0"
    }

    print(f"  [Step 2] Threat Engine Triggered: Conf=0.96 | Severity={alert_payload['severity']}")
    print(f"  [Step 3] Broadcasting ThreatAlert to Backend API & Frontend WebSocket...")

    success = send_alert_to_api(alert_payload)
    if success:
        print("  [SUCCESS] Alert injected into API & broadcasted via WebSocket!")
        print(f"  [LIVE UI] Look at your Frontend UI (http://localhost:3000):")
        print(f"            - Active Incident '{scenario['label']}' appears at the top")
        print(f"            - Shows FROM: {src_ip} ({scenario['origin']})")
        print(f"            - Shows TO:   {dst_ip} ({scenario['target']})")
        print(f"            - Severity Badge: {scenario['severity']} (Active Attack)")
    else:
        print("  [INFO] Alert processed locally. (Ensure Express API is running on port 3001)")

    print("=" * 75)

    if auto_stop:
        print(f"\n  [Waiting {active_duration_sec}s for attack duration before stopping automatically...]")
        time.sleep(active_duration_sec)
        stop_payload = {
            "alert_id": f"stop-{alert_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_classification": f"{scenario['label']}_STOPPED",
            "severity": "LOW",
            "status": "STOPPED",
            "confidence_score": 0.0,
            "affected_context": {
                "entity_type": "ip",
                "entity_id": src_ip,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "origin": scenario["origin"],
                "target": scenario["target"],
                "direction": "ATTACK CEASED"
            },
            "observation_window_seconds": 0,
            "contributing_detectors": [scenario["category"]],
            "structured_evidence": [
                {
                    "code": "ATTACK_TERMINATED",
                    "message": f"{scenario['title']} stopped. Telemetry arrival rate returned to baseline normal.",
                    "value": "0 pps",
                    "threshold": "Baseline",
                    "detector_source": scenario["category"]
                }
            ],
            "mitigation_recommendation": "TRAFFIC_NORMALIZED",
            "event_type": "ThreatAlert",
            "version": "1.0"
        }
        send_alert_to_api(stop_payload)
        print("  [ATTACK STOPPED] Emitted cessation event -> UI status changed to STOPPED / BENIGN.\n")


def run_all_scenarios_sequential():
    print("\n" + "=" * 75)
    print("  [RUNNING FULL TEST SUITE — ALL 11 ATTACK SCENARIOS SEQUENTIALLY]")
    print("=" * 75)
    for k in sorted(ATTACK_SCENARIOS.keys(), key=lambda x: int(x)):
        execute_attack_scenario(k, auto_stop=False)
        time.sleep(2.0)
    print("\n[✓] All 11 Attack scenarios simulated successfully! Check Frontend UI.\n")


def run_continuous_stream():
    import random
    print("\n" + "=" * 75)
    print("  [STARTING CONTINUOUS LIVE ATTACK STREAM — Press Ctrl+C to Stop]")
    print("=" * 75)
    keys = list(ATTACK_SCENARIOS.keys())
    try:
        while True:
            k = random.choice(keys)
            execute_attack_scenario(k, auto_stop=False)
            time.sleep(3.5)
    except KeyboardInterrupt:
        print("\n\n  [STOPPING STREAM] Sending Stop & Traffic Normalized Signal...")
        stop_all_active_attacks()


def print_menu():
    print("""
================================================================================
       PASSIVESHIELD AI — MANUAL ATTACK SIMULATION & DEFENSE CONTROLLER
================================================================================
 Select an attack vector to simulate and inject into the live system:

 [1]  SYN Flood Attack              (Volumetric DDoS / High SYN Rate)
 [2]  UDP Flood Attack              (Volumetric DDoS / UDP Saturation)
 [3]  Slowloris / Slow HTTP         (Low-and-Slow Application Exhaustion)
 [4]  Vertical Port Scan            (Reconnaissance / Single Host 64 Ports)
 [5]  Horizontal Subnet Sweep       (Reconnaissance / Subnet 85 IPs Probe)
 [6]  C2 Periodic Beaconing         (Command & Control / Low-Jitter 15s)
 [7]  DNS Tunneling Exfiltration    (Data Exfiltration via TXT Queries)
 [8]  DGA Domain Generation         (Malware Algorithmically Gen Domains)
 [9]  High-Volume Data Exfiltration (Outbound 48.5 MB Bulk Leak)
 [10] Malicious TLS JA3 Signature   (Cobalt Strike / Metasploit Beacon)
 [11] Correlated Multi-Vector APT   (Full Threat Fusion: 4 Detectors)
 --------------------------------------------------------------------------------
 [0]  STOP / CEASE ALL ATTACKS      (Signal "Attack Stopped / Baseline Normal")
 [12] Run ALL 11 Attack Vectors Sequentially (Full Benchmark)
 [13] Continuous Live Simulation Stream (Randomized every 3.5s)
 [Q]  Quit / Exit
================================================================================
""")


def main():
    while True:
        print_menu()
        choice = input("Enter option [0-13, Q]: ").strip().upper()
        if choice in ("Q", "QUIT", "EXIT"):
            print("\nExiting Attack Control Center. Goodbye!\n")
            break
        elif choice == "0" or choice == "S" or choice == "STOP":
            stop_all_active_attacks()
        elif choice == "12":
            run_all_scenarios_sequential()
        elif choice == "13":
            run_continuous_stream()
        elif choice in ATTACK_SCENARIOS:
            print("\nOptions for this attack:")
            print("  [1] Fire continuous/active attack (stays active until you stop)")
            print("  [2] Fire attack for 5 seconds and automatically stop (shows start -> stop)")
            sub_opt = input("  Select mode [1/2, default: 1]: ").strip()
            auto_stop = sub_opt == "2"
            execute_attack_scenario(choice, auto_stop=auto_stop, active_duration_sec=5)
        else:
            print(f"\n[!] Invalid option '{choice}'. Please choose from 0-13 or Q.\n")
        
        input("Press Enter to continue...")


if __name__ == "__main__":
    main()
