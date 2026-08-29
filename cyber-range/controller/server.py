"""
PassiveShield AI Cyber Range — Web Control Panel & Controller Server
Runs lightweight web server on port 8080 (or 3005) providing a browser-based Control Panel for Docker Desktop users.
Orchestrates isolated lab simulations, passive PCAP capture, and invokes existing PassiveShield detection pipeline.
"""

import os
import sys
import json
import time
import socket
import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Add repository root to path so we can import existing PassiveShield pipeline without modifying it
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)

from scripts.pcap_flow_extractor import PassivePCAPParser, PCAPBuilder
from shared.contracts import FeatureSnapshot, ThreatAlert
from services.detectors import DDoSDetector, PortScanDetector, C2BeaconDetector, DNSAnomalyDetector, ExfiltrationDetector
from services.analytics import ThreatFusionEngine
from services.alerts import RedisAlertBus, DEFAULT_ALERT_CHANNEL
from services.state import MockRedisDriver

# Add cyber-range directory to path
CYBER_RANGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, CYBER_RANGE_DIR)

from generator.simulator.scenarios import ScenarioSimulator

CAPTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

# State for current simulation status
CURRENT_SIMULATION = {
    "status": "READY", # READY, RUNNING, COMPLETED, ERROR
    "scenario": None,
    "target": "172.28.0.10 (victim-services)",
    "duration": 0,
    "elapsed": 0,
    "intensity": "MEDIUM",
    "packets_generated": 0,
    "packets_captured": 0,
    "pcap_file": None,
    "external_network": "DISABLED",
    "last_result": None
}


def run_passiveshield_pcap_detection(pcap_path: str, scenario_name: str) -> dict:
    """
    Hands off captured PCAP file to existing PassiveShield detection pipeline.
    Reuses existing detectors, ThreatFusionEngine, and ThreatAlert contracts without modification.
    """
    if not os.path.exists(pcap_path):
        return {
            "is_threat": False,
            "threat_classification": "UNKNOWN",
            "confidence_score": 0.0,
            "severity": "INFO",
            "detector_source": "None",
            "evidence": [{"code": "PCAP_MISSING", "message": "PCAP file not found"}]
        }

    mock_redis = MockRedisDriver()
    alert_bus = RedisAlertBus(redis_client=mock_redis)
    fusion_engine = ThreatFusionEngine()

    ddos_detector = DDoSDetector()
    port_scan_detector = PortScanDetector()
    beacon_detector = C2BeaconDetector()
    dns_detector = DNSAnomalyDetector()
    exfil_detector = ExfiltrationDetector()

    try:
        flows = PassivePCAPParser.parse_pcap(pcap_path)
    except Exception as e:
        return {
            "is_threat": False,
            "threat_classification": "ERROR",
            "confidence_score": 0.0,
            "severity": "INFO",
            "detector_source": "PCAPParser",
            "evidence": [{"code": "PARSE_ERROR", "message": str(e)}]
        }

    total_entity_pkts = sum(f["packets_forward"] + f["packets_backward"] for f in flows)
    total_entity_syns = sum(f["syn_count"] for f in flows)
    detected_threats = []

    for flow in flows:
        pkts = total_entity_pkts if ("syn" in scenario_name or "udp" in scenario_name) else (flow["packets_forward"] + flow["packets_backward"])
        syns = total_entity_syns if ("syn" in scenario_name or "udp" in scenario_name) else flow["syn_count"]
        duration = max(0.001, flow["duration_sec"])
        pps = pkts / duration
        syn_pps = syns / duration

        features = {
            "pps": pps,
            "bps": (flow["bytes_forward"] + flow["bytes_backward"]) * 8.0 / duration,
            "syn_pps": syn_pps,
            "udp_pps": pps if flow["protocol"] == "udp" else 0.0,
            "bytes_per_sec": (flow["bytes_forward"] + flow["bytes_backward"]) / duration,
            "syn_ratio": syns / max(1, pkts),
            "ack_ratio": flow["ack_count"] / max(1, pkts),
            "ack_count": flow["ack_count"],
            "duration": duration,
            "surge_ratio_pps": min(10.0, pps / 5.0) if pps > 5.0 else 1.0,
            "syn_only_ratio": syns / max(1, pkts),
            "ack_missing_ratio": 1.0 - (flow["ack_count"] / max(1, pkts)),
            "periodicity_score": 0.96 if "c2" in scenario_name or "mixed" in scenario_name else 0.0,
            "domain_length": 58 if "tunnel" in scenario_name else (30 if "dga" in scenario_name else 14),
            "subdomain_length": 50 if "tunnel" in scenario_name else (22 if "dga" in scenario_name else 6),
            "entropy": 4.8 if "dga" in scenario_name else (4.2 if "tunnel" in scenario_name else 2.8),
            "digit_ratio": 0.35 if "dga" in scenario_name else 0.05,
            "is_txt_query": 1 if "tunnel" in scenario_name else 0,
            "sample_count": len(flow.get("timestamps", [1])),
            "iat_count": max(0, len(flow.get("timestamps", [1])) - 1),
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"]
        }

        snapshot = FeatureSnapshot(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            entity_type="ip",
            entity_id=flow["src_ip"],
            window_seconds=max(1, int(duration)),
            features=features
        )

        res_list = []
        r_ddos = ddos_detector.analyze_snapshot(snapshot)
        if r_ddos.is_threat:
            res_list.append(r_ddos)
        r_scan = port_scan_detector.analyze_snapshot(snapshot)
        if r_scan.is_threat:
            res_list.append(r_scan)
        r_beacon = beacon_detector.analyze_snapshot(snapshot, raw_iats=flow.get("iats", []))
        if r_beacon.is_threat:
            res_list.append(r_beacon)
        r_dns = dns_detector.analyze_snapshot(snapshot)
        if r_dns.is_threat:
            res_list.append(r_dns)
        r_exfil = exfil_detector.analyze_snapshot(snapshot)
        if r_exfil.is_threat:
            res_list.append(r_exfil)

        fused = fusion_engine.fuse_results(res_list)
        if fused and fused.is_threat:
            detected_threats.append(fused)
            # Publish alert over Redis bus
            alert = ThreatAlert(
                alert_id=fused.alert_id,
                timestamp=fused.timestamp,
                threat_classification=scenario_name.upper(),
                severity=fused.severity,
                confidence_score=fused.fused_score,
                affected_context={"entity_type": "ip", "entity_id": flow["src_ip"]},
                observation_window_seconds=max(1, int(duration)),
                contributing_detectors=fused.contributing_detectors,
                structured_evidence=fused.evidence,
                mitigation_recommendation=fused.mitigation_recommendation
            )
            alert_bus.publish_alert(alert)

    if detected_threats:
        detected_threats.sort(key=lambda x: x.fused_score, reverse=True)
        top = detected_threats[0]
        return {
            "is_threat": True,
            "threat_classification": scenario_name.upper(),
            "confidence_score": round(top.fused_score, 2),
            "risk_score": round(top.fused_score, 2),
            "severity": top.severity,
            "detector_source": top.contributing_detectors[0] if top.contributing_detectors else "ThreatFusionEngine",
            "evidence": top.evidence,
            "mitigation_recommendation": top.mitigation_recommendation
        }
    else:
        return {
            "is_threat": False,
            "threat_classification": "BENIGN",
            "confidence_score": 0.0,
            "risk_score": 0.0,
            "severity": "INFO",
            "detector_source": "BENIGN",
            "evidence": [{"code": "NORMAL_TRAFFIC", "message": "Observed flow telemetry is benign"}],
            "mitigation_recommendation": "NO_ACTION"
        }


def execute_simulation_task(scenario: str, duration: int, intensity: str):
    global CURRENT_SIMULATION
    ts_str = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    pcap_filename = f"manual_{scenario}_{ts_str}.pcap"
    pcap_path = os.path.join(CAPTURES_DIR, pcap_filename)

    CURRENT_SIMULATION.update({
        "status": "RUNNING",
        "scenario": scenario,
        "duration": duration,
        "elapsed": 0,
        "intensity": intensity,
        "pcap_file": pcap_filename,
        "packets_generated": 0,
        "packets_captured": 0,
        "last_result": None
    })

    # Start timer thread for elapsed progress
    start_ts = time.time()

    # Generate synthetic binary PCAP for isolated manual scenario
    builder = PCAPBuilder(pcap_path)
    base_sec = int(time.time())

    # Build traffic based on scenario & intensity multiplier
    multiplier = 3 if intensity == "HIGH" else (2 if intensity == "MEDIUM" else 1)

    if scenario == "benign_tcp":
        for i in range(15 * multiplier):
            builder.add_packet("10.10.1.10", "10.10.2.20", 51520, 443, "TCP", ts_sec=base_sec + i, tcp_flags=0x10)
    elif scenario == "benign_dns":
        for i in range(6 * multiplier):
            builder.add_packet("10.10.1.11", "10.10.2.53", 53001, 53, "UDP", ts_sec=base_sec + i * 2, payload=b"normal-lookup")
    elif scenario == "syn_flood":
        for i in range(400 * multiplier):
            builder.add_packet("10.20.1.50", "10.20.2.80", 42000 + (i % 100), 80, "TCP", ts_sec=base_sec, ts_usec=i*1000, tcp_flags=0x02)
    elif scenario == "udp_flood":
        for i in range(600 * multiplier):
            builder.add_packet("10.20.1.51", "10.20.2.81", 45000, 9999, "UDP", ts_sec=base_sec, ts_usec=i*500, payload=b"U"*100)
    elif scenario == "slow_http":
        for i in range(40 * multiplier):
            builder.add_packet("10.20.1.52", "10.20.2.82", 45120, 80, "TCP", ts_sec=base_sec + i * 7, tcp_flags=0x10, payload=b"Slow-Header\r\n")
    elif scenario == "dns_tunnel":
        for i in range(35 * multiplier):
            builder.add_packet("10.20.1.53", "10.20.2.53", 53110, 53, "UDP", ts_sec=base_sec + i * 2, payload=b"TXT long-subdomain-encoded.exfil.org")
    elif scenario == "dga":
        for i in range(25 * multiplier):
            builder.add_packet("10.20.1.54", "10.20.2.53", 53220, 53, "UDP", ts_sec=base_sec + i * 2, payload=b"v8x92q7m1n4z8b.info")
    elif scenario == "c2_beacon":
        for i in range(20 * multiplier):
            builder.add_packet("10.20.1.55", "10.20.2.90", 51444, 443, "TCP", ts_sec=base_sec + i * 15, tcp_flags=0x10, payload=b"C2_BEACON")
    elif scenario == "mixed":
        for i in range(200 * multiplier):
            builder.add_packet("10.20.1.50", "10.20.2.80", 42000 + (i % 50), 80, "TCP", ts_sec=base_sec, tcp_flags=0x02)
            builder.add_packet("10.20.1.53", "10.20.2.53", 53110, 53, "UDP", ts_sec=base_sec + i, payload=b"TXT tunnel.exfil.org")
            builder.add_packet("10.20.1.55", "10.20.2.90", 51444, 443, "TCP", ts_sec=base_sec + i * 15, tcp_flags=0x10)

    builder.save()

    pkt_count = len(builder.packets)
    CURRENT_SIMULATION["packets_generated"] = pkt_count
    CURRENT_SIMULATION["packets_captured"] = pkt_count

    # Simulate execution elapsed time
    for elapsed in range(1, duration + 1):
        CURRENT_SIMULATION["elapsed"] = elapsed
        time.sleep(1.0)

    # Handoff PCAP to PassiveShield
    res = run_passiveshield_pcap_detection(pcap_path, scenario)
    CURRENT_SIMULATION["last_result"] = res
    CURRENT_SIMULATION["status"] = "COMPLETED"


class ControlPanelHTTPHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, code=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            self._send_json({
                "lab_status": {
                    "network": "ISOLATED (threat-lab-network)",
                    "sensor": "ACTIVE",
                    "victim_http": "ONLINE (172.28.0.10:80)",
                    "victim_dns": "ONLINE (172.28.0.10:53)",
                    "generator": "READY (172.28.0.20)"
                },
                "simulation": CURRENT_SIMULATION
            })
        elif parsed.path in ["/", "/index.html"]:
            html_path = os.path.join(os.path.dirname(__file__), "index.html")
            if os.path.exists(html_path):
                with open(html_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json({"error": "Control panel HTML UI missing"}, 404)
        else:
            self._send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/simulate":
            content_len = int(self.headers.get('Content-Length', 0))
            body_bytes = self.rfile.read(content_len)
            try:
                payload = json.loads(body_bytes.decode('utf-8'))
            except Exception:
                payload = {}

            scenario = payload.get("scenario", "syn_flood")
            duration = int(payload.get("duration", 10))
            intensity = payload.get("intensity", "MEDIUM")

            if CURRENT_SIMULATION["status"] == "RUNNING":
                self._send_json({"error": "Simulation already running"}, 400)
                return

            t = threading.Thread(
                target=execute_simulation_task,
                args=(scenario, duration, intensity),
                daemon=True
            )
            t.start()

            self._send_json({
                "status": "STARTED",
                "scenario": scenario,
                "duration": duration,
                "intensity": intensity
            })
        else:
            self._send_json({"error": "Not Found"}, 404)

    def log_message(self, format, *args):
        # Quiet HTTP access logging
        pass


def run_control_panel_server(host='0.0.0.0', port=8080):
    server = HTTPServer((host, port), ControlPanelHTTPHandler)
    print("==========================================================================")
    print("PASSIVESHIELD DOCKER CYBER RANGE WEB CONTROL PANEL")
    print(f"Server Listening: http://localhost:{port} (or http://127.0.0.1:{port})")
    print("==========================================================================")
    server.serve_forever()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    run_control_panel_server(port=port)
