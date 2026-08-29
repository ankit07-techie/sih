"""
PassiveShield AI Cyber Range — Passive Network PCAP Sensor
Passively captures network traffic on the isolated lab network interface without injecting packets or modifying traffic.
Outputs binary .pcap capture files to /captures directory.
"""

import os
import sys
import time
import struct
import socket
import argparse
from datetime import datetime


PCAP_GLOBAL_HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


class PassiveSensor:
    """
    100% Passive Network Sensor for Cyber Range Lab environment.
    Uses AF_PACKET raw socket reading (Linux) or socket listener to passively write .pcap files.
    """

    def __init__(self, output_dir: str = "/captures"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def capture_scenario(self, scenario_name: str, duration_sec: int = 10) -> str:
        filepath = os.path.join(self.output_dir, f"{scenario_name}.pcap")
        print(f"[SENSOR] Starting passive PCAP capture for scenario '{scenario_name}' -> {filepath}")

        packets = []
        base_ts = int(time.time())

        # Attempt raw packet capture on Linux socket if available
        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            raw_sock.settimeout(1.0)

            t_end = time.time() + duration_sec
            while time.time() < t_end:
                try:
                    pkt_data, _ = raw_sock.recvfrom(65535)
                    ts_now = time.time()
                    ts_sec = int(ts_now)
                    ts_usec = int((ts_now - ts_sec) * 1_000_000)
                    pkt_len = len(pkt_data)
                    pkt_rec_hdr = struct.pack('<IIII', ts_sec, ts_usec, pkt_len, pkt_len)
                    packets.append(pkt_rec_hdr + pkt_data)
                except socket.timeout:
                    continue
            raw_sock.close()
        except Exception as e:
            print(f"[SENSOR] Note: Raw socket access fallback (non-root or simulated): {e}")

        # Write PCAP file
        with open(filepath, 'wb') as f:
            f.write(PCAP_GLOBAL_HEADER)
            for pkt in packets:
                f.write(pkt)

        print(f"[SENSOR] Capture complete: {len(packets)} packets written to {filepath}")
        return filepath


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PassiveShield Cyber Range Sensor")
    parser.add_argument("--scenario", default="mixed", help="Scenario name for capture file")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds")
    parser.add_argument("--output-dir", default="/captures", help="Target output directory")

    args = parser.parse_args()
    sensor = PassiveSensor(output_dir=args.output_dir)
    sensor.capture_scenario(args.scenario, duration_sec=args.duration)
