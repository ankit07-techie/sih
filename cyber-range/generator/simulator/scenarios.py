"""
PassiveShield AI Cyber Range — Traffic Simulator Scenarios
Generates realistic benign traffic and synthetic threat simulations strictly inside the isolated lab network.
Never targets external IP addresses or public infrastructure.
"""

import os
import time
import socket
import random
import string
import threading
import urllib.request


VICTIM_IP = os.getenv("VICTIM_IP", "172.28.0.10")
GENERATOR_IP = os.getenv("GENERATOR_IP", "172.28.0.20")


def random_subdomain(length=30):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


class ScenarioSimulator:
    """
    Traffic generator for lab scenarios inside threat-lab-network.
    """

    @staticmethod
    def run_benign_tcp(duration_sec=10):
        print(f"[GENERATOR] Running BENIGN TCP Scenario against {VICTIM_IP}:80 for {duration_sec}s...")
        t_end = time.time() + duration_sec
        count = 0
        while time.time() < t_end:
            try:
                req = urllib.request.Request(f"http://{VICTIM_IP}/", headers={"User-Agent": "Lab-Browser/1.0"})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    _ = resp.read()
                count += 1
                time.sleep(random.uniform(0.2, 0.8))
            except Exception:
                time.sleep(0.5)
        print(f"[GENERATOR] BENIGN TCP complete: {count} HTTP requests sent.")

    @staticmethod
    def run_benign_dns(duration_sec=10):
        print(f"[GENERATOR] Running BENIGN DNS Scenario against {VICTIM_IP}:53 for {duration_sec}s...")
        t_end = time.time() + duration_sec
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        count = 0
        while time.time() < t_end:
            try:
                tx_id = random.randbytes(2)
                # Standard query for normal domain
                query = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
                sock.sendto(query, (VICTIM_IP, 53))
                count += 1
                time.sleep(random.uniform(0.3, 1.0))
            except Exception:
                time.sleep(0.5)
        sock.close()
        print(f"[GENERATOR] BENIGN DNS complete: {count} queries sent.")

    @staticmethod
    def run_syn_flood(duration_sec=10):
        print(f"[GENERATOR] Running SYN FLOOD Simulation against {VICTIM_IP}:80 for {duration_sec}s...")
        t_end = time.time() + duration_sec
        count = 0
        while time.time() < t_end:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.05)
                # Initiate TCP SYN connect attempt
                sock.connect_ex((VICTIM_IP, 80))
                sock.close()
                count += 1
            except Exception:
                pass
        print(f"[GENERATOR] SYN FLOOD complete: {count} connection attempts sent.")

    @staticmethod
    def run_udp_flood(duration_sec=10):
        print(f"[GENERATOR] Running UDP FLOOD Simulation against {VICTIM_IP}:9999 for {duration_sec}s...")
        t_end = time.time() + duration_sec
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * 1024
        count = 0
        while time.time() < t_end:
            try:
                sock.sendto(payload, (VICTIM_IP, 9999))
                count += 1
            except Exception:
                pass
        sock.close()
        print(f"[GENERATOR] UDP FLOOD complete: {count} UDP packets sent.")

    @staticmethod
    def run_slow_http(duration_sec=15):
        print(f"[GENERATOR] Running SLOW HTTP Simulation against {VICTIM_IP}:80 for {duration_sec}s...")
        sockets = []
        # Open 10 slow HTTP connections sending headers at 5-second intervals
        for _ in range(10):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((VICTIM_IP, 80))
                s.send(b"POST / HTTP/1.1\r\nHost: victim.lab.internal\r\nContent-Length: 1000\r\n")
                sockets.append(s)
            except Exception:
                pass

        t_end = time.time() + duration_sec
        while time.time() < t_end:
            for s in sockets:
                try:
                    s.send(b"X-Header: " + random_subdomain(10).encode('utf-8') + b"\r\n")
                except Exception:
                    pass
            time.sleep(3.0)

        for s in sockets:
            try:
                s.close()
            except Exception:
                pass
        print(f"[GENERATOR] SLOW HTTP complete: {len(sockets)} slow HTTP sessions executed.")

    @staticmethod
    def run_dns_tunnel(duration_sec=10):
        print(f"[GENERATOR] Running DNS TUNNEL Simulation against {VICTIM_IP}:53 for {duration_sec}s...")
        t_end = time.time() + duration_sec
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        count = 0
        while time.time() < t_end:
            try:
                tx_id = random.randbytes(2)
                subdomain = random_subdomain(50)
                # Form TXT query payload for tunneling simulation
                query = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes([len(subdomain)]) + subdomain.encode('utf-8') + b"\x06tunnel\x03org\x00\x00\x10\x00\x01"
                sock.sendto(query, (VICTIM_IP, 53))
                count += 1
                time.sleep(0.1)
            except Exception:
                time.sleep(0.2)
        sock.close()
        print(f"[GENERATOR] DNS TUNNEL complete: {count} tunneling queries sent.")

    @staticmethod
    def run_dga(duration_sec=10):
        print(f"[GENERATOR] Running DGA Simulation against {VICTIM_IP}:53 for {duration_sec}s...")
        t_end = time.time() + duration_sec
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        count = 0
        while time.time() < t_end:
            try:
                tx_id = random.randbytes(2)
                dga_name = "dga" + random_subdomain(20)
                query = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes([len(dga_name)]) + dga_name.encode('utf-8') + b"\x03com\x00\x00\x01\x00\x01"
                sock.sendto(query, (VICTIM_IP, 53))
                count += 1
                time.sleep(0.15)
            except Exception:
                time.sleep(0.2)
        sock.close()
        print(f"[GENERATOR] DGA Simulation complete: {count} algorithmic domain queries sent.")

    @staticmethod
    def run_c2_beacon(duration_sec=15):
        print(f"[GENERATOR] Running C2 BEACON Simulation against {VICTIM_IP}:443 for {duration_sec}s...")
        t_end = time.time() + duration_sec
        count = 0
        while time.time() < t_end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((VICTIM_IP, 443))
                s.sendall(b"\x16\x03\x01\x00\x64" + b"BEACON_PROBE")
                _ = s.recv(1024)
                s.close()
                count += 1
                time.sleep(2.0)  # Periodic beaconing interval
            except Exception:
                time.sleep(2.0)
        print(f"[GENERATOR] C2 BEACON complete: {count} periodic beacon probes sent.")

    @classmethod
    def run_mixed(cls, duration_sec=15):
        print(f"[GENERATOR] Running MIXED THREAT SCENARIO against {VICTIM_IP} for {duration_sec}s...")
        threads = [
            threading.Thread(target=cls.run_benign_tcp, args=(duration_sec,)),
            threading.Thread(target=cls.run_benign_dns, args=(duration_sec,)),
            threading.Thread(target=cls.run_syn_flood, args=(duration_sec,)),
            threading.Thread(target=cls.run_udp_flood, args=(duration_sec,)),
            threading.Thread(target=cls.run_slow_http, args=(duration_sec,)),
            threading.Thread(target=cls.run_dns_tunnel, args=(duration_sec,)),
            threading.Thread(target=cls.run_dga, args=(duration_sec,)),
            threading.Thread(target=cls.run_c2_beacon, args=(duration_sec,))
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print("[GENERATOR] MIXED THREAT SCENARIO COMPLETE.")
