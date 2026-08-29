"""
PassiveShield AI Cyber Range — Lab Victim Multi-Protocol Service Server
Runs isolated HTTP (port 80), UDP (port 9999), DNS (port 53), and HTTPS/C2 target (port 443) services.
Never probes or interacts outside the lab network.
"""

import sys
import time
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class LabHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('X-Lab-Server', 'PassiveShield-Victim-v2')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>PassiveShield Lab Victim HTTP Service</h1></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        _ = self.rfile.read(content_length) if content_length > 0 else b""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "message": "Telemetry received"}')

    def log_message(self, format, *args):
        # Suppress verbose HTTP access logs in test lab
        pass


def run_http_server(host='0.0.0.0', port=80):
    server = HTTPServer((host, port), LabHTTPHandler)
    server.serve_forever()


def run_udp_server(host='0.0.0.0', port=9999):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except Exception:
            break


def run_dns_server(host='0.0.0.0', port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) >= 12:
                # Basic DNS header response (NOERROR or NXDOMAIN for lab testing)
                tx_id = data[:2]
                flags = b'\x81\x80' if b'dga' not in data.lower() else b'\x81\x83' # 0x8183 = NXDOMAIN
                resp = tx_id + flags + b'\x00\x01\x00\x01\x00\x00\x00\x00' + data[12:]
                sock.sendto(resp, addr)
        except Exception:
            break


def run_c2_target_server(host='0.0.0.0', port=443):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(10)
    while True:
        try:
            conn, addr = sock.accept()
            # Send dummy C2 server response payload
            conn.sendall(b"\x16\x03\x03\x00\x46\x02\x00\x00\x42\x03\x03" + b"A" * 60)
            conn.close()
        except Exception:
            break


def start_victim_services():
    print("==========================================================")
    print("PASSIVESHIELD CYBER RANGE — VICTIM LAB SERVICES STARTING")
    print("Target Services: HTTP:80, UDP:9999, DNS:53, HTTPS/C2:443")
    print("==========================================================")

    t_http = threading.Thread(target=run_http_server, daemon=True)
    t_udp = threading.Thread(target=run_udp_server, daemon=True)
    t_dns = threading.Thread(target=run_dns_server, daemon=True)
    t_c2 = threading.Thread(target=run_c2_target_server, daemon=True)

    t_http.start()
    t_udp.start()
    t_dns.start()
    t_c2.start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    start_victim_services()
