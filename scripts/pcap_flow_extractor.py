"""
PassiveShield AI — Pure Python PCAP Generator & Passive Flow Extractor
Generates compliant binary .pcap files for synthetic passive flow validation and parses .pcap binary data into 5-tuple flow metrics and feature snapshots without active network interaction.
"""

import os
import sys
import struct
import socket
import math
import time
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone

# Global PCAP Header format: <IHHIIII
# Magic: 0xa1b2c3d4, Version: 2.4, Snaplen: 65535, Network: 1 (Ethernet)
PCAP_GLOBAL_HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


def ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)


def bytes_to_ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in frequencies.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 2)


class PCAPBuilder:
    """
    Constructs binary .pcap files containing synthetic Ethernet/IP/TCP/UDP packet headers.
    """

    def __init__(self, filename: str):
        self.filename = filename
        self.packets: List[bytes] = []

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str = "TCP",
        ts_sec: int = 1724854380,
        ts_usec: int = 0,
        payload: bytes = b"",
        tcp_flags: int = 0x02  # SYN=0x02, ACK=0x10, SYN-ACK=0x12
    ):
        # 1. Ethernet Header (14 bytes): Dst MAC, Src MAC, EthType (0x0800 = IPv4)
        eth_hdr = struct.pack('!6s6sH', b'\x00\x11\x22\x33\x44\x55', b'\x66\x77\x88\x99\xaa\xbb', 0x0800)

        # 2. IP / Transport Headers
        proto_code = 6 if protocol.upper() == "TCP" else 17

        if protocol.upper() == "TCP":
            # TCP Header (20 bytes): src_port, dst_port, seq, ack_seq, offset_flags, window, checksum, urg_ptr
            trans_hdr = struct.pack('!HHIIHHHH', src_port, dst_port, 1000, 0, (5 << 12) | tcp_flags, 8192, 0, 0)
        else:
            # UDP Header (8 bytes): src_port, dst_port, length, checksum
            udp_len = 8 + len(payload)
            trans_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)

        ip_len = 20 + len(trans_hdr) + len(payload)
        # IP Header (20 bytes): ver_ihl, tos, total_len, id, flags_offset, ttl, protocol, checksum, src_ip, dst_ip
        ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 54321, 0, 64, proto_code, 0, ip_to_bytes(src_ip), ip_to_bytes(dst_ip))

        full_pkt = eth_hdr + ip_hdr + trans_hdr + payload
        pkt_len = len(full_pkt)

        # PCAP Packet Record Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
        pkt_rec_hdr = struct.pack('<IIII', ts_sec, ts_usec, pkt_len, pkt_len)
        self.packets.append(pkt_rec_hdr + full_pkt)

    def save(self):
        with open(self.filename, 'wb') as f:
            f.write(PCAP_GLOBAL_HEADER)
            for pkt in self.packets:
                f.write(pkt)


class PassivePCAPParser:
    """
    Passively parses binary .pcap files, extracting Ethernet/IP 5-tuple flow metrics
    without generating any active network traffic.
    """

    @staticmethod
    def parse_pcap(filepath: str) -> List[Dict[str, Any]]:
        with open(filepath, 'rb') as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                raise ValueError("PCAP file too small")
            magic = struct.unpack('<I', global_hdr[:4])[0]
            if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
                raise ValueError(f"Invalid PCAP magic: {hex(magic)}")

            flows: Dict[str, Dict[str, Any]] = {}

            while True:
                rec_hdr = f.read(16)
                if not rec_hdr or len(rec_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rec_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                # Parse Ethernet Header (14B)
                if len(pkt_data) < 34:  # 14B Eth + 20B IP
                    continue

                eth_type = struct.unpack('!H', pkt_data[12:14])[0]
                if eth_type != 0x0800:  # IPv4
                    continue

                # Parse IP Header (20B)
                ip_hdr = pkt_data[14:34]
                ver_ihl, tos, tot_len, pkt_id, off, ttl, proto_code, csum, src_ip_b, dst_ip_b = struct.unpack('!BBHHHBBH4s4s', ip_hdr)
                src_ip = bytes_to_ip(src_ip_b)
                dst_ip = bytes_to_ip(dst_ip_b)

                proto_str = "tcp" if proto_code == 6 else ("udp" if proto_code == 17 else "other")

                # Parse Transport Header
                trans_data = pkt_data[34:]
                if len(trans_data) < 8:
                    continue

                if proto_str == "tcp":
                    src_port, dst_port, seq, ack_seq, offset_flags = struct.unpack('!HHIIH', trans_data[:14])
                    flags = offset_flags & 0x00ff
                    syn_flag = 1 if (flags & 0x02) else 0
                    ack_flag = 1 if (flags & 0x10) else 0
                else:
                    src_port, dst_port = struct.unpack('!HH', trans_data[:4])
                    syn_flag = 0
                    ack_flag = 0

                pkt_ts = ts_sec + (ts_usec / 1e6)
                flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto_str}"

                if flow_key not in flows:
                    flows[flow_key] = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": proto_str,
                        "start_ts": pkt_ts,
                        "end_ts": pkt_ts,
                        "packets_forward": 0,
                        "bytes_forward": 0,
                        "syn_count": 0,
                        "ack_count": 0,
                        "timestamps": []
                    }

                flow = flows[flow_key]
                flow["packets_forward"] += 1
                flow["bytes_forward"] += incl_len
                flow["syn_count"] += syn_flag
                flow["ack_count"] += ack_flag
                flow["end_ts"] = max(flow["end_ts"], pkt_ts)
                flow["timestamps"].append(pkt_ts)

            # Summarize flows
            summaries = []
            for k, flow in flows.items():
                duration = max(0.001, flow["end_ts"] - flow["start_ts"])
                iats = []
                if len(flow["timestamps"]) > 1:
                    ts_list = sorted(flow["timestamps"])
                    iats = [ts_list[i] - ts_list[i-1] for i in range(1, len(ts_list))]

                mean_iat = (sum(iats) / len(iats)) if iats else 0.0
                std_iat = math.sqrt(sum((x - mean_iat)**2 for x in iats) / len(iats)) if len(iats) > 1 else 0.0

                summaries.append({
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                    "src_port": flow["src_port"],
                    "dst_port": flow["dst_port"],
                    "protocol": flow["protocol"],
                    "duration_sec": round(duration, 3),
                    "packets_forward": flow["packets_forward"],
                    "packets_backward": 0,  # One-directional passive observation
                    "bytes_forward": flow["bytes_forward"],
                    "bytes_backward": 0,
                    "syn_count": flow["syn_count"],
                    "ack_count": flow["ack_count"],
                    "mean_iat_ms": round(mean_iat * 1000.0, 2),
                    "std_iat_ms": round(std_iat * 1000.0, 2),
                    "timestamps": flow["timestamps"],
                    "iats": iats
                })

            return summaries
