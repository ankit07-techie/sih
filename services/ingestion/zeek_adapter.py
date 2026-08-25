"""
PassiveShield AI — Zeek Log Ingestion Adapter
Parses raw JSON lines from Zeek conn.log, dns.log, and ssl.log files,
validates required fields, and maps them to normalized internal event schemas.
"""

import json
from typing import Dict, Any, Optional

class ZeekAdapterError(Exception):
    """Exception raised for unrecoverable Zeek log parsing errors."""
    pass

class ZeekAdapter:
    """Parser and validator converting raw Zeek JSON logs into internal ingestion boundary objects."""

    @staticmethod
    def parse_conn_event(raw_json_line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a line from conn.log into a normalized flow event dictionary.
        Returns None if line is empty or malformed.
        """
        if not raw_json_line or not raw_json_line.strip():
            return None

        try:
            data = json.loads(raw_json_line.strip())
        except json.JSONDecodeError:
            return None

        # Validate mandatory flow fields
        required_keys = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]
        for key in required_keys:
            if key not in data or data[key] is None:
                return None

        return {
            "event_type": "NormalizedFlowEvent",
            "version": "1.0",
            "timestamp": str(data["ts"]),
            "flow_id": str(data["uid"]),
            "src_ip": str(data["id.orig_h"]),
            "src_port": int(data["id.orig_p"]),
            "dst_ip": str(data["id.resp_h"]),
            "dst_port": int(data["id.resp_p"]),
            "protocol": str(data["proto"]).lower(),
            "duration": float(data.get("duration", 0.0) or 0.0),
            "orig_bytes": int(data.get("orig_bytes", 0) or 0),
            "resp_bytes": int(data.get("resp_bytes", 0) or 0),
            "orig_packets": int(data.get("orig_pkts", 0) or 0),
            "resp_packets": int(data.get("resp_pkts", 0) or 0),
            "conn_state": str(data.get("conn_state", "UNKNOWN")),
            "service": str(data.get("service", ""))
        }

    @staticmethod
    def parse_dns_event(raw_json_line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a line from dns.log into a normalized DNS observation dictionary.
        Returns None if line is empty or malformed.
        """
        if not raw_json_line or not raw_json_line.strip():
            return None

        try:
            data = json.loads(raw_json_line.strip())
        except json.JSONDecodeError:
            return None

        # Validate mandatory DNS fields
        required_keys = ["ts", "uid", "id.orig_h", "query"]
        for key in required_keys:
            if key not in data or data[key] is None:
                return None

        answers = data.get("answers", [])
        if not isinstance(answers, list):
            answers = []

        return {
            "event_type": "DNSObservation",
            "version": "1.0",
            "timestamp": str(data["ts"]),
            "flow_id": str(data["uid"]),
            "client_ip": str(data["id.orig_h"]),
            "server_ip": str(data.get("id.resp_h", "")),
            "query_domain": str(data["query"]),
            "query_type": str(data.get("qtype_name", "A")),
            "response_code": str(data.get("rcode_name", "NOERROR")),
            "answers": [str(ans) for ans in answers]
        }

    @staticmethod
    def parse_ssl_event(raw_json_line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a line from ssl.log into a normalized TLS observation dictionary.
        Returns None if line is empty or malformed.
        """
        if not raw_json_line or not raw_json_line.strip():
            return None

        try:
            data = json.loads(raw_json_line.strip())
        except json.JSONDecodeError:
            return None

        # Validate mandatory TLS fields
        required_keys = ["ts", "uid", "id.orig_h", "id.resp_h"]
        for key in required_keys:
            if key not in data or data[key] is None:
                return None

        return {
            "event_type": "TLSObservation",
            "version": "1.0",
            "timestamp": str(data["ts"]),
            "flow_id": str(data["uid"]),
            "client_ip": str(data["id.orig_h"]),
            "server_ip": str(data["id.resp_h"]),
            "tls_version": str(data.get("version", "UNKNOWN")),
            "cipher_suite": str(data.get("cipher", "UNKNOWN")),
            "sni_hostname": str(data.get("server_name", "")),
            "established": bool(data.get("established", False))
        }
