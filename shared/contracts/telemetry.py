"""
PassiveShield AI — Versioned Telemetry Event Contracts
Data contract classes for NormalizedFlowEvent, DNSObservation, and TLSObservation.
Includes strict type validation, IP address verification, and JSON serialization.
"""

import json
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


class ContractValidationError(ValueError):
    """Raised when telemetry data violates contract schema or validation constraints."""
    pass


def _validate_ip(ip_str: str, field_name: str, allow_empty: bool = False) -> str:
    """Validates IPv4 or IPv6 address string."""
    if not ip_str:
        if allow_empty:
            return ""
        raise ContractValidationError(f"Field '{field_name}' cannot be empty.")
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError as e:
        raise ContractValidationError(f"Invalid IP address for '{field_name}': '{ip_str}'") from e


def _validate_port(port: int, field_name: str) -> int:
    """Validates TCP/UDP port number (0-65535)."""
    if not isinstance(port, int) or not (0 <= port <= 65535):
        raise ContractValidationError(f"Field '{field_name}' must be an integer between 0 and 65535, got: {port}")
    return port


def _validate_non_negative_int(val: int, field_name: str) -> int:
    """Validates non-negative integer."""
    if not isinstance(val, int) or val < 0:
        raise ContractValidationError(f"Field '{field_name}' must be a non-negative integer, got: {val}")
    return val


def _validate_non_negative_float(val: float, field_name: str) -> float:
    """Validates non-negative float."""
    if not isinstance(val, (int, float)) or val < 0:
        raise ContractValidationError(f"Field '{field_name}' must be a non-negative float/int, got: {val}")
    return float(val)


@dataclass
class NormalizedFlowEvent:
    timestamp: str
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    event_type: str = "NormalizedFlowEvent"
    version: str = "1.0"
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_packets: int = 0
    resp_packets: int = 0
    conn_state: str = "UNKNOWN"
    service: str = ""

    def __post_init__(self):
        if not self.timestamp:
            raise ContractValidationError("Field 'timestamp' cannot be empty.")
        if not self.flow_id:
            raise ContractValidationError("Field 'flow_id' cannot be empty.")
        _validate_ip(self.src_ip, "src_ip")
        _validate_ip(self.dst_ip, "dst_ip")
        self.src_port = _validate_port(self.src_port, "src_port")
        self.dst_port = _validate_port(self.dst_port, "dst_port")
        self.duration = _validate_non_negative_float(self.duration, "duration")
        self.orig_bytes = _validate_non_negative_int(self.orig_bytes, "orig_bytes")
        self.resp_bytes = _validate_non_negative_int(self.resp_bytes, "resp_bytes")
        self.orig_packets = _validate_non_negative_int(self.orig_packets, "orig_packets")
        self.resp_packets = _validate_non_negative_int(self.resp_packets, "resp_packets")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'NormalizedFlowEvent':
        try:
            return cls(
                timestamp=str(d["timestamp"]),
                flow_id=str(d["flow_id"]),
                src_ip=str(d["src_ip"]),
                src_port=int(d["src_port"]),
                dst_ip=str(d["dst_ip"]),
                dst_port=int(d["dst_port"]),
                protocol=str(d.get("protocol", "tcp")),
                event_type=str(d.get("event_type", "NormalizedFlowEvent")),
                version=str(d.get("version", "1.0")),
                duration=float(d.get("duration", 0.0)),
                orig_bytes=int(d.get("orig_bytes", 0)),
                resp_bytes=int(d.get("resp_bytes", 0)),
                orig_packets=int(d.get("orig_packets", 0)),
                resp_packets=int(d.get("resp_packets", 0)),
                conn_state=str(d.get("conn_state", "UNKNOWN")),
                service=str(d.get("service", ""))
            )
        except KeyError as e:
            raise ContractValidationError(f"Missing required key for NormalizedFlowEvent: {e}") from e
        except (ValueError, TypeError) as e:
            raise ContractValidationError(f"Type conversion failed for NormalizedFlowEvent: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> 'NormalizedFlowEvent':
        try:
            d = json.loads(json_str)
            return cls.from_dict(d)
        except json.JSONDecodeError as e:
            raise ContractValidationError(f"Invalid JSON string for NormalizedFlowEvent: {e}") from e


@dataclass
class DNSObservation:
    timestamp: str
    flow_id: str
    client_ip: str
    query_domain: str
    event_type: str = "DNSObservation"
    version: str = "1.0"
    server_ip: str = ""
    query_type: str = "A"
    response_code: str = "NOERROR"
    answers: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            raise ContractValidationError("Field 'timestamp' cannot be empty.")
        if not self.flow_id:
            raise ContractValidationError("Field 'flow_id' cannot be empty.")
        if not self.query_domain:
            raise ContractValidationError("Field 'query_domain' cannot be empty.")
        _validate_ip(self.client_ip, "client_ip")
        if self.server_ip:
            _validate_ip(self.server_ip, "server_ip", allow_empty=True)
        if not isinstance(self.answers, list):
            raise ContractValidationError("Field 'answers' must be a list of strings.")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'DNSObservation':
        try:
            answers = d.get("answers", [])
            if not isinstance(answers, list):
                answers = []
            return cls(
                timestamp=str(d["timestamp"]),
                flow_id=str(d["flow_id"]),
                client_ip=str(d["client_ip"]),
                query_domain=str(d["query_domain"]),
                event_type=str(d.get("event_type", "DNSObservation")),
                version=str(d.get("version", "1.0")),
                server_ip=str(d.get("server_ip", "")),
                query_type=str(d.get("query_type", "A")),
                response_code=str(d.get("response_code", "NOERROR")),
                answers=[str(ans) for ans in answers]
            )
        except KeyError as e:
            raise ContractValidationError(f"Missing required key for DNSObservation: {e}") from e
        except (ValueError, TypeError) as e:
            raise ContractValidationError(f"Type conversion failed for DNSObservation: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> 'DNSObservation':
        try:
            d = json.loads(json_str)
            return cls.from_dict(d)
        except json.JSONDecodeError as e:
            raise ContractValidationError(f"Invalid JSON string for DNSObservation: {e}") from e


@dataclass
class TLSObservation:
    timestamp: str
    flow_id: str
    client_ip: str
    server_ip: str
    event_type: str = "TLSObservation"
    version: str = "1.0"
    tls_version: str = "UNKNOWN"
    cipher_suite: str = "UNKNOWN"
    sni_hostname: str = ""
    established: bool = False

    def __post_init__(self):
        if not self.timestamp:
            raise ContractValidationError("Field 'timestamp' cannot be empty.")
        if not self.flow_id:
            raise ContractValidationError("Field 'flow_id' cannot be empty.")
        _validate_ip(self.client_ip, "client_ip")
        _validate_ip(self.server_ip, "server_ip")
        if not isinstance(self.established, bool):
            raise ContractValidationError("Field 'established' must be a boolean.")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'TLSObservation':
        try:
            return cls(
                timestamp=str(d["timestamp"]),
                flow_id=str(d["flow_id"]),
                client_ip=str(d["client_ip"]),
                server_ip=str(d["server_ip"]),
                event_type=str(d.get("event_type", "TLSObservation")),
                version=str(d.get("version", "1.0")),
                tls_version=str(d.get("tls_version", "UNKNOWN")),
                cipher_suite=str(d.get("cipher_suite", "UNKNOWN")),
                sni_hostname=str(d.get("sni_hostname", "")),
                established=bool(d.get("established", False))
            )
        except KeyError as e:
            raise ContractValidationError(f"Missing required key for TLSObservation: {e}") from e
        except (ValueError, TypeError) as e:
            raise ContractValidationError(f"Type conversion failed for TLSObservation: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> 'TLSObservation':
        try:
            d = json.loads(json_str)
            return cls.from_dict(d)
        except json.JSONDecodeError as e:
            raise ContractValidationError(f"Invalid JSON string for TLSObservation: {e}") from e
