"""
PassiveShield AI — ThreatAlert Contract & Standardization
Dataclass event model representing standardized, correlated security threat alerts emitted to downstream alert buses and SOC operations dashboards.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .telemetry import ContractValidationError

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_CLASSIFICATIONS = {
    "DDOS_ATTACK",
    "PORT_SCAN",
    "C2_BEACONING",
    "DNS_ANOMALY",
    "DATA_EXFILTRATION",
    "TLS_ANOMALY",
    "CORRELATED_MULTI_VECTOR",
    "UNKNOWN_THREAT"
}


@dataclass
class ThreatAlert:
    alert_id: str
    timestamp: str
    threat_classification: str
    severity: str
    confidence_score: float
    affected_context: Dict[str, Any]
    observation_window_seconds: int
    contributing_detectors: List[str]
    structured_evidence: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_recommendation: str = "NO_ACTION"
    event_type: str = "ThreatAlert"
    version: str = "1.0"

    def __post_init__(self):
        if not self.alert_id:
            raise ContractValidationError("Field 'alert_id' cannot be empty.")
        if not self.timestamp:
            raise ContractValidationError("Field 'timestamp' cannot be empty.")
        if not self.threat_classification:
            raise ContractValidationError("Field 'threat_classification' cannot be empty.")
        if self.severity not in VALID_SEVERITIES:
            raise ContractValidationError(f"Invalid severity level '{self.severity}'. Must be one of {VALID_SEVERITIES}.")
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ContractValidationError(f"Confidence score must be between 0.0 and 1.0, got: {self.confidence_score}")
        if not isinstance(self.affected_context, dict):
            raise ContractValidationError("Field 'affected_context' must be a dictionary.")
        if self.observation_window_seconds <= 0:
            raise ContractValidationError(f"Observation window seconds must be positive, got: {self.observation_window_seconds}")
        if not isinstance(self.contributing_detectors, list):
            raise ContractValidationError("Field 'contributing_detectors' must be a list.")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'ThreatAlert':
        try:
            return cls(
                alert_id=str(d.get("alert_id", str(uuid.uuid4()))),
                timestamp=str(d["timestamp"]),
                threat_classification=str(d["threat_classification"]),
                severity=str(d["severity"]),
                confidence_score=float(d["confidence_score"]),
                affected_context=dict(d.get("affected_context", {})),
                observation_window_seconds=int(d.get("observation_window_seconds", 60)),
                contributing_detectors=list(d.get("contributing_detectors", [])),
                structured_evidence=list(d.get("structured_evidence", [])),
                mitigation_recommendation=str(d.get("mitigation_recommendation", "NO_ACTION")),
                event_type=str(d.get("event_type", "ThreatAlert")),
                version=str(d.get("version", "1.0"))
            )
        except KeyError as e:
            raise ContractValidationError(f"Missing required key for ThreatAlert: {e}") from e
        except (ValueError, TypeError) as e:
            raise ContractValidationError(f"Type conversion failed for ThreatAlert: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> 'ThreatAlert':
        try:
            d = json.loads(json_str)
            return cls.from_dict(d)
        except json.JSONDecodeError as e:
            raise ContractValidationError(f"Invalid JSON string for ThreatAlert: {e}") from e
