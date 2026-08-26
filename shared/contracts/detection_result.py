"""
PassiveShield AI — DetectionResult & ThreatEvidence Contracts
Data contract models representing threat detection analysis results and diagnostic evidence.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from .telemetry import ContractValidationError


@dataclass
class ThreatEvidence:
    code: str
    message: str
    value: Any = None
    threshold: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionResult:
    timestamp: str
    detector_name: str
    entity_type: str
    entity_id: str
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence_score: float
    is_threat: bool
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_recommendation: str = "NO_ACTION"
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "DetectionResult"
    version: str = "1.0"

    def __post_init__(self):
        if not self.timestamp:
            raise ContractValidationError("Field 'timestamp' cannot be empty.")
        if not self.detector_name:
            raise ContractValidationError("Field 'detector_name' cannot be empty.")
        if not self.entity_id:
            raise ContractValidationError("Field 'entity_id' cannot be empty.")
        if self.severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ContractValidationError(f"Invalid severity level: {self.severity}")
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ContractValidationError(f"Confidence score must be between 0.0 and 1.0, got: {self.confidence_score}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'DetectionResult':
        try:
            return cls(
                timestamp=str(d["timestamp"]),
                detector_name=str(d["detector_name"]),
                entity_type=str(d.get("entity_type", "ip")),
                entity_id=str(d["entity_id"]),
                severity=str(d["severity"]),
                confidence_score=float(d["confidence_score"]),
                is_threat=bool(d["is_threat"]),
                evidence=list(d.get("evidence", [])),
                mitigation_recommendation=str(d.get("mitigation_recommendation", "NO_ACTION")),
                detection_id=str(d.get("detection_id", str(uuid.uuid4()))),
                event_type=str(d.get("event_type", "DetectionResult")),
                version=str(d.get("version", "1.0"))
            )
        except KeyError as e:
            raise ContractValidationError(f"Missing required key for DetectionResult: {e}") from e
        except (ValueError, TypeError) as e:
            raise ContractValidationError(f"Type conversion failed for DetectionResult: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> 'DetectionResult':
        try:
            d = json.loads(json_str)
            return cls.from_dict(d)
        except json.JSONDecodeError as e:
            raise ContractValidationError(f"Invalid JSON string for DetectionResult: {e}") from e
