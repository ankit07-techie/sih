"""
PassiveShield AI — FeatureSnapshot Event Contract
Data contract model representing an aggregated feature vector snapshot calculated over sliding windows.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional
from .telemetry import ContractValidationError


@dataclass
class FeatureSnapshot:
    timestamp: str
    entity_type: str  # e.g., "ip", "domain", "flow_pair"
    entity_id: str    # e.g., "192.168.1.50", "example.com"
    window_seconds: int
    features: Dict[str, Any]
    snapshot_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "FeatureSnapshot"
    version: str = "1.0"

    def __post_init__(self):
        if not self.timestamp:
            raise ContractValidationError("Field 'timestamp' cannot be empty.")
        if not self.entity_type:
            raise ContractValidationError("Field 'entity_type' cannot be empty.")
        if not self.entity_id:
            raise ContractValidationError("Field 'entity_id' cannot be empty.")
        if not isinstance(self.window_seconds, int) or self.window_seconds <= 0:
            raise ContractValidationError("Field 'window_seconds' must be a positive integer.")
        if not isinstance(self.features, dict):
            raise ContractValidationError("Field 'features' must be a dictionary.")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'FeatureSnapshot':
        try:
            return cls(
                timestamp=str(d["timestamp"]),
                entity_type=str(d["entity_type"]),
                entity_id=str(d["entity_id"]),
                window_seconds=int(d["window_seconds"]),
                features=dict(d.get("features", {})),
                snapshot_id=str(d.get("snapshot_id", str(uuid.uuid4()))),
                event_type=str(d.get("event_type", "FeatureSnapshot")),
                version=str(d.get("version", "1.0"))
            )
        except KeyError as e:
            raise ContractValidationError(f"Missing required key for FeatureSnapshot: {e}") from e
        except (ValueError, TypeError) as e:
            raise ContractValidationError(f"Type conversion failed for FeatureSnapshot: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> 'FeatureSnapshot':
        try:
            d = json.loads(json_str)
            return cls.from_dict(d)
        except json.JSONDecodeError as e:
            raise ContractValidationError(f"Invalid JSON string for FeatureSnapshot: {e}") from e
