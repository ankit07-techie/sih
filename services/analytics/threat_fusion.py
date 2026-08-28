"""
PassiveShield AI — Multi-Detector Threat Fusion Engine
Fuses streaming DetectionResult contracts from independent detectors (DDoS, PortScan, Beaconing, DNS, Exfiltration, TLS),
performing multi-detector score fusion, deduplication, severity normalization, and evidence preservation.
"""

import uuid
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from shared.contracts import (
    DetectionResult,
    ThreatEvidence,
    ContractValidationError
)

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

MITIGATION_PRIORITY = {
    "APPLY_PASSIVE_SHIELD_FILTERS": 5,
    "BLOCK_RECONNAISSANCE_IP": 4,
    "BLOCK_C2_HOST": 4,
    "BLOCK_DOMAIN_RESOLUTION": 4,
    "BLOCK_DATA_EXFILTRATION_FLOW": 4,
    "BLOCK_TLS_CLIENT": 4,
    "FLAG_RECONNAISSANCE_IP": 3,
    "FLAG_SUSPECT_C2_HOST": 3,
    "FLAG_SUSPECT_DOMAIN": 3,
    "FLAG_SUSPECT_EXFILTRATION_HOST": 3,
    "FLAG_SUSPECT_TLS_CLIENT": 3,
    "MONITOR_SOURCE_IP": 2,
    "MONITOR_CONNECTION_PAIR": 2,
    "MONITOR_DOMAIN_QUERIES": 2,
    "MONITOR_DATA_FLOW": 2,
    "MONITOR_TLS_FLOW": 2,
    "NO_ACTION": 0
}


@dataclass
class FusedThreatAlert:
    """
    Contract representing a multi-detector correlated threat alert.
    """
    timestamp: str
    entity_type: str
    entity_id: str
    severity: str
    fused_score: float
    is_threat: bool
    contributing_detectors: List[str]
    evidence: List[Dict[str, Any]]
    mitigation_recommendation: str
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = "FusedThreatAlert"
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatFusionEngine:
    """
    Fuses multiple DetectionResult instances for an entity into a correlated FusedThreatAlert contract.
    """

    def __init__(self, detector_weights: Optional[Dict[str, float]] = None):
        self.detector_weights = detector_weights or {
            "DDoSDetector": 1.0,
            "PortScanDetector": 1.0,
            "C2BeaconDetector": 1.0,
            "DNSAnomalyDetector": 1.0,
            "ExfiltrationDetector": 1.0,
            "TLSMetadataAnalyzer": 1.0
        }

    def fuse_results(self, results: List[DetectionResult]) -> Optional[FusedThreatAlert]:
        """
        Fuses a list of DetectionResult objects for a single entity into a unified FusedThreatAlert.
        Returns None if input results list is empty.
        """
        if not results:
            return None

        entity_id = results[0].entity_id
        entity_type = results[0].entity_type
        timestamp = results[0].timestamp

        # 1. Deduplicate results by detector_name (keep highest confidence result per detector)
        detector_results: Dict[str, DetectionResult] = {}
        for res in results:
            d_name = res.detector_name
            if d_name not in detector_results or res.confidence_score > detector_results[d_name].confidence_score:
                detector_results[d_name] = res

        contributing_detectors = list(detector_results.keys())
        unique_results = list(detector_results.values())

        # 2. Multi-Detector Score Fusion Calculation
        # Probabilistic independence fusion: S_fused = 1 - PROD(1 - S_i * w_i)
        prob_non_threat = 1.0
        max_single_score = 0.0

        for res in unique_results:
            w = self.detector_weights.get(res.detector_name, 1.0)
            score = res.confidence_score * w
            max_single_score = max(max_single_score, score)
            prob_non_threat *= (1.0 - min(0.99, score))

        combined_prob_score = 1.0 - prob_non_threat

        # Apply multi-detector correlation boost if 2+ distinct threat detectors triggered
        threat_count = sum(1 for res in unique_results if res.is_threat)
        if threat_count >= 2:
            combined_prob_score = min(1.0, combined_prob_score * 1.15)

        fused_score = round(min(1.0, max(0.0, combined_prob_score)), 2)

        # 3. Severity Normalization
        if fused_score < 0.35:
            severity = "INFO"
            is_threat = False
        elif fused_score < 0.60:
            severity = "LOW"
            is_threat = True
        elif fused_score < 0.85:
            severity = "MEDIUM"
            is_threat = True
        elif fused_score < 0.95:
            severity = "HIGH"
            is_threat = True
        else:
            severity = "CRITICAL"
            is_threat = True

        # 4. Evidence Preservation & Deduplication
        fused_evidence: List[Dict[str, Any]] = []
        seen_evidence_keys = set()

        for res in unique_results:
            for ev in res.evidence:
                ev_code = ev.get("code", "UNKNOWN")
                ev_key = f"{res.detector_name}:{ev_code}:{ev.get('message')}"
                if ev_key not in seen_evidence_keys:
                    seen_evidence_keys.add(ev_key)
                    ev_copy = dict(ev)
                    ev_copy["detector_source"] = res.detector_name
                    fused_evidence.append(ev_copy)

        # 5. Mitigation Recommendation Consolidation
        highest_priority = -1
        best_rec = "NO_ACTION"
        for res in unique_results:
            rec = res.mitigation_recommendation
            prio = MITIGATION_PRIORITY.get(rec, 0)
            if prio > highest_priority:
                highest_priority = prio
                best_rec = rec

        return FusedThreatAlert(
            timestamp=timestamp,
            entity_type=entity_type,
            entity_id=entity_id,
            severity=severity,
            fused_score=fused_score,
            is_threat=is_threat,
            contributing_detectors=contributing_detectors,
            evidence=fused_evidence,
            mitigation_recommendation=best_rec
        )
