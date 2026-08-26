"""
PassiveShield AI — Port Scan & Reconnaissance Threat Detector
Evaluates FeatureSnapshot event contracts for vertical port scanning, horizontal IP sweeps,
and stealth probe reconnaissance.
Outputs structured DetectionResult and ThreatEvidence contract instances.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from shared.contracts import (
    FeatureSnapshot,
    DetectionResult,
    ThreatEvidence
)

logger = logging.getLogger(__name__)

DETECTOR_NAME = "PortScanDetector"

MIN_VERTICAL_PORTS_FLOOR = 5
MIN_HORIZONTAL_IPS_FLOOR = 3


class PortScanDetector:
    """
    Evaluates streaming FeatureSnapshot event contracts for Port Scanning & Reconnaissance threats.
    """

    def __init__(
        self,
        min_ports_floor: int = MIN_VERTICAL_PORTS_FLOOR,
        min_ips_floor: int = MIN_HORIZONTAL_IPS_FLOOR
    ):
        self.min_ports_floor = min_ports_floor
        self.min_ips_floor = min_ips_floor

    def analyze_snapshot(self, snapshot: FeatureSnapshot) -> DetectionResult:
        """Analyzes a FeatureSnapshot and computes reconnaissance threat confidence score & severity."""
        features = snapshot.features or {}
        timestamp = snapshot.timestamp or datetime.now(timezone.utc).isoformat()
        entity_id = snapshot.entity_id

        evidence_list: List[Dict[str, Any]] = []

        unique_dst_ports = int(features.get("unique_dst_ports", 0))
        unique_dst_ips = int(features.get("unique_dst_ips", 0))
        fanout_ports_per_sec = float(features.get("fanout_ports_per_sec", 0.0))
        port_growth_rate = float(features.get("port_growth_rate", 0.0))
        failed_conn_ratio = float(features.get("failed_conn_ratio", 0.0))
        stealth_scan_ratio = float(features.get("stealth_scan_ratio", 0.0))

        # Check static minimum floor safeguards
        if unique_dst_ports < self.min_ports_floor and unique_dst_ips < self.min_ips_floor:
            evidence_list.append(ThreatEvidence(
                code="BELOW_SCAN_FLOOR",
                message=f"Reconnaissance fan-out ({unique_dst_ports} ports, {unique_dst_ips} IPs) is below minimum scan floors.",
                value={"ports": unique_dst_ports, "ips": unique_dst_ips},
                threshold={"min_ports": self.min_ports_floor, "min_ips": self.min_ips_floor}
            ).to_dict())

            return DetectionResult(
                timestamp=timestamp,
                detector_name=DETECTOR_NAME,
                entity_type="ip",
                entity_id=entity_id,
                severity="INFO",
                confidence_score=0.0,
                is_threat=False,
                evidence=evidence_list,
                mitigation_recommendation="NO_ACTION"
            )

        # 1. Vertical Scan Sub-score (unique ports on target)
        s_vert = min(1.0, unique_dst_ports / 50.0) * (0.5 + 0.5 * failed_conn_ratio)
        if unique_dst_ports >= 15:
            evidence_list.append(ThreatEvidence(
                code="VERTICAL_PORT_SCAN",
                message=f"Vertical port scan detected: {unique_dst_ports} distinct ports probed.",
                value=unique_dst_ports,
                threshold=15
            ).to_dict())

        # 2. Horizontal Scan Sub-score (unique IPs across subnet)
        s_horiz = min(1.0, unique_dst_ips / 20.0) * (0.5 + 0.5 * failed_conn_ratio)
        if unique_dst_ips >= 8:
            evidence_list.append(ThreatEvidence(
                code="HORIZONTAL_IP_SWEEP",
                message=f"Horizontal IP sweep detected: {unique_dst_ips} distinct IPs probed.",
                value=unique_dst_ips,
                threshold=8
            ).to_dict())

        # 3. Growth Acceleration Sub-score
        s_growth = min(1.0, max(0.0, port_growth_rate / 3.0))
        if port_growth_rate >= 1.5:
            evidence_list.append(ThreatEvidence(
                code="SCAN_ACCELERATION",
                message=f"Port scanning fan-out accelerated by {port_growth_rate:.1f}x.",
                value=port_growth_rate,
                threshold=1.5
            ).to_dict())

        # 4. Failed / Stealth Connection Evidence
        if failed_conn_ratio >= 0.40:
            evidence_list.append(ThreatEvidence(
                code="HIGH_FAILURE_RATIO",
                message=f"High connection failure/rejection ratio: {failed_conn_ratio * 100:.1f}%.",
                value=failed_conn_ratio,
                threshold=0.40
            ).to_dict())

        # Composite Confidence Score Formulation
        base_scan_score = max(s_vert, s_horiz)
        total_score = base_scan_score * 0.70 + s_growth * 0.30

        # Stealth probe multiplier boost if stealth scanning detected
        if stealth_scan_ratio >= 0.50:
            total_score = min(1.0, total_score * 1.20)
            evidence_list.append(ThreatEvidence(
                code="STEALTH_PROBE_SIGNAL",
                message=f"Stealth half-open TCP scan ratio: {stealth_scan_ratio * 100:.1f}%.",
                value=stealth_scan_ratio,
                threshold=0.50
            ).to_dict())

        confidence_score = round(min(1.0, max(0.0, total_score)), 2)

        # Severity Mapping
        if confidence_score < 0.35:
            severity = "INFO"
            is_threat = False
            rec = "NO_ACTION"
        elif confidence_score < 0.60:
            severity = "LOW"
            is_threat = True
            rec = "MONITOR_SOURCE_IP"
        elif confidence_score < 0.85:
            severity = "MEDIUM"
            is_threat = True
            rec = "FLAG_RECONNAISSANCE_IP"
        elif confidence_score < 0.95:
            severity = "HIGH"
            is_threat = True
            rec = "BLOCK_RECONNAISSANCE_IP"
        else:
            severity = "CRITICAL"
            is_threat = True
            rec = "APPLY_PASSIVE_SHIELD_FILTERS"

        return DetectionResult(
            timestamp=timestamp,
            detector_name=DETECTOR_NAME,
            entity_type="ip",
            entity_id=entity_id,
            severity=severity,
            confidence_score=confidence_score,
            is_threat=is_threat,
            evidence=evidence_list,
            mitigation_recommendation=rec
        )
