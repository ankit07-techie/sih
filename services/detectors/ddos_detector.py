"""
PassiveShield AI — Approved DDoS Threat Detector
Implements the approved DDoS threat detection model specified in docs/DDOS_DETECTOR_DESIGN.md.
Evaluates FeatureSnapshot objects and returns structured DetectionResult and ThreatEvidence instances.
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

DETECTOR_NAME = "DDoSDetector"

# Minimum floors to prevent false positives on low idle baseline volume
MIN_VOLUMETRIC_PPS_FLOOR = 50.0
MIN_VOLUMETRIC_BPS_FLOOR = 500_000.0  # 500 Kbps


class DDoSDetector:
    """
    Evaluates streaming FeatureSnapshot event contracts for DDoS / Volumetric Flood threats.
    Returns structured DetectionResult instances with diagnostic ThreatEvidence.
    """

    def __init__(self, pps_floor: float = MIN_VOLUMETRIC_PPS_FLOOR, bps_floor: float = MIN_VOLUMETRIC_BPS_FLOOR):
        self.pps_floor = pps_floor
        self.bps_floor = bps_floor

    def analyze_snapshot(self, snapshot: FeatureSnapshot) -> DetectionResult:
        """Analyzes a FeatureSnapshot and computes threat confidence score & severity."""
        features = snapshot.features or {}
        timestamp = snapshot.timestamp or datetime.now(timezone.utc).isoformat()
        entity_id = snapshot.entity_id

        evidence_list: List[Dict[str, Any]] = []

        pps = float(features.get("pps", 0.0))
        bps = float(features.get("bps", 0.0))
        surge_ratio_pps = float(features.get("surge_ratio_pps", 1.0))
        syn_only_ratio = features.get("syn_only_ratio")
        ack_missing_ratio = features.get("ack_missing_ratio")
        unique_src_ips = int(features.get("unique_source_ips", 0))
        port_entropy = float(features.get("destination_port_entropy", 0.0))

        # 0. Dedicated Passive Slow HTTP / Slowloris Heuristic Check
        duration = float(features.get("duration") or features.get("duration_sec") or 0.0)
        flow_rate_pps = float(features.get("flow_rate_pps") or features.get("pps") or 0.0)
        ack_ratio = float(features.get("ack_ratio") or 0.0)
        protocol = str(features.get("protocol") or "tcp").lower()
        dst_port = int(features.get("dst_port") or 80)

        is_slow_http = (
            duration >= 300.0 and
            0.0 < flow_rate_pps <= 0.5 and
            (ack_ratio >= 0.4 or features.get("ack_ratio") is not None or features.get("ack_count", 0) > 0) and
            protocol in ["tcp", "http", "https"] and
            dst_port in [80, 443, 8080, 8443]
        )

        if is_slow_http:
            slow_evidence = [
                ThreatEvidence(
                    code="SLOW_HTTP_EXHAUSTION_DETECTED",
                    message=f"Passive Slow HTTP / Slowloris connection pattern detected: duration={duration}s, rate={flow_rate_pps:.2f} pps.",
                    value={"duration": duration, "flow_rate_pps": flow_rate_pps, "ack_ratio": ack_ratio},
                    threshold={"min_duration": 300.0, "max_pps": 0.5}
                ).to_dict()
            ]
            return DetectionResult(
                timestamp=timestamp,
                detector_name=DETECTOR_NAME,
                entity_type="ip",
                entity_id=entity_id,
                severity="HIGH",
                confidence_score=0.88,
                is_threat=True,
                evidence=slow_evidence,
                mitigation_recommendation="FLAG_SUSPECT_IPS"
            )

        # Check static volumetric floors safeguard
        if pps < self.pps_floor and bps < self.bps_floor:
            evidence_list.append(ThreatEvidence(
                code="BELOW_VOLUMETRIC_FLOOR",
                message=f"Traffic rates (PPS: {pps}, BPS: {bps}) are below minimum volumetric floors.",
                value={"pps": pps, "bps": bps},
                threshold={"min_pps": self.pps_floor, "min_bps": self.bps_floor}
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

        # 1. Volumetric Surge Score Calculation (w1 = 0.40)
        s_rate = min(1.0, max(0.0, (surge_ratio_pps - 1.0) / 9.0))
        if surge_ratio_pps >= 3.0:
            evidence_list.append(ThreatEvidence(
                code="VOLUMETRIC_SURGE",
                message=f"PPS ({pps}) is {surge_ratio_pps:.1f}x baseline.",
                value=surge_ratio_pps,
                threshold=3.0
            ).to_dict())

        # 2. Connection Handshake Score & Incomplete Telemetry Handling (w2 = 0.35)
        has_handshake_telemetry = (syn_only_ratio is not None) and (ack_missing_ratio is not None)
        if has_handshake_telemetry:
            syn_ratio = float(syn_only_ratio)
            ack_ratio = float(ack_missing_ratio)
            s_handshake = 0.7 * syn_ratio + 0.3 * ack_ratio
            w1, w2, w3 = 0.40, 0.35, 0.25

            if syn_ratio >= 0.40:
                evidence_list.append(ThreatEvidence(
                    code="SYN_FLOOD_SIGNAL",
                    message=f"Unacknowledged TCP SYN ratio is {syn_ratio * 100:.1f}%.",
                    value=syn_ratio,
                    threshold=0.40
                ).to_dict())
        else:
            # Degraded Telemetry: Reallocate w2 to w1
            s_handshake = 0.0
            w1, w2, w3 = 0.75, 0.0, 0.25
            evidence_list.append(ThreatEvidence(
                code="DEGRADED_TELEMETRY",
                message="Missing TCP handshake state metrics; reallocating weight to volumetric rate.",
                value="MISSING_HANDSHAKE_LOGS",
                threshold=None
            ).to_dict())

        # 3. Entropy & Diversity Score Calculation (w3 = 0.25)
        div_score = min(1.0, unique_src_ips / 100.0)
        ent_penalty = 1.0 - min(1.0, port_entropy / 4.0)
        s_entropy = div_score * ent_penalty

        if unique_src_ips >= 50:
            evidence_list.append(ThreatEvidence(
                code="DISTRIBUTED_FOOTPRINT",
                message=f"High source IP diversity: {unique_src_ips} unique source IPs active.",
                value=unique_src_ips,
                threshold=50
            ).to_dict())

        # Composite Confidence Score Calculation
        total_score = w1 * s_rate + w2 * s_handshake + w3 * s_entropy
        confidence_score = round(min(1.0, max(0.0, total_score)), 2)

        # Severity Mapping
        if confidence_score < 0.35:
            severity = "INFO"
            is_threat = False
            rec = "NO_ACTION"
        elif confidence_score < 0.60:
            severity = "LOW"
            is_threat = True
            rec = "MONITOR_TRAFFIC"
        elif confidence_score < 0.85:
            severity = "MEDIUM"
            is_threat = True
            rec = "FLAG_SUSPECT_IPS"
        elif confidence_score < 0.95:
            severity = "HIGH"
            is_threat = True
            rec = "RATE_LIMIT_IP"
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
