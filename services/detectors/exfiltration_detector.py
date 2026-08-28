"""
PassiveShield AI — Data Exfiltration Behavioral Threat Detector
Evaluates FeatureSnapshot event contracts for directional byte imbalance and robust Z-score anomalies.
Outputs structured DetectionResult and ThreatEvidence contract instances with explicit evidence tagging.
"""

import math
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from shared.contracts import (
    FeatureSnapshot,
    DetectionResult,
    ThreatEvidence
)

logger = logging.getLogger(__name__)

DETECTOR_NAME = "ExfiltrationDetector"
MIN_EXFIL_BYTES_FLOOR = 100_000  # 100 KB floor safeguard


def compute_robust_zscore(value: float, history: List[float]) -> float:
    """
    Computes Robust Z-score using Median Absolute Deviation (MAD):
    Robust Z = 0.6745 * (value - median) / (MAD + 1e-5)
    """
    if len(history) < 3:
        return 0.0

    sorted_hist = sorted(history)
    n = len(sorted_hist)
    median = sorted_hist[n // 2] if n % 2 == 1 else (sorted_hist[n // 2 - 1] + sorted_hist[n // 2]) / 2.0

    mads = sorted([abs(x - median) for x in history])
    mad = mads[n // 2] if n % 2 == 1 else (mads[n // 2 - 1] + mads[n // 2]) / 2.0

    if mad < 1e-5:
        # Fallback to standard deviation if MAD is 0
        mean = sum(history) / float(n)
        var = sum((x - mean) ** 2 for x in history) / float(n)
        std = math.sqrt(var)
        return (value - mean) / (std + 1e-5)

    return 0.6745 * (value - median) / (mad + 1e-5)


class ExfiltrationDetector:
    """
    Evaluates streaming FeatureSnapshot event contracts for Data Exfiltration threats.
    """

    def __init__(self, min_bytes_floor: int = MIN_EXFIL_BYTES_FLOOR):
        self.min_bytes_floor = min_bytes_floor

    def analyze_snapshot(
        self,
        snapshot: FeatureSnapshot,
        historical_orig_bytes: Optional[List[float]] = None
    ) -> DetectionResult:
        """Analyzes a FeatureSnapshot and returns structured DetectionResult with explicit evidence."""
        features = snapshot.features or {}
        timestamp = snapshot.timestamp or datetime.now(timezone.utc).isoformat()
        entity_id = snapshot.entity_id

        evidence_list: List[Dict[str, Any]] = []

        orig_bytes = int(features.get("orig_bytes", features.get("bytes_sent", 0)))
        resp_bytes = int(features.get("resp_bytes", features.get("bytes_received", 0)))

        # Check static minimum bytes floor safeguard
        if orig_bytes < self.min_bytes_floor:
            evidence_list.append(ThreatEvidence(
                code="BELOW_EXFIL_FLOOR",
                message=f"Outbound byte volume ({orig_bytes} B) is below minimum exfiltration threshold ({self.min_bytes_floor} B).",
                value=orig_bytes,
                threshold=self.min_bytes_floor
            ).to_dict())

            return DetectionResult(
                timestamp=timestamp,
                detector_name=DETECTOR_NAME,
                entity_type="flow_pair",
                entity_id=entity_id,
                severity="INFO",
                confidence_score=0.0,
                is_threat=False,
                evidence=evidence_list,
                mitigation_recommendation="NO_ACTION"
            )

        # 1. Directional Byte Asymmetry Score
        total_bytes = orig_bytes + resp_bytes
        directional_ratio = round(orig_bytes / float(total_bytes + 1), 4)

        if directional_ratio >= 0.80:
            s_asymmetry = min(1.0, (directional_ratio - 0.70) / 0.25)
            evidence_list.append(ThreatEvidence(
                code="EXFIL_HIGH_DIRECTIONAL_RATIO",
                message=f"Outbound data ratio dominates flow volume ({directional_ratio * 100:.1f}% outbound).",
                value=directional_ratio,
                threshold=0.80
            ).to_dict())
        else:
            s_asymmetry = 0.0

        # 2. Volume Burst Score
        if orig_bytes >= 10_000_000:  # 10 MB+
            s_burst = 1.0
            evidence_list.append(ThreatEvidence(
                code="EXFIL_HIGH_BURST_VOLUME",
                message=f"Large single-flow outbound data transfer ({orig_bytes / (1024 * 1024):.1f} MB).",
                value=orig_bytes,
                threshold=10_000_000
            ).to_dict())
        elif orig_bytes >= 1_000_000:  # 1 MB+
            s_burst = min(1.0, orig_bytes / 10_000_000.0)
            evidence_list.append(ThreatEvidence(
                code="EXFIL_ELEVATED_BURST_VOLUME",
                message=f"Elevated outbound data transfer volume ({orig_bytes / 1024:.1f} KB).",
                value=orig_bytes,
                threshold=1_000_000
            ).to_dict())
        else:
            s_burst = min(1.0, orig_bytes / 1_000_000.0)

        # 3. Robust Z-Score Anomaly Score
        s_zscore = 0.0
        robust_z = 0.0
        history = historical_orig_bytes or []
        if len(history) >= 3:
            robust_z = compute_robust_zscore(float(orig_bytes), history)
            if robust_z >= 3.5:
                s_zscore = min(1.0, (robust_z - 3.0) / 5.0)
                evidence_list.append(ThreatEvidence(
                    code="EXFIL_ROBUST_ZSCORE_ANOMALY",
                    message=f"Outbound byte volume robust Z-score spike ({robust_z:.2f} standard deviations above median).",
                    value=round(robust_z, 2),
                    threshold=3.5
                ).to_dict())

        # Composite Confidence Score
        if len(history) >= 3:
            total_score = 0.45 * s_asymmetry + 0.35 * s_burst + 0.20 * s_zscore
        else:
            total_score = 0.60 * s_asymmetry + 0.40 * s_burst

        confidence_score = round(min(1.0, max(0.0, total_score)), 2)

        # Severity Mapping
        if confidence_score < 0.35:
            severity = "INFO"
            is_threat = False
            rec = "NO_ACTION"
        elif confidence_score < 0.60:
            severity = "LOW"
            is_threat = True
            rec = "MONITOR_DATA_FLOW"
        elif confidence_score < 0.85:
            severity = "MEDIUM"
            is_threat = True
            rec = "FLAG_SUSPECT_EXFILTRATION_HOST"
        elif confidence_score < 0.95:
            severity = "HIGH"
            is_threat = True
            rec = "BLOCK_DATA_EXFILTRATION_FLOW"
        else:
            severity = "CRITICAL"
            is_threat = True
            rec = "APPLY_PASSIVE_SHIELD_FILTERS"

        return DetectionResult(
            timestamp=timestamp,
            detector_name=DETECTOR_NAME,
            entity_type="flow_pair",
            entity_id=entity_id,
            severity=severity,
            confidence_score=confidence_score,
            is_threat=is_threat,
            evidence=evidence_list,
            mitigation_recommendation=rec
        )
