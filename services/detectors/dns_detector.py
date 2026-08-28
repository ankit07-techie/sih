"""
PassiveShield AI — Approved DNS Anomaly Threat Detector
Evaluates FeatureSnapshot event contracts for DGA (Domain Generation Algorithms)
and DNS Tunneling exfiltration patterns.
Outputs structured DetectionResult and ThreatEvidence contract instances with distinct evidence tagging.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

try:
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from shared.contracts import (
    FeatureSnapshot,
    DetectionResult,
    ThreatEvidence
)

logger = logging.getLogger(__name__)

DETECTOR_NAME = "DNSAnomalyDetector"


class DNSAnomalyDetector:
    """
    Evaluates streaming FeatureSnapshot event contracts for DNS Anomalies (DGA & DNS Tunneling).
    """

    def __init__(self, ml_model: Optional[Any] = None):
        self.ml_model = ml_model

    def analyze_snapshot(self, snapshot: FeatureSnapshot) -> DetectionResult:
        """Analyzes a FeatureSnapshot and returns structured DetectionResult with distinct DGA / Tunneling evidence."""
        features = snapshot.features or {}
        timestamp = snapshot.timestamp or datetime.now(timezone.utc).isoformat()
        entity_id = snapshot.entity_id

        evidence_list: List[Dict[str, Any]] = []

        domain_length = int(features.get("domain_length", 0))
        subdomain_length = int(features.get("subdomain_length", 0))
        subdomain_depth = int(features.get("subdomain_depth", 0))
        entropy = float(features.get("entropy", 0.0))
        bigram_entropy = float(features.get("bigram_entropy", 0.0))
        digit_ratio = float(features.get("digit_ratio", 0.0))
        max_cons_seq = int(features.get("max_consecutive_consonants", 0))
        is_nxdomain = int(features.get("is_nxdomain", 0))
        is_txt_query = int(features.get("is_txt_query", 0))

        # --- 1. DGA Suspicion Sub-Score ---
        s_dga_entropy = min(1.0, max(0.0, (entropy - 2.5) / 2.0))
        s_dga_digits = min(1.0, digit_ratio / 0.35)
        s_dga_cons = min(1.0, max_cons_seq / 6.0)
        s_dga_nx = 1.0 if is_nxdomain == 1 else 0.0

        s_dga = (0.35 * s_dga_entropy + 0.25 * s_dga_digits + 0.20 * s_dga_cons + 0.20 * s_dga_nx)

        # Tag DGA-specific evidence
        if entropy >= 3.5:
            evidence_list.append(ThreatEvidence(
                code="DGA_HIGH_ENTROPY",
                message=f"High Shannon entropy in domain string ({entropy:.2f}).",
                value=entropy,
                threshold=3.5
            ).to_dict())

        if digit_ratio >= 0.25:
            evidence_list.append(ThreatEvidence(
                code="DGA_DIGIT_DENSITY",
                message=f"High numeric digit density ({digit_ratio * 100:.1f}%).",
                value=digit_ratio,
                threshold=0.25
            ).to_dict())

        if max_cons_seq >= 5:
            evidence_list.append(ThreatEvidence(
                code="DGA_CONSONANT_CLUSTER",
                message=f"High consecutive consonant sequence ({max_cons_seq} characters).",
                value=max_cons_seq,
                threshold=5
            ).to_dict())

        if is_nxdomain == 1:
            evidence_list.append(ThreatEvidence(
                code="DGA_NXDOMAIN_FAILURE",
                message="DNS query resulted in NXDOMAIN failure (indicates DGA probe).",
                value=1,
                threshold=1
            ).to_dict())

        # --- 2. DNS Tunneling Suspicion Sub-Score ---
        s_tun_sublen = min(1.0, max(0.0, (subdomain_length - 15) / 35.0))
        s_tun_depth = min(1.0, max(0.0, (subdomain_depth - 1) / 3.0))
        s_tun_txt = 1.0 if is_txt_query == 1 else 0.0
        s_tun_bigram = min(1.0, max(0.0, (bigram_entropy - 2.5) / 2.0))

        s_tunnel = (0.40 * s_tun_sublen + 0.25 * s_tun_depth + 0.20 * s_tun_txt + 0.15 * s_tun_bigram)

        # Tag Tunneling-specific evidence
        if subdomain_length >= 20:
            evidence_list.append(ThreatEvidence(
                code="TUNNEL_SUBDOMAIN_LENGTH",
                message=f"Excessive subdomain payload length ({subdomain_length} characters).",
                value=subdomain_length,
                threshold=20
            ).to_dict())

        if subdomain_depth >= 3:
            evidence_list.append(ThreatEvidence(
                code="TUNNEL_DEEP_SUBDOMAIN",
                message=f"Deeply nested subdomain structure ({subdomain_depth} labels).",
                value=subdomain_depth,
                threshold=3
            ).to_dict())

        if is_txt_query == 1:
            evidence_list.append(ThreatEvidence(
                code="TUNNEL_TXT_QUERY",
                message="DNS TXT record query used (common in data exfiltration).",
                value=1,
                threshold=1
            ).to_dict())

        if bigram_entropy >= 3.0:
            evidence_list.append(ThreatEvidence(
                code="TUNNEL_HIGH_BIGRAM_ENTROPY",
                message=f"High 2-gram character entropy in subdomain ({bigram_entropy:.2f}).",
                value=bigram_entropy,
                threshold=3.0
            ).to_dict())

        # Composite Confidence Score
        confidence_score = round(min(1.0, max(0.0, max(s_dga, s_tunnel))), 2)

        # Severity Mapping
        if confidence_score < 0.35:
            severity = "INFO"
            is_threat = False
            rec = "NO_ACTION"
        elif confidence_score < 0.60:
            severity = "LOW"
            is_threat = True
            rec = "MONITOR_DOMAIN_QUERIES"
        elif confidence_score < 0.85:
            severity = "MEDIUM"
            is_threat = True
            rec = "FLAG_SUSPECT_DOMAIN"
        elif confidence_score < 0.95:
            severity = "HIGH"
            is_threat = True
            rec = "BLOCK_DOMAIN_RESOLUTION"
        else:
            severity = "CRITICAL"
            is_threat = True
            rec = "APPLY_PASSIVE_SHIELD_FILTERS"

        return DetectionResult(
            timestamp=timestamp,
            detector_name=DETECTOR_NAME,
            entity_type="domain",
            entity_id=entity_id,
            severity=severity,
            confidence_score=confidence_score,
            is_threat=is_threat,
            evidence=evidence_list,
            mitigation_recommendation=rec
        )
