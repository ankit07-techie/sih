"""
PassiveShield AI — Approved C2 Beaconing Threat Detector
Evaluates FeatureSnapshot event contracts for Command and Control (C2) beaconing patterns,
applying statistical IAT regularity analysis and SciPy FFT spectral peak analysis when justified.
Outputs structured DetectionResult and ThreatEvidence contract instances.
"""

import math
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

try:
    from scipy.fft import rfft
    import numpy as np
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    np = None

from shared.contracts import (
    FeatureSnapshot,
    DetectionResult,
    ThreatEvidence
)

logger = logging.getLogger(__name__)

DETECTOR_NAME = "C2BeaconDetector"
MIN_SAMPLES_FLOOR = 5
MIN_FFT_SAMPLES_FLOOR = 16


class C2BeaconDetector:
    """
    Evaluates streaming FeatureSnapshot event contracts for C2 Beaconing threats.
    """

    def __init__(self, min_samples_floor: int = MIN_SAMPLES_FLOOR):
        self.min_samples_floor = min_samples_floor

    def _compute_spectral_peak_ratio(self, iats: List[float]) -> float:
        """
        Computes the ratio of peak spectral power to total spectral power using FFT.
        Only executed when HAS_SCIPY is True and len(iats) >= MIN_FFT_SAMPLES_FLOOR.
        """
        if not HAS_SCIPY or len(iats) < MIN_FFT_SAMPLES_FLOOR:
            return 0.0

        try:
            # Convert IAT intervals into time series vector
            signal = np.array(iats, dtype=float)
            signal = signal - np.mean(signal)  # Zero-mean normalization

            fft_vals = np.abs(rfft(signal))
            if len(fft_vals) <= 1:
                return 0.0

            # Exclude DC component (index 0)
            power_spectrum = fft_vals[1:] ** 2
            total_power = np.sum(power_spectrum)

            if total_power <= 1e-9:
                return 0.0

            peak_power = np.max(power_spectrum)
            return float(peak_power / total_power)
        except Exception as e:
            logger.warning(f"FFT spectral analysis calculation failed: {e}")
            return 0.0

    def analyze_snapshot(self, snapshot: FeatureSnapshot, raw_iats: Optional[List[float]] = None) -> DetectionResult:
        """Analyzes a FeatureSnapshot and returns structured DetectionResult with ThreatEvidence."""
        features = snapshot.features or {}
        timestamp = snapshot.timestamp or datetime.now(timezone.utc).isoformat()
        entity_id = snapshot.entity_id

        evidence_list: List[Dict[str, Any]] = []

        sample_count = int(features.get("sample_count", 0))
        iat_count = int(features.get("iat_count", 0))
        mean_iat = float(features.get("mean_iat", 0.0))
        cv_iat = float(features.get("cv_iat", 1.0))
        periodicity_score = float(features.get("periodicity_score", 0.0))
        payload_size_std = float(features.get("payload_size_std", 100.0))

        # Check minimum samples safeguard
        if sample_count < self.min_samples_floor or iat_count < 4:
            evidence_list.append(ThreatEvidence(
                code="INSUFFICIENT_BEACON_SAMPLES",
                message=f"Sample count ({sample_count}) is below minimum beaconing observation threshold ({self.min_samples_floor}).",
                value=sample_count,
                threshold=self.min_samples_floor
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

        # 1. Statistical Periodicity Score Calculation
        s_periodicity = max(0.0, 1.0 - min(1.0, cv_iat / 0.50))

        if cv_iat < 0.25:
            evidence_list.append(ThreatEvidence(
                code="PERIODIC_BEACONING_SIGNAL",
                message=f"Highly regular inter-arrival intervals detected (CV: {cv_iat:.4f}, Mean IAT: {mean_iat:.1f}s).",
                value=cv_iat,
                threshold=0.25
            ).to_dict())
        elif cv_iat > 0.80:
            evidence_list.append(ThreatEvidence(
                code="BURST_TRAFFIC_FILTERED",
                message=f"Irregular connection pattern / burst traffic detected (CV: {cv_iat:.4f}).",
                value=cv_iat,
                threshold=0.80
            ).to_dict())

        # 2. Payload Consistency Score
        if payload_size_std < 10.0 and sample_count >= 5:
            s_payload = 1.0
            evidence_list.append(ThreatEvidence(
                code="FIXED_PAYLOAD_SIZE",
                message=f"Highly consistent outbound payload size (std dev: {payload_size_std:.1f} bytes).",
                value=payload_size_std,
                threshold=10.0
            ).to_dict())
        else:
            s_payload = max(0.0, 1.0 - (payload_size_std / 500.0))

        # 3. Spectral FFT Analysis (SciPy when justified by N >= 16)
        iats_vector = raw_iats or []
        run_fft = (HAS_SCIPY and len(iats_vector) >= MIN_FFT_SAMPLES_FLOOR)
        spectral_peak_ratio = 0.0

        if run_fft:
            spectral_peak_ratio = self._compute_spectral_peak_ratio(iats_vector)
            s_spectral = min(1.0, spectral_peak_ratio / 0.60)
            if spectral_peak_ratio >= 0.50:
                evidence_list.append(ThreatEvidence(
                    code="SPECTRAL_PEAK_DETECTED",
                    message=f"FFT spectral peak power ratio is {spectral_peak_ratio * 100:.1f}%.",
                    value=round(spectral_peak_ratio, 4),
                    threshold=0.50
                ).to_dict())

            # Weighted score with spectral analysis (w1=0.50, w2=0.30, w3=0.20)
            total_score = 0.50 * s_periodicity + 0.30 * s_spectral + 0.20 * s_payload
        else:
            # Weighted score without spectral analysis (w1=0.75, w3=0.25)
            total_score = 0.75 * s_periodicity + 0.25 * s_payload

        # Jitter penalty if CV > 0.40
        if cv_iat > 0.40:
            total_score = total_score * max(0.1, 1.0 - (cv_iat - 0.40))

        confidence_score = round(min(1.0, max(0.0, total_score)), 2)

        # Severity Mapping
        if confidence_score < 0.35:
            severity = "INFO"
            is_threat = False
            rec = "NO_ACTION"
        elif confidence_score < 0.60:
            severity = "LOW"
            is_threat = True
            rec = "MONITOR_CONNECTION_PAIR"
        elif confidence_score < 0.85:
            severity = "MEDIUM"
            is_threat = True
            rec = "FLAG_SUSPECT_C2_HOST"
        elif confidence_score < 0.95:
            severity = "HIGH"
            is_threat = True
            rec = "BLOCK_C2_HOST"
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
