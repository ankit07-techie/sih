"""
PassiveShield AI — Reusable C2 Beaconing Feature Extractor
Extracts inter-arrival time (IAT) statistical metrics (mean, variance, std dev, CV),
periodicity scores, jitter ratios, and payload size consistency for C2 beaconing analysis.
"""

import math
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager


class BeaconingFeatureExtractor:
    """
    Computes reusable C2 Beaconing features for connection pairs (src_ip -> dst_ip).
    Outputs FeatureSnapshot contract objects.
    Contains 0% detector classification or threat scoring logic.
    """

    def __init__(self, state_manager: RedisStateManager):
        self.state_mgr = state_manager

    def compute_beaconing_features(
        self,
        src_ip: str,
        dst_ip: str,
        window_seconds: int = 300,
        orig_bytes_list: Optional[List[int]] = None,
        timestamp: Optional[str] = None
    ) -> FeatureSnapshot:
        """
        Calculates inter-arrival time (IAT) statistics and periodicity signals for a connection pair.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        # Query IAT timestamp history from Redis state
        timestamps = self.state_mgr.get_inter_arrival_timestamps(src_ip, dst_ip)

        iats: List[float] = []
        if len(timestamps) > 1:
            for i in range(1, len(timestamps)):
                diff = timestamps[i] - timestamps[i - 1]
                if diff >= 0:
                    iats.append(diff)

        sample_count = len(timestamps)
        iat_count = len(iats)

        mean_iat = sum(iats) / float(iat_count) if iat_count > 0 else 0.0

        if iat_count > 1:
            variance_iat = sum((x - mean_iat) ** 2 for x in iats) / float(iat_count - 1)
        else:
            variance_iat = 0.0

        std_iat = math.sqrt(variance_iat)
        cv_iat = round(std_iat / (mean_iat + 1e-5), 4)

        # Periodicity & Jitter
        periodicity_score = round(max(0.0, 1.0 - min(1.0, cv_iat)), 4)
        jitter_ratio = round(std_iat / (mean_iat + 1e-5), 4)

        # Payload size consistency
        bytes_list = orig_bytes_list or []
        if len(bytes_list) > 1:
            mean_bytes = sum(bytes_list) / float(len(bytes_list))
            var_bytes = sum((b - mean_bytes) ** 2 for b in bytes_list) / float(len(bytes_list) - 1)
            payload_size_std = round(math.sqrt(var_bytes), 2)
        else:
            payload_size_std = 0.0

        features = {
            "sample_count": sample_count,
            "iat_count": iat_count,
            "mean_iat": round(mean_iat, 4),
            "variance_iat": round(variance_iat, 4),
            "std_iat": round(std_iat, 4),
            "cv_iat": cv_iat,
            "periodicity_score": periodicity_score,
            "jitter_ratio": jitter_ratio,
            "payload_size_std": payload_size_std
        }

        return FeatureSnapshot(
            timestamp=ts,
            entity_type="flow_pair",
            entity_id=f"{src_ip}->{dst_ip}",
            window_seconds=window_seconds,
            features=features
        )
