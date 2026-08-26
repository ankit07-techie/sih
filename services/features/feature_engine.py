"""
PassiveShield AI — Shared Feature Engine
Provides reusable feature extraction interfaces for IP traffic statistics,
inter-arrival beaconing metrics, and domain lexical features.
Outputs standardized FeatureSnapshot contract instances.
"""

import math
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager


def compute_shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of string s."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


class FeatureEngine:
    """
    Reusable feature calculation engine for network traffic analytics.
    Interactions occur exclusively through state queries and mathematical feature extraction.
    Contains zero threat classification logic.
    """

    def __init__(self, state_manager: RedisStateManager):
        self.state_mgr = state_manager

    def _current_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def compute_ip_features(self, src_ip: str, window_seconds: int = 60, timestamp: Optional[str] = None) -> FeatureSnapshot:
        """Computes windowed IP traffic rate, volume, and fan-out features."""
        ts = timestamp or self._current_timestamp()
        raw_metrics = self.state_mgr.get_flow_metrics(src_ip, window_seconds)

        flow_count = raw_metrics.get("flow_count", 0)
        orig_bytes = raw_metrics.get("orig_bytes", 0)
        resp_bytes = raw_metrics.get("resp_bytes", 0)
        orig_pkts = raw_metrics.get("orig_pkts", 0)
        resp_pkts = raw_metrics.get("resp_pkts", 0)

        unique_ports = self.state_mgr.get_unique_target_count(src_ip, "ports", window_seconds)
        unique_ips = self.state_mgr.get_unique_target_count(src_ip, "ips", window_seconds)

        total_bytes = orig_bytes + resp_bytes
        total_pkts = orig_pkts + resp_pkts

        features = {
            "flow_count": flow_count,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "byte_ratio": round(orig_bytes / (resp_bytes + 1), 4),
            "bytes_per_sec": round(total_bytes / float(window_seconds), 2),
            "pkts_per_sec": round(total_pkts / float(window_seconds), 2),
            "avg_bytes_per_flow": round(total_bytes / float(flow_count + 1), 2),
            "unique_dest_ports": unique_ports,
            "unique_dest_ips": unique_ips
        }

        return FeatureSnapshot(
            timestamp=ts,
            entity_type="ip",
            entity_id=src_ip,
            window_seconds=window_seconds,
            features=features
        )

    def compute_beacon_features(self, src_ip: str, dst_ip: str, timestamp: Optional[str] = None) -> FeatureSnapshot:
        """Computes inter-arrival time (IAT) statistics for a src_ip -> dst_ip connection pair."""
        ts = timestamp or self._current_timestamp()
        timestamps = self.state_mgr.get_inter_arrival_timestamps(src_ip, dst_ip)

        iats: List[float] = []
        if len(timestamps) > 1:
            for i in range(1, len(timestamps)):
                diff = timestamps[i] - timestamps[i - 1]
                if diff >= 0:
                    iats.append(diff)

        sample_count = len(timestamps)
        mean_iat = sum(iats) / len(iats) if iats else 0.0

        if len(iats) > 1:
            variance_iat = sum((x - mean_iat) ** 2 for x in iats) / (len(iats) - 1)
        else:
            variance_iat = 0.0

        std_iat = math.sqrt(variance_iat)
        cv_iat = round(std_iat / (mean_iat + 1e-5), 4)

        features = {
            "sample_count": sample_count,
            "iat_count": len(iats),
            "mean_iat": round(mean_iat, 4),
            "variance_iat": round(variance_iat, 4),
            "std_iat": round(std_iat, 4),
            "cv_iat": cv_iat
        }

        return FeatureSnapshot(
            timestamp=ts,
            entity_type="flow_pair",
            entity_id=f"{src_ip}->{dst_ip}",
            window_seconds=300,
            features=features
        )

    def compute_dns_features(self, domain: str, timestamp: Optional[str] = None) -> FeatureSnapshot:
        """Computes lexical domain features (length, Shannon entropy, digit ratio, subdomain depth)."""
        ts = timestamp or self._current_timestamp()
        domain_str = domain.strip().lower()

        length = len(domain_str)
        entropy = compute_shannon_entropy(domain_str)
        digits = sum(c.isdigit() for c in domain_str)
        digit_ratio = digits / float(length) if length > 0 else 0.0
        subdomain_depth = domain_str.count('.')

        features = {
            "domain_length": length,
            "entropy": round(entropy, 4),
            "digit_count": digits,
            "digit_ratio": round(digit_ratio, 4),
            "subdomain_depth": subdomain_depth
        }

        return FeatureSnapshot(
            timestamp=ts,
            entity_type="domain",
            entity_id=domain_str,
            window_seconds=60,
            features=features
        )
