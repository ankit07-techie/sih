"""
PassiveShield AI — Reusable DDoS Feature Extractor
Extracts traffic rates (pps, bps), SYN/ACK TCP handshake characteristics,
source IP/port distribution entropy, destination concentration, and baseline surge ratios.
"""

import math
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager
from .feature_engine import compute_shannon_entropy


class DDoSFeatureExtractor:
    """
    Computes reusable DDoS-related features for target IP entities.
    Outputs FeatureSnapshot contract objects.
    Contains 0% detector scoring or classification logic.
    """

    def __init__(self, state_manager: RedisStateManager):
        self.state_mgr = state_manager

    def compute_ddos_features(
        self,
        target_ip: str,
        window_seconds: int = 60,
        baseline_pps: float = 100.0,
        baseline_bps: float = 100000.0,
        conn_states: Optional[List[str]] = None,
        source_ips: Optional[List[str]] = None,
        target_ports: Optional[List[int]] = None,
        timestamp: Optional[str] = None
    ) -> FeatureSnapshot:
        """
        Calculates DDoS traffic signals for a target IP entity over a window.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        raw_metrics = self.state_mgr.get_flow_metrics(target_ip, window_seconds)

        flow_count = raw_metrics.get("flow_count", 0)
        orig_bytes = raw_metrics.get("orig_bytes", 0)
        resp_bytes = raw_metrics.get("resp_bytes", 0)
        orig_pkts = raw_metrics.get("orig_pkts", 0)
        resp_pkts = raw_metrics.get("resp_pkts", 0)

        total_bytes = orig_bytes + resp_bytes
        total_pkts = orig_pkts + resp_pkts

        # Rate calculations
        pps = round(total_pkts / float(window_seconds), 2)
        bps = round((total_bytes * 8) / float(window_seconds), 2)
        mbps = round(bps / 1_000_000.0, 4)
        avg_pkt_size = round(total_bytes / float(total_pkts + 1), 2)

        # Connection state / SYN-ACK flags
        conn_list = conn_states or []
        s0_count = conn_list.count("S0")  # SYN sent, no response
        rej_count = conn_list.count("REJ") + conn_list.count("RSTO") + conn_list.count("RSTOS0")
        total_conn_samples = len(conn_list) or 1

        syn_only_ratio = round(s0_count / float(total_conn_samples), 4)
        ack_missing_ratio = round((s0_count + rej_count) / float(total_conn_samples), 4)

        # Entropy & distribution signals
        src_list = source_ips or []
        port_list = [str(p) for p in (target_ports or [])]

        unique_src_count = len(set(src_list))
        src_entropy = round(compute_shannon_entropy("".join(src_list)), 4) if src_list else 0.0
        port_entropy = round(compute_shannon_entropy("".join(port_list)), 4) if port_list else 0.0

        # Destination concentration
        unique_ports_count = len(set(port_list))
        port_concentration_ratio = round(1.0 / float(unique_ports_count + 1e-5), 4) if unique_ports_count > 0 else 0.0

        # Baseline surge input ratios
        surge_ratio_pps = round(pps / float(baseline_pps + 1e-5), 2)
        surge_ratio_bps = round(bps / float(baseline_bps + 1e-5), 2)

        features = {
            "pps": pps,
            "bps": bps,
            "mbps": mbps,
            "avg_pkt_size": avg_pkt_size,
            "flow_count": flow_count,
            "syn_only_ratio": syn_only_ratio,
            "ack_missing_ratio": ack_missing_ratio,
            "unique_source_ips": unique_src_count,
            "source_ip_entropy": src_entropy,
            "destination_port_entropy": port_entropy,
            "port_concentration_ratio": port_concentration_ratio,
            "surge_ratio_pps": surge_ratio_pps,
            "surge_ratio_bps": surge_ratio_bps
        }

        return FeatureSnapshot(
            timestamp=ts,
            entity_type="ip",
            entity_id=target_ip,
            window_seconds=window_seconds,
            features=features
        )
