"""
PassiveShield AI — Reusable Port Scan Feature Extractor
Extracts unique port fan-out counts, unique destination IP counts, fan-out growth rates,
and TCP connection failure/reset characteristics for port scan detection.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager


class PortScanFeatureExtractor:
    """
    Computes reusable Port Scan & Reconnaissance features for source IP entities.
    Outputs FeatureSnapshot contract objects.
    Contains 0% detector classification or threat scoring logic.
    """

    def __init__(self, state_manager: RedisStateManager):
        self.state_mgr = state_manager

    def compute_port_scan_features(
        self,
        src_ip: str,
        window_seconds: int = 60,
        prev_unique_ports: int = 0,
        target_ports: Optional[List[int]] = None,
        target_ips: Optional[List[str]] = None,
        conn_states: Optional[List[str]] = None,
        timestamp: Optional[str] = None
    ) -> FeatureSnapshot:
        """
        Calculates port scanning signals for a source IP entity over a window.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        # Redis state queries
        state_unique_ports = self.state_mgr.get_unique_target_count(src_ip, "ports", window_seconds)
        state_unique_ips = self.state_mgr.get_unique_target_count(src_ip, "ips", window_seconds)

        # Merge with provided list inputs if present
        input_ports = set(target_ports or [])
        input_ips = set(target_ips or [])

        unique_dst_ports = max(state_unique_ports, len(input_ports))
        unique_dst_ips = max(state_unique_ips, len(input_ips))

        # Fan-out rates
        fanout_ports_per_sec = round(unique_dst_ports / float(window_seconds), 2)
        fanout_ips_per_sec = round(unique_dst_ips / float(window_seconds), 2)

        # Growth rate signal
        denom = max(1, prev_unique_ports)
        port_growth_rate = round((unique_dst_ports - prev_unique_ports) / float(denom), 2)

        # Connection state characteristics
        conn_list = conn_states or []
        total_samples = len(conn_list) or 1

        rej_count = conn_list.count("REJ")
        rsto_count = conn_list.count("RSTO") + conn_list.count("RSTR") + conn_list.count("RSTOS0")
        s0_count = conn_list.count("S0")
        stealth_count = s0_count + conn_list.count("S1") + conn_list.count("SH")

        failed_conn_ratio = round((rej_count + rsto_count + s0_count) / float(total_samples), 4)
        rst_ratio = round(rsto_count / float(total_samples), 4)
        stealth_scan_ratio = round(stealth_count / float(total_samples), 4)

        features = {
            "unique_dst_ports": unique_dst_ports,
            "unique_dst_ips": unique_dst_ips,
            "fanout_ports_per_sec": fanout_ports_per_sec,
            "fanout_ips_per_sec": fanout_ips_per_sec,
            "port_growth_rate": port_growth_rate,
            "failed_conn_ratio": failed_conn_ratio,
            "rst_ratio": rst_ratio,
            "stealth_scan_ratio": stealth_scan_ratio
        }

        return FeatureSnapshot(
            timestamp=ts,
            entity_type="ip",
            entity_id=src_ip,
            window_seconds=window_seconds,
            features=features
        )
