"""
PassiveShield AI — False-Positive & C2 Temporal Verification Suite
Tests false-positive resistance on legitimate traffic patterns and verifies C2 temporal FFT vs single-snapshot fallback behavior.
"""

import unittest
from datetime import datetime, timezone

from shared.contracts import FeatureSnapshot, TLSObservation, DNSObservation
from services.state import RedisStateManager, MockRedisDriver
from services.detectors import DDoSDetector, PortScanDetector, C2BeaconDetector, DNSAnomalyDetector, ExfiltrationDetector
from services.analytics import TLSMetadataAnalyzer, ThreatFusionEngine


class TestFalsePositivesAndC2Temporal(unittest.TestCase):

    def setUp(self):
        self.mock_redis = MockRedisDriver()
        self.state_mgr = RedisStateManager(redis_client=self.mock_redis)
        self.ddos_detector = DDoSDetector()
        self.port_scan_detector = PortScanDetector()
        self.beacon_detector = C2BeaconDetector()
        self.dns_detector = DNSAnomalyDetector()
        self.exfil_detector = ExfiltrationDetector()
        self.fusion_engine = ThreatFusionEngine()

    def test_false_positive_case1_long_lived_legitimate_tcp(self):
        # Long-lived legitimate HTTPS connection: duration=1200s, rate=2.5 pps (>0.5 pps floor)
        snap = FeatureSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type="ip",
            entity_id="10.10.1.100",
            window_seconds=1200,
            features={
                "duration": 1200.0,
                "flow_rate_pps": 2.5,
                "ack_ratio": 0.50,
                "protocol": "tcp",
                "dst_port": 443,
                "pps": 2.5,
                "bps": 20000.0
            }
        )
        res_ddos = self.ddos_detector.analyze_snapshot(snap)
        self.assertFalse(res_ddos.is_threat, "Long-lived connection at 2.5 pps (>0.5 pps) should NOT trigger Slow HTTP")

    def test_false_positive_case2_low_rate_legitimate_https(self):
        # Low-rate HTTPS connection: rate=1.2 pps (>0.5 pps floor)
        snap = FeatureSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type="ip",
            entity_id="10.10.1.101",
            window_seconds=400,
            features={
                "duration": 400.0,
                "flow_rate_pps": 1.2,
                "ack_ratio": 0.48,
                "protocol": "tcp",
                "dst_port": 443,
                "pps": 1.2,
                "bps": 12000.0
            }
        )
        res_ddos = self.ddos_detector.analyze_snapshot(snap)
        self.assertFalse(res_ddos.is_threat)

    def test_false_positive_case4_normal_dns_traffic(self):
        # Normal DNS query: low length, normal entropy
        snap = FeatureSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type="domain",
            entity_id="normal-website.com",
            window_seconds=60,
            features={
                "domain_length": 18,
                "subdomain_length": 6,
                "subdomain_depth": 1,
                "entropy": 2.8,
                "bigram_entropy": 2.4,
                "digit_ratio": 0.0,
                "is_txt_query": 0
            }
        )
        res_dns = self.dns_detector.analyze_snapshot(snap)
        self.assertFalse(res_dns.is_threat, "Normal DNS query should NOT trigger DNS Anomaly Detector")

    def test_false_positive_case5_normal_low_volume_telemetry(self):
        # Low volume telemetry
        snap = FeatureSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type="ip",
            entity_id="10.10.1.105",
            window_seconds=30,
            features={
                "orig_bytes": 1200,
                "resp_bytes": 4500,
                "directional_ratio": 0.21,
                "pps": 0.3,
                "bps": 1500.0
            }
        )
        res_exfil = self.exfil_detector.analyze_snapshot(snap)
        self.assertFalse(res_exfil.is_threat)

    def test_c2_temporal_test_a_single_snapshot_fallback(self):
        # Test A: Single snapshot with strong periodicity_score (0.96) without N >= 16 Redis timestamps
        snap = FeatureSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type="flow_pair",
            entity_id="10.20.1.55->10.20.2.90",
            window_seconds=1800,
            features={
                "sample_count": 1,
                "iat_count": 0,
                "periodicity_score": 0.96,
                "mean_iat": 15.0,
                "cv_iat": 0.05
            }
        )
        res_c2 = self.beacon_detector.analyze_snapshot(snap)
        self.assertTrue(res_c2.is_threat, "Single snapshot with strong periodicity_score should trigger C2 fallback")
        self.assertIn("PERIODIC_BEACONING_FALLBACK", [ev["code"] for ev in res_c2.evidence])

    def test_c2_temporal_test_b_temporal_history_fft(self):
        # Test B: 20 historical inter-arrival observations (N >= 16)
        iats_vector = [10.0 + (0.5 if i % 2 == 0 else -0.5) for i in range(20)]
        snap = FeatureSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            entity_type="flow_pair",
            entity_id="10.20.1.55->10.20.2.90",
            window_seconds=1800,
            features={
                "sample_count": 20,
                "iat_count": 19,
                "mean_iat": 15.0,
                "cv_iat": 0.01,
                "payload_size_std": 2.0
            }
        )
        res_c2 = self.beacon_detector.analyze_snapshot(snap, raw_iats=iats_vector)
        self.assertTrue(res_c2.is_threat, "Sequence of N >= 16 observations should trigger C2 beaconing detection")
        evidence_codes = [ev["code"] for ev in res_c2.evidence]
        self.assertTrue("PERIODIC_BEACONING_SIGNAL" in evidence_codes or "SPECTRAL_PEAK_DETECTED" in evidence_codes)


if __name__ == "__main__":
    unittest.main()
