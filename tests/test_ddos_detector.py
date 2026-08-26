import os
import unittest
from shared.contracts import FeatureSnapshot, DetectionResult
from services.detectors.ddos_detector import DDoSDetector
from services.ingestion import ZeekAdapter
from services.state import RedisStateManager, MockRedisDriver
from services.features import FeatureEngine


class TestDDoSDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DDoSDetector()

    def test_benign_traffic(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:12:00Z",
            entity_type="ip",
            entity_id="10.0.0.1",
            window_seconds=60,
            features={
                "pps": 10.0,
                "bps": 50000.0,
                "surge_ratio_pps": 1.0,
                "syn_only_ratio": 0.05,
                "ack_missing_ratio": 0.05,
                "unique_source_ips": 5,
                "destination_port_entropy": 2.5
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertIsInstance(res, DetectionResult)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)
        self.assertEqual(res.confidence_score, 0.0)

    def test_syn_flood_attack(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:12:01Z",
            entity_type="ip",
            entity_id="10.0.0.1",
            window_seconds=60,
            features={
                "pps": 1000.0,
                "bps": 5_000_000.0,
                "surge_ratio_pps": 10.0,  # 10x surge -> s_rate = 1.0
                "syn_only_ratio": 0.90,   # s_handshake = 0.7*0.9 + 0.3*0.9 = 0.9
                "ack_missing_ratio": 0.90,
                "unique_source_ips": 150, # div_score = 1.0
                "destination_port_entropy": 0.5  # ent_penalty = 1.0 - 0.125 = 0.875
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("HIGH", "CRITICAL"))
        self.assertGreaterEqual(res.confidence_score, 0.85)

        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("VOLUMETRIC_SURGE", evidence_codes)
        self.assertIn("SYN_FLOOD_SIGNAL", evidence_codes)

    def test_incomplete_telemetry_degradation(self):
        # Missing syn_only_ratio and ack_missing_ratio
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:12:02Z",
            entity_type="ip",
            entity_id="10.0.0.1",
            window_seconds=60,
            features={
                "pps": 800.0,
                "bps": 4_000_000.0,
                "surge_ratio_pps": 8.0,
                "unique_source_ips": 80,
                "destination_port_entropy": 1.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("DEGRADED_TELEMETRY", evidence_codes)

    def test_deterministic_replay_pipeline(self):
        # Replay conn.log through ZeekAdapter -> RedisStateManager -> FeatureEngine -> DDoSDetector
        conn_log_path = "fixtures/sample_zeek_logs/conn.log"
        if not os.path.exists(conn_log_path):
            self.skipTest("conn.log fixture not found.")

        driver = MockRedisDriver()
        state_mgr = RedisStateManager(client_instance=driver)
        feature_engine = FeatureEngine(state_mgr)

        with open(conn_log_path, 'r') as f:
            for line in f:
                event = ZeekAdapter.parse_conn_event(line)
                if event:
                    state_mgr.record_flow_metrics(
                        src_ip=event["dst_ip"], # Record traffic towards destination
                        orig_bytes=event["orig_bytes"],
                        resp_bytes=event["resp_bytes"],
                        orig_pkts=event["orig_packets"],
                        resp_pkts=event["resp_packets"],
                        window_seconds=60
                    )

        snap = feature_engine.compute_ip_features("10.0.0.1", window_seconds=60)
        res = self.detector.analyze_snapshot(snap)

        self.assertIsInstance(res, DetectionResult)
        self.assertEqual(res.entity_id, "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
