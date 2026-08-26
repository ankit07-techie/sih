import unittest
from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager, MockRedisDriver
from services.features.port_scan_features import PortScanFeatureExtractor


class TestPortScanFeatures(unittest.TestCase):

    def setUp(self):
        self.driver = MockRedisDriver()
        self.state_mgr = RedisStateManager(client_instance=self.driver)
        self.extractor = PortScanFeatureExtractor(self.state_mgr)

    def test_port_scan_fanout_and_growth(self):
        src_ip = "192.168.1.99"
        
        # Record 20 unique ports in Redis state
        for p in range(1, 21):
            self.state_mgr.record_unique_target(src_ip, str(p), "ports", window_seconds=60)

        # Record 5 unique IPs in Redis state
        for ip in range(1, 6):
            self.state_mgr.record_unique_target(src_ip, f"10.0.0.{ip}", "ips", window_seconds=60)

        conn_states = ["REJ", "REJ", "S0", "S0", "RSTO", "SF", "SF", "SF", "SF", "SF"]

        snap = self.extractor.compute_port_scan_features(
            src_ip=src_ip,
            window_seconds=60,
            prev_unique_ports=5,  # 5 in previous window -> 20 in current = 3.0x growth
            conn_states=conn_states
        )

        self.assertEqual(snap.entity_id, src_ip)
        self.assertEqual(snap.event_type, "FeatureSnapshot")
        
        features = snap.features
        self.assertEqual(features["unique_dst_ports"], 20)
        self.assertEqual(features["unique_dst_ips"], 5)
        self.assertEqual(features["fanout_ports_per_sec"], 0.33)  # 20 / 60
        self.assertEqual(features["port_growth_rate"], 3.0)       # (20 - 5) / 5 = 3.0
        self.assertEqual(features["failed_conn_ratio"], 0.5)      # (2 REJ + 2 S0 + 1 RSTO) / 10 = 0.5
        self.assertEqual(features["rst_ratio"], 0.1)              # 1 RSTO / 10 = 0.1


if __name__ == "__main__":
    unittest.main()
