import unittest
from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager, MockRedisDriver
from services.features.ddos_features import DDoSFeatureExtractor


class TestDDoSFeatures(unittest.TestCase):

    def setUp(self):
        self.driver = MockRedisDriver()
        self.state_mgr = RedisStateManager(client_instance=self.driver)
        self.extractor = DDoSFeatureExtractor(self.state_mgr)

    def test_ddos_rates_and_ratios(self):
        target_ip = "10.0.0.1"
        self.state_mgr.record_flow_metrics(
            src_ip=target_ip,
            orig_bytes=10000,
            resp_bytes=20000,
            orig_pkts=100,
            resp_pkts=200,
            window_seconds=60
        )

        conn_states = ["S0", "S0", "SF", "SF", "REJ"]
        source_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.1"]
        target_ports = [80, 80, 80, 443]

        snap = self.extractor.compute_ddos_features(
            target_ip=target_ip,
            window_seconds=60,
            baseline_pps=2.0,
            conn_states=conn_states,
            source_ips=source_ips,
            target_ports=target_ports
        )

        self.assertEqual(snap.entity_id, target_ip)
        self.assertEqual(snap.event_type, "FeatureSnapshot")
        
        features = snap.features
        self.assertEqual(features["pps"], 5.0)  # (100+200)/60 = 5.0
        self.assertEqual(features["syn_only_ratio"], 0.4)  # 2 S0 out of 5
        self.assertEqual(features["ack_missing_ratio"], 0.6)  # (2 S0 + 1 REJ) / 5
        self.assertEqual(features["unique_source_ips"], 3)
        self.assertEqual(features["surge_ratio_pps"], 2.5)  # 5.0 / 2.0 = 2.5x baseline surge


if __name__ == "__main__":
    unittest.main()
