import unittest
from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager, MockRedisDriver
from services.features.beaconing_features import BeaconingFeatureExtractor


class TestBeaconingFeatures(unittest.TestCase):

    def setUp(self):
        self.driver = MockRedisDriver()
        self.state_mgr = RedisStateManager(client_instance=self.driver)
        self.extractor = BeaconingFeatureExtractor(self.state_mgr)

    def test_periodic_c2_beaconing(self):
        src_ip = "192.168.1.50"
        dst_ip = "198.51.100.25"

        # Record 10 periodic connections exactly 15 seconds apart
        base_t = 1700000000.0
        for i in range(10):
            self.state_mgr.record_inter_arrival(src_ip, dst_ip, base_t + (i * 15.0))

        orig_bytes = [128, 128, 128, 128, 128]

        snap = self.extractor.compute_beaconing_features(
            src_ip=src_ip,
            dst_ip=dst_ip,
            window_seconds=300,
            orig_bytes_list=orig_bytes
        )

        self.assertEqual(snap.entity_id, f"{src_ip}->{dst_ip}")
        self.assertEqual(snap.entity_type, "flow_pair")
        
        features = snap.features
        self.assertEqual(features["sample_count"], 10)
        self.assertEqual(features["iat_count"], 9)
        self.assertEqual(features["mean_iat"], 15.0)
        self.assertEqual(features["variance_iat"], 0.0)
        self.assertEqual(features["cv_iat"], 0.0)
        self.assertEqual(features["periodicity_score"], 1.0)
        self.assertEqual(features["payload_size_std"], 0.0)

    def test_jittered_c2_beaconing(self):
        src_ip = "192.168.1.50"
        dst_ip = "198.51.100.26"

        # Record connection timestamps with small 1s jitter around 30s
        delays = [0, 30, 61, 90, 121, 150]
        base_t = 1700000000.0
        for d in delays:
            self.state_mgr.record_inter_arrival(src_ip, dst_ip, base_t + d)

        snap = self.extractor.compute_beaconing_features(src_ip, dst_ip)
        features = snap.features
        self.assertLess(features["cv_iat"], 0.20)
        self.assertGreater(features["periodicity_score"], 0.80)

    def test_random_human_traffic(self):
        src_ip = "192.168.1.50"
        dst_ip = "198.51.100.27"

        # Record irregular random delays
        delays = [0, 2, 45, 47, 190, 192]
        base_t = 1700000000.0
        for d in delays:
            self.state_mgr.record_inter_arrival(src_ip, dst_ip, base_t + d)

        snap = self.extractor.compute_beaconing_features(src_ip, dst_ip)
        features = snap.features
        self.assertGreater(features["cv_iat"], 0.80)
        self.assertLess(features["periodicity_score"], 0.20)


if __name__ == "__main__":
    unittest.main()
