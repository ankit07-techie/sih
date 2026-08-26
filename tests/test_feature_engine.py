import os
import unittest
from shared.contracts import FeatureSnapshot, ContractValidationError
from services.state import RedisStateManager, MockRedisDriver
from services.features import FeatureEngine, compute_shannon_entropy


class TestFeatureEngine(unittest.TestCase):

    def setUp(self):
        self.driver = MockRedisDriver()
        self.state_mgr = RedisStateManager(client_instance=self.driver)
        self.feature_engine = FeatureEngine(self.state_mgr)

    def test_feature_snapshot_contract(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:07:00Z",
            entity_type="ip",
            entity_id="192.168.1.50",
            window_seconds=60,
            features={"flow_count": 5, "byte_ratio": 1.5}
        )
        self.assertEqual(snap.event_type, "FeatureSnapshot")
        self.assertEqual(snap.version, "1.0")

        # JSON Roundtrip
        json_str = snap.to_json()
        restored = FeatureSnapshot.from_json(json_str)
        self.assertEqual(restored.entity_id, "192.168.1.50")
        self.assertEqual(restored.features["flow_count"], 5)

    def test_feature_snapshot_fixture(self):
        fixture_path = "fixtures/contracts/feature_snapshot.json"
        if os.path.exists(fixture_path):
            with open(fixture_path, 'r') as f:
                snap = FeatureSnapshot.from_json(f.read())
                self.assertEqual(snap.event_type, "FeatureSnapshot")
                self.assertEqual(snap.entity_id, "192.168.1.50")

    def test_compute_ip_features(self):
        src_ip = "192.168.1.50"
        self.state_mgr.record_flow_metrics(src_ip, orig_bytes=1000, resp_bytes=4000, orig_pkts=10, resp_pkts=20, window_seconds=60)
        self.state_mgr.record_unique_target(src_ip, "80", "ports", 60)
        self.state_mgr.record_unique_target(src_ip, "443", "ports", 60)

        snap = self.feature_engine.compute_ip_features(src_ip, window_seconds=60)
        self.assertEqual(snap.entity_id, src_ip)
        self.assertEqual(snap.features["flow_count"], 1)
        self.assertEqual(snap.features["orig_bytes"], 1000)
        self.assertEqual(snap.features["resp_bytes"], 4000)
        self.assertEqual(snap.features["unique_dest_ports"], 2)

    def test_compute_beacon_features(self):
        src_ip = "192.168.1.10"
        dst_ip = "10.0.0.5"

        # Record 5 periodic timestamps with exactly 10s interval
        for t in [100.0, 110.0, 120.0, 130.0, 140.0]:
            self.state_mgr.record_inter_arrival(src_ip, dst_ip, t)

        snap = self.feature_engine.compute_beacon_features(src_ip, dst_ip)
        self.assertEqual(snap.entity_type, "flow_pair")
        self.assertEqual(snap.features["sample_count"], 5)
        self.assertEqual(snap.features["mean_iat"], 10.0)
        self.assertEqual(snap.features["variance_iat"], 0.0)
        self.assertEqual(snap.features["cv_iat"], 0.0)  # Periodic beaconing -> CV = 0.0

    def test_compute_dns_features(self):
        # DGA domain test
        domain = "a1b2c3d4e5f6.malicious.net"
        snap = self.feature_engine.compute_dns_features(domain)

        self.assertEqual(snap.entity_type, "domain")
        self.assertEqual(snap.entity_id, domain)
        self.assertEqual(snap.features["domain_length"], len(domain))
        self.assertGreater(snap.features["entropy"], 3.0)
        self.assertEqual(snap.features["subdomain_depth"], 2)

    def test_shannon_entropy(self):
        self.assertEqual(compute_shannon_entropy("aaaaa"), 0.0)
        self.assertGreater(compute_shannon_entropy("abcdef"), 2.0)


if __name__ == "__main__":
    unittest.main()
