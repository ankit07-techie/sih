import time
import unittest
from services.state.redis_state import RedisStateManager, MockRedisDriver

class TestRedisStateManager(unittest.TestCase):

    def setUp(self):
        self.driver = MockRedisDriver()
        self.state_mgr = RedisStateManager(client_instance=self.driver)

    def test_flow_metrics_aggregation(self):
        src_ip = "192.168.1.50"
        self.state_mgr.record_flow_metrics(src_ip, orig_bytes=500, resp_bytes=1000, orig_pkts=5, resp_pkts=10, window_seconds=60)
        self.state_mgr.record_flow_metrics(src_ip, orig_bytes=200, resp_bytes=300, orig_pkts=2, resp_pkts=3, window_seconds=60)

        metrics = self.state_mgr.get_flow_metrics(src_ip, window_seconds=60)
        self.assertEqual(metrics["flow_count"], 2)
        self.assertEqual(metrics["orig_bytes"], 700)
        self.assertEqual(metrics["resp_bytes"], 1300)
        self.assertEqual(metrics["orig_pkts"], 7)
        self.assertEqual(metrics["resp_pkts"], 13)

    def test_unique_target_fanout(self):
        src_ip = "10.0.0.5"
        # Record connections to multiple ports
        for port in [80, 443, 22, 8080, 80]:
            self.state_mgr.record_unique_target(src_ip, target=str(port), target_type="ports", window_seconds=10)

        count = self.state_mgr.get_unique_target_count(src_ip, target_type="ports", window_seconds=10)
        self.assertEqual(count, 4) # 4 unique ports (80, 443, 22, 8080)

    def test_inter_arrival_timestamps_bounded_capping(self):
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Record 15 timestamps with max_history=10
        base_time = 1700000000.0
        for i in range(15):
            self.state_mgr.record_inter_arrival(src_ip, dst_ip, base_time + i, max_history=10)

        timestamps = self.state_mgr.get_inter_arrival_timestamps(src_ip, dst_ip)
        self.assertEqual(len(timestamps), 10)
        # Should contain the latest 10 timestamps (base_time + 5 to base_time + 14)
        self.assertEqual(timestamps[0], base_time + 5)
        self.assertEqual(timestamps[-1], base_time + 14)

    def test_ttl_expiration(self):
        src_ip = "192.168.1.200"
        key = self.state_mgr._get_flow_key(src_ip, 1)
        self.driver.hincrby(key, "flow_count", 1)
        self.driver.expire(key, 1) # Set 1 second TTL

        # Verify present immediately
        self.assertEqual(self.driver.hgetall(key)["flow_count"], "1")

        # Wait 1.1s for expiration
        time.sleep(1.1)

        # Verify key expired
        self.assertEqual(self.driver.hgetall(key), {})

    def test_key_naming_convention(self):
        flow_key = self.state_mgr._get_flow_key("1.2.3.4", 60)
        self.assertTrue(flow_key.startswith("passiveshield:state:flow:1.2.3.4:60s"))

        target_key = self.state_mgr._get_target_key("1.2.3.4", "ports", 10)
        self.assertTrue(target_key.startswith("passiveshield:state:targets:1.2.3.4:ports:10s"))

        beacon_key = self.state_mgr._get_beacon_key("1.2.3.4", "5.6.7.8")
        self.assertEqual(beacon_key, "passiveshield:state:beacon:1.2.3.4:5.6.7.8")

if __name__ == "__main__":
    unittest.main()
