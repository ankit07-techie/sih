import unittest
from shared.contracts import FeatureSnapshot, DetectionResult
from services.detectors.port_scan_detector import PortScanDetector


class TestPortScanDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PortScanDetector()

    def test_benign_traffic(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:18:00Z",
            entity_type="ip",
            entity_id="192.168.1.50",
            window_seconds=60,
            features={
                "unique_dst_ports": 2,
                "unique_dst_ips": 1,
                "fanout_ports_per_sec": 0.03,
                "port_growth_rate": 0.0,
                "failed_conn_ratio": 0.0,
                "stealth_scan_ratio": 0.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertIsInstance(res, DetectionResult)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)

    def test_horizontal_ip_sweep(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:18:01Z",
            entity_type="ip",
            entity_id="192.168.1.200",
            window_seconds=60,
            features={
                "unique_dst_ports": 1,
                "unique_dst_ips": 30,  # 30 unique IPs -> s_horiz = 1.0 * (0.5 + 0.4) = 0.9
                "fanout_ips_per_sec": 0.5,
                "port_growth_rate": 2.0,
                "failed_conn_ratio": 0.8,
                "stealth_scan_ratio": 0.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("MEDIUM", "HIGH"))
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("HORIZONTAL_IP_SWEEP", evidence_codes)

    def test_vertical_port_scan(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:18:02Z",
            entity_type="ip",
            entity_id="192.168.1.201",
            window_seconds=60,
            features={
                "unique_dst_ports": 100, # 100 ports -> s_vert = 1.0 * (0.5 + 0.45) = 0.95
                "unique_dst_ips": 1,
                "fanout_ports_per_sec": 1.66,
                "port_growth_rate": 4.0,  # s_growth = 1.0
                "failed_conn_ratio": 0.9,
                "stealth_scan_ratio": 0.6  # Stealth multiplier boost
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertEqual(res.severity, "CRITICAL")
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("VERTICAL_PORT_SCAN", evidence_codes)
        self.assertIn("STEALTH_PROBE_SIGNAL", evidence_codes)

    def test_slow_port_scan(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-26T22:18:03Z",
            entity_type="ip",
            entity_id="192.168.1.202",
            window_seconds=300,
            features={
                "unique_dst_ports": 25,
                "unique_dst_ips": 1,
                "fanout_ports_per_sec": 0.08,
                "port_growth_rate": 0.5,
                "failed_conn_ratio": 0.70,
                "stealth_scan_ratio": 0.10
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertEqual(res.severity, "LOW")


if __name__ == "__main__":
    unittest.main()
