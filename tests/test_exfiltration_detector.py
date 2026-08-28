import unittest
from shared.contracts import FeatureSnapshot, DetectionResult
from services.detectors.exfiltration_detector import ExfiltrationDetector, compute_robust_zscore


class TestExfiltrationDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ExfiltrationDetector()

    def test_benign_download_flow(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:50:00Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->142.250.190.46",
            window_seconds=60,
            features={
                "orig_bytes": 2000,
                "resp_bytes": 500000,  # Download-heavy traffic
                "duration": 5.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertIsInstance(res, DetectionResult)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)

    def test_high_directional_exfiltration_upload(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:50:01Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.200",
            window_seconds=60,
            features={
                "orig_bytes": 15000000,  # 15 MB outbound upload
                "resp_bytes": 500,        # 500 B inbound
                "duration": 12.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("HIGH", "CRITICAL"))
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("EXFIL_HIGH_DIRECTIONAL_RATIO", evidence_codes)
        self.assertIn("EXFIL_HIGH_BURST_VOLUME", evidence_codes)

    def test_robust_zscore_anomaly(self):
        history = [50000.0, 48000.0, 52000.0, 49000.0, 51000.0]  # ~50 KB historical baseline
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:50:02Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.201",
            window_seconds=60,
            features={
                "orig_bytes": 5000000,  # 5 MB burst
                "resp_bytes": 1000,
                "duration": 8.0
            }
        )

        res = self.detector.analyze_snapshot(snap, historical_orig_bytes=history)
        self.assertTrue(res.is_threat)
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("EXFIL_ROBUST_ZSCORE_ANOMALY", evidence_codes)

    def test_below_exfil_floor(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:50:03Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.202",
            window_seconds=60,
            features={
                "orig_bytes": 500,  # Below 100 KB floor
                "resp_bytes": 50
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("BELOW_EXFIL_FLOOR", evidence_codes)

    def test_robust_zscore_calculation(self):
        history = [100.0, 102.0, 98.0, 101.0, 99.0]
        z = compute_robust_zscore(500.0, history)
        self.assertGreater(z, 5.0)


if __name__ == "__main__":
    unittest.main()
