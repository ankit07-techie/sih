import unittest
from shared.contracts import FeatureSnapshot, DetectionResult
from services.detectors.beacon_detector import C2BeaconDetector


class TestC2BeaconDetector(unittest.TestCase):

    def setUp(self):
        self.detector = C2BeaconDetector()

    def test_insufficient_samples(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:40:00Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.25",
            window_seconds=300,
            features={
                "sample_count": 3,  # Below min floor 5
                "iat_count": 2,
                "mean_iat": 15.0,
                "cv_iat": 0.01
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertIsInstance(res, DetectionResult)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("INSUFFICIENT_BEACON_SAMPLES", evidence_codes)

    def test_periodic_c2_beaconing(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:40:01Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.25",
            window_seconds=300,
            features={
                "sample_count": 12,
                "iat_count": 11,
                "mean_iat": 15.0,
                "cv_iat": 0.0,  # Perfect periodicity
                "periodicity_score": 1.0,
                "payload_size_std": 2.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("HIGH", "CRITICAL"))
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("PERIODIC_BEACONING_SIGNAL", evidence_codes)
        self.assertIn("FIXED_PAYLOAD_SIZE", evidence_codes)

    def test_jittered_c2_beaconing(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:40:02Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.26",
            window_seconds=300,
            features={
                "sample_count": 10,
                "iat_count": 9,
                "mean_iat": 30.0,
                "cv_iat": 0.12,  # Small jitter
                "periodicity_score": 0.88,
                "payload_size_std": 5.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("MEDIUM", "HIGH"))

    def test_burst_traffic_filtered(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:40:03Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.27",
            window_seconds=300,
            features={
                "sample_count": 15,
                "iat_count": 14,
                "mean_iat": 10.0,
                "cv_iat": 1.25,  # High variance burst traffic
                "periodicity_score": 0.0,
                "payload_size_std": 250.0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("BURST_TRAFFIC_FILTERED", evidence_codes)

    def test_spectral_fft_analysis(self):
        # 32 periodic samples (spaced by 10s)
        iats = [10.0] * 32
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:40:04Z",
            entity_type="flow_pair",
            entity_id="192.168.1.50->198.51.100.28",
            window_seconds=300,
            features={
                "sample_count": 33,
                "iat_count": 32,
                "mean_iat": 10.0,
                "cv_iat": 0.0,
                "periodicity_score": 1.0,
                "payload_size_std": 0.0
            }
        )

        res = self.detector.analyze_snapshot(snap, raw_iats=iats)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("HIGH", "CRITICAL"))


if __name__ == "__main__":
    unittest.main()
