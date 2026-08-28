import unittest
from shared.contracts import DetectionResult, ThreatEvidence
from services.analytics.threat_fusion import ThreatFusionEngine, FusedThreatAlert


class TestThreatFusionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ThreatFusionEngine()

    def test_single_detector_fusion(self):
        res = DetectionResult(
            timestamp="2026-08-28T16:53:00Z",
            detector_name="DDoSDetector",
            entity_type="ip",
            entity_id="192.168.1.100",
            severity="HIGH",
            confidence_score=0.88,
            is_threat=True,
            evidence=[
                ThreatEvidence(code="SYN_FLOOD_DETECTED", message="High SYN packet rate", value=800, threshold=500).to_dict()
            ],
            mitigation_recommendation="APPLY_PASSIVE_SHIELD_FILTERS"
        )

        alert = self.engine.fuse_results([res])
        self.assertIsInstance(alert, FusedThreatAlert)
        self.assertEqual(alert.entity_id, "192.168.1.100")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.fused_score, 0.88)
        self.assertTrue(alert.is_threat)
        self.assertEqual(alert.contributing_detectors, ["DDoSDetector"])
        self.assertEqual(len(alert.evidence), 1)
        self.assertEqual(alert.evidence[0]["detector_source"], "DDoSDetector")

    def test_multi_detector_fusion(self):
        res1 = DetectionResult(
            timestamp="2026-08-28T16:53:01Z",
            detector_name="PortScanDetector",
            entity_type="ip",
            entity_id="192.168.1.200",
            severity="MEDIUM",
            confidence_score=0.75,
            is_threat=True,
            evidence=[
                ThreatEvidence(code="VERTICAL_PORT_SCAN", message="Probed 50 ports", value=50, threshold=15).to_dict()
            ],
            mitigation_recommendation="FLAG_RECONNAISSANCE_IP"
        )

        res2 = DetectionResult(
            timestamp="2026-08-28T16:53:01Z",
            detector_name="ExfiltrationDetector",
            entity_type="ip",
            entity_id="192.168.1.200",
            severity="HIGH",
            confidence_score=0.85,
            is_threat=True,
            evidence=[
                ThreatEvidence(code="EXFIL_HIGH_BURST_VOLUME", message="Uploaded 15 MB", value=15000000, threshold=10000000).to_dict()
            ],
            mitigation_recommendation="BLOCK_DATA_EXFILTRATION_FLOW"
        )

        alert = self.engine.fuse_results([res1, res2])
        self.assertEqual(alert.entity_id, "192.168.1.200")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertGreater(alert.fused_score, 0.95)
        self.assertEqual(set(alert.contributing_detectors), {"PortScanDetector", "ExfiltrationDetector"})
        self.assertEqual(len(alert.evidence), 2)
        self.assertEqual(alert.mitigation_recommendation, "BLOCK_DATA_EXFILTRATION_FLOW")

    def test_duplicate_result_handling(self):
        res_low = DetectionResult(
            timestamp="2026-08-28T16:53:02Z",
            detector_name="DDoSDetector",
            entity_type="ip",
            entity_id="192.168.1.101",
            severity="LOW",
            confidence_score=0.40,
            is_threat=True,
            evidence=[ThreatEvidence(code="PPS_SURGE", message="Surge in pps", value=100, threshold=50).to_dict()]
        )

        res_high = DetectionResult(
            timestamp="2026-08-28T16:53:02Z",
            detector_name="DDoSDetector",
            entity_type="ip",
            entity_id="192.168.1.101",
            severity="HIGH",
            confidence_score=0.90,
            is_threat=True,
            evidence=[ThreatEvidence(code="PPS_SURGE", message="Surge in pps", value=500, threshold=50).to_dict()]
        )

        alert = self.engine.fuse_results([res_low, res_high])
        self.assertEqual(alert.fused_score, 0.90)
        self.assertEqual(len(alert.contributing_detectors), 1)

    def test_empty_results(self):
        alert = self.engine.fuse_results([])
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
