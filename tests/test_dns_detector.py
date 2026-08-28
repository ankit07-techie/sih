import unittest
from shared.contracts import FeatureSnapshot, DetectionResult
from services.detectors.dns_detector import DNSAnomalyDetector


class TestDNSAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DNSAnomalyDetector()

    def test_benign_domain(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:45:00Z",
            entity_type="domain",
            entity_id="google.com",
            window_seconds=60,
            features={
                "domain_length": 10,
                "subdomain_length": 6,
                "subdomain_depth": 1,
                "entropy": 2.1,
                "bigram_entropy": 1.8,
                "digit_ratio": 0.0,
                "max_consecutive_consonants": 2,
                "is_nxdomain": 0,
                "is_txt_query": 0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertIsInstance(res, DetectionResult)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)

    def test_dga_domain_detection(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:45:01Z",
            entity_type="domain",
            entity_id="x1y2z3a4b5c6d7e8f9.malicious.net",
            window_seconds=60,
            features={
                "domain_length": 31,
                "subdomain_length": 18,
                "subdomain_depth": 2,
                "entropy": 4.15,
                "bigram_entropy": 3.2,
                "digit_ratio": 0.29,
                "max_consecutive_consonants": 6,
                "is_nxdomain": 1,
                "is_txt_query": 0
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("HIGH", "CRITICAL"))
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("DGA_HIGH_ENTROPY", evidence_codes)
        self.assertIn("DGA_DIGIT_DENSITY", evidence_codes)
        self.assertIn("DGA_NXDOMAIN_FAILURE", evidence_codes)
        self.assertNotIn("TUNNEL_TXT_QUERY", evidence_codes)

    def test_dns_tunneling_detection(self):
        snap = FeatureSnapshot(
            timestamp="2026-08-28T16:45:02Z",
            entity_type="domain",
            entity_id="chunk99887766554433221100aaabbbccc.tunnel.exfil.org",
            window_seconds=60,
            features={
                "domain_length": 55,
                "subdomain_length": 45,
                "subdomain_depth": 4,
                "entropy": 4.2,
                "bigram_entropy": 4.1,
                "digit_ratio": 0.45,
                "max_consecutive_consonants": 3,
                "is_nxdomain": 0,
                "is_txt_query": 1
            }
        )

        res = self.detector.analyze_snapshot(snap)
        self.assertTrue(res.is_threat)
        self.assertIn(res.severity, ("MEDIUM", "HIGH", "CRITICAL"))
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("TUNNEL_SUBDOMAIN_LENGTH", evidence_codes)
        self.assertIn("TUNNEL_DEEP_SUBDOMAIN", evidence_codes)
        self.assertIn("TUNNEL_TXT_QUERY", evidence_codes)
        self.assertNotIn("DGA_NXDOMAIN_FAILURE", evidence_codes)


if __name__ == "__main__":
    unittest.main()
