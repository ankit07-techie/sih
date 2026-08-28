import unittest
from shared.contracts import FeatureSnapshot
from services.features.dns_features import DNSFeatureExtractor, compute_bigram_entropy, max_consecutive_consonants


class TestDNSFeatures(unittest.TestCase):

    def setUp(self):
        self.extractor = DNSFeatureExtractor()

    def test_benign_domain_features(self):
        domain = "google.com"
        snap = self.extractor.compute_dns_features(domain)

        self.assertEqual(snap.entity_id, domain)
        self.assertEqual(snap.entity_type, "domain")
        self.assertEqual(snap.event_type, "FeatureSnapshot")

        features = snap.features
        self.assertEqual(features["domain_length"], 10)
        self.assertEqual(features["subdomain_depth"], 1)
        self.assertLess(features["entropy"], 3.0)
        self.assertEqual(features["digit_count"], 0)
        self.assertEqual(features["is_nxdomain"], 0)
        self.assertEqual(features["is_txt_query"], 0)

    def test_dga_domain_features(self):
        domain = "x1y2z3a4b5c6d7e8f9.malicious.net"
        snap = self.extractor.compute_dns_features(domain, response_code="NXDOMAIN")

        features = snap.features
        self.assertGreater(features["domain_length"], 25)
        self.assertEqual(features["subdomain_depth"], 2)
        self.assertGreater(features["entropy"], 3.5)
        self.assertGreater(features["digit_ratio"], 0.20)
        self.assertEqual(features["is_nxdomain"], 1)

    def test_dns_tunneling_txt_query(self):
        domain = "chunk998877665544.tunnel.exfil.org"
        snap = self.extractor.compute_dns_features(domain, query_type="TXT")

        features = snap.features
        self.assertEqual(features["is_txt_query"], 1)
        self.assertEqual(features["subdomain_depth"], 3)
        self.assertGreater(features["subdomain_length"], 15)

    def test_consecutive_consonants_and_bigram_entropy(self):
        s = "strnngth"
        self.assertEqual(max_consecutive_consonants(s), 8)
        self.assertGreater(compute_bigram_entropy("abcdefgh"), 2.0)


if __name__ == "__main__":
    unittest.main()
