import os
import unittest
from shared.contracts import TLSObservation, DetectionResult
from services.analytics.tls_analyzer import TLSMetadataAnalyzer


class TestTLSMetadataAnalyzer(unittest.TestCase):

    def setUp(self):
        sig_file = os.path.join(os.path.dirname(__file__), "..", "fixtures", "tls_signatures.json")
        if os.path.exists(sig_file):
            self.analyzer = TLSMetadataAnalyzer.from_signature_file(sig_file)
        else:
            self.analyzer = TLSMetadataAnalyzer()

    def test_benign_tls_flow(self):
        obs = TLSObservation(
            timestamp="2026-08-28T16:48:00Z",
            flow_id="C12345",
            client_ip="192.168.1.50",
            server_ip="142.250.190.46",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            sni_hostname="google.com",
            established=True,
            ja3="771,4865-4866-4867,0-23-65281,29-23-24,0",
            ja4="t13d151600_normal_client"
        )

        res = self.analyzer.analyze_tls_observation(obs)
        self.assertIsInstance(res, DetectionResult)
        self.assertEqual(res.severity, "INFO")
        self.assertFalse(res.is_threat)

    def test_ja3_cobalt_strike_match(self):
        obs = TLSObservation(
            timestamp="2026-08-28T16:48:01Z",
            flow_id="C12346",
            client_ip="192.168.1.50",
            server_ip="198.51.100.99",
            tls_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            sni_hostname="badc2.com",
            established=True,
            ja3="e7ed94cc5e470845a0b4b2941f15e32a"  # Cobalt Strike JA3
        )

        res = self.analyzer.analyze_tls_observation(obs)
        self.assertTrue(res.is_threat)
        self.assertEqual(res.severity, "CRITICAL")
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("JA3_MALWARE_SIGNATURE_MATCH", evidence_codes)

    def test_ja4_cobalt_strike_match(self):
        obs = TLSObservation(
            timestamp="2026-08-28T16:48:02Z",
            flow_id="C12347",
            client_ip="192.168.1.50",
            server_ip="198.51.100.99",
            tls_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            sni_hostname="badc2.com",
            established=True,
            ja4="t13d151600_8da5c1b52b28_0123456789ab"  # Cobalt Strike JA4
        )

        res = self.analyzer.analyze_tls_observation(obs)
        self.assertTrue(res.is_threat)
        self.assertEqual(res.severity, "CRITICAL")
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("JA4_MALWARE_SIGNATURE_MATCH", evidence_codes)

    def test_outdated_tls_and_weak_cipher(self):
        obs = TLSObservation(
            timestamp="2026-08-28T16:48:03Z",
            flow_id="C12348",
            client_ip="192.168.1.50",
            server_ip="198.51.100.100",
            tls_version="TLSv1.0",
            cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
            sni_hostname="legacy-server.com",
            established=True
        )

        res = self.analyzer.analyze_tls_observation(obs)
        self.assertTrue(res.is_threat)
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("OUTDATED_TLS_VERSION", evidence_codes)
        self.assertIn("WEAK_CIPHER_SUITE", evidence_codes)

    def test_missing_sni_hostname(self):
        obs = TLSObservation(
            timestamp="2026-08-28T16:48:04Z",
            flow_id="C12349",
            client_ip="192.168.1.50",
            server_ip="198.51.100.101",
            tls_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            sni_hostname="",
            established=True
        )

        res = self.analyzer.analyze_tls_observation(obs)
        evidence_codes = [e["code"] for e in res.evidence]
        self.assertIn("MISSING_SNI_HOSTNAME", evidence_codes)


if __name__ == "__main__":
    unittest.main()
