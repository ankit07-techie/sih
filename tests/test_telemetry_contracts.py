import os
import json
import unittest
from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation,
    ContractValidationError
)

class TestTelemetryContracts(unittest.TestCase):

    def test_flow_event_valid(self):
        event = NormalizedFlowEvent(
            timestamp="2026-08-26T21:49:00Z",
            flow_id="C1001",
            src_ip="192.168.1.10",
            src_port=50000,
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="tcp",
            duration=1.25,
            orig_bytes=100,
            resp_bytes=500
        )
        self.assertEqual(event.event_type, "NormalizedFlowEvent")
        self.assertEqual(event.version, "1.0")
        
        # Test serialization
        d = event.to_dict()
        self.assertEqual(d["src_ip"], "192.168.1.10")
        
        json_str = event.to_json()
        restored = NormalizedFlowEvent.from_json(json_str)
        self.assertEqual(restored, event)

    def test_flow_event_invalid_ip(self):
        with self.assertRaises(ContractValidationError):
            NormalizedFlowEvent(
                timestamp="2026-08-26T21:49:00Z",
                flow_id="C1001",
                src_ip="999.999.999.999", # Invalid IP
                src_port=80,
                dst_ip="10.0.0.1",
                dst_port=80,
                protocol="tcp"
            )

    def test_flow_event_invalid_port(self):
        with self.assertRaises(ContractValidationError):
            NormalizedFlowEvent(
                timestamp="2026-08-26T21:49:00Z",
                flow_id="C1001",
                src_ip="192.168.1.1",
                src_port=70000, # Invalid port > 65535
                dst_ip="10.0.0.1",
                dst_port=80,
                protocol="tcp"
            )

    def test_dns_observation_valid(self):
        dns = DNSObservation(
            timestamp="2026-08-26T21:49:01Z",
            flow_id="C1002",
            client_ip="192.168.1.20",
            query_domain="malicious.dga.net",
            answers=["1.1.1.1", "1.0.0.1"]
        )
        self.assertEqual(dns.event_type, "DNSObservation")
        self.assertEqual(dns.query_domain, "malicious.dga.net")
        
        json_str = dns.to_json()
        restored = DNSObservation.from_json(json_str)
        self.assertEqual(restored, dns)

    def test_dns_observation_missing_domain(self):
        with self.assertRaises(ContractValidationError):
            DNSObservation(
                timestamp="2026-08-26T21:49:01Z",
                flow_id="C1002",
                client_ip="192.168.1.20",
                query_domain="" # Empty domain forbidden
            )

    def test_tls_observation_valid(self):
        tls = TLSObservation(
            timestamp="2026-08-26T21:49:02Z",
            flow_id="C1003",
            client_ip="192.168.1.30",
            server_ip="10.0.0.5",
            tls_version="TLSv13",
            sni_hostname="api.example.com",
            established=True
        )
        self.assertEqual(tls.event_type, "TLSObservation")
        self.assertTrue(tls.established)

        json_str = tls.to_json()
        restored = TLSObservation.from_json(json_str)
        self.assertEqual(restored, tls)

    def test_fixtures(self):
        flow_fixture = "fixtures/contracts/normalized_flow_event.json"
        if os.path.exists(flow_fixture):
            with open(flow_fixture, "r") as f:
                event = NormalizedFlowEvent.from_json(f.read())
                self.assertEqual(event.event_type, "NormalizedFlowEvent")

        dns_fixture = "fixtures/contracts/dns_observation.json"
        if os.path.exists(dns_fixture):
            with open(dns_fixture, "r") as f:
                dns = DNSObservation.from_json(f.read())
                self.assertEqual(dns.event_type, "DNSObservation")

        tls_fixture = "fixtures/contracts/tls_observation.json"
        if os.path.exists(tls_fixture):
            with open(tls_fixture, "r") as f:
                tls = TLSObservation.from_json(f.read())
                self.assertEqual(tls.event_type, "TLSObservation")

if __name__ == "__main__":
    unittest.main()
