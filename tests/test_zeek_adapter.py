import os
import unittest
from services.ingestion.zeek_adapter import ZeekAdapter

class TestZeekAdapter(unittest.TestCase):

    def test_parse_conn_valid(self):
        line = '{"ts":"2026-08-26T00:00:01.000Z","uid":"C12345678901","id.orig_h":"192.168.1.50","id.orig_p":49152,"id.resp_h":"10.0.0.1","id.resp_p":80,"proto":"tcp","service":"http","duration":0.125,"orig_bytes":512,"resp_bytes":2048,"conn_state":"SF","orig_pkts":5,"resp_pkts":6}'
        event = ZeekAdapter.parse_conn_event(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "NormalizedFlowEvent")
        self.assertEqual(event["src_ip"], "192.168.1.50")
        self.assertEqual(event["dst_ip"], "10.0.0.1")
        self.assertEqual(event["src_port"], 49152)
        self.assertEqual(event["dst_port"], 80)
        self.assertEqual(event["protocol"], "tcp")
        self.assertEqual(event["orig_bytes"], 512)
        self.assertEqual(event["resp_bytes"], 2048)

    def test_parse_conn_malformed(self):
        # Missing required id.orig_h field
        line = '{"ts":"2026-08-26T00:00:01.000Z","uid":"C12345678901"}'
        self.assertIsNone(ZeekAdapter.parse_conn_event(line))

        # Invalid JSON
        self.assertIsNone(ZeekAdapter.parse_conn_event("not a json string"))
        self.assertIsNone(ZeekAdapter.parse_conn_event(""))

    def test_parse_dns_valid(self):
        line = '{"ts":"2026-08-26T00:00:01.100Z","uid":"C12345678904","id.orig_h":"192.168.1.50","id.orig_p":53535,"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp","trans_id":1001,"query":"example.com","qclass":1,"qclass_name":"C_INTERNET","qtype":1,"qtype_name":"A","rcode":0,"rcode_name":"NOERROR","answers":["93.184.216.34"]}'
        event = ZeekAdapter.parse_dns_event(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "DNSObservation")
        self.assertEqual(event["client_ip"], "192.168.1.50")
        self.assertEqual(event["query_domain"], "example.com")
        self.assertEqual(event["query_type"], "A")
        self.assertEqual(event["response_code"], "NOERROR")
        self.assertEqual(event["answers"], ["93.184.216.34"])

    def test_parse_dns_malformed(self):
        # Missing query field
        line = '{"ts":"2026-08-26T00:00:01.100Z","uid":"C12345678904","id.orig_h":"192.168.1.50"}'
        self.assertIsNone(ZeekAdapter.parse_dns_event(line))

    def test_parse_ssl_valid(self):
        line = '{"ts":"2026-08-26T00:00:02.100Z","uid":"C12345678902","id.orig_h":"192.168.1.51","id.orig_p":51234,"id.resp_h":"10.0.0.2","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","server_name":"secure.example.com","established":true}'
        event = ZeekAdapter.parse_ssl_event(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "TLSObservation")
        self.assertEqual(event["client_ip"], "192.168.1.51")
        self.assertEqual(event["server_ip"], "10.0.0.2")
        self.assertEqual(event["tls_version"], "TLSv13")
        self.assertEqual(event["sni_hostname"], "secure.example.com")
        self.assertTrue(event["established"])

    def test_parse_fixtures(self):
        conn_fixture = "fixtures/sample_zeek_logs/conn.log"
        if os.path.exists(conn_fixture):
            with open(conn_fixture, "r") as f:
                for line in f:
                    event = ZeekAdapter.parse_conn_event(line)
                    self.assertIsNotNone(event)
                    self.assertEqual(event["event_type"], "NormalizedFlowEvent")

if __name__ == "__main__":
    unittest.main()
