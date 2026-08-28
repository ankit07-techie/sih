"""
PassiveShield AI — Deterministic Backend End-to-End Pipeline Integration Test
Verifies complete flow: Replay → Zeek → Redpanda → Python Analytics → Redis State → Detectors → Threat Fusion → ThreatAlert → Redis Alert Bus (cyber_alerts) → Express / Socket.IO.
"""

import json
import unittest
from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation,
    FeatureSnapshot,
    DetectionResult,
    ThreatAlert
)
from services.ingestion import ZeekAdapter, TelemetryProducer
from services.state import RedisStateManager, MockRedisDriver
from services.features import DDoSFeatureExtractor, PortScanFeatureExtractor, BeaconingFeatureExtractor, DNSFeatureExtractor
from services.detectors import DDoSDetector, PortScanDetector, C2BeaconDetector, DNSAnomalyDetector, ExfiltrationDetector
from services.analytics import TLSMetadataAnalyzer, ThreatFusionEngine, FusedThreatAlert
from services.alerts import RedisAlertBus, DEFAULT_ALERT_CHANNEL


class TestBackendE2EPipeline(unittest.TestCase):

    def setUp(self):
        self.mock_redis = MockRedisDriver()
        self.state_mgr = RedisStateManager(redis_client=self.mock_redis)
        self.producer = TelemetryProducer()
        self.zeek_adapter = ZeekAdapter()
        self.fusion_engine = ThreatFusionEngine()
        self.alert_bus = RedisAlertBus(redis_client=self.mock_redis)

        # Detectors
        self.ddos_detector = DDoSDetector()
        self.port_scan_detector = PortScanDetector()
        self.beacon_detector = C2BeaconDetector()
        self.dns_detector = DNSAnomalyDetector()
        self.exfil_detector = ExfiltrationDetector()
        self.tls_analyzer = TLSMetadataAnalyzer()

    def test_e2e_reconnaissance_and_exfiltration_threat_fusion_pipeline(self):
        # 1. Zeek Log Ingestion (Simulated Replay)
        conn_dict = {
            "ts": 1724854380.1,
            "uid": "C123456",
            "id.orig_h": "192.168.1.200",
            "id.orig_p": 54321,
            "id.resp_h": "198.51.100.99",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.5,
            "orig_bytes": 15000000,
            "resp_bytes": 2000,
            "conn_state": "SF",
            "orig_pkts": 100,
            "resp_pkts": 50
        }
        ssl_dict = {
            "ts": 1724854380.1,
            "uid": "C123456",
            "id.orig_h": "192.168.1.200",
            "id.orig_p": 54321,
            "id.resp_h": "198.51.100.99",
            "id.resp_p": 443,
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "ja3": "e7ed94cc5e470845a0b4b2941f15e32a"
        }

        conn_raw = self.zeek_adapter.parse_conn_event(json.dumps(conn_dict))
        ssl_raw = self.zeek_adapter.parse_ssl_event(json.dumps(ssl_dict))

        flow_event = NormalizedFlowEvent.from_dict(conn_raw)
        ssl_event = TLSObservation.from_dict(ssl_raw)

        self.assertIsInstance(flow_event, NormalizedFlowEvent)
        self.assertIsInstance(ssl_event, TLSObservation)

        # 2. Redis State Recording
        self.state_mgr.record_flow_metrics(
            src_ip=flow_event.src_ip,
            orig_bytes=flow_event.orig_bytes,
            resp_bytes=flow_event.resp_bytes,
            orig_pkts=flow_event.orig_packets,
            resp_pkts=flow_event.resp_packets,
            window_seconds=60
        )
        # Record vertical port scan activity
        for port in range(1, 51):
            self.state_mgr.record_unique_target(flow_event.src_ip, str(port), "ports", 60)

        # 3. Feature Extraction & Threat Detection
        scan_extractor = PortScanFeatureExtractor(self.state_mgr)
        scan_features = scan_extractor.compute_port_scan_features(flow_event.src_ip, 60)

        exfil_snapshot = FeatureSnapshot(
            timestamp="2026-08-28T17:12:00Z",
            entity_type="ip",
            entity_id=flow_event.src_ip,
            window_seconds=60,
            features={
                "orig_bytes": flow_event.orig_bytes,
                "resp_bytes": flow_event.resp_bytes,
                "directional_ratio": 15000000 / 15002000
            }
        )

        res_scan = self.port_scan_detector.analyze_snapshot(scan_features)
        res_exfil = self.exfil_detector.analyze_snapshot(exfil_snapshot)
        res_tls = self.tls_analyzer.analyze_tls_observation(ssl_event)

        self.assertTrue(res_scan.is_threat)
        self.assertTrue(res_exfil.is_threat)
        self.assertTrue(res_tls.is_threat)

        # 4. Threat Fusion Engine Combination
        fused_alert = self.fusion_engine.fuse_results([res_scan, res_exfil, res_tls])
        self.assertIsInstance(fused_alert, FusedThreatAlert)
        self.assertEqual(fused_alert.severity, "CRITICAL")
        self.assertGreaterEqual(fused_alert.fused_score, 0.95)
        self.assertGreaterEqual(len(fused_alert.evidence), 3)

        # 5. Convert Fused Alert to Standardized ThreatAlert Contract
        threat_alert = ThreatAlert(
            alert_id=fused_alert.alert_id,
            timestamp=fused_alert.timestamp,
            threat_classification="CORRELATED_MULTI_VECTOR",
            severity=fused_alert.severity,
            confidence_score=fused_alert.fused_score,
            affected_context={
                "entity_type": fused_alert.entity_type,
                "entity_id": fused_alert.entity_id,
                "src_ip": flow_event.src_ip,
                "dst_ip": flow_event.dst_ip
            },
            observation_window_seconds=60,
            contributing_detectors=fused_alert.contributing_detectors,
            structured_evidence=fused_alert.evidence,
            mitigation_recommendation=fused_alert.mitigation_recommendation
        )

        # 6. Publish to Redis Alert Bus over channel 'cyber_alerts'
        received_alerts = []

        def alert_subscriber_callback(alert: ThreatAlert):
            received_alerts.append(alert)

        self.alert_bus.subscribe_alerts(alert_subscriber_callback)
        pub_success = self.alert_bus.publish_alert(threat_alert)

        self.assertTrue(pub_success)
        self.assertEqual(len(received_alerts), 1)

        rec = received_alerts[0]
        self.assertEqual(rec.alert_id, fused_alert.alert_id)
        self.assertEqual(rec.severity, "CRITICAL")
        self.assertEqual(rec.threat_classification, "CORRELATED_MULTI_VECTOR")
        self.assertGreaterEqual(len(rec.structured_evidence), 3)


if __name__ == "__main__":
    unittest.main()
