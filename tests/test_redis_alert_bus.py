import unittest
from shared.contracts import ThreatAlert, ContractValidationError
from services.state import MockRedisDriver
from services.alerts.redis_alert_bus import RedisAlertBus, DEFAULT_ALERT_CHANNEL


class TestRedisAlertBus(unittest.TestCase):

    def setUp(self):
        self.mock_driver = MockRedisDriver()
        self.alert_bus = RedisAlertBus(redis_client=self.mock_driver)

    def test_publish_and_subscribe_alert(self):
        received_alerts = []

        def handle_alert(alert: ThreatAlert):
            received_alerts.append(alert)

        # Subscribe handler
        self.alert_bus.subscribe_alerts(handle_alert)

        alert = ThreatAlert(
            alert_id="alert-uuid-999",
            timestamp="2026-08-28T16:58:00Z",
            threat_classification="DDOS_ATTACK",
            severity="HIGH",
            confidence_score=0.95,
            affected_context={"entity_type": "ip", "entity_id": "192.168.1.50"},
            observation_window_seconds=60,
            contributing_detectors=["DDoSDetector"],
            structured_evidence=[{"code": "SYN_FLOOD", "message": "High SYN rate"}]
        )

        success = self.alert_bus.publish_alert(alert)
        self.assertTrue(success)

        self.assertEqual(len(received_alerts), 1)
        rec = received_alerts[0]
        self.assertEqual(rec.alert_id, "alert-uuid-999")
        self.assertEqual(rec.threat_classification, "DDOS_ATTACK")
        self.assertEqual(rec.severity, "HIGH")

    def test_invalid_alert_type_raises(self):
        with self.assertRaises(ContractValidationError):
            self.alert_bus.publish_alert("not-an-alert-object")

    def test_default_channel_name(self):
        self.assertEqual(self.alert_bus.channel, DEFAULT_ALERT_CHANNEL)
        self.assertEqual(DEFAULT_ALERT_CHANNEL, "cyber_alerts")


if __name__ == "__main__":
    unittest.main()
