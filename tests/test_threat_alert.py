import os
import json
import unittest
from shared.contracts import ThreatAlert, ContractValidationError


class TestThreatAlertContract(unittest.TestCase):

    def test_valid_threat_alert_instantiation(self):
        alert = ThreatAlert(
            alert_id="test-alert-123",
            timestamp="2026-08-28T16:55:00Z",
            threat_classification="DDOS_ATTACK",
            severity="HIGH",
            confidence_score=0.92,
            affected_context={"entity_type": "ip", "entity_id": "192.168.1.100"},
            observation_window_seconds=60,
            contributing_detectors=["DDoSDetector"],
            structured_evidence=[{"code": "SYN_FLOOD", "message": "High SYN packet rate"}],
            mitigation_recommendation="APPLY_PASSIVE_SHIELD_FILTERS"
        )

        self.assertEqual(alert.alert_id, "test-alert-123")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.confidence_score, 0.92)

    def test_json_roundtrip_serialization(self):
        alert = ThreatAlert(
            alert_id="test-alert-456",
            timestamp="2026-08-28T16:55:01Z",
            threat_classification="PORT_SCAN",
            severity="CRITICAL",
            confidence_score=0.96,
            affected_context={"entity_type": "ip", "entity_id": "192.168.1.200"},
            observation_window_seconds=120,
            contributing_detectors=["PortScanDetector"],
            structured_evidence=[]
        )

        json_str = alert.to_json()
        parsed = ThreatAlert.from_json(json_str)

        self.assertEqual(parsed.alert_id, alert.alert_id)
        self.assertEqual(parsed.severity, alert.severity)
        self.assertEqual(parsed.confidence_score, alert.confidence_score)

    def test_contract_validation_errors(self):
        # Empty alert_id
        with self.assertRaises(ContractValidationError):
            ThreatAlert(
                alert_id="",
                timestamp="2026-08-28T16:55:00Z",
                threat_classification="DDOS_ATTACK",
                severity="HIGH",
                confidence_score=0.8,
                affected_context={},
                observation_window_seconds=60,
                contributing_detectors=[]
            )

        # Invalid severity
        with self.assertRaises(ContractValidationError):
            ThreatAlert(
                alert_id="valid-id",
                timestamp="2026-08-28T16:55:00Z",
                threat_classification="DDOS_ATTACK",
                severity="EXTREME",  # Invalid
                confidence_score=0.8,
                affected_context={},
                observation_window_seconds=60,
                contributing_detectors=[]
            )

        # Out-of-bounds confidence score
        with self.assertRaises(ContractValidationError):
            ThreatAlert(
                alert_id="valid-id",
                timestamp="2026-08-28T16:55:00Z",
                threat_classification="DDOS_ATTACK",
                severity="HIGH",
                confidence_score=1.5,  # Out of range
                affected_context={},
                observation_window_seconds=60,
                contributing_detectors=[]
            )

    def test_fixture_file_parsing(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "contracts", "threat_alert.json")
        if os.path.exists(fixture_path):
            with open(fixture_path, "r", encoding="utf-8") as f:
                json_str = f.read()
            alert = ThreatAlert.from_json(json_str)
            self.assertEqual(alert.threat_classification, "CORRELATED_MULTI_VECTOR")
            self.assertEqual(alert.severity, "CRITICAL")
            self.assertEqual(len(alert.contributing_detectors), 3)


if __name__ == "__main__":
    unittest.main()
