import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation
)
from services.analytics.telemetry_consumer import (
    TelemetryConsumer,
    TelemetryConsumerError,
    DEFAULT_TOPICS
)


class MockKafkaMessage:
    def __init__(self, topic: str, value: dict):
        self.topic = topic
        self.value = value


class MockAsyncKafkaConsumer:
    def __init__(self, messages):
        self.messages = messages
        self.start = AsyncMock()
        self.stop = AsyncMock()

    def __aiter__(self):
        return self._generator()

    async def _generator(self):
        for msg in self.messages:
            yield msg


class TestTelemetryConsumer(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.mock_kafka = AsyncMock()
        self.consumer = TelemetryConsumer(consumer_instance=self.mock_kafka)

    async def test_start_and_stop_lifecycle(self):
        await self.consumer.start()
        self.assertTrue(self.consumer._started)
        self.mock_kafka.start.assert_awaited_once()

        await self.consumer.stop()
        self.assertFalse(self.consumer._started)
        self.mock_kafka.stop.assert_awaited_once()

    def test_parse_message_payload_flow(self):
        raw = {
            "event_type": "NormalizedFlowEvent",
            "version": "1.0",
            "timestamp": "2026-08-26T22:00:00Z",
            "flow_id": "C1001",
            "src_ip": "192.168.1.50",
            "src_port": 50000,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "tcp"
        }
        res = self.consumer.parse_message_payload("raw_conn", raw)
        self.assertIsInstance(res, NormalizedFlowEvent)
        self.assertEqual(res.src_ip, "192.168.1.50")

    def test_parse_message_payload_dns(self):
        raw = {
            "event_type": "DNSObservation",
            "version": "1.0",
            "timestamp": "2026-08-26T22:00:01Z",
            "flow_id": "C1002",
            "client_ip": "192.168.1.50",
            "query_domain": "example.com",
            "answers": ["93.184.216.34"]
        }
        res = self.consumer.parse_message_payload("raw_dns", raw)
        self.assertIsInstance(res, DNSObservation)
        self.assertEqual(res.query_domain, "example.com")

    def test_parse_message_payload_ssl(self):
        raw = {
            "event_type": "TLSObservation",
            "version": "1.0",
            "timestamp": "2026-08-26T22:00:02Z",
            "flow_id": "C1003",
            "client_ip": "192.168.1.51",
            "server_ip": "10.0.0.2",
            "tls_version": "TLSv13"
        }
        res = self.consumer.parse_message_payload("raw_ssl", raw)
        self.assertIsInstance(res, TLSObservation)
        self.assertEqual(res.server_ip, "10.0.0.2")

    def test_parse_malformed_payload(self):
        # Malformed invalid IP
        raw = {
            "event_type": "NormalizedFlowEvent",
            "timestamp": "2026-08-26T22:00:00Z",
            "flow_id": "C1001",
            "src_ip": "bad_ip",
            "src_port": 80,
            "dst_ip": "10.0.0.1",
            "dst_port": 80
        }
        res = self.consumer.parse_message_payload("raw_conn", raw)
        self.assertIsNone(res)

    async def test_consume_loop_with_mock_stream(self):
        msg1 = MockKafkaMessage("raw_conn", {
            "event_type": "NormalizedFlowEvent", "timestamp": "2026-08-26T22:00:00Z",
            "flow_id": "C1001", "src_ip": "192.168.1.50", "src_port": 50000,
            "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "tcp"
        })
        msg2 = MockKafkaMessage("raw_dns", {
            "event_type": "DNSObservation", "timestamp": "2026-08-26T22:00:01Z",
            "flow_id": "C1002", "client_ip": "192.168.1.50", "query_domain": "example.com"
        })

        mock_consumer = MockAsyncKafkaConsumer([msg1, msg2])
        consumer = TelemetryConsumer(consumer_instance=mock_consumer)
        await consumer.start()

        received_events = []

        async def handler(topic, contract_obj):
            received_events.append((topic, contract_obj))

        await consumer.consume_loop(handler, max_messages=2)

        self.assertEqual(len(received_events), 2)
        self.assertEqual(received_events[0][0], "raw_conn")
        self.assertIsInstance(received_events[0][1], NormalizedFlowEvent)
        self.assertEqual(received_events[1][0], "raw_dns")
        self.assertIsInstance(received_events[1][1], DNSObservation)

    async def test_consume_unstarted_error(self):
        with self.assertRaises(TelemetryConsumerError):
            await self.consumer.consume_loop(AsyncMock())


if __name__ == "__main__":
    unittest.main()
