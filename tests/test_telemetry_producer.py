import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation,
    ContractValidationError
)
from services.ingestion.telemetry_producer import (
    TelemetryProducer,
    TelemetryProducerError,
    TOPIC_RAW_CONN,
    TOPIC_RAW_DNS,
    TOPIC_RAW_SSL
)


class TestTelemetryProducer(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.mock_aiokafka = AsyncMock()
        self.producer = TelemetryProducer(producer_instance=self.mock_aiokafka)

    async def test_start_and_stop(self):
        await self.producer.start()
        self.assertTrue(self.producer._started)
        self.mock_aiokafka.start.assert_awaited_once()

        await self.producer.stop()
        self.assertFalse(self.producer._started)
        self.mock_aiokafka.stop.assert_awaited_once()

    async def test_send_flow_event_to_raw_conn(self):
        await self.producer.start()
        flow = NormalizedFlowEvent(
            timestamp="2026-08-26T21:56:00Z",
            flow_id="C1001",
            src_ip="192.168.1.50",
            src_port=50000,
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="tcp"
        )
        res = await self.producer.send_flow_event(flow)
        self.assertTrue(res)
        self.mock_aiokafka.send_and_wait.assert_awaited_once_with(
            TOPIC_RAW_CONN,
            value=flow.to_dict(),
            key=b"C1001"
        )

    async def test_send_dns_observation_to_raw_dns(self):
        await self.producer.start()
        dns = DNSObservation(
            timestamp="2026-08-26T21:56:01Z",
            flow_id="C1002",
            client_ip="192.168.1.50",
            query_domain="example.com",
            answers=["93.184.216.34"]
        )
        res = await self.producer.send_dns_observation(dns)
        self.assertTrue(res)
        self.mock_aiokafka.send_and_wait.assert_awaited_once_with(
            TOPIC_RAW_DNS,
            value=dns.to_dict(),
            key=b"C1002"
        )

    async def test_send_tls_observation_to_raw_ssl(self):
        await self.producer.start()
        tls = TLSObservation(
            timestamp="2026-08-26T21:56:02Z",
            flow_id="C1003",
            client_ip="192.168.1.51",
            server_ip="10.0.0.2",
            tls_version="TLSv13",
            established=True
        )
        res = await self.producer.send_tls_observation(tls)
        self.assertTrue(res)
        self.mock_aiokafka.send_and_wait.assert_awaited_once_with(
            TOPIC_RAW_SSL,
            value=tls.to_dict(),
            key=b"C1003"
        )

    async def test_publish_unstarted_error(self):
        flow = NormalizedFlowEvent(
            timestamp="2026-08-26T21:56:00Z",
            flow_id="C1001",
            src_ip="192.168.1.50",
            src_port=50000,
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="tcp"
        )
        with self.assertRaises(TelemetryProducerError):
            await self.producer.send_flow_event(flow)

    async def test_invalid_event_type_error(self):
        await self.producer.start()
        with self.assertRaises(ContractValidationError):
            await self.producer.send_flow_event("not a NormalizedFlowEvent")

    async def test_producer_failure_handling(self):
        self.mock_aiokafka.send_and_wait.side_effect = Exception("Kafka Broker Down")
        await self.producer.start()

        flow = NormalizedFlowEvent(
            timestamp="2026-08-26T21:56:00Z",
            flow_id="C1001",
            src_ip="192.168.1.50",
            src_port=50000,
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol="tcp"
        )
        with self.assertRaises(TelemetryProducerError):
            await self.producer.send_flow_event(flow)


if __name__ == "__main__":
    unittest.main()
