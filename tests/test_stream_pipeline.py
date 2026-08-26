import os
import asyncio
import unittest
from unittest.mock import AsyncMock

from services.ingestion.telemetry_producer import TelemetryProducer, TOPIC_RAW_CONN, TOPIC_RAW_DNS, TOPIC_RAW_SSL
from services.ingestion.stream_pipeline import IngestionPipeline


class TestStreamPipelineIntegration(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.mock_kafka = AsyncMock()
        self.producer = TelemetryProducer(producer_instance=self.mock_kafka)
        await self.producer.start()
        self.pipeline = IngestionPipeline(self.producer)

    async def test_end_to_end_sample_fixtures(self):
        fixture_dir = "fixtures/sample_zeek_logs"
        if not os.path.exists(fixture_dir):
            self.skipTest("Sample Zeek log fixtures directory not found.")

        stats = await self.pipeline.run_pipeline(fixture_dir)

        # Verify event processing counts
        self.assertGreater(stats["conn_events"], 0, "conn.log events should be > 0")
        self.assertGreater(stats["dns_events"], 0, "dns.log events should be > 0")
        self.assertGreater(stats["ssl_events"], 0, "ssl.log events should be > 0")
        self.assertEqual(
            stats["total_events"],
            stats["conn_events"] + stats["dns_events"] + stats["ssl_events"]
        )

        # Verify mock Kafka producer received expected send_and_wait calls
        call_topics = [call.args[0] for call in self.mock_kafka.send_and_wait.call_args_list]
        self.assertIn(TOPIC_RAW_CONN, call_topics)
        self.assertIn(TOPIC_RAW_DNS, call_topics)
        self.assertIn(TOPIC_RAW_SSL, call_topics)

    async def test_nonexistent_directory_handling(self):
        stats = await self.pipeline.run_pipeline("nonexistent_log_dir")
        self.assertEqual(stats["total_events"], 0)


if __name__ == "__main__":
    unittest.main()
