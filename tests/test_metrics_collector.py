import unittest
import time
from services.analytics.metrics_collector import MetricsCollector, PerformanceMetricsSummary


class TestMetricsCollector(unittest.TestCase):

    def setUp(self):
        self.collector = MetricsCollector()

    def test_record_events_and_latencies(self):
        latencies = [1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 15.0, 20.0, 25.0, 100.0]
        for lat in latencies:
            self.collector.record_event_processed(payload_bytes=1000, latency_ms=lat)

        self.collector.record_event_failed()
        self.collector.record_alert_generated()
        self.collector.record_alert_published()

        summary = self.collector.get_summary()

        self.assertEqual(summary.events_processed, 10)
        self.assertEqual(summary.events_failed, 1)
        self.assertEqual(summary.alerts_generated, 1)
        self.assertEqual(summary.alerts_published, 1)

        self.assertGreater(summary.events_per_second, 0.0)
        self.assertGreater(summary.throughput_bytes_per_sec, 0.0)

        # Percentile checks
        self.assertEqual(summary.latency_p50_ms, 5.0)
        self.assertGreaterEqual(summary.latency_p95_ms, 25.0)
        self.assertEqual(summary.latency_p99_ms, 100.0)

    def test_reset_collector(self):
        self.collector.record_event_processed(payload_bytes=500, latency_ms=5.0)
        self.collector.reset()

        summary = self.collector.get_summary()
        self.assertEqual(summary.events_processed, 0)
        self.assertEqual(summary.latency_p50_ms, 0.0)


if __name__ == "__main__":
    unittest.main()
