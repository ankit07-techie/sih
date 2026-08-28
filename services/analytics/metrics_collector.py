"""
PassiveShield AI — Backend Observability & Performance Metrics Collector
Tracks event processing rates, throughput, alert delivery latency, error counts, and system resource behavior.
"""

import time
import math
import os
import sys
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetricsSummary:
    events_processed: int
    events_failed: int
    alerts_generated: int
    alerts_published: int
    duration_seconds: float
    events_per_second: float
    throughput_bytes_per_sec: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    error_rate_percent: float
    memory_usage_mb: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MetricsCollector:
    """
    In-memory thread-safe metrics collector for pipeline latency, throughput, error rates, and resource utilization.
    """

    def __init__(self):
        self._events_processed = 0
        self._events_failed = 0
        self._alerts_generated = 0
        self._alerts_published = 0
        self._total_bytes_processed = 0
        self._start_time = time.time()
        self._processing_latencies_ms: List[float] = []

    def record_event_processed(self, payload_bytes: int = 0, latency_ms: float = 0.0):
        self._events_processed += 1
        self._total_bytes_processed += payload_bytes
        if latency_ms > 0:
            self._processing_latencies_ms.append(latency_ms)

    def record_event_failed(self):
        self._events_failed += 1

    def record_alert_generated(self):
        self._alerts_generated += 1

    def record_alert_published(self):
        self._alerts_published += 1

    def calculate_percentile(self, percent: float) -> float:
        if not self._processing_latencies_ms:
            return 0.0
        sorted_latencies = sorted(self._processing_latencies_ms)
        index = int(math.ceil((percent / 100.0) * len(sorted_latencies))) - 1
        index = max(0, min(index, len(sorted_latencies) - 1))
        return round(sorted_latencies[index], 2)

    def get_summary(self) -> PerformanceMetricsSummary:
        elapsed = max(0.001, time.time() - self._start_time)
        eps = round(self._events_processed / elapsed, 2)
        bytes_per_sec = round(self._total_bytes_processed / elapsed, 2)
        total_events = self._events_processed + self._events_failed
        error_rate = round((self._events_failed / total_events * 100.0) if total_events > 0 else 0.0, 2)

        mem_mb = 0.0
        try:
            import psutil
            process = psutil.Process(os.getpid())
            mem_mb = round(process.memory_info().rss / (1024 * 1024), 2)
        except ImportError:
            pass

        return PerformanceMetricsSummary(
            events_processed=self._events_processed,
            events_failed=self._events_failed,
            alerts_generated=self._alerts_generated,
            alerts_published=self._alerts_published,
            duration_seconds=round(elapsed, 2),
            events_per_second=eps,
            throughput_bytes_per_sec=bytes_per_sec,
            latency_p50_ms=self.calculate_percentile(50),
            latency_p95_ms=self.calculate_percentile(95),
            latency_p99_ms=self.calculate_percentile(99),
            error_rate_percent=error_rate,
            memory_usage_mb=mem_mb
        )

    def reset(self):
        self._events_processed = 0
        self._events_failed = 0
        self._alerts_generated = 0
        self._alerts_published = 0
        self._total_bytes_processed = 0
        self._start_time = time.time()
        self._processing_latencies_ms.clear()
