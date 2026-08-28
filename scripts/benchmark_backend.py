"""
PassiveShield AI — Backend Observability Benchmark Measurement Script
Measures event processing rate (events/sec), throughput (bytes/sec), latency percentiles (p50, p95, p99), error rate, and RSS memory usage across 10,000 synthetic flow events.
"""

import time
import json
import random
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.contracts import NormalizedFlowEvent, FeatureSnapshot
from services.state import RedisStateManager, MockRedisDriver
from services.features import DDoSFeatureExtractor, PortScanFeatureExtractor
from services.detectors import DDoSDetector, PortScanDetector
from services.analytics import ThreatFusionEngine, MetricsCollector


def run_benchmark(num_events: int = 10000):
    print(f"===========================================================")
    print(f"PassiveShield AI — Backend Performance Benchmark")
    print(f"Target Events: {num_events:,}")
    print(f"===========================================================")

    mock_redis = MockRedisDriver()
    state_mgr = RedisStateManager(redis_client=mock_redis)
    ddos_detector = DDoSDetector()
    port_scan_detector = PortScanDetector()
    fusion_engine = ThreatFusionEngine()
    collector = MetricsCollector()

    start_bench = time.time()

    for i in range(1, num_events + 1):
        t0 = time.perf_counter()

        src_ip = f"192.168.1.{random.randint(1, 250)}"
        dst_port = random.randint(1, 1024)
        bytes_count = random.randint(500, 5000)

        # 1. State update
        state_mgr.record_flow_metrics(src_ip, orig_bytes=bytes_count, orig_pkts=5, window_seconds=60)
        state_mgr.record_unique_target(src_ip, str(dst_port), "ports", 60)

        # 2. Feature Extraction
        features = FeatureSnapshot(
            timestamp="2026-08-28T17:14:00Z",
            entity_type="ip",
            entity_id=src_ip,
            window_seconds=60,
            features={"orig_bytes": bytes_count, "unique_dst_ports": dst_port % 10}
        )

        # 3. Detection
        res1 = ddos_detector.analyze_snapshot(features)
        res2 = port_scan_detector.analyze_snapshot(features)

        # 4. Fusion
        fused = fusion_engine.fuse_results([res1, res2])
        if fused and fused.is_threat:
            collector.record_alert_generated()
            collector.record_alert_published()

        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0
        collector.record_event_processed(payload_bytes=bytes_count, latency_ms=latency_ms)

    summary = collector.get_summary()

    print("\n--- MEASURED BENCHMARK RESULTS ---")
    print(f"Processed Events    : {summary.events_processed:,}")
    print(f"Failed Events       : {summary.events_failed}")
    print(f"Generated Alerts    : {summary.alerts_generated:,}")
    print(f"Total Duration      : {summary.duration_seconds} sec")
    print(f"Processing Rate     : {summary.events_per_second:,.2f} events/sec")
    print(f"Throughput          : {summary.throughput_bytes_per_sec / (1024*1024):,.2f} MB/sec ({summary.throughput_bytes_per_sec:,.2f} B/s)")
    print(f"Latency p50 (Median): {summary.latency_p50_ms:.3f} ms")
    print(f"Latency p95         : {summary.latency_p95_ms:.3f} ms")
    print(f"Latency p99         : {summary.latency_p99_ms:.3f} ms")
    print(f"Error Rate          : {summary.error_rate_percent}%")
    print(f"Memory RSS Footprint: {summary.memory_usage_mb} MB")
    print(f"===========================================================\n")

    return summary


if __name__ == "__main__":
    run_benchmark(10000)
