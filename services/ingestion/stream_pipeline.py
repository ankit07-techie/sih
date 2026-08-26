"""
PassiveShield AI — Telemetry Stream Ingestion Pipeline
Integrates: Input (Zeek log files) -> ZeekAdapter -> Telemetry Contracts -> TelemetryProducer -> Redpanda Topics.
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional

from .zeek_adapter import ZeekAdapter
from .telemetry_producer import TelemetryProducer
from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation,
    ContractValidationError
)

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """
    Orchestrates line-by-line reading of Zeek JSON logs, adapter normalization,
    contract conversion, and streaming to Redpanda topics (raw_conn, raw_dns, raw_ssl).
    """

    def __init__(self, producer: TelemetryProducer):
        self.producer = producer

    async def process_conn_log(self, file_path: str) -> int:
        """Reads a conn.log file line by line and publishes NormalizedFlowEvents to raw_conn."""
        if not os.path.exists(file_path):
            logger.warning(f"conn.log file not found: {file_path}")
            return 0

        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                event_dict = ZeekAdapter.parse_conn_event(line)
                if event_dict:
                    try:
                        flow_event = NormalizedFlowEvent.from_dict(event_dict)
                        await self.producer.send_flow_event(flow_event)
                        count += 1
                    except ContractValidationError as e:
                        logger.warning(f"Flow event failed contract validation: {e}")
        return count

    async def process_dns_log(self, file_path: str) -> int:
        """Reads a dns.log file line by line and publishes DNSObservations to raw_dns."""
        if not os.path.exists(file_path):
            logger.warning(f"dns.log file not found: {file_path}")
            return 0

        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                event_dict = ZeekAdapter.parse_dns_event(line)
                if event_dict:
                    try:
                        dns_obs = DNSObservation.from_dict(event_dict)
                        await self.producer.send_dns_observation(dns_obs)
                        count += 1
                    except ContractValidationError as e:
                        logger.warning(f"DNS observation failed contract validation: {e}")
        return count

    async def process_ssl_log(self, file_path: str) -> int:
        """Reads a ssl.log file line by line and publishes TLSObservations to raw_ssl."""
        if not os.path.exists(file_path):
            logger.warning(f"ssl.log file not found: {file_path}")
            return 0

        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                event_dict = ZeekAdapter.parse_ssl_event(line)
                if event_dict:
                    try:
                        tls_obs = TLSObservation.from_dict(event_dict)
                        await self.producer.send_tls_observation(tls_obs)
                        count += 1
                    except ContractValidationError as e:
                        logger.warning(f"TLS observation failed contract validation: {e}")
        return count

    async def run_pipeline(self, log_dir: str) -> Dict[str, int]:
        """Runs end-to-end ingestion processing across conn.log, dns.log, and ssl.log in a directory."""
        conn_path = os.path.join(log_dir, "conn.log")
        dns_path = os.path.join(log_dir, "dns.log")
        ssl_path = os.path.join(log_dir, "ssl.log")

        conn_count = await self.process_conn_log(conn_path)
        dns_count = await self.process_dns_log(dns_path)
        ssl_count = await self.process_ssl_log(ssl_path)

        return {
            "conn_events": conn_count,
            "dns_events": dns_count,
            "ssl_events": ssl_count,
            "total_events": conn_count + dns_count + ssl_count
        }
