"""
PassiveShield AI — Async Telemetry Producer
Maps approved telemetry event contract objects to Redpanda streaming topics:
- NormalizedFlowEvent -> raw_conn
- DNSObservation      -> raw_dns
- TLSObservation      -> raw_ssl
"""

import inspect
import logging
import json
from typing import Optional, Dict, Any

try:
    from aiokafka import AIOKafkaProducer
    HAS_AIOKAFKA = True
except ImportError:
    HAS_AIOKAFKA = False
    AIOKafkaProducer = None

from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation,
    ContractValidationError
)

logger = logging.getLogger(__name__)

TOPIC_RAW_CONN = "raw_conn"
TOPIC_RAW_DNS = "raw_dns"
TOPIC_RAW_SSL = "raw_ssl"


class TelemetryProducerError(Exception):
    """Raised on unrecoverable producer transmission errors."""
    pass


class TelemetryProducer:
    """
    Asynchronous Kafka/Redpanda producer mapping telemetry event contracts
    to raw_conn, raw_dns, and raw_ssl topics.
    """

    def __init__(self, bootstrap_servers: str = "localhost:19092", client_id: str = "passiveshield-producer", producer_instance=None):
        self.bootstrap_servers = bootstrap_servers
        self.client_id = client_id
        self._producer = producer_instance
        self._started = False

    async def start(self):
        """Starts the underlying aiokafka producer connection."""
        if self._started:
            return

        if self._producer is None:
            if not HAS_AIOKAFKA:
                logger.warning("aiokafka package not found; running TelemetryProducer in mock/dry-run mode.")
                self._started = True
                return
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                client_id=self.client_id,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )

        if hasattr(self._producer, 'start'):
            if inspect.iscoroutinefunction(self._producer.start):
                await self._producer.start()
            else:
                self._producer.start()

        self._started = True

    async def stop(self):
        """Stops the underlying aiokafka producer connection."""
        if not self._started:
            return

        if self._producer and hasattr(self._producer, 'stop'):
            if inspect.iscoroutinefunction(self._producer.stop):
                await self._producer.stop()
            else:
                self._producer.stop()

        self._started = False

    async def send_flow_event(self, event: NormalizedFlowEvent) -> bool:
        """Publishes a NormalizedFlowEvent to the raw_conn topic."""
        if not isinstance(event, NormalizedFlowEvent):
            raise ContractValidationError(f"Expected NormalizedFlowEvent instance, got: {type(event)}")
        return await self._publish(TOPIC_RAW_CONN, key=event.flow_id, value=event.to_dict())

    async def send_dns_observation(self, obs: DNSObservation) -> bool:
        """Publishes a DNSObservation to the raw_dns topic."""
        if not isinstance(obs, DNSObservation):
            raise ContractValidationError(f"Expected DNSObservation instance, got: {type(obs)}")
        return await self._publish(TOPIC_RAW_DNS, key=obs.flow_id, value=obs.to_dict())

    async def send_tls_observation(self, obs: TLSObservation) -> bool:
        """Publishes a TLSObservation to the raw_ssl topic."""
        if not isinstance(obs, TLSObservation):
            raise ContractValidationError(f"Expected TLSObservation instance, got: {type(obs)}")
        return await self._publish(TOPIC_RAW_SSL, key=obs.flow_id, value=obs.to_dict())

    async def _publish(self, topic: str, key: str, value: Dict[str, Any]) -> bool:
        """Internal helper to publish messages to Redpanda topics with error handling."""
        if not self._started:
            raise TelemetryProducerError("TelemetryProducer is not started. Call start() before publishing.")

        try:
            if self._producer and hasattr(self._producer, 'send_and_wait'):
                key_bytes = key.encode('utf-8') if key else None
                if inspect.iscoroutinefunction(self._producer.send_and_wait):
                    await self._producer.send_and_wait(topic, value=value, key=key_bytes)
                else:
                    self._producer.send_and_wait(topic, value=value, key=key_bytes)
            return True
        except Exception as e:
            logger.error(f"Failed to publish message to topic '{topic}': {e}")
            raise TelemetryProducerError(f"Publish failed for topic '{topic}': {e}") from e
