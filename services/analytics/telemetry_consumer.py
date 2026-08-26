"""
PassiveShield AI — Async Telemetry Stream Consumer Foundation
Consumes telemetry events from Redpanda topics (raw_conn, raw_dns, raw_ssl),
deserializes them into versioned dataclass contracts, and dispatches them to handler callbacks.
"""

import inspect
import logging
import json
import asyncio
from typing import Optional, List, Callable, Awaitable, Dict, Any, Union

try:
    from aiokafka import AIOKafkaConsumer
    HAS_AIOKAFKA = True
except ImportError:
    HAS_AIOKAFKA = False
    AIOKafkaConsumer = None

from shared.contracts import (
    NormalizedFlowEvent,
    DNSObservation,
    TLSObservation,
    ContractValidationError
)

logger = logging.getLogger(__name__)

DEFAULT_TOPICS = ["raw_conn", "raw_dns", "raw_ssl"]


class TelemetryConsumerError(Exception):
    """Raised on unrecoverable stream consumer errors."""
    pass


class TelemetryConsumer:
    """
    Async Kafka/Redpanda consumer foundation for telemetry streams.
    Provides start/stop lifecycle management, topic subscription, message deserialization,
    and callback handler dispatching.
    """

    def __init__(
        self,
        topics: Optional[List[str]] = None,
        bootstrap_servers: str = "localhost:19092",
        group_id: str = "passiveshield-analytics-group",
        consumer_instance=None
    ):
        self.topics = topics or DEFAULT_TOPICS
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self._consumer = consumer_instance
        self._started = False
        self._running = False

    async def start(self):
        """Starts the underlying aiokafka consumer connection."""
        if self._started:
            return

        if self._consumer is None:
            if not HAS_AIOKAFKA:
                logger.warning("aiokafka package not found; running TelemetryConsumer in mock mode.")
                self._started = True
                return
            self._consumer = AIOKafkaConsumer(
                *self.topics,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                auto_offset_reset="earliest",
                value_deserializer=lambda m: json.loads(m.decode('utf-8'))
            )

        if hasattr(self._consumer, 'start'):
            if inspect.iscoroutinefunction(self._consumer.start):
                await self._consumer.start()
            else:
                self._consumer.start()

        self._started = True

    async def stop(self):
        """Stops the underlying aiokafka consumer connection."""
        self._running = False
        if not self._started:
            return

        if self._consumer and hasattr(self._consumer, 'stop'):
            if inspect.iscoroutinefunction(self._consumer.stop):
                await self._consumer.stop()
            else:
                self._consumer.stop()

        self._started = False

    def parse_message_payload(self, topic: str, raw_payload: Dict[str, Any]) -> Optional[Union[NormalizedFlowEvent, DNSObservation, TLSObservation]]:
        """
        Parses raw dict payload into a versioned contract object based on topic or event_type.
        Returns None if parsing or validation fails.
        """
        if not isinstance(raw_payload, dict):
            return None

        event_type = raw_payload.get("event_type")

        try:
            if topic in ("raw_conn", "raw-flow-events") or event_type == "NormalizedFlowEvent":
                return NormalizedFlowEvent.from_dict(raw_payload)
            elif topic in ("raw_dns", "dns-observations") or event_type == "DNSObservation":
                return DNSObservation.from_dict(raw_payload)
            elif topic in ("raw_ssl", "tls-observations") or event_type == "TLSObservation":
                return TLSObservation.from_dict(raw_payload)
            else:
                logger.warning(f"Unknown topic/event_type format: topic={topic}, event_type={event_type}")
                return None
        except ContractValidationError as e:
            logger.warning(f"Contract validation failed for message from topic '{topic}': {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected parsing error for message from topic '{topic}': {e}")
            return None

    async def consume_loop(self, handler_callback: Callable[[str, Any], Awaitable[None]], max_messages: Optional[int] = None):
        """
        Runs the async message consumption loop.
        Dispatches parsed events to handler_callback(topic, contract_obj).
        """
        if not self._started:
            raise TelemetryConsumerError("TelemetryConsumer is not started. Call start() first.")

        self._running = True
        message_count = 0

        try:
            while self._running:
                if self._consumer is None or not hasattr(self._consumer, '__aiter__'):
                    # Mock/Dry-run exit loop
                    break

                async for msg in self._consumer:
                    if not self._running:
                        break

                    topic = msg.topic
                    contract_obj = self.parse_message_payload(topic, msg.value)

                    if contract_obj is not None:
                        try:
                            if inspect.iscoroutinefunction(handler_callback):
                                await handler_callback(topic, contract_obj)
                            else:
                                handler_callback(topic, contract_obj)
                        except Exception as e:
                            logger.error(f"Error in consumer callback handler for topic '{topic}': {e}")

                    message_count += 1
                    if max_messages and message_count >= max_messages:
                        self._running = False
                        break

        except Exception as e:
            logger.error(f"Error in consumer loop: {e}")
            raise TelemetryConsumerError(f"Consumer loop failed: {e}") from e
        finally:
            self._running = False
