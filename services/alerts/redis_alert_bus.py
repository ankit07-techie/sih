"""
PassiveShield AI — Redis Pub/Sub Alert Bus
Provides high-throughput alert publishing and narrow subscriber interfaces for standardized ThreatAlert contracts over the approved 'cyber_alerts' Redis Pub/Sub channel.
"""

import json
import logging
from typing import Callable, Optional, Any
from shared.contracts import ThreatAlert, ContractValidationError
from services.state import RedisStateManager, MockRedisDriver

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

logger = logging.getLogger(__name__)

DEFAULT_ALERT_CHANNEL = "cyber_alerts"


class RedisAlertBus:
    """
    Manages publication and subscription of standardized ThreatAlert contracts over Redis Pub/Sub.
    """

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        channel: str = DEFAULT_ALERT_CHANNEL,
        host: str = "localhost",
        port: int = 6379,
        password: Optional[str] = None
    ):
        self.channel = channel
        self._using_mock = False

        if redis_client is not None:
            self._client = redis_client
            if isinstance(redis_client, MockRedisDriver):
                self._using_mock = True
        else:
            if HAS_REDIS:
                try:
                    self._client = redis.Redis(
                        host=host,
                        port=port,
                        password=password,
                        decode_responses=True,
                        socket_timeout=2.0
                    )
                except Exception as e:
                    logger.warning(f"Failed to connect to Redis for alert bus: {e}; falling back to MockRedisDriver.")
                    self._client = MockRedisDriver()
                    self._using_mock = True
            else:
                logger.warning("redis package not installed; alert bus falling back to MockRedisDriver.")
                self._client = MockRedisDriver()
                self._using_mock = True

    def publish_alert(self, alert: ThreatAlert) -> bool:
        """
        Serializes and publishes a standardized ThreatAlert to the approved 'cyber_alerts' Redis Pub/Sub channel.
        Returns True on successful publication, False otherwise.
        """
        if not isinstance(alert, ThreatAlert):
            raise ContractValidationError(f"Expected ThreatAlert object, got {type(alert)}")

        try:
            payload = alert.to_json()
            listeners = self._client.publish(self.channel, payload)
            logger.info(f"Published ThreatAlert '{alert.alert_id}' (severity: {alert.severity}) to channel '{self.channel}' ({listeners} active listeners).")
            return True
        except Exception as e:
            logger.error(f"Failed to publish ThreatAlert to channel '{self.channel}': {e}")
            return False

    def subscribe_alerts(self, callback: Callable[[ThreatAlert], None]):
        """
        Subscribes to the 'cyber_alerts' channel and invokes callback(alert) for each incoming ThreatAlert.
        """
        if self._using_mock or isinstance(self._client, MockRedisDriver):

            def _mock_handler(msg_str: str):
                try:
                    alert = ThreatAlert.from_json(msg_str)
                    callback(alert)
                except Exception as e:
                    logger.error(f"Failed to parse incoming mock alert payload: {e}")

            self._client.register_mock_subscriber(self.channel, _mock_handler)
            logger.info(f"Registered mock subscriber for alert channel '{self.channel}'.")
            return

        # Real Redis Pub/Sub handling
        try:
            pubsub = self._client.pubsub()
            pubsub.subscribe(self.channel)
            logger.info(f"Subscribed to Redis alert channel '{self.channel}'.")

            for message in pubsub.listen():
                if message and message.get("type") == "message":
                    data = message.get("data")
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    try:
                        alert = ThreatAlert.from_json(data)
                        callback(alert)
                    except Exception as e:
                        logger.error(f"Error parsing ThreatAlert from channel '{self.channel}': {e}")
        except Exception as e:
            logger.error(f"Error in Redis alert bus subscription thread: {e}")
