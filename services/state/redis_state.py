"""
PassiveShield AI — Bounded Redis Sliding-Window State Manager
Manages temporal sliding-window state in Redis (or in-memory mock fallback).
Enforces key naming standards, TTL expiration, bounded set sizes, and deterministic state retrieval.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Set

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

logger = logging.getLogger(__name__)

KEY_PREFIX = "passiveshield:state"
DEFAULT_TTL_BUFFER = 30  # Additional seconds added to TTL to ensure window coverage


class RedisStateError(Exception):
    """Raised on state manager errors."""
    pass


class MockRedisDriver:
    """In-memory mock driver providing Redis-like operations for offline testing and fallback."""

    def __init__(self):
        self._hashes: Dict[str, Dict[str, int]] = {}
        self._sets: Dict[str, Set[str]] = {}
        self._zsets: Dict[str, List[tuple]] = {}
        self._ttls: Dict[str, float] = {}

    def _clean_expired(self):
        now = time.time()
        expired = [k for k, exp in self._ttls.items() if exp <= now]
        for k in expired:
            self._hashes.pop(k, None)
            self._sets.pop(k, None)
            self._zsets.pop(k, None)
            self._ttls.pop(k, None)

    def expire(self, key: str, seconds: int):
        self._clean_expired()
        self._ttls[key] = time.time() + seconds

    def hincrby(self, key: str, field: str, amount: int) -> int:
        self._clean_expired()
        if key not in self._hashes:
            self._hashes[key] = {}
        curr = self._hashes[key].get(field, 0)
        new_val = curr + amount
        self._hashes[key][field] = new_val
        return new_val

    def hgetall(self, key: str) -> Dict[str, str]:
        self._clean_expired()
        res = self._hashes.get(key, {})
        return {k: str(v) for k, v in res.items()}

    def sadd(self, key: str, member: str) -> int:
        self._clean_expired()
        if key not in self._sets:
            self._sets[key] = set()
        if member in self._sets[key]:
            return 0
        self._sets[key].add(member)
        return 1

    def scard(self, key: str) -> int:
        self._clean_expired()
        return len(self._sets.get(key, set()))

    def smembers(self, key: str) -> Set[str]:
        self._clean_expired()
        return set(self._sets.get(key, set()))

    def zadd(self, key: str, mapping: Dict[str, float]) -> int:
        self._clean_expired()
        if key not in self._zsets:
            self._zsets[key] = []
        added = 0
        for member, score in mapping.items():
            # Remove existing member if present
            self._zsets[key] = [item for item in self._zsets[key] if item[0] != member]
            self._zsets[key].append((member, score))
            added += 1
        # Sort by score ascending
        self._zsets[key].sort(key=lambda x: x[1])
        return added

    def zremrangebyrank(self, key: str, start: int, stop: int) -> int:
        self._clean_expired()
        if key not in self._zsets:
            return 0
        zlist = self._zsets[key]
        n = len(zlist)
        if start < 0:
            start += n
        if stop < 0:
            stop += n
        start = max(0, start)
        stop = min(n - 1, stop)
        if start > stop or start >= n:
            return 0
        removed = zlist[start:stop + 1]
        self._zsets[key] = zlist[:start] + zlist[stop + 1:]
        return len(removed)

    def zrange(self, key: str, start: int, stop: int, withscores: bool = False) -> list:
        self._clean_expired()
        if key not in self._zsets:
            return []
        zlist = self._zsets[key]
        n = len(zlist)
        if start < 0:
            start += n
        if stop < 0:
            stop += n
        start = max(0, start)
        stop = min(n, stop + 1)
        sliced = zlist[start:stop]
        if withscores:
            return [(member.encode('utf-8') if isinstance(member, str) else member, score) for member, score in sliced]
        return [member.encode('utf-8') if isinstance(member, str) else member for member, _ in sliced]

    def zcard(self, key: str) -> int:
        self._clean_expired()
        return len(self._zsets.get(key, []))

    def publish(self, channel: str, message: str) -> int:
        self._clean_expired()
        if not hasattr(self, "_subscribers"):
            self._subscribers: Dict[str, List[Any]] = {}
        subs = self._subscribers.get(channel, [])
        for callback in subs:
            try:
                callback(message)
            except Exception as e:
                logger.error(f"Error in mock pubsub subscriber callback: {e}")
        return len(subs)

    def register_mock_subscriber(self, channel: str, callback: Any):
        if not hasattr(self, "_subscribers"):
            self._subscribers: Dict[str, List[Any]] = {}
        if channel not in self._subscribers:
            self._subscribers[channel] = []
        self._subscribers[channel].append(callback)


class RedisStateManager:
    """
    Bounded sliding-window state manager for network traffic telemetry.
    Supports flow counter aggregation, target fan-out tracking, and inter-arrival timing sets.
    """

    def __init__(self, host: str = "localhost", port: int = 6379, password: str = "redis_dev_secret", client_instance=None):
        self.host = host
        self.port = port
        self.password = password
        self._client = client_instance
        self._using_mock = False

        if self._client is None:
            if HAS_REDIS:
                try:
                    self._client = redis.Redis(
                        host=self.host,
                        port=self.port,
                        password=self.password,
                        decode_responses=True,
                        socket_timeout=2.0
                    )
                except Exception as e:
                    logger.warning(f"Failed to connect to Redis server: {e}; falling back to MockRedisDriver.")
                    self._client = MockRedisDriver()
                    self._using_mock = True
            else:
                logger.warning("redis package not installed; falling back to MockRedisDriver.")
                self._client = MockRedisDriver()
                self._using_mock = True

    def _get_flow_key(self, src_ip: str, window_seconds: int) -> str:
        return f"{KEY_PREFIX}:flow:{src_ip}:{window_seconds}s"

    def _get_target_key(self, src_ip: str, target_type: str, window_seconds: int) -> str:
        return f"{KEY_PREFIX}:targets:{src_ip}:{target_type}:{window_seconds}s"

    def _get_beacon_key(self, src_ip: str, dst_ip: str) -> str:
        return f"{KEY_PREFIX}:beacon:{src_ip}:{dst_ip}"

    def record_flow_metrics(
        self,
        src_ip: str,
        orig_bytes: int = 0,
        resp_bytes: int = 0,
        orig_pkts: int = 0,
        resp_pkts: int = 0,
        window_seconds: int = 60
    ):
        """Records flow metrics for a source IP over a sliding window."""
        key = self._get_flow_key(src_ip, window_seconds)
        ttl = window_seconds + DEFAULT_TTL_BUFFER

        try:
            self._client.hincrby(key, "flow_count", 1)
            self._client.hincrby(key, "orig_bytes", orig_bytes)
            self._client.hincrby(key, "resp_bytes", resp_bytes)
            self._client.hincrby(key, "orig_pkts", orig_pkts)
            self._client.hincrby(key, "resp_pkts", resp_pkts)
            self._client.expire(key, ttl)
        except Exception as e:
            logger.error(f"Error recording flow metrics for key {key}: {e}")

    def record_unique_target(self, src_ip: str, target: str, target_type: str = "ports", window_seconds: int = 60):
        """Records a unique target (e.g. destination port or IP) accessed by src_ip."""
        key = self._get_target_key(src_ip, target_type, window_seconds)
        ttl = window_seconds + DEFAULT_TTL_BUFFER

        try:
            self._client.sadd(key, target)
            self._client.expire(key, ttl)
        except Exception as e:
            logger.error(f"Error recording target for key {key}: {e}")

    def record_inter_arrival(self, src_ip: str, dst_ip: str, timestamp: float, max_history: int = 100, ttl_seconds: int = 600):
        """Records a connection timestamp in a ZSET capped at max_history items for C2 beaconing analysis."""
        key = self._get_beacon_key(src_ip, dst_ip)
        member_str = f"{timestamp:.6f}"

        try:
            self._client.zadd(key, {member_str: timestamp})
            # Trim ZSET if size exceeds max_history
            card = self._client.zcard(key)
            if card > max_history:
                self._client.zremrangebyrank(key, 0, card - max_history - 1)
            self._client.expire(key, ttl_seconds)
        except Exception as e:
            logger.error(f"Error recording inter-arrival timestamp for key {key}: {e}")

    def get_flow_metrics(self, src_ip: str, window_seconds: int = 60) -> Dict[str, int]:
        """Retrieves aggregated flow metrics for a source IP over a window."""
        key = self._get_flow_key(src_ip, window_seconds)
        try:
            raw = self._client.hgetall(key)
            return {k: int(v) for k, v in raw.items()}
        except Exception as e:
            logger.error(f"Error fetching flow metrics for key {key}: {e}")
            return {}

    def get_unique_target_count(self, src_ip: str, target_type: str = "ports", window_seconds: int = 60) -> int:
        """Returns the count of unique targets accessed by src_ip over a window."""
        key = self._get_target_key(src_ip, target_type, window_seconds)
        try:
            return self._client.scard(key)
        except Exception as e:
            logger.error(f"Error fetching target count for key {key}: {e}")
            return 0

    def get_inter_arrival_timestamps(self, src_ip: str, dst_ip: str) -> List[float]:
        """Returns the list of recent connection timestamps for a src_ip -> dst_ip pair."""
        key = self._get_beacon_key(src_ip, dst_ip)
        try:
            res = self._client.zrange(key, 0, -1, withscores=True)
            return [score for _, score in res]
        except Exception as e:
            logger.error(f"Error fetching timestamps for key {key}: {e}")
            return []
