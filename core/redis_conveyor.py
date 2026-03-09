"""
Redis Conveyor Belt (v5.0): Industrial-Grade Message Pipeline.
Uses Redis Streams (XADD/XREADGROUP/XACK) for reliable task queuing
and PUB/SUB for real-time telemetry broadcasting.

Redis = The Nervous System (fast signals, hot cache, real-time pub/sub).
PostgreSQL = The Brain (permanent intelligence, knowledge hierarchy).
"""
import os
import json
import time
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger("RedisConveyor")


class RedisConveyor:
    """
    Industrial Redis Streams Conveyor Belt.
    Provides reliable task queuing with consumer groups,
    real-time telemetry pub/sub, and hot caching.
    """

    def __init__(
        self,
        redis_host: str = None,
        redis_port: int = None,
        redis_db: int = 0
    ):
        self.host = redis_host or os.getenv("REDIS_HOST", "localhost")
        self.port = redis_port or int(os.getenv("REDIS_PORT", 6379))
        self.db = redis_db
        self._client: Optional[redis.Redis] = None
        self._connected = False

    @property
    def client(self) -> redis.Redis:
        """Lazy connection with auto-reconnect."""
        if not self._client or not self._connected:
            self._connect()
        return self._client

    def _connect(self):
        """Establishes connection to Redis with resilience."""
        if not REDIS_AVAILABLE:
            logger.error("CONVEYOR: redis package not installed.")
            raise ImportError("redis package required: pip install redis")

        try:
            self._client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                decode_responses=True,
                socket_connect_timeout=5,
                retry_on_timeout=True
            )
            self._client.ping()
            self._connected = True
            logger.info(f"CONVEYOR: Connected to Redis at {self.host}:{self.port}")
        except redis.ConnectionError as e:
            self._connected = False
            logger.error(f"CONVEYOR: Redis connection failed: {e}")
            raise

    def is_connected(self) -> bool:
        """Health check for the Redis connection. Attempts connection if not yet initialised."""
        try:
            if not self._client:
                self._connect()
            return self._client.ping()
        except Exception:
            self._connected = False
            return False

    # -----------------------------------------------------------------------
    # TASK QUEUING (Redis Streams — reliable, ordered, consumer groups)
    # -----------------------------------------------------------------------

    def ensure_consumer_group(self, stream: str, group: str):
        """Creates a consumer group if it doesn't exist."""
        try:
            self.client.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def produce(self, stream: str, payload: dict) -> str:
        """
        Pushes a task onto the conveyor belt (Redis Stream).
        Returns the message ID.
        """
        message_id = self.client.xadd(stream, {
            "data": json.dumps(payload),
            "produced_at": datetime.utcnow().isoformat()
        })
        logger.debug(f"CONVEYOR: Produced to {stream} -> {message_id}")
        return message_id

    def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 1,
        block_ms: int = 2000
    ) -> List[Dict[str, Any]]:
        """
        Claims tasks from the stream using consumer groups.
        Blocks for `block_ms` milliseconds waiting for new messages.
        Returns list of {id, data} dicts.
        """
        self.ensure_consumer_group(stream, group)

        messages = self.client.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream: ">"},
            count=count,
            block=block_ms
        )

        results = []
        if messages:
            for stream_name, entries in messages:
                for msg_id, fields in entries:
                    try:
                        data = json.loads(fields.get("data", "{}"))
                    except json.JSONDecodeError:
                        data = fields
                    results.append({"id": msg_id, "data": data})

        return results

    def acknowledge(self, stream: str, group: str, message_id: str):
        """Marks a task as successfully processed (XACK)."""
        self.client.xack(stream, group, message_id)
        logger.debug(f"CONVEYOR: ACK {stream}/{group} -> {message_id}")

    def get_pending_count(self, stream: str, group: str) -> int:
        """Returns the number of unacknowledged messages in a consumer group."""
        try:
            info = self.client.xpending(stream, group)
            return info.get("pending", 0) if isinstance(info, dict) else 0
        except redis.ResponseError:
            return 0

    # -----------------------------------------------------------------------
    # REAL-TIME TELEMETRY (PUB/SUB)
    # -----------------------------------------------------------------------

    def broadcast_telemetry(
        self,
        worker_id: str,
        message: str,
        level: str = "info",
        mission_id: int = None,
        swarm_id: str = None
    ):
        """Publishes real-time telemetry for dashboard consumption."""
        payload = {
            "worker_id": worker_id,
            "message": message,
            "level": level,
            "mission_id": mission_id,
            "swarm_id": swarm_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.client.publish("swarm:telemetry", json.dumps(payload))

    def subscribe_telemetry(self):
        """Returns a PubSub object listening on the telemetry channel."""
        pubsub = self.client.pubsub()
        pubsub.subscribe("swarm:telemetry")
        return pubsub

    # -----------------------------------------------------------------------
    # WORKER HEARTBEAT (TTL-based liveness)
    # -----------------------------------------------------------------------

    def heartbeat(self, worker_id: str, status: str = "idle",
                  current_task: str = None, ttl_seconds: int = 30):
        """Atomic heartbeat with TTL — if it expires, worker is considered dead."""
        key = f"worker:{worker_id}"
        data = {
            "status": status,
            "current_task": current_task or "",
            "last_heartbeat": datetime.utcnow().isoformat()
        }
        pipe = self.client.pipeline()
        pipe.hset(key, mapping=data)
        pipe.expire(key, ttl_seconds)
        pipe.execute()

    def get_live_workers(self) -> List[Dict[str, Any]]:
        """Returns all workers with active heartbeats (TTL not expired)."""
        workers = []
        for key in self.client.scan_iter("worker:*"):
            data = self.client.hgetall(key)
            if data:
                worker_id = key.replace("worker:", "")
                data["id"] = worker_id
                data["ttl"] = self.client.ttl(key)
                workers.append(data)
        return workers

    # -----------------------------------------------------------------------
    # HOT CACHE (for dashboard API responses)
    # -----------------------------------------------------------------------

    def cache_set(self, key: str, value: Any, ttl_seconds: int = 10):
        """Sets a cached value with TTL for dashboard use."""
        self.client.setex(key, ttl_seconds, json.dumps(value))

    def cache_get(self, key: str) -> Optional[Any]:
        """Gets a cached value, returns None if expired/missing."""
        raw = self.client.get(key)
        if raw:
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
        return None

    # -----------------------------------------------------------------------
    # STREAM MANAGEMENT
    # -----------------------------------------------------------------------

    def trim_stream(self, stream: str, max_length: int = 10000):
        """Prevents unbounded stream growth."""
        self.client.xtrim(stream, maxlen=max_length, approximate=True)

    def get_stream_info(self, stream: str) -> Dict[str, Any]:
        """Returns metadata about a stream (length, groups, etc.)."""
        try:
            info = self.client.xinfo_stream(stream)
            return {
                "length": info.get("length", 0),
                "first_entry": info.get("first-entry"),
                "last_entry": info.get("last-entry")
            }
        except redis.ResponseError:
            return {"length": 0}
