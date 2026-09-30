"""Cross-service dashboard events.

Any service (API, scan-worker, scheduler) can publish a dashboard event; only the
API holds WebSocket connections. Events travel over Redis pub/sub on
``DASHBOARD_EVENTS_CHANNEL`` so every API replica relays them to its clients.

When Redis is not configured (local dev, tests) events are delivered in-process
to a registered local sink, which the API wires to its WebSocket manager.
"""
from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any, Awaitable, Callable, Optional

from sentinel_core.config import settings

logger = logging.getLogger(__name__)

DASHBOARD_EVENTS_CHANNEL = "api-sentinel:dashboard-events"

LocalSink = Callable[[dict[str, Any], Optional[int]], Awaitable[None]]
_local_sink: LocalSink | None = None
_redis_client: Any = None


class EventType(str, Enum):
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_PROGRESS = "SCAN_PROGRESS"
    THREAT_ACTOR_FLAGGED = "THREAT_ACTOR_FLAGGED"
    TRAFFIC_INGESTED = "TRAFFIC_INGESTED"
    IP_BLOCKED = "IP_BLOCKED"
    ENDPOINT_BLOCKED = "ENDPOINT_BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    INCIDENT_CREATED = "INCIDENT_CREATED"


def set_local_sink(sink: LocalSink | None) -> None:
    """Register the in-process delivery target used when Redis is unavailable."""
    global _local_sink
    _local_sink = sink


def _redis():
    global _redis_client
    if not settings.REDIS_URL:
        return None
    if _redis_client is None:
        try:
            import redis.asyncio as redis_asyncio
        except ImportError:
            return None
        _redis_client = redis_asyncio.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


def encode_event(message: dict[str, Any], account_id: Optional[int]) -> str:
    return json.dumps({"account_id": account_id, "message": message}, default=str)


def decode_event(raw: str) -> tuple[dict[str, Any], Optional[int]]:
    envelope = json.loads(raw)
    return envelope["message"], envelope.get("account_id")


async def publish_dashboard_event(message: dict[str, Any], account_id: Optional[int] = None) -> None:
    """Publish an event for dashboard clients. Never raises: events are best-effort."""
    client = _redis()
    if client is not None:
        try:
            await client.publish(DASHBOARD_EVENTS_CHANNEL, encode_event(message, account_id))
            return
        except Exception as exc:
            logger.warning("dashboard_event_publish_failed", extra={"error": str(exc)})
    if _local_sink is not None:
        try:
            await _local_sink(message, account_id)
        except Exception as exc:
            logger.debug("dashboard_event_local_delivery_failed", extra={"error": str(exc)})
