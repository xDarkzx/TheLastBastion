"""
Protocol Message Bus — In-memory ring buffer capturing every M2M protocol interaction.

Provides a "Wireshark for agent communication" — captures auth results, message types,
processing times, and payload summaries for every protocol message flowing through The Last Bastion.

Usage:
    from core.protocol_bus import protocol_bus
    protocol_bus.record(
        direction="INBOUND",
        message_type="REGISTER",
        sender_id="financial-bot-001",
        endpoint="/m2m/register",
        auth_result="SKIPPED",
    )
"""
import secrets
import threading
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ProtocolLogEntry:
    """A single captured protocol message."""

    log_id: str = ""
    timestamp: str = ""
    direction: str = "INBOUND"  # INBOUND | OUTBOUND
    message_type: str = ""  # REGISTER, DISCOVER, TASK_SUBMIT, etc.
    sender_id: str = ""
    recipient_id: str = ""
    endpoint: str = ""
    auth_result: str = ""  # AUTHENTICATED | REJECTED | SKIPPED
    auth_reason: str = ""
    payload_summary: str = ""  # keys + field count, never raw data
    payload_size_bytes: int = 0
    nonce: str = ""  # first 16 chars
    protocol_version: str = ""
    signature_present: bool = False
    processing_ms: float = 0.0
    error: str = ""

    def __post_init__(self):
        if not self.log_id:
            self.log_id = f"msg-{secrets.token_hex(4)}"
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProtocolMessageBus:
    """
    In-memory ring buffer (500 messages) capturing every M2M protocol interaction.
    Thread-safe. Same pattern as _activity_feed in m2m_router.py.

    Supports WebSocket broadcast via on_event callback.
    """

    def __init__(self, maxlen: int = 500):
        self._buffer: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._stats: Dict[str, int] = {}
        self._total_recorded: int = 0
        self._on_event_callback = None  # Set by regional_core to broadcast via WebSocket

    def set_event_callback(self, callback):
        """Register a callback invoked on every record(). Used for WebSocket broadcast."""
        self._on_event_callback = callback

    def record(
        self,
        direction: str = "INBOUND",
        message_type: str = "",
        sender_id: str = "",
        recipient_id: str = "registry-base",
        endpoint: str = "",
        auth_result: str = "SKIPPED",
        auth_reason: str = "",
        payload_summary: str = "",
        payload_size_bytes: int = 0,
        nonce: str = "",
        protocol_version: str = "",
        signature_present: bool = False,
        processing_ms: float = 0.0,
        error: str = "",
    ) -> ProtocolLogEntry:
        """Record a protocol message in the ring buffer."""
        entry = ProtocolLogEntry(
            direction=direction,
            message_type=message_type,
            sender_id=sender_id,
            recipient_id=recipient_id,
            endpoint=endpoint,
            auth_result=auth_result,
            auth_reason=auth_reason,
            payload_summary=payload_summary,
            payload_size_bytes=payload_size_bytes,
            nonce=nonce[:16] if nonce else "",
            protocol_version=protocol_version,
            signature_present=signature_present,
            processing_ms=processing_ms,
            error=error,
        )

        with self._lock:
            self._buffer.append(entry)
            self._total_recorded += 1
            self._stats[message_type] = self._stats.get(message_type, 0) + 1

        # Fire WebSocket broadcast callback if registered
        if self._on_event_callback:
            try:
                import asyncio
                event = {"type": "protocol", **entry.to_dict()}
                loop = asyncio.get_running_loop()
                loop.create_task(self._on_event_callback(event))
            except RuntimeError:
                pass  # No running event loop (called from sync context outside async)
            except Exception:
                pass  # Never crash the bus

        return entry

    def query(
        self,
        limit: int = 50,
        message_type: Optional[str] = None,
        sender_id: Optional[str] = None,
        auth_result: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query the buffer with optional filters. Returns newest first."""
        with self._lock:
            entries = list(self._buffer)

        # Filter
        if message_type:
            entries = [e for e in entries if e.message_type == message_type]
        if sender_id:
            entries = [e for e in entries if e.sender_id == sender_id]
        if auth_result:
            entries = [e for e in entries if e.auth_result == auth_result]

        # Newest first, limit
        entries.reverse()
        return [e.to_dict() for e in entries[:limit]]

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate stats about the bus."""
        with self._lock:
            return {
                "total_recorded": self._total_recorded,
                "buffer_size": len(self._buffer),
                "buffer_capacity": self._buffer.maxlen,
                "by_message_type": dict(self._stats),
            }


# Global singleton
protocol_bus = ProtocolMessageBus()
