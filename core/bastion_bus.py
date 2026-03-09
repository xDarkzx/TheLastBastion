"""
Bastion Protocol Bus — In-memory ring buffer capturing every binary frame event.

Provides a "packet capture" view for the Bastion Protocol — records handshakes,
data frames, encryption events, and connection lifecycle for every binary wire
interaction between agents.

Usage:
    from core.bastion_bus import bastion_bus
    bastion_bus.record(
        event_type="FRAME_SENT",
        frame_type="DATA",
        sender_agent="producer-bot",
        receiver_agent="compliance-bot",
        payload_size=256,
    )
"""
import secrets
import threading
import time as _time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class BastionLogEntry:
    """A single captured Bastion Protocol frame event."""

    log_id: str = ""
    timestamp: str = ""
    event_type: str = ""  # HANDSHAKE_INIT, HANDSHAKE_COMPLETE, FRAME_SENT, FRAME_RECEIVED, CONNECTION_CLOSED, ERROR
    frame_type: str = ""  # HELLO, HELLO_ACK, DATA, DATA_ACK, PING, PONG, ERROR, CLOSE, STREAM_*
    sender_agent: str = ""
    receiver_agent: str = ""
    direction: str = ""  # SENT | RECEIVED
    sequence: int = 0
    passport_hash: str = ""  # hex
    signature_verified: bool = False
    encrypted: bool = False
    payload_size: int = 0
    total_frame_size: int = 0
    session_id: str = ""  # unique per connection pair
    error_code: int = 0
    error_message: str = ""
    latency_ms: float = 0.0
    trust_score: float = 0.0
    key_exchange: str = ""  # X25519
    payload_description: str = ""  # "Batch WK-2847: Milk Powder export cert"
    payload_type: str = ""  # "application/msgpack", "image/jpeg", "application/pdf", "text/csv"
    payload_encoding: str = ""  # "msgpack", "jwt", "raw"
    cipher: str = ""  # "XSalsa20-Poly1305" or "" for handshake
    nonce: str = ""  # 24-byte nonce hex (first 16 chars)
    integrity_check: str = ""  # "PASS" | "FAIL"
    key_exchange_pub: str = ""  # truncated X25519 pub key hex
    accepted: bool = False  # True when DATA_ACK received for this frame
    handshake_params: dict = field(default_factory=dict)  # JWT claims, pub key, nonce for HELLO frames

    def __post_init__(self):
        if not self.log_id:
            self.log_id = f"bp-{secrets.token_hex(4)}"
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BastionProtocolBus:
    """
    In-memory ring buffer (1000 entries) capturing every Bastion Protocol frame event.
    Thread-safe. Mirrors the pattern from core/protocol_bus.py.

    Supports WebSocket broadcast via on_event callback.
    """

    def __init__(self, maxlen: int = 1000):
        self._buffer: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._stats: Dict[str, int] = {}
        self._total_recorded: int = 0
        self._total_bytes: int = 0
        self._handshakes_completed: int = 0
        self._active_sessions: Dict[str, Dict[str, Any]] = {}  # session_id -> info
        self._agent_last_seen: Dict[str, float] = {}  # agent_name -> timestamp
        self._on_event_callback = None

    def set_event_callback(self, callback):
        """Register a callback invoked on every record(). Used for WebSocket broadcast."""
        self._on_event_callback = callback

    def record(
        self,
        event_type: str = "",
        frame_type: str = "",
        sender_agent: str = "",
        receiver_agent: str = "",
        direction: str = "",
        sequence: int = 0,
        passport_hash: str = "",
        signature_verified: bool = False,
        encrypted: bool = False,
        payload_size: int = 0,
        total_frame_size: int = 0,
        session_id: str = "",
        error_code: int = 0,
        error_message: str = "",
        latency_ms: float = 0.0,
        trust_score: float = 0.0,
        key_exchange: str = "",
        payload_description: str = "",
        payload_type: str = "",
        payload_encoding: str = "",
        cipher: str = "",
        nonce: str = "",
        integrity_check: str = "",
        key_exchange_pub: str = "",
        accepted: bool = False,
        handshake_params: Optional[dict] = None,
    ) -> BastionLogEntry:
        """Record a frame event in the ring buffer."""
        entry = BastionLogEntry(
            event_type=event_type,
            frame_type=frame_type,
            sender_agent=sender_agent,
            receiver_agent=receiver_agent,
            direction=direction,
            sequence=sequence,
            passport_hash=passport_hash,
            signature_verified=signature_verified,
            encrypted=encrypted,
            payload_size=payload_size,
            total_frame_size=total_frame_size,
            session_id=session_id,
            error_code=error_code,
            error_message=error_message,
            latency_ms=latency_ms,
            trust_score=trust_score,
            key_exchange=key_exchange,
            payload_description=payload_description,
            payload_type=payload_type,
            payload_encoding=payload_encoding,
            cipher=cipher,
            nonce=nonce,
            integrity_check=integrity_check,
            key_exchange_pub=key_exchange_pub,
            accepted=accepted,
            handshake_params=handshake_params or {},
        )

        with self._lock:
            self._buffer.append(entry)
            self._total_recorded += 1
            self._total_bytes += total_frame_size
            self._stats[frame_type] = self._stats.get(frame_type, 0) + 1

            # Track agent last-seen timestamps
            now = _time.time()
            if sender_agent:
                self._agent_last_seen[sender_agent] = now
            if receiver_agent:
                self._agent_last_seen[receiver_agent] = now

            if event_type == "HANDSHAKE_COMPLETE":
                self._handshakes_completed += 1

            # Track active sessions
            if session_id:
                if event_type == "CONNECTION_CLOSED":
                    self._active_sessions.pop(session_id, None)
                else:
                    if session_id not in self._active_sessions:
                        self._active_sessions[session_id] = {
                            "session_id": session_id,
                            "agents": [sender_agent, receiver_agent],
                            "started": entry.timestamp,
                            "frame_count": 0,
                            "bytes": 0,
                            "state": "HANDSHAKING",
                        }
                    sess = self._active_sessions[session_id]
                    sess["frame_count"] += 1
                    sess["bytes"] += total_frame_size
                    if event_type == "HANDSHAKE_COMPLETE":
                        sess["state"] = "ESTABLISHED"
                    sess["last_activity"] = entry.timestamp

        # Fire WebSocket broadcast
        if self._on_event_callback:
            try:
                import asyncio
                event = {"type": "bastion", **entry.to_dict()}
                loop = asyncio.get_running_loop()
                loop.create_task(self._on_event_callback(event))
            except RuntimeError:
                pass
            except Exception:
                pass

        return entry

    def record_handshake(
        self,
        event_type: str,
        sender: str,
        receiver: str,
        session_id: str = "",
        trust_score: float = 0.0,
        key_exchange: str = "X25519",
        passport_hash: str = "",
        latency_ms: float = 0.0,
        key_exchange_pub: str = "",
        handshake_params: Optional[dict] = None,
    ) -> BastionLogEntry:
        """Convenience method for handshake events."""
        frame_type = "HELLO" if event_type == "HANDSHAKE_INIT" else "HELLO_ACK"
        return self.record(
            event_type=event_type,
            frame_type=frame_type,
            sender_agent=sender,
            receiver_agent=receiver,
            direction="SENT",
            session_id=session_id,
            trust_score=trust_score,
            key_exchange=key_exchange,
            passport_hash=passport_hash,
            encrypted=False,
            signature_verified=True,
            latency_ms=latency_ms,
            payload_encoding="jwt",
            key_exchange_pub=key_exchange_pub,
            handshake_params=handshake_params or {},
        )

    def query(
        self,
        limit: int = 200,
        event_type: Optional[str] = None,
        sender_agent: Optional[str] = None,
        frame_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query the buffer with optional filters. Returns newest first."""
        with self._lock:
            entries = list(self._buffer)

        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        if sender_agent:
            entries = [e for e in entries if e.sender_agent == sender_agent]
        if frame_type:
            entries = [e for e in entries if e.frame_type == frame_type]

        entries.reverse()
        return [e.to_dict() for e in entries[:limit]]

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate stats about the bus."""
        with self._lock:
            return {
                "total_frames": self._total_recorded,
                "by_frame_type": dict(self._stats),
                "active_connections": len(self._active_sessions),
                "total_bytes": self._total_bytes,
                "handshakes_completed": self._handshakes_completed,
                "buffer_size": len(self._buffer),
                "buffer_capacity": self._buffer.maxlen,
            }

    def get_connections(self) -> List[Dict[str, Any]]:
        """Return list of connection pairs with state, frame counts, peer info."""
        with self._lock:
            return list(self._active_sessions.values())

    def get_agent_status(self, window: float = 60.0) -> Dict[str, str]:
        """Return online/offline status for each agent based on last-seen timestamp.

        An agent is 'online' if it was seen within the given window (default 60s).
        """
        now = _time.time()
        with self._lock:
            return {
                agent_id: "online" if (now - last_seen) < window else "offline"
                for agent_id, last_seen in self._agent_last_seen.items()
            }


# Global singleton
bastion_bus = BastionProtocolBus(maxlen=1000)
