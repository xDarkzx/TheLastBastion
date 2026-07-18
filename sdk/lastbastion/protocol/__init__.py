"""
Bastion Protocol -- binary agent-to-agent wire protocol.

No HTTP. No headers. No URLs. No status codes.
Identity, encryption, and signing are structural -- not optional.

Hard dependencies: pynacl, msgpack.
"""

from lastbastion.protocol.frames import (
    FrameType,
    FrameFlags,
    BastionFrame,
    FrameEncoder,
    FrameDecoder,
    ErrorCode,
    PROTOCOL_VERSION,
    MAX_FRAME_SIZE,
    FRAME_HEADER_SIZE,
    SIGNATURE_SIZE,
    PASSPORT_HASH_SIZE,
    FRAME_FLAGS_SIZE,
    FRAME_TIMESTAMP_SIZE,
    FRAME_FRESHNESS_SECONDS,
    PING_TIMEOUT_SECONDS,
    MAX_SEQUENCE,
)
from lastbastion.protocol.handshake import (
    NonceRegistry,
    NONCE_CACHE_MAX,
    # DIRECT mode — no passport office required, key-pinned peer auth
    DirectHandshakeInitiator,
    DirectHandshakeResponder,
    DirectHandshakeResult,
    # Session resumption — skip the full handshake on reconnect
    ResumptionResponder,
    ResumeResult,
    build_resume,
    parse_resume,
    complete_resume,
)
from lastbastion.protocol.resumption import (
    derive_resumption_secret,
    derive_resumed_session_key,
    issue_ticket,
    redeem_ticket,
    TicketClaims,
    DEFAULT_TICKET_TTL_SECONDS,
)
from lastbastion.protocol.trust_store import PeerTrustStore, PinResult
from lastbastion.protocol.socket import (
    AgentSocket,
    AgentConnection,
    PeerInfo,
    ProtocolMetrics,
    DirectAgentSocket,
    DirectAgentSocketServer,
)

__all__ = [
    "FrameType",
    "FrameFlags",
    "BastionFrame",
    "FrameEncoder",
    "FrameDecoder",
    "ErrorCode",
    "AgentSocket",
    "AgentConnection",
    "PeerInfo",
    "ProtocolMetrics",
    "DirectAgentSocket",
    "DirectAgentSocketServer",
    "PROTOCOL_VERSION",
    "MAX_FRAME_SIZE",
    "FRAME_HEADER_SIZE",
    "SIGNATURE_SIZE",
    "PASSPORT_HASH_SIZE",
    "FRAME_FLAGS_SIZE",
    "FRAME_TIMESTAMP_SIZE",
    "FRAME_FRESHNESS_SECONDS",
    "PING_TIMEOUT_SECONDS",
    "MAX_SEQUENCE",
    "NonceRegistry",
    "NONCE_CACHE_MAX",
    "DirectHandshakeInitiator",
    "DirectHandshakeResponder",
    "DirectHandshakeResult",
    "ResumptionResponder",
    "ResumeResult",
    "build_resume",
    "parse_resume",
    "complete_resume",
    "derive_resumption_secret",
    "derive_resumed_session_key",
    "issue_ticket",
    "redeem_ticket",
    "TicketClaims",
    "DEFAULT_TICKET_TTL_SECONDS",
    "PeerTrustStore",
    "PinResult",
]
