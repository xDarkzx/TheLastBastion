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
from lastbastion.protocol.handshake import NonceRegistry, NONCE_CACHE_MAX
from lastbastion.protocol.socket import AgentSocket, AgentConnection, PeerInfo, ProtocolMetrics

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
]
