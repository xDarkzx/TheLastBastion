"""
Agent Communication Protocol (ACP) — The Last Bastion M2M Foundation.

Defines the standard message format, identity system, and
protocol types that ALL machine-to-machine communication uses.

Every external agent that talks to The Last Bastion speaks ACP v1.0.

Message Lifecycle:
    1. Agent creates an AgentIdentity (Ed25519 keypair)
    2. Agent builds a ProtocolMessage with typed payload
    3. Agent signs the message with their private key
    4. The Last Bastion verifies the signature + validates the message
    5. The Last Bastion routes to the appropriate handler

Security:
    - Ed25519 digital signatures (no passwords)
    - Replay protection via nonce + timestamp window
    - Message integrity via payload hashing
"""
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AgentProtocol")

# Protocol version — semantic versioning for forward compatibility
PROTOCOL_VERSION = "1.0.0"

# Maximum age of a message before it's considered stale (seconds)
MAX_MESSAGE_AGE_SECONDS = 300  # 5 minutes

# Nonce length (bytes) for replay protection
NONCE_LENGTH = 16


class MessageType(str, Enum):
    """
    Standard message types in the Agent Communication Protocol.

    Each type has a defined payload schema and expected response.
    """
    # Discovery & Registration
    DISCOVER = "DISCOVER"               # "What services do you offer?"
    REGISTER = "REGISTER"               # "I want to register as a client"
    DEREGISTER = "DEREGISTER"           # "Remove my registration"

    # Quotation
    QUOTE_REQUEST = "QUOTE_REQUEST"     # "How much for this task?"
    QUOTE_RESPONSE = "QUOTE_RESPONSE"   # "Here's my price"

    # Task Lifecycle
    TASK_SUBMIT = "TASK_SUBMIT"         # "Please do this work"
    TASK_STATUS = "TASK_STATUS"         # "What's the progress?"
    TASK_RESULT = "TASK_RESULT"         # "Here are the results"
    TASK_CANCEL = "TASK_CANCEL"         # "Cancel this task"

    # Verification
    VERIFY_REQUEST = "VERIFY_REQUEST"   # "Verify this data for me"
    VERIFY_RESULT = "VERIFY_RESULT"     # "Here's the verification verdict"
    PROOF_QUERY = "PROOF_QUERY"         # "Show me the proof for hash X"

    # Agent-to-Agent Handoff
    HANDOFF_REQUEST = "HANDOFF_REQUEST"         # "I want to hand off data to you"
    HANDOFF_ACCEPT = "HANDOFF_ACCEPT"           # "Handoff accepted"
    HANDOFF_REJECT = "HANDOFF_REJECT"           # "Handoff rejected"
    REGISTER_REDIRECT = "REGISTER_REDIRECT"     # "Get verified first, then retry"

    # Health & Admin
    HEARTBEAT = "HEARTBEAT"             # "I'm alive"
    ACK = "ACK"                         # "Message received"
    ERROR = "ERROR"                     # "Something went wrong"
    CHALLENGE = "CHALLENGE"             # "Prove your identity"
    CHALLENGE_RESPONSE = "CHALLENGE_RESPONSE"  # "Here's my proof"


class AgentRole(str, Enum):
    """Roles an agent can have in the ecosystem."""
    DATA_CONSUMER = "DATA_CONSUMER"     # Buys verified data
    DATA_PROVIDER = "DATA_PROVIDER"     # Submits raw data for verification
    VERIFIER = "VERIFIER"               # Runs verification services (us)
    BROKER = "BROKER"                   # Routes tasks between agents
    OBSERVER = "OBSERVER"               # Read-only access to public data


@dataclass
class AgentIdentity:
    """
    Cryptographic identity for an agent in the M2M ecosystem.

    Each agent has:
    - A unique agent_id (human-readable)
    - An Ed25519 public key (for signature verification)
    - A role (what they're allowed to do)
    - A display name and optional metadata

    The private key is NEVER stored by The Last Bastion — only the agent
    holds their own private key. We only store the public key.
    """
    agent_id: str                       # Unique identifier (e.g., "agent-mercury-nz-001")
    public_key: str                     # Ed25519 public key (hex-encoded)
    role: AgentRole = AgentRole.DATA_CONSUMER
    display_name: str = ""
    capabilities: List[str] = field(default_factory=list)  # e.g., ["energy-nz", "invoice-scan"]
    registered_at: str = ""
    last_seen: str = ""
    reputation_score: float = 0.5       # 0.0 (untrusted) to 1.0 (gold partner)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.registered_at:
            self.registered_at = datetime.utcnow().isoformat()
        if not self.display_name:
            self.display_name = self.agent_id

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for storage or transmission (NO private key)."""
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "role": self.role.value,
            "display_name": self.display_name,
            "capabilities": self.capabilities,
            "registered_at": self.registered_at,
            "last_seen": self.last_seen,
            "reputation_score": round(self.reputation_score, 4),
            "metadata": self.metadata,
        }


@dataclass
class ProtocolMessage:
    """
    Standard message envelope for ALL M2M communication.

    Structure:
        header:
            protocol_version: "1.0.0"
            message_type: MessageType
            sender_id: agent_id of the sender
            recipient_id: agent_id of the recipient (or "the-last-bastion")
            timestamp: ISO-8601
            nonce: random hex string (replay protection)
            message_id: unique ID for this message
        payload: Dict — type-specific structured data
        signature: Ed25519 signature of the canonical payload
    """
    message_type: MessageType
    sender_id: str
    payload: Dict[str, Any]
    recipient_id: str = "the-last-bastion"
    protocol_version: str = PROTOCOL_VERSION
    timestamp: str = ""
    nonce: str = ""
    message_id: str = ""
    signature: str = ""                 # Hex-encoded Ed25519 signature

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()
        if not self.nonce:
            self.nonce = secrets.token_hex(NONCE_LENGTH)
        if not self.message_id:
            self.message_id = f"msg-{secrets.token_hex(8)}"

    def canonical_bytes(self) -> bytes:
        """
        Creates the canonical byte representation for signing.

        The canonical form is a deterministic JSON string of:
            protocol_version + message_type + sender_id +
            recipient_id + timestamp + nonce + sorted(payload)

        This ensures both sender and verifier produce the
        same bytes for the same message.
        """
        canonical = {
            "v": self.protocol_version,
            "t": self.message_type.value,
            "s": self.sender_id,
            "r": self.recipient_id,
            "ts": self.timestamp,
            "n": self.nonce,
            "p": self.payload,
        }
        return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()

    def payload_hash(self) -> str:
        """SHA-256 hash of the canonical payload for audit."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for transmission."""
        return {
            "header": {
                "protocol_version": self.protocol_version,
                "message_type": self.message_type.value,
                "sender_id": self.sender_id,
                "recipient_id": self.recipient_id,
                "timestamp": self.timestamp,
                "nonce": self.nonce,
                "message_id": self.message_id,
            },
            "payload": self.payload,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtocolMessage":
        """Deserialise from received transmission."""
        header = data.get("header", {})
        return cls(
            message_type=MessageType(header.get("message_type", "ERROR")),
            sender_id=header.get("sender_id", "unknown"),
            recipient_id=header.get("recipient_id", "the-last-bastion"),
            protocol_version=header.get("protocol_version", PROTOCOL_VERSION),
            timestamp=header.get("timestamp", ""),
            nonce=header.get("nonce", ""),
            message_id=header.get("message_id", ""),
            payload=data.get("payload", {}),
            signature=data.get("signature", ""),
        )


def validate_message_freshness(msg: ProtocolMessage) -> bool:
    """
    Checks if a message is fresh enough to process.

    Rejects messages older than MAX_MESSAGE_AGE_SECONDS to
    prevent replay attacks with stale messages.
    """
    try:
        msg_time = datetime.fromisoformat(msg.timestamp)
        now = datetime.utcnow()
        age = (now - msg_time).total_seconds()
        return abs(age) <= MAX_MESSAGE_AGE_SECONDS
    except (ValueError, TypeError):
        return False


def validate_protocol_version(msg: ProtocolMessage) -> bool:
    """
    Checks protocol version compatibility.

    Accepts messages from the same major version (e.g., 1.x.x).
    """
    try:
        msg_major = int(msg.protocol_version.split(".")[0])
        our_major = int(PROTOCOL_VERSION.split(".")[0])
        return msg_major == our_major
    except (ValueError, IndexError):
        return False


def build_error_response(
    original: ProtocolMessage,
    error_code: str,
    error_message: str,
) -> ProtocolMessage:
    """Creates a standardised error response to a message."""
    return ProtocolMessage(
        message_type=MessageType.ERROR,
        sender_id="the-last-bastion",
        recipient_id=original.sender_id,
        payload={
            "error_code": error_code,
            "error_message": error_message,
            "original_message_id": original.message_id,
        },
    )


def build_ack_response(original: ProtocolMessage) -> ProtocolMessage:
    """Creates a standardised acknowledgement."""
    return ProtocolMessage(
        message_type=MessageType.ACK,
        sender_id="the-last-bastion",
        recipient_id=original.sender_id,
        payload={
            "acknowledged_message_id": original.message_id,
            "status": "received",
        },
    )
