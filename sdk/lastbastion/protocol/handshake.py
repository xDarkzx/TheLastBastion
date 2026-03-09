"""
Bastion Protocol -- Handshake (HELLO / HELLO_ACK).

Performs mutual authentication and session key derivation:
1. Initiator sends HELLO with signed passport envelope + ephemeral X25519 public key + nonce + timestamp
2. Responder verifies passport, checks freshness, sends HELLO_ACK with its own passport + ephemeral key
3. Both sides derive a shared session key via X25519 Diffie-Hellman
4. Ephemeral keys are destroyed when connection closes (forward secrecy)

Passport format: Signed binary envelope (MessagePack + Ed25519 signature).
No JWT in the binary protocol — JWT is only used in the HTTP API layer.

Hard dependencies: pynacl (X25519 DH + SecretBox encryption), msgpack.
"""

import os
import time
import hashlib
import threading
from dataclasses import dataclass
from typing import Optional, Tuple, Set

from lastbastion.protocol.frames import (
    BastionFrame,
    FrameType,
    FrameEncoder,
    PROTOCOL_VERSION,
    PASSPORT_HASH_SIZE,
    serialize_payload,
    deserialize_payload,
    compute_passport_hash,
)
from lastbastion.passport import AgentPassport

# Hard dependency -- no fallback DH or encryption
try:
    from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, Box
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random
except ImportError:
    raise ImportError(
        "Bastion Protocol requires PyNaCl for X25519 DH and SecretBox encryption. "
        "Install: pip install pynacl"
    )


# Handshake freshness window
HANDSHAKE_FRESHNESS_SECONDS = 30

# Nonce anti-replay: maximum number of seen nonces before oldest are evicted
NONCE_CACHE_MAX = 10_000


# ---------------------------------------------------------------------------
# Nonce Registry — prevents cross-session replay within freshness window
# ---------------------------------------------------------------------------

class NonceRegistry:
    """Thread-safe seen-nonce tracker. Rejects duplicate nonces within the
    freshness window to prevent replay attacks across different responders.

    Nonces older than HANDSHAKE_FRESHNESS_SECONDS are automatically purged.
    """

    def __init__(self, max_size: int = NONCE_CACHE_MAX):
        self._seen: dict[bytes, float] = {}  # nonce → timestamp
        self._max_size = max_size
        self._lock = threading.Lock()

    def check_and_record(self, nonce: bytes) -> bool:
        """Returns True if nonce is fresh (not seen before). Records it.
        Returns False if nonce was already seen (replay attempt).
        Thread-safe via internal lock."""
        with self._lock:
            self._purge_expired()

            if nonce in self._seen:
                return False  # Replay detected

            # Evict oldest if at capacity
            if len(self._seen) >= self._max_size:
                oldest_key = min(self._seen, key=self._seen.get)
                del self._seen[oldest_key]

            self._seen[nonce] = time.time()
            return True

    def _purge_expired(self):
        """Remove nonces older than freshness window. Caller must hold _lock."""
        cutoff = time.time() - HANDSHAKE_FRESHNESS_SECONDS
        expired = [n for n, t in self._seen.items() if t < cutoff]
        for n in expired:
            del self._seen[n]

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


# Global nonce registry (shared across all responders in the same process)
_global_nonce_registry = NonceRegistry()


# ---------------------------------------------------------------------------
# Ephemeral Key Pair
# ---------------------------------------------------------------------------

@dataclass
class EphemeralKeyPair:
    """X25519 key pair for session key derivation. Destroyed after use."""
    public_key: bytes  # 32 bytes
    _private_key: bytes  # 32 bytes (secret)

    def derive_shared_key(self, peer_public: bytes) -> bytes:
        """Derive 32-byte shared secret via X25519 Diffie-Hellman."""
        my_key = X25519PrivateKey(self._private_key)
        peer_key = X25519PublicKey(peer_public)
        box = Box(my_key, peer_key)
        return box.shared_key()

    def destroy(self):
        """Zero out private key material."""
        self._private_key = b"\x00" * 32


def generate_ephemeral_keypair() -> EphemeralKeyPair:
    """Generate a fresh X25519 key pair for this session."""
    private = X25519PrivateKey.generate()
    return EphemeralKeyPair(
        public_key=bytes(private.public_key),
        _private_key=bytes(private),
    )


# ---------------------------------------------------------------------------
# Session Crypto
# ---------------------------------------------------------------------------

@dataclass
class SessionKeys:
    """Derived session keys for encrypt/decrypt after handshake."""
    shared_key: bytes  # 32 bytes -- NaCl SecretBox key
    _alive: bool = True

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt payload with session key (NaCl SecretBox: XSalsa20 + Poly1305)."""
        if not self._alive:
            raise RuntimeError("Session keys destroyed")
        box = SecretBox(self.shared_key)
        return bytes(box.encrypt(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt payload with session key."""
        if not self._alive:
            raise RuntimeError("Session keys destroyed")
        box = SecretBox(self.shared_key)
        return bytes(box.decrypt(ciphertext))

    def destroy(self):
        """Zero out key material."""
        self.shared_key = b"\x00" * 32
        self._alive = False


# ---------------------------------------------------------------------------
# Handshake Messages
# ---------------------------------------------------------------------------

def build_hello(
    passport: AgentPassport,
    signing_key: str,
    ephemeral_pub: bytes,
) -> BastionFrame:
    """Build a HELLO frame for initiating a connection.

    Uses signed binary envelope (not JWT) for passport serialization.
    """
    passport_hash = compute_passport_hash(passport.passport_id)
    passport_signed = passport.to_signed_bytes(signing_key)

    payload_data = {
        "passport_signed": passport_signed,
        "ephemeral_pub": ephemeral_pub,
        "supported_versions": [PROTOCOL_VERSION],
        "nonce": os.urandom(32),
        "timestamp": time.time(),
    }
    payload = serialize_payload(payload_data)

    encoder = FrameEncoder(passport_hash, signing_key)
    return encoder.encode(FrameType.HELLO, payload)


def build_hello_ack(
    passport: AgentPassport,
    signing_key: str,
    ephemeral_pub: bytes,
    peer_nonce: bytes,
    chosen_version: int = PROTOCOL_VERSION,
) -> BastionFrame:
    """Build a HELLO_ACK frame for accepting a connection.

    Uses signed binary envelope (not JWT) for passport serialization.
    """
    passport_hash = compute_passport_hash(passport.passport_id)
    passport_signed = passport.to_signed_bytes(signing_key)

    payload_data = {
        "passport_signed": passport_signed,
        "ephemeral_pub": ephemeral_pub,
        "chosen_version": chosen_version,
        "nonce": os.urandom(32),
        "peer_nonce": peer_nonce,  # Echo back initiator's nonce
        "timestamp": time.time(),
    }
    payload = serialize_payload(payload_data)

    encoder = FrameEncoder(passport_hash, signing_key)
    return encoder.encode(FrameType.HELLO_ACK, payload)


def parse_hello(frame: BastionFrame) -> dict:
    """Parse a HELLO frame payload. Returns dict with passport_signed, ephemeral_pub, etc."""
    if frame.msg_type != FrameType.HELLO:
        raise ValueError(f"Expected HELLO, got 0x{frame.msg_type:02x}")
    data = deserialize_payload(frame.payload)

    # Validate timestamp freshness
    timestamp = data.get("timestamp", 0)
    age = abs(time.time() - timestamp)
    if age > HANDSHAKE_FRESHNESS_SECONDS:
        raise ValueError(
            f"HELLO too old: {age:.1f}s (max {HANDSHAKE_FRESHNESS_SECONDS}s)"
        )

    # Support both formats: signed bytes (v2) and JWT (v1 compat)
    passport_signed = data.get("passport_signed", b"")
    passport_jwt = data.get("passport_jwt", "")
    if isinstance(passport_signed, list):
        passport_signed = bytes(passport_signed)

    return {
        "passport_signed": passport_signed,
        "passport_jwt": passport_jwt,  # v1 backward compat
        "ephemeral_pub": data["ephemeral_pub"] if isinstance(data["ephemeral_pub"], bytes)
                         else bytes(data["ephemeral_pub"]),
        "supported_versions": data.get("supported_versions", [PROTOCOL_VERSION]),
        "nonce": data["nonce"] if isinstance(data["nonce"], bytes)
                 else bytes(data["nonce"]),
        "timestamp": timestamp,
    }


def parse_hello_ack(frame: BastionFrame, expected_nonce: bytes = b"") -> dict:
    """Parse a HELLO_ACK frame payload."""
    if frame.msg_type != FrameType.HELLO_ACK:
        raise ValueError(f"Expected HELLO_ACK, got 0x{frame.msg_type:02x}")
    data = deserialize_payload(frame.payload)

    # Validate timestamp freshness
    timestamp = data.get("timestamp", 0)
    age = abs(time.time() - timestamp)
    if age > HANDSHAKE_FRESHNESS_SECONDS:
        raise ValueError(
            f"HELLO_ACK too old: {age:.1f}s (max {HANDSHAKE_FRESHNESS_SECONDS}s)"
        )

    # Validate nonce echo (if we sent one)
    if expected_nonce:
        peer_nonce = data.get("peer_nonce", b"")
        if isinstance(peer_nonce, list):
            peer_nonce = bytes(peer_nonce)
        if peer_nonce != expected_nonce:
            raise ValueError("HELLO_ACK nonce mismatch -- possible replay")

    # Support both formats: signed bytes (v2) and JWT (v1 compat)
    passport_signed = data.get("passport_signed", b"")
    passport_jwt = data.get("passport_jwt", "")
    if isinstance(passport_signed, list):
        passport_signed = bytes(passport_signed)

    return {
        "passport_signed": passport_signed,
        "passport_jwt": passport_jwt,  # v1 backward compat
        "ephemeral_pub": data["ephemeral_pub"] if isinstance(data["ephemeral_pub"], bytes)
                         else bytes(data["ephemeral_pub"]),
        "chosen_version": data.get("chosen_version", PROTOCOL_VERSION),
        "nonce": data.get("nonce", b""),
        "peer_nonce": data.get("peer_nonce", b""),
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# Handshake Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class HandshakeResult:
    """Result of a successful handshake."""
    session_keys: SessionKeys
    peer_passport: AgentPassport
    peer_passport_hash: bytes
    chosen_version: int
    ephemeral_keypair: EphemeralKeyPair  # Caller should destroy after setup

    def finalize(self):
        """Destroy ephemeral keys after session setup is complete."""
        self.ephemeral_keypair.destroy()


class HandshakeInitiator:
    """Client-side handshake: send HELLO, receive HELLO_ACK, derive session key."""

    def __init__(self, passport: AgentPassport, signing_key: str, verify_key: str):
        """
        Args:
            passport: This agent's passport
            signing_key: Ed25519 private key hex for signing
            verify_key: Ed25519 public key hex for verifying peer's passport JWT (REQUIRED)
        """
        self.passport = passport
        self.signing_key = signing_key
        self.verify_key = verify_key
        self.ephemeral = generate_ephemeral_keypair()
        self._hello_nonce: bytes = b""

    def build_hello(self) -> BastionFrame:
        """Build the HELLO frame to send."""
        frame = build_hello(self.passport, self.signing_key, self.ephemeral.public_key)
        # Extract nonce from the frame we just built so we can verify it in HELLO_ACK
        data = deserialize_payload(frame.payload)
        nonce = data["nonce"]
        self._hello_nonce = nonce if isinstance(nonce, bytes) else bytes(nonce)
        return frame

    def complete(self, hello_ack_frame: BastionFrame) -> HandshakeResult:
        """Process HELLO_ACK and derive session keys."""
        ack_data = parse_hello_ack(hello_ack_frame, expected_nonce=self._hello_nonce)

        # Verify peer passport — prefer signed bytes, fall back to JWT
        if ack_data.get("passport_signed"):
            peer_passport = AgentPassport.from_signed_bytes(ack_data["passport_signed"], self.verify_key)
        else:
            peer_passport = AgentPassport.from_jwt(ack_data["passport_jwt"], self.verify_key)
        if peer_passport.is_expired():
            raise ValueError("Peer passport has expired -- handshake rejected")
        if peer_passport.verdict == "MALICIOUS":
            raise ValueError("Peer agent has MALICIOUS verdict -- handshake rejected")

        # Derive session key
        peer_ephemeral = ack_data["ephemeral_pub"]
        shared_secret = self.ephemeral.derive_shared_key(peer_ephemeral)
        session_keys = SessionKeys(shared_key=shared_secret)

        peer_hash = compute_passport_hash(peer_passport.passport_id)

        return HandshakeResult(
            session_keys=session_keys,
            peer_passport=peer_passport,
            peer_passport_hash=peer_hash,
            chosen_version=ack_data["chosen_version"],
            ephemeral_keypair=self.ephemeral,
        )


class HandshakeResponder:
    """Server-side handshake: receive HELLO, send HELLO_ACK, derive session key."""

    def __init__(
        self,
        passport: AgentPassport,
        signing_key: str,
        verify_key: str,
        min_trust_score: float = 0.0,
        nonce_registry: Optional[NonceRegistry] = None,
    ):
        """
        Args:
            passport: This agent's passport
            signing_key: Ed25519 private key hex for signing
            verify_key: Ed25519 public key hex for verifying peer's passport envelope (REQUIRED)
            min_trust_score: Minimum trust score to accept connections
            nonce_registry: Optional NonceRegistry for cross-session replay detection.
                            Uses global registry if not provided.
        """
        self.passport = passport
        self.signing_key = signing_key
        self.verify_key = verify_key
        self.min_trust_score = min_trust_score
        self.ephemeral = generate_ephemeral_keypair()
        self._nonce_registry = nonce_registry or _global_nonce_registry

    def process_hello(self, hello_frame: BastionFrame) -> Tuple[BastionFrame, HandshakeResult]:
        """
        Process incoming HELLO frame. Returns (HELLO_ACK frame, HandshakeResult).
        Raises ValueError if peer is rejected or nonce was replayed.
        """
        hello_data = parse_hello(hello_frame)

        # Anti-replay: reject duplicate nonces
        if not self._nonce_registry.check_and_record(hello_data["nonce"]):
            raise ValueError("HELLO nonce replay detected — duplicate nonce rejected")

        # Verify peer passport — prefer signed bytes, fall back to JWT
        if hello_data.get("passport_signed"):
            peer_passport = AgentPassport.from_signed_bytes(hello_data["passport_signed"], self.verify_key)
        else:
            peer_passport = AgentPassport.from_jwt(hello_data["passport_jwt"], self.verify_key)

        # Check expiry before trust
        if peer_passport.is_expired():
            raise ValueError("Peer passport has expired -- connection rejected")

        # Check trust
        if peer_passport.verdict == "MALICIOUS":
            raise ValueError("Peer agent has MALICIOUS verdict -- connection rejected")
        if peer_passport.trust_score < self.min_trust_score:
            raise ValueError(
                f"Peer trust score {peer_passport.trust_score} "
                f"below minimum {self.min_trust_score}"
            )

        # Version negotiation
        supported = hello_data.get("supported_versions", [PROTOCOL_VERSION])
        if PROTOCOL_VERSION not in supported:
            raise ValueError(f"No compatible version (peer supports {supported})")

        # Build HELLO_ACK with peer's nonce echoed back
        ack_frame = build_hello_ack(
            self.passport,
            self.signing_key,
            self.ephemeral.public_key,
            peer_nonce=hello_data["nonce"],
            chosen_version=PROTOCOL_VERSION,
        )

        # Derive session key
        peer_ephemeral = hello_data["ephemeral_pub"]
        shared_secret = self.ephemeral.derive_shared_key(peer_ephemeral)
        session_keys = SessionKeys(shared_key=shared_secret)

        peer_hash = compute_passport_hash(peer_passport.passport_id)

        result = HandshakeResult(
            session_keys=session_keys,
            peer_passport=peer_passport,
            peer_passport_hash=peer_hash,
            chosen_version=PROTOCOL_VERSION,
            ephemeral_keypair=self.ephemeral,
        )

        return ack_frame, result
