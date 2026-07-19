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
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Tuple

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
from lastbastion.crypto import verify_signature_raw

# Hard dependency -- no fallback DH or encryption
try:
    from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, Box
    from nacl.secret import SecretBox
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
    """Seen-nonce tracker. Rejects duplicate nonces within the retention
    window to prevent replay attacks across different responders.

    Backed by Redis when available (SET NX EX — atomic, shared across every
    process/replica), falling back to an in-memory dict otherwise. The
    in-memory-only fallback is NOT safe once you run more than one Border
    Police / AgentSocket process: a nonce seen by process A is invisible to
    process B, so replay protection silently stops working across replicas.

    ttl_seconds controls how long a seen value is remembered before being
    purged and becoming replayable again. The 30s default is correct for
    handshake nonces (HANDSHAKE_FRESHNESS_SECONDS -- a HELLO is only ever
    valid within that freshness window anyway, so nothing is lost by
    forgetting it after 30s). It is WRONG for anything with a longer natural
    lifetime -- e.g. session-resumption ticket IDs, which stay redeemable
    for DEFAULT_TICKET_TTL_SECONDS (1 hour) in resumption.py. Using the 30s
    default there meant a ticket was only actually protected against replay
    for the first 30 seconds after redemption, then silently became
    replayable again for the remaining ~59 minutes of its life with no
    private key needed -- ResumptionResponder now passes a TTL matching the
    ticket lifetime instead of relying on this default.
    """

    def __init__(self, max_size: int = NONCE_CACHE_MAX, ttl_seconds: int = HANDSHAKE_FRESHNESS_SECONDS):
        self._seen: dict[bytes, float] = {}  # nonce → timestamp (in-memory fallback)
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._redis = None
        self._redis_prefix = "bastion:handshake_nonce:"
        self._init_redis()

    def _init_redis(self) -> None:
        """Try to connect to Redis for cross-process nonce storage."""
        try:
            import os
            import redis
            host = os.getenv("REDIS_HOST", "localhost")
            port = int(os.getenv("REDIS_PORT", "6379"))
            self._redis = redis.Redis(host=host, port=port, db=0, socket_timeout=2)
            self._redis.ping()
        except Exception:
            self._redis = None  # Fall back to in-memory (single-process only)
            logging.getLogger("BastionNonceRegistry").warning(
                "NonceRegistry: Redis unavailable, falling back to in-memory "
                "replay tracking -- a nonce/ticket seen by this process is "
                "invisible to any other worker process or replica. Replay "
                "protection silently stops working across process boundaries "
                "until Redis is reachable. Fine for a single-process "
                "deployment; not fine behind more than one uvicorn worker "
                "or multiple replicas."
            )

    def check_and_record(self, nonce: bytes) -> bool:
        """Returns True if nonce is fresh (not seen before). Records it.
        Returns False if nonce was already seen (replay attempt).
        Thread-safe via internal lock."""
        if self._redis:
            try:
                key = self._redis_prefix + nonce.hex()
                was_set = self._redis.set(key, "1", nx=True, ex=self._ttl_seconds)
                return bool(was_set)
            except Exception:
                pass  # Redis hiccup — fall through to in-memory for this call

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
        """Remove nonces older than the retention window. Caller must hold _lock."""
        cutoff = time.time() - self._ttl_seconds
        expired = [n for n, t in self._seen.items() if t < cutoff]
        for n in expired:
            del self._seen[n]

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


# Global nonce registry (shared across all responders in the same process).
# TTL matches HANDSHAKE_FRESHNESS_SECONDS -- only appropriate for handshake
# nonces. Do NOT reuse this instance for ticket single-use tracking (see
# NonceRegistry's docstring); ResumptionResponder builds its own dedicated
# instance with a TTL matching the actual ticket lifetime.
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
    _box: object = field(default=None, repr=False, compare=False)

    def _get_box(self) -> SecretBox:
        # SecretBox is stateless/reusable for many encrypt/decrypt calls with
        # the same key -- that's its designed usage. Constructing a fresh one
        # per call (the original implementation) was measured as a real,
        # avoidable cost on every single DATA frame; caching it here changes
        # nothing about the crypto itself, only how many times the wrapper
        # object gets built.
        if self._box is None:
            self._box = SecretBox(self.shared_key)
        return self._box

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt payload with session key (NaCl SecretBox: XSalsa20 + Poly1305)."""
        if not self._alive:
            raise RuntimeError("Session keys destroyed")
        return bytes(self._get_box().encrypt(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt payload with session key."""
        if not self._alive:
            raise RuntimeError("Session keys destroyed")
        return bytes(self._get_box().decrypt(ciphertext))

    def destroy(self):
        """Zero out key material."""
        self.shared_key = b"\x00" * 32
        self._alive = False
        self._box = None


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
        # `nonce_registry or _global_nonce_registry` looks right but silently
        # discards a caller-supplied registry whenever it's falsy -- and
        # NonceRegistry defines __len__, so any *freshly constructed* (empty)
        # registry passed in here is falsy and gets replaced by the global
        # one, defeating the entire point of passing a dedicated instance.
        self._nonce_registry = nonce_registry if nonce_registry is not None else _global_nonce_registry

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


# ---------------------------------------------------------------------------
# DIRECT Mode -- no passport office required
# ---------------------------------------------------------------------------
#
# Two agents holding their own persistent Ed25519 keypairs can authenticate
# each other directly, with no issuer/trust-authority in the loop. Security
# comes from key PINNING (see trust_store.PeerTrustStore) -- the same trust
# model SSH uses for host keys, not the same model as a CA-issued certificate.
# This exists for exactly the case where no Bastion verification authority
# exists (yet), but two agents still want a fast, encrypted, mutually
# authenticated channel.
#
# Security note: the responder verifies the frame's Ed25519 signature against
# whatever public_key the HELLO payload CLAIMS (there's no other way to check
# it — the key itself is what's being introduced). That is only safe because
# of what happens next: the claimed (agent_id, public_key) pair is checked
# against the trust store, which independently decides whether to accept it
# (already pinned + matches, or first contact under TOFU) or reject it
# (pinned to a DIFFERENT key = impersonation signal, never silently accepted).
# Skipping that second, independent check is exactly the bug that was found
# and fixed in core/border_agent.py's PASSPORT-mode handling.
#
# Known limitation, inherent to TOFU (same as SSH host keys): first contact
# is trust-on-faith. If an attacker wins the race to be the FIRST party to
# claim a given agent_id (before the real agent ever connects), their key
# gets pinned instead of the real one, and the real agent is later rejected
# as the "impersonator." TOFU protects every connection AFTER the first one,
# not the first one itself. For agents where that first-contact risk isn't
# acceptable, pre-populate the trust store via PeerTrustStore.pin() using a
# key learned out-of-band (e.g. from an A2A Agent Card fetched over TLS)
# instead of relying on tofu=True.

def build_direct_hello(
    agent_id: str,
    public_key: str,
    signing_key: str,
    ephemeral_pub: bytes,
) -> BastionFrame:
    """Build a DIRECT-mode HELLO frame -- no passport, just the sender's own identity."""
    payload_data = {
        "mode": "direct",
        "agent_id": agent_id,
        "public_key": public_key,
        "ephemeral_pub": ephemeral_pub,
        "supported_versions": [PROTOCOL_VERSION],
        "nonce": os.urandom(32),
        "timestamp": time.time(),
    }
    payload = serialize_payload(payload_data)
    # passport_hash header field has no passport to hash in DIRECT mode --
    # filled with a hash of agent_id purely for observability/logging, never
    # trusted as an identity proof on its own
    encoder = FrameEncoder(compute_passport_hash(agent_id), signing_key)
    return encoder.encode(FrameType.HELLO, payload)


def build_direct_hello_ack(
    agent_id: str,
    public_key: str,
    signing_key: str,
    ephemeral_pub: bytes,
    peer_nonce: bytes,
    chosen_version: int = PROTOCOL_VERSION,
    session_ticket: Optional[bytes] = None,
) -> BastionFrame:
    """
    Build a DIRECT-mode HELLO_ACK frame.

    session_ticket is optional -- only present if the responder is configured
    with a ticket_key (see DirectHandshakeResponder). Lets the client resume
    this session later without a full handshake.
    """
    payload_data = {
        "mode": "direct",
        "agent_id": agent_id,
        "public_key": public_key,
        "ephemeral_pub": ephemeral_pub,
        "chosen_version": chosen_version,
        "nonce": os.urandom(32),
        "peer_nonce": peer_nonce,
        "timestamp": time.time(),
        "session_ticket": session_ticket,
    }
    payload = serialize_payload(payload_data)
    encoder = FrameEncoder(compute_passport_hash(agent_id), signing_key)
    return encoder.encode(FrameType.HELLO_ACK, payload)


def _parse_direct_payload(frame: BastionFrame, expected_type: FrameType) -> dict:
    """Shared payload parsing for DIRECT-mode HELLO/HELLO_ACK (structure + freshness only)."""
    if frame.msg_type != expected_type:
        raise ValueError(f"Expected 0x{expected_type:02x}, got 0x{frame.msg_type:02x}")
    data = deserialize_payload(frame.payload)
    if data.get("mode") != "direct":
        raise ValueError("Not a DIRECT-mode frame")

    timestamp = data.get("timestamp", 0)
    age = abs(time.time() - timestamp)
    if age > HANDSHAKE_FRESHNESS_SECONDS:
        raise ValueError(f"DIRECT-mode frame too old: {age:.1f}s (max {HANDSHAKE_FRESHNESS_SECONDS}s)")

    for key in ("ephemeral_pub", "nonce", "peer_nonce"):
        if isinstance(data.get(key), list):
            data[key] = bytes(data[key])
    return data


@dataclass
class DirectHandshakeResult:
    """Result of a successful DIRECT-mode handshake."""
    session_keys: SessionKeys
    peer_agent_id: str
    peer_public_key: str
    chosen_version: int
    ephemeral_keypair: EphemeralKeyPair
    trust_pin: object  # trust_store.PinResult — tells the caller if this was first contact (TOFU)
    resumption_secret: bytes = b""  # Derived from session_keys.shared_key -- store alongside session_ticket
    session_ticket: Optional[bytes] = None  # None if the peer didn't offer resumption

    def finalize(self):
        """Destroy ephemeral keys after session setup is complete."""
        self.ephemeral_keypair.destroy()


class DirectHandshakeInitiator:
    """Client-side DIRECT-mode handshake: send HELLO, receive HELLO_ACK, derive session key."""

    def __init__(self, agent_id: str, public_key: str, signing_key: str, trust_store):
        """
        Args:
            agent_id: This agent's identifier
            public_key: This agent's own Ed25519 public key (hex)
            signing_key: This agent's own Ed25519 private key (hex) — signs the HELLO
            trust_store: A trust_store.PeerTrustStore used to pin/verify the peer's key
        """
        self.agent_id = agent_id
        self.public_key = public_key
        self.signing_key = signing_key
        self.trust_store = trust_store
        self.ephemeral = generate_ephemeral_keypair()
        self._hello_nonce: bytes = b""

    def build_hello(self) -> BastionFrame:
        """Build the HELLO frame to send."""
        frame = build_direct_hello(self.agent_id, self.public_key, self.signing_key, self.ephemeral.public_key)
        data = deserialize_payload(frame.payload)
        nonce = data["nonce"]
        self._hello_nonce = nonce if isinstance(nonce, bytes) else bytes(nonce)
        return frame

    def complete(self, hello_ack_frame: BastionFrame, tofu: bool = True) -> DirectHandshakeResult:
        """Process HELLO_ACK, verify + pin the peer's key, and derive session keys."""
        raw_data = deserialize_payload(hello_ack_frame.payload)
        claimed_pub = raw_data.get("public_key", "")
        if not claimed_pub:
            raise ValueError("DIRECT-mode HELLO_ACK missing public_key")

        # Verify the frame was really signed by whoever holds the private key
        # matching the claimed public key. Safe ONLY because trust_store below
        # independently decides whether that claimed key is the right one.
        if not verify_signature_raw(
            hello_ack_frame.signable_bytes, hello_ack_frame.signature, claimed_pub
        ):
            raise ValueError("DIRECT-mode HELLO_ACK signature verification failed")

        ack_data = _parse_direct_payload(hello_ack_frame, FrameType.HELLO_ACK)
        if ack_data.get("peer_nonce") != self._hello_nonce:
            raise ValueError("HELLO_ACK nonce mismatch -- possible replay")

        peer_agent_id = ack_data["agent_id"]
        pin_result = self.trust_store.verify_or_pin(peer_agent_id, claimed_pub, tofu=tofu)
        if not pin_result.accepted:
            raise ValueError(
                f"DIRECT-mode trust check failed for {peer_agent_id}: {pin_result.reason}"
            )

        peer_ephemeral = ack_data["ephemeral_pub"]
        shared_secret = self.ephemeral.derive_shared_key(peer_ephemeral)
        session_keys = SessionKeys(shared_key=shared_secret)

        from lastbastion.protocol.resumption import derive_resumption_secret
        resumption_secret = derive_resumption_secret(shared_secret)

        session_ticket = ack_data.get("session_ticket")
        if isinstance(session_ticket, list):
            session_ticket = bytes(session_ticket)

        return DirectHandshakeResult(
            session_keys=session_keys,
            peer_agent_id=peer_agent_id,
            peer_public_key=claimed_pub,
            chosen_version=ack_data.get("chosen_version", PROTOCOL_VERSION),
            ephemeral_keypair=self.ephemeral,
            trust_pin=pin_result,
            resumption_secret=resumption_secret,
            session_ticket=session_ticket,
        )


class DirectHandshakeResponder:
    """Server-side DIRECT-mode handshake: receive HELLO, send HELLO_ACK, derive session key."""

    def __init__(
        self,
        agent_id: str,
        public_key: str,
        signing_key: str,
        trust_store,
        nonce_registry: Optional[NonceRegistry] = None,
        ticket_key: Optional[bytes] = None,
    ):
        """
        Args:
            agent_id: This agent's identifier
            public_key: This agent's own Ed25519 public key (hex)
            signing_key: This agent's own Ed25519 private key (hex) — signs the HELLO_ACK
            trust_store: A trust_store.PeerTrustStore used to pin/verify the peer's key
            nonce_registry: Optional NonceRegistry for replay detection (uses global if not provided)
            ticket_key: Optional symmetric key (crypto.load_or_create_symmetric_key)
                — when set, every successful handshake also issues a session
                ticket in the HELLO_ACK so the peer can resume later without a
                full handshake. Omit to run DIRECT mode without resumption.
        """
        self.agent_id = agent_id
        self.public_key = public_key
        self.signing_key = signing_key
        self.trust_store = trust_store
        self.ephemeral = generate_ephemeral_keypair()
        # See HandshakeResponder's __init__ for why this must be `is not
        # None`, not `or` -- a freshly-constructed (empty) NonceRegistry is
        # falsy (it defines __len__) and `or` would silently discard it.
        self._nonce_registry = nonce_registry if nonce_registry is not None else _global_nonce_registry
        self.ticket_key = ticket_key

    def process_hello(
        self, hello_frame: BastionFrame, tofu: bool = True
    ) -> Tuple[BastionFrame, DirectHandshakeResult]:
        """
        Process incoming DIRECT-mode HELLO frame. Returns (HELLO_ACK frame, DirectHandshakeResult).
        Raises ValueError if the peer is rejected or the nonce was replayed.
        """
        raw_data = deserialize_payload(hello_frame.payload)
        claimed_pub = raw_data.get("public_key", "")
        if not claimed_pub:
            raise ValueError("DIRECT-mode HELLO missing public_key")

        if not verify_signature_raw(
            hello_frame.signable_bytes, hello_frame.signature, claimed_pub
        ):
            raise ValueError("DIRECT-mode HELLO signature verification failed")

        hello_data = _parse_direct_payload(hello_frame, FrameType.HELLO)

        # Anti-replay: reject duplicate nonces
        if not self._nonce_registry.check_and_record(hello_data["nonce"]):
            raise ValueError("HELLO nonce replay detected -- duplicate nonce rejected")

        peer_agent_id = hello_data["agent_id"]
        pin_result = self.trust_store.verify_or_pin(peer_agent_id, claimed_pub, tofu=tofu)
        if not pin_result.accepted:
            raise ValueError(
                f"DIRECT-mode trust check failed for {peer_agent_id}: {pin_result.reason}"
            )

        supported = hello_data.get("supported_versions", [PROTOCOL_VERSION])
        if PROTOCOL_VERSION not in supported:
            raise ValueError(f"No compatible version (peer supports {supported})")

        peer_ephemeral = hello_data["ephemeral_pub"]
        shared_secret = self.ephemeral.derive_shared_key(peer_ephemeral)
        session_keys = SessionKeys(shared_key=shared_secret)

        from lastbastion.protocol.resumption import derive_resumption_secret, issue_ticket
        resumption_secret = derive_resumption_secret(shared_secret)

        session_ticket = None
        if self.ticket_key is not None:
            session_ticket = issue_ticket(
                self.ticket_key, peer_agent_id, claimed_pub, resumption_secret,
            )

        ack_frame = build_direct_hello_ack(
            self.agent_id,
            self.public_key,
            self.signing_key,
            self.ephemeral.public_key,
            peer_nonce=hello_data["nonce"],
            session_ticket=session_ticket,
        )

        result = DirectHandshakeResult(
            session_keys=session_keys,
            peer_agent_id=peer_agent_id,
            peer_public_key=claimed_pub,
            chosen_version=PROTOCOL_VERSION,
            ephemeral_keypair=self.ephemeral,
            trust_pin=pin_result,
            resumption_secret=resumption_secret,
            session_ticket=session_ticket,
        )
        return ack_frame, result


# ---------------------------------------------------------------------------
# Session Resumption (RESUME / RESUME_ACK)
# ---------------------------------------------------------------------------
#
# Works identically for a session that started in PASSPORT mode or DIRECT
# mode -- resumption only needs (agent_id, public_key, resumption_secret),
# not the original passport itself. See resumption.py for the ticket crypto
# and the reasoning behind it (forward secrecy across resumptions, single-use
# tickets, rotation).

def build_resume(ticket: bytes, client_nonce: bytes) -> BastionFrame:
    """Build a RESUME frame -- presents a prior session's ticket instead of a full HELLO."""
    payload_data = {
        "ticket": ticket,
        "client_nonce": client_nonce,
        "timestamp": time.time(),
    }
    payload = serialize_payload(payload_data)
    # RESUME carries no Ed25519 signature -- the encrypted ticket itself IS
    # the credential (only the server that issued it can decrypt it)
    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE, "")
    return encoder.encode(FrameType.RESUME, payload)


def parse_resume(frame: BastionFrame) -> dict:
    """Parse a RESUME frame payload."""
    if frame.msg_type != FrameType.RESUME:
        raise ValueError(f"Expected RESUME, got 0x{frame.msg_type:02x}")
    data = deserialize_payload(frame.payload)
    for key in ("ticket", "client_nonce"):
        if isinstance(data.get(key), list):
            data[key] = bytes(data[key])
    timestamp = data.get("timestamp", 0)
    age = abs(time.time() - timestamp)
    if age > HANDSHAKE_FRESHNESS_SECONDS:
        raise ValueError(f"RESUME frame too old: {age:.1f}s (max {HANDSHAKE_FRESHNESS_SECONDS}s)")
    return data


@dataclass
class ResumeResult:
    """Result of a successful session resumption."""
    session_keys: SessionKeys
    peer_agent_id: str
    peer_public_key: str
    next_ticket: bytes  # Rotated ticket to store for the FOLLOWING reconnect


class ResumptionResponder:
    """
    Server-side resumption handler.

    Needs the server's ticket_key (symmetric, generated once via
    crypto.load_or_create_symmetric_key, never sent over the wire) and a
    NonceRegistry to enforce single-use redemption.
    """

    def __init__(
        self,
        ticket_key: bytes,
        nonce_registry: Optional[NonceRegistry] = None,
        revocation_check=None,
        ticket_ttl_seconds: Optional[int] = None,
    ):
        """
        Args:
            ticket_key: This server's symmetric ticket-encryption key
            nonce_registry: Optional NonceRegistry for single-use enforcement.
                If not provided, a DEDICATED registry is built (never the
                30s-TTL global handshake-nonce registry -- reusing that one
                here meant a redeemed ticket was only actually protected
                against replay for 30 seconds, then silently replayable again
                for the rest of its ~1 hour life with no private key needed).
                If you pass your own registry explicitly, size its ttl_seconds
                to match (or exceed) whatever ttl_seconds you pass to
                issue_ticket() -- a shorter TTL here reopens the same hole.
            revocation_check: Optional callable(agent_id) -> bool, True if
                agent_id is currently revoked. A resumed session skips full
                passport/trust re-verification by design, so if you need live
                revocation to apply to resumed sessions too (not just fresh
                handshakes), wire it here. Kept as a pluggable callback rather
                than importing a specific app's DB layer directly, since the
                SDK itself has no opinion on where revocation state lives.
            ticket_ttl_seconds: Must match the ttl_seconds this server's
                issue_ticket() calls use (defaults to
                resumption.DEFAULT_TICKET_TTL_SECONDS, same as issue_ticket's
                own default). Only used to size the dedicated registry's
                retention window when nonce_registry isn't provided.
        """
        from lastbastion.protocol.resumption import DEFAULT_TICKET_TTL_SECONDS

        self.ticket_key = ticket_key
        # `is not None`, not `or` -- see HandshakeResponder.__init__ for why:
        # a freshly-constructed (empty) NonceRegistry is falsy.
        self._nonce_registry = nonce_registry if nonce_registry is not None else NonceRegistry(
            ttl_seconds=ticket_ttl_seconds or DEFAULT_TICKET_TTL_SECONDS,
        )
        self.revocation_check = revocation_check
        if revocation_check is None:
            logging.getLogger("BastionResumption").warning(
                "ResumptionResponder created with no revocation_check — resumed "
                "sessions will NOT be checked against live revocation status for "
                "up to the ticket's TTL. Wire revocation_check if agents can be "
                "revoked mid-session and that should take effect before the "
                "ticket naturally expires."
            )

    def process_resume(self, resume_frame: BastionFrame) -> Tuple[BastionFrame, ResumeResult]:
        """
        Process an incoming RESUME frame. Returns (RESUME_ACK frame, ResumeResult).
        Raises ValueError if the ticket is invalid, expired, already redeemed,
        or the agent has been revoked.
        """
        from lastbastion.protocol.resumption import (
            redeem_ticket,
            derive_resumed_session_key,
            issue_ticket,
        )

        data = parse_resume(resume_frame)
        ticket = data["ticket"]
        client_nonce = data["client_nonce"]

        try:
            claims = redeem_ticket(self.ticket_key, ticket)
        except ValueError as e:
            raise ValueError(f"TICKET_INVALID: {e}")

        # Single-use enforcement -- this exact ticket must never be redeemed twice
        if not self._nonce_registry.check_and_record(claims.ticket_id):
            raise ValueError("TICKET_REPLAYED: ticket already redeemed")

        if self.revocation_check is not None and self.revocation_check(claims.agent_id):
            raise ValueError(f"PEER_REVOKED: {claims.agent_id} has been revoked")

        server_nonce = os.urandom(32)
        session_key = derive_resumed_session_key(
            claims.resumption_secret, client_nonce, server_nonce
        )
        session_keys = SessionKeys(shared_key=session_key)

        # Rotate: issue a fresh ticket bound to the same resumption_secret for
        # the NEXT reconnect, so a stolen ticket only ever grants one resumption
        next_ticket = issue_ticket(
            self.ticket_key, claims.agent_id, claims.public_key, claims.resumption_secret,
        )

        ack_payload = serialize_payload({
            "server_nonce": server_nonce,
            "next_ticket": next_ticket,
            "timestamp": time.time(),
        })
        encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE, "")
        ack_frame = encoder.encode(FrameType.RESUME_ACK, ack_payload)

        result = ResumeResult(
            session_keys=session_keys,
            peer_agent_id=claims.agent_id,
            peer_public_key=claims.public_key,
            next_ticket=next_ticket,
        )
        return ack_frame, result


def complete_resume(
    ack_frame: BastionFrame, client_nonce: bytes, resumption_secret: bytes,
) -> Tuple[SessionKeys, bytes]:
    """
    Client-side: derives the same session key the server derived from a
    RESUME_ACK, and extracts the next (rotated) ticket to store for the
    following reconnect.

    Returns (session_keys, next_ticket).
    """
    from lastbastion.protocol.resumption import derive_resumed_session_key

    if ack_frame.msg_type != FrameType.RESUME_ACK:
        raise ValueError(f"Expected RESUME_ACK, got 0x{ack_frame.msg_type:02x}")

    data = deserialize_payload(ack_frame.payload)
    server_nonce = data["server_nonce"]
    if isinstance(server_nonce, list):
        server_nonce = bytes(server_nonce)
    next_ticket = data["next_ticket"]
    if isinstance(next_ticket, list):
        next_ticket = bytes(next_ticket)

    session_key = derive_resumed_session_key(resumption_secret, client_nonce, server_nonce)
    return SessionKeys(shared_key=session_key), next_ticket
