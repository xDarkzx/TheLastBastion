"""
Bastion Protocol -- Binary Frame Encoder/Decoder (v2).

Frame structure (116 bytes fixed overhead + N payload):
+----------+----------+-------+-----------+----------+-----------+---------+--------------+-----------+
| Version  | Msg Type | Flags | Passport  | Sequence | Timestamp | Payload |   Payload    | Signature |
| 1 byte   | 1 byte   | 2 B   |  Hash     |  Number  |  (usec)   | Length  |  (encrypted) | (Ed25519) |
|          |          |       |  32 bytes |  4 bytes | 8 bytes   | 4 bytes |  N bytes     | 64 bytes  |
+----------+----------+-------+-----------+----------+-----------+---------+--------------+-----------+

v2 changes from v1:
- Passport hash: 16B (truncated SHA-256) → 32B (full SHA-256, 256-bit collision resistance)
- Added flags field: 2 bytes for compression, fragmentation, priority signaling
- Added timestamp: 8 bytes (microseconds since epoch) for per-frame freshness enforcement
- Header: 26B → 52B (+26 bytes, protocol version bumped to 0x02)

Crypto stack (unchanged):
- Signing: Ed25519 via PyNaCl (128-bit security level)
- Encryption: NaCl SecretBox (XSalsa20-Poly1305) via session keys
- Key exchange: X25519 Diffie-Hellman (ephemeral, forward secrecy)
- Serialization: MessagePack (binary, no JSON fallback)

Hard dependencies: msgpack, pynacl.
"""

import struct
import hashlib
import time
from enum import IntEnum, IntFlag
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Hard dependencies -- no silent fallbacks
# ---------------------------------------------------------------------------

try:
    import msgpack
except ImportError:
    raise ImportError(
        "Bastion Protocol requires msgpack for binary serialization. "
        "Install: pip install msgpack"
    )

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder
    from nacl.exceptions import BadSignatureError
except ImportError:
    raise ImportError(
        "Bastion Protocol requires PyNaCl for Ed25519 signing. "
        "Install: pip install pynacl"
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 0x02
MAX_FRAME_SIZE = 16 * 1024 * 1024  # 16MB
PASSPORT_HASH_SIZE = 32  # Full SHA-256 (256-bit collision resistance, birthday bound 2^128)
FRAME_FLAGS_SIZE = 2     # 16-bit flags field
FRAME_TIMESTAMP_SIZE = 8 # Microseconds since epoch (uint64)
FRAME_HEADER_SIZE = 52   # version(1) + type(1) + flags(2) + passport_hash(32) + seq(4) + timestamp(8) + length(4)
SIGNATURE_SIZE = 64      # Ed25519 (128-bit security level)
FRAME_TIMEOUT_SECONDS = 5
PING_INTERVAL_SECONDS = 30
PING_TIMEOUT_SECONDS = 5
MAX_SEQUENCE = 0xFFFFFFFF  # 2^32 - 1 (~4.3 billion frames per session)
FRAME_FRESHNESS_SECONDS = 60  # Per-frame staleness window (post-handshake)


# ---------------------------------------------------------------------------
# Message Types
# ---------------------------------------------------------------------------

class FrameType(IntEnum):
    """Binary message types for the Bastion Protocol."""
    HELLO = 0x01
    HELLO_ACK = 0x02
    DATA = 0x03
    DATA_ACK = 0x04
    STREAM_START = 0x05
    STREAM_CHUNK = 0x06
    STREAM_END = 0x07
    PING = 0x08
    PONG = 0x09
    ERROR = 0x0A
    CLOSE = 0x0B


class FrameFlags(IntFlag):
    """Per-frame flags (16-bit field)."""
    NONE = 0x0000
    COMPRESSED = 0x0001     # Payload is zstd-compressed
    FRAGMENTED = 0x0002     # Multi-frame payload (fragment follows)
    PRIORITY = 0x0004       # High-priority frame (process before queued)
    FRESHNESS_STRICT = 0x0008  # Receiver MUST enforce FRAME_FRESHNESS_SECONDS
    # Bits 4-15: Reserved (must be 0)


# Frames that don't carry encrypted payloads
# ERROR is unencrypted so crypto failures can still report errors
UNENCRYPTED_TYPES = {FrameType.HELLO, FrameType.HELLO_ACK, FrameType.ERROR}

# Frames that must terminate the connection on error
FATAL_TYPES = {FrameType.ERROR}


# ---------------------------------------------------------------------------
# Error Codes
# ---------------------------------------------------------------------------

class ErrorCode(IntEnum):
    """Protocol-level error codes."""
    GENERIC = 1000
    INVALID_FRAME = 1001
    PASSPORT_FAILED = 1002
    TRUST_INSUFFICIENT = 1003
    SEQUENCE_VIOLATION = 1004
    FRAME_TOO_LARGE = 1005
    FRAME_TIMEOUT = 1006
    VERSION_UNSUPPORTED = 1007
    SIGNATURE_FAILED = 1008
    DECRYPTION_FAILED = 1009
    STREAM_HASH_MISMATCH = 1010
    PING_TIMEOUT = 1011
    BUDGET_EXHAUSTED = 1012
    AGENT_LOCKED_OUT = 1013


# Fatal error codes -- connection MUST be closed after these
FATAL_ERROR_CODES = {
    ErrorCode.PASSPORT_FAILED,
    ErrorCode.TRUST_INSUFFICIENT,
    ErrorCode.SEQUENCE_VIOLATION,
    ErrorCode.FRAME_TOO_LARGE,
    ErrorCode.FRAME_TIMEOUT,
    ErrorCode.VERSION_UNSUPPORTED,
    ErrorCode.SIGNATURE_FAILED,
    ErrorCode.DECRYPTION_FAILED,
    ErrorCode.AGENT_LOCKED_OUT,
}


# ---------------------------------------------------------------------------
# Frame Data Class
# ---------------------------------------------------------------------------

@dataclass
class BastionFrame:
    """A single Bastion Protocol v2 frame."""
    version: int = PROTOCOL_VERSION
    msg_type: int = FrameType.DATA
    flags: int = FrameFlags.NONE
    passport_hash: bytes = b"\x00" * PASSPORT_HASH_SIZE
    sequence: int = 0
    timestamp_us: int = 0  # Microseconds since epoch
    payload: bytes = b""
    signature: bytes = b"\x00" * SIGNATURE_SIZE

    @property
    def is_encrypted_type(self) -> bool:
        return self.msg_type not in UNENCRYPTED_TYPES

    @property
    def timestamp_seconds(self) -> float:
        """Timestamp as seconds (float) for comparison with time.time()."""
        return self.timestamp_us / 1_000_000.0

    @property
    def header_bytes(self) -> bytes:
        """Pack the fixed header (52 bytes)."""
        return struct.pack(
            ">BBH32sIQI",
            self.version,
            self.msg_type,
            self.flags,
            self.passport_hash[:PASSPORT_HASH_SIZE].ljust(PASSPORT_HASH_SIZE, b"\x00"),
            self.sequence,
            self.timestamp_us,
            len(self.payload),
        )

    @property
    def signable_bytes(self) -> bytes:
        """Everything that gets signed: header + payload."""
        return self.header_bytes + self.payload

    def to_bytes(self) -> bytes:
        """Serialize the complete frame to bytes."""
        return self.header_bytes + self.payload + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "BastionFrame":
        """Deserialize a frame from bytes. Raises ValueError on invalid data."""
        if len(data) < FRAME_HEADER_SIZE + SIGNATURE_SIZE:
            raise ValueError(
                f"Frame too short: {len(data)} bytes "
                f"(minimum {FRAME_HEADER_SIZE + SIGNATURE_SIZE})"
            )

        (version, msg_type, flags, passport_hash,
         sequence, timestamp_us, payload_length) = struct.unpack(
            ">BBH32sIQI", data[:FRAME_HEADER_SIZE]
        )

        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")

        if msg_type not in [t.value for t in FrameType]:
            raise ValueError(f"Unknown message type: 0x{msg_type:02x}")

        # Reject reserved flags (bits 4-15 must be 0 in current version)
        reserved_mask = 0xFFF0
        if flags & reserved_mask:
            raise ValueError(
                f"Reserved flags set: 0x{flags:04x} "
                f"(reserved bits: 0x{flags & reserved_mask:04x})"
            )

        if payload_length > MAX_FRAME_SIZE:
            raise ValueError(
                f"Payload too large: {payload_length} bytes "
                f"(max {MAX_FRAME_SIZE})"
            )

        expected_size = FRAME_HEADER_SIZE + payload_length + SIGNATURE_SIZE
        if len(data) < expected_size:
            raise ValueError(
                f"Frame incomplete: got {len(data)} bytes, "
                f"expected {expected_size}"
            )

        # Reject trailing data -- exact size match required
        if len(data) > expected_size:
            raise ValueError(
                f"Frame has trailing data: {len(data)} bytes, "
                f"expected exactly {expected_size}"
            )

        payload = data[FRAME_HEADER_SIZE:FRAME_HEADER_SIZE + payload_length]
        sig_start = FRAME_HEADER_SIZE + payload_length
        signature = data[sig_start:sig_start + SIGNATURE_SIZE]

        return cls(
            version=version,
            msg_type=msg_type,
            flags=flags,
            passport_hash=passport_hash,
            sequence=sequence,
            timestamp_us=timestamp_us,
            payload=payload,
            signature=signature,
        )


# ---------------------------------------------------------------------------
# Payload Serialization (MessagePack only -- no JSON fallback)
# ---------------------------------------------------------------------------

def serialize_payload(data: dict) -> bytes:
    """Serialize a dict to bytes using MessagePack."""
    return msgpack.packb(data, use_bin_type=True)


def deserialize_payload(data: bytes) -> dict:
    """Deserialize bytes to dict using MessagePack."""
    return msgpack.unpackb(data, raw=False)


# ---------------------------------------------------------------------------
# Passport Hash
# ---------------------------------------------------------------------------

def compute_passport_hash(passport_id: str) -> bytes:
    """Compute the 32-byte passport hash used in frame headers.

    Full SHA-256 digest (256 bits). No truncation.
    - Preimage resistance: 2^256
    - Birthday collision resistance: 2^128
    - Meets NIST SP 800-107 guidelines for new protocol designs.
    """
    return hashlib.sha256(passport_id.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# Frame Encoder
# ---------------------------------------------------------------------------

class FrameEncoder:
    """
    Builds and signs Bastion Protocol v2 frames.

    Tracks monotonically increasing sequence numbers.
    Stamps each frame with a microsecond timestamp.
    Signs every frame with the agent's Ed25519 key.
    Raises OverflowError when sequence exceeds 2^32-1 (reconnect required).
    """

    def __init__(self, passport_hash: bytes, signing_key: str = ""):
        """
        Args:
            passport_hash: 32-byte passport identifier (full SHA-256)
            signing_key: Ed25519 private key (hex) for signing frames
        """
        self._passport_hash = passport_hash[:PASSPORT_HASH_SIZE]
        self._signing_key = signing_key
        self._sequence = 0

    @property
    def next_sequence(self) -> int:
        """Get current sequence number (does not increment)."""
        return self._sequence

    def encode(
        self,
        msg_type: FrameType,
        payload: bytes = b"",
        encrypt_func=None,
        flags: int = FrameFlags.NONE,
    ) -> BastionFrame:
        """
        Build a signed frame with timestamp.

        Args:
            msg_type: The message type
            payload: Raw payload bytes (will be encrypted for post-handshake messages)
            encrypt_func: Optional encryption function (session_key based).
                          Called for encrypted message types only.
            flags: FrameFlags bitmask (default: NONE)

        Returns:
            Complete BastionFrame ready to send

        Raises:
            OverflowError: If sequence number exceeds 2^32-1
        """
        # Check sequence overflow
        if self._sequence > MAX_SEQUENCE:
            raise OverflowError(
                f"Sequence number overflow ({self._sequence} > {MAX_SEQUENCE}). "
                "Reconnect to reset sequence."
            )

        # Encrypt payload for post-handshake messages
        if msg_type not in UNENCRYPTED_TYPES and encrypt_func is not None:
            payload = encrypt_func(payload)

        # Check size
        if len(payload) > MAX_FRAME_SIZE:
            raise ValueError(
                f"Payload size {len(payload)} exceeds MAX_FRAME_SIZE {MAX_FRAME_SIZE}"
            )

        # Timestamp: microseconds since epoch
        timestamp_us = int(time.time() * 1_000_000)

        frame = BastionFrame(
            version=PROTOCOL_VERSION,
            msg_type=msg_type,
            flags=flags,
            passport_hash=self._passport_hash,
            sequence=self._sequence,
            timestamp_us=timestamp_us,
            payload=payload,
        )

        # Sign (covers header + payload, including timestamp — tamper-proof)
        frame.signature = self._sign(frame.signable_bytes)

        # Increment sequence for next frame
        self._sequence += 1

        return frame

    def encode_data(self, data: dict, encrypt_func=None) -> BastionFrame:
        """Convenience: serialize dict + encode as DATA frame."""
        payload = serialize_payload(data)
        return self.encode(FrameType.DATA, payload, encrypt_func)

    def encode_error(self, code: ErrorCode, message: str, encrypt_func=None) -> BastionFrame:
        """Build an ERROR frame. Always unencrypted so crypto failures can report."""
        payload = serialize_payload({"code": int(code), "message": message})
        # ERROR is in UNENCRYPTED_TYPES, so encrypt_func is never called
        return self.encode(FrameType.ERROR, payload, encrypt_func)

    def encode_ping(self, encrypt_func=None) -> BastionFrame:
        """Build a PING frame."""
        return self.encode(FrameType.PING, b"", encrypt_func)

    def encode_pong(self, encrypt_func=None) -> BastionFrame:
        """Build a PONG frame."""
        return self.encode(FrameType.PONG, b"", encrypt_func)

    def encode_close(self, encrypt_func=None) -> BastionFrame:
        """Build a CLOSE frame."""
        return self.encode(FrameType.CLOSE, b"", encrypt_func)

    def _sign(self, data: bytes) -> bytes:
        """Sign data with Ed25519. Returns exactly 64 bytes."""
        if not self._signing_key:
            return b"\x00" * SIGNATURE_SIZE

        sk = SigningKey(bytes.fromhex(self._signing_key))
        signed = sk.sign(data)
        sig = signed.signature
        if len(sig) != SIGNATURE_SIZE:
            raise ValueError(
                f"Ed25519 signature is {len(sig)} bytes, expected {SIGNATURE_SIZE}"
            )
        return sig


# ---------------------------------------------------------------------------
# Frame Decoder
# ---------------------------------------------------------------------------

class FrameDecoder:
    """
    Parses and verifies incoming Bastion Protocol v2 frames.

    Enforces:
    - Valid frame structure (no trailing data)
    - Monotonically increasing sequence numbers
    - Passport hash matches expected value (full 32-byte SHA-256)
    - Ed25519 signature verification
    - Per-frame timestamp freshness (when FRESHNESS_STRICT flag is set)
    - Reserved flags rejection
    - Max frame size
    """

    def __init__(
        self,
        expected_passport_hash: bytes = b"",
        verify_key: str = "",
        enforce_freshness: bool = True,
    ):
        """
        Args:
            expected_passport_hash: 32-byte hash that must match every frame
            verify_key: Ed25519 public key (hex) for signature verification
            enforce_freshness: If True, reject frames older than FRAME_FRESHNESS_SECONDS
        """
        self._expected_hash = expected_passport_hash[:PASSPORT_HASH_SIZE] if expected_passport_hash else b""
        self._verify_key = verify_key
        self._expected_sequence = 0
        self._handshake_complete = False
        self._enforce_freshness = enforce_freshness

    def set_peer_identity(self, passport_hash: bytes, verify_key: str):
        """Set peer identity after receiving HELLO/HELLO_ACK."""
        self._expected_hash = passport_hash[:PASSPORT_HASH_SIZE]
        self._verify_key = verify_key
        self._handshake_complete = True

    def decode(
        self,
        data: bytes,
        decrypt_func=None,
    ) -> BastionFrame:
        """
        Parse and verify a frame.

        Args:
            data: Raw frame bytes
            decrypt_func: Optional decryption function for encrypted payloads

        Returns:
            Verified BastionFrame

        Raises:
            ValueError: Frame is invalid (structure, sequence, signature, size,
                         trailing data, freshness, reserved flags)
        """
        frame = BastionFrame.from_bytes(data)

        # Verify passport hash (skip during handshake -- we don't know peer yet)
        if self._expected_hash and frame.msg_type not in UNENCRYPTED_TYPES:
            if frame.passport_hash[:len(self._expected_hash)] != self._expected_hash:
                raise ValueError(
                    f"Passport hash mismatch: expected {self._expected_hash.hex()}, "
                    f"got {frame.passport_hash.hex()}"
                )

        # Verify signature
        if self._verify_key:
            if not self._verify_signature(frame):
                raise ValueError("Signature verification failed")
        elif self._handshake_complete:
            # Post-handshake: signature verification is mandatory
            if frame.signature == b"\x00" * SIGNATURE_SIZE:
                raise ValueError("Unsigned frame after handshake")

        # Verify sequence (skip for unencrypted types -- they start the sequence)
        if frame.msg_type not in UNENCRYPTED_TYPES:
            if frame.sequence != self._expected_sequence:
                raise ValueError(
                    f"Sequence violation: expected {self._expected_sequence}, "
                    f"got {frame.sequence}"
                )
            self._expected_sequence += 1

        # Verify timestamp freshness
        # Enforced when: decoder flag is set OR frame has FRESHNESS_STRICT flag
        if frame.timestamp_us > 0 and frame.msg_type not in UNENCRYPTED_TYPES:
            check_freshness = (
                self._enforce_freshness or
                (frame.flags & FrameFlags.FRESHNESS_STRICT)
            )
            if check_freshness:
                now_us = int(time.time() * 1_000_000)
                age_seconds = (now_us - frame.timestamp_us) / 1_000_000.0
                # Reject frames from the future (clock skew > 5s)
                if age_seconds < -5.0:
                    raise ValueError(
                        f"Frame from the future: {-age_seconds:.1f}s ahead "
                        f"(max clock skew: 5s)"
                    )
                # Reject stale frames
                if age_seconds > FRAME_FRESHNESS_SECONDS:
                    raise ValueError(
                        f"Frame too stale: {age_seconds:.1f}s old "
                        f"(max {FRAME_FRESHNESS_SECONDS}s)"
                    )

        # Decrypt payload if needed
        if frame.is_encrypted_type and decrypt_func is not None and frame.payload:
            frame.payload = decrypt_func(frame.payload)

        return frame

    def _verify_signature(self, frame: BastionFrame) -> bool:
        """Verify frame signature with peer's Ed25519 public key."""
        if not self._verify_key:
            return True
        try:
            vk = VerifyKey(bytes.fromhex(self._verify_key))
            vk.verify(frame.signable_bytes, frame.signature)
            return True
        except (BadSignatureError, Exception):
            return False
