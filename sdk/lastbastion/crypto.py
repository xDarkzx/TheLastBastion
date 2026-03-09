"""
Last Bastion Crypto Utilities — Ed25519 signing, JWT, and signed envelopes.

Hard dependency: PyNaCl (libsodium) for Ed25519.
No HMAC fallback — fail-closed. If PyNaCl is not installed, all crypto
operations raise ImportError at module load time.

Provides two signing formats:
1. JWT (for HTTP API layer) — standard web tokens for REST endpoints
2. Signed Envelopes (for binary protocol) — MessagePack + raw Ed25519 signature
"""

import hashlib
import json
import time
import base64
from typing import Tuple, Dict, Any, Optional

# Hard dependency — no silent fallback. Fail at import, not at runtime.
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder
    from nacl.exceptions import BadSignatureError
except ImportError:
    raise ImportError(
        "Last Bastion SDK requires PyNaCl for Ed25519 cryptography. "
        "Install: pip install pynacl"
    )

# MessagePack for binary envelopes
try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False


def generate_keypair() -> Tuple[str, str]:
    """Generate an Ed25519 keypair. Returns (public_key_hex, private_key_hex)."""
    sk = SigningKey.generate()
    public_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
    private_hex = sk.encode(encoder=HexEncoder).decode()
    return public_hex, private_hex


def sign_bytes(data: bytes, private_key_hex: str) -> str:
    """Sign arbitrary bytes with Ed25519. Returns signature as hex string."""
    sk = SigningKey(bytes.fromhex(private_key_hex))
    signed = sk.sign(data)
    return signed.signature.hex()


def sign_bytes_raw(data: bytes, private_key_hex: str) -> bytes:
    """Sign arbitrary bytes with Ed25519. Returns raw 64-byte signature."""
    sk = SigningKey(bytes.fromhex(private_key_hex))
    signed = sk.sign(data)
    return signed.signature


def verify_signature(data: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature against data and public key."""
    try:
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(data, bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, Exception):
        return False


def verify_signature_raw(data: bytes, signature: bytes, public_key_hex: str) -> bool:
    """Verify a raw Ed25519 signature (bytes, not hex)."""
    try:
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(data, signature)
        return True
    except (BadSignatureError, Exception):
        return False


# ---------------------------------------------------------------------------
# Signed Envelopes — binary alternative to JWT for the wire protocol
# ---------------------------------------------------------------------------

def create_signed_envelope(claims: Dict[str, Any], private_key_hex: str) -> bytes:
    """
    Create a signed binary envelope: MessagePack payload + 64-byte Ed25519 signature.

    Format: [payload_bytes | signature_64B]

    Unlike JWT:
    - No JSON, no base64, no text encoding
    - Native binary (MessagePack handles bytes, floats, nested structures)
    - Signature is raw Ed25519 (64 bytes), not base64url-encoded

    Requires msgpack. Raises ImportError if not available.
    """
    if not HAS_MSGPACK:
        raise ImportError(
            "Signed envelopes require msgpack. Install: pip install msgpack"
        )
    payload = msgpack.packb(claims, use_bin_type=True)
    signature = sign_bytes_raw(payload, private_key_hex)
    return payload + signature


def verify_signed_envelope(envelope: bytes, public_key_hex: str) -> Dict[str, Any]:
    """
    Verify and decode a signed binary envelope.

    Returns the claims dict if signature is valid.
    Raises ValueError if signature fails or envelope is malformed.
    """
    if not HAS_MSGPACK:
        raise ImportError(
            "Signed envelopes require msgpack. Install: pip install msgpack"
        )
    if len(envelope) < 64:
        raise ValueError(f"Envelope too short: {len(envelope)} bytes (minimum 64)")

    payload = envelope[:-64]
    signature = envelope[-64:]

    if not verify_signature_raw(payload, signature, public_key_hex):
        raise ValueError("Envelope signature verification failed")

    return msgpack.unpackb(payload, raw=False)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_jwt(claims: Dict[str, Any], private_key_hex: str) -> str:
    """
    Create a JWT signed with Ed25519 (EdDSA algorithm).

    Used for the HTTP API layer (middleware, gateway, REST endpoints).
    For the binary protocol, use create_signed_envelope() instead.
    """
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    sk = SigningKey(bytes.fromhex(private_key_hex))
    sig = sk.sign(signing_input).signature

    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_jwt(token: str, public_key_hex: str) -> Dict[str, Any]:
    """
    Verify a JWT and return its claims.

    Raises ValueError if the token is invalid, expired, or signature fails.
    Only accepts EdDSA (Ed25519) algorithm — no HMAC, no RSA.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header_b64, payload_b64, sig_b64 = parts

    # Decode header
    header = json.loads(_b64url_decode(header_b64))
    alg = header.get("alg", "")

    if alg != "EdDSA":
        raise ValueError(
            f"Unsupported JWT algorithm: {alg}. "
            "Only EdDSA (Ed25519) is accepted."
        )

    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = _b64url_decode(sig_b64)

    try:
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(signing_input, sig)
    except Exception:
        raise ValueError("JWT signature verification failed")

    # Decode claims
    claims = json.loads(_b64url_decode(payload_b64))

    # Check expiry
    if "exp" in claims and claims["exp"] < time.time():
        raise ValueError("JWT has expired")

    return claims


def compute_hash(data: str) -> str:
    """SHA-256 hash of a string, returned as hex."""
    return hashlib.sha256(data.encode()).hexdigest()
