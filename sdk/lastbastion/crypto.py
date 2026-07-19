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
from typing import Tuple, Dict, Any

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


def load_or_create_keypair(path: str) -> Tuple[str, str]:
    """
    Load an Ed25519 keypair from a JSON file, generating and persisting a new
    one on first use. Returns (public_key_hex, private_key_hex).

    A keypair generated fresh every process start has no continuity — nothing
    that saw the old public key can recognize the new one. Use this anywhere
    an agent (or an issuer) needs a stable identity across restarts.

    The file is created with owner-only permissions (0600) on POSIX systems —
    this holds a raw private key, and on a shared Linux host (the common case
    for anything actually deployed) a default-umask file is often
    world-readable, handing the private key to any other local user/process.
    """
    import json
    import logging
    import os
    import stat

    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            data = None  # Corrupt/unreadable file — fall through and regenerate

        if data is not None:
            if os.name == "posix":
                try:
                    mode = stat.S_IMODE(os.stat(path).st_mode)
                    if mode & (stat.S_IRWXG | stat.S_IRWXO):
                        logging.getLogger("LastBastionCrypto").warning(
                            "Key file %s is readable/writable beyond its owner "
                            "(mode %o) — tightening to 0600", path, mode
                        )
                        os.chmod(path, 0o600)
                except OSError:
                    pass
            return data["public_key"], data["private_key"]

    public_key, private_key = generate_keypair()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    payload = json.dumps({"public_key": public_key, "private_key": private_key}).encode()
    # Create with restrictive permissions from the moment the file exists —
    # no window where it's briefly sitting at the default (often
    # world-readable) umask before a later chmod call tightens it.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)

    return public_key, private_key


def load_or_create_issuer_keypair(
    keys_file: str = ".bastion_keys.json",
    env_pub: str = "BASTION_ISSUER_PUB",
    env_priv: str = "BASTION_ISSUER_PRIV",
) -> Tuple[str, str]:
    """
    Resolves the Bastion Protocol issuer keypair.

    Environment variables take priority (production: the real issuer key is
    provisioned externally, e.g. from a secrets manager). Falls back to a
    persisted local file so dev/demo restarts don't mint a new issuer
    identity — which would invalidate every passport issued before restart,
    since passports are only valid if signed by an issuer key the verifier
    already recognizes.
    """
    import os

    pub = os.environ.get(env_pub, "")
    priv = os.environ.get(env_priv, "")
    if pub and priv:
        return pub, priv
    return load_or_create_keypair(keys_file)


def load_or_create_symmetric_key(path: str, env_var: str = "") -> bytes:
    """
    Resolves a raw 32-byte symmetric key (e.g. for NaCl SecretBox), persisted
    to a JSON file with owner-only (0600) permissions on first use — same
    reasoning as load_or_create_keypair: a fresh key every restart has no
    continuity with anything encrypted/decrypted before that restart.

    If env_var is given and set, its hex value is used instead of the file
    (production: provisioned externally rather than living on disk at all).
    """
    import json
    import os

    if env_var:
        hex_val = os.environ.get(env_var, "")
        if hex_val:
            return bytes.fromhex(hex_val)

    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
            return bytes.fromhex(data["key"])
        except Exception:
            pass  # Corrupt/unreadable — fall through and regenerate

    key = os.urandom(32)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    payload = json.dumps({"key": key.hex()}).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    return key


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
