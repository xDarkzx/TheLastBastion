"""
Bastion Protocol -- Session Resumption.

Skips the full X25519 Diffie-Hellman exchange + identity re-verification on
reconnect, the way TLS 1.3 session tickets do. Without this, every single
reconnect between the same two agents pays the full handshake cost again --
this is the actual "make agent-to-agent communication faster" lever, not
serialization format.

How it works:
  1. After a full handshake (PASSPORT or DIRECT mode) completes, the server
     issues an opaque, encrypted SessionTicket to the client, bound to the
     peer's identity and a resumption_secret derived from that session's
     shared key (NOT the shared key itself -- so a leaked ticket can't be
     used to decrypt the original session's traffic).
  2. On reconnect, the client presents the ticket + a fresh nonce in a RESUME
     frame instead of a full HELLO.
  3. The server decrypts the ticket with its own ticket key (never sent over
     the wire), checks it hasn't expired or already been redeemed (single-use
     -- see NonceRegistry), and derives a NEW session key by mixing the
     resumption_secret with fresh nonces from both sides -- so resumed-session
     traffic keys are never the same as the original session's, or any other
     resumption of the same ticket lineage (forward secrecy is preserved).
  4. A fresh ticket is issued in RESUME_ACK for the next reconnect
     (rotation -- an attacker who steals one ticket only gets one resumption,
     not an indefinitely reusable credential).

Ticket encryption is symmetric (NaCl SecretBox) using a key only the ISSUING
SERVER holds -- the ticket itself is meaningless to anyone else, which is what
makes this stateless (no shared session cache needed across replicas) and
safe to hand to the client to store.

Hard dependency: pynacl.
"""
import hashlib
import hmac
import time
from dataclasses import dataclass

from lastbastion.protocol.frames import serialize_payload, deserialize_payload

try:
    from nacl.secret import SecretBox
    from nacl.utils import random as nacl_random
except ImportError:
    raise ImportError(
        "Bastion Protocol resumption requires PyNaCl. Install: pip install pynacl"
    )


DEFAULT_TICKET_TTL_SECONDS = 3600  # 1 hour
RESUME_NONCE_SIZE = 32


def derive_resumption_secret(shared_key: bytes) -> bytes:
    """
    Derives a resumption secret from an original session's shared key.

    Domain-separated from the shared key itself (SHA-256 with a fixed label)
    so a leaked ticket -- which embeds this secret -- can't be used to
    recover the original session's actual traffic key.
    """
    return hashlib.sha256(shared_key + b"bastion-resumption-secret-v1").digest()


def derive_resumed_session_key(
    resumption_secret: bytes, client_nonce: bytes, server_nonce: bytes
) -> bytes:
    """
    Derives a fresh session key for a resumed connection.

    HMAC-SHA256(resumption_secret, client_nonce || server_nonce) -- a
    single-step HKDF-style key derivation. Both nonces are freshly random per
    resumption attempt, so every resumption of the same ticket lineage gets a
    distinct traffic key even though they all derive from the same
    resumption_secret: forward secrecy holds across resumptions, not just
    across original handshakes.
    """
    return hmac.new(
        resumption_secret, client_nonce + server_nonce, hashlib.sha256
    ).digest()


def issue_ticket(
    ticket_key: bytes,
    agent_id: str,
    public_key: str,
    resumption_secret: bytes,
    ttl_seconds: int = DEFAULT_TICKET_TTL_SECONDS,
) -> bytes:
    """
    Builds an opaque, encrypted session ticket. Only the server holding
    ticket_key can ever decrypt it -- the client just stores and replays it
    without being able to read or modify its contents.
    """
    now = time.time()
    claims = {
        "tid": nacl_random(16),  # unique ticket id -- for single-use enforcement
        "aid": agent_id,
        "pub": public_key,
        "rs": resumption_secret,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload = serialize_payload(claims)
    box = SecretBox(ticket_key)
    return bytes(box.encrypt(payload))


@dataclass
class TicketClaims:
    ticket_id: bytes
    agent_id: str
    public_key: str
    resumption_secret: bytes
    issued_at: float
    expires_at: float

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


def redeem_ticket(ticket_key: bytes, ticket: bytes) -> TicketClaims:
    """
    Decrypts and validates a session ticket.

    Raises ValueError if the ticket is malformed, wasn't encrypted with this
    server's ticket_key, or has expired. Does NOT check single-use/replay --
    callers MUST additionally check ticket_id against a NonceRegistry (or
    equivalent) before trusting a resumption. Decrypting successfully only
    proves the ticket is genuine; it says nothing about whether it's already
    been redeemed once.
    """
    box = SecretBox(ticket_key)
    try:
        payload = box.decrypt(bytes(ticket))
    except Exception as e:
        raise ValueError(f"Ticket decryption failed: {e}")

    claims = deserialize_payload(payload)
    tid = claims["tid"]
    if isinstance(tid, list):
        tid = bytes(tid)
    rs = claims["rs"]
    if isinstance(rs, list):
        rs = bytes(rs)

    result = TicketClaims(
        ticket_id=tid,
        agent_id=claims["aid"],
        public_key=claims["pub"],
        resumption_secret=rs,
        issued_at=claims["iat"],
        expires_at=claims["exp"],
    )
    if result.is_expired:
        raise ValueError("Ticket expired")
    return result
