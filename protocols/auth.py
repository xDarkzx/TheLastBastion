"""
M2M Authentication & Security Layer.

Handles all security concerns for machine-to-machine communication:

1. Ed25519 digital signatures — agents sign messages, we verify
2. API key management — issue, rotate, revoke keys
3. Replay protection — nonce tracking with expiry window
4. Rate limiting — per-agent request throttling
5. Permission scoping — role-based access control

Security model:
    Machines don't use passwords. They use cryptographic identity.
    An agent's Ed25519 private key IS their identity.
    We never store private keys — only public keys.
    Every message must be signed. No exceptions.
"""
import hashlib
import hmac
import logging
import os
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from protocols.agent_protocol import (
    AgentIdentity,
    AgentRole,
    MAX_MESSAGE_AGE_SECONDS,
    MessageType,
    ProtocolMessage,
    validate_message_freshness,
    validate_protocol_version,
)

logger = logging.getLogger("M2MAuth")

# Check for PyNaCl availability at import time
try:
    import nacl.signing
    _NACL_AVAILABLE = True
except ImportError:
    _NACL_AVAILABLE = False
    logging.getLogger("AUTH").critical(
        "PyNaCl not installed — Ed25519 signature verification DISABLED. "
        "Install with: pip install pynacl"
    )


@dataclass
class APIKey:
    """
    An API key issued to a registered agent.

    API keys are the simpler authentication path for agents
    that don't want to implement Ed25519 signing. They provide
    HMAC-based message authentication instead.
    """
    key_id: str                    # Public identifier (e.g., "sk_live_abc123")
    key_hash: str                  # SHA-256 hash of the actual secret
    agent_id: str                  # Which agent owns this key
    permissions: List[str] = field(default_factory=list)
    created_at: str = ""
    expires_at: Optional[str] = None
    is_active: bool = True
    rate_limit_per_minute: int = 60
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()


class ReplayProtector:
    """
    Prevents message replay attacks using nonce tracking.

    Primary: Redis-backed (persists across restarts).
    Fallback: in-memory dict (if Redis unavailable).
    Nonces expire after the configured window.
    """

    def __init__(self, window_seconds: int = MAX_MESSAGE_AGE_SECONDS) -> None:
        self._seen_nonces: Dict[str, float] = {}
        self._window = window_seconds
        self._last_cleanup = time.time()
        self._cleanup_interval = 60
        self._redis = None
        self._redis_prefix = "bastion:nonce:"
        self._init_redis()

    def _init_redis(self) -> None:
        """Try to connect to Redis for persistent nonce storage."""
        try:
            import redis
            import os
            host = os.getenv("REDIS_HOST", "localhost")
            port = int(os.getenv("REDIS_PORT", "6379"))
            self._redis = redis.Redis(host=host, port=port, db=0, socket_timeout=2)
            self._redis.ping()
            logger.info("ReplayProtector: Redis-backed nonce storage active")
        except Exception:
            self._redis = None
            logger.warning("ReplayProtector: Redis unavailable — using in-memory nonce storage (not restart-safe)")

    def check_and_record(self, nonce: str) -> bool:
        """
        Returns True if the nonce is fresh (not seen before).
        Returns False if this is a replay (nonce already used).
        """
        # Try Redis first (persistent across restarts)
        if self._redis:
            try:
                key = f"{self._redis_prefix}{nonce}"
                # SET NX = only set if not exists, EX = expire after window
                was_set = self._redis.set(key, "1", nx=True, ex=self._window)
                if not was_set:
                    logger.warning(f"REPLAY DETECTED (Redis): nonce={nonce[:16]}...")
                    return False
                return True
            except Exception:
                pass  # Fall through to in-memory

        # Fallback: in-memory
        self._maybe_cleanup()

        if nonce in self._seen_nonces:
            logger.warning(f"REPLAY DETECTED: nonce={nonce[:16]}...")
            return False

        self._seen_nonces[nonce] = time.time()
        return True

    def _maybe_cleanup(self) -> None:
        """Evicts expired nonces from in-memory fallback."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - self._window
        expired = [
            n for n, ts in self._seen_nonces.items()
            if ts < cutoff
        ]
        for n in expired:
            del self._seen_nonces[n]

        self._last_cleanup = now
        if expired:
            logger.debug(f"Cleaned {len(expired)} expired nonces")


class RateLimiter:
    """
    Per-agent request rate limiting using sliding window.

    Prevents any single agent from overwhelming the system.
    """

    def __init__(self, default_limit: int = 60) -> None:
        # agent_id -> list of request timestamps
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._default_limit = default_limit
        self._last_cleanup = time.time()

    def check(
        self, agent_id: str, limit: Optional[int] = None
    ) -> Tuple[bool, int]:
        """
        Returns (allowed, remaining_requests).

        If allowed is False, the agent has exceeded their rate limit.
        """
        max_requests = limit or self._default_limit
        now = time.time()
        window_start = now - 60  # 1-minute sliding window

        # Clean old requests
        self._requests[agent_id] = [
            t for t in self._requests[agent_id]
            if t > window_start
        ]

        current_count = len(self._requests[agent_id])
        remaining = max(0, max_requests - current_count)

        if current_count >= max_requests:
            logger.warning(
                f"RATE LIMIT: agent={agent_id}, "
                f"requests={current_count}/{max_requests}"
            )
            return False, 0

        self._requests[agent_id].append(now)

        # Periodic cleanup: evict stale agent entries every 5 minutes
        if now - self._last_cleanup > 300:
            self._last_cleanup = now
            stale = [aid for aid, ts in self._requests.items() if not ts or ts[-1] < now - 300]
            for aid in stale:
                del self._requests[aid]

        return True, remaining - 1


# Permission definitions for role-based access control
ROLE_PERMISSIONS: Dict[AgentRole, Set[str]] = {
    AgentRole.DATA_CONSUMER: {
        "discover", "quote", "submit_task",
        "query_status", "get_result", "verify_proof",
    },
    AgentRole.DATA_PROVIDER: {
        "discover", "quote", "submit_data", "query_status",
        "get_result", "verify_proof",
    },
    AgentRole.VERIFIER: {
        "discover", "submit_data", "submit_task",
        "query_status", "get_result", "verify_proof",
        "challenge",
    },
    AgentRole.BROKER: {
        "discover", "quote", "submit_task",
        "query_status", "get_result", "verify_proof",
        "register_agent",
    },
    AgentRole.OBSERVER: {
        "discover", "verify_proof",
    },
}


# Trust-based rate limits (Phase C)
TRUST_RATE_LIMITS = {
    "NONE": 5,
    "NEW": 5,
    "BASIC": 15,
    "VERIFIED": 60,
    "ESTABLISHED": 120,
    "GOLD": 300,
}

TRUST_THRESHOLDS = {
    "NONE": 0.0,
    "NEW": 0.40,
    "BASIC": 0.55,
    "VERIFIED": 0.65,
    "ESTABLISHED": 0.75,
    "GOLD": 0.90,
}


def _get_trust_level(score: float) -> str:
    """Returns the trust level name for a given score."""
    for name in ["GOLD", "ESTABLISHED", "VERIFIED", "BASIC", "NEW"]:
        if score >= TRUST_THRESHOLDS[name]:
            return name
    return "NONE"


class M2MAuthenticator:
    """
    Central authentication and authorization service.

    Handles the full auth pipeline:
    1. Verify message signature or API key
    2. Check replay protection
    3. Check rate limits (trust-based)
    4. Check permissions
    """

    def __init__(self, db_session_factory=None) -> None:
        self._replay_protector = ReplayProtector()
        self._rate_limiter = RateLimiter()
        self._api_keys: Dict[str, APIKey] = {}     # key_id -> APIKey
        self._agents: Dict[str, AgentIdentity] = {}  # agent_id -> identity
        self._db_session_factory = db_session_factory
        self.logger = logging.getLogger(self.__class__.__name__)

    def register_agent(self, identity: AgentIdentity) -> None:
        """Stores an agent's public identity for future verification."""
        self._agents[identity.agent_id] = identity
        self.logger.info(
            f"Registered agent: {identity.agent_id} "
            f"(role={identity.role.value})"
        )

    def issue_api_key(
        self,
        agent_id: str,
        permissions: Optional[List[str]] = None,
        rate_limit: int = 60,
        ttl_hours: Optional[int] = None,
        environment: str = "production",
        org_id: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Issues a new API key for an agent.

        Returns: (key_id, raw_secret)
        The raw_secret is returned ONCE and never stored.
        We only store the SHA-256 hash.

        environment: "sandbox" or "production" — determines key prefix and rate limits.
        """
        if agent_id not in self._agents:
            raise ValueError(f"Agent {agent_id} not registered")

        agent = self._agents[agent_id]
        prefix = "sandbox_sk" if environment == "sandbox" else "live_sk"
        key_id = f"{prefix}_{secrets.token_hex(4)}"
        raw_secret = secrets.token_hex(32)
        key_hash = hashlib.sha256(raw_secret.encode()).hexdigest()

        # Default permissions from role if not specified
        if permissions is None:
            permissions = list(ROLE_PERMISSIONS.get(
                agent.role, set()
            ))

        # Sandbox keys get lower default rate limits
        if environment == "sandbox" and rate_limit == 60:
            rate_limit = 10

        expires_at = None
        if ttl_hours:
            expires_at = (
                datetime.utcnow() + timedelta(hours=ttl_hours)
            ).isoformat()

        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            agent_id=agent_id,
            permissions=permissions,
            rate_limit_per_minute=rate_limit,
            expires_at=expires_at,
            metadata={"environment": environment, "org_id": org_id},
        )
        self._api_keys[key_id] = api_key

        # Persist to DB if available
        if self._db_session_factory:
            try:
                from core.database import save_persistent_api_key
                expires_dt = datetime.fromisoformat(expires_at) if expires_at else None
                save_persistent_api_key(
                    key_id=key_id,
                    key_hash=key_hash,
                    agent_id=agent_id,
                    org_id=org_id,
                    environment=environment,
                    permissions=permissions,
                    rate_limit_per_minute=rate_limit,
                    expires_at=expires_dt,
                )
            except Exception as e:
                self.logger.warning(f"Failed to persist API key to DB: {e}")

        self.logger.info(
            f"Issued API key {key_id} for agent {agent_id} "
            f"(env={environment}, permissions={len(permissions)}, rate={rate_limit}/min)"
        )

        return key_id, raw_secret

    def revoke_api_key(self, key_id: str) -> bool:
        """Revokes an API key (marks as inactive) in memory and DB."""
        if key_id in self._api_keys:
            self._api_keys[key_id].is_active = False
            self.logger.info(f"Revoked API key: {key_id}")
        # Also revoke in DB
        if self._db_session_factory:
            try:
                from core.database import revoke_persistent_api_key
                revoke_persistent_api_key(key_id)
            except Exception as e:
                self.logger.warning(f"Failed to revoke key in DB: {e}")
        return key_id in self._api_keys

    def warm_load_keys(self) -> int:
        """Loads all active API keys from DB into memory cache. Returns count loaded."""
        if not self._db_session_factory:
            return 0
        try:
            from core.database import load_all_api_keys
            keys = load_all_api_keys()
            loaded = 0
            for k in keys:
                if k["key_id"] not in self._api_keys:
                    self._api_keys[k["key_id"]] = APIKey(
                        key_id=k["key_id"],
                        key_hash=k["key_hash"],
                        agent_id=k["agent_id"],
                        permissions=k.get("permissions", []),
                        rate_limit_per_minute=k.get("rate_limit_per_minute", 60),
                        expires_at=k.get("expires_at"),
                        metadata={
                            "environment": k.get("environment", "production"),
                            "org_id": k.get("org_id"),
                        },
                    )
                    loaded += 1
            self.logger.info(f"Warm-loaded {loaded} API keys from DB")
            return loaded
        except Exception as e:
            self.logger.warning(f"warm_load_keys failed: {e}")
            return 0

    def authenticate_message(
        self, msg: ProtocolMessage
    ) -> Tuple[bool, str]:
        """
        Full authentication pipeline for a protocol message.

        Returns: (is_authenticated, reason)
        """
        # Step 1: Protocol version check
        if not validate_protocol_version(msg):
            return False, f"Unsupported protocol version: {msg.protocol_version}"

        # Step 2: Freshness check (anti-replay time window)
        if not validate_message_freshness(msg):
            return False, "Message too old or timestamp invalid"

        # Step 3: Nonce replay check
        if not self._replay_protector.check_and_record(msg.nonce):
            return False, f"Replay detected: nonce {msg.nonce[:16]}... already used"

        # Step 4: Agent identity check
        if msg.sender_id not in self._agents:
            return False, f"Unknown agent: {msg.sender_id}"

        # Step 5: Rate limit check
        agent = self._agents[msg.sender_id]
        allowed, remaining = self._rate_limiter.check(msg.sender_id)
        if not allowed:
            return False, f"Rate limit exceeded for {msg.sender_id}"

        # Step 6: Signature verification
        if msg.signature:
            sig_valid = self._verify_signature(msg, agent)
            if not sig_valid:
                return False, "Invalid message signature"
        else:
            # No signature — check if we have an API key auth path
            # For now, require signature for all messages
            return False, "Message not signed — signature required"

        # Update last_seen
        agent.last_seen = datetime.utcnow().isoformat()

        self.logger.info(
            f"AUTH OK: {msg.sender_id} -> {msg.message_type.value} "
            f"(remaining={remaining})"
        )
        return True, "authenticated"

    def authenticate_api_key(
        self, key_id: str, raw_secret: str
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """
        Simple API key authentication (alternative to message signing).

        Returns: (is_valid, reason, agent_id, environment)
        """
        api_key = self._api_keys.get(key_id)

        # If not in memory cache, try DB
        if api_key is None and self._db_session_factory:
            try:
                from core.database import get_persistent_api_key
                db_key = get_persistent_api_key(key_id)
                if db_key:
                    api_key = APIKey(
                        key_id=db_key["key_id"],
                        key_hash=db_key["key_hash"],
                        agent_id=db_key["agent_id"],
                        permissions=db_key.get("permissions", []),
                        rate_limit_per_minute=db_key.get("rate_limit_per_minute", 60),
                        expires_at=db_key.get("expires_at"),
                        is_active=db_key.get("is_active", True),
                        metadata={
                            "environment": db_key.get("environment", "production"),
                            "org_id": db_key.get("org_id"),
                        },
                    )
                    # Cache it
                    self._api_keys[key_id] = api_key
            except Exception as e:
                self.logger.warning(f"DB key lookup failed: {e}")

        if api_key is None:
            return False, "Unknown API key", None, None

        if not api_key.is_active:
            return False, "API key revoked", None, None

        # Check expiry
        if api_key.expires_at:
            try:
                expires = datetime.fromisoformat(api_key.expires_at)
                if datetime.utcnow() > expires:
                    return False, "API key expired", None, None
            except ValueError:
                pass

        # Verify secret
        provided_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
        if not hmac.compare_digest(provided_hash, api_key.key_hash):
            return False, "Invalid API key secret", None, None

        # Trust-based rate limit: look up agent trust score from DB
        effective_limit = api_key.rate_limit_per_minute
        try:
            trust_limit = self._get_trust_rate_limit(api_key.agent_id)
            if trust_limit is not None:
                effective_limit = trust_limit
        except Exception:
            pass  # Fall back to per-key limit

        allowed, _ = self._rate_limiter.check(
            api_key.agent_id, effective_limit
        )
        if not allowed:
            return False, "Rate limit exceeded", api_key.agent_id, None

        environment = api_key.metadata.get("environment", "production")
        return True, "authenticated", api_key.agent_id, environment

    def check_permission(
        self, agent_id: str, action: str
    ) -> bool:
        """
        Checks if an agent has permission to perform an action.

        Uses role-based permissions from ROLE_PERMISSIONS.
        """
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        allowed = ROLE_PERMISSIONS.get(agent.role, set())
        has_perm = action in allowed

        if not has_perm:
            self.logger.warning(
                f"PERMISSION DENIED: {agent_id} (role={agent.role.value}) "
                f"tried action '{action}'"
            )

        return has_perm

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        """Returns an agent's identity if registered."""
        return self._agents.get(agent_id)

    def list_agents(self) -> List[AgentIdentity]:
        """Returns all registered agents."""
        return list(self._agents.values())

    def _get_trust_rate_limit(self, agent_id: str) -> Optional[int]:
        """Looks up agent trust score from DB and returns the corresponding rate limit."""
        if not self._db_session_factory:
            return None
        try:
            from core.database import get_agent_trust
            trust = get_agent_trust(agent_id)
            score = trust.get("trust_score", 0.0)
            if trust.get("status") == "UNKNOWN":
                return None  # No verification record — use default
            level = _get_trust_level(score)
            return TRUST_RATE_LIMITS.get(level, 5)
        except Exception:
            return None

    def _verify_signature(
        self, msg: ProtocolMessage, agent: AgentIdentity
    ) -> bool:
        """
        Verifies message signature against the agent's Ed25519 public key.

        Requires PyNaCl. Returns False if PyNaCl is not installed.
        """
        if not _NACL_AVAILABLE:
            self.logger.critical(
                "SIGNATURE VERIFICATION FAILED: PyNaCl not installed. "
                "Install with: pip install pynacl"
            )
            return False
        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError
            verify_key = VerifyKey(bytes.fromhex(agent.public_key))
            verify_key.verify(msg.canonical_bytes(), bytes.fromhex(msg.signature))
            return True
        except (BadSignatureError, Exception):
            return False


def sign_message(
    msg: ProtocolMessage, private_key: str
) -> ProtocolMessage:
    """
    Signs a protocol message with the sender's Ed25519 private key.

    Requires PyNaCl. Raises ImportError if not installed.
    """
    if not _NACL_AVAILABLE:
        raise ImportError(
            "PyNaCl is required for message signing but is not installed. "
            "Install with: pip install pynacl"
        )
    from nacl.signing import SigningKey
    canonical = msg.canonical_bytes()
    signing_key = SigningKey(bytes.fromhex(private_key))
    signed = signing_key.sign(canonical)
    msg.signature = signed.signature.hex()
    return msg
