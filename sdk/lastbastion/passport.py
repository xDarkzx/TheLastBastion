"""
Agent Passport — cryptographic identity document that agents carry.

An Agent Passport proves:
1. The agent was verified by a trusted issuer (The Last Bastion or other entities)
2. The agent's identity hasn't been tampered with
3. The agent possesses the private key matching the embedded public key
4. The passport hasn't expired or been cloned to a different environment

Two serialization formats:
- JWT (to_jwt / from_jwt): For HTTP API layer — standard web tokens
- Signed bytes (to_signed_bytes / from_signed_bytes): For binary protocol —
  MessagePack + raw Ed25519 signature. No JSON, no base64.

Anti-cloning measures:
- Ed25519 challenge: only the real agent has the private key
- Runtime fingerprint: OS/hostname hash changes on different machines
- IP allowlist hash: mismatch if request comes from unexpected network
- Issuer signature: Ed25519 over all fields — can't forge
- crypto_hash: any field tampering invalidates the passport
- Blockchain anchor: on-chain proof hash for independent verification
"""

import hashlib
import json
import time
import uuid
import platform
import socket
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from pydantic import BaseModel, Field

from lastbastion.crypto import (
    create_jwt, verify_jwt, compute_hash, sign_bytes, verify_signature,
    generate_keypair, create_signed_envelope, verify_signed_envelope,
)


class AgentPassport(BaseModel):
    """The passport document agents carry as proof of verified identity."""

    # Identity
    passport_id: str = Field(default_factory=lambda: f"pp-{uuid.uuid4().hex[:12]}")
    agent_id: str
    agent_name: str = ""
    public_key: str = ""  # Ed25519 hex — agent's own key

    # Organizational
    company_name: str = ""
    company_domain: str = ""
    agent_card_url: str = ""

    # Environmental (anti-cloning)
    geo_ip: str = ""
    geo_country: str = ""
    gps_coordinates: Optional[Dict[str, float]] = None
    runtime_fingerprint: str = ""
    ip_allowlist_hash: str = ""

    # Trust
    trust_score: float = 0.0
    trust_level: str = "NONE"  # NONE, NEW, BASIC, VERIFIED, ESTABLISHED, GOLD
    verdict: str = ""  # TRUSTED, SUSPICIOUS, MALICIOUS
    checks_summary: Dict[str, Any] = Field(default_factory=dict)
    risk_flags: List[str] = Field(default_factory=list)
    sandbox_resilience: float = 0.0

    # Cryptographic
    crypto_hash: str = ""  # SHA-256 of all fields above
    proof_hash: str = ""  # From verification pipeline
    blockchain_tx: str = ""
    blockchain_network: str = ""

    # Budget (diminishing returns)
    interaction_budget: int = 100          # Current remaining (mutable, tracked externally)
    interaction_budget_max: int = 100      # Max at issuance (immutable, in crypto_hash)
    budget_exhausted_at: float = 0.0       # Timestamp when budget hit 0

    # Lifecycle
    issuer: str = "the-last-bastion"
    issuer_public_key: str = ""
    issued_at: float = Field(default_factory=time.time)
    expires_at: float = Field(
        default_factory=lambda: time.time() + 90 * 24 * 3600  # 90 days
    )
    protocol_version: str = "1.0"

    def compute_crypto_hash(self) -> str:
        """Compute SHA-256 over all identity, trust, and environmental fields."""
        fields = {
            "passport_id": self.passport_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "public_key": self.public_key,
            "company_name": self.company_name,
            "company_domain": self.company_domain,
            "agent_card_url": self.agent_card_url,
            "geo_ip": self.geo_ip,
            "geo_country": self.geo_country,
            "gps_coordinates": self.gps_coordinates,
            "runtime_fingerprint": self.runtime_fingerprint,
            "ip_allowlist_hash": self.ip_allowlist_hash,
            "trust_score": self.trust_score,
            "trust_level": self.trust_level,
            "verdict": self.verdict,
            "checks_summary": self.checks_summary,
            "risk_flags": self.risk_flags,
            "sandbox_resilience": self.sandbox_resilience,
            "proof_hash": self.proof_hash,
            "blockchain_tx": self.blockchain_tx,
            "blockchain_network": self.blockchain_network,
            "interaction_budget_max": self.interaction_budget_max,
            "issuer": self.issuer,
            "issuer_public_key": self.issuer_public_key,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "protocol_version": self.protocol_version,
        }
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self) -> "AgentPassport":
        """Compute and set the crypto_hash. Call after populating all fields."""
        self.crypto_hash = self.compute_crypto_hash()
        return self

    def verify_integrity(self) -> bool:
        """Verify that no fields have been tampered with since sealing."""
        return self.crypto_hash == self.compute_crypto_hash()

    def is_expired(self) -> bool:
        """Check if the passport has expired."""
        return time.time() > self.expires_at

    def is_budget_exhausted(self) -> bool:
        """Check if the interaction budget has been used up."""
        return self.interaction_budget <= 0

    def is_budget_tampered(self) -> bool:
        """Check if budget exceeds max (client-side inflation attempt)."""
        return self.interaction_budget > self.interaction_budget_max

    def decrement_budget(self) -> int:
        """Decrement budget by 1. Returns new remaining count.

        NOTE: Budget tracking MUST happen server-side. The interaction_budget
        field is intentionally excluded from crypto_hash because it's mutable.
        Servers must maintain their own budget counter per passport_id and
        reject requests when their counter reaches 0, regardless of what the
        client claims in the passport.
        """
        self.interaction_budget = max(0, self.interaction_budget - 1)
        if self.interaction_budget == 0 and self.budget_exhausted_at == 0.0:
            self.budget_exhausted_at = time.time()
        return self.interaction_budget

    def to_jwt(self, issuer_private_key: str) -> str:
        """Serialize passport to a signed JWT (for HTTP API layer)."""
        self.seal()
        claims = self.model_dump()
        return create_jwt(claims, issuer_private_key)

    @classmethod
    def from_jwt(cls, token: str, issuer_public_key: str) -> "AgentPassport":
        """Deserialize and verify a passport JWT. Raises ValueError on failure."""
        claims = verify_jwt(token, issuer_public_key)
        passport = cls(**claims)
        if not passport.verify_integrity():
            raise ValueError("Passport integrity check failed — fields were tampered")
        return passport

    def to_signed_bytes(self, issuer_private_key: str) -> bytes:
        """Serialize passport to a signed binary envelope (for wire protocol).

        Format: [MessagePack payload | Ed25519 signature (64 bytes)]

        No JSON, no base64, no JWT. Pure binary, consistent with the
        Bastion Protocol frame format.
        """
        self.seal()
        claims = self.model_dump()
        return create_signed_envelope(claims, issuer_private_key)

    @classmethod
    def from_signed_bytes(cls, envelope: bytes, issuer_public_key: str) -> "AgentPassport":
        """Deserialize and verify a signed binary passport envelope.

        Raises ValueError if signature fails or fields were tampered.
        """
        claims = verify_signed_envelope(envelope, issuer_public_key)
        passport = cls(**claims)
        if not passport.verify_integrity():
            raise ValueError("Passport integrity check failed — fields were tampered")
        return passport

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return self.model_dump()


def generate_runtime_fingerprint() -> str:
    """Generate a fingerprint of the current runtime environment."""
    parts = [
        platform.system(),
        platform.node(),
        platform.machine(),
        platform.processor() or "unknown",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def generate_ip_allowlist_hash(ips: List[str]) -> str:
    """Hash a list of allowed IPs for embedding in passport."""
    canonical = ",".join(sorted(ips))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


class PassportVerifier:
    """Utility for verifying Agent Passports."""

    def __init__(self, issuer_public_key: str = ""):
        self.issuer_public_key = issuer_public_key

    def verify_jwt_signature(self, jwt_token: str) -> AgentPassport:
        """Verify JWT signature and return the passport. Raises ValueError on failure."""
        if not self.issuer_public_key:
            raise ValueError("Issuer public key not configured")
        return AgentPassport.from_jwt(jwt_token, self.issuer_public_key)

    def verify_integrity(self, passport: AgentPassport) -> bool:
        """Recompute crypto_hash and compare."""
        return passport.verify_integrity()

    def verify_freshness(self, passport: AgentPassport) -> bool:
        """Check the passport hasn't expired."""
        return not passport.is_expired()

    async def challenge_agent(
        self, passport: AgentPassport, agent_url: str
    ) -> bool:
        """
        Challenge-response: send a nonce to the agent, it must sign with
        its private key matching the public_key in the passport.
        """
        import httpx

        nonce = uuid.uuid4().hex
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{agent_url.rstrip('/')}/passport/challenge",
                    json={"nonce": nonce, "passport_id": passport.passport_id},
                )
                if resp.status_code != 200:
                    return False
                data = resp.json()
                signature_hex = data.get("signature", "")
                return verify_signature(
                    nonce.encode(), signature_hex, passport.public_key
                )
        except Exception:
            return False

    def full_verify(
        self,
        passport: AgentPassport,
        observed_ip: str = "",
        observed_fingerprint: str = "",
    ) -> Dict[str, Any]:
        """
        Run all offline verification checks including anti-clone enforcement.

        Args:
            passport: The passport to verify.
            observed_ip: The IP address the agent connected from (if available).
            observed_fingerprint: Runtime fingerprint from the live agent (if available).

        Returns a report dict with pass/fail and reasons.
        """
        integrity = self.verify_integrity(passport)
        fresh = self.verify_freshness(passport)
        trust_ok = passport.trust_level not in ("NONE",)
        verdict_ok = passport.verdict not in ("MALICIOUS",)
        budget_ok = not passport.is_budget_exhausted()
        budget_tampered = passport.is_budget_tampered()
        if budget_tampered:
            budget_ok = False

        # Issuer verification: passport must declare who issued it,
        # and that issuer must match our configured trusted issuer
        issuer_ok = True
        if self.issuer_public_key:
            # Passport must have an issuer key and it must match ours
            issuer_ok = (
                bool(passport.issuer_public_key)
                and passport.issuer_public_key == self.issuer_public_key
            )
        else:
            # No issuer key configured — can't verify, fail closed
            issuer_ok = False

        # Anti-clone: runtime fingerprint check
        fingerprint_ok = True
        if observed_fingerprint and passport.runtime_fingerprint:
            fingerprint_ok = observed_fingerprint == passport.runtime_fingerprint

        # Anti-clone: IP cross-check
        ip_ok = True
        if observed_ip and passport.geo_ip:
            ip_ok = observed_ip == passport.geo_ip

        passed = (
            integrity and fresh and trust_ok and verdict_ok
            and budget_ok and issuer_ok and fingerprint_ok and ip_ok
        )
        reasons = []
        if not integrity:
            reasons.append("integrity_failed")
        if not fresh:
            reasons.append("expired")
        if not issuer_ok:
            reasons.append("issuer_key_mismatch_or_missing")
        if not trust_ok:
            reasons.append("insufficient_trust")
        if not verdict_ok:
            reasons.append("malicious_verdict")
        if not budget_ok:
            reasons.append("budget_tampered" if budget_tampered else "budget_exhausted")
        if not fingerprint_ok:
            reasons.append(
                f"runtime_fingerprint_mismatch: passport={passport.runtime_fingerprint[:12]}... "
                f"observed={observed_fingerprint[:12]}..."
            )
        if not ip_ok:
            reasons.append(
                f"ip_mismatch: passport={passport.geo_ip} observed={observed_ip}"
            )

        return {
            "valid": passed,
            "integrity": integrity,
            "fresh": fresh,
            "trust_ok": trust_ok,
            "verdict_ok": verdict_ok,
            "budget_ok": budget_ok,
            "issuer_ok": issuer_ok,
            "fingerprint_ok": fingerprint_ok,
            "ip_ok": ip_ok,
            "reasons": reasons,
            "agent_id": passport.agent_id,
            "trust_score": passport.trust_score,
            "trust_level": passport.trust_level,
            "budget_remaining": passport.interaction_budget,
            "budget_max": passport.interaction_budget_max,
        }
