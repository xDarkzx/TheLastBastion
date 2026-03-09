"""
Passport Generator — create clean and deliberately broken agent passports.

Used by the Border Police demo to let developers:
1. Generate a CLEAN passport → passes all 10 verification checks
2. Generate a BAD passport → fails specific checks (educational)

Five defect types:
  tampered   — crypto_hash corrupted after sealing (integrity check fails)
  expired    — expires_at set to yesterday (temporal check fails)
  injected   — SQL/XSS in agent_name (SchemaGatekeeper catches it)
  wrong_key  — signed with a different key than claimed public_key (crypto check fails)
  sybil      — duplicate public_key (anti-Sybil check catches it)
"""

import json
import os
import time
import uuid
from typing import Dict, Tuple

from lastbastion.crypto import generate_keypair, sign_bytes
from lastbastion.passport import AgentPassport, generate_runtime_fingerprint


# ---------------------------------------------------------------------------
# Clean Passport
# ---------------------------------------------------------------------------

def generate_passport_file(
    output_path: str = "agent.passport",
    agent_name: str = "",
    agent_id: str = "",
) -> Dict[str, str]:
    """
    Generate a clean, properly signed Agent Passport and save to file.

    Returns dict with paths: {"passport": ..., "keypair": ..., "public_key": ..., "private_key": ...}
    """
    public_key, private_key = generate_keypair()

    # Also generate an issuer keypair (in production this is The Last Bastion's key)
    issuer_pub, issuer_priv = generate_keypair()

    passport = AgentPassport(
        agent_id=agent_id or f"agent-{uuid.uuid4().hex[:8]}",
        agent_name=agent_name or "Demo Agent",
        public_key=public_key,
        company_name="Demo Organization",
        company_domain="demo.example.com",
        runtime_fingerprint=generate_runtime_fingerprint(),
        trust_score=0.75,
        trust_level="VERIFIED",
        verdict="TRUSTED",
        issuer="the-last-bastion",
        issuer_public_key=issuer_pub,
        issued_at=time.time(),
        expires_at=time.time() + 90 * 24 * 3600,  # 90 days
        interaction_budget=100,
        interaction_budget_max=100,
    )
    passport.seal()

    # Write signed envelope
    signed_bytes = passport.to_signed_bytes(issuer_priv)

    # Determine output paths
    base = output_path.rsplit(".", 1)[0] if "." in output_path else output_path
    passport_path = output_path
    keypair_path = f"{base}.keys.json"

    with open(passport_path, "wb") as f:
        f.write(signed_bytes)

    keypair_data = {
        "agent_id": passport.agent_id,
        "passport_id": passport.passport_id,
        "public_key": public_key,
        "private_key": private_key,
        "issuer_public_key": issuer_pub,
        "issuer_private_key": issuer_priv,
    }
    with open(keypair_path, "w") as f:
        json.dump(keypair_data, f, indent=2)

    return {
        "passport": passport_path,
        "keypair": keypair_path,
        "agent_id": passport.agent_id,
        "passport_id": passport.passport_id,
        "public_key": public_key,
        "private_key": private_key,
        "issuer_public_key": issuer_pub,
        "issuer_private_key": issuer_priv,
    }


# ---------------------------------------------------------------------------
# Bad Passport (5 defect types)
# ---------------------------------------------------------------------------

DEFECT_TYPES = ("tampered", "expired", "injected", "wrong_key", "sybil")

# Known sybil key — any passport using this key triggers anti-Sybil
_SYBIL_PUBLIC_KEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def generate_bad_passport_file(
    output_path: str = "bad_agent.passport",
    defect_type: str = "tampered",
    agent_name: str = "",
    agent_id: str = "",
) -> Dict[str, str]:
    """
    Generate a deliberately broken passport for educational/demo purposes.

    Args:
        output_path: File path for the passport
        defect_type: One of: tampered, expired, injected, wrong_key, sybil

    Returns dict with paths and defect info.
    """
    if defect_type not in DEFECT_TYPES:
        raise ValueError(f"Unknown defect type: {defect_type}. Must be one of {DEFECT_TYPES}")

    public_key, private_key = generate_keypair()
    issuer_pub, issuer_priv = generate_keypair()

    passport = AgentPassport(
        agent_id=agent_id or f"bad-agent-{uuid.uuid4().hex[:8]}",
        agent_name=agent_name or "Demo Agent",
        public_key=public_key,
        company_name="Demo Organization",
        company_domain="demo.example.com",
        runtime_fingerprint=generate_runtime_fingerprint(),
        trust_score=0.75,
        trust_level="VERIFIED",
        verdict="TRUSTED",
        issuer="the-last-bastion",
        issuer_public_key=issuer_pub,
        issued_at=time.time(),
        expires_at=time.time() + 90 * 24 * 3600,
        interaction_budget=100,
        interaction_budget_max=100,
    )

    defect_description = ""

    if defect_type == "tampered":
        # Seal properly, then corrupt the hash
        passport.seal()
        passport.crypto_hash = "deadbeef" + passport.crypto_hash[8:]
        defect_description = "crypto_hash corrupted after sealing — integrity check will fail"

    elif defect_type == "expired":
        # Set expiry to yesterday
        passport.expires_at = time.time() - 86400
        passport.seal()
        defect_description = "expires_at set to yesterday — temporal check will fail"

    elif defect_type == "injected":
        # SQL/XSS injection in agent_name
        passport.agent_name = "Agent<script>alert('xss')</script>'; DROP TABLE agents;--"
        passport.seal()
        defect_description = "SQL/XSS injection in agent_name — SchemaGatekeeper catches it"

    elif defect_type == "wrong_key":
        # Sign with a DIFFERENT key than claimed public_key
        _, wrong_private = generate_keypair()
        passport.seal()
        signed_bytes = passport.to_signed_bytes(wrong_private)

        # Write and return early since we need the wrong signing key
        base = output_path.rsplit(".", 1)[0] if "." in output_path else output_path
        keypair_path = f"{base}.keys.json"

        with open(output_path, "wb") as f:
            f.write(signed_bytes)

        keypair_data = {
            "agent_id": passport.agent_id,
            "passport_id": passport.passport_id,
            "public_key": public_key,
            "private_key": private_key,
            "issuer_public_key": issuer_pub,
            "issuer_private_key": issuer_priv,
            "defect_type": defect_type,
            "defect": "Signed with a different key than claimed — crypto verification fails",
        }
        with open(keypair_path, "w") as f:
            json.dump(keypair_data, f, indent=2)

        return {
            "passport": output_path,
            "keypair": keypair_path,
            "agent_id": passport.agent_id,
            "passport_id": passport.passport_id,
            "public_key": public_key,
            "private_key": private_key,
            "issuer_public_key": issuer_pub,
            "issuer_private_key": issuer_priv,
            "defect_type": defect_type,
            "defect": defect_description or "Signed with wrong key",
        }

    elif defect_type == "sybil":
        # Use a known duplicate public key
        passport.public_key = _SYBIL_PUBLIC_KEY
        passport.seal()
        defect_description = "Uses a known duplicate public_key — anti-Sybil check catches it"

    # Default signing path (tampered, expired, injected, sybil)
    signed_bytes = passport.to_signed_bytes(issuer_priv)

    base = output_path.rsplit(".", 1)[0] if "." in output_path else output_path
    keypair_path = f"{base}.keys.json"

    with open(output_path, "wb") as f:
        f.write(signed_bytes)

    keypair_data = {
        "agent_id": passport.agent_id,
        "passport_id": passport.passport_id,
        "public_key": passport.public_key,
        "private_key": private_key,
        "issuer_public_key": issuer_pub,
        "issuer_private_key": issuer_priv,
        "defect_type": defect_type,
        "defect": defect_description,
    }
    with open(keypair_path, "w") as f:
        json.dump(keypair_data, f, indent=2)

    return {
        "passport": output_path,
        "keypair": keypair_path,
        "agent_id": passport.agent_id,
        "passport_id": passport.passport_id,
        "public_key": passport.public_key,
        "private_key": private_key,
        "issuer_public_key": issuer_pub,
        "issuer_private_key": issuer_priv,
        "defect_type": defect_type,
        "defect": defect_description,
    }
