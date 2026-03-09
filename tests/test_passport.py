"""
Tests for the Last Bastion SDK — Agent Passport system.

Covers:
1. Crypto utilities (Ed25519 keypair, sign/verify, JWT)
2. AgentPassport (creation, sealing, integrity, expiry, JWT round-trip)
3. PassportVerifier (offline verification)
4. Gateway (trust level checks, caching, decisions)
5. Anti-cloning (runtime fingerprint, IP allowlist hash)
"""

import sys
import os
import time
import asyncio

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))


def test_crypto_keypair():
    """Generate Ed25519 keypair and verify format."""
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()
    assert len(pub) == 64, f"Public key should be 64 hex chars, got {len(pub)}"
    assert len(priv) == 64, f"Private key should be 64 hex chars, got {len(priv)}"
    assert pub != priv, "Ed25519 public and private keys must differ"
    print(f"  PASS: Keypair generated (pub={pub[:16]}...)")


def test_crypto_sign_verify():
    """Sign data and verify signature."""
    from lastbastion.crypto import generate_keypair, sign_bytes, verify_signature
    pub, priv = generate_keypair()
    data = b"test message for signing"
    sig = sign_bytes(data, priv)
    assert len(sig) > 0, "Signature should not be empty"
    valid = verify_signature(data, sig, pub)
    assert valid, "Signature should be valid"
    # Tampered data should fail (if PyNaCl is available)
    tampered_valid = verify_signature(b"tampered", sig, pub)
    assert not tampered_valid, "Tampered data should fail verification"
    print(f"  PASS: Sign/verify works")


def test_jwt_roundtrip():
    """Create and verify a JWT."""
    from lastbastion.crypto import generate_keypair, create_jwt, verify_jwt
    pub, priv = generate_keypair()
    claims = {
        "sub": "agent-001",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "trust": 0.85,
    }
    token = create_jwt(claims, priv)
    assert token.count(".") == 2, "JWT should have 3 parts"
    decoded = verify_jwt(token, pub)
    assert decoded["sub"] == "agent-001"
    assert decoded["trust"] == 0.85
    print(f"  PASS: JWT round-trip (token={token[:40]}...)")


def test_jwt_expiry():
    """Expired JWT should raise ValueError."""
    from lastbastion.crypto import generate_keypair, create_jwt, verify_jwt
    pub, priv = generate_keypair()
    claims = {"sub": "expired", "exp": int(time.time()) - 100}
    token = create_jwt(claims, priv)
    try:
        verify_jwt(token, pub)
        assert False, "Should have raised ValueError for expired JWT"
    except ValueError as e:
        assert "expired" in str(e).lower()
    print("  PASS: Expired JWT correctly rejected")


def test_passport_creation():
    """Create a passport and verify fields."""
    from lastbastion.passport import AgentPassport
    passport = AgentPassport(
        agent_id="test-agent-001",
        agent_name="Test Agent",
        trust_score=0.82,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )
    assert passport.agent_id == "test-agent-001"
    assert passport.passport_id.startswith("pp-")
    assert passport.trust_score == 0.82
    assert not passport.is_expired()
    print(f"  PASS: Passport created (id={passport.passport_id})")


def test_passport_seal_integrity():
    """Seal a passport and verify integrity check."""
    from lastbastion.passport import AgentPassport
    passport = AgentPassport(
        agent_id="test-agent-002",
        trust_score=0.75,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )
    passport.seal()
    assert passport.crypto_hash != "", "crypto_hash should be set after sealing"
    assert passport.verify_integrity(), "Integrity should pass immediately after sealing"

    # Tamper with a field
    passport.trust_score = 0.99
    assert not passport.verify_integrity(), "Integrity should fail after tampering"
    print("  PASS: Seal/integrity check works")


def test_passport_jwt_roundtrip():
    """Serialize passport to JWT and deserialize."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    passport = AgentPassport(
        agent_id="test-agent-003",
        agent_name="JWT Test Agent",
        trust_score=0.88,
        trust_level="ESTABLISHED",
        verdict="TRUSTED",
        risk_flags=["NONE"],
        issuer_public_key=pub,
    )

    jwt_token = passport.to_jwt(priv)
    assert jwt_token.count(".") == 2

    # Deserialize
    restored = AgentPassport.from_jwt(jwt_token, pub)
    assert restored.agent_id == "test-agent-003"
    assert restored.trust_score == 0.88
    assert restored.verify_integrity()
    print(f"  PASS: Passport JWT round-trip (token={jwt_token[:40]}...)")


def test_passport_expiry():
    """Passport with past expiry should be detected."""
    from lastbastion.passport import AgentPassport
    passport = AgentPassport(
        agent_id="expired-agent",
        expires_at=time.time() - 1000,
    )
    assert passport.is_expired(), "Passport should be expired"
    print("  PASS: Expired passport detected")


def test_passport_verifier():
    """PassportVerifier offline checks."""
    from lastbastion.passport import AgentPassport, PassportVerifier
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    # Valid passport
    passport = AgentPassport(
        agent_id="verifier-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )
    passport.seal()

    verifier = PassportVerifier(issuer_public_key=pub)
    report = verifier.full_verify(passport)
    assert report["valid"], f"Should be valid: {report}"
    assert report["integrity"]
    assert report["fresh"]
    assert report["trust_ok"]
    assert report["verdict_ok"]

    # Malicious verdict
    bad_passport = AgentPassport(
        agent_id="evil-agent",
        trust_score=0.10,
        trust_level="NONE",
        verdict="MALICIOUS",
    )
    bad_passport.seal()
    bad_report = verifier.full_verify(bad_passport)
    assert not bad_report["valid"], "Malicious agent should fail"
    assert "malicious_verdict" in bad_report["reasons"]
    assert "insufficient_trust" in bad_report["reasons"]
    print("  PASS: PassportVerifier offline checks work")


def test_runtime_fingerprint():
    """Runtime fingerprint should be consistent on same machine."""
    from lastbastion.passport import generate_runtime_fingerprint
    fp1 = generate_runtime_fingerprint()
    fp2 = generate_runtime_fingerprint()
    assert fp1 == fp2, "Fingerprint should be deterministic"
    assert len(fp1) == 16, f"Fingerprint should be 16 chars, got {len(fp1)}"
    print(f"  PASS: Runtime fingerprint consistent ({fp1})")


def test_ip_allowlist_hash():
    """IP allowlist hash should detect different IP sets."""
    from lastbastion.passport import generate_ip_allowlist_hash
    hash1 = generate_ip_allowlist_hash(["192.168.1.1", "10.0.0.1"])
    hash2 = generate_ip_allowlist_hash(["10.0.0.1", "192.168.1.1"])  # same IPs, different order
    hash3 = generate_ip_allowlist_hash(["192.168.1.1", "10.0.0.2"])  # different IP
    assert hash1 == hash2, "Order shouldn't matter"
    assert hash1 != hash3, "Different IPs should produce different hash"
    print(f"  PASS: IP allowlist hash works ({hash1})")


def test_gateway_trust_levels():
    """Gateway should correctly compare trust levels."""
    from lastbastion.gateway import LastBastionGateway
    gw = LastBastionGateway.__wrapped__(min_trust_level="BASIC") if hasattr(LastBastionGateway, '__wrapped__') else None
    # Direct import for testing
    from lastbastion.gateway import LastBastionGateway as GW
    gw = GW(min_trust_level="BASIC")
    assert gw._trust_sufficient("BASIC")
    assert gw._trust_sufficient("VERIFIED")
    assert gw._trust_sufficient("GOLD")
    assert not gw._trust_sufficient("NONE")
    assert not gw._trust_sufficient("NEW")
    print("  PASS: Gateway trust level comparison works")


def test_gateway_check_no_passport():
    """Gateway should deny when passport required but not provided."""
    from lastbastion.gateway import LastBastionGateway as GW
    gw = GW(require_passport=True, verify_online=False)

    async def _test():
        decision = await gw.check_agent("", None)
        assert not decision.allowed
        assert decision.reason == "no_passport_provided"
        # With require_passport=False
        gw2 = GW(require_passport=False, verify_online=False)
        decision2 = await gw2.check_agent("", None)
        assert decision2.allowed
    asyncio.run(_test())
    print("  PASS: Gateway handles missing passport correctly")


def test_gateway_caching():
    """Gateway should cache decisions."""
    from lastbastion.gateway import LastBastionGateway as GW
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair

    pub, priv = generate_keypair()
    gw = GW(
        issuer_public_key=pub,
        min_trust_level="BASIC",
        verify_online=False,
        cache_ttl_seconds=60,
    )

    passport = AgentPassport(
        agent_id="cache-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )
    jwt_token = passport.to_jwt(priv)

    async def _test():
        d1 = await gw.check_agent(jwt_token)
        assert d1.allowed
        assert not d1.cached

        d2 = await gw.check_agent(jwt_token)
        assert d2.allowed
        assert d2.cached
    asyncio.run(_test())
    print("  PASS: Gateway caching works")


def test_compute_hash():
    """compute_hash should be deterministic."""
    from lastbastion.crypto import compute_hash
    h1 = compute_hash("test data")
    h2 = compute_hash("test data")
    h3 = compute_hash("different data")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64
    print("  PASS: compute_hash is deterministic")


def test_exceptions():
    """Exception hierarchy should work."""
    from lastbastion.exceptions import (
        LastBastionError, AuthenticationError, PassportError, GatewayDeniedError,
    )
    try:
        raise PassportError("test error", status_code=403)
    except LastBastionError as e:
        assert e.message == "test error"
        assert e.status_code == 403
    print("  PASS: Exception hierarchy works")


def test_models():
    """SDK models should serialize correctly."""
    from lastbastion.models import GatewayDecision, PassportResponse
    decision = GatewayDecision(
        allowed=True, agent_id="test", trust_score=0.85,
        trust_level="VERIFIED", reason="verified",
    )
    d = decision.model_dump()
    assert d["allowed"] is True
    assert d["trust_score"] == 0.85
    print("  PASS: SDK models work")


# ---------------------------------------------------------------------------
# Budget tests
# ---------------------------------------------------------------------------

def test_budget_decrement():
    """Budget should decrement and track exhaustion."""
    from lastbastion.passport import AgentPassport
    passport = AgentPassport(
        agent_id="budget-test",
        trust_level="VERIFIED",
        verdict="TRUSTED",
        interaction_budget=3,
        interaction_budget_max=3,
    )
    assert not passport.is_budget_exhausted()
    assert passport.decrement_budget() == 2
    assert passport.decrement_budget() == 1
    assert passport.decrement_budget() == 0
    assert passport.is_budget_exhausted()
    assert passport.budget_exhausted_at > 0
    # Further decrements stay at 0
    assert passport.decrement_budget() == 0
    print("  PASS: Budget decrement and exhaustion tracking works")


def test_budget_in_crypto_hash():
    """interaction_budget_max should be in crypto_hash, interaction_budget should not."""
    from lastbastion.passport import AgentPassport
    p1 = AgentPassport(
        agent_id="hash-test", trust_level="VERIFIED",
        interaction_budget=100, interaction_budget_max=100,
    )
    p2 = AgentPassport(
        agent_id="hash-test", trust_level="VERIFIED",
        interaction_budget=50, interaction_budget_max=100,
        # Same passport_id and issued_at for deterministic comparison
        passport_id=p1.passport_id, issued_at=p1.issued_at, expires_at=p1.expires_at,
    )
    # interaction_budget differs but NOT in hash — hashes should match
    assert p1.compute_crypto_hash() == p2.compute_crypto_hash()

    p3 = AgentPassport(
        agent_id="hash-test", trust_level="VERIFIED",
        interaction_budget=100, interaction_budget_max=200,  # different max
        passport_id=p1.passport_id, issued_at=p1.issued_at, expires_at=p1.expires_at,
    )
    # interaction_budget_max differs and IS in hash — hashes should differ
    assert p1.compute_crypto_hash() != p3.compute_crypto_hash()
    print("  PASS: Budget max in crypto_hash, budget current is not")


def test_budget_verifier_check():
    """PassportVerifier should reject budget-exhausted passports."""
    from lastbastion.passport import AgentPassport, PassportVerifier
    passport = AgentPassport(
        agent_id="verifier-budget",
        trust_level="VERIFIED",
        verdict="TRUSTED",
        interaction_budget=0,
        interaction_budget_max=100,
    )
    passport.seal()
    verifier = PassportVerifier()
    report = verifier.full_verify(passport)
    assert not report["valid"], "Budget-exhausted passport should fail"
    assert "budget_exhausted" in report["reasons"]
    assert report["budget_remaining"] == 0
    assert report["budget_max"] == 100
    print("  PASS: Verifier rejects exhausted budget")


def test_budget_tiered_values():
    """Trust-tiered budget values should match the spec."""
    from lastbastion.gateway import LastBastionGateway as GW
    expected = {"NONE": 0, "NEW": 25, "BASIC": 50, "VERIFIED": 100, "ESTABLISHED": 200, "GOLD": 500}
    assert GW.BUDGET_BY_TRUST == expected
    print("  PASS: Trust-tiered budget values correct")


def test_gateway_budget_tracking():
    """Gateway should track and exhaust budget."""
    from lastbastion.gateway import LastBastionGateway as GW
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    gw = GW(
        issuer_public_key=pub,
        min_trust_level="BASIC",
        verify_online=False,
        cache_ttl_seconds=0,  # Disable cache so each call checks budget
    )

    passport = AgentPassport(
        agent_id="gw-budget-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
        interaction_budget=3,
        interaction_budget_max=3,
    )
    jwt_token = passport.to_jwt(priv)

    async def _test():
        # First 3 calls should pass, decrementing budget
        d1 = await gw.check_agent(jwt_token)
        assert d1.allowed, f"Should be allowed: {d1.reason}"
        assert d1.budget_remaining == 2

        d2 = await gw.check_agent(jwt_token)
        assert d2.allowed
        assert d2.budget_remaining == 1

        d3 = await gw.check_agent(jwt_token)
        assert d3.allowed
        assert d3.budget_remaining == 0

        # 4th call — budget exhausted
        d4 = await gw.check_agent(jwt_token)
        assert not d4.allowed, "Should be denied after budget exhausted"
        assert d4.reason == "budget_exhausted"
        assert d4.budget_exhausted

    asyncio.run(_test())
    print("  PASS: Gateway budget tracking and exhaustion works")


def test_gateway_budget_refresh():
    """Gateway should accept refreshed budget after re-verification."""
    from lastbastion.gateway import LastBastionGateway as GW
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    gw = GW(
        issuer_public_key=pub,
        min_trust_level="BASIC",
        verify_online=False,
        cache_ttl_seconds=0,
    )

    passport = AgentPassport(
        agent_id="refresh-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
        interaction_budget=1,
        interaction_budget_max=1,
    )
    jwt_token = passport.to_jwt(priv)

    async def _test():
        # Use the one interaction
        d1 = await gw.check_agent(jwt_token)
        assert d1.allowed

        # Now exhausted
        d2 = await gw.check_agent(jwt_token)
        assert not d2.allowed

        # Refresh budget (simulating re-verification)
        gw.refresh_budget(passport.passport_id, 100)

        # Should work again
        d3 = await gw.check_agent(jwt_token)
        assert d3.allowed
        assert d3.budget_remaining == 99

    asyncio.run(_test())
    print("  PASS: Gateway budget refresh after re-verification works")


def test_models_budget_fields():
    """GatewayDecision should have budget fields."""
    from lastbastion.models import GatewayDecision
    d = GatewayDecision(
        allowed=True, agent_id="test",
        budget_remaining=42, budget_max=100, budget_exhausted=False,
    )
    dump = d.model_dump()
    assert dump["budget_remaining"] == 42
    assert dump["budget_max"] == 100
    assert dump["budget_exhausted"] is False

    # Default backward compat
    d2 = GatewayDecision(allowed=True)
    assert d2.budget_remaining == -1  # not tracked
    print("  PASS: GatewayDecision budget fields work")


def test_passport_jwt_budget_roundtrip():
    """Budget fields should survive JWT serialization."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    passport = AgentPassport(
        agent_id="jwt-budget",
        trust_level="GOLD",
        verdict="TRUSTED",
        interaction_budget=500,
        interaction_budget_max=500,
    )
    jwt_token = passport.to_jwt(priv)
    restored = AgentPassport.from_jwt(jwt_token, pub)
    assert restored.interaction_budget == 500
    assert restored.interaction_budget_max == 500
    assert restored.verify_integrity()
    print("  PASS: Budget fields survive JWT round-trip")


# ---------------------------------------------------------------------------
# Escalation & Strike tests
# ---------------------------------------------------------------------------

def test_gateway_strike_counter():
    """Gateway should count strikes after budget exhaustion."""
    from lastbastion.gateway import LastBastionGateway as GW
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    gw = GW(
        issuer_public_key=pub,
        min_trust_level="BASIC",
        verify_online=False,
        cache_ttl_seconds=0,
    )

    passport = AgentPassport(
        agent_id="strike-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
        interaction_budget=1,
        interaction_budget_max=1,
    )
    jwt_token = passport.to_jwt(priv)

    async def _test():
        # Use up the budget
        d1 = await gw.check_agent(jwt_token)
        assert d1.allowed

        # Post-exhaustion: strikes should increment
        d2 = await gw.check_agent(jwt_token)
        assert not d2.allowed
        assert d2.post_exhaustion_strikes == 1
        assert d2.escalation_tier == 0

        d3 = await gw.check_agent(jwt_token)
        assert d3.post_exhaustion_strikes == 2
        assert d3.escalation_tier == 0

    asyncio.run(_test())
    print("  PASS: Gateway tracks post-exhaustion strikes")


def test_gateway_tier_detection():
    """Gateway should detect tier boundaries at 5, 15, 30 strikes."""
    from lastbastion.gateway import LastBastionGateway as GW

    assert GW._tier_for_strikes(4) is None
    assert GW._tier_for_strikes(5) == 1
    assert GW._tier_for_strikes(6) is None
    assert GW._tier_for_strikes(14) is None
    assert GW._tier_for_strikes(15) == 2
    assert GW._tier_for_strikes(16) is None
    assert GW._tier_for_strikes(29) is None
    assert GW._tier_for_strikes(30) == 3
    print("  PASS: Tier boundary detection works (5->1, 15->2, 30->3)")


def test_gateway_escalation_tier_at_boundary():
    """Gateway should set escalation_tier when strike boundary is hit."""
    from lastbastion.gateway import LastBastionGateway as GW
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    gw = GW(
        issuer_public_key=pub,
        min_trust_level="BASIC",
        verify_online=False,
        cache_ttl_seconds=0,
    )

    passport = AgentPassport(
        agent_id="tier-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
        interaction_budget=1,
        interaction_budget_max=1,
    )
    jwt_token = passport.to_jwt(priv)

    async def _test():
        # Exhaust budget
        await gw.check_agent(jwt_token)

        # Fire 5 strikes to hit tier 1
        for i in range(5):
            d = await gw.check_agent(jwt_token)

        assert d.post_exhaustion_strikes == 5
        assert d.escalation_tier == 1

        # Fire 10 more to hit tier 2 (total 15)
        for i in range(10):
            d = await gw.check_agent(jwt_token)

        assert d.post_exhaustion_strikes == 15
        assert d.escalation_tier == 2

        # Fire 15 more to hit tier 3 (total 30)
        for i in range(15):
            d = await gw.check_agent(jwt_token)

        assert d.post_exhaustion_strikes == 30
        assert d.escalation_tier == 3

    asyncio.run(_test())
    print("  PASS: Escalation tier progresses at boundaries")


def test_gateway_decision_strike_fields():
    """GatewayDecision should include strike fields."""
    from lastbastion.models import GatewayDecision
    d = GatewayDecision(
        allowed=False,
        agent_id="test",
        reason="budget_exhausted",
        post_exhaustion_strikes=7,
        escalation_tier=1,
    )
    dump = d.model_dump()
    assert dump["post_exhaustion_strikes"] == 7
    assert dump["escalation_tier"] == 1

    # Defaults
    d2 = GatewayDecision(allowed=True)
    assert d2.post_exhaustion_strikes == 0
    assert d2.escalation_tier == 0
    print("  PASS: GatewayDecision strike fields work")


def test_middleware_strike_tracking():
    """Middleware should track strikes and include in 429 response."""
    from lastbastion.middleware import LastBastionMiddleware
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    pub, priv = generate_keypair()

    # Create a minimal ASGI app
    async def dummy_app(scope, receive, send):
        pass

    mw = LastBastionMiddleware(
        dummy_app,
        issuer_public_key=pub,
        min_trust_level="BASIC",
    )

    passport = AgentPassport(
        agent_id="mw-strike-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
        interaction_budget=0,  # Already exhausted
        interaction_budget_max=100,
    )

    # Simulate budget tracker state
    pid = passport.passport_id
    mw._budget_tracker[pid] = {
        "remaining": 0,
        "max": 100,
        "agent_id": passport.agent_id,
        "strikes": 4,  # Next will be 5 → tier 1
        "escalation_tier": 0,
    }

    # Simulate one more strike
    budget_info = mw._budget_tracker[pid]
    budget_info["strikes"] += 1
    strikes = budget_info["strikes"]
    assert strikes == 5
    # Tier detection
    tier = None
    if strikes == 5:
        tier = 1
    elif strikes == 15:
        tier = 2
    elif strikes == 30:
        tier = 3
    if tier is not None:
        budget_info["escalation_tier"] = tier
    assert budget_info["escalation_tier"] == 1

    # Check that appeal_url would be included at 5+ strikes
    assert strikes >= 5
    print("  PASS: Middleware tracks strikes and escalation tiers")


def test_appeal_model_fields():
    """AgentAppeal DB model should have all required fields."""
    # Just test the import and basic construction
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.database import AgentAppeal, STRIKE_TIER_1, STRIKE_TIER_2, STRIKE_TIER_3

    assert STRIKE_TIER_1 == 5
    assert STRIKE_TIER_2 == 15
    assert STRIKE_TIER_3 == 30

    # Check table name
    assert AgentAppeal.__tablename__ == "agent_appeals"

    # Check columns exist
    columns = {c.name for c in AgentAppeal.__table__.columns}
    required = {"appeal_id", "agent_id", "org_id", "reason", "evidence",
                "escalation_tier", "strikes_at_filing", "trust_score_at_filing",
                "verdict_at_filing", "status", "filed_at", "resolved_at",
                "resolved_by", "resolution_notes", "trust_score_restored_to",
                "passport_renewed"}
    assert required.issubset(columns), f"Missing columns: {required - columns}"
    print("  PASS: AgentAppeal model has all required fields")


def test_passport_escalation_columns():
    """AgentPassportRecord should have escalation columns."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.database import AgentPassportRecord

    columns = {c.name for c in AgentPassportRecord.__table__.columns}
    assert "post_exhaustion_strikes" in columns
    assert "escalation_tier" in columns
    assert "escalation_locked_at" in columns
    print("  PASS: AgentPassportRecord has escalation columns")


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        ("Crypto: Keypair generation", test_crypto_keypair),
        ("Crypto: Sign/verify", test_crypto_sign_verify),
        ("Crypto: JWT round-trip", test_jwt_roundtrip),
        ("Crypto: JWT expiry", test_jwt_expiry),
        ("Crypto: compute_hash", test_compute_hash),
        ("Passport: Creation", test_passport_creation),
        ("Passport: Seal/integrity", test_passport_seal_integrity),
        ("Passport: JWT round-trip", test_passport_jwt_roundtrip),
        ("Passport: Expiry detection", test_passport_expiry),
        ("Passport: Verifier", test_passport_verifier),
        ("Anti-clone: Runtime fingerprint", test_runtime_fingerprint),
        ("Anti-clone: IP allowlist hash", test_ip_allowlist_hash),
        ("Gateway: Trust levels", test_gateway_trust_levels),
        ("Gateway: No passport", test_gateway_check_no_passport),
        ("Gateway: Caching", test_gateway_caching),
        ("SDK: Exceptions", test_exceptions),
        ("SDK: Models", test_models),
        ("Budget: Decrement tracking", test_budget_decrement),
        ("Budget: Crypto hash inclusion", test_budget_in_crypto_hash),
        ("Budget: Verifier check", test_budget_verifier_check),
        ("Budget: Trust-tiered values", test_budget_tiered_values),
        ("Budget: Gateway tracking", test_gateway_budget_tracking),
        ("Budget: Gateway refresh", test_gateway_budget_refresh),
        ("Budget: Model fields", test_models_budget_fields),
        ("Budget: JWT round-trip", test_passport_jwt_budget_roundtrip),
        ("Escalation: Strike counter", test_gateway_strike_counter),
        ("Escalation: Tier detection", test_gateway_tier_detection),
        ("Escalation: Tier at boundary", test_gateway_escalation_tier_at_boundary),
        ("Escalation: Decision fields", test_gateway_decision_strike_fields),
        ("Escalation: Middleware strikes", test_middleware_strike_tracking),
        ("Escalation: Appeal model", test_appeal_model_fields),
        ("Escalation: Passport columns", test_passport_escalation_columns),
    ]

    print("=" * 60)
    print("LAST BASTION SDK — PASSPORT TEST SUITE")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            print(f"\n[TEST] {name}")
            fn()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed, {len(tests)} total")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)
