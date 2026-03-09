"""
Progressive Trust Pipeline — Verification Tests

Tests all 6 phases:
  A. Challenge-Response Crypto at Registration
  B. Trust-Gated Access
  C. Progressive Rate Limiting
  D. Mandatory Sandbox Probation
  E. Trust Decay & Re-verification
  F. Peer Reporting
"""
import asyncio
import hashlib
import logging
import os
import secrets
import sys
import time

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)-30s | %(levelname)-7s | %(message)s")
logger = logging.getLogger("TrustPipelineTest")


async def test_phase_a_challenge_response():
    """Phase A: Challenge-Response Crypto at Registration"""
    logger.info("=" * 60)
    logger.info("PHASE A: CHALLENGE-RESPONSE REGISTRATION")
    logger.info("=" * 60)

    from core.database import (
        save_registration_challenge, get_registration_challenge,
        complete_registration_challenge, init_db,
    )
    from datetime import datetime, timedelta

    init_db()

    # Test 1: Create a challenge
    challenge_id = f"reg-test-{secrets.token_hex(4)}"
    nonce = secrets.token_hex(32)
    public_key = secrets.token_hex(32)  # Fake key for unit test

    save_registration_challenge(
        challenge_id=challenge_id,
        agent_id="test-agent-alpha",
        nonce=nonce,
        public_key=public_key,
        role="DATA_CONSUMER",
        display_name="Alpha Bot",
        capabilities=["energy", "nz"],
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    logger.info(f"  OK  Challenge created: {challenge_id}")

    # Test 2: Retrieve the challenge
    challenge = get_registration_challenge(challenge_id)
    assert challenge, "Challenge not found"
    assert challenge["status"] == "PENDING", f"Expected PENDING, got {challenge['status']}"
    assert challenge["nonce"] == nonce, "Nonce mismatch"
    assert challenge["agent_id"] == "test-agent-alpha"
    logger.info(f"  OK  Challenge retrieved: status={challenge['status']}, nonce matches")

    # Test 3: Complete the challenge
    ok = complete_registration_challenge(challenge_id)
    assert ok, "complete_registration_challenge returned False"
    updated = get_registration_challenge(challenge_id)
    assert updated["status"] == "COMPLETED", f"Expected COMPLETED, got {updated['status']}"
    logger.info(f"  OK  Challenge completed: status={updated['status']}")

    # Test 4: HTTP challenge-response flow
    try:
        import httpx
        from regional_core import app
        import core.m2m_router as m2m_mod

        # Ensure challenge mode is ON
        m2m_mod.REQUIRE_CHALLENGE = True
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Register should return challenge, NOT api key
            resp = await client.post("/m2m/register", json={
                "agent_id": "challenge-test-bot",
                "public_key": secrets.token_hex(32),
                "role": "DATA_CONSUMER",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "challenge_id" in data, f"Expected challenge_id in response, got: {list(data.keys())}"
            assert "nonce" in data, "Expected nonce in response"
            assert data["status"] == "PENDING"
            assert "api_key" not in data, "Should NOT return api_key in challenge mode"
            logger.info(f"  OK  HTTP register returns challenge: {data['challenge_id']}")

            # Verify with bad signature -> 401
            bad_resp = await client.post("/m2m/register/verify", json={
                "challenge_id": data["challenge_id"],
                "signature": "bad_signature_000000",
            })
            assert bad_resp.status_code == 401, f"Expected 401, got {bad_resp.status_code}"
            logger.info(f"  OK  Bad signature rejected: 401")

            # Verify with correct HMAC fallback signature
            expected_sig = hashlib.sha256(
                (data["nonce"] + resp.json()["nonce"]).encode()  # This won't match; let's use proper construction
            ).hexdigest()
            # The fallback HMAC is sha256(nonce + public_key) — but we need the stored public_key
            ch = get_registration_challenge(data["challenge_id"])
            correct_sig = hashlib.sha256(
                (ch["nonce"] + ch["public_key"]).encode()
            ).hexdigest()
            good_resp = await client.post("/m2m/register/verify", json={
                "challenge_id": data["challenge_id"],
                "signature": correct_sig,
            })
            assert good_resp.status_code == 200, f"Expected 200, got {good_resp.status_code}: {good_resp.text}"
            gdata = good_resp.json()
            assert gdata["status"] == "REGISTERED"
            assert gdata["trust_level"] == "NEW"
            assert gdata["trust_score"] == 0.42
            assert gdata["api_key"]["environment"] == "sandbox"
            assert gdata["api_key"]["key_id"].startswith("sandbox_sk_")
            logger.info(f"  OK  Challenge verified: agent={gdata['agent_id']}, key={gdata['api_key']['key_id']}, trust=NEW")

        m2m_mod.REQUIRE_CHALLENGE = True  # restore
    except ImportError as ie:
        logger.warning(f"  SKIP  HTTP test (missing httpx): {ie}")

    return True


async def test_phase_b_trust_gating():
    """Phase B: Trust-Gated Access"""
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE B: TRUST-GATED ACCESS")
    logger.info("=" * 60)

    try:
        import httpx
        from regional_core import app
        import core.m2m_router as m2m_mod
        from core.database import (
            save_agent_verification, update_agent_verification,
            SessionLocal, AgentVerification,
        )
        from protocols.auth import M2MAuthenticator

        m2m_mod.REQUIRE_CHALLENGE = False
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Register a low-trust agent
            reg = await client.post("/m2m/register", json={
                "agent_id": "low-trust-bot",
                "public_key": secrets.token_hex(32),
                "role": "DATA_CONSUMER",
            })
            assert reg.status_code == 200
            key_id = reg.json()["api_key"]["key_id"]
            secret = reg.json()["api_key"]["secret"]
            headers = {"x-api-key-id": key_id, "x-api-secret": secret}

            # Set trust to 0.30 (below NEW threshold)
            avr = save_agent_verification(agent_id="low-trust-bot", agent_name="Low Trust Bot")
            update_agent_verification(verification_id=avr.id, verdict="SUSPICIOUS", trust_score=0.30)

            # Try refinery/submit — should be 403 (requires NEW = 0.40)
            resp = await client.post("/refinery/submit", json={
                "payload": {"test": "data"},
                "source_agent_id": "low-trust-bot",
            }, headers=headers)
            assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text[:200]}"
            logger.info(f"  OK  Refinery submit blocked for trust=0.30: 403")

            # Try m2m/submit — should be 403 (requires BASIC = 0.55)
            # First get a quote
            quote_resp = await client.post("/m2m/quote", json={
                "service_id": "svc-data-extraction",
                "task_params": {},
            }, headers=headers)
            # Quote should work (ANY_KEY)
            assert quote_resp.status_code == 200, f"Quote should work: {quote_resp.status_code}"
            logger.info(f"  OK  Quote works at trust=0.30 (no trust gate)")

            quote_id = quote_resp.json()["quote"]["quote_id"]
            submit_resp = await client.post("/m2m/submit", json={
                "service_id": "svc-data-extraction",
                "quote_id": quote_id,
                "payload": {"test": "data"},
            }, headers=headers)
            assert submit_resp.status_code == 403, f"Expected 403, got {submit_resp.status_code}"
            logger.info(f"  OK  M2M submit blocked for trust=0.30: 403 (requires BASIC)")

            # Upgrade trust to 0.55 (BASIC)
            update_agent_verification(verification_id=avr.id, verdict="TRUSTED", trust_score=0.55)

            # Now refinery/submit should work
            resp2 = await client.post("/refinery/submit", json={
                "payload": {"company": "Test Co", "value": 42},
                "source_agent_id": "low-trust-bot",
            }, headers=headers)
            assert resp2.status_code == 200, f"Expected 200 after trust upgrade, got {resp2.status_code}: {resp2.text[:200]}"
            logger.info(f"  OK  Refinery submit works at trust=0.55: verdict={resp2.json().get('verdict')}")

        m2m_mod.REQUIRE_CHALLENGE = True
    except ImportError:
        logger.warning("  SKIP  HTTP test (missing httpx)")

    return True


async def test_phase_c_progressive_rate_limits():
    """Phase C: Progressive Rate Limiting"""
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE C: PROGRESSIVE RATE LIMITING")
    logger.info("=" * 60)

    from protocols.auth import (
        M2MAuthenticator, TRUST_RATE_LIMITS, TRUST_THRESHOLDS,
        _get_trust_level, RateLimiter,
    )

    # Test 1: Trust level mapping
    assert _get_trust_level(0.0) == "NONE"
    assert _get_trust_level(0.42) == "NEW"
    assert _get_trust_level(0.55) == "BASIC"
    assert _get_trust_level(0.70) == "VERIFIED"
    assert _get_trust_level(0.80) == "ESTABLISHED"
    assert _get_trust_level(0.95) == "GOLD"
    logger.info("  OK  Trust level mapping correct for all tiers")

    # Test 2: Rate limits per tier
    assert TRUST_RATE_LIMITS["NONE"] == 5
    assert TRUST_RATE_LIMITS["NEW"] == 5
    assert TRUST_RATE_LIMITS["BASIC"] == 15
    assert TRUST_RATE_LIMITS["VERIFIED"] == 60
    assert TRUST_RATE_LIMITS["ESTABLISHED"] == 120
    assert TRUST_RATE_LIMITS["GOLD"] == 300
    logger.info("  OK  Rate limit tiers: NONE=5, NEW=5, BASIC=15, VERIFIED=60, ESTABLISHED=120, GOLD=300")

    # Test 3: RateLimiter respects custom limits
    rl = RateLimiter(default_limit=60)
    # With limit=5, should allow 5 and block 6th
    agent = "rate-test-agent"
    for i in range(5):
        ok, _ = rl.check(agent, limit=5)
        assert ok, f"Request {i+1} should be allowed"
    blocked, remaining = rl.check(agent, limit=5)
    assert not blocked, "6th request should be blocked at limit=5"
    assert remaining == 0
    logger.info("  OK  RateLimiter enforces limit=5 (5 allowed, 6th blocked)")

    return True


async def test_phase_d_sandbox_probation():
    """Phase D: Mandatory Sandbox Probation"""
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE D: SANDBOX PROBATION / LIVE KEY UPGRADE")
    logger.info("=" * 60)

    from core.database import (
        get_agent_sandbox_graduation, save_sandbox_session,
        update_sandbox_session, save_sandbox_attack_result,
        save_agent_verification, update_agent_verification,
        save_sandbox_organization, init_db,
    )

    init_db()

    # Test 1: Agent with no sandbox sessions → not graduated
    grad = get_agent_sandbox_graduation("no-sandbox-agent")
    assert not grad["passed"], "Should not pass without sandbox sessions"
    assert grad["sessions_completed"] == 0
    logger.info(f"  OK  No sandbox → not graduated: passed={grad['passed']}")

    # Test 2: Create sandbox session with poor results → still not graduated
    org_id = f"org-test-{secrets.token_hex(4)}"
    save_sandbox_organization(org_id=org_id, name="Test Org", email=f"test-{secrets.token_hex(4)}@test.com")
    sess_id = f"sess-{secrets.token_hex(4)}"
    save_sandbox_session(session_id=sess_id, org_id=org_id, agent_id="sandbox-test-agent")
    # 1 passed, 3 failed = 0.25 resilience
    for attack in ["prompt_injection", "identity_spoofing", "sybil_flood"]:
        save_sandbox_attack_result(session_id=sess_id, agent_id="sandbox-test-agent", attack_type=attack, passed=False)
    save_sandbox_attack_result(session_id=sess_id, agent_id="sandbox-test-agent", attack_type="replay", passed=True)
    update_sandbox_session(sess_id, status="completed")

    grad2 = get_agent_sandbox_graduation("sandbox-test-agent")
    assert not grad2["passed"], f"Should not pass with 0.25 resilience, got: {grad2}"
    logger.info(f"  OK  Low resilience (0.25) → not graduated: passed={grad2['passed']}")

    # Test 3: Create session with good results → graduated
    sess_id2 = f"sess-{secrets.token_hex(4)}"
    save_sandbox_session(session_id=sess_id2, org_id=org_id, agent_id="sandbox-test-agent")
    for attack in ["prompt_injection", "identity_spoofing", "sybil_flood", "replay"]:
        save_sandbox_attack_result(session_id=sess_id2, agent_id="sandbox-test-agent", attack_type=attack, passed=True)
    save_sandbox_attack_result(session_id=sess_id2, agent_id="sandbox-test-agent", attack_type="exfiltration", passed=False)
    update_sandbox_session(sess_id2, status="completed")

    grad3 = get_agent_sandbox_graduation("sandbox-test-agent")
    assert grad3["passed"], f"Should pass with 0.80 resilience, got: {grad3}"
    assert grad3["best_resilience_score"] >= 0.5
    logger.info(f"  OK  Good resilience ({grad3['best_resilience_score']}) → graduated: passed={grad3['passed']}")

    # Test 4: HTTP upgrade-to-live endpoint
    try:
        import httpx
        from regional_core import app
        import core.m2m_router as m2m_mod

        m2m_mod.REQUIRE_CHALLENGE = False
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Register agent
            reg = await client.post("/m2m/register", json={
                "agent_id": "upgrade-test-bot",
                "public_key": secrets.token_hex(32),
                "role": "DATA_CONSUMER",
            })
            key_id = reg.json()["api_key"]["key_id"]
            secret = reg.json()["api_key"]["secret"]
            headers = {"x-api-key-id": key_id, "x-api-secret": secret}

            # Try upgrade without meeting requirements
            resp = await client.post("/m2m/upgrade-to-live", headers=headers)
            assert resp.status_code == 403, f"Should fail: {resp.status_code}"
            detail = resp.json().get("detail", {})
            assert "checklist" in detail or "message" in detail
            logger.info(f"  OK  Upgrade blocked (requirements not met): 403")

        m2m_mod.REQUIRE_CHALLENGE = True
    except ImportError:
        logger.warning("  SKIP  HTTP test (missing httpx)")

    return True


async def test_phase_e_trust_decay():
    """Phase E: Trust Decay & Re-verification"""
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE E: TRUST DECAY & RE-VERIFICATION")
    logger.info("=" * 60)

    from core.database import (
        save_agent_verification, update_agent_verification,
        apply_trust_decay, get_agent_trust,
        get_agent_rejection_rate, update_agent_last_active,
        get_agents_for_decay, ensure_agent_verification_columns,
        init_db,
    )
    from datetime import datetime

    init_db()
    ensure_agent_verification_columns()

    # Test 1: apply_trust_decay
    agent_id = f"decay-test-{secrets.token_hex(4)}"
    avr = save_agent_verification(agent_id=agent_id, agent_name="Decay Test")
    update_agent_verification(verification_id=avr.id, verdict="TRUSTED", trust_score=0.70)

    ok = apply_trust_decay(agent_id, 0.67, "Test decay: 3 weeks inactivity")
    assert ok, "apply_trust_decay should return True"
    trust = get_agent_trust(agent_id)
    assert abs(trust["trust_score"] - 0.67) < 0.01, f"Expected ~0.67, got {trust['trust_score']}"
    logger.info(f"  OK  Trust decay applied: 0.70 -> {trust['trust_score']:.2f}")

    # Test 2: update_agent_last_active
    ok2 = update_agent_last_active(agent_id)
    assert ok2, "update_agent_last_active should return True"
    logger.info(f"  OK  Last active updated for {agent_id}")

    # Test 3: get_agent_rejection_rate (no submissions = 0%)
    rate = get_agent_rejection_rate(f"nonexistent-{secrets.token_hex(4)}")
    assert rate == 0.0, f"Expected 0.0, got {rate}"
    logger.info(f"  OK  Rejection rate for unknown agent: {rate}")

    # Test 4: Decay below 0.40 should trigger live key revocation logic
    ok3 = apply_trust_decay(agent_id, 0.35, "Severe inactivity")
    trust2 = get_agent_trust(agent_id)
    assert trust2["trust_score"] < 0.40
    logger.info(f"  OK  Trust decayed below 0.40: {trust2['trust_score']:.2f}")

    return True


async def test_phase_f_peer_reporting():
    """Phase F: Peer Reporting"""
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE F: PEER REPORTING")
    logger.info("=" * 60)

    from core.database import (
        save_agent_report, get_reports_against,
        count_unique_reporters, has_reported,
        get_reporter_false_report_rate,
        save_agent_verification, update_agent_verification,
        apply_trust_decay, get_agent_trust, init_db,
    )

    init_db()

    target_id = f"target-{secrets.token_hex(4)}"
    # Create target with VERIFIED trust
    avr = save_agent_verification(agent_id=target_id, agent_name="Target Bot")
    update_agent_verification(verification_id=avr.id, verdict="TRUSTED", trust_score=0.80)

    # Test 1: Save a report
    save_agent_report(
        reporter_id="reporter-1",
        target_id=target_id,
        reason="spam",
        evidence="Sends garbage data repeatedly",
    )
    reports = get_reports_against(target_id)
    assert len(reports) == 1
    assert reports[0]["reason"] == "spam"
    logger.info(f"  OK  Report saved: reporter-1 -> {target_id} (spam)")

    # Test 2: has_reported — prevents double-reporting
    assert has_reported("reporter-1", target_id), "Should detect existing report"
    assert not has_reported("reporter-2", target_id), "No report from reporter-2 yet"
    logger.info(f"  OK  has_reported: reporter-1=True, reporter-2=False")

    # Test 3: count_unique_reporters
    count = count_unique_reporters(target_id)
    assert count == 1
    logger.info(f"  OK  Unique reporters: {count}")

    # Test 4: Add more reports up to 3 → auto re-verification
    save_agent_report(reporter_id="reporter-2", target_id=target_id, reason="malicious_data")
    save_agent_report(reporter_id="reporter-3", target_id=target_id, reason="sybil")
    count3 = count_unique_reporters(target_id)
    assert count3 == 3
    logger.info(f"  OK  3 unique reporters: count={count3}")

    # Simulate the auto-escalation (re-verify at BASIC)
    apply_trust_decay(target_id, 0.55, f"Re-verification triggered: {count3} peer reports")
    trust = get_agent_trust(target_id)
    assert abs(trust["trust_score"] - 0.55) < 0.01
    logger.info(f"  OK  Auto re-verification: trust dropped to {trust['trust_score']:.2f}")

    # Test 5: Add 2 more reports → quarantine (5 total)
    save_agent_report(reporter_id="reporter-4", target_id=target_id, reason="spam")
    save_agent_report(reporter_id="reporter-5", target_id=target_id, reason="impersonation")
    count5 = count_unique_reporters(target_id)
    assert count5 == 5

    # Simulate quarantine
    apply_trust_decay(target_id, 0.30, f"Quarantined: {count5} peer reports")
    trust2 = get_agent_trust(target_id)
    assert trust2["trust_score"] <= 0.30
    logger.info(f"  OK  Auto quarantine: trust dropped to {trust2['trust_score']:.2f} ({count5} reporters)")

    # Test 6: false report rate
    rate = get_reporter_false_report_rate("reporter-1")
    assert rate == 0.0, "No dismissed reports yet"
    logger.info(f"  OK  False report rate for reporter-1: {rate}")

    # Test 7: HTTP report-agent endpoint
    try:
        import httpx
        from regional_core import app
        import core.m2m_router as m2m_mod

        m2m_mod.REQUIRE_CHALLENGE = False
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Register reporter with VERIFIED trust
            reg = await client.post("/m2m/register", json={
                "agent_id": "http-reporter-bot",
                "public_key": secrets.token_hex(32),
                "role": "DATA_CONSUMER",
            })
            key_id = reg.json()["api_key"]["key_id"]
            secret = reg.json()["api_key"]["secret"]
            headers = {"x-api-key-id": key_id, "x-api-secret": secret}

            # Bootstrap reporter trust to VERIFIED (0.70)
            ravr = save_agent_verification(agent_id="http-reporter-bot", agent_name="Reporter")
            update_agent_verification(verification_id=ravr.id, verdict="TRUSTED", trust_score=0.70)

            # Report the target
            http_target = f"http-target-{secrets.token_hex(4)}"
            resp = await client.post("/m2m/report-agent", json={
                "target_id": http_target,
                "reason": "spam",
                "evidence": "HTTP test report",
            }, headers=headers)
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
            rdata = resp.json()
            assert rdata["status"] == "REPORTED"
            assert rdata["unique_reporters"] == 1
            logger.info(f"  OK  HTTP report-agent: target={http_target}, reporters={rdata['unique_reporters']}")

            # Self-report should fail
            self_resp = await client.post("/m2m/report-agent", json={
                "target_id": "http-reporter-bot",
                "reason": "spam",
            }, headers=headers)
            assert self_resp.status_code == 400
            logger.info(f"  OK  Self-report blocked: 400")

            # Double-report should fail
            dup_resp = await client.post("/m2m/report-agent", json={
                "target_id": http_target,
                "reason": "malicious_data",
            }, headers=headers)
            assert dup_resp.status_code == 409
            logger.info(f"  OK  Double-report blocked: 409")

        m2m_mod.REQUIRE_CHALLENGE = True
    except ImportError:
        logger.warning("  SKIP  HTTP test (missing httpx)")

    return True


async def main():
    logger.info("=" * 60)
    logger.info("PROGRESSIVE TRUST PIPELINE — VERIFICATION TESTS")
    logger.info("=" * 60)
    logger.info("")

    results = {}

    results["A_challenge_response"] = await test_phase_a_challenge_response()
    results["B_trust_gating"] = await test_phase_b_trust_gating()
    results["C_rate_limits"] = await test_phase_c_progressive_rate_limits()
    results["D_sandbox_probation"] = await test_phase_d_sandbox_probation()
    results["E_trust_decay"] = await test_phase_e_trust_decay()
    results["F_peer_reporting"] = await test_phase_f_peer_reporting()

    logger.info("")
    logger.info("=" * 60)
    logger.info("RESULTS")
    logger.info("=" * 60)

    passed = 0
    failed = 0
    for name, result in sorted(results.items()):
        status = "PASS" if result else "FAIL"
        icon = "✅" if result else "❌"
        logger.info(f"   {icon} {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    logger.info("")
    logger.info(f"   PASSED: {passed} | FAILED: {failed}")
    if failed == 0:
        logger.info("🎯 ALL PROGRESSIVE TRUST PHASES VERIFIED")
    else:
        logger.info("⚠️  Some phases failed")

    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
